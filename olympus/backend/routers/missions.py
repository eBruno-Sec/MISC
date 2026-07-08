import asyncio
import csv
import io
import json
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_session, AsyncSessionLocal
from core.models import Mission, MissionStatus, AgentLog, Finding, ApprovalRequest, MissionNote, HttpExchange, AuthProfile
from routers.ws import manager
from core.security import is_valid_target, validate_targets
from core import poc, replay

router = APIRouter()

AGENT_SYMBOL = {
    "zeus": "⚡", "athena": "🦉", "hermes": "☿", "ares": "⚔",
    "hephaestus": "🔥", "hades": "💀", "apollo": "☀", "metis": "⚖",
}

VALID_AGENTS = {"hermes", "ares", "hephaestus", "hades", "apollo", "athena"}


# ── Pydantic schemas ──────────────────────────────────────────

class MissionCreate(BaseModel):
    target: str
    scope: str = ""
    mode: str = "passive"
    scope_rules: dict = {}


class ApprovalResolve(BaseModel):
    approved: bool


class FindingCreate(BaseModel):
    title: str
    severity: str = "medium"
    description: Optional[str] = None
    evidence: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None


class FindingUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    evidence: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None
    tag: Optional[str] = None           # confirmed | false_positive | reported | fixed | null
    analyst_notes: Optional[str] = None


class NoteCreate(BaseModel):
    content: str


class AddTargetsBody(BaseModel):
    targets: List[str]
    run_scan: bool = False              # immediately kick Ares on these targets


class AgentRunBody(BaseModel):
    targets: Optional[List[str]] = None  # override targets; None = use mission context
    options: dict = {}                   # e.g. {"nmap_flags": "-p 80,443", "nuclei_tags": "cve"}


class ReplayBody(BaseModel):
    method: str = "GET"
    url: str
    headers: dict = {}
    body: Optional[str] = None
    follow_redirects: bool = False
    save: bool = True                    # persist as HttpExchange evidence
    finding_id: Optional[str] = None
    notes: Optional[str] = None


class FuzzBody(BaseModel):
    method: str = "GET"
    url: str
    headers: dict = {}
    body: Optional[str] = None
    param: str
    param_in: str = "query"              # query | body | header
    payloads: Optional[List[str]] = None
    wordlist_id: Optional[str] = None    # e.g. "sqli", "xss", "lfi" (curated lists)
    follow_redirects: bool = False
    max_payloads: int = 200


class DiffBody(BaseModel):
    a_id: str
    b_id: str


class ProfileBody(BaseModel):
    name: str                            # unique label, e.g. "user-a"
    role: Optional[str] = None           # human role, e.g. "standard user", "admin"
    headers: dict = {}                   # auth headers for this session (Cookie / Authorization / ...)


class AccessCheckBody(BaseModel):
    method: str = "GET"
    url: str
    body: Optional[str] = None
    extra_headers: dict = {}             # non-auth headers common to every role
    profile_ids: List[str] = []          # roles to test the request as
    owner_profile_id: Optional[str] = None   # the account that legitimately owns the object
    include_anon: bool = True            # also send with no auth (control)
    follow_redirects: bool = False
    save: bool = True                    # capture each role's response as evidence


# ── Helper: serialise findings ────────────────────────────────

def _finding_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "title": f.title,
        "severity": f.severity,
        "description": f.description,
        "evidence": f.evidence,
        "cvss_score": f.cvss_score,
        "remediation": f.remediation,
        "found_by": f.found_by,
        "tag": f.tag,
        "is_manual": f.is_manual,
        "analyst_notes": f.analyst_notes,
        "timestamp": f.timestamp.isoformat(),
    }


def _exchange_dict(ex: HttpExchange) -> dict:
    return {
        "id": ex.id,
        "finding_id": ex.finding_id,
        "method": ex.method,
        "url": ex.url,
        "request_headers": ex.request_headers or {},
        "request_body": ex.request_body,
        "status_code": ex.status_code,
        "response_headers": ex.response_headers or {},
        "response_body": ex.response_body,
        "duration_ms": ex.duration_ms,
        "source": ex.source,
        "notes": ex.notes,
        "redacted": ex.redacted,
        "created_at": ex.created_at.isoformat(),
    }


async def _exchanges_by_finding(session: AsyncSession, mission_id: str) -> dict:
    rows = (await session.execute(
        select(HttpExchange).where(HttpExchange.mission_id == mission_id).order_by(HttpExchange.created_at)
    )).scalars().all()
    grouped: dict = {}
    for ex in rows:
        grouped.setdefault(ex.finding_id, []).append(_exchange_dict(ex))
    return grouped


# ── Mission CRUD ──────────────────────────────────────────────

@router.post("")
async def create_mission(
    body: MissionCreate,
    request: Request,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_session),
):
    _target = body.target.strip()
    if not is_valid_target(_target):
        raise HTTPException(400, "Invalid target. Use a bare hostname, IPv4, or CIDR (no schemes, flags, or shell characters).")
    mission = Mission(
        target=_target,
        scope=body.scope,
        mode=body.mode,
        status=MissionStatus.PENDING,
        scope_rules=body.scope_rules,
    )
    session.add(mission)
    await session.commit()
    await session.refresh(mission)

    background_tasks.add_task(
        _run_mission,
        mission.id,
        body.target.strip(),
        body.mode,
        body.scope,
        body.scope_rules,
        request.app.state.approval_gates,
        request.app.state.approval_results,
    )

    return {"id": mission.id, "target": mission.target, "status": mission.status}


@router.get("")
async def list_missions(session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(Mission).order_by(desc(Mission.created_at)).limit(100)
    )).scalars().all()
    return [
        {
            "id": m.id, "target": m.target, "mode": m.mode,
            "status": m.status, "current_phase": m.current_phase,
            "created_at": m.created_at.isoformat(),
            "completed_at": m.completed_at.isoformat() if m.completed_at else None,
        }
        for m in rows
    ]


@router.get("/{mission_id}")
async def get_mission(mission_id: str, session: AsyncSession = Depends(get_session)):
    mission = await session.get(Mission, mission_id)
    if not mission:
        raise HTTPException(404, "Mission not found")

    findings = (await session.execute(
        select(Finding).where(Finding.mission_id == mission_id).order_by(desc(Finding.timestamp))
    )).scalars().all()

    logs = (await session.execute(
        select(AgentLog).where(AgentLog.mission_id == mission_id).order_by(AgentLog.timestamp)
    )).scalars().all()

    pending = (await session.execute(
        select(ApprovalRequest).where(
            ApprovalRequest.mission_id == mission_id,
            ApprovalRequest.status == "pending",
        )
    )).scalars().all()

    notes = (await session.execute(
        select(MissionNote).where(MissionNote.mission_id == mission_id).order_by(MissionNote.timestamp)
    )).scalars().all()

    ex_by_finding = await _exchanges_by_finding(session, mission_id)

    return {
        "id": mission.id, "target": mission.target, "scope": mission.scope,
        "mode": mission.mode, "status": mission.status,
        "current_phase": mission.current_phase,
        "scope_rules": mission.scope_rules,
        "created_at": mission.created_at.isoformat(),
        "completed_at": mission.completed_at.isoformat() if mission.completed_at else None,
        "findings": [{**_finding_dict(f), "exchanges": ex_by_finding.get(f.id, [])} for f in findings],
        "logs": [
            {
                "id": l.id, "agent": l.agent,
                "symbol": AGENT_SYMBOL.get(l.agent, "○"),
                "level": l.level, "message": l.message,
                "timestamp": l.timestamp.isoformat(),
            }
            for l in logs
        ],
        "pending_approvals": [
            {"id": a.id, "agent": a.agent, "action": a.action,
             "description": a.description, "created_at": a.created_at.isoformat()}
            for a in pending
        ],
        "notes": [
            {"id": n.id, "content": n.content, "timestamp": n.timestamp.isoformat()}
            for n in notes
        ],
        "context": mission.context or {},
    }


@router.delete("/{mission_id}")
async def delete_mission(mission_id: str, session: AsyncSession = Depends(get_session)):
    mission = await session.get(Mission, mission_id)
    if not mission:
        raise HTTPException(404, "Mission not found")
    await session.delete(mission)
    await session.commit()
    return {"deleted": True}


# ── Approval gates ────────────────────────────────────────────

@router.post("/{mission_id}/approvals/{approval_id}/resolve")
async def resolve_approval(
    mission_id: str,
    approval_id: str,
    body: ApprovalResolve,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    approval = await session.get(ApprovalRequest, approval_id)
    if not approval or approval.mission_id != mission_id:
        raise HTTPException(404, "Approval request not found")

    approval.status = "approved" if body.approved else "denied"
    approval.resolved_at = datetime.utcnow()
    await session.commit()

    gates: dict = request.app.state.approval_gates
    results: dict = request.app.state.approval_results
    if approval_id in gates:
        results[approval_id] = body.approved
        gates[approval_id].set()

    await manager.broadcast(mission_id, {
        "type": "approval_resolved",
        "approval_id": approval_id,
        "approved": body.approved,
        "timestamp": datetime.utcnow().isoformat(),
    })
    return {"status": "resolved", "approved": body.approved}


# ── Findings CRUD ─────────────────────────────────────────────

@router.post("/{mission_id}/findings")
async def add_finding(
    mission_id: str,
    body: FindingCreate,
    session: AsyncSession = Depends(get_session),
):
    mission = await session.get(Mission, mission_id)
    if not mission:
        raise HTTPException(404, "Mission not found")

    finding = Finding(
        mission_id=mission_id,
        title=body.title,
        severity=body.severity,
        description=body.description,
        evidence=body.evidence,
        cvss_score=body.cvss_score,
        remediation=body.remediation,
        found_by="analyst",
        is_manual=True,
    )
    session.add(finding)
    await session.commit()
    await session.refresh(finding)

    await manager.broadcast(mission_id, {
        "type": "finding",
        "severity": finding.severity,
        "title": finding.title,
        "found_by": "analyst",
        "display_name": "ANALYST",
        "timestamp": finding.timestamp.isoformat(),
    })
    return _finding_dict(finding)


@router.patch("/{mission_id}/findings/{finding_id}")
async def update_finding(
    mission_id: str,
    finding_id: str,
    body: FindingUpdate,
    session: AsyncSession = Depends(get_session),
):
    finding = await session.get(Finding, finding_id)
    if not finding or finding.mission_id != mission_id:
        raise HTTPException(404, "Finding not found")

    for field, value in body.model_dump(exclude_none=True).items():
        setattr(finding, field, value)
    await session.commit()
    await session.refresh(finding)

    await manager.broadcast(mission_id, {
        "type": "finding_updated",
        "finding_id": finding_id,
        "tag": finding.tag,
        "severity": finding.severity,
        "timestamp": datetime.utcnow().isoformat(),
    })
    return _finding_dict(finding)


@router.delete("/{mission_id}/findings/{finding_id}")
async def delete_finding(
    mission_id: str,
    finding_id: str,
    session: AsyncSession = Depends(get_session),
):
    finding = await session.get(Finding, finding_id)
    if not finding or finding.mission_id != mission_id:
        raise HTTPException(404, "Finding not found")
    await session.delete(finding)
    await session.commit()
    await manager.broadcast(mission_id, {"type": "finding_deleted", "finding_id": finding_id})
    return {"deleted": True}


# ── Mission notes ─────────────────────────────────────────────

@router.post("/{mission_id}/notes")
async def add_note(
    mission_id: str,
    body: NoteCreate,
    session: AsyncSession = Depends(get_session),
):
    mission = await session.get(Mission, mission_id)
    if not mission:
        raise HTTPException(404, "Mission not found")

    note = MissionNote(mission_id=mission_id, content=body.content.strip())
    session.add(note)
    await session.commit()
    await session.refresh(note)

    await manager.broadcast(mission_id, {
        "type": "note_added",
        "note": {"id": note.id, "content": note.content, "timestamp": note.timestamp.isoformat()},
    })
    return {"id": note.id, "content": note.content, "timestamp": note.timestamp.isoformat()}


@router.delete("/{mission_id}/notes/{note_id}")
async def delete_note(
    mission_id: str,
    note_id: str,
    session: AsyncSession = Depends(get_session),
):
    note = await session.get(MissionNote, note_id)
    if not note or note.mission_id != mission_id:
        raise HTTPException(404, "Note not found")
    await session.delete(note)
    await session.commit()
    return {"deleted": True}


# ── Add targets + optional re-scan ───────────────────────────

@router.post("/{mission_id}/targets")
async def add_targets(
    mission_id: str,
    body: AddTargetsBody,
    request: Request,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_session),
):
    mission = await session.get(Mission, mission_id)
    if not mission:
        raise HTTPException(404, "Mission not found")

    targets, rejected = validate_targets(body.targets)
    if not targets:
        raise HTTPException(400, f"No valid targets. Rejected: {rejected}. Use bare hostnames, IPv4, or CIDR only.")

    # Merge into mission context
    ctx = mission.context or {}
    live_hosts = ctx.get("hermes", {}).get("live_hosts", [])
    existing = {h.get("host", "") for h in live_hosts}
    for t in targets:
        if t not in existing:
            live_hosts.append({"host": t, "url": f"https://{t}", "status_code": None, "server": "", "manually_added": True})
    ctx.setdefault("hermes", {})["live_hosts"] = live_hosts
    mission.context = ctx
    await session.commit()

    await manager.broadcast(mission_id, {
        "type": "targets_added",
        "targets": targets,
        "timestamp": datetime.utcnow().isoformat(),
    })

    if body.run_scan:
        background_tasks.add_task(
            _run_single_agent,
            mission_id, "ares",
            {"targets": targets},
            request.app.state.approval_gates,
            request.app.state.approval_results,
        )

    return {"added": targets, "rejected": rejected, "scan_triggered": body.run_scan}


# ── Re-run individual agent ───────────────────────────────────

@router.post("/{mission_id}/agents/{agent_name}/run")
async def rerun_agent(
    mission_id: str,
    agent_name: str,
    body: AgentRunBody,
    request: Request,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_session),
):
    if agent_name not in VALID_AGENTS:
        raise HTTPException(400, f"Unknown agent: {agent_name}. Valid: {', '.join(VALID_AGENTS)}")

    mission = await session.get(Mission, mission_id)
    if not mission:
        raise HTTPException(404, "Mission not found")

    background_tasks.add_task(
        _run_single_agent,
        mission_id,
        agent_name,
        {"targets": body.targets, "options": body.options},
        request.app.state.approval_gates,
        request.app.state.approval_results,
    )

    await manager.broadcast(mission_id, {
        "type": "agent_rerun",
        "agent": agent_name,
        "symbol": AGENT_SYMBOL.get(agent_name, "○"),
        "timestamp": datetime.utcnow().isoformat(),
    })
    return {"status": "queued", "agent": agent_name}


# ── Export ────────────────────────────────────────────────────

@router.get("/{mission_id}/export")
async def export_findings(
    mission_id: str,
    format: str = "json",
    redact: bool = True,
    session: AsyncSession = Depends(get_session),
):
    mission = await session.get(Mission, mission_id)
    if not mission:
        raise HTTPException(404, "Mission not found")

    findings = (await session.execute(
        select(Finding).where(Finding.mission_id == mission_id).order_by(desc(Finding.timestamp))
    )).scalars().all()

    safe_target = mission.target.replace(".", "_").replace("/", "_")[:30]
    filename = f"olympus_{safe_target}_{mission_id[:8]}"

    if format == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=[
            "id", "title", "severity", "cvss_score", "tag",
            "description", "evidence", "remediation", "found_by",
            "is_manual", "analyst_notes", "timestamp",
        ])
        writer.writeheader()
        for f in findings:
            writer.writerow({
                "id": f.id, "title": f.title, "severity": f.severity,
                "cvss_score": f.cvss_score or "", "tag": f.tag or "",
                "description": (f.description or "").replace("\n", " "),
                "evidence": (f.evidence or "").replace("\n", " "),
                "remediation": (f.remediation or "").replace("\n", " "),
                "found_by": f.found_by or "", "is_manual": f.is_manual,
                "analyst_notes": (f.analyst_notes or "").replace("\n", " "),
                "timestamp": f.timestamp.isoformat(),
            })
        buf.seek(0)
        return StreamingResponse(
            iter([buf.read()]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}.csv"'},
        )

    if format in ("md", "markdown"):
        # Copy-ready PoC report: findings + captured request/response, curl and
        # raw HTTP repro. Sensitive headers redacted unless redact=false.
        ex_by_finding = await _exchanges_by_finding(session, mission_id)
        md = poc.mission_markdown(
            mission.target,
            [_finding_dict(f) for f in findings],
            ex_by_finding,
            redact=redact,
        )
        return StreamingResponse(
            iter([md]),
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="{filename}.md"'},
        )

    # JSON default
    payload = {
        "mission_id": mission_id,
        "target": mission.target,
        "mode": mission.mode,
        "exported_at": datetime.utcnow().isoformat(),
        "findings": [_finding_dict(f) for f in findings],
    }
    content = json.dumps(payload, indent=2, default=str)
    return StreamingResponse(
        iter([content]),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}.json"'},
    )


@router.get("/{mission_id}/findings/{finding_id}/poc")
async def finding_poc(
    mission_id: str,
    finding_id: str,
    redact: bool = True,
    session: AsyncSession = Depends(get_session),
):
    """Copy-ready Markdown PoC for a single finding (curl + raw HTTP + evidence)."""
    finding = await session.get(Finding, finding_id)
    if not finding or finding.mission_id != mission_id:
        raise HTTPException(404, "Finding not found")
    exchanges = (await session.execute(
        select(HttpExchange).where(HttpExchange.finding_id == finding_id).order_by(HttpExchange.created_at)
    )).scalars().all()
    md = poc.finding_markdown(
        _finding_dict(finding),
        [_exchange_dict(e) for e in exchanges],
        redact=redact,
    )
    return StreamingResponse(
        iter([md]),
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="poc_{finding_id[:8]}.md"'},
    )


@router.get("/{mission_id}/exchanges")
async def list_exchanges(mission_id: str, session: AsyncSession = Depends(get_session)):
    """All captured HTTP request/response evidence for a mission."""
    mission = await session.get(Mission, mission_id)
    if not mission:
        raise HTTPException(404, "Mission not found")
    rows = (await session.execute(
        select(HttpExchange).where(HttpExchange.mission_id == mission_id).order_by(HttpExchange.created_at)
    )).scalars().all()
    return {"exchanges": [_exchange_dict(e) for e in rows], "total": len(rows)}


# ── Request workbench (replay / fuzz / diff) ──────────────────────

def _host_in_scope(mission: Mission, url: str) -> bool:
    """Keep the workbench scoped to the mission's target (and its subdomains) so
    it cannot be used as an open request relay against arbitrary hosts."""
    from urllib.parse import urlparse
    import re as _re
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = parsed.netloc.split(":")[0].lower()
    if not host or not is_valid_target(host):
        return False
    th = _re.sub(r"^https?://", "", (mission.target or "").lower()).split("/")[0].split(":")[0]
    if not th:
        return True
    return host == th or host.endswith("." + th) or th.endswith("." + host)


@router.post("/{mission_id}/replay")
async def replay_request(
    mission_id: str,
    body: ReplayBody,
    session: AsyncSession = Depends(get_session),
):
    """Repeater: send an analyst-crafted request, capture the response, and (by
    default) store it as PoC evidence."""
    mission = await session.get(Mission, mission_id)
    if not mission:
        raise HTTPException(404, "Mission not found")
    if not _host_in_scope(mission, body.url):
        raise HTTPException(400, "Target host is outside this mission's scope")

    try:
        async with replay.client(follow_redirects=body.follow_redirects) as c:
            res = await replay.send(c, body.method, body.url, body.headers, body.body)
    except Exception as e:
        raise HTTPException(502, f"Request failed: {e}")

    exchange_id = None
    if body.save:
        ex = HttpExchange(
            mission_id=mission_id, finding_id=body.finding_id,
            method=body.method.upper(), url=body.url,
            request_headers=poc.redact_headers(body.headers or {}),
            request_body=body.body,
            status_code=res["status"],
            response_headers=poc.redact_headers(res["headers"]),
            response_body=((res["body"] or "")[:4000] or None),
            duration_ms=res["duration_ms"], source="replay",
            notes=body.notes, redacted=True,
        )
        session.add(ex)
        await session.commit()
        exchange_id = ex.id

    return {
        "exchange_id": exchange_id,
        "status": res["status"],
        "length": res["length"],
        "duration_ms": res["duration_ms"],
        "headers": res["headers"],
        "body": (res["body"] or "")[:8000],
    }


@router.post("/{mission_id}/fuzz")
async def fuzz_param(
    mission_id: str,
    body: FuzzBody,
    session: AsyncSession = Depends(get_session),
):
    """Intruder: fire a payload list at one parameter and rank by anomaly."""
    mission = await session.get(Mission, mission_id)
    if not mission:
        raise HTTPException(404, "Mission not found")
    if not _host_in_scope(mission, body.url):
        raise HTTPException(400, "Target host is outside this mission's scope")

    payloads = list(body.payloads or [])
    if not payloads and body.wordlist_id:
        from core import wordlists as wl
        path = wl.path_for_id(body.wordlist_id)
        if path:
            try:
                with open(path, "r", errors="replace") as f:
                    payloads = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
            except OSError:
                payloads = []
    if not payloads:
        raise HTTPException(400, "Provide payloads or a valid wordlist_id")
    payloads = payloads[: max(1, min(body.max_payloads, replay.MAX_PAYLOADS))]

    if body.param_in not in ("query", "body", "header"):
        raise HTTPException(400, "param_in must be query, body, or header")

    try:
        async with replay.client(follow_redirects=body.follow_redirects) as c:
            out = await replay.fuzz(c, body.method, body.url, body.headers, body.body,
                                    body.param, body.param_in, payloads)
    except Exception as e:
        raise HTTPException(502, f"Fuzz run failed: {e}")
    return out


@router.post("/{mission_id}/diff")
async def diff_exchanges(
    mission_id: str,
    body: DiffBody,
    session: AsyncSession = Depends(get_session),
):
    """Diff two captured exchanges: status / length / header / body deltas."""
    a = await session.get(HttpExchange, body.a_id)
    b = await session.get(HttpExchange, body.b_id)
    if not a or not b or a.mission_id != mission_id or b.mission_id != mission_id:
        raise HTTPException(404, "Exchange not found")

    def _summary(ex):
        return {"status": ex.status_code, "length": len(ex.response_body or ""),
                "duration_ms": ex.duration_ms, "headers": ex.response_headers or {},
                "body": ex.response_body or ""}

    return replay.diff_responses(_summary(a), _summary(b))


# ── Auth profiles + cross-role access control (IDOR / BOLA / BFLA) ─

def _profile_dict(p: AuthProfile) -> dict:
    """Never echo raw session material back over the API — redact header values."""
    return {
        "id": p.id, "name": p.name, "role": p.role,
        "headers": poc.redact_headers(p.headers or {}),
        "created_at": p.created_at.isoformat() if p.created_at else None,
    }


@router.post("/{mission_id}/profiles")
async def create_profile(
    mission_id: str,
    body: ProfileBody,
    session: AsyncSession = Depends(get_session),
):
    """Register a named session/role (its auth headers) for cross-role testing."""
    mission = await session.get(Mission, mission_id)
    if not mission:
        raise HTTPException(404, "Mission not found")
    p = AuthProfile(mission_id=mission_id, name=body.name, role=body.role,
                    headers=body.headers or {})
    session.add(p)
    await session.commit()
    return _profile_dict(p)


@router.get("/{mission_id}/profiles")
async def list_profiles(mission_id: str, session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(
        select(AuthProfile).where(AuthProfile.mission_id == mission_id).order_by(AuthProfile.created_at)
    )).scalars().all()
    return {"profiles": [_profile_dict(p) for p in rows], "total": len(rows)}


@router.delete("/{mission_id}/profiles/{profile_id}")
async def delete_profile(mission_id: str, profile_id: str, session: AsyncSession = Depends(get_session)):
    p = await session.get(AuthProfile, profile_id)
    if not p or p.mission_id != mission_id:
        raise HTTPException(404, "Profile not found")
    await session.delete(p)
    await session.commit()
    return {"deleted": profile_id}


@router.post("/{mission_id}/access-check")
async def access_check(
    mission_id: str,
    body: AccessCheckBody,
    session: AsyncSession = Depends(get_session),
):
    """Send the SAME request as each role (+ anon) and flag broken access control.

    Point this at a request that returns one account's object/function. If another
    role — or anon — gets the owner's response, that's a candidate IDOR/BOLA/BFLA.
    Every response is captured as evidence; findings stay analyst-confirmed."""
    mission = await session.get(Mission, mission_id)
    if not mission:
        raise HTTPException(404, "Mission not found")
    if not _host_in_scope(mission, body.url):
        raise HTTPException(400, "Target host is outside this mission's scope")

    # Build the roster of (label, headers, is_owner, is_anon) to test.
    roster = []
    if body.include_anon:
        roster.append(("anon (no auth)", dict(body.extra_headers or {}), False, True))
    for pid in body.profile_ids:
        p = await session.get(AuthProfile, pid)
        if not p or p.mission_id != mission_id:
            continue
        h = dict(body.extra_headers or {})
        h.update(p.headers or {})
        roster.append((p.role or p.name, h, pid == body.owner_profile_id, not (p.headers or {})))
    if not roster:
        raise HTTPException(400, "Provide profile_ids (and/or include_anon) to test")

    results = []
    async with replay.client(follow_redirects=body.follow_redirects) as c:
        for label, headers, is_owner, is_anon in roster:
            try:
                r = await replay.send(c, body.method, body.url, headers, body.body)
            except Exception as e:
                results.append({"role": label, "error": str(e), "is_owner": is_owner})
                continue
            entry = {"role": label, "status": r["status"], "length": r["length"],
                     "duration_ms": r["duration_ms"], "is_owner": is_owner, "is_anon": is_anon}
            results.append(entry)
            if body.save:
                ex = HttpExchange(
                    mission_id=mission_id, method=body.method.upper(), url=body.url,
                    request_headers=poc.redact_headers(headers),
                    request_body=body.body, status_code=r["status"],
                    response_headers=poc.redact_headers(r["headers"]),
                    response_body=((r["body"] or "")[:4000] or None),
                    duration_ms=r["duration_ms"], source="access-check",
                    notes=f"role={label}" + (" (owner)" if is_owner else ""), redacted=True,
                )
                session.add(ex)
    if body.save:
        await session.commit()

    verdict = replay.access_verdict(results)
    return {
        "request": {"method": body.method.upper(), "url": body.url},
        "results": results,
        **verdict,
    }


# ── Report ────────────────────────────────────────────────────

@router.get("/{mission_id}/report")
async def get_report(mission_id: str):
    import os
    from fastapi.responses import FileResponse
    from core.config import settings
    path = os.path.join(settings.reports_dir, f"report_{mission_id}.html")
    if not os.path.exists(path):
        raise HTTPException(404, "Report not yet generated")
    return FileResponse(path, media_type="text/html")


# ── Background tasks ──────────────────────────────────────────

async def _run_mission(
    mission_id: str, target: str, mode: str, scope: str,
    scope_rules: dict, approval_gates: dict, approval_results: dict,
):
    async with AsyncSessionLocal() as session:
        from agents.zeus import Zeus
        zeus = Zeus(
            session=session, mission_id=mission_id,
            ws_manager=manager,
            approval_gates=approval_gates,
            approval_results=approval_results,
        )
        try:
            await zeus.execute(target, {"mode": mode, "scope": scope, "scope_rules": scope_rules})
        except Exception as e:
            from sqlalchemy import update
            await session.execute(
                update(Mission).where(Mission.id == mission_id).values(status=MissionStatus.FAILED)
            )
            await session.commit()
            await manager.broadcast(mission_id, {
                "type": "mission_failed", "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            })


async def _run_single_agent(
    mission_id: str,
    agent_name: str,
    overrides: dict,
    approval_gates: dict,
    approval_results: dict,
):
    """Re-run a single god outside of the Zeus sequence."""
    AGENT_MAP = {
        "hermes": "agents.hermes.Hermes",
        "ares": "agents.ares.Ares",
        "hephaestus": "agents.hephaestus.Hephaestus",
        "hades": "agents.hades.Hades",
        "apollo": "agents.apollo.Apollo",
        "athena": "agents.athena.Athena",
    }

    async with AsyncSessionLocal() as session:
        mission = await session.get(Mission, mission_id)
        if not mission:
            return

        # Update status to show agent is running
        from sqlalchemy import update
        await session.execute(
            update(Mission).where(Mission.id == mission_id)
            .values(status=MissionStatus.SCANNING, current_phase=agent_name)
        )
        await session.commit()

        await manager.broadcast(mission_id, {
            "type": "status_change",
            "status": MissionStatus.SCANNING,
            "phase": agent_name,
            "timestamp": datetime.utcnow().isoformat(),
        })

        try:
            import importlib
            module_path, class_name = AGENT_MAP[agent_name].rsplit(".", 1)
            mod = importlib.import_module(module_path)
            AgentClass = getattr(mod, class_name)

            agent = AgentClass(
                session=session,
                mission_id=mission_id,
                ws_manager=manager,
                approval_gates=approval_gates,
                approval_results=approval_results,
            )

            # Build context from stored mission context
            ctx = dict(mission.context or {})

            # Override live targets if specified
            target_override = overrides.get("targets")
            if target_override and agent_name in ("ares", "hermes"):
                ctx.setdefault("hermes", {})["live_hosts"] = [
                    {"host": t, "url": f"https://{t}"} for t in target_override
                ]

            # Pass custom options into context for agents that respect them
            ctx["_options"] = overrides.get("options", {})

            result = await agent.execute(mission.target, ctx)

            # Merge result back into mission context
            fresh_mission = await session.get(Mission, mission_id)
            if fresh_mission:
                new_ctx = dict(fresh_mission.context or {})
                new_ctx[agent_name] = result
                fresh_mission.context = new_ctx
                fresh_mission.status = MissionStatus.COMPLETE
                fresh_mission.current_phase = None
                await session.commit()

            await manager.broadcast(mission_id, {
                "type": "status_change",
                "status": MissionStatus.COMPLETE,
                "phase": None,
                "timestamp": datetime.utcnow().isoformat(),
            })

        except Exception as e:
            await manager.broadcast(mission_id, {
                "type": "log",
                "agent": agent_name,
                "symbol": AGENT_SYMBOL.get(agent_name, "○"),
                "display_name": agent_name.upper(),
                "level": "error",
                "message": f"Re-run failed: {e}",
                "timestamp": datetime.utcnow().isoformat(),
            })
            await session.execute(
                update(Mission).where(Mission.id == mission_id)
                .values(status=MissionStatus.COMPLETE, current_phase=None)
            )
            await session.commit()
