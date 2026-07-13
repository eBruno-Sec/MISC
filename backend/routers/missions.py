import asyncio
import csv
import io
import json
from contextlib import suppress
from datetime import datetime
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from typing import Optional, List, Any

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
import httpx

from core.database import get_session, AsyncSessionLocal
from core.models import Mission, MissionStatus, AgentLog, Finding, ApprovalRequest, MissionNote, HttpExchange
from routers.ws import manager
from core.security import is_valid_target, validate_targets
from core.mission_health import mission_heartbeat_loop, record_mission_health
from core.backup import (
    BackupValidationError, build_backup_payload, safe_backup_filename,
    summarize_backup, validate_backup_payload,
)
from core.poc import redact_headers, render_markdown_poc
from core.web_security import analyze_idor_pair, is_url_in_scope

router = APIRouter()

AGENT_SYMBOL = {
    "zeus": "OD", "athena": "FR", "hermes": "HE", "ares": "TY",
    "hephaestus": "BR", "hades": "SK", "apollo": "SA",
}

AGENT_DISPLAY = {
    "zeus": "ODIN", "athena": "FRIGG", "hermes": "HEIMDALL", "ares": "TYR",
    "hephaestus": "BROKKR", "hades": "SKULD", "apollo": "SAGA",
}

VALID_AGENTS = {"hermes", "ares", "hephaestus", "hades", "apollo", "athena"}


def _approval_lost_message(approval: ApprovalRequest | None = None) -> str:
    action = f" for '{approval.action}'" if approval else ""
    return (
        f"Approval gate{action} is no longer active. The backend was likely restarted "
        "while this mission was waiting, so the in-memory task that could continue "
        "the scan is gone. Relaunch the mission to start a fresh run."
    )


async def _mark_orphaned_approval(
    session: AsyncSession,
    mission: Mission,
    approval: ApprovalRequest | None,
) -> str:
    message = _approval_lost_message(approval)
    now = datetime.utcnow()

    if approval and approval.status == "pending":
        approval.status = "stale"
        approval.resolved_at = now

    if mission.status not in (MissionStatus.COMPLETE, MissionStatus.FAILED):
        mission.status = MissionStatus.FAILED
        mission.current_phase = None
        mission.completed_at = now

    session.add(AgentLog(
        mission_id=mission.id,
        agent="zeus",
        level="error",
        message=message,
    ))
    await session.commit()
    return message


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
    run_scan: bool = False              # immediately kick Tyr on these targets


class AgentRunBody(BaseModel):
    targets: Optional[List[str]] = None  # override targets; None = use mission context
    options: dict = {}                   # e.g. {"nmap_flags": "-p 80,443", "nuclei_tags": "cve"}


class BackupImportBody(BaseModel):
    payload: dict[str, Any]


class HttpExchangeCreate(BaseModel):
    label: Optional[str] = None
    finding_id: Optional[str] = None
    method: str = "GET"
    url: str
    request_headers: dict[str, Any] = {}
    request_body: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: dict[str, Any] = {}
    response_body: Optional[str] = None


class ReplayBody(BaseModel):
    method: str = "GET"
    url: str
    headers: dict[str, Any] = {}
    body: Optional[str] = None
    timeout: int = 15


class FuzzBody(BaseModel):
    method: str = "GET"
    url: str
    parameter: str
    payloads: List[str]
    headers: dict[str, Any] = {}
    timeout: int = 10


class AccessCheckBody(BaseModel):
    method: str = "GET"
    url: str
    high_priv_headers: dict[str, Any] = {}
    low_priv_headers: dict[str, Any] = {}
    body: Optional[str] = None
    timeout: int = 15


# ── Helper: serialise findings ────────────────────────────────

def _base_url(mission: Mission) -> str:
    target = mission.target.strip()
    if target.startswith(("http://", "https://")):
        return target
    return f"https://{target}"


def _ensure_url_in_mission_scope(mission: Mission, url: str) -> None:
    if not is_url_in_scope(url, _base_url(mission), mission.scope_rules or {}):
        raise HTTPException(400, "Target host is outside this mission's scope")


def _exchange_dict(exchange: HttpExchange) -> dict:
    return {
        "id": exchange.id,
        "mission_id": exchange.mission_id,
        "finding_id": exchange.finding_id,
        "label": exchange.label,
        "method": exchange.method,
        "url": exchange.url,
        "request_headers": exchange.request_headers or {},
        "request_body": exchange.request_body,
        "response_status": exchange.response_status,
        "response_headers": exchange.response_headers or {},
        "response_body": exchange.response_body,
        "timestamp": exchange.timestamp.isoformat(),
    }


def _mutate_query_param(url: str, parameter: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    seen = False
    mutated = []
    for key, old in pairs:
        if key == parameter:
            mutated.append((key, value))
            seen = True
        else:
            mutated.append((key, old))
    if not seen:
        mutated.append((parameter, value))
    return urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))


async def _send_workbench_request(method: str, url: str, headers: dict[str, Any], body: str | None, timeout: int) -> httpx.Response:
    bounded_timeout = max(1, min(int(timeout or 15), 30))
    async with httpx.AsyncClient(follow_redirects=False, timeout=bounded_timeout) as client:
        return await client.request((method or "GET").upper(), url, headers={str(k): str(v) for k, v in (headers or {}).items()}, content=body)


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


# ── Mission CRUD ──────────────────────────────────────────────

# Workspace backup

@router.post("/backup/summary")
async def backup_summary(body: BackupImportBody):
    try:
        return summarize_backup(body.payload)
    except BackupValidationError as exc:
        raise HTTPException(422, str(exc))


@router.post("/backup/import")
async def import_backup(
    body: BackupImportBody,
    session: AsyncSession = Depends(get_session),
):
    try:
        data = validate_backup_payload(body.payload)
    except BackupValidationError as exc:
        raise HTTPException(422, str(exc))

    mission = Mission(
        target=data["mission"]["target"],
        scope=data["mission"]["scope"],
        mode=data["mission"]["mode"],
        status=MissionStatus.COMPLETE,
        scope_rules=data["mission"]["scope_rules"],
        context={
            **data["mission"]["context"],
            "backup_import": {
                "source_workspace_id": data["workspace_id"],
                "imported_at": datetime.utcnow().isoformat(),
                "version": data["version"],
            },
        },
        completed_at=datetime.utcnow(),
    )
    try:
        session.add(mission)
        await session.flush()
        for item in data["findings"]:
            session.add(Finding(mission_id=mission.id, **item))
        for item in data["notes"]:
            session.add(MissionNote(mission_id=mission.id, **item))
        for item in data["logs"]:
            session.add(AgentLog(mission_id=mission.id, **item))
        for item in data["http_exchanges"]:
            item = dict(item)
            item.pop("finding_id", None)
            session.add(HttpExchange(mission_id=mission.id, **item))
        session.add(AgentLog(
            mission_id=mission.id,
            agent="import",
            level="info",
            message=f"Workspace backup imported from {data['workspace_id']} with {len(data['findings'])} findings",
        ))
        await session.commit()
        await session.refresh(mission)
    except Exception:
        await session.rollback()
        raise

    return {
        "id": mission.id,
        "target": mission.target,
        "status": mission.status,
        "imported_from": data["workspace_id"],
    }


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

@router.post("/{mission_id}/relaunch")
async def relaunch_mission(
    mission_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_session),
):
    original = await session.get(Mission, mission_id)
    if not original:
        raise HTTPException(404, "Mission not found")

    new_mission = Mission(
        target=original.target,
        scope=original.scope or "",
        mode=original.mode,
        status=MissionStatus.PENDING,
        scope_rules=original.scope_rules or {},
        context={"relaunched_from": mission_id},
    )
    session.add(new_mission)
    await session.commit()
    await session.refresh(new_mission)

    background_tasks.add_task(
        _run_mission,
        new_mission.id,
        new_mission.target,
        new_mission.mode,
        new_mission.scope or "",
        new_mission.scope_rules or {},
        request.app.state.approval_gates,
        request.app.state.approval_results,
    )

    await manager.broadcast(new_mission.id, {
        "type": "log",
        "agent": "zeus",
        "symbol": AGENT_SYMBOL.get("zeus", "âš¡"),
        "display_name": AGENT_DISPLAY.get("zeus", "ODIN"),
        "level": "info",
        "message": f"Mission relaunched from {mission_id[:8].upper()}",
        "timestamp": datetime.utcnow().isoformat(),
    })

    return {
        "id": new_mission.id,
        "target": new_mission.target,
        "status": new_mission.status,
        "relaunched_from": mission_id,
    }

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
async def get_mission(
    mission_id: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    mission = await session.get(Mission, mission_id)
    if not mission:
        raise HTTPException(404, "Mission not found")

    pending = (await session.execute(
        select(ApprovalRequest).where(
            ApprovalRequest.mission_id == mission_id,
            ApprovalRequest.status == "pending",
        )
    )).scalars().all()

    active_gate_ids = set(getattr(request.app.state, "approval_gates", {}).keys())
    stale_pending = [a for a in pending if a.id not in active_gate_ids]
    if mission.status == MissionStatus.AWAITING_APPROVAL and stale_pending:
        await _mark_orphaned_approval(session, mission, stale_pending[0])
        await manager.broadcast(mission_id, {
            "type": "approval_resolved",
            "approval_id": stale_pending[0].id,
            "approved": False,
            "timestamp": datetime.utcnow().isoformat(),
        })
        await manager.broadcast(mission_id, {
            "type": "mission_failed",
            "error": _approval_lost_message(stale_pending[0]),
            "timestamp": datetime.utcnow().isoformat(),
        })
        pending = []

    findings = (await session.execute(
        select(Finding).where(Finding.mission_id == mission_id).order_by(desc(Finding.timestamp))
    )).scalars().all()

    logs = (await session.execute(
        select(AgentLog).where(AgentLog.mission_id == mission_id).order_by(AgentLog.timestamp)
    )).scalars().all()

    notes = (await session.execute(
        select(MissionNote).where(MissionNote.mission_id == mission_id).order_by(MissionNote.timestamp)
    )).scalars().all()

    return {
        "id": mission.id, "target": mission.target, "scope": mission.scope,
        "mode": mission.mode, "status": mission.status,
        "current_phase": mission.current_phase,
        "scope_rules": mission.scope_rules,
        "created_at": mission.created_at.isoformat(),
        "completed_at": mission.completed_at.isoformat() if mission.completed_at else None,
        "findings": [_finding_dict(f) for f in findings],
        "logs": [
            {
                "id": l.id, "agent": l.agent,
                "symbol": AGENT_SYMBOL.get(l.agent, "--"),
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

    if approval.status != "pending":
        return {"status": approval.status, "approved": approval.status == "approved"}

    gates: dict = request.app.state.approval_gates
    results: dict = request.app.state.approval_results
    if approval_id not in gates:
        mission = await session.get(Mission, mission_id)
        if mission:
            message = await _mark_orphaned_approval(session, mission, approval)
            await manager.broadcast(mission_id, {
                "type": "approval_resolved",
                "approval_id": approval_id,
                "approved": False,
                "timestamp": datetime.utcnow().isoformat(),
            })
            await manager.broadcast(mission_id, {
                "type": "mission_failed",
                "error": message,
                "timestamp": datetime.utcnow().isoformat(),
            })
            return {"status": "stale", "approved": False, "detail": message}
        raise HTTPException(409, _approval_lost_message(approval))

    approval.status = "approved" if body.approved else "denied"
    approval.resolved_at = datetime.utcnow()
    await session.commit()

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
        "symbol": AGENT_SYMBOL.get(agent_name, "--"),
        "timestamp": datetime.utcnow().isoformat(),
    })
    return {"status": "queued", "agent": agent_name}


# ── Export ────────────────────────────────────────────────────

@router.get("/{mission_id}/export")
async def export_findings(
    mission_id: str,
    format: str = "json",
    session: AsyncSession = Depends(get_session),
):
    mission = await session.get(Mission, mission_id)
    if not mission:
        raise HTTPException(404, "Mission not found")

    findings = (await session.execute(
        select(Finding).where(Finding.mission_id == mission_id).order_by(desc(Finding.timestamp))
    )).scalars().all()

    safe_target = mission.target.replace(".", "_").replace("/", "_")[:30]
    filename = f"yggdrasil_{safe_target}_{mission_id[:8]}"

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
                "description": f.description or "",
                "evidence": f.evidence or "",
                "remediation": f.remediation or "",
                "found_by": f.found_by or "", "is_manual": f.is_manual,
                "analyst_notes": f.analyst_notes or "",
                "timestamp": f.timestamp.isoformat(),
            })
        buf.seek(0)
        return StreamingResponse(
            iter([buf.read()]),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}.csv"'},
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


# ── Report ────────────────────────────────────────────────────

@router.get("/{mission_id}/backup")
async def export_backup(mission_id: str, session: AsyncSession = Depends(get_session)):
    mission = await session.get(Mission, mission_id)
    if not mission:
        raise HTTPException(404, "Mission not found")

    findings = (await session.execute(select(Finding).where(Finding.mission_id == mission_id))).scalars().all()
    notes = (await session.execute(select(MissionNote).where(MissionNote.mission_id == mission_id))).scalars().all()
    logs = (await session.execute(select(AgentLog).where(AgentLog.mission_id == mission_id))).scalars().all()
    exchanges = (await session.execute(select(HttpExchange).where(HttpExchange.mission_id == mission_id))).scalars().all()

    payload = build_backup_payload(
        workspace_id=mission.id,
        mission={
            "id": mission.id,
            "target": mission.target,
            "scope": mission.scope,
            "mode": mission.mode,
            "scope_rules": mission.scope_rules or {},
            "context": mission.context or {},
        },
        findings=[_finding_dict(f) for f in findings],
        notes=[{"id": n.id, "content": n.content, "timestamp": n.timestamp.isoformat()} for n in notes],
        logs=[{"id": l.id, "agent": l.agent, "level": l.level, "message": l.message, "raw_output": l.raw_output, "timestamp": l.timestamp.isoformat()} for l in logs],
        exchanges=[_exchange_dict(e) for e in exchanges],
    )
    content = json.dumps(payload, indent=2, default=str)
    return StreamingResponse(
        iter([content]),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{safe_backup_filename(mission.id)}"'},
    )


@router.get("/{mission_id}/http-exchanges")
async def list_http_exchanges(mission_id: str, session: AsyncSession = Depends(get_session)):
    mission = await session.get(Mission, mission_id)
    if not mission:
        raise HTTPException(404, "Mission not found")
    rows = (await session.execute(
        select(HttpExchange).where(HttpExchange.mission_id == mission_id).order_by(desc(HttpExchange.timestamp)).limit(200)
    )).scalars().all()
    return [_exchange_dict(row) for row in rows]


@router.post("/{mission_id}/http-exchanges")
async def add_http_exchange(
    mission_id: str,
    body: HttpExchangeCreate,
    session: AsyncSession = Depends(get_session),
):
    mission = await session.get(Mission, mission_id)
    if not mission:
        raise HTTPException(404, "Mission not found")
    _ensure_url_in_mission_scope(mission, body.url)

    exchange = HttpExchange(
        mission_id=mission_id,
        finding_id=body.finding_id,
        label=body.label,
        method=(body.method or "GET").upper(),
        url=body.url,
        request_headers=redact_headers(body.request_headers),
        request_body=body.request_body,
        response_status=body.response_status,
        response_headers=redact_headers(body.response_headers),
        response_body=body.response_body,
    )
    session.add(exchange)
    await session.commit()
    await session.refresh(exchange)
    return _exchange_dict(exchange)


@router.get("/{mission_id}/http-exchanges/{exchange_id}/poc")
async def get_http_exchange_poc(mission_id: str, exchange_id: str, session: AsyncSession = Depends(get_session)):
    exchange = await session.get(HttpExchange, exchange_id)
    if not exchange or exchange.mission_id != mission_id:
        raise HTTPException(404, "HTTP exchange not found")
    return {
        "markdown": render_markdown_poc(
            exchange.method,
            exchange.url,
            exchange.request_headers or {},
            exchange.request_body,
            exchange.response_status,
            exchange.response_headers or {},
            exchange.response_body,
        )
    }


@router.post("/{mission_id}/replay")
async def replay_request(mission_id: str, body: ReplayBody, session: AsyncSession = Depends(get_session)):
    mission = await session.get(Mission, mission_id)
    if not mission:
        raise HTTPException(404, "Mission not found")
    _ensure_url_in_mission_scope(mission, body.url)
    try:
        response = await _send_workbench_request(body.method, body.url, body.headers, body.body, body.timeout)
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"Replay request failed: {exc}")

    exchange = HttpExchange(
        mission_id=mission_id,
        label="Workbench replay",
        method=(body.method or "GET").upper(),
        url=body.url,
        request_headers=redact_headers(body.headers),
        request_body=body.body,
        response_status=response.status_code,
        response_headers=redact_headers(dict(response.headers)),
        response_body=response.text[:200000],
    )
    session.add(exchange)
    await session.commit()
    await session.refresh(exchange)
    return {
        "exchange_id": exchange.id,
        "status_code": response.status_code,
        "headers": redact_headers(dict(response.headers)),
        "body": response.text[:200000],
    }


@router.post("/{mission_id}/fuzz")
async def fuzz_request(mission_id: str, body: FuzzBody, session: AsyncSession = Depends(get_session)):
    mission = await session.get(Mission, mission_id)
    if not mission:
        raise HTTPException(404, "Mission not found")
    payloads = [str(p) for p in body.payloads[:25]]
    if not payloads:
        raise HTTPException(400, "At least one payload is required")

    results = []
    for payload in payloads:
        url = _mutate_query_param(body.url, body.parameter, payload)
        _ensure_url_in_mission_scope(mission, url)
        try:
            response = await _send_workbench_request(body.method, url, body.headers, None, body.timeout)
            results.append({
                "payload": payload,
                "url": url,
                "status_code": response.status_code,
                "length": len(response.content),
                "body_preview": response.text[:500],
            })
        except httpx.HTTPError as exc:
            results.append({"payload": payload, "url": url, "error": str(exc)})
    return {"parameter": body.parameter, "count": len(results), "results": results}


@router.post("/{mission_id}/access-check")
async def access_check(mission_id: str, body: AccessCheckBody, session: AsyncSession = Depends(get_session)):
    mission = await session.get(Mission, mission_id)
    if not mission:
        raise HTTPException(404, "Mission not found")
    _ensure_url_in_mission_scope(mission, body.url)
    try:
        high = await _send_workbench_request(body.method, body.url, body.high_priv_headers, body.body, body.timeout)
        low = await _send_workbench_request(body.method, body.url, body.low_priv_headers, body.body, body.timeout)
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"Access check failed: {exc}")

    verdict = analyze_idor_pair(high, low, cross_role=True) or {
        "severity": "info",
        "confidence": "low",
        "reason": "Responses did not show a strong cross-role access-control signal.",
    }
    for label, headers, response in (
        ("Access check high privilege", body.high_priv_headers, high),
        ("Access check low privilege", body.low_priv_headers, low),
    ):
        session.add(HttpExchange(
            mission_id=mission_id,
            label=label,
            method=(body.method or "GET").upper(),
            url=body.url,
            request_headers=redact_headers(headers),
            request_body=body.body,
            response_status=response.status_code,
            response_headers=redact_headers(dict(response.headers)),
            response_body=response.text[:200000],
        ))
    await session.commit()
    return {
        "verdict": verdict,
        "high_status": high.status_code,
        "low_status": low.status_code,
        "high_length": len(high.content),
        "low_length": len(low.content),
    }


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
    """Re-run a single stage outside of the main orchestration sequence."""
    AGENT_MAP = {
        "hermes": "agents.hermes.Hermes",
        "ares": "agents.ares.Ares",
        "hephaestus": "agents.hephaestus.Hephaestus",
        "hades": "agents.hades.Hades",
        "apollo": "agents.apollo.Apollo",
        "athena": "agents.athena.Athena",
    }

    heartbeat_task = asyncio.create_task(mission_heartbeat_loop(mission_id, manager))
    try:
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
            await record_mission_health(mission_id, manager, allow_terminal=True)

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
                    await record_mission_health(mission_id, manager, allow_terminal=True)

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
                    "symbol": AGENT_SYMBOL.get(agent_name, "--"),
                    "display_name": AGENT_DISPLAY.get(agent_name, agent_name.upper()),
                    "level": "error",
                    "message": f"Re-run failed: {e}",
                    "timestamp": datetime.utcnow().isoformat(),
                })
                await session.execute(
                    update(Mission).where(Mission.id == mission_id)
                    .values(status=MissionStatus.COMPLETE, current_phase=None)
                )
                await session.commit()
                await record_mission_health(mission_id, manager, allow_terminal=True)
    finally:
        heartbeat_task.cancel()
        with suppress(asyncio.CancelledError):
            await heartbeat_task
