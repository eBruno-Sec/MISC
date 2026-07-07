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
from core.models import Mission, MissionStatus, AgentLog, Finding, ApprovalRequest, MissionNote
from routers.ws import manager
from core.security import is_valid_target, validate_targets

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
