import asyncio
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel
from core.database import get_session, AsyncSessionLocal
from core.models import Mission, MissionStatus, AgentLog, Finding, ApprovalRequest
from routers.ws import manager

router = APIRouter()


class MissionCreate(BaseModel):
    target: str
    scope: str = ""
    mode: str = "passive"


class ApprovalResolve(BaseModel):
    approved: bool


@router.post("")
async def create_mission(
    body: MissionCreate,
    request: Request,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_session),
):
    mission = Mission(
        target=body.target.strip(),
        scope=body.scope,
        mode=body.mode,
        status=MissionStatus.PENDING,
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
        request.app.state.approval_gates,
        request.app.state.approval_results,
    )

    return {"id": mission.id, "target": mission.target, "status": mission.status}


@router.get("")
async def list_missions(session: AsyncSession = Depends(get_session)):
    result = await session.execute(
        select(Mission).order_by(desc(Mission.created_at)).limit(100)
    )
    missions = result.scalars().all()
    return [
        {
            "id": m.id,
            "target": m.target,
            "mode": m.mode,
            "status": m.status,
            "current_phase": m.current_phase,
            "created_at": m.created_at.isoformat(),
            "completed_at": m.completed_at.isoformat() if m.completed_at else None,
        }
        for m in missions
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

    return {
        "id": mission.id,
        "target": mission.target,
        "scope": mission.scope,
        "mode": mission.mode,
        "status": mission.status,
        "current_phase": mission.current_phase,
        "created_at": mission.created_at.isoformat(),
        "completed_at": mission.completed_at.isoformat() if mission.completed_at else None,
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "evidence": f.evidence,
                "cvss_score": f.cvss_score,
                "remediation": f.remediation,
                "found_by": f.found_by,
                "timestamp": f.timestamp.isoformat(),
            }
            for f in findings
        ],
        "logs": [
            {
                "id": l.id,
                "agent": l.agent,
                "symbol": {"zeus": "⚡", "athena": "🦉", "hermes": "☿", "ares": "⚔",
                           "hephaestus": "🔥", "hades": "💀", "apollo": "☀"}.get(l.agent, "○"),
                "level": l.level,
                "message": l.message,
                "timestamp": l.timestamp.isoformat(),
            }
            for l in logs
        ],
        "pending_approvals": [
            {
                "id": a.id,
                "agent": a.agent,
                "action": a.action,
                "description": a.description,
                "created_at": a.created_at.isoformat(),
            }
            for a in pending
        ],
    }


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


@router.get("/{mission_id}/report")
async def get_report(mission_id: str):
    import os
    from fastapi.responses import FileResponse
    from core.config import settings

    path = os.path.join(settings.reports_dir, f"report_{mission_id}.html")
    if not os.path.exists(path):
        raise HTTPException(404, "Report not yet generated")
    return FileResponse(path, media_type="text/html")


@router.delete("/{mission_id}")
async def delete_mission(mission_id: str, session: AsyncSession = Depends(get_session)):
    mission = await session.get(Mission, mission_id)
    if not mission:
        raise HTTPException(404, "Mission not found")
    await session.delete(mission)
    await session.commit()
    return {"deleted": True}


async def _run_mission(
    mission_id: str,
    target: str,
    mode: str,
    scope: str,
    approval_gates: dict,
    approval_results: dict,
):
    async with AsyncSessionLocal() as session:
        from agents.zeus import Zeus
        zeus = Zeus(
            session=session,
            mission_id=mission_id,
            ws_manager=manager,
            approval_gates=approval_gates,
            approval_results=approval_results,
        )
        try:
            await zeus.execute(target, {"mode": mode, "scope": scope})
        except Exception as e:
            from sqlalchemy import update
            await session.execute(
                update(Mission).where(Mission.id == mission_id).values(status=MissionStatus.FAILED)
            )
            await session.commit()
            await manager.broadcast(mission_id, {
                "type": "mission_failed",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            })
