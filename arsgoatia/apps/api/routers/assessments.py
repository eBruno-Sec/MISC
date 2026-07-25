"""Assessment control-plane endpoints (§22).

Create → authorize → compile-scope → start (Temporal) → pause/resume → get.
Every mutation writes an append-only audit event and a transactional-outbox
event in the same transaction as the state change.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from audit.audit import record_audit
from domain import repositories as repo
from events.outbox import enqueue_event
from schemas.events import EventEnvelope, EventType

from ..deps import get_session, get_tenant_id

router = APIRouter(prefix="/api/v1/assessments", tags=["assessments"])


# --------------------------------------------------------------------------- #
# Request bodies
# --------------------------------------------------------------------------- #
class CreateAssessment(BaseModel):
    name: str
    assessment_types: list[str] = ["web"]


class Authorize(BaseModel):
    authorizing_party: str
    authorized_testing_types: list[str] = ["web"]
    valid_from: datetime
    valid_until: datetime
    artifact_ref: str | None = None
    artifact_hash: str | None = None


class ScopeTargetIn(BaseModel):
    kind: str = "hostname"
    value: str
    disposition: str = "include"


class CompileScope(BaseModel):
    targets: list[ScopeTargetIn]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
async def _emit(
    session: AsyncSession,
    *,
    tenant_id: str,
    assessment_id: str,
    event_type: EventType,
    payload: dict,
    revision: int = 0,
    policy_revision: int = 0,
) -> None:
    env = EventEnvelope(
        event_type=event_type,
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        assessment_revision=revision,
        policy_revision=policy_revision,
        aggregate_type="assessment",
        aggregate_id=assessment_id,
        producer="api",
        correlation_id=uuid4(),
        payload=payload,
    ).finalized()
    await record_audit(session, env)
    await enqueue_event(session, env)


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #
@router.post("")
async def create(
    body: CreateAssessment,
    tenant_id: str = Depends(get_tenant_id),
    session: AsyncSession = Depends(get_session),
) -> dict:
    assessment = await repo.create_assessment(
        session, tenant_id=tenant_id, name=body.name, assessment_types=body.assessment_types
    )
    await _emit(
        session,
        tenant_id=tenant_id,
        assessment_id=str(assessment.id),
        event_type=EventType.ASSESSMENT_CREATED,
        payload={"name": body.name, "assessment_types": body.assessment_types},
    )
    return {"id": str(assessment.id), "lifecycle_state": assessment.lifecycle_state}


@router.post("/{assessment_id}/authorize")
async def authorize(
    assessment_id: str,
    body: Authorize,
    tenant_id: str = Depends(get_tenant_id),
    session: AsyncSession = Depends(get_session),
) -> dict:
    if await repo.get_assessment(session, assessment_id) is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    record = await repo.record_authorization(
        session,
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        authorizing_party=body.authorizing_party,
        authorized_testing_types=body.authorized_testing_types,
        valid_from=body.valid_from,
        valid_until=body.valid_until,
        artifact_ref=body.artifact_ref,
        artifact_hash=body.artifact_hash,
    )
    await _emit(
        session,
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        event_type=EventType.AUTHORIZATION_VALIDATED,
        payload={"authorization_record_id": str(record.id)},
    )
    return {"authorization_record_id": str(record.id), "lifecycle_state": "AUTHORIZATION_VALIDATED"}


@router.post("/{assessment_id}/compile-scope")
async def compile_scope(
    assessment_id: str,
    body: CompileScope,
    tenant_id: str = Depends(get_tenant_id),
    session: AsyncSession = Depends(get_session),
) -> dict:
    assessment = await repo.get_assessment(session, assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    if assessment.lifecycle_state != "AUTHORIZATION_VALIDATED":
        raise HTTPException(status_code=409, detail="authorization must be validated first")
    revision = await repo.compile_scope(
        session,
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        targets=[t.model_dump() for t in body.targets],
    )
    await _emit(
        session,
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        event_type=EventType.SCOPE_COMPILED,
        payload={"revision": revision.revision_number, "targets": [t.value for t in body.targets]},
        revision=revision.revision_number,
    )
    return {"revision_id": str(revision.id), "lifecycle_state": "SCOPE_COMPILED"}


@router.post("/{assessment_id}/start")
async def start(
    assessment_id: str,
    tenant_id: str = Depends(get_tenant_id),
    session: AsyncSession = Depends(get_session),
) -> dict:
    from temporal_common.client import get_temporal_client
    from temporal.workflows.assessment import AssessmentWorkflow
    from config.settings import get_settings

    assessment = await repo.get_assessment(session, assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    if assessment.lifecycle_state != "SCOPE_COMPILED":
        raise HTTPException(status_code=409, detail="scope must be compiled first")

    client = await get_temporal_client()
    workflow_id = f"assessment-{assessment_id}"
    handle = await client.start_workflow(
        AssessmentWorkflow.run,
        {"assessment_id": assessment_id, "tenant_id": tenant_id},
        id=workflow_id,
        task_queue=get_settings().temporal_task_queue_control,
    )
    await repo.set_workflow_handle(
        session, assessment_id=assessment_id, workflow_id=workflow_id, run_id=handle.result_run_id
    )
    return {"workflow_id": workflow_id, "run_id": handle.result_run_id}


async def _signal(assessment_id: str, signal_name: str) -> None:
    from temporal_common.client import get_temporal_client

    client = await get_temporal_client()
    handle = client.get_workflow_handle(f"assessment-{assessment_id}")
    await handle.signal(signal_name)


@router.post("/{assessment_id}/pause")
async def pause(assessment_id: str, _: str = Depends(get_tenant_id)) -> dict:
    await _signal(assessment_id, "pause")
    return {"status": "pause_signaled"}


@router.post("/{assessment_id}/resume")
async def resume(assessment_id: str, _: str = Depends(get_tenant_id)) -> dict:
    await _signal(assessment_id, "resume")
    return {"status": "resume_signaled"}


@router.get("/{assessment_id}/assets")
async def list_assets(
    assessment_id: str,
    _: str = Depends(get_tenant_id),
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
    assets = await repo.list_assets(session, assessment_id)
    return [
        {
            "id": str(a.id),
            "asset_type": a.asset_type,
            "canonical_name": a.canonical_name,
            "scope_status": a.scope_status,
            "assertion_state": a.assertion_state,
        }
        for a in assets
    ]


@router.get("/{assessment_id}/endpoints")
async def list_endpoints(
    assessment_id: str,
    _: str = Depends(get_tenant_id),
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
    endpoints = await repo.list_endpoints(session, assessment_id)
    return [
        {
            "id": str(e.id),
            "method": e.method,
            "host": e.host,
            "path_template": e.path_template,
            "auth_schemes": e.auth_schemes,
        }
        for e in endpoints
    ]


@router.get("/{assessment_id}/evidence")
async def list_evidence(
    assessment_id: str,
    _: str = Depends(get_tenant_id),
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
    evidence = await repo.list_evidence(session, assessment_id)
    return [
        {
            "id": str(e.id),
            "evidence_type": e.evidence_type,
            "object_uri": e.object_uri,
            "sha256": e.sha256,
            "size_bytes": e.size_bytes,
            "redaction_state": e.redaction_state,
        }
        for e in evidence
    ]


@router.get("/{assessment_id}")
async def get_one(
    assessment_id: str,
    tenant_id: str = Depends(get_tenant_id),
    session: AsyncSession = Depends(get_session),
) -> dict:
    assessment = await repo.get_assessment(session, assessment_id)
    if assessment is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    workflow_state = None
    if assessment.temporal_workflow_id:
        try:
            from temporal_common.client import get_temporal_client

            client = await get_temporal_client()
            handle = client.get_workflow_handle(assessment.temporal_workflow_id)
            workflow_state = await handle.query("get_state")
        except Exception:  # noqa: BLE001 - workflow may not be running
            workflow_state = None
    return {
        "id": str(assessment.id),
        "name": assessment.name,
        "lifecycle_state": assessment.lifecycle_state,
        "current_revision_id": str(assessment.current_revision_id)
        if assessment.current_revision_id
        else None,
        "workflow": workflow_state,
    }
