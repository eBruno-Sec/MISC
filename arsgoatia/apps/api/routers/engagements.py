"""Engagement lifecycle endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Query, status
from pydantic import BaseModel, Field

from apps.api import temporal as temporal_client
from apps.api.deps import AuthCtx, DbSession, TenantId
from packages.persistence import repos

router = APIRouter(prefix="/engagements", tags=["engagements"])


# -- Request / Response models -------------------------------------------------


class ScopeRuleIn(BaseModel):
    type: str = Field(
        description="dns_suffix | url_prefix | exact_host",
    )
    value: str


class ScopeIn(BaseModel):
    include: list[ScopeRuleIn] = Field(default_factory=list)
    exclude: list[ScopeRuleIn] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    redirect_policy: str = Field(default="reject")


class RulesIn(BaseModel):
    mode: str = Field(default="autonomous")
    allowed_risk_tiers: list[str] = Field(default_factory=lambda: ["R0", "R1", "R2"])
    identity_count: int = Field(default=2, ge=1, le=8)
    data_residency: str | None = None
    persistence: str = Field(default="ephemeral")


class BudgetIn(BaseModel):
    requests: int | None = None
    requests_per_second: float | None = None
    concurrent_actions: int | None = None
    bytes_received: int | None = None
    ai_cost_usd: float | None = None


class CreateEngagementRequest(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    description: str = Field(default="")
    target_url: str = Field(
        min_length=1,
        description="Base URL of the target system (e.g. http://juice-shop:3000)",
    )
    scope: ScopeIn = Field(default_factory=ScopeIn)
    rules: RulesIn = Field(default_factory=RulesIn)
    budgets: BudgetIn = Field(default_factory=BudgetIn)
    tags: dict[str, str] = Field(default_factory=dict)


class EngagementSummary(BaseModel):
    id: UUID
    name: str
    state: str
    created_at: datetime
    updated_at: datetime
    temporal_workflow_id: str | None = None
    current_revision: int | None = None
    tags: dict[str, str] = Field(default_factory=dict)


class EngagementDetail(EngagementSummary):
    description: str = ""
    target_url: str = ""
    scope: ScopeIn | None = None
    rules: RulesIn | None = None
    budgets: BudgetIn | None = None
    content_digest: str | None = None
    workflow_state: dict | None = None


class EngagementListResponse(BaseModel):
    items: list[EngagementSummary]
    total: int
    offset: int
    limit: int


# -- Endpoints -----------------------------------------------------------------


def _to_summary(row: dict) -> EngagementSummary:
    return EngagementSummary(
        id=row["id"],
        name=row["name"],
        state=row["lifecycle_state"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        temporal_workflow_id=row.get("temporal_workflow_id"),
        current_revision=row.get("revision_number"),
    )


@router.post(
    "",
    response_model=EngagementDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Create draft engagement",
)
async def create_engagement(
    body: CreateEngagementRequest,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
):
    spec = {
        "target_url": body.target_url,
        "description": body.description,
        "scope": body.scope.model_dump(),
        "rules": body.rules.model_dump(),
        "budgets": body.budgets.model_dump(),
        "tags": body.tags,
    }
    row = await repos.create_engagement(
        session,
        tenant_id=tenant_id,
        name=body.name,
        spec=spec,
        created_by=auth["user"],
    )
    await repos.record_audit_event(
        session,
        tenant_id=tenant_id,
        event_type="engagement.created",
        actor_id=auth["user"],
        engagement_id=row["id"],
        payload={"name": body.name},
    )
    return EngagementDetail(
        id=row["id"],
        name=row["name"],
        description=body.description,
        target_url=body.target_url,
        state=row["lifecycle_state"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        current_revision=row["current_revision_number"],
        content_digest=row["content_digest"],
        scope=body.scope,
        rules=body.rules,
        budgets=body.budgets,
        tags=body.tags,
    )


@router.get(
    "",
    response_model=EngagementListResponse,
    summary="List engagements",
)
async def list_engagements(
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    state: str | None = Query(default=None),
):
    rows, total = await repos.list_engagements(session, offset=offset, limit=limit, state=state)
    return EngagementListResponse(
        items=[_to_summary(r) for r in rows],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get(
    "/{engagement_id}",
    response_model=EngagementDetail,
    summary="Get engagement detail",
)
async def get_engagement(
    engagement_id: UUID,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
):
    row = await repos.get_engagement(session, engagement_id)
    if not row:
        raise HTTPException(status_code=404, detail="Engagement not found")
    spec = row.get("spec") or {}
    workflow_state = None
    if row.get("temporal_workflow_id"):
        workflow_state = await temporal_client.query_engagement_state(str(engagement_id))
        # Reconcile: workflow reports the true lifecycle; write terminal transitions
        # back to the row so lists + badges reflect reality without a background job.
        if workflow_state and workflow_state.get("lifecycle"):
            wf_state = workflow_state["lifecycle"]
            if wf_state != row["lifecycle_state"] and wf_state in (
                "COMPLETED", "FAILED", "PAUSED", "STOPPING", "REPORTING", "CLEANUP_PENDING"
            ):
                await repos.update_engagement_state(
                    session, engagement_id, lifecycle_state=wf_state
                )
                row["lifecycle_state"] = wf_state
    return EngagementDetail(
        id=row["id"],
        name=row["name"],
        state=row["lifecycle_state"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        temporal_workflow_id=row.get("temporal_workflow_id"),
        current_revision=row.get("revision_number"),
        content_digest=row.get("content_digest"),
        description=spec.get("description", ""),
        target_url=spec.get("target_url", ""),
        scope=ScopeIn(**spec["scope"]) if spec.get("scope") else None,
        rules=RulesIn(**spec["rules"]) if spec.get("rules") else None,
        budgets=BudgetIn(**spec["budgets"]) if spec.get("budgets") else None,
        tags=spec.get("tags", {}),
        workflow_state=workflow_state,
    )


@router.post(
    "/{engagement_id}:start",
    response_model=EngagementSummary,
    summary="Start engagement execution via Temporal",
)
async def start_engagement(
    engagement_id: UUID,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
):
    row = await repos.get_engagement(session, engagement_id)
    if not row:
        raise HTTPException(status_code=404, detail="Engagement not found")
    if row["lifecycle_state"] not in ("DRAFT", "READY", "SCOPE_COMPILED"):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot start from state {row['lifecycle_state']}",
        )

    spec = row.get("spec") or {}
    scope = spec.get("scope", {})
    rules = spec.get("rules", {})
    include_rules = scope.get("include") or [
        {"type": "url_prefix", "value": spec.get("target_url", "")}
    ]

    workflow_id, run_id = await temporal_client.start_engagement_workflow(
        engagement_id=str(engagement_id),
        tenant_id=str(tenant_id),
        target_url=spec.get("target_url", ""),
        scope_rules=[{"type": r["type"], "value": r["value"]} for r in include_rules],
        identity_count=int(rules.get("identity_count", 2)),
    )

    await repos.update_engagement_state(
        session,
        engagement_id,
        lifecycle_state="RUNNING",
        workflow_id=workflow_id,
        run_id=run_id,
    )
    await repos.record_audit_event(
        session,
        tenant_id=tenant_id,
        event_type="engagement.started",
        actor_id=auth["user"],
        engagement_id=engagement_id,
        payload={"workflow_id": workflow_id, "run_id": run_id},
    )

    updated = await repos.get_engagement(session, engagement_id)
    return _to_summary(updated)


@router.post(
    "/{engagement_id}:pause",
    response_model=EngagementSummary,
    summary="Pause a running engagement",
)
async def pause_engagement(
    engagement_id: UUID,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
):
    row = await repos.get_engagement(session, engagement_id)
    if not row:
        raise HTTPException(status_code=404, detail="Engagement not found")
    await temporal_client.signal_engagement(str(engagement_id), "pause_engagement")
    await repos.update_engagement_state(session, engagement_id, lifecycle_state="PAUSED")
    await repos.record_audit_event(
        session,
        tenant_id=tenant_id,
        event_type="engagement.paused",
        actor_id=auth["user"],
        engagement_id=engagement_id,
    )
    return _to_summary(await repos.get_engagement(session, engagement_id))


@router.post(
    "/{engagement_id}:resume",
    response_model=EngagementSummary,
    summary="Resume a paused engagement",
)
async def resume_engagement(
    engagement_id: UUID,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
):
    row = await repos.get_engagement(session, engagement_id)
    if not row:
        raise HTTPException(status_code=404, detail="Engagement not found")
    await temporal_client.signal_engagement(str(engagement_id), "resume_engagement")
    await repos.update_engagement_state(session, engagement_id, lifecycle_state="RUNNING")
    await repos.record_audit_event(
        session,
        tenant_id=tenant_id,
        event_type="engagement.resumed",
        actor_id=auth["user"],
        engagement_id=engagement_id,
    )
    return _to_summary(await repos.get_engagement(session, engagement_id))


@router.post(
    "/{engagement_id}:emergency-stop",
    response_model=EngagementSummary,
    summary="Emergency stop — halt all actions immediately",
)
async def emergency_stop(
    engagement_id: UUID,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
):
    row = await repos.get_engagement(session, engagement_id)
    if not row:
        raise HTTPException(status_code=404, detail="Engagement not found")
    try:
        await temporal_client.signal_engagement(str(engagement_id), "emergency_stop")
    except Exception:
        pass
    await repos.update_engagement_state(session, engagement_id, lifecycle_state="STOPPING")
    await repos.record_audit_event(
        session,
        tenant_id=tenant_id,
        event_type="engagement.emergency_stop",
        actor_id=auth["user"],
        engagement_id=engagement_id,
    )
    return _to_summary(await repos.get_engagement(session, engagement_id))
