"""Engagement lifecycle endpoints."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, HTTPException, Query, status
from pydantic import BaseModel, Field

from apps.api.deps import AuthCtx, DbSession, TenantId

router = APIRouter(prefix="/engagements", tags=["engagements"])


# -- Request / Response models -------------------------------------------------


class ScopeRuleIn(BaseModel):
    type: str = Field(description="dns_suffix | cidr | url_prefix | exact_host | repository | cloud_account")
    value: str


class ScopeIn(BaseModel):
    include: list[ScopeRuleIn] = Field(default_factory=list)
    exclude: list[ScopeRuleIn] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    redirect_policy: str = Field(default="reject")


class RulesIn(BaseModel):
    mode: str = Field(default="autonomous")
    allowed_risk_tiers: list[str] = Field(default_factory=list)
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
    current_revision: int | None = None
    tags: dict[str, str] = Field(default_factory=dict)


class EngagementDetail(EngagementSummary):
    description: str = ""
    scope: ScopeIn | None = None
    rules: RulesIn | None = None
    budgets: BudgetIn | None = None


class RevisionResponse(BaseModel):
    revision_id: UUID
    engagement_id: UUID
    revision_number: int
    content_digest: str
    created_at: datetime


class CoverageEntry(BaseModel):
    technique_id: str
    category: str
    status: str
    action_count: int


class CoverageMatrix(BaseModel):
    engagement_id: UUID
    total_techniques: int
    covered: int
    entries: list[CoverageEntry]


class EngagementListResponse(BaseModel):
    items: list[EngagementSummary]
    total: int
    offset: int
    limit: int


# -- Endpoints -----------------------------------------------------------------


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
    now = datetime.now(timezone.utc)
    engagement_id = uuid4()
    # TODO: persist via repository
    return EngagementDetail(
        id=engagement_id,
        name=body.name,
        description=body.description,
        state="DRAFT",
        created_at=now,
        updated_at=now,
        scope=body.scope,
        rules=body.rules,
        budgets=body.budgets,
        tags=body.tags,
    )


@router.post(
    "/{engagement_id}/revisions",
    response_model=RevisionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Compile immutable engagement revision",
)
async def create_revision(
    engagement_id: UUID,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
):
    now = datetime.now(timezone.utc)
    # TODO: compile from current draft state
    return RevisionResponse(
        revision_id=uuid4(),
        engagement_id=engagement_id,
        revision_number=1,
        content_digest="sha256:placeholder",
        created_at=now,
    )


@router.post(
    "/{engagement_id}:start",
    response_model=EngagementSummary,
    summary="Start engagement execution",
)
async def start_engagement(
    engagement_id: UUID,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
):
    now = datetime.now(timezone.utc)
    # TODO: trigger Temporal workflow
    return EngagementSummary(
        id=engagement_id,
        name="",
        state="RUNNING",
        created_at=now,
        updated_at=now,
    )


@router.post(
    "/{engagement_id}:pause",
    response_model=EngagementSummary,
    summary="Pause running engagement",
)
async def pause_engagement(
    engagement_id: UUID,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
):
    now = datetime.now(timezone.utc)
    # TODO: signal Temporal workflow
    return EngagementSummary(
        id=engagement_id,
        name="",
        state="PAUSED",
        created_at=now,
        updated_at=now,
    )


@router.post(
    "/{engagement_id}:resume",
    response_model=EngagementSummary,
    summary="Resume paused engagement",
)
async def resume_engagement(
    engagement_id: UUID,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
):
    now = datetime.now(timezone.utc)
    # TODO: signal Temporal workflow
    return EngagementSummary(
        id=engagement_id,
        name="",
        state="RUNNING",
        created_at=now,
        updated_at=now,
    )


@router.post(
    "/{engagement_id}:emergency-stop",
    response_model=EngagementSummary,
    summary="Emergency stop -- halt all actions immediately",
)
async def emergency_stop(
    engagement_id: UUID,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
):
    now = datetime.now(timezone.utc)
    # TODO: cancel Temporal workflow + cleanup
    return EngagementSummary(
        id=engagement_id,
        name="",
        state="STOPPING",
        created_at=now,
        updated_at=now,
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
    # TODO: fetch from repository
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Engagement not found")


@router.get(
    "/{engagement_id}/coverage",
    response_model=CoverageMatrix,
    summary="Get coverage matrix for engagement",
)
async def get_coverage(
    engagement_id: UUID,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
):
    # TODO: compute coverage from executed actions
    return CoverageMatrix(
        engagement_id=engagement_id,
        total_techniques=0,
        covered=0,
        entries=[],
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
    # TODO: paginated query
    return EngagementListResponse(items=[], total=0, offset=offset, limit=limit)
