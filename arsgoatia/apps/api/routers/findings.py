"""Finding management endpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, Query, status
from pydantic import BaseModel, Field

from apps.api.deps import AuthCtx, DbSession, TenantId

router = APIRouter(prefix="/findings", tags=["findings"])


# -- Request / Response models -------------------------------------------------


class FindingSummary(BaseModel):
    id: UUID
    engagement_id: UUID
    weakness: str
    affected_object: str
    severity: float = Field(ge=0, le=10)
    confidence: float = Field(ge=0, le=1)
    state: str
    evidence_count: int = 0
    created_at: datetime


class FindingDetail(FindingSummary):
    root_cause: str | None = None
    evidence_refs: list[UUID] = Field(default_factory=list)
    validator_digest: str | None = None
    evidence_profile_version: str | None = None
    updated_at: datetime | None = None


class FindingListResponse(BaseModel):
    items: list[FindingSummary]
    total: int
    offset: int
    limit: int


class AcceptRiskRequest(BaseModel):
    justification: str = Field(min_length=1, max_length=4000)
    accepted_by: str = Field(default="")
    review_date: datetime | None = None


class AcceptRiskResponse(BaseModel):
    id: UUID
    state: str
    justification: str
    accepted_by: str
    accepted_at: datetime


class RetestRequest(BaseModel):
    engagement_id: UUID | None = None
    notes: str = Field(default="", max_length=2000)


class RetestResponse(BaseModel):
    retest_id: UUID
    finding_id: UUID
    state: str
    created_at: datetime


# -- Endpoints -----------------------------------------------------------------


@router.get(
    "",
    response_model=FindingListResponse,
    summary="List findings with filtering",
)
async def list_findings(
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
    engagement_id: UUID | None = Query(default=None),
    state: str | None = Query(default=None),
    min_severity: float | None = Query(default=None, ge=0, le=10),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
):
    # TODO: paginated query with filters
    return FindingListResponse(items=[], total=0, offset=offset, limit=limit)


@router.post(
    "/{finding_id}:accept-risk",
    response_model=AcceptRiskResponse,
    summary="Accept risk for a confirmed finding",
)
async def accept_risk(
    finding_id: UUID,
    body: AcceptRiskRequest,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
):
    now = datetime.now(timezone.utc)
    # TODO: verify finding exists, transition to ACCEPTED_RISK, emit audit event
    return AcceptRiskResponse(
        id=finding_id,
        state="ACCEPTED_RISK",
        justification=body.justification,
        accepted_by=body.accepted_by or auth["user"],
        accepted_at=now,
    )


@router.post(
    "/{finding_id}:retest",
    response_model=RetestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a retest for a finding",
)
async def create_retest(
    finding_id: UUID,
    body: RetestRequest,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
):
    now = datetime.now(timezone.utc)
    # TODO: create retest engagement or action
    return RetestResponse(
        retest_id=uuid4(),
        finding_id=finding_id,
        state="RETEST_PENDING",
        created_at=now,
    )
