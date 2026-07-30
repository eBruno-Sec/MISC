"""Immutable audit log endpoints."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from apps.api.deps import AuthCtx, DbSession, TenantId

router = APIRouter(prefix="/audit", tags=["audit"])


# -- Response models -----------------------------------------------------------


class AuditEvent(BaseModel):
    event_id: UUID
    event_type: str
    tenant_id: UUID
    aggregate_type: str
    aggregate_id: UUID
    actor: str
    occurred_at: datetime
    classification: str = Field(default="internal")
    payload: dict[str, object] = Field(default_factory=dict)
    correlation_id: UUID | None = None
    causation_id: UUID | None = None


class AuditEventListResponse(BaseModel):
    items: list[AuditEvent]
    total: int
    offset: int
    limit: int
    has_more: bool


# -- Endpoints -----------------------------------------------------------------


@router.get(
    "/events",
    response_model=AuditEventListResponse,
    summary="Query the immutable audit log",
)
async def list_audit_events(
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
    engagement_id: UUID | None = Query(default=None),
    event_type: str | None = Query(default=None),
    actor: str | None = Query(default=None),
    after: datetime | None = Query(default=None, description="Events after this timestamp"),
    before: datetime | None = Query(default=None, description="Events before this timestamp"),
    aggregate_type: str | None = Query(default=None),
    aggregate_id: UUID | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=1000),
):
    # TODO: query append-only audit event store with filters
    return AuditEventListResponse(
        items=[],
        total=0,
        offset=offset,
        limit=limit,
        has_more=False,
    )
