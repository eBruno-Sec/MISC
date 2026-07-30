"""Immutable audit log endpoints."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from apps.api.deps import AuthCtx, DbSession, TenantId
from packages.persistence import repos

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditEvent(BaseModel):
    id: UUID
    event_type: str
    tenant_id: UUID
    engagement_id: UUID | None = None
    actor_id: str | None = None
    payload: dict = Field(default_factory=dict)
    created_at: datetime


class AuditEventListResponse(BaseModel):
    items: list[AuditEvent]
    total: int
    offset: int
    limit: int


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
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=1000),
):
    rows, total = await repos.list_audit_events(
        session,
        engagement_id=engagement_id,
        event_type=event_type,
        offset=offset,
        limit=limit,
    )
    return AuditEventListResponse(
        items=[AuditEvent(**r) for r in rows],
        total=total,
        offset=offset,
        limit=limit,
    )
