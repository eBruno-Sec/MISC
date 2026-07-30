"""Report read endpoints."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Query
from pydantic import BaseModel

from apps.api.deps import AuthCtx, DbSession, TenantId
from packages.persistence import repos

router = APIRouter(prefix="/reports", tags=["reports"])


class ReportSummary(BaseModel):
    id: UUID
    engagement_id: UUID
    report_type: str
    format: str
    digest: str
    storage_uri: str
    created_at: datetime


class ReportListResponse(BaseModel):
    items: list[ReportSummary]
    total: int
    offset: int
    limit: int


@router.get(
    "",
    response_model=ReportListResponse,
    summary="List reports",
)
async def list_reports(
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
    engagement_id: UUID | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
):
    rows, total = await repos.list_reports(
        session,
        engagement_id=engagement_id,
        offset=offset,
        limit=limit,
    )
    return ReportListResponse(
        items=[ReportSummary(**r) for r in rows],
        total=total,
        offset=offset,
        limit=limit,
    )
