"""Finding read endpoints."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.deps import AuthCtx, DbSession, TenantId
from packages.persistence import repos

router = APIRouter(prefix="/findings", tags=["findings"])


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
    title: str = ""
    evidence_refs: list[str] = Field(default_factory=list)
    capability_refs: list[str] = Field(default_factory=list)
    updated_at: datetime | None = None


class FindingListResponse(BaseModel):
    items: list[FindingSummary]
    total: int
    offset: int
    limit: int


def _severity_num(sev: str | None) -> float:
    m = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 1.0}
    if not sev:
        return 0.0
    return m.get(sev.lower(), 0.0)


def _to_summary(row: dict) -> FindingSummary:
    evidence_refs = row.get("evidence_refs") or []
    return FindingSummary(
        id=row["id"],
        engagement_id=row["engagement_id"],
        weakness=row["technique_id"],
        affected_object=row["target"],
        severity=_severity_num(row.get("severity")),
        confidence=1.0 if row.get("state") == "CONFIRMED" else 0.5,
        state=row["state"],
        evidence_count=len(evidence_refs),
        created_at=row["created_at"],
    )


@router.get(
    "",
    response_model=FindingListResponse,
    summary="List findings with filters",
)
async def list_findings(
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
    engagement_id: UUID | None = Query(default=None),
    state: str | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
):
    rows, total = await repos.list_findings(
        session,
        engagement_id=engagement_id,
        state=state,
        offset=offset,
        limit=limit,
    )
    return FindingListResponse(
        items=[_to_summary(r) for r in rows],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get(
    "/{finding_id}",
    response_model=FindingDetail,
    summary="Get finding detail",
)
async def get_finding(
    finding_id: UUID,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
):
    row = await repos.get_finding(session, finding_id)
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")
    summary = _to_summary(row)
    return FindingDetail(
        **summary.model_dump(),
        title=row.get("title", ""),
        evidence_refs=row.get("evidence_refs") or [],
        capability_refs=row.get("capability_refs") or [],
        updated_at=row.get("updated_at"),
    )
