"""Evidence read endpoints."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from apps.api.deps import AuthCtx, DbSession, TenantId
from packages.persistence import repos

router = APIRouter(prefix="/evidence", tags=["evidence"])


class EvidenceMetadata(BaseModel):
    id: UUID
    engagement_id: UUID
    action_id: UUID
    kind: str
    digest: str
    size_bytes: int
    media_type: str
    storage_uri: str
    sensitivity: str
    created_at: datetime


class EvidenceListResponse(BaseModel):
    items: list[EvidenceMetadata]
    total: int
    offset: int
    limit: int


def _to_metadata(row: dict) -> EvidenceMetadata:
    return EvidenceMetadata(
        id=row["id"],
        engagement_id=row["engagement_id"],
        action_id=row["action_id"],
        kind=row["kind"],
        digest=row["digest"],
        size_bytes=row["size_bytes"],
        media_type=row["media_type"],
        storage_uri=row["storage_uri"],
        sensitivity=row["sensitivity"],
        created_at=row["created_at"],
    )


@router.get(
    "",
    response_model=EvidenceListResponse,
    summary="List evidence artifacts",
)
async def list_evidence(
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
    engagement_id: UUID | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
):
    rows, total = await repos.list_evidence(
        session,
        engagement_id=engagement_id,
        offset=offset,
        limit=limit,
    )
    return EvidenceListResponse(
        items=[_to_metadata(r) for r in rows],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get(
    "/{evidence_id}",
    response_model=EvidenceMetadata,
    summary="Get evidence artifact metadata",
)
async def get_evidence(
    evidence_id: UUID,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
):
    row = await repos.get_evidence(session, evidence_id)
    if not row:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return _to_metadata(row)
