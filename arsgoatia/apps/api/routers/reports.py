"""Report read + download endpoints."""

from __future__ import annotations

import io
import os
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from apps.api.deps import AuthCtx, DbSession, TenantId
from packages.persistence import repos

router = APIRouter(prefix="/reports", tags=["reports"])

MINIO_ENDPOINT = os.environ.get("ARSGOATIA_MINIO_ENDPOINT", "minio:9000")
MINIO_ACCESS_KEY = os.environ.get("ARSGOATIA_MINIO_ACCESS_KEY", "arsgoatia")
MINIO_SECRET_KEY = os.environ.get("ARSGOATIA_MINIO_SECRET_KEY", "arsgoatia-dev-secret")
MINIO_BUCKET = os.environ.get("ARSGOATIA_MINIO_BUCKET", "arsgoatia-evidence")

_MEDIA_TYPES = {
    "json": "application/json",
    "html": "text/html",
    "sarif": "application/sarif+json",
    "pdf": "application/pdf",
}


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


async def _fetch_report_bytes(digest: str) -> bytes:
    """Look up a stored report artifact in MinIO by its SHA-256 digest."""
    import miniopy_async  # noqa: PLC0415

    client = miniopy_async.Minio(
        MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=False,
    )
    expected = digest.removeprefix("sha256:")
    async for obj in client.list_objects(MINIO_BUCKET, recursive=True):
        if obj.object_name and obj.object_name.endswith(f"/{expected}"):
            resp = await client.get_object(MINIO_BUCKET, obj.object_name)
            try:
                data = await resp.read()
            finally:
                resp.close()
                await resp.release()
            return data
    raise HTTPException(status_code=404, detail="Report bytes not found in object store")


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


@router.get(
    "/{report_id}/download",
    summary="Stream a report artifact from object storage",
)
async def download_report(
    report_id: UUID,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
):
    rows, _ = await repos.list_reports(session, limit=500)
    match = next((r for r in rows if r["id"] == report_id), None)
    if not match:
        raise HTTPException(status_code=404, detail="Report not found")
    data = await _fetch_report_bytes(match["digest"])
    media = _MEDIA_TYPES.get(match["format"], "application/octet-stream")
    filename = f"arsgoatia-report-{report_id}.{match['format']}"
    return StreamingResponse(
        io.BytesIO(data),
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
