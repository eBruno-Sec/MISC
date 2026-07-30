"""Evidence upload and retrieval endpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field

from apps.api.deps import AuthCtx, DbSession, TenantId

router = APIRouter(prefix="/evidence", tags=["evidence"])


# -- Request / Response models -------------------------------------------------


class CreateUploadGrantRequest(BaseModel):
    engagement_id: UUID
    action_id: UUID
    kind: str = Field(
        min_length=1, description="Evidence kind: request, response, screenshot, pcap, etc."
    )
    media_type: str = Field(default="application/octet-stream")
    size_hint: int | None = Field(default=None, ge=0, description="Expected size in bytes")
    sensitivity: str = Field(default="restricted")


class UploadGrant(BaseModel):
    evidence_id: UUID
    upload_url: str = Field(description="Pre-signed MinIO PUT URL")
    upload_headers: dict[str, str] = Field(default_factory=dict)
    expires_at: datetime
    max_bytes: int


class EvidenceMetadata(BaseModel):
    evidence_id: UUID
    engagement_id: UUID
    action_id: UUID
    kind: str
    media_type: str
    size: int
    digest: str
    sensitivity: str
    captured_at: datetime
    storage_uri: str


class ArtifactGrant(BaseModel):
    evidence_id: UUID
    download_url: str = Field(description="Pre-signed MinIO GET URL")
    expires_at: datetime
    media_type: str
    size: int


# -- Endpoints -----------------------------------------------------------------


@router.post(
    "/uploads",
    response_model=UploadGrant,
    status_code=status.HTTP_201_CREATED,
    summary="Create an upload grant for evidence submission",
)
async def create_upload_grant(
    body: CreateUploadGrantRequest,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
):
    now = datetime.now(timezone.utc)
    evidence_id = uuid4()

    # TODO: generate MinIO pre-signed PUT URL, record pending upload
    return UploadGrant(
        evidence_id=evidence_id,
        upload_url=f"http://localhost:9100/arsgoatia-evidence/{evidence_id}",
        upload_headers={"Content-Type": body.media_type},
        expires_at=now,
        max_bytes=100 * 1024 * 1024,  # 100 MiB default
    )


@router.get(
    "/{evidence_id}",
    summary="Get evidence metadata or artifact download grant",
)
async def get_evidence(
    evidence_id: UUID,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
    artifact: bool = False,
):
    # TODO: look up evidence record

    if artifact:
        # Return a download grant
        now = datetime.now(timezone.utc)
        return ArtifactGrant(
            evidence_id=evidence_id,
            download_url=f"http://localhost:9100/arsgoatia-evidence/{evidence_id}",
            expires_at=now,
            media_type="application/octet-stream",
            size=0,
        )

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Evidence not found",
    )
