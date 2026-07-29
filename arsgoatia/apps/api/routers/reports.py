"""Report generation and artifact retrieval endpoints."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID, uuid4

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field

from apps.api.deps import AuthCtx, DbSession, TenantId

router = APIRouter(prefix="/reports", tags=["reports"])


# -- Request / Response models -------------------------------------------------


class CreateReportRequest(BaseModel):
    engagement_id: UUID
    title: str = Field(min_length=1, max_length=512)
    format: str = Field(default="pdf", description="pdf | html | json")
    include_evidence: bool = Field(default=True)
    include_remediation: bool = Field(default=True)
    classification: str = Field(default="internal")


class ReportSummary(BaseModel):
    id: UUID
    engagement_id: UUID
    title: str
    format: str
    state: str
    content_digest: str | None = None
    classification: str
    created_at: datetime
    frozen_at: datetime | None = None


class ReportArtifact(BaseModel):
    artifact_id: UUID
    report_id: UUID
    media_type: str
    size: int
    digest: str
    download_url: str


class ReportArtifactsResponse(BaseModel):
    report_id: UUID
    artifacts: list[ReportArtifact]


# -- Endpoints -----------------------------------------------------------------


@router.post(
    "",
    response_model=ReportSummary,
    status_code=status.HTTP_201_CREATED,
    summary="Create a frozen report from engagement data",
)
async def create_report(
    body: CreateReportRequest,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
):
    now = datetime.now(timezone.utc)
    report_id = uuid4()

    # TODO: snapshot engagement findings/evidence, render report, freeze
    return ReportSummary(
        id=report_id,
        engagement_id=body.engagement_id,
        title=body.title,
        format=body.format,
        state="GENERATING",
        classification=body.classification,
        created_at=now,
    )


@router.get(
    "/{report_id}/artifacts",
    response_model=ReportArtifactsResponse,
    summary="Get downloadable artifacts for a frozen report",
)
async def get_report_artifacts(
    report_id: UUID,
    tenant_id: TenantId,
    session: DbSession,
    auth: AuthCtx,
):
    # TODO: look up report, verify frozen, return pre-signed artifact URLs
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Report not found",
    )
