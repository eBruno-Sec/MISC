"""ArsGoatia evidence service — content-addressed immutable artifact storage."""

from __future__ import annotations

import hashlib
from typing import Any
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field

app = FastAPI(title="ArsGoatia Evidence Service", version="0.1.0")


class StoreRequest(BaseModel):
    tenant_id: UUID
    action_id: UUID
    media_type: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class StoreResponse(BaseModel):
    digest: str
    size: int
    storage_uri: str


class ArtifactMetadata(BaseModel):
    digest: str
    size: int
    media_type: str
    tenant_id: UUID
    action_id: UUID | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/evidence", response_model=StoreResponse)
async def store_evidence(request: Request, meta: StoreRequest) -> StoreResponse:
    body = await request.body()
    if not body:
        raise HTTPException(status_code=400, detail="empty body")

    digest = "sha256:" + hashlib.sha256(body).hexdigest()
    size = len(body)
    storage_uri = f"evidence://{meta.tenant_id}/{digest}"

    return StoreResponse(digest=digest, size=size, storage_uri=storage_uri)


@app.get("/api/v1/evidence/{tenant_id}/{digest}")
async def get_evidence(tenant_id: UUID, digest: str) -> Response:
    raise HTTPException(status_code=404, detail="not found (stub)")


@app.get("/api/v1/evidence/{tenant_id}/{digest}/metadata", response_model=ArtifactMetadata)
async def get_metadata(tenant_id: UUID, digest: str) -> ArtifactMetadata:
    raise HTTPException(status_code=404, detail="not found (stub)")
