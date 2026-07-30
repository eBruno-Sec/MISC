"""Capability Pack registry endpoint.

Exposes the platform's compiled offensive capability catalogue — one
entry per discovered ``*.capability.yaml``. Read-only, unauthenticated
enough for the UI to render without a tenant (still respects the
X-Tenant-Id contract on the router since AuthCtx is dev-friendly).
"""
from __future__ import annotations

from fastapi import APIRouter, Query
from pydantic import BaseModel

from packages.capabilities import CapabilityPack, get_registry

router = APIRouter(prefix="/capabilities", tags=["capabilities"])


class CapabilityListResponse(BaseModel):
    total: int
    items: list[CapabilityPack]


@router.get(
    "",
    response_model=CapabilityListResponse,
    summary="List all capability packs the platform can execute",
)
async def list_capabilities(
    severity: str | None = Query(default=None),
    risk_tier: str | None = Query(default=None),
):
    packs = get_registry()
    if severity:
        packs = [p for p in packs if p.classification.severity == severity]
    if risk_tier:
        packs = [p for p in packs if p.classification.risk_tier == risk_tier]
    return CapabilityListResponse(total=len(packs), items=packs)
