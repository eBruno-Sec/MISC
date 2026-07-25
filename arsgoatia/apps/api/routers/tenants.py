"""Tenant bootstrap (dev). The tenant table is not tenant-scoped (it is the root
of the RLS hierarchy), so this endpoint does not require X-Tenant-Id."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from domain.db import session_scope
from domain.models import Tenant

router = APIRouter(prefix="/api/v1/tenants", tags=["tenants"])


class CreateTenant(BaseModel):
    name: str


@router.post("")
async def create_tenant(body: CreateTenant) -> dict:
    async with session_scope() as session:
        tenant = Tenant(name=body.name)
        session.add(tenant)
        await session.flush()
        return {"id": str(tenant.id), "name": tenant.name}
