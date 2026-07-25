"""Request dependencies: tenant resolution, RLS-scoped DB session, object auth.

Authorization requires both a role/tenant check and a per-object tenant check
(§22). In local mode the tenant comes from the X-Tenant-Id header; RLS then
guarantees a session only sees that tenant's rows, so object lookups that return
None are treated as not-found rather than leaking existence across tenants.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from fastapi import Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from domain.db import get_sessionmaker, set_tenant


async def get_tenant_id(x_tenant_id: str = Header(..., alias="X-Tenant-Id")) -> str:
    if not x_tenant_id:
        raise HTTPException(status_code=401, detail="missing X-Tenant-Id")
    return x_tenant_id


async def get_session(x_tenant_id: str = Header(..., alias="X-Tenant-Id")) -> AsyncIterator[AsyncSession]:
    maker = get_sessionmaker()
    async with maker() as session:
        await set_tenant(session, x_tenant_id)
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
