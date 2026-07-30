"""Shared FastAPI dependencies for ArsGoatia API."""

from __future__ import annotations

import os
from typing import Annotated, AsyncGenerator
from uuid import UUID

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

DATABASE_URL = os.environ.get(
    "ARSGOATIA_DATABASE_URL",
    os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://arsgoatia:arsgoatia@localhost:5433/arsgoatia",
    ),
)

engine = create_async_engine(DATABASE_URL, echo=False, pool_size=10, max_overflow=20)
async_session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


# -- Tenant -------------------------------------------------------------------


async def get_tenant_id(
    request: Request,
    x_tenant_id: Annotated[str | None, Header(alias="X-Tenant-Id")] = None,
) -> UUID:
    if x_tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing tenant identifier",
        )
    try:
        return UUID(x_tenant_id)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail="X-Tenant-Id must be a valid UUID",
        )


# -- Database session with RLS ------------------------------------------------


async def get_session(
    tenant_id: Annotated[UUID, Depends(get_tenant_id)],
) -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        await session.execute(
            text("SELECT set_config('app.tenant_id', :tid, true)"),
            {"tid": str(tenant_id)},
        )
        try:
            yield session
        finally:
            await session.close()


# -- Auth context --------------------------------------------------------------


async def require_auth(
    request: Request,
    x_auth_user: Annotated[str | None, Header(alias="X-Auth-User")] = None,
    x_auth_role: Annotated[str | None, Header(alias="X-Auth-Role")] = None,
) -> dict:
    user = x_auth_user or "dev-operator"
    role = x_auth_role or "admin"
    return {
        "user": user,
        "role": role,
        "source": "header",
    }


# -- Convenience type aliases --------------------------------------------------

TenantId = Annotated[UUID, Depends(get_tenant_id)]
DbSession = Annotated[AsyncSession, Depends(get_session)]
AuthCtx = Annotated[dict, Depends(require_auth)]
