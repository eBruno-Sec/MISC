"""Shared FastAPI dependencies for ArsGoatia API."""

from __future__ import annotations

import os
from typing import Annotated, AsyncGenerator
from uuid import UUID

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from apps.api.auth import AuthError, verify_token

DATABASE_URL = os.environ.get(
    "ARSGOATIA_DATABASE_URL",
    os.environ.get(
        "DATABASE_URL",
        "postgresql+asyncpg://arsgoatia:arsgoatia@localhost:5433/arsgoatia",
    ),
)

engine = create_async_engine(DATABASE_URL, echo=False, pool_size=10, max_overflow=20)
async_session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


# -- Auth context --------------------------------------------------------------


async def require_auth(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_auth_user: Annotated[str | None, Header(alias="X-Auth-User")] = None,
    x_auth_role: Annotated[str | None, Header(alias="X-Auth-Role")] = None,
) -> dict:
    """Return an auth context.

    Preference order:
      1. ``Authorization: Bearer <jwt>`` — verified against the shared HS256 key
      2. Legacy ``X-Auth-User`` / ``X-Auth-Role`` headers (dev only)
      3. Fall through to a ``dev-operator/admin`` context

    The third path is intentional for the local Compose stack; production
    deployments should set ``ARSGOATIA_REQUIRE_AUTH=1`` to disable it.
    """
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        try:
            claims = verify_token(token)
        except AuthError as exc:
            raise HTTPException(status_code=401, detail=f"invalid token: {exc}")
        return {
            "user": claims.get("sub", ""),
            "role": claims.get("role", "operator"),
            "source": "jwt",
            "claims": claims,
        }
    if os.environ.get("ARSGOATIA_REQUIRE_AUTH") == "1":
        raise HTTPException(status_code=401, detail="Authorization: Bearer <jwt> required")
    return {
        "user": x_auth_user or "dev-operator",
        "role": x_auth_role or "admin",
        "source": "header",
    }


# -- Tenant -------------------------------------------------------------------


async def get_tenant_id(
    request: Request,
    x_tenant_id: Annotated[str | None, Header(alias="X-Tenant-Id")] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> UUID:
    """Extract tenant id.

    Prefer the ``tenant_id`` claim on a verified JWT. Fall back to
    ``X-Tenant-Id`` header for the dev workflow.
    """
    tid_str: str | None = None
    if authorization and authorization.lower().startswith("bearer "):
        try:
            claims = verify_token(authorization.split(" ", 1)[1].strip())
            tid_str = claims.get("tenant_id")
        except AuthError:
            pass
    if not tid_str:
        tid_str = x_tenant_id
    if tid_str is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing tenant identifier",
        )
    try:
        return UUID(tid_str)
    except ValueError:
        raise HTTPException(status_code=422, detail="tenant id must be a valid UUID")


# -- Database session with RLS ------------------------------------------------


async def get_session(
    tenant_id: Annotated[UUID, Depends(get_tenant_id)],
) -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        try:
            await session.begin()
            await session.execute(
                text("SELECT set_config('app.tenant_id', :tid, true)"),
                {"tid": str(tenant_id)},
            )
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


TenantId = Annotated[UUID, Depends(get_tenant_id)]
DbSession = Annotated[AsyncSession, Depends(get_session)]
AuthCtx = Annotated[dict, Depends(require_auth)]
