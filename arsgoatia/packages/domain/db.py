"""Async database engine, session factory, and per-session tenant scoping.

Row-level security policies (created in the initial migration) filter on a
session GUC `app.current_tenant`. Every request/activity sets it via
`set_tenant()` so a connection can only see its tenant's rows.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import lru_cache

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from config.settings import get_settings


@lru_cache
def get_engine() -> AsyncEngine:
    settings = get_settings()
    # database_url uses the psycopg (v3) driver, which SQLAlchemy 2.0 drives
    # asynchronously under create_async_engine.
    return create_async_engine(settings.database_url, pool_pre_ping=True, future=True)


@lru_cache
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(get_engine(), expire_on_commit=False, class_=AsyncSession)


async def set_tenant(session: AsyncSession, tenant_id: str) -> None:
    """Bind the RLS tenant GUC for this session's connection."""
    await session.execute(
        text("SELECT set_config('app.current_tenant', :tid, true)"), {"tid": str(tenant_id)}
    )


@asynccontextmanager
async def session_scope(tenant_id: str | None = None) -> AsyncIterator[AsyncSession]:
    """Transactional session. Commits on success, rolls back on error."""
    maker = get_sessionmaker()
    async with maker() as session:
        try:
            if tenant_id is not None:
                await set_tenant(session, tenant_id)
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
