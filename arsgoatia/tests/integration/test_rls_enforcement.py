"""Row-level security enforcement — real Postgres required.

Asserts the spec invariant: with RLS enabled + FORCE ROW LEVEL SECURITY,
no session set to tenant A can ever read or write rows belonging to
tenant B, regardless of the SQL issued.

Skipped when no reachable Postgres is available (unit-test contexts).
"""
from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

DATABASE_URL = os.environ.get(
    "ARSGOATIA_TEST_DATABASE_URL",
    os.environ.get(
        "ARSGOATIA_DATABASE_URL",
        "postgresql+asyncpg://arsgoatia:arsgoatia@postgres:5432/arsgoatia",
    ),
)


async def _reachable() -> bool:
    try:
        engine = create_async_engine(DATABASE_URL, echo=False)
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        await engine.dispose()
    except Exception:
        return False
    return True


@pytest_asyncio.fixture(scope="module")
async def engine():
    if not await _reachable():
        pytest.skip(f"Postgres not reachable at {DATABASE_URL}")
    eng = create_async_engine(DATABASE_URL, echo=False)
    yield eng
    await eng.dispose()


async def _set_tenant(conn, tenant_id: str) -> None:
    await conn.execute(
        text("SELECT set_config('app.tenant_id', :tid, true)"),
        {"tid": tenant_id},
    )


async def _insert_engagement(conn, tenant_id: str, name: str) -> str:
    eng_id = str(uuid.uuid4())
    await conn.execute(
        text(
            """
            INSERT INTO governance.engagement (id, tenant_id, name, lifecycle_state)
            VALUES (:id, :tid, :name, 'DRAFT')
            """
        ),
        {"id": eng_id, "tid": tenant_id, "name": name},
    )
    return eng_id


@pytest.mark.asyncio
async def test_tenant_a_cannot_read_tenant_b_engagements(engine):
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())

    # Insert one row per tenant.
    async with engine.begin() as conn:
        await _set_tenant(conn, tenant_a)
        a_eng = await _insert_engagement(conn, tenant_a, "tenant-a-secret-work")
    async with engine.begin() as conn:
        await _set_tenant(conn, tenant_b)
        b_eng = await _insert_engagement(conn, tenant_b, "tenant-b-secret-work")

    # Reading under tenant A must only see tenant A's row.
    async with engine.connect() as conn:
        await _set_tenant(conn, tenant_a)
        rows = (
            await conn.execute(
                text("SELECT id, name FROM governance.engagement"),
            )
        ).all()
        ids = {str(r._mapping["id"]) for r in rows}
        names = {r._mapping["name"] for r in rows}
        assert a_eng in ids
        assert b_eng not in ids
        assert "tenant-b-secret-work" not in names


@pytest.mark.asyncio
async def test_tenant_a_cannot_write_row_owned_by_tenant_b(engine):
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    forged_id = str(uuid.uuid4())

    async with engine.connect() as conn:
        await _set_tenant(conn, tenant_a)
        # Attempt to insert a row claiming to belong to tenant_b while the
        # session is bound to tenant_a. FORCE ROW LEVEL SECURITY + a USING-
        # only policy means the insert either fails or lands invisibly.
        with pytest.raises(Exception):
            async with conn.begin():
                await conn.execute(
                    text(
                        """
                        INSERT INTO governance.engagement (id, tenant_id, name, lifecycle_state)
                        VALUES (:id, :tid, 'forged', 'DRAFT')
                        """
                    ),
                    {"id": forged_id, "tid": tenant_b},
                )

    # And under tenant_b, the forged row must not be visible.
    async with engine.connect() as conn:
        await _set_tenant(conn, tenant_b)
        r = (
            await conn.execute(
                text("SELECT COUNT(*) FROM governance.engagement WHERE id = :id"),
                {"id": forged_id},
            )
        ).scalar_one()
        assert r == 0


@pytest.mark.asyncio
async def test_no_tenant_set_reads_nothing(engine):
    async with engine.begin() as conn:
        await _set_tenant(conn, str(uuid.uuid4()))
        await _insert_engagement(conn, str(uuid.uuid4()), "seeded-for-noread")

    async with engine.connect() as conn:
        # Do NOT call _set_tenant — RLS should fail closed.
        with pytest.raises(Exception):
            await conn.execute(text("SELECT * FROM governance.engagement"))
