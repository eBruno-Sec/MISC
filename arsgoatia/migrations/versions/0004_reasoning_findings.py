"""reasoning, validation, findings, capabilities

Adds the M4 tables. observation/action_proposal/approval/action_execution/
tool_execution are append-only; capability is write-once (immutable); hypothesis/
validation_plan/finding are mutable heads. All tenant-scoped with RLS. Reuses the
arsgoatia_block_mutation function from 0001.

Revision ID: 0004
Revises: 0003
Create Date: 2026-07-25
"""

from __future__ import annotations

from alembic import op

from domain.models import (
    WRITE_APPEND_ONLY,
    WRITE_IMMUTABLE,
    Base,
    tables_by_write_policy,
    tables_for_migration,
    tenant_scoped_tables,
)

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

_OWN = set(tables_for_migration("0004"))


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(
        bind=bind, tables=[Base.metadata.tables[name] for name in sorted(_OWN)]
    )

    for tbl in tables_by_write_policy(WRITE_IMMUTABLE):
        if tbl not in _OWN:
            continue
        op.execute(
            f"CREATE TRIGGER {tbl}_immutable BEFORE UPDATE OR DELETE ON {tbl} "
            f"FOR EACH ROW EXECUTE FUNCTION arsgoatia_block_mutation('immutable')"
        )

    for tbl in tables_by_write_policy(WRITE_APPEND_ONLY):
        if tbl not in _OWN:
            continue
        op.execute(
            f"CREATE TRIGGER {tbl}_append_only BEFORE UPDATE OR DELETE ON {tbl} "
            f"FOR EACH ROW EXECUTE FUNCTION arsgoatia_block_mutation('append_only')"
        )

    for tbl in tenant_scoped_tables():
        if tbl not in _OWN:
            continue
        op.execute(f"ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {tbl} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY {tbl}_tenant_isolation ON {tbl}
              USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
              WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid)
            """
        )


def downgrade() -> None:
    Base.metadata.drop_all(
        bind=op.get_bind(), tables=[Base.metadata.tables[name] for name in sorted(_OWN)]
    )
