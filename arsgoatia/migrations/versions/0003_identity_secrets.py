"""identity/access tables + dev secret store

Adds identity, credential_reference, session, access_context, and the dev-only
secret table (ADR 0003). All are tenant-scoped and get row-level security; none
are append-only.

Revision ID: 0003
Revises: 0002
Create Date: 2026-07-25
"""

from __future__ import annotations

from alembic import op

from domain.models import Base, tables_for_migration, tenant_scoped_tables

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

_OWN = set(tables_for_migration("0003"))


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(
        bind=bind, tables=[Base.metadata.tables[name] for name in sorted(_OWN)]
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
