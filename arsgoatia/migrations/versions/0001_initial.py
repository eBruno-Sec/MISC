"""initial schema: control plane, audit, and outbox with RLS + immutability

Creates the M1 tables from the ORM metadata, then layers the safety DDL the ORM
cannot express: append-only / write-once triggers and per-tenant row-level
security. Later milestones add tables in their own explicit migrations.

Revision ID: 0001
Revises:
Create Date: 2026-07-25
"""

from __future__ import annotations

from alembic import op

from domain.models import (
    WRITE_APPEND_ONLY,
    WRITE_IMMUTABLE,
    Base,
    tables_by_write_policy,
    tenant_scoped_tables,
)

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    # Tables come straight from the ORM so models are the single source of truth.
    Base.metadata.create_all(bind=bind)

    # Generic block: reject UPDATE/DELETE on immutable and append-only tables.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION arsgoatia_block_mutation() RETURNS trigger AS $$
        BEGIN
          RAISE EXCEPTION '% is % and cannot be %d',
            TG_TABLE_NAME, TG_ARGV[0], lower(TG_OP);
        END;
        $$ LANGUAGE plpgsql;
        """
    )

    # Write-once (revisions, verified records): no UPDATE, no DELETE.
    for tbl in tables_by_write_policy(WRITE_IMMUTABLE):
        op.execute(
            f"CREATE TRIGGER {tbl}_immutable BEFORE UPDATE OR DELETE ON {tbl} "
            f"FOR EACH ROW EXECUTE FUNCTION arsgoatia_block_mutation('immutable')"
        )

    # Append-only (audit): no UPDATE, no DELETE.
    for tbl in tables_by_write_policy(WRITE_APPEND_ONLY):
        if tbl == "outbox":
            continue
        op.execute(
            f"CREATE TRIGGER {tbl}_append_only BEFORE UPDATE OR DELETE ON {tbl} "
            f"FOR EACH ROW EXECUTE FUNCTION arsgoatia_block_mutation('append_only')"
        )

    # Outbox is append-only except for a one-time dispatched_at stamp by the relay:
    # the payload never changes and rows are never deleted or re-dispatched.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION arsgoatia_outbox_guard() RETURNS trigger AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'outbox is append-only';
          END IF;
          IF OLD.dispatched_at IS NOT NULL THEN
            RAISE EXCEPTION 'outbox row already dispatched';
          END IF;
          IF NEW.event_id <> OLD.event_id
             OR NEW.event_type <> OLD.event_type
             OR NEW.envelope::text <> OLD.envelope::text THEN
            RAISE EXCEPTION 'outbox payload is immutable';
          END IF;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        "CREATE TRIGGER outbox_guard BEFORE UPDATE OR DELETE ON outbox "
        "FOR EACH ROW EXECUTE FUNCTION arsgoatia_outbox_guard()"
    )

    # Per-tenant row-level security. FORCE so the table owner (the app role) is
    # also subject to isolation. Reads/writes must set app.current_tenant.
    for tbl in tenant_scoped_tables():
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
    op.execute("DROP FUNCTION IF EXISTS arsgoatia_outbox_guard() CASCADE")
    op.execute("DROP FUNCTION IF EXISTS arsgoatia_block_mutation() CASCADE")
    Base.metadata.drop_all(bind=op.get_bind())
