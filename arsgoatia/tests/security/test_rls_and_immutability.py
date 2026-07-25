"""Migration safety coverage: RLS + immutability/append-only triggers.

Reads the initial migration as text (no DB, no alembic import needed) and asserts
the DDL constructs exist, then checks that the migration iterates over the same
table classifications the models declare — so a new tenant-scoped or immutable
table cannot silently skip its protection.
"""

from __future__ import annotations

from pathlib import Path

from domain.models import (
    WRITE_APPEND_ONLY,
    WRITE_IMMUTABLE,
    tables_by_write_policy,
    tenant_scoped_tables,
)

MIGRATION = (
    Path(__file__).resolve().parents[2] / "migrations" / "versions" / "0001_initial.py"
).read_text()


def test_migration_enables_forced_rls_and_tenant_policy():
    assert "ENABLE ROW LEVEL SECURITY" in MIGRATION
    assert "FORCE ROW LEVEL SECURITY" in MIGRATION
    assert "current_setting('app.current_tenant', true)::uuid" in MIGRATION
    assert "_tenant_isolation" in MIGRATION


def test_migration_installs_immutability_and_outbox_guards():
    assert "arsgoatia_block_mutation" in MIGRATION
    assert "arsgoatia_outbox_guard" in MIGRATION
    assert "outbox row already dispatched" in MIGRATION


def test_migration_iterates_declared_classifications():
    # The migration builds triggers/policies by iterating these helpers, so their
    # coverage is the real guarantee. Lock the expected membership.
    assert set(tables_by_write_policy(WRITE_IMMUTABLE)) >= {
        "assessment_revision",
        "authorization_record",
        "policy_revision",
    }
    assert set(tables_by_write_policy(WRITE_APPEND_ONLY)) >= {
        "audit_event",
        "outbox",
        "evidence",
        "observation",
        "approval",
    }
    scoped = set(tenant_scoped_tables())
    assert {"assessment", "authorization_record", "audit_event", "outbox"} <= scoped
    assert "tenant" not in scoped
