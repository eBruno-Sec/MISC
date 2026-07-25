"""ORM metadata + write-policy classification (drift guard for the migration)."""

from __future__ import annotations

from domain.models import (
    WRITE_APPEND_ONLY,
    WRITE_IMMUTABLE,
    Base,
    tables_by_write_policy,
    tenant_scoped_tables,
)

EXPECTED_TABLES = {
    "tenant",
    "app_user",
    "team",
    "assessment",
    "assessment_revision",
    "authorization_record",
    "scope_definition",
    "scope_target",
    "policy",
    "policy_revision",
    "workflow_record",
    "module_definition",
    "audit_event",
    "outbox",
}


def test_all_m1_tables_present():
    assert EXPECTED_TABLES <= set(Base.metadata.tables)


def test_immutable_tables_classified():
    assert set(tables_by_write_policy(WRITE_IMMUTABLE)) == {
        "assessment_revision",
        "authorization_record",
        "scope_definition",
        "scope_target",
        "policy_revision",
    }


def test_append_only_tables_classified():
    # evidence joins audit_event + outbox as append-only in M2 (§16).
    assert set(tables_by_write_policy(WRITE_APPEND_ONLY)) == {"audit_event", "outbox", "evidence"}


def test_tenant_scoping_excludes_root_tables():
    scoped = set(tenant_scoped_tables())
    # tenant is the RLS root; module_definition is a global catalog — neither is
    # tenant-scoped.
    assert "tenant" not in scoped
    assert "module_definition" not in scoped
    # Everything carrying tenant_id must be covered by RLS.
    assert {"assessment", "audit_event", "outbox", "scope_target", "policy_revision"} <= scoped
