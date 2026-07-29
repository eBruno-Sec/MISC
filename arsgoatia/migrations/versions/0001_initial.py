"""Initial schema with RLS and immutability triggers.

Revision ID: 0001
Revises:
Create Date: 2026-07-29
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

SCHEMAS = [
    "iam",
    "governance",
    "knowledge",
    "reasoning",
    "execution",
    "evidence",
    "findings",
    "reporting",
    "remediation",
    "audit",
]

IMMUTABLE_TABLES = [
    ("governance", "engagement_revision"),
    ("governance", "authorization_verification"),
    ("governance", "scope_revision"),
    ("governance", "policy_revision"),
    ("evidence", "evidence"),
    ("audit", "audit_event"),
]

APPEND_ONLY_TABLES = [
    ("governance", "approval"),
    ("knowledge", "observation"),
    ("execution", "tool_execution"),
    ("findings", "capability_transition"),
    ("audit", "outbox_event"),
]


def _immutable_trigger_sql(schema: str, table: str) -> str:
    func_name = f"{schema}.reject_{table}_mutation"
    return f"""
CREATE OR REPLACE FUNCTION {func_name}() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'Table {schema}.{table} is immutable: UPDATE and DELETE are prohibited';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_{table}_immutable
    BEFORE UPDATE OR DELETE ON {schema}.{table}
    FOR EACH ROW EXECUTE FUNCTION {func_name}();
"""


def _append_only_trigger_sql(schema: str, table: str) -> str:
    func_name = f"{schema}.reject_{table}_update"
    return f"""
CREATE OR REPLACE FUNCTION {func_name}() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'Table {schema}.{table} is append-only: UPDATE and DELETE are prohibited';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_{table}_append_only
    BEFORE UPDATE OR DELETE ON {schema}.{table}
    FOR EACH ROW EXECUTE FUNCTION {func_name}();
"""


def _rls_sql(schema: str, table: str) -> str:
    return f"""
ALTER TABLE {schema}.{table} ENABLE ROW LEVEL SECURITY;
ALTER TABLE {schema}.{table} FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON {schema}.{table}
    USING (tenant_id = current_setting('app.tenant_id')::uuid);
"""


def upgrade() -> None:
    for schema in SCHEMAS:
        op.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")

    # --- IAM ---
    op.create_table(
        "tenant",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="iam",
    )
    op.create_table(
        "app_user",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("iam.tenant.id"), nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("roles", postgresql.JSONB, server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="iam",
    )

    # --- Governance ---
    op.create_table(
        "engagement",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("lifecycle_state", sa.String(50), nullable=False, server_default="draft"),
        sa.Column("current_revision_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("temporal_workflow_id", sa.String(255), nullable=True),
        sa.Column("temporal_run_id", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="governance",
    )
    op.create_table(
        "engagement_revision",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("revision_number", sa.Integer, nullable=False),
        sa.Column("content_digest", sa.String(128), nullable=False),
        sa.Column("spec", postgresql.JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False),
        schema="governance",
    )
    op.create_table(
        "authorization_verification",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("artifact_digest", sa.String(128), nullable=False),
        sa.Column("issuer", sa.String(255), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="governance",
    )
    op.create_table(
        "scope_revision",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("revision_number", sa.Integer, nullable=False),
        sa.Column("content_digest", sa.String(128), nullable=False),
        sa.Column("spec", postgresql.JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="governance",
    )
    op.create_table(
        "policy_revision",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("revision_number", sa.Integer, nullable=False),
        sa.Column("content_digest", sa.String(128), nullable=False),
        sa.Column("rules", postgresql.JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="governance",
    )
    op.create_table(
        "approval",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("action_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("approver_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("decision", sa.String(50), nullable=False),
        sa.Column("reason", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="governance",
    )

    # --- Knowledge ---
    op.create_table(
        "asset",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("kind", sa.String(50), nullable=False),
        sa.Column("identifier", sa.String(500), nullable=False),
        sa.Column("metadata_", postgresql.JSONB, server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="knowledge",
    )
    op.create_table(
        "observation",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source", sa.String(255), nullable=False),
        sa.Column("kind", sa.String(100), nullable=False),
        sa.Column("content", postgresql.JSONB, nullable=False),
        sa.Column("evidence_ref", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="knowledge",
    )

    # --- Reasoning ---
    op.create_table(
        "hypothesis",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("state", sa.String(50), nullable=False, server_default="open"),
        sa.Column("technique_id", sa.String(255), nullable=False),
        sa.Column("target", sa.String(500), nullable=False),
        sa.Column("rationale", sa.Text, nullable=False),
        sa.Column("evidence_refs", postgresql.JSONB, server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="reasoning",
    )
    op.create_table(
        "action_proposal",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("hypothesis_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("state", sa.String(50), nullable=False, server_default="proposed"),
        sa.Column("technique_id", sa.String(255), nullable=False),
        sa.Column("target", sa.String(500), nullable=False),
        sa.Column("risk_tier", sa.String(10), nullable=False),
        sa.Column("mutation_class", sa.String(50), nullable=False),
        sa.Column("parameters", postgresql.JSONB, server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="reasoning",
    )

    # --- Execution ---
    op.create_table(
        "execution",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("action_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("state", sa.String(50), nullable=False),
        sa.Column("envelope_digest", sa.String(128), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result", postgresql.JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="execution",
    )
    op.create_table(
        "access_context",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("identity_label", sa.String(255), nullable=False),
        sa.Column("credential_ref", sa.String(500), nullable=True),
        sa.Column("fingerprint", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="execution",
    )
    op.create_table(
        "tool_execution",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("execution_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tool_name", sa.String(255), nullable=False),
        sa.Column("request_digest", sa.String(128), nullable=False),
        sa.Column("response_digest", sa.String(128), nullable=True),
        sa.Column("status_code", sa.Integer, nullable=True),
        sa.Column("duration_ms", sa.Integer, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="execution",
    )
    op.create_table(
        "cleanup_obligation",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("action_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("state", sa.String(50), nullable=False, server_default="planned"),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("handler", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        schema="execution",
    )

    # --- Evidence ---
    op.create_table(
        "evidence",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("action_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("kind", sa.String(100), nullable=False),
        sa.Column("digest", sa.String(128), nullable=False, unique=True),
        sa.Column("size_bytes", sa.BigInteger, nullable=False),
        sa.Column("media_type", sa.String(100), nullable=False),
        sa.Column("storage_uri", sa.String(500), nullable=False),
        sa.Column("sensitivity", sa.String(50), nullable=False, server_default="restricted"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="evidence",
    )

    # --- Findings ---
    op.create_table(
        "finding",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("state", sa.String(50), nullable=False, server_default="candidate"),
        sa.Column("technique_id", sa.String(255), nullable=False),
        sa.Column("target", sa.String(500), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("severity", sa.String(50), nullable=True),
        sa.Column("evidence_refs", postgresql.JSONB, server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("capability_refs", postgresql.JSONB, server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="findings",
    )
    op.create_table(
        "capability",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("type", sa.String(100), nullable=False),
        sa.Column("technique_id", sa.String(255), nullable=False),
        sa.Column("target", sa.String(500), nullable=False),
        sa.Column("evidence_refs", postgresql.JSONB, server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("proven", sa.Boolean, nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="findings",
    )
    op.create_table(
        "attack_path",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("objective", sa.Text, nullable=False),
        sa.Column("steps", postgresql.JSONB, server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="findings",
    )

    # --- Reporting ---
    op.create_table(
        "report",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("report_type", sa.String(50), nullable=False),
        sa.Column("format", sa.String(20), nullable=False),
        sa.Column("digest", sa.String(128), nullable=False),
        sa.Column("storage_uri", sa.String(500), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="reporting",
    )

    # --- Audit ---
    op.create_table(
        "audit_event",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("actor_id", sa.String(255), nullable=True),
        sa.Column("engagement_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("payload", postgresql.JSONB, server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="audit",
    )
    op.create_table(
        "outbox_event",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("payload", postgresql.JSONB, nullable=False),
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        schema="audit",
    )

    # --- RLS on all tenant-scoped tables ---
    rls_tables = [
        ("iam", "app_user"),
        ("governance", "engagement"),
        ("governance", "engagement_revision"),
        ("governance", "authorization_verification"),
        ("governance", "scope_revision"),
        ("governance", "policy_revision"),
        ("governance", "approval"),
        ("knowledge", "asset"),
        ("knowledge", "observation"),
        ("reasoning", "hypothesis"),
        ("reasoning", "action_proposal"),
        ("execution", "execution"),
        ("execution", "access_context"),
        ("execution", "tool_execution"),
        ("execution", "cleanup_obligation"),
        ("evidence", "evidence"),
        ("findings", "finding"),
        ("findings", "capability"),
        ("findings", "attack_path"),
        ("reporting", "report"),
        ("audit", "audit_event"),
        ("audit", "outbox_event"),
    ]
    for schema, table in rls_tables:
        op.execute(_rls_sql(schema, table))

    # --- Immutability triggers ---
    for schema, table in IMMUTABLE_TABLES:
        op.execute(_immutable_trigger_sql(schema, table))

    # --- Append-only triggers ---
    for schema, table in APPEND_ONLY_TABLES:
        op.execute(_append_only_trigger_sql(schema, table))


def downgrade() -> None:
    for schema in reversed(SCHEMAS):
        op.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
