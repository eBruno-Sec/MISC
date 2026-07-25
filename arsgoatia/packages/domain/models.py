"""SQLAlchemy 2.0 ORM for the ArsGoatia canonical store.

Scope: the M1 control-plane and cross-cutting tables the vertical slice needs to
create/authorize an assessment, compile scope, and drive the root workflow. Later
milestones add asset/evidence/finding/capability tables via new migrations.

Conventions (spec §6, §33):
  * UUID primary keys (server default gen_random_uuid()).
  * tenant_id on every row for row-level security.
  * timestamptz timestamps.
  * IMMUTABLE tables are written once (revisions); APPEND-ONLY tables never
    UPDATE/DELETE. Both are enforced by DB triggers (see migrations) and the
    repository layer. The classification is declared here via __arsgoatia_write__
    so tests and the migration generator can assert coverage.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


# Write-policy classifications used by the migration + drift tests.
WRITE_MUTABLE = "mutable"
WRITE_IMMUTABLE = "immutable"  # write-once (revisions, verified records)
WRITE_APPEND_ONLY = "append_only"  # never UPDATE/DELETE (audit, evidence, outbox)


def _uuid_pk() -> Mapped[str]:
    return mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )


def _created_at() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=text("now()"), nullable=False)


# --------------------------------------------------------------------------- #
# Control plane / authorization
# --------------------------------------------------------------------------- #
class Tenant(Base):
    __tablename__ = "tenant"
    __arsgoatia_write__ = WRITE_MUTABLE
    id: Mapped[str] = _uuid_pk()
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = _created_at()


class AppUser(Base):
    __tablename__ = "app_user"
    __arsgoatia_write__ = WRITE_MUTABLE
    id: Mapped[str] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenant.id"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    role: Mapped[str] = mapped_column(String(40), nullable=False, default="Analyst")
    created_at: Mapped[datetime] = _created_at()


class Team(Base):
    __tablename__ = "team"
    __arsgoatia_write__ = WRITE_MUTABLE
    id: Mapped[str] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenant.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)


class Assessment(Base):
    """Mutable head row. Points at the current immutable revision + policy."""

    __tablename__ = "assessment"
    __arsgoatia_write__ = WRITE_MUTABLE
    id: Mapped[str] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenant.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    lifecycle_state: Mapped[str] = mapped_column(String(40), nullable=False, default="draft")
    assessment_types: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    current_revision_id: Mapped[str | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    current_policy_revision_id: Mapped[str | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    temporal_workflow_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    temporal_run_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = _created_at()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )


class AssessmentRevision(Base):
    """Immutable snapshot: authorization + scope + policy at a revision number.
    A new revision forces re-evaluation of pending actions (§8)."""

    __tablename__ = "assessment_revision"
    __arsgoatia_write__ = WRITE_IMMUTABLE
    id: Mapped[str] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    assessment_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment.id"), nullable=False, index=True
    )
    revision_number: Mapped[int] = mapped_column(Integer, nullable=False)
    authorization_record_id: Mapped[str | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    scope_definition_id: Mapped[str | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    policy_revision_id: Mapped[str | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    source_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    created_at: Mapped[datetime] = _created_at()


class AuthorizationRecord(Base):
    """Immutable once verified. Gates every action (§13, guardrail: no
    authorization → deny)."""

    __tablename__ = "authorization_record"
    __arsgoatia_write__ = WRITE_IMMUTABLE
    id: Mapped[str] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    assessment_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment.id"), nullable=False, index=True
    )
    authorizing_party: Mapped[str] = mapped_column(String(300), nullable=False)
    authorized_testing_types: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    artifact_ref: Mapped[str | None] = mapped_column(String(500), nullable=True)
    artifact_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verification_state: Mapped[str] = mapped_column(String(40), nullable=False, default="pending")
    created_at: Mapped[datetime] = _created_at()


class ScopeDefinition(Base):
    __tablename__ = "scope_definition"
    __arsgoatia_write__ = WRITE_IMMUTABLE
    id: Mapped[str] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    assessment_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment.id"), nullable=False, index=True
    )
    third_party_policy: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    resolution_policy: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    environment_classification: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = _created_at()


class ScopeTarget(Base):
    __tablename__ = "scope_target"
    __arsgoatia_write__ = WRITE_IMMUTABLE
    id: Mapped[str] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    scope_definition_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scope_definition.id"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    value: Mapped[str] = mapped_column(String(500), nullable=False)
    disposition: Mapped[str] = mapped_column(String(20), nullable=False, default="include")
    constraints: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    environment_classification: Mapped[str] = mapped_column(
        String(40), nullable=False, default="unknown"
    )


class Policy(Base):
    __tablename__ = "policy"
    __arsgoatia_write__ = WRITE_MUTABLE
    id: Mapped[str] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    assessment_id: Mapped[str | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    profile: Mapped[str] = mapped_column(String(40), nullable=False, default="lab-safe")
    current_revision_id: Mapped[str | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = _created_at()


class PolicyRevision(Base):
    """Immutable. rules encodes the risk-class → decision matrix + limits (§13)."""

    __tablename__ = "policy_revision"
    __arsgoatia_write__ = WRITE_IMMUTABLE
    id: Mapped[str] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    policy_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), ForeignKey("policy.id"), nullable=False, index=True
    )
    revision_number: Mapped[int] = mapped_column(Integer, nullable=False)
    profile: Mapped[str] = mapped_column(String(40), nullable=False, default="lab-safe")
    rules: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    scoring_weights_version: Mapped[str] = mapped_column(String(20), nullable=False, default="1")
    created_at: Mapped[datetime] = _created_at()


class WorkflowRecord(Base):
    __tablename__ = "workflow_record"
    __arsgoatia_write__ = WRITE_MUTABLE
    id: Mapped[str] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    assessment_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment.id"), nullable=False, index=True
    )
    workflow_id: Mapped[str] = mapped_column(String(200), nullable=False)
    run_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    workflow_type: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = _created_at()


class ModuleDefinition(Base):
    __tablename__ = "module_definition"
    __arsgoatia_write__ = WRITE_MUTABLE
    id: Mapped[str] = mapped_column(String(120), primary_key=True)  # e.g. web.authorization.idor
    version: Mapped[str] = mapped_column(String(40), primary_key=True)
    domain: Mapped[str] = mapped_column(String(40), nullable=False)
    contract: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = _created_at()


# --------------------------------------------------------------------------- #
# Cross-cutting: audit (append-only) and transactional outbox (append-only)
# --------------------------------------------------------------------------- #
class AuditEvent(Base):
    """Append-only audit log. Mirrors the §9 event envelope shape."""

    __tablename__ = "audit_event"
    __arsgoatia_write__ = WRITE_APPEND_ONLY
    id: Mapped[str] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    assessment_id: Mapped[str | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    assessment_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    policy_revision: Mapped[int | None] = mapped_column(Integer, nullable=True)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    aggregate_type: Mapped[str] = mapped_column(String(80), nullable=False)
    aggregate_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )
    producer: Mapped[str] = mapped_column(String(120), nullable=False)
    correlation_id: Mapped[str | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    causation_id: Mapped[str | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")


class Outbox(Base):
    """Transactional outbox (spec §9; replaces NATS). Rows are written in the
    same transaction as the state change and dispatched by the relay poller.
    Append-only: dispatched_at is set once via the relay's guarded update."""

    __tablename__ = "outbox"
    __arsgoatia_write__ = WRITE_APPEND_ONLY
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False, unique=True)
    tenant_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    envelope: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = _created_at()
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# --------------------------------------------------------------------------- #
# Knowledge: assets, services, endpoints (M2 recon), evidence (immutable)
# --------------------------------------------------------------------------- #
class Asset(Base):
    __tablename__ = "asset"
    __arsgoatia_write__ = WRITE_MUTABLE
    id: Mapped[str] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    assessment_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment.id"), nullable=False, index=True
    )
    asset_type: Mapped[str] = mapped_column(String(40), nullable=False)
    canonical_name: Mapped[str] = mapped_column(String(500), nullable=False)
    identifiers: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    environment_id: Mapped[str | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    scope_status: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown")
    assertion_state: Mapped[str] = mapped_column(String(20), nullable=False, default="observed")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    first_seen_at: Mapped[datetime] = _created_at()
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()"), nullable=False
    )
    evidence_refs: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)


class Service(Base):
    __tablename__ = "service"
    __arsgoatia_write__ = WRITE_MUTABLE
    id: Mapped[str] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    asset_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), ForeignKey("asset.id"), nullable=False, index=True
    )
    protocol: Mapped[str] = mapped_column(String(40), nullable=False)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    transport: Mapped[str] = mapped_column(String(20), nullable=False, default="tcp")
    product: Mapped[str | None] = mapped_column(String(200), nullable=True)
    version: Mapped[str | None] = mapped_column(String(80), nullable=True)
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    evidence_refs: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)


class Endpoint(Base):
    __tablename__ = "endpoint"
    __arsgoatia_write__ = WRITE_MUTABLE
    id: Mapped[str] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    asset_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), ForeignKey("asset.id"), nullable=False, index=True
    )
    service_id: Mapped[str | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    protocol: Mapped[str] = mapped_column(String(20), nullable=False, default="https")
    method: Mapped[str | None] = mapped_column(String(10), nullable=True)
    host: Mapped[str] = mapped_column(String(300), nullable=False)
    path_template: Mapped[str] = mapped_column(String(1000), nullable=False)
    parameters: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    auth_schemes: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    content_types: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    source_locations: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    reachability_contexts: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    evidence_refs: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)


class Evidence(Base):
    """Immutable, append-only (§16). Corrections create derivative rows."""

    __tablename__ = "evidence"
    __arsgoatia_write__ = WRITE_APPEND_ONLY
    id: Mapped[str] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    assessment_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment.id"), nullable=False, index=True
    )
    evidence_type: Mapped[str] = mapped_column(String(40), nullable=False)
    object_uri: Mapped[str] = mapped_column(String(1000), nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    media_type: Mapped[str] = mapped_column(String(120), nullable=False)
    captured_at: Mapped[datetime] = _created_at()
    captured_by: Mapped[str] = mapped_column(String(120), nullable=False)
    source_execution_id: Mapped[str | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    redaction_state: Mapped[str] = mapped_column(String(20), nullable=False, default="redacted")
    sensitivity: Mapped[str] = mapped_column(String(20), nullable=False, default="confidential")
    meta: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict)


# --------------------------------------------------------------------------- #
# Identity / access (M3). Secrets live only in the secret table, addressed by uri.
# --------------------------------------------------------------------------- #
class Identity(Base):
    __tablename__ = "identity"
    __arsgoatia_write__ = WRITE_MUTABLE
    id: Mapped[str] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    assessment_id: Mapped[str] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assessment.id"), nullable=False, index=True
    )
    identity_type: Mapped[str] = mapped_column(String(40), nullable=False, default="human_user")
    principal: Mapped[str] = mapped_column(String(320), nullable=False)
    authority: Mapped[str] = mapped_column(String(300), nullable=False, default="")
    tenant_or_domain: Mapped[str | None] = mapped_column(String(300), nullable=True)
    privilege_label: Mapped[str | None] = mapped_column(String(80), nullable=True)
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="observed")
    evidence_refs: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)


class CredentialReference(Base):
    """Raw material lives in the secret store; only a uri + fingerprint here."""

    __tablename__ = "credential_reference"
    __arsgoatia_write__ = WRITE_MUTABLE
    id: Mapped[str] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    assessment_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    identity_id: Mapped[str | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    credential_type: Mapped[str] = mapped_column(String(40), nullable=False, default="jwt")
    secret_uri: Mapped[str] = mapped_column(String(300), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="discovered")
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    evidence_refs: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)


class Session(Base):
    __tablename__ = "session"
    __arsgoatia_write__ = WRITE_MUTABLE
    id: Mapped[str] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    assessment_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    identity_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False)
    target_asset_id: Mapped[str | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    credential_reference_id: Mapped[str | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    session_type: Mapped[str] = mapped_column(String(20), nullable=False, default="api")
    privilege_label: Mapped[str] = mapped_column(String(80), nullable=False, default="standard_user")
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    established_at: Mapped[datetime] = _created_at()
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    evidence_refs: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)


class AccessContext(Base):
    __tablename__ = "access_context"
    __arsgoatia_write__ = WRITE_MUTABLE
    id: Mapped[str] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    assessment_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    origin_asset_id: Mapped[str | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    identity_id: Mapped[str | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    session_id: Mapped[str | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    credential_reference_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    privilege_label: Mapped[str | None] = mapped_column(String(80), nullable=True)
    capability_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    reachable_asset_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="active")


class Secret(Base):
    """Dev-only local secret store (ADR 0003). Raw material never enters the
    canonical graph, prompts, or Temporal history — only a secret_uri + sha256
    fingerprint are referenced elsewhere. Not a knowledge entity."""

    __tablename__ = "secret"
    __arsgoatia_write__ = WRITE_MUTABLE
    id: Mapped[str] = _uuid_pk()
    tenant_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    assessment_id: Mapped[str] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = _created_at()


# Which migration owns each table's DDL (so each migration creates only its own).
_MIGRATION_TABLES: dict[str, list[str]] = {
    "0001": [
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
    ],
    "0002": ["asset", "service", "endpoint", "evidence"],
    "0003": ["identity", "credential_reference", "session", "access_context", "secret"],
}


def tables_for_migration(tag: str) -> list[str]:
    return list(_MIGRATION_TABLES.get(tag, []))


# Tables carrying tenant_id that get row-level security enabled by the migration.
def tenant_scoped_tables() -> list[str]:
    scoped = []
    for mapper in Base.registry.mappers:
        cls = mapper.class_
        cols = {c.name for c in cls.__table__.columns}
        if "tenant_id" in cols:
            scoped.append(cls.__tablename__)
    return sorted(scoped)


def tables_by_write_policy(policy: str) -> list[str]:
    out = []
    for mapper in Base.registry.mappers:
        cls = mapper.class_
        if getattr(cls, "__arsgoatia_write__", WRITE_MUTABLE) == policy:
            out.append(cls.__tablename__)
    return sorted(out)
