from __future__ import annotations

import enum
from datetime import datetime
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy import ForeignKey, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class LifecycleStateDB(str, enum.Enum):
    DRAFT = "draft"
    AUTHORIZATION_PENDING = "authorization_pending"
    SCOPE_COMPILED = "scope_compiled"
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    CLEANUP_PENDING = "cleanup_pending"
    REPORTING = "reporting"
    COMPLETED = "completed"
    REVOCATION_REQUESTED = "revocation_requested"
    REVOKED = "revoked"
    FAILED = "failed"


class ActionStateDB(str, enum.Enum):
    PROPOSED = "proposed"
    REJECTED = "rejected"
    APPROVAL_REQUIRED = "approval_required"
    APPROVED = "approved"
    DISPATCHED = "dispatched"
    LEASED = "leased"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    UNKNOWN_REQUIRES_REVIEW = "unknown_requires_review"
    EVIDENCE_ACCEPTED = "evidence_accepted"
    EVIDENCE_REJECTED = "evidence_rejected"
    CLEANUP_PENDING = "cleanup_pending"
    CLEANUP_VERIFIED = "cleanup_verified"


class FindingStateDB(str, enum.Enum):
    CANDIDATE = "candidate"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"
    ACCEPTED_RISK = "accepted_risk"
    REMEDIATION_PLANNED = "remediation_planned"
    REMEDIATED = "remediated"
    RETEST_PENDING = "retest_pending"
    CLOSED = "closed"
    REGRESSED = "regressed"


class HypothesisStateDB(str, enum.Enum):
    OPEN = "open"
    TESTABLE = "testable"
    TESTING = "testing"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    STALE = "stale"


class CleanupStateDB(str, enum.Enum):
    NOT_REQUIRED = "not_required"
    PLANNED = "planned"
    DUE = "due"
    RUNNING = "running"
    VERIFIED = "verified"
    FAILED = "failed"
    ESCALATED = "escalated"


# ── governance schema ──────────────────────────────────────────────


class Tenant(Base):
    __tablename__ = "tenant"
    __table_args__ = {"schema": "governance"}

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    name: Mapped[str] = mapped_column(sa.String(255))
    region: Mapped[str | None] = mapped_column(sa.String(64))
    status: Mapped[str] = mapped_column(sa.String(32), server_default="active")
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()
    )


class Engagement(Base):
    __tablename__ = "engagement"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        {"schema": "governance"},
    )

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(
        sa.Uuid, ForeignKey("governance.tenant.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(sa.String(255))
    lifecycle_state: Mapped[str] = mapped_column(sa.String(64), server_default="draft")
    current_revision_id: Mapped[UUID | None] = mapped_column(sa.Uuid)
    temporal_workflow_id: Mapped[str | None] = mapped_column(sa.String(255))
    temporal_run_id: Mapped[str | None] = mapped_column(sa.String(255))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()
    )


class EngagementRevision(Base):
    __tablename__ = "engagement_revision"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        {"schema": "governance"},
    )

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    engagement_id: Mapped[UUID] = mapped_column(
        sa.Uuid, ForeignKey("governance.engagement.id"), nullable=False
    )
    revision_number: Mapped[int] = mapped_column(sa.Integer)
    authorization_digest: Mapped[str | None] = mapped_column(sa.String(128))
    scope_revision_id: Mapped[UUID | None] = mapped_column(sa.Uuid)
    policy_revision_id: Mapped[UUID | None] = mapped_column(sa.Uuid)
    time_window_start: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    time_window_end: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    budgets_json: Mapped[dict | None] = mapped_column(sa.JSON)
    digest: Mapped[str | None] = mapped_column(sa.String(128))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )


class AuthorizationVerification(Base):
    __tablename__ = "authorization_verification"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        {"schema": "governance"},
    )

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    engagement_id: Mapped[UUID] = mapped_column(
        sa.Uuid, ForeignKey("governance.engagement.id"), nullable=False
    )
    artifact_digest: Mapped[str] = mapped_column(sa.String(128))
    issuer: Mapped[str] = mapped_column(sa.String(255))
    verifier: Mapped[str | None] = mapped_column(sa.String(255))
    covered_types: Mapped[dict | None] = mapped_column(sa.JSON)
    valid_from: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
    valid_until: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True))
    verification_method: Mapped[str | None] = mapped_column(sa.String(128))
    verified_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )


class ScopeRevision(Base):
    __tablename__ = "scope_revision"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        {"schema": "governance"},
    )

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    engagement_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    document_json: Mapped[dict] = mapped_column(sa.JSON)
    compiled_claims_json: Mapped[dict | None] = mapped_column(sa.JSON)
    compiler_version: Mapped[str] = mapped_column(sa.String(64))
    digest: Mapped[str] = mapped_column(sa.String(128))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )


class PolicyRevision(Base):
    __tablename__ = "policy_revision"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        {"schema": "governance"},
    )

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    engagement_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    rules_json: Mapped[dict] = mapped_column(sa.JSON)
    risk_tier_decisions_json: Mapped[dict | None] = mapped_column(sa.JSON)
    version: Mapped[str] = mapped_column(sa.String(64))
    digest: Mapped[str] = mapped_column(sa.String(128))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )


class ScopeTarget(Base):
    __tablename__ = "scope_target"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        {"schema": "governance"},
    )

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    scope_revision_id: Mapped[UUID] = mapped_column(
        sa.Uuid, ForeignKey("governance.scope_revision.id"), nullable=False
    )
    rule_type: Mapped[str] = mapped_column(sa.String(64))
    value: Mapped[str] = mapped_column(sa.String(1024))
    is_exclude: Mapped[bool] = mapped_column(sa.Boolean, server_default="false")
    ports_json: Mapped[dict | None] = mapped_column(sa.JSON)


class Approval(Base):
    __tablename__ = "approval"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        {"schema": "governance"},
    )

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    engagement_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    proposal_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    action_digest: Mapped[str] = mapped_column(sa.String(128))
    decision: Mapped[str] = mapped_column(sa.String(32))
    approver_id: Mapped[UUID] = mapped_column(sa.Uuid)
    quorum_slot: Mapped[int] = mapped_column(sa.Integer, server_default="1")
    expiry: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    rationale: Mapped[str | None] = mapped_column(sa.Text)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )


# ── knowledge schema ──────────────────────────────────────────────


class Asset(Base):
    __tablename__ = "asset"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        {"schema": "knowledge"},
    )

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    engagement_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    asset_type: Mapped[str] = mapped_column(sa.String(64))
    canonical_name: Mapped[str] = mapped_column(sa.String(1024))
    ownership_confidence: Mapped[str] = mapped_column(sa.String(32), server_default="candidate")
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )


class Service(Base):
    __tablename__ = "service"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        {"schema": "knowledge"},
    )

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    asset_id: Mapped[UUID] = mapped_column(
        sa.Uuid, ForeignKey("knowledge.asset.id"), nullable=False
    )
    protocol: Mapped[str] = mapped_column(sa.String(32))
    port: Mapped[int] = mapped_column(sa.Integer)
    name: Mapped[str | None] = mapped_column(sa.String(255))
    version: Mapped[str | None] = mapped_column(sa.String(128))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )


class Endpoint(Base):
    __tablename__ = "endpoint"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        {"schema": "knowledge"},
    )

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    service_id: Mapped[UUID] = mapped_column(
        sa.Uuid, ForeignKey("knowledge.service.id"), nullable=False
    )
    method: Mapped[str] = mapped_column(sa.String(16))
    path: Mapped[str] = mapped_column(sa.String(2048))
    parameters_json: Mapped[dict | None] = mapped_column(sa.JSON)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )


class Observation(Base):
    __tablename__ = "observation"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        {"schema": "knowledge"},
    )

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    engagement_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    observation_type: Mapped[str] = mapped_column(sa.String(128))
    value_json: Mapped[dict] = mapped_column(sa.JSON)
    provenance: Mapped[str] = mapped_column(sa.String(32))
    valid_time: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    observed_time: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    confidence: Mapped[float] = mapped_column(sa.Float, server_default="1.0")
    evidence_refs_json: Mapped[dict | None] = mapped_column(sa.JSON)
    retracted: Mapped[bool] = mapped_column(sa.Boolean, server_default="false")
    retracted_reason: Mapped[str | None] = mapped_column(sa.Text)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )


# ── reasoning schema ──────────────────────────────────────────────


class Hypothesis(Base):
    __tablename__ = "hypothesis"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        {"schema": "reasoning"},
    )

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    engagement_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    claim: Mapped[str] = mapped_column(sa.Text)
    rationale: Mapped[str | None] = mapped_column(sa.Text)
    prerequisites_json: Mapped[dict | None] = mapped_column(sa.JSON)
    confidence: Mapped[float] = mapped_column(sa.Float, server_default="0.0")
    status: Mapped[str] = mapped_column(sa.String(32), server_default="open")
    missing_evidence_json: Mapped[dict | None] = mapped_column(sa.JSON)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )


class ActionProposal(Base):
    __tablename__ = "action_proposal"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        {"schema": "reasoning"},
    )

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    engagement_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    technique_id: Mapped[str] = mapped_column(sa.String(255))
    technique_version: Mapped[str] = mapped_column(sa.String(64))
    target_id: Mapped[UUID | None] = mapped_column(sa.Uuid)
    parameters_hash: Mapped[str | None] = mapped_column(sa.String(128))
    risk_tier: Mapped[str] = mapped_column(sa.String(8))
    expected_evidence_json: Mapped[dict | None] = mapped_column(sa.JSON)
    status: Mapped[str] = mapped_column(sa.String(64), server_default="proposed")
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )


class Capability(Base):
    __tablename__ = "capability"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        {"schema": "reasoning"},
    )

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    engagement_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    actor_id: Mapped[UUID | None] = mapped_column(sa.Uuid)
    access_context_id: Mapped[UUID | None] = mapped_column(sa.Uuid)
    operation: Mapped[str] = mapped_column(sa.String(255))
    object_id: Mapped[str | None] = mapped_column(sa.String(512))
    evidence_refs_json: Mapped[dict | None] = mapped_column(sa.JSON)
    confidence: Mapped[float] = mapped_column(sa.Float, server_default="1.0")
    valid_from: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    revision: Mapped[int] = mapped_column(sa.Integer, server_default="1")
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )


class AttackPath(Base):
    __tablename__ = "attack_path"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        {"schema": "reasoning"},
    )

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    engagement_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    name: Mapped[str | None] = mapped_column(sa.String(255))
    combined_risk: Mapped[float] = mapped_column(sa.Float, server_default="0.0")
    pre_state_json: Mapped[dict | None] = mapped_column(sa.JSON)
    post_state_json: Mapped[dict | None] = mapped_column(sa.JSON)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )


class AttackPathStep(Base):
    __tablename__ = "attack_path_step"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        {"schema": "reasoning"},
    )

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    attack_path_id: Mapped[UUID] = mapped_column(
        sa.Uuid, ForeignKey("reasoning.attack_path.id"), nullable=False
    )
    sequence: Mapped[int] = mapped_column(sa.Integer)
    technique_id: Mapped[str] = mapped_column(sa.String(255))
    preconditions_json: Mapped[dict | None] = mapped_column(sa.JSON)
    postconditions_json: Mapped[dict | None] = mapped_column(sa.JSON)
    evidence_refs_json: Mapped[dict | None] = mapped_column(sa.JSON)
    cost_json: Mapped[dict | None] = mapped_column(sa.JSON)


# ── execution schema ──────────────────────────────────────────────


class Execution(Base):
    __tablename__ = "execution"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        UniqueConstraint("idempotency_key"),
        {"schema": "execution"},
    )

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    engagement_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    action_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    envelope_digest: Mapped[str | None] = mapped_column(sa.String(128))
    attempt_number: Mapped[int] = mapped_column(sa.Integer, server_default="1")
    runner_id: Mapped[str | None] = mapped_column(sa.String(255))
    started_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    exit_class: Mapped[str | None] = mapped_column(sa.String(64))
    resource_use_json: Mapped[dict | None] = mapped_column(sa.JSON)
    idempotency_key: Mapped[str] = mapped_column(sa.String(128))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )


class AccessContext(Base):
    __tablename__ = "access_context"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        {"schema": "execution"},
    )

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    engagement_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    persona: Mapped[str] = mapped_column(sa.String(255))
    credential_ref: Mapped[str | None] = mapped_column(sa.String(512))
    session_ref: Mapped[str | None] = mapped_column(sa.String(512))
    privileges_json: Mapped[dict | None] = mapped_column(sa.JSON)
    source: Mapped[str | None] = mapped_column(sa.String(128))
    expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )


class CleanupObligationDB(Base):
    __tablename__ = "cleanup_obligation"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        {"schema": "execution"},
    )

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    engagement_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    execution_id: Mapped[UUID | None] = mapped_column(sa.Uuid)
    inverse_action_json: Mapped[dict | None] = mapped_column(sa.JSON)
    trigger: Mapped[str | None] = mapped_column(sa.String(128))
    deadline: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    status: Mapped[str] = mapped_column(sa.String(32), server_default="planned")
    proof_json: Mapped[dict | None] = mapped_column(sa.JSON)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )


# ── evidence schema ───────────────────────────────────────────────


class Evidence(Base):
    __tablename__ = "evidence"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        {"schema": "evidence"},
    )

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    engagement_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    action_id: Mapped[UUID | None] = mapped_column(sa.Uuid)
    kind: Mapped[str] = mapped_column(sa.String(128))
    artifact_digest: Mapped[str] = mapped_column(sa.String(128))
    artifact_size: Mapped[int] = mapped_column(sa.BigInteger)
    media_type: Mapped[str] = mapped_column(sa.String(255))
    storage_uri: Mapped[str] = mapped_column(sa.String(1024))
    capture_metadata_json: Mapped[dict | None] = mapped_column(sa.JSON)
    redaction_json: Mapped[dict | None] = mapped_column(sa.JSON)
    lineage_json: Mapped[dict | None] = mapped_column(sa.JSON)
    sensitivity: Mapped[str] = mapped_column(sa.String(32), server_default="restricted")
    retention_policy: Mapped[str] = mapped_column(
        sa.String(128), server_default="engagement-plus-365d"
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )


# ── findings schema ───────────────────────────────────────────────


class Finding(Base):
    __tablename__ = "finding"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        {"schema": "findings"},
    )

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    engagement_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    weakness: Mapped[str] = mapped_column(sa.String(255))
    affected_object_id: Mapped[str | None] = mapped_column(sa.String(512))
    status: Mapped[str] = mapped_column(sa.String(64), server_default="candidate")
    confidence: Mapped[float] = mapped_column(sa.Float, server_default="0.0")
    severity_json: Mapped[dict | None] = mapped_column(sa.JSON)
    root_cause: Mapped[str | None] = mapped_column(sa.Text)
    evidence_profile_version: Mapped[str | None] = mapped_column(sa.String(64))
    validator_digest: Mapped[str | None] = mapped_column(sa.String(128))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )


# ── reporting schema ──────────────────────────────────────────────


class Report(Base):
    __tablename__ = "report"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id"),
        {"schema": "reporting"},
    )

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    engagement_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    report_type: Mapped[str] = mapped_column(sa.String(64))
    manifest_json: Mapped[dict | None] = mapped_column(sa.JSON)
    template_version: Mapped[str | None] = mapped_column(sa.String(64))
    renderer_digest: Mapped[str | None] = mapped_column(sa.String(128))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )


# ── audit schema ──────────────────────────────────────────────────


class AuditEvent(Base):
    __tablename__ = "audit_event"
    __table_args__ = {"schema": "audit"}

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    event_type: Mapped[str] = mapped_column(sa.String(128))
    aggregate_type: Mapped[str | None] = mapped_column(sa.String(64))
    aggregate_id: Mapped[UUID | None] = mapped_column(sa.Uuid)
    aggregate_version: Mapped[int | None] = mapped_column(sa.Integer)
    actor_id: Mapped[UUID | None] = mapped_column(sa.Uuid)
    causation_id: Mapped[UUID | None] = mapped_column(sa.Uuid)
    correlation_id: Mapped[UUID | None] = mapped_column(sa.Uuid)
    payload_json: Mapped[dict | None] = mapped_column(sa.JSON)
    occurred_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )
    trace_context_json: Mapped[dict | None] = mapped_column(sa.JSON)


class OutboxEvent(Base):
    __tablename__ = "outbox_event"
    __table_args__ = {"schema": "audit"}

    id: Mapped[UUID] = mapped_column(sa.Uuid, primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(sa.Uuid, nullable=False)
    event_type: Mapped[str] = mapped_column(sa.String(128))
    aggregate_type: Mapped[str | None] = mapped_column(sa.String(64))
    aggregate_id: Mapped[UUID | None] = mapped_column(sa.Uuid)
    aggregate_version: Mapped[int | None] = mapped_column(sa.Integer)
    payload_json: Mapped[dict | None] = mapped_column(sa.JSON)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now()
    )
    dispatched_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    consumer_id: Mapped[str | None] = mapped_column(sa.String(128))
    attempts: Mapped[int] = mapped_column(sa.Integer, server_default="0")
    dead_letter: Mapped[bool] = mapped_column(sa.Boolean, server_default="false")


ALL_MODELS = [
    Tenant,
    Engagement,
    EngagementRevision,
    AuthorizationVerification,
    ScopeRevision,
    PolicyRevision,
    ScopeTarget,
    Approval,
    Asset,
    Service,
    Endpoint,
    Observation,
    Hypothesis,
    ActionProposal,
    Capability,
    AttackPath,
    AttackPathStep,
    Execution,
    AccessContext,
    CleanupObligationDB,
    Evidence,
    Finding,
    Report,
    AuditEvent,
    OutboxEvent,
]

IMMUTABLE_TABLES = {
    "governance.engagement_revision",
    "governance.authorization_verification",
    "governance.scope_revision",
    "governance.policy_revision",
    "reasoning.action_proposal",
    "reasoning.capability",
    "evidence.evidence",
    "reporting.report",
}

APPEND_ONLY_TABLES = {
    "knowledge.observation",
    "governance.approval",
    "audit.audit_event",
    "audit.outbox_event",
}
