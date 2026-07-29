from __future__ import annotations

from pydantic import Field

from .common import (
    BaseContract,
    MutationClass,
    RiskTier,
    TimestampTZ,
    UUIDv7,
)


class ApprovalBinding(BaseContract):
    requirement: str
    decision_ids: list[UUIDv7] = Field(default_factory=list)
    decision_digest: str | None = None
    quorum: int = Field(default=1, ge=1)


class EnvelopeSignature(BaseContract):
    alg: str
    kid: str
    value: str


class TargetSpec(BaseContract):
    asset_id: UUIDv7
    locator: str
    expected_addresses: list[str] = Field(default_factory=list)
    resolution_policy: str = Field(default="pinned")


class RevisionDigests(BaseContract):
    auth_digest: str
    scope_digest: str
    policy_digest: str


class AttemptPolicy(BaseContract):
    max_attempts: int = Field(default=1, ge=1)
    backoff_seconds: float = Field(default=1.0, ge=0)
    timeout_seconds: float | None = None


class ActionEnvelope(BaseContract):
    action_id: UUIDv7
    action_digest: str
    tenant_id: UUIDv7
    engagement_revision_id: UUIDv7
    proposal_id: UUIDv7
    actor: str
    revisions: RevisionDigests
    technique: str
    adapter: str
    runner: str
    target: TargetSpec
    access_context_ids: list[UUIDv7] = Field(default_factory=list)
    secret_lease_refs: list[str] = Field(default_factory=list)
    parameters: dict[str, object] = Field(default_factory=dict)
    request_spec_digest: str
    effective_risk_tier: RiskTier
    mutation_class: MutationClass
    cleanup_obligation_ids: list[UUIDv7] = Field(default_factory=list)
    budget: dict[str, object] = Field(default_factory=dict)
    approval: ApprovalBinding | None = None
    attempt_policy: AttemptPolicy = Field(default_factory=AttemptPolicy)
    revocation_epoch: int = Field(default=0, ge=0)
    not_before: TimestampTZ | None = None
    expires_at: TimestampTZ
    nonce: str
    idempotency_key: str
    signature: EnvelopeSignature
