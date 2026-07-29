from __future__ import annotations

from pydantic import Field

from .common import (
    BaseContract,
    CleanupState,
    FindingState,
    HypothesisState,
    MutationClass,
    ProvenanceClass,
    TimestampTZ,
    UUIDv7,
)


class Observation(BaseContract):
    observation_id: UUIDv7
    typed_value: dict[str, object]
    provenance: ProvenanceClass
    valid_time: TimestampTZ
    observed_time: TimestampTZ
    confidence: float = Field(ge=0, le=1)
    evidence_refs: list[UUIDv7] = Field(default_factory=list)
    retraction: UUIDv7 | None = None


class Hypothesis(BaseContract):
    hypothesis_id: UUIDv7
    claim: str
    rationale: str
    prerequisites: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)
    status: HypothesisState = HypothesisState.OPEN
    missing_evidence: list[str] = Field(default_factory=list)


class Finding(BaseContract):
    finding_id: UUIDv7
    weakness: str
    affected_object: str
    status: FindingState = FindingState.CANDIDATE
    confidence: float = Field(ge=0, le=1)
    severity: float = Field(ge=0, le=10)
    root_cause: str | None = None
    evidence_profile_version: str | None = None
    validator_digest: str | None = None


class Capability(BaseContract):
    capability_id: UUIDv7
    actor: str
    access_context: UUIDv7
    operation: str
    object: str
    evidence_refs: list[UUIDv7] = Field(default_factory=list)
    validity: TimestampTZ | None = None
    expiry: TimestampTZ | None = None
    revision: int = Field(default=1, ge=1)


class CostVector(BaseContract):
    time_seconds: float = Field(default=0, ge=0)
    complexity: float = Field(default=0, ge=0)
    privilege_required: str = Field(default="none")
    detection_risk: float = Field(default=0, ge=0, le=1)


class AttackPathStep(BaseContract):
    step_id: UUIDv7
    preconditions: list[str] = Field(default_factory=list)
    action: str
    postconditions: list[str] = Field(default_factory=list)
    evidence: list[UUIDv7] = Field(default_factory=list)
    mutation: MutationClass = MutationClass.none
    cleanup: UUIDv7 | None = None
    cost_vector: CostVector = Field(default_factory=CostVector)


class AttackPath(BaseContract):
    path_id: UUIDv7
    steps: list[AttackPathStep] = Field(default_factory=list)
    combined_risk: float = Field(ge=0, le=10)
    pre_state: dict[str, object] = Field(default_factory=dict)
    post_state: dict[str, object] = Field(default_factory=dict)


class CleanupObligation(BaseContract):
    obligation_id: UUIDv7
    inverse_action: str
    trigger: str
    deadline: TimestampTZ
    status: CleanupState = CleanupState.PLANNED
    proof: UUIDv7 | None = None


class AccessContext(BaseContract):
    context_id: UUIDv7
    persona: str
    credential_refs: list[str] = Field(default_factory=list)
    session_refs: list[str] = Field(default_factory=list)
    privileges: list[str] = Field(default_factory=list)
    source: str | None = None
    expiry: TimestampTZ | None = None
