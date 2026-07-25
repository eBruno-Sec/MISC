"""Domain value objects (§6.13-6.21).

These mirror the canonical entities the persistence layer stores. They are the
serialization shape used in events, module output, and the API; packages/domain
maps them to ORM rows. Immutability/append-only rules are enforced at the
persistence layer, not here.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from schemas.common import (
    AssertionState,
    CapabilityState,
    Confidence,
    FindingValidationState,
    HypothesisState,
    RedactionState,
    Sensitivity,
    SeverityLabel,
    utcnow,
)


class Observation(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    assessment_id: UUID
    observation_type: str
    subject_type: str
    subject_id: UUID | None = None
    assertion_state: AssertionState = AssertionState.OBSERVED
    confidence: Confidence = 0.5
    summary: str = ""
    structured_data: dict[str, Any] = Field(default_factory=dict)
    source_tool_execution_id: UUID | None = None
    evidence_refs: list[UUID] = Field(default_factory=list)


class Hypothesis(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    assessment_id: UUID
    hypothesis_class: str
    summary: str = ""
    rationale: str = ""
    supporting_observation_refs: list[UUID] = Field(default_factory=list)
    contradicting_observation_refs: list[UUID] = Field(default_factory=list)
    target_refs: list[UUID] = Field(default_factory=list)
    required_context_refs: list[UUID] = Field(default_factory=list)
    confidence: Confidence = 0.5
    state: HypothesisState = HypothesisState.PROPOSED


class Finding(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    assessment_id: UUID
    internal_class: str
    title: str = ""
    summary: str = ""
    technical_description: str = ""
    affected_asset_ids: list[UUID] = Field(default_factory=list)
    affected_endpoint_ids: list[UUID] = Field(default_factory=list)
    affected_identity_ids: list[UUID] = Field(default_factory=list)
    validation_state: FindingValidationState = FindingValidationState.CANDIDATE
    confidence: Confidence = 0.5
    severity_label: SeverityLabel = SeverityLabel.INFORMATIONAL
    evidence_profile: str = ""
    evidence_refs: list[UUID] = Field(default_factory=list)
    capability_refs: list[UUID] = Field(default_factory=list)
    cleanup_state: str = "not_required"
    discovered_at: datetime = Field(default_factory=utcnow)
    validated_at: datetime | None = None
    reported_at: datetime | None = None


class CapabilityType(str, enum.Enum):
    READ_OBJECT = "read_object"
    MODIFY_OBJECT = "modify_object"
    DELETE_OBJECT = "delete_object"
    IMPERSONATE_IDENTITY = "impersonate_identity"
    ESTABLISH_SESSION = "establish_session"
    EXECUTE_COMMAND = "execute_command"
    SERVER_SIDE_HTTP_REQUEST = "server_side_http_request"
    REACH_INTERNAL_NETWORK = "reach_internal_network"
    READ_FILE = "read_file"
    WRITE_FILE = "write_file"
    UPLOAD_FILE = "upload_file"
    ASSUME_CLOUD_ROLE = "assume_cloud_role"
    ENUMERATE_DIRECTORY = "enumerate_directory"
    ACCESS_DATABASE = "access_database"
    EXPORT_DATA = "export_data"
    RESET_PASSWORD = "reset_password"
    INVOKE_ADMIN_FUNCTION = "invoke_admin_function"
    CONTROL_RESOURCE = "control_resource"


class Capability(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    assessment_id: UUID
    capability_type: CapabilityType
    subject_identity_id: UUID | None = None
    target_asset_id: UUID | None = None
    access_context_id: UUID
    privilege: str | None = None
    validation_state: CapabilityState = CapabilityState.CANDIDATE
    confidence: Confidence = 0.5
    origin_finding_id: UUID | None = None
    evidence_refs: list[UUID] = Field(default_factory=list)
    valid_from: datetime = Field(default_factory=utcnow)
    valid_until: datetime | None = None
    # Labeled capability name as declared by the producing module
    # (e.g. read_foreign_object) — kept alongside the canonical type.
    label: str | None = None


class Evidence(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    assessment_id: UUID
    evidence_type: str
    object_uri: str
    sha256: str
    size_bytes: int
    media_type: str
    captured_at: datetime = Field(default_factory=utcnow)
    captured_by: str
    source_execution_id: UUID | None = None
    redaction_state: RedactionState = RedactionState.REDACTED
    sensitivity: Sensitivity = Sensitivity.CONFIDENTIAL
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackChainStep(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    attack_chain_id: UUID
    sequence_number: int
    prerequisite_capability_ids: list[UUID] = Field(default_factory=list)
    source_context_id: UUID
    action_execution_id: UUID | None = None
    finding_id: UUID | None = None
    resulting_capability_ids: list[UUID] = Field(default_factory=list)
    resulting_context_ids: list[UUID] = Field(default_factory=list)
    evidence_refs: list[UUID] = Field(default_factory=list)
    validation_state: str = "candidate"


class AttackChain(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    assessment_id: UUID
    title: str = ""
    objective: str = ""
    starting_context_id: UUID
    final_capability_ids: list[UUID] = Field(default_factory=list)
    state: str = "candidate"
    confidence: Confidence = 0.5
    business_impact: str = ""
    chain_severity: SeverityLabel = SeverityLabel.INFORMATIONAL
    chain_scoring_rationale: dict[str, Any] = Field(default_factory=dict)
    step_ids: list[UUID] = Field(default_factory=list)
    evidence_refs: list[UUID] = Field(default_factory=list)
