"""Event envelope and event-type catalog (§9).

Events are immutable facts written through a transactional outbox. At-least-once
delivery; consumers must be idempotent (keyed on event_id).
"""

from __future__ import annotations

import enum
import hashlib
import json
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from schemas.common import SchemaVersion, utcnow


class EventType(str, enum.Enum):
    """Catalog from §9. The slice emits the subset it needs; the full set is
    declared so producers reference a single enum."""

    ASSESSMENT_CREATED = "AssessmentCreated"
    AUTHORIZATION_VALIDATED = "AuthorizationValidated"
    SCOPE_COMPILED = "ScopeCompiled"
    ASSET_OBSERVED = "AssetObserved"
    ASSET_VALIDATED = "AssetValidated"
    ENDPOINT_DISCOVERED = "EndpointDiscovered"
    IDENTITY_OBSERVED = "IdentityObserved"
    CREDENTIAL_DISCOVERED = "CredentialDiscovered"
    CREDENTIAL_VERIFIED = "CredentialVerified"
    SESSION_ESTABLISHED = "SessionEstablished"
    OBSERVATION_RECORDED = "ObservationRecorded"
    HYPOTHESIS_PROPOSED = "HypothesisProposed"
    VALIDATION_PLANNED = "ValidationPlanned"
    ACTION_PROPOSED = "ActionProposed"
    ACTION_APPROVED = "ActionApproved"
    ACTION_DENIED = "ActionDenied"
    ACTION_EXECUTED = "ActionExecuted"
    EVIDENCE_STORED = "EvidenceStored"
    FINDING_VALIDATED = "FindingValidated"
    CAPABILITY_PRODUCED = "CapabilityProduced"
    ACCESS_CONTEXT_CREATED = "AccessContextCreated"
    REACHABILITY_VALIDATED = "ReachabilityValidated"
    MODULE_ELIGIBLE = "ModuleEligible"
    MODULE_STARTED = "ModuleStarted"
    MODULE_COMPLETED = "ModuleCompleted"
    ATTACK_CHAIN_UPDATED = "AttackChainUpdated"
    CLEANUP_REQUIRED = "CleanupRequired"
    CLEANUP_COMPLETED = "CleanupCompleted"
    REPORT_GENERATED = "ReportGenerated"
    ASSESSMENT_PAUSED = "AssessmentPaused"
    EMERGENCY_STOP_ACTIVATED = "EmergencyStopActivated"


def payload_hash(payload: dict[str, Any]) -> str:
    """Deterministic sha256 over the canonical JSON payload."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class EventEnvelope(BaseModel):
    """§9 event envelope. payload_hash is derived, never trusted from input."""

    model_config = ConfigDict(frozen=True)

    event_id: UUID = Field(default_factory=uuid4)
    event_type: EventType
    schema_version: SchemaVersion = 1
    tenant_id: UUID
    assessment_id: UUID
    assessment_revision: int
    policy_revision: int
    aggregate_type: str
    aggregate_id: UUID
    occurred_at: datetime = Field(default_factory=utcnow)
    producer: str
    correlation_id: UUID
    causation_id: UUID | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    payload_hash: str = ""

    def finalized(self) -> "EventEnvelope":
        """Return a copy with payload_hash computed from the payload."""
        return self.model_copy(update={"payload_hash": payload_hash(self.payload)})
