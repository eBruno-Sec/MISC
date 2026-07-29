from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

UUIDv7 = Annotated[UUID, Field(description="UUID v7 (time-ordered)")]
TimestampTZ = Annotated[datetime, Field(description="Timezone-aware UTC timestamp")]


class RiskTier(str, Enum):
    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"
    R4 = "R4"
    R5 = "R5"


class MutationClass(str, Enum):
    none = "none"
    reversible = "reversible"
    state_changing = "state_changing"
    destructive = "destructive"


class DecisionOutcome(str, Enum):
    allow = "allow"
    allow_with_limits = "allow_with_limits"
    require_approval = "require_approval"
    deny = "deny"


class Sensitivity(str, Enum):
    public = "public"
    internal = "internal"
    restricted = "restricted"
    confidential = "confidential"


class ProvenanceClass(str, Enum):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    ASSERTED = "ASSERTED"
    CONFIRMED = "CONFIRMED"


class LifecycleState(str, Enum):
    DRAFT = "DRAFT"
    AUTHORIZATION_PENDING = "AUTHORIZATION_PENDING"
    SCOPE_COMPILED = "SCOPE_COMPILED"
    READY = "READY"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    STOPPING = "STOPPING"
    CLEANUP_PENDING = "CLEANUP_PENDING"
    REPORTING = "REPORTING"
    COMPLETED = "COMPLETED"
    REVOCATION_REQUESTED = "REVOCATION_REQUESTED"
    REVOKED = "REVOKED"
    FAILED = "FAILED"


class ActionState(str, Enum):
    PROPOSED = "PROPOSED"
    REJECTED = "REJECTED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVED = "APPROVED"
    DISPATCHED = "DISPATCHED"
    LEASED = "LEASED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"
    UNKNOWN_REQUIRES_REVIEW = "UNKNOWN_REQUIRES_REVIEW"
    EVIDENCE_ACCEPTED = "EVIDENCE_ACCEPTED"
    EVIDENCE_REJECTED = "EVIDENCE_REJECTED"
    CLEANUP_PENDING = "CLEANUP_PENDING"
    CLEANUP_VERIFIED = "CLEANUP_VERIFIED"


class HypothesisState(str, Enum):
    OPEN = "OPEN"
    TESTABLE = "TESTABLE"
    TESTING = "TESTING"
    SUPPORTED = "SUPPORTED"
    REFUTED = "REFUTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    STALE = "STALE"


class FindingState(str, Enum):
    CANDIDATE = "CANDIDATE"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    REMEDIATION_PLANNED = "REMEDIATION_PLANNED"
    REMEDIATED = "REMEDIATED"
    RETEST_PENDING = "RETEST_PENDING"
    CLOSED = "CLOSED"
    REGRESSED = "REGRESSED"


class CleanupState(str, Enum):
    NOT_REQUIRED = "NOT_REQUIRED"
    PLANNED = "PLANNED"
    DUE = "DUE"
    RUNNING = "RUNNING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    ESCALATED = "ESCALATED"


class ToolOutcome(str, Enum):
    succeeded = "succeeded"
    negative = "negative"
    partial = "partial"
    unsupported = "unsupported"
    blocked_by_policy = "blocked_by_policy"
    blocked_by_target = "blocked_by_target"
    invalid_input = "invalid_input"
    adapter_error = "adapter_error"
    resource_exhausted = "resource_exhausted"
    timed_out = "timed_out"
    cancelled = "cancelled"


class BaseContract(BaseModel):
    model_config = ConfigDict(strict=True, frozen=True)
