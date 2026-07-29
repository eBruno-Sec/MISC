from __future__ import annotations

from enum import Enum

from pydantic import Field

from .common import (
    BaseContract,
    Sensitivity,
    TimestampTZ,
    UUIDv7,
)


class EventType(str, Enum):
    ENGAGEMENT_REVISION_READY = "engagement.revision.ready"
    ENGAGEMENT_STARTED = "engagement.started"
    ENGAGEMENT_PAUSED = "engagement.paused"
    ENGAGEMENT_RESUMED = "engagement.resumed"
    ENGAGEMENT_COMPLETED = "engagement.completed"
    ENGAGEMENT_REVOKED = "engagement.revoked"
    ENGAGEMENT_FAILED = "engagement.failed"

    EXECUTION_STARTED = "execution.started"
    EXECUTION_COMPLETED = "execution.completed"
    EXECUTION_FAILED = "execution.failed"
    EXECUTION_TIMED_OUT = "execution.timed_out"

    ACTION_PROPOSED = "action.proposed"
    ACTION_APPROVED = "action.approved"
    ACTION_REJECTED = "action.rejected"
    ACTION_DISPATCHED = "action.dispatched"
    ACTION_SUCCEEDED = "action.succeeded"
    ACTION_FAILED = "action.failed"
    ACTION_CANCELLED = "action.cancelled"

    EVIDENCE_CAPTURED = "evidence.captured"
    EVIDENCE_ACCEPTED = "evidence.accepted"
    EVIDENCE_REJECTED = "evidence.rejected"

    FINDING_CANDIDATE = "finding.candidate"
    FINDING_CONFIRMED = "finding.confirmed"
    FINDING_REJECTED = "finding.rejected"
    FINDING_REMEDIATED = "finding.remediated"
    FINDING_REGRESSED = "finding.regressed"

    HYPOTHESIS_OPENED = "hypothesis.opened"
    HYPOTHESIS_SUPPORTED = "hypothesis.supported"
    HYPOTHESIS_REFUTED = "hypothesis.refuted"

    CLEANUP_DUE = "cleanup.due"
    CLEANUP_VERIFIED = "cleanup.verified"
    CLEANUP_FAILED = "cleanup.failed"
    CLEANUP_ESCALATED = "cleanup.escalated"

    POLICY_DECISION_MADE = "policy.decision.made"
    POLICY_VIOLATION = "policy.violation"

    SCOPE_VIOLATION = "scope.violation"
    BUDGET_EXHAUSTED = "budget.exhausted"
    BUDGET_WARNING = "budget.warning"

    REVOCATION_REQUESTED = "revocation.requested"
    REVOCATION_COMPLETED = "revocation.completed"


class TraceContext(BaseContract):
    trace_id: str
    span_id: str
    trace_flags: int = 0


class EventEnvelope(BaseContract):
    event_id: UUIDv7
    event_type: EventType
    schema_version: str = Field(default="1.0")
    tenant_id: UUIDv7
    aggregate_type: str
    aggregate_id: UUIDv7
    aggregate_version: int = Field(ge=0)
    causation_id: UUIDv7 | None = None
    correlation_id: UUIDv7 | None = None
    actor: str
    occurred_at: TimestampTZ
    classification: Sensitivity = Sensitivity.internal
    payload: dict[str, object] = Field(default_factory=dict)
    trace_context: TraceContext | None = None
