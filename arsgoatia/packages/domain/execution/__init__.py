"""ArsGoatia execution domain — action lifecycle, runners, and cleanup.

Tracks the full action state machine from PROPOSED through execution
to cleanup verification per §6.3 and §9.6 of the spec.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID


class ActionState(enum.Enum):
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


ACTION_TRANSITIONS: dict[ActionState, frozenset[ActionState]] = {
    ActionState.PROPOSED: frozenset(
        {
            ActionState.REJECTED,
            ActionState.APPROVAL_REQUIRED,
            ActionState.DISPATCHED,
        }
    ),
    ActionState.REJECTED: frozenset(),
    ActionState.APPROVAL_REQUIRED: frozenset({ActionState.APPROVED, ActionState.REJECTED}),
    ActionState.APPROVED: frozenset({ActionState.DISPATCHED}),
    ActionState.DISPATCHED: frozenset({ActionState.LEASED, ActionState.CANCELLED}),
    ActionState.LEASED: frozenset({ActionState.RUNNING, ActionState.CANCELLED}),
    ActionState.RUNNING: frozenset(
        {
            ActionState.SUCCEEDED,
            ActionState.FAILED,
            ActionState.TIMED_OUT,
            ActionState.CANCELLED,
            ActionState.UNKNOWN_REQUIRES_REVIEW,
        }
    ),
    ActionState.SUCCEEDED: frozenset(
        {
            ActionState.EVIDENCE_ACCEPTED,
            ActionState.EVIDENCE_REJECTED,
            ActionState.CLEANUP_PENDING,
        }
    ),
    ActionState.FAILED: frozenset({ActionState.CLEANUP_PENDING}),
    ActionState.TIMED_OUT: frozenset({ActionState.CLEANUP_PENDING}),
    ActionState.CANCELLED: frozenset({ActionState.CLEANUP_PENDING}),
    ActionState.UNKNOWN_REQUIRES_REVIEW: frozenset({ActionState.CLEANUP_PENDING}),
    ActionState.EVIDENCE_ACCEPTED: frozenset({ActionState.CLEANUP_PENDING}),
    ActionState.EVIDENCE_REJECTED: frozenset({ActionState.CLEANUP_PENDING}),
    ActionState.CLEANUP_PENDING: frozenset({ActionState.CLEANUP_VERIFIED}),
    ActionState.CLEANUP_VERIFIED: frozenset(),
}


def can_transition_action(current: ActionState, target: ActionState) -> bool:
    return target in ACTION_TRANSITIONS.get(current, frozenset())


class ToolOutcome(enum.Enum):
    SUCCEEDED = "succeeded"
    NEGATIVE = "negative"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"
    BLOCKED_BY_POLICY = "blocked_by_policy"
    BLOCKED_BY_TARGET = "blocked_by_target"
    INVALID_INPUT = "invalid_input"
    ADAPTER_ERROR = "adapter_error"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class ExecutionRecord:
    id: UUID
    tenant_id: UUID
    engagement_id: UUID
    action_id: UUID
    state: ActionState
    envelope_digest: str | None = None
    runner_id: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    outcome: ToolOutcome | None = None
    evidence_refs: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RunnerLease:
    lease_id: UUID
    runner_id: str
    action_id: UUID
    pool_id: str
    claimed_at: datetime
    expires_at: datetime
    revoked: bool = False


def is_lease_valid(lease: RunnerLease, now: datetime) -> bool:
    return not lease.revoked and now < lease.expires_at


MUTATION_STATES = frozenset(
    {
        ActionState.RUNNING,
        ActionState.SUCCEEDED,
        ActionState.FAILED,
        ActionState.TIMED_OUT,
        ActionState.UNKNOWN_REQUIRES_REVIEW,
    }
)


def requires_cleanup(state: ActionState, mutation_class: str) -> bool:
    """Actions that may have mutated state need cleanup regardless of outcome."""
    if mutation_class == "none":
        return False
    return state in MUTATION_STATES
