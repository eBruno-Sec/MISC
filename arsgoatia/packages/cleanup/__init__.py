"""ArsGoatia cleanup verification — ensures mutation actions are reversed.

Per spec §3 invariant: mutation actions require cleanup verification.
Any action that changes target state (reversible, state_changing, destructive)
creates a cleanup obligation that must be fulfilled before the engagement
can transition to COMPLETED.

Cleanup obligations are tracked as an append-only ledger. Each obligation
has a state machine: PENDING → ATTEMPTED → VERIFIED | FAILED → ESCALATED.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4


class CleanupState(enum.Enum):
    PENDING = "pending"
    ATTEMPTED = "attempted"
    VERIFIED = "verified"
    FAILED = "failed"
    ESCALATED = "escalated"
    WAIVED = "waived"


CLEANUP_TRANSITIONS: dict[CleanupState, frozenset[CleanupState]] = {
    CleanupState.PENDING: frozenset({CleanupState.ATTEMPTED, CleanupState.WAIVED}),
    CleanupState.ATTEMPTED: frozenset({CleanupState.VERIFIED, CleanupState.FAILED}),
    CleanupState.VERIFIED: frozenset(),
    CleanupState.FAILED: frozenset({CleanupState.ATTEMPTED, CleanupState.ESCALATED}),
    CleanupState.ESCALATED: frozenset({CleanupState.ATTEMPTED, CleanupState.WAIVED}),
    CleanupState.WAIVED: frozenset(),
}

TERMINAL_STATES = frozenset({CleanupState.VERIFIED, CleanupState.WAIVED})


@dataclass(frozen=True)
class CleanupObligation:
    obligation_id: UUID
    tenant_id: UUID
    engagement_id: UUID
    action_id: UUID
    mutation_class: str
    description: str
    state: CleanupState = CleanupState.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    evidence_digests: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CleanupAttempt:
    attempt_id: UUID
    obligation_id: UUID
    technique: str
    result: str
    evidence_digest: str | None = None
    attempted_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class CleanupLedger:
    def __init__(self) -> None:
        self._obligations: dict[tuple[UUID, UUID], CleanupObligation] = {}
        self._attempts: list[CleanupAttempt] = []

    def create_obligation(
        self,
        tenant_id: UUID,
        engagement_id: UUID,
        action_id: UUID,
        mutation_class: str,
        description: str,
    ) -> CleanupObligation:
        obligation = CleanupObligation(
            obligation_id=uuid4(),
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            action_id=action_id,
            mutation_class=mutation_class,
            description=description,
        )
        key = (tenant_id, obligation.obligation_id)
        self._obligations[key] = obligation
        return obligation

    def get(self, tenant_id: UUID, obligation_id: UUID) -> CleanupObligation | None:
        return self._obligations.get((tenant_id, obligation_id))

    def transition(
        self, tenant_id: UUID, obligation_id: UUID, new_state: CleanupState
    ) -> CleanupObligation | None:
        key = (tenant_id, obligation_id)
        obligation = self._obligations.get(key)
        if obligation is None:
            return None

        if new_state not in CLEANUP_TRANSITIONS.get(obligation.state, frozenset()):
            raise ValueError(
                f"invalid cleanup transition: {obligation.state.value} → {new_state.value}"
            )

        updated = CleanupObligation(
            obligation_id=obligation.obligation_id,
            tenant_id=obligation.tenant_id,
            engagement_id=obligation.engagement_id,
            action_id=obligation.action_id,
            mutation_class=obligation.mutation_class,
            description=obligation.description,
            state=new_state,
            created_at=obligation.created_at,
            evidence_digests=obligation.evidence_digests,
            metadata=obligation.metadata,
        )
        self._obligations[key] = updated
        return updated

    def record_attempt(self, attempt: CleanupAttempt) -> None:
        self._attempts.append(attempt)

    def attempts_for(self, obligation_id: UUID) -> list[CleanupAttempt]:
        return [a for a in self._attempts if a.obligation_id == obligation_id]

    def pending_for_engagement(
        self, tenant_id: UUID, engagement_id: UUID
    ) -> list[CleanupObligation]:
        return [
            o
            for o in self._obligations.values()
            if o.tenant_id == tenant_id
            and o.engagement_id == engagement_id
            and o.state not in TERMINAL_STATES
        ]

    def all_resolved(self, tenant_id: UUID, engagement_id: UUID) -> bool:
        return len(self.pending_for_engagement(tenant_id, engagement_id)) == 0

    def count(self, tenant_id: UUID, engagement_id: UUID) -> dict[str, int]:
        counts: dict[str, int] = {}
        for o in self._obligations.values():
            if o.tenant_id == tenant_id and o.engagement_id == engagement_id:
                state_name = o.state.value
                counts[state_name] = counts.get(state_name, 0) + 1
        return counts
