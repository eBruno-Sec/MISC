"""ArsGoatia reasoning domain — hypotheses, observations, and planning.

Handles the hypothesis lifecycle, observation management, truth maintenance,
and technique eligibility per §9.1-9.4 of the spec.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID


class HypothesisState(enum.Enum):
    OPEN = "open"
    TESTABLE = "testable"
    TESTING = "testing"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    STALE = "stale"


HYPOTHESIS_TRANSITIONS: dict[HypothesisState, frozenset[HypothesisState]] = {
    HypothesisState.OPEN: frozenset({HypothesisState.TESTABLE, HypothesisState.STALE}),
    HypothesisState.TESTABLE: frozenset({HypothesisState.TESTING, HypothesisState.STALE}),
    HypothesisState.TESTING: frozenset({
        HypothesisState.SUPPORTED,
        HypothesisState.REFUTED,
        HypothesisState.INCONCLUSIVE,
        HypothesisState.STALE,
    }),
    HypothesisState.SUPPORTED: frozenset(),
    HypothesisState.REFUTED: frozenset(),
    HypothesisState.INCONCLUSIVE: frozenset({HypothesisState.OPEN}),
    HypothesisState.STALE: frozenset({HypothesisState.OPEN}),
}


def can_transition_hypothesis(current: HypothesisState, target: HypothesisState) -> bool:
    return target in HYPOTHESIS_TRANSITIONS.get(current, frozenset())


@dataclass(frozen=True)
class HypothesisRecord:
    id: UUID
    engagement_id: UUID
    state: HypothesisState
    technique_id: str
    target: str
    rationale: str
    prerequisites: list[str] = field(default_factory=list)
    supporting_evidence: list[str] = field(default_factory=list)
    confidence: float = 0.0


class ProvenanceClass(enum.Enum):
    OBSERVED = "observed"
    INFERRED = "inferred"
    ASSERTED = "asserted"
    CONFIRMED = "confirmed"


@dataclass(frozen=True)
class ObservationFact:
    id: UUID
    engagement_id: UUID
    source: str
    kind: str
    value: object
    provenance: ProvenanceClass
    observed_at: datetime
    confidence: float = 1.0
    evidence_ref: str | None = None
    retracted: bool = False
    retraction_reason: str | None = None


@dataclass
class TruthMaintenance:
    """Track facts and retract stale or contradicted ones."""

    def __init__(self) -> None:
        self._facts: dict[UUID, ObservationFact] = {}
        self._dependents: dict[UUID, list[UUID]] = {}

    def record(self, fact: ObservationFact) -> None:
        self._facts[fact.id] = fact

    def retract(self, fact_id: UUID, reason: str) -> list[UUID]:
        """Retract a fact and cascade to dependents. Returns list of retracted IDs."""
        retracted: list[UUID] = []
        fact = self._facts.get(fact_id)
        if fact is None or fact.retracted:
            return retracted

        self._facts[fact_id] = ObservationFact(
            id=fact.id,
            engagement_id=fact.engagement_id,
            source=fact.source,
            kind=fact.kind,
            value=fact.value,
            provenance=fact.provenance,
            observed_at=fact.observed_at,
            confidence=fact.confidence,
            evidence_ref=fact.evidence_ref,
            retracted=True,
            retraction_reason=reason,
        )
        retracted.append(fact_id)

        for dep_id in self._dependents.get(fact_id, []):
            retracted.extend(self.retract(dep_id, f"parent {fact_id} retracted"))

        return retracted

    def add_dependency(self, fact_id: UUID, depends_on: UUID) -> None:
        self._dependents.setdefault(depends_on, []).append(fact_id)

    def active_facts(self) -> list[ObservationFact]:
        return [f for f in self._facts.values() if not f.retracted]

    def get(self, fact_id: UUID) -> ObservationFact | None:
        return self._facts.get(fact_id)


@dataclass(frozen=True)
class CandidateAction:
    technique_id: str
    target: str
    risk_tier: str
    parameters: dict[str, object] = field(default_factory=dict)
    expected_observations: list[str] = field(default_factory=list)
    utility_score: float = 0.0
    elimination_reason: str | None = None


def score_candidate(
    candidate: CandidateAction,
    *,
    info_gain: float = 0.0,
    capability_gain: float = 0.0,
    finding_value: float = 0.0,
    cost: float = 0.0,
    noise: float = 0.0,
) -> float:
    return (
        0.3 * info_gain
        + 0.25 * capability_gain
        + 0.3 * finding_value
        - 0.1 * cost
        - 0.05 * noise
    )
