"""ArsGoatia hypothesis registry — truth-maintenance, observation-backed hypotheses.

Per spec §6.3 / PRX-019:
  - Hypotheses represent testable claims with explicit prerequisites and missing-evidence lists.
  - State machine: OPEN → TESTABLE → TESTING → SUPPORTED | REFUTED | INCONCLUSIVE | STALE
  - Observations support hypotheses; retracting an observation can cascade to STALE.
  - Confidence is a float [0,1] and is updated deterministically — AI opinion is never the source.
  - Hypothesis records are immutable (frozen dataclass); the registry stores the latest version.
  - Truth maintenance: when a supporting observation is retracted the registry marks all dependent
    hypotheses STALE unless they remain independently supported.
  - Scoped to (tenant_id, engagement_id); cross-tenant access returns None / empty list.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4


class HypothesisState(enum.Enum):
    OPEN = "open"
    TESTABLE = "testable"
    TESTING = "testing"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"
    STALE = "stale"


HYPOTHESIS_TRANSITIONS: dict[HypothesisState, frozenset[HypothesisState]] = {
    HypothesisState.OPEN: frozenset({
        HypothesisState.TESTABLE,
        HypothesisState.STALE,
    }),
    HypothesisState.TESTABLE: frozenset({
        HypothesisState.TESTING,
        HypothesisState.STALE,
    }),
    HypothesisState.TESTING: frozenset({
        HypothesisState.SUPPORTED,
        HypothesisState.REFUTED,
        HypothesisState.INCONCLUSIVE,
        HypothesisState.STALE,
    }),
    HypothesisState.SUPPORTED: frozenset({HypothesisState.STALE}),
    HypothesisState.REFUTED: frozenset({HypothesisState.STALE}),
    HypothesisState.INCONCLUSIVE: frozenset({
        HypothesisState.TESTABLE,
        HypothesisState.STALE,
    }),
    HypothesisState.STALE: frozenset({HypothesisState.OPEN}),
}

TERMINAL_HYPOTHESIS_STATES: frozenset[HypothesisState] = frozenset()

ACTIVE_HYPOTHESIS_STATES: frozenset[HypothesisState] = frozenset({
    HypothesisState.OPEN,
    HypothesisState.TESTABLE,
    HypothesisState.TESTING,
    HypothesisState.SUPPORTED,
})


class HypothesisError(Exception):
    pass


class InvalidTransitionError(HypothesisError):
    pass


class HypothesisNotFoundError(HypothesisError):
    pass


class ObservationAlreadyRetractedError(HypothesisError):
    pass


@dataclass(frozen=True)
class ObservationRecord:
    """An immutable observation that supports one or more hypotheses."""
    observation_id: UUID
    tenant_id: UUID
    engagement_id: UUID
    observation_type: str
    value: dict[str, Any]
    provenance: str
    confidence: float
    evidence_refs: frozenset[str] = field(default_factory=frozenset)
    retracted: bool = False
    retraction_reason: str | None = None
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class HypothesisRecord:
    """An immutable snapshot of a hypothesis at a point in time."""
    hypothesis_id: UUID
    tenant_id: UUID
    engagement_id: UUID
    claim: str
    rationale: str
    state: HypothesisState
    confidence: float
    prerequisites: tuple[str, ...] = field(default_factory=tuple)
    missing_evidence: tuple[str, ...] = field(default_factory=tuple)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class HypothesisTransition:
    """Immutable audit record of a state transition."""
    transition_id: UUID
    hypothesis_id: UUID
    from_state: HypothesisState
    to_state: HypothesisState
    reason: str
    actor: str
    transitioned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class HypothesisRegistry:
    """In-process hypothesis store with truth-maintenance via observation retraction."""

    def __init__(self) -> None:
        self._hypotheses: dict[tuple[UUID, UUID], HypothesisRecord] = {}
        self._observations: dict[tuple[UUID, UUID], ObservationRecord] = {}
        self._transitions: list[HypothesisTransition] = []
        # (tenant_id, engagement_id, hypothesis_id) → set of observation_ids
        self._support_links: dict[tuple[UUID, UUID, UUID], set[UUID]] = {}

    # ── observations ────────────────────────────────────────────────────

    def record_observation(
        self,
        tenant_id: UUID,
        engagement_id: UUID,
        observation_type: str,
        value: dict[str, Any],
        provenance: str,
        confidence: float = 1.0,
        evidence_refs: frozenset[str] | None = None,
    ) -> ObservationRecord:
        obs = ObservationRecord(
            observation_id=uuid4(),
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            observation_type=observation_type,
            value=value,
            provenance=provenance,
            confidence=max(0.0, min(1.0, confidence)),
            evidence_refs=evidence_refs or frozenset(),
        )
        self._observations[(tenant_id, obs.observation_id)] = obs
        return obs

    def get_observation(self, tenant_id: UUID, observation_id: UUID) -> ObservationRecord | None:
        return self._observations.get((tenant_id, observation_id))

    def retract_observation(
        self,
        tenant_id: UUID,
        observation_id: UUID,
        reason: str = "",
    ) -> ObservationRecord:
        """Retract an observation and cascade STALE to any hypothesis it solely supported."""
        key = (tenant_id, observation_id)
        obs = self._observations.get(key)
        if obs is None:
            raise HypothesisNotFoundError(f"observation not found: {observation_id}")
        if obs.retracted:
            raise ObservationAlreadyRetractedError(
                f"observation already retracted: {observation_id}"
            )
        retracted_obs = ObservationRecord(
            observation_id=obs.observation_id,
            tenant_id=obs.tenant_id,
            engagement_id=obs.engagement_id,
            observation_type=obs.observation_type,
            value=obs.value,
            provenance=obs.provenance,
            confidence=obs.confidence,
            evidence_refs=obs.evidence_refs,
            retracted=True,
            retraction_reason=reason,
            observed_at=obs.observed_at,
            created_at=obs.created_at,
        )
        self._observations[key] = retracted_obs
        self._cascade_retraction(tenant_id, obs.engagement_id, observation_id)
        return retracted_obs

    def _cascade_retraction(
        self, tenant_id: UUID, engagement_id: UUID, retracted_obs_id: UUID
    ) -> None:
        """Mark hypotheses STALE when their last active supporting observation is retracted."""
        for (tid, eid, hid), obs_ids in list(self._support_links.items()):
            if tid != tenant_id or eid != engagement_id:
                continue
            if retracted_obs_id not in obs_ids:
                continue
            # Check if any remaining linked observations are still active
            remaining_active = any(
                not self._observations.get((tid, oid), ObservationRecord(
                    observation_id=oid, tenant_id=tid, engagement_id=eid,
                    observation_type="", value={}, provenance="",
                    confidence=0.0, retracted=True,
                )).retracted
                for oid in obs_ids
                if oid != retracted_obs_id
            )
            if remaining_active:
                continue
            # No active supporting observations left — cascade to STALE
            hkey = (tid, hid)
            record = self._hypotheses.get(hkey)
            if record is None or record.state not in ACTIVE_HYPOTHESIS_STATES:
                continue
            allowed = HYPOTHESIS_TRANSITIONS.get(record.state, frozenset())
            if HypothesisState.STALE not in allowed:
                continue
            self._do_transition(tid, hid, HypothesisState.STALE, "observation retracted", "system")

    # ── hypotheses ──────────────────────────────────────────────────────

    def create(
        self,
        tenant_id: UUID,
        engagement_id: UUID,
        claim: str,
        rationale: str,
        *,
        prerequisites: list[str] | None = None,
        missing_evidence: list[str] | None = None,
        confidence: float = 0.0,
        metadata: dict[str, Any] | None = None,
        initial_state: HypothesisState = HypothesisState.OPEN,
    ) -> HypothesisRecord:
        record = HypothesisRecord(
            hypothesis_id=uuid4(),
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            claim=claim,
            rationale=rationale,
            state=initial_state,
            confidence=max(0.0, min(1.0, confidence)),
            prerequisites=tuple(prerequisites or []),
            missing_evidence=tuple(missing_evidence or []),
            metadata=metadata or {},
        )
        self._hypotheses[(tenant_id, record.hypothesis_id)] = record
        return record

    def get(self, tenant_id: UUID, hypothesis_id: UUID) -> HypothesisRecord | None:
        return self._hypotheses.get((tenant_id, hypothesis_id))

    def link_observation(
        self,
        tenant_id: UUID,
        hypothesis_id: UUID,
        observation_id: UUID,
    ) -> None:
        """Record that an observation supports this hypothesis."""
        hyp = self._hypotheses.get((tenant_id, hypothesis_id))
        if hyp is None:
            raise HypothesisNotFoundError(f"hypothesis not found: {hypothesis_id}")
        obs = self._observations.get((tenant_id, observation_id))
        if obs is None:
            raise HypothesisNotFoundError(f"observation not found: {observation_id}")
        key = (tenant_id, hyp.engagement_id, hypothesis_id)
        self._support_links.setdefault(key, set()).add(observation_id)

    def observations_for(
        self, tenant_id: UUID, hypothesis_id: UUID
    ) -> list[ObservationRecord]:
        hyp = self._hypotheses.get((tenant_id, hypothesis_id))
        if hyp is None:
            return []
        key = (tenant_id, hyp.engagement_id, hypothesis_id)
        obs_ids = self._support_links.get(key, set())
        result = []
        for oid in obs_ids:
            obs = self._observations.get((tenant_id, oid))
            if obs:
                result.append(obs)
        return result

    def transition(
        self,
        tenant_id: UUID,
        hypothesis_id: UUID,
        new_state: HypothesisState,
        reason: str = "",
        actor: str = "system",
    ) -> HypothesisRecord:
        key = (tenant_id, hypothesis_id)
        record = self._hypotheses.get(key)
        if record is None:
            raise HypothesisNotFoundError(f"hypothesis not found: {hypothesis_id}")
        allowed = HYPOTHESIS_TRANSITIONS.get(record.state, frozenset())
        if new_state not in allowed:
            raise InvalidTransitionError(
                f"invalid hypothesis transition: {record.state.value} → {new_state.value}"
            )
        return self._do_transition(tenant_id, hypothesis_id, new_state, reason, actor)

    def _do_transition(
        self,
        tenant_id: UUID,
        hypothesis_id: UUID,
        new_state: HypothesisState,
        reason: str,
        actor: str,
    ) -> HypothesisRecord:
        key = (tenant_id, hypothesis_id)
        record = self._hypotheses[key]
        self._transitions.append(HypothesisTransition(
            transition_id=uuid4(),
            hypothesis_id=hypothesis_id,
            from_state=record.state,
            to_state=new_state,
            reason=reason,
            actor=actor,
        ))
        now = datetime.now(timezone.utc)
        updated = HypothesisRecord(
            hypothesis_id=record.hypothesis_id,
            tenant_id=record.tenant_id,
            engagement_id=record.engagement_id,
            claim=record.claim,
            rationale=record.rationale,
            state=new_state,
            confidence=record.confidence,
            prerequisites=record.prerequisites,
            missing_evidence=record.missing_evidence,
            created_at=record.created_at,
            updated_at=now,
            metadata=record.metadata,
        )
        self._hypotheses[key] = updated
        return updated

    def update_confidence(
        self,
        tenant_id: UUID,
        hypothesis_id: UUID,
        confidence: float,
    ) -> HypothesisRecord:
        """Update confidence deterministically (e.g., from evidence scoring)."""
        key = (tenant_id, hypothesis_id)
        record = self._hypotheses.get(key)
        if record is None:
            raise HypothesisNotFoundError(f"hypothesis not found: {hypothesis_id}")
        now = datetime.now(timezone.utc)
        updated = HypothesisRecord(
            hypothesis_id=record.hypothesis_id,
            tenant_id=record.tenant_id,
            engagement_id=record.engagement_id,
            claim=record.claim,
            rationale=record.rationale,
            state=record.state,
            confidence=max(0.0, min(1.0, confidence)),
            prerequisites=record.prerequisites,
            missing_evidence=record.missing_evidence,
            created_at=record.created_at,
            updated_at=now,
            metadata=record.metadata,
        )
        self._hypotheses[key] = updated
        return updated

    def resolve_missing_evidence(
        self,
        tenant_id: UUID,
        hypothesis_id: UUID,
        resolved_item: str,
    ) -> HypothesisRecord:
        """Remove one item from the missing_evidence list after evidence is supplied."""
        key = (tenant_id, hypothesis_id)
        record = self._hypotheses.get(key)
        if record is None:
            raise HypothesisNotFoundError(f"hypothesis not found: {hypothesis_id}")
        now = datetime.now(timezone.utc)
        new_missing = tuple(m for m in record.missing_evidence if m != resolved_item)
        updated = HypothesisRecord(
            hypothesis_id=record.hypothesis_id,
            tenant_id=record.tenant_id,
            engagement_id=record.engagement_id,
            claim=record.claim,
            rationale=record.rationale,
            state=record.state,
            confidence=record.confidence,
            prerequisites=record.prerequisites,
            missing_evidence=new_missing,
            created_at=record.created_at,
            updated_at=now,
            metadata=record.metadata,
        )
        self._hypotheses[key] = updated
        return updated

    def transitions_for(self, hypothesis_id: UUID) -> list[HypothesisTransition]:
        return [t for t in self._transitions if t.hypothesis_id == hypothesis_id]

    def list_for_engagement(
        self,
        tenant_id: UUID,
        engagement_id: UUID,
        *,
        states: frozenset[HypothesisState] | None = None,
    ) -> list[HypothesisRecord]:
        results = [
            r for r in self._hypotheses.values()
            if r.tenant_id == tenant_id and r.engagement_id == engagement_id
        ]
        if states is not None:
            results = [r for r in results if r.state in states]
        return results

    def active_for_engagement(
        self, tenant_id: UUID, engagement_id: UUID
    ) -> list[HypothesisRecord]:
        return self.list_for_engagement(
            tenant_id, engagement_id, states=ACTIVE_HYPOTHESIS_STATES
        )

    def hypotheses_for_observation(
        self, tenant_id: UUID, observation_id: UUID
    ) -> list[HypothesisRecord]:
        """Return all hypotheses linked to this observation."""
        obs = self._observations.get((tenant_id, observation_id))
        if obs is None:
            return []
        results = []
        for (tid, eid, hid), obs_ids in self._support_links.items():
            if tid == tenant_id and observation_id in obs_ids:
                rec = self._hypotheses.get((tid, hid))
                if rec:
                    results.append(rec)
        return results
