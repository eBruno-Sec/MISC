from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from packages.domain.reasoning import (
    HYPOTHESIS_TRANSITIONS,
    CandidateAction,
    HypothesisRecord,
    HypothesisState,
    ObservationFact,
    ProvenanceClass,
    TruthMaintenance,
    can_transition_hypothesis,
    score_candidate,
)


def test_hypothesis_valid_transitions():
    assert can_transition_hypothesis(HypothesisState.OPEN, HypothesisState.TESTABLE)
    assert can_transition_hypothesis(HypothesisState.TESTABLE, HypothesisState.TESTING)
    assert can_transition_hypothesis(HypothesisState.TESTING, HypothesisState.SUPPORTED)
    assert can_transition_hypothesis(HypothesisState.TESTING, HypothesisState.REFUTED)


def test_hypothesis_invalid_transitions():
    assert not can_transition_hypothesis(HypothesisState.OPEN, HypothesisState.SUPPORTED)
    assert not can_transition_hypothesis(HypothesisState.SUPPORTED, HypothesisState.OPEN)
    assert not can_transition_hypothesis(HypothesisState.REFUTED, HypothesisState.TESTING)


def test_terminal_states_cannot_transition():
    for state in (HypothesisState.SUPPORTED, HypothesisState.REFUTED):
        for target in HypothesisState:
            assert not can_transition_hypothesis(state, target)


def test_inconclusive_can_reopen():
    assert can_transition_hypothesis(HypothesisState.INCONCLUSIVE, HypothesisState.OPEN)


def test_truth_maintenance_record_and_retract():
    tm = TruthMaintenance()
    eid = uuid4()
    fact = ObservationFact(
        id=uuid4(),
        engagement_id=eid,
        source="recon",
        kind="endpoint_discovered",
        value={"path": "/api/users"},
        provenance=ProvenanceClass.OBSERVED,
        observed_at=datetime.now(timezone.utc),
    )
    tm.record(fact)
    assert len(tm.active_facts()) == 1

    retracted = tm.retract(fact.id, "contradicted by new scan")
    assert fact.id in retracted
    assert len(tm.active_facts()) == 0
    assert tm.get(fact.id).retracted is True


def test_truth_maintenance_cascade_retraction():
    tm = TruthMaintenance()
    eid = uuid4()
    now = datetime.now(timezone.utc)

    parent = ObservationFact(
        id=uuid4(), engagement_id=eid, source="recon", kind="host",
        value="api.test", provenance=ProvenanceClass.OBSERVED, observed_at=now,
    )
    child = ObservationFact(
        id=uuid4(), engagement_id=eid, source="inference", kind="endpoint",
        value="/api/v1", provenance=ProvenanceClass.INFERRED, observed_at=now,
    )
    tm.record(parent)
    tm.record(child)
    tm.add_dependency(child.id, parent.id)

    retracted = tm.retract(parent.id, "host no longer resolves")
    assert parent.id in retracted
    assert child.id in retracted
    assert len(tm.active_facts()) == 0


def test_score_candidate():
    c = CandidateAction(technique_id="test", target="t", risk_tier="R2")
    score = score_candidate(c, info_gain=1.0, capability_gain=0.5, finding_value=0.8)
    assert score > 0


def test_score_with_high_cost():
    c = CandidateAction(technique_id="test", target="t", risk_tier="R2")
    score = score_candidate(c, info_gain=0.1, cost=10.0, noise=5.0)
    assert score < 0


def test_hypothesis_record_creation():
    h = HypothesisRecord(
        id=uuid4(),
        engagement_id=uuid4(),
        state=HypothesisState.OPEN,
        technique_id="web.authz.bola.differential",
        target="https://api.test/basket/1",
        rationale="Basket endpoint uses sequential IDs without authz check",
    )
    assert h.state == HypothesisState.OPEN
    assert h.confidence == 0.0
