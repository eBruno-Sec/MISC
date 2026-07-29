"""Unit tests for the hypothesis registry with truth maintenance."""
from __future__ import annotations

from uuid import uuid4

import pytest

from packages.hypothesis import (
    ACTIVE_HYPOTHESIS_STATES,
    HYPOTHESIS_TRANSITIONS,
    HypothesisError,
    HypothesisNotFoundError,
    HypothesisRegistry,
    HypothesisState,
    InvalidTransitionError,
    ObservationAlreadyRetractedError,
)


def _registry() -> HypothesisRegistry:
    return HypothesisRegistry()


def _create(
    reg: HypothesisRegistry,
    tenant_id=None,
    engagement_id=None,
    claim="object-level authz may be missing",
    rationale="differential response suggests different access levels",
    **kw,
):
    tid = tenant_id or uuid4()
    eid = engagement_id or uuid4()
    return reg.create(
        tenant_id=tid,
        engagement_id=eid,
        claim=claim,
        rationale=rationale,
        **kw,
    ), tid, eid


class TestTransitionTable:
    def test_open_to_testable(self):
        assert HypothesisState.TESTABLE in HYPOTHESIS_TRANSITIONS[HypothesisState.OPEN]

    def test_open_to_stale(self):
        assert HypothesisState.STALE in HYPOTHESIS_TRANSITIONS[HypothesisState.OPEN]

    def test_testable_to_testing(self):
        assert HypothesisState.TESTING in HYPOTHESIS_TRANSITIONS[HypothesisState.TESTABLE]

    def test_testing_terminal_states(self):
        allowed = HYPOTHESIS_TRANSITIONS[HypothesisState.TESTING]
        assert HypothesisState.SUPPORTED in allowed
        assert HypothesisState.REFUTED in allowed
        assert HypothesisState.INCONCLUSIVE in allowed
        assert HypothesisState.STALE in allowed

    def test_supported_to_stale(self):
        assert HypothesisState.STALE in HYPOTHESIS_TRANSITIONS[HypothesisState.SUPPORTED]

    def test_refuted_to_stale(self):
        assert HypothesisState.STALE in HYPOTHESIS_TRANSITIONS[HypothesisState.REFUTED]

    def test_inconclusive_to_testable(self):
        assert HypothesisState.TESTABLE in HYPOTHESIS_TRANSITIONS[HypothesisState.INCONCLUSIVE]

    def test_stale_to_open(self):
        assert HypothesisState.OPEN in HYPOTHESIS_TRANSITIONS[HypothesisState.STALE]


class TestCreate:
    def test_creates_in_open_state(self):
        reg = _registry()
        h, tid, eid = _create(reg, tenant_id=uuid4(), engagement_id=uuid4())
        assert h.state == HypothesisState.OPEN

    def test_default_confidence_zero(self):
        reg = _registry()
        h, _, _ = _create(reg)
        assert h.confidence == 0.0

    def test_custom_confidence_clamped(self):
        reg = _registry()
        h, _, _ = _create(reg, confidence=1.5)
        assert h.confidence == 1.0

    def test_negative_confidence_clamped(self):
        reg = _registry()
        h, _, _ = _create(reg, confidence=-0.1)
        assert h.confidence == 0.0

    def test_prerequisites_stored(self):
        reg = _registry()
        h, _, _ = _create(reg, prerequisites=["auth required", "two users"])
        assert "auth required" in h.prerequisites

    def test_missing_evidence_stored(self):
        reg = _registry()
        h, _, _ = _create(reg, missing_evidence=["negative control", "positive control"])
        assert "negative control" in h.missing_evidence

    def test_frozen(self):
        reg = _registry()
        h, _, _ = _create(reg)
        with pytest.raises((AttributeError, TypeError)):
            h.claim = "tampered"  # type: ignore[misc]

    def test_unique_ids(self):
        reg = _registry()
        tid, eid = uuid4(), uuid4()
        h1, _, _ = _create(reg, tenant_id=tid, engagement_id=eid)
        h2, _, _ = _create(reg, tenant_id=tid, engagement_id=eid)
        assert h1.hypothesis_id != h2.hypothesis_id

    def test_initial_state_override(self):
        reg = _registry()
        h, _, _ = _create(reg, initial_state=HypothesisState.TESTABLE)
        assert h.state == HypothesisState.TESTABLE


class TestGet:
    def test_get_by_id(self):
        reg = _registry()
        h, tid, _ = _create(reg, tenant_id=uuid4())
        found = reg.get(tid, h.hypothesis_id)
        assert found == h

    def test_get_wrong_tenant_returns_none(self):
        reg = _registry()
        h, tid_a, _ = _create(reg, tenant_id=uuid4())
        assert reg.get(uuid4(), h.hypothesis_id) is None

    def test_get_unknown_returns_none(self):
        reg = _registry()
        assert reg.get(uuid4(), uuid4()) is None


class TestTransition:
    def test_open_to_testable(self):
        reg = _registry()
        h, tid, _ = _create(reg, tenant_id=uuid4())
        updated = reg.transition(tid, h.hypothesis_id, HypothesisState.TESTABLE)
        assert updated.state == HypothesisState.TESTABLE

    def test_testable_to_testing(self):
        reg = _registry()
        h, tid, _ = _create(reg, tenant_id=uuid4())
        reg.transition(tid, h.hypothesis_id, HypothesisState.TESTABLE)
        updated = reg.transition(tid, h.hypothesis_id, HypothesisState.TESTING)
        assert updated.state == HypothesisState.TESTING

    def test_testing_to_supported(self):
        reg = _registry()
        h, tid, _ = _create(reg, tenant_id=uuid4())
        reg.transition(tid, h.hypothesis_id, HypothesisState.TESTABLE)
        reg.transition(tid, h.hypothesis_id, HypothesisState.TESTING)
        updated = reg.transition(tid, h.hypothesis_id, HypothesisState.SUPPORTED)
        assert updated.state == HypothesisState.SUPPORTED

    def test_testing_to_refuted(self):
        reg = _registry()
        h, tid, _ = _create(reg, tenant_id=uuid4())
        reg.transition(tid, h.hypothesis_id, HypothesisState.TESTABLE)
        reg.transition(tid, h.hypothesis_id, HypothesisState.TESTING)
        updated = reg.transition(tid, h.hypothesis_id, HypothesisState.REFUTED)
        assert updated.state == HypothesisState.REFUTED

    def test_testing_to_inconclusive(self):
        reg = _registry()
        h, tid, _ = _create(reg, tenant_id=uuid4())
        reg.transition(tid, h.hypothesis_id, HypothesisState.TESTABLE)
        reg.transition(tid, h.hypothesis_id, HypothesisState.TESTING)
        updated = reg.transition(tid, h.hypothesis_id, HypothesisState.INCONCLUSIVE)
        assert updated.state == HypothesisState.INCONCLUSIVE

    def test_inconclusive_to_testable(self):
        reg = _registry()
        h, tid, _ = _create(reg, tenant_id=uuid4())
        reg.transition(tid, h.hypothesis_id, HypothesisState.TESTABLE)
        reg.transition(tid, h.hypothesis_id, HypothesisState.TESTING)
        reg.transition(tid, h.hypothesis_id, HypothesisState.INCONCLUSIVE)
        updated = reg.transition(tid, h.hypothesis_id, HypothesisState.TESTABLE)
        assert updated.state == HypothesisState.TESTABLE

    def test_stale_to_open(self):
        reg = _registry()
        h, tid, _ = _create(reg, tenant_id=uuid4())
        reg.transition(tid, h.hypothesis_id, HypothesisState.STALE)
        updated = reg.transition(tid, h.hypothesis_id, HypothesisState.OPEN)
        assert updated.state == HypothesisState.OPEN

    def test_invalid_transition_raises(self):
        reg = _registry()
        h, tid, _ = _create(reg, tenant_id=uuid4())
        with pytest.raises(InvalidTransitionError):
            reg.transition(tid, h.hypothesis_id, HypothesisState.SUPPORTED)

    def test_unknown_hypothesis_raises(self):
        reg = _registry()
        with pytest.raises(HypothesisNotFoundError):
            reg.transition(uuid4(), uuid4(), HypothesisState.TESTABLE)

    def test_transition_records_history(self):
        reg = _registry()
        h, tid, _ = _create(reg, tenant_id=uuid4())
        reg.transition(tid, h.hypothesis_id, HypothesisState.TESTABLE, reason="prereqs met")
        history = reg.transitions_for(h.hypothesis_id)
        assert len(history) == 1
        assert history[0].from_state == HypothesisState.OPEN
        assert history[0].to_state == HypothesisState.TESTABLE
        assert history[0].reason == "prereqs met"

    def test_multiple_transitions_recorded(self):
        reg = _registry()
        h, tid, _ = _create(reg, tenant_id=uuid4())
        reg.transition(tid, h.hypothesis_id, HypothesisState.TESTABLE)
        reg.transition(tid, h.hypothesis_id, HypothesisState.TESTING)
        reg.transition(tid, h.hypothesis_id, HypothesisState.SUPPORTED)
        assert len(reg.transitions_for(h.hypothesis_id)) == 3


class TestObservations:
    def test_record_observation(self):
        reg = _registry()
        tid, eid = uuid4(), uuid4()
        obs = reg.record_observation(
            tid, eid, "http_response", {"status": 200}, "tool:http_diff", confidence=0.9
        )
        assert obs.observation_type == "http_response"
        assert obs.confidence == 0.9
        assert not obs.retracted

    def test_get_observation(self):
        reg = _registry()
        tid, eid = uuid4(), uuid4()
        obs = reg.record_observation(tid, eid, "dns_record", {"a": "1.2.3.4"}, "tool:recon")
        found = reg.get_observation(tid, obs.observation_id)
        assert found == obs

    def test_get_observation_wrong_tenant_returns_none(self):
        reg = _registry()
        tid, eid = uuid4(), uuid4()
        obs = reg.record_observation(tid, eid, "dns_record", {}, "tool")
        assert reg.get_observation(uuid4(), obs.observation_id) is None

    def test_observation_frozen(self):
        reg = _registry()
        tid, eid = uuid4(), uuid4()
        obs = reg.record_observation(tid, eid, "t", {}, "tool")
        with pytest.raises((AttributeError, TypeError)):
            obs.confidence = 0.5  # type: ignore[misc]

    def test_confidence_clamped(self):
        reg = _registry()
        tid, eid = uuid4(), uuid4()
        obs = reg.record_observation(tid, eid, "t", {}, "tool", confidence=2.0)
        assert obs.confidence == 1.0

    def test_retract_observation(self):
        reg = _registry()
        tid, eid = uuid4(), uuid4()
        obs = reg.record_observation(tid, eid, "t", {}, "tool")
        retracted = reg.retract_observation(tid, obs.observation_id, "contradicted")
        assert retracted.retracted is True
        assert retracted.retraction_reason == "contradicted"

    def test_retract_already_retracted_raises(self):
        reg = _registry()
        tid, eid = uuid4(), uuid4()
        obs = reg.record_observation(tid, eid, "t", {}, "tool")
        reg.retract_observation(tid, obs.observation_id)
        with pytest.raises(ObservationAlreadyRetractedError):
            reg.retract_observation(tid, obs.observation_id)

    def test_retract_unknown_raises(self):
        reg = _registry()
        with pytest.raises(HypothesisNotFoundError):
            reg.retract_observation(uuid4(), uuid4())


class TestObservationLinks:
    def test_link_observation(self):
        reg = _registry()
        tid, eid = uuid4(), uuid4()
        h, _, _ = _create(reg, tenant_id=tid, engagement_id=eid)
        obs = reg.record_observation(tid, eid, "t", {}, "tool")
        reg.link_observation(tid, h.hypothesis_id, obs.observation_id)
        linked = reg.observations_for(tid, h.hypothesis_id)
        assert any(o.observation_id == obs.observation_id for o in linked)

    def test_link_unknown_hypothesis_raises(self):
        reg = _registry()
        tid, eid = uuid4(), uuid4()
        obs = reg.record_observation(tid, eid, "t", {}, "tool")
        with pytest.raises(HypothesisNotFoundError):
            reg.link_observation(tid, uuid4(), obs.observation_id)

    def test_link_unknown_observation_raises(self):
        reg = _registry()
        h, tid, _ = _create(reg, tenant_id=uuid4())
        with pytest.raises(HypothesisNotFoundError):
            reg.link_observation(tid, h.hypothesis_id, uuid4())

    def test_hypotheses_for_observation(self):
        reg = _registry()
        tid, eid = uuid4(), uuid4()
        h, _, _ = _create(reg, tenant_id=tid, engagement_id=eid)
        obs = reg.record_observation(tid, eid, "t", {}, "tool")
        reg.link_observation(tid, h.hypothesis_id, obs.observation_id)
        hyps = reg.hypotheses_for_observation(tid, obs.observation_id)
        assert any(hh.hypothesis_id == h.hypothesis_id for hh in hyps)

    def test_hypotheses_for_unknown_observation_returns_empty(self):
        reg = _registry()
        assert reg.hypotheses_for_observation(uuid4(), uuid4()) == []


class TestTruthMaintenance:
    def test_retraction_cascades_to_stale(self):
        reg = _registry()
        tid, eid = uuid4(), uuid4()
        h, _, _ = _create(reg, tenant_id=tid, engagement_id=eid)
        obs = reg.record_observation(tid, eid, "t", {}, "tool")
        reg.link_observation(tid, h.hypothesis_id, obs.observation_id)
        reg.retract_observation(tid, obs.observation_id)
        updated = reg.get(tid, h.hypothesis_id)
        assert updated.state == HypothesisState.STALE

    def test_retraction_with_remaining_support_does_not_cascade(self):
        reg = _registry()
        tid, eid = uuid4(), uuid4()
        h, _, _ = _create(reg, tenant_id=tid, engagement_id=eid)
        obs1 = reg.record_observation(tid, eid, "t", {}, "tool")
        obs2 = reg.record_observation(tid, eid, "t", {}, "tool")
        reg.link_observation(tid, h.hypothesis_id, obs1.observation_id)
        reg.link_observation(tid, h.hypothesis_id, obs2.observation_id)
        reg.retract_observation(tid, obs1.observation_id)
        updated = reg.get(tid, h.hypothesis_id)
        # obs2 still active → hypothesis not cascaded to stale
        assert updated.state == HypothesisState.OPEN

    def test_retraction_cascades_to_supported_hypothesis(self):
        reg = _registry()
        tid, eid = uuid4(), uuid4()
        h, _, _ = _create(reg, tenant_id=tid, engagement_id=eid)
        obs = reg.record_observation(tid, eid, "t", {}, "tool")
        reg.link_observation(tid, h.hypothesis_id, obs.observation_id)
        reg.transition(tid, h.hypothesis_id, HypothesisState.TESTABLE)
        reg.transition(tid, h.hypothesis_id, HypothesisState.TESTING)
        reg.transition(tid, h.hypothesis_id, HypothesisState.SUPPORTED)
        reg.retract_observation(tid, obs.observation_id)
        updated = reg.get(tid, h.hypothesis_id)
        assert updated.state == HypothesisState.STALE

    def test_retraction_only_affects_linked_hypotheses(self):
        reg = _registry()
        tid, eid = uuid4(), uuid4()
        h1, _, _ = _create(reg, tenant_id=tid, engagement_id=eid)
        h2, _, _ = _create(reg, tenant_id=tid, engagement_id=eid, claim="other claim")
        obs = reg.record_observation(tid, eid, "t", {}, "tool")
        reg.link_observation(tid, h1.hypothesis_id, obs.observation_id)
        # h2 NOT linked
        reg.retract_observation(tid, obs.observation_id)
        h1_updated = reg.get(tid, h1.hypothesis_id)
        h2_updated = reg.get(tid, h2.hypothesis_id)
        assert h1_updated.state == HypothesisState.STALE
        assert h2_updated.state == HypothesisState.OPEN

    def test_retraction_does_not_affect_different_tenant(self):
        reg = _registry()
        tid_a, tid_b = uuid4(), uuid4()
        eid = uuid4()
        h_a, _, _ = _create(reg, tenant_id=tid_a, engagement_id=eid)
        obs_a = reg.record_observation(tid_a, eid, "t", {}, "tool")
        # Create same obs shape for tenant_b but different id
        obs_b = reg.record_observation(tid_b, eid, "t", {}, "tool")
        reg.link_observation(tid_a, h_a.hypothesis_id, obs_a.observation_id)
        h_b, _, _ = _create(reg, tenant_id=tid_b, engagement_id=eid)
        reg.link_observation(tid_b, h_b.hypothesis_id, obs_b.observation_id)
        # Retract tenant_a's observation
        reg.retract_observation(tid_a, obs_a.observation_id)
        # Only h_a should go stale
        assert reg.get(tid_a, h_a.hypothesis_id).state == HypothesisState.STALE
        assert reg.get(tid_b, h_b.hypothesis_id).state == HypothesisState.OPEN

    def test_stale_hypothesis_can_be_reopened(self):
        reg = _registry()
        tid, eid = uuid4(), uuid4()
        h, _, _ = _create(reg, tenant_id=tid, engagement_id=eid)
        obs = reg.record_observation(tid, eid, "t", {}, "tool")
        reg.link_observation(tid, h.hypothesis_id, obs.observation_id)
        reg.retract_observation(tid, obs.observation_id)
        assert reg.get(tid, h.hypothesis_id).state == HypothesisState.STALE
        reg.transition(tid, h.hypothesis_id, HypothesisState.OPEN, "re-investigating")
        assert reg.get(tid, h.hypothesis_id).state == HypothesisState.OPEN


class TestUpdateConfidence:
    def test_updates_confidence(self):
        reg = _registry()
        h, tid, _ = _create(reg, tenant_id=uuid4())
        updated = reg.update_confidence(tid, h.hypothesis_id, 0.8)
        assert abs(updated.confidence - 0.8) < 1e-9

    def test_clamps_above_one(self):
        reg = _registry()
        h, tid, _ = _create(reg, tenant_id=uuid4())
        updated = reg.update_confidence(tid, h.hypothesis_id, 2.0)
        assert updated.confidence == 1.0

    def test_clamps_below_zero(self):
        reg = _registry()
        h, tid, _ = _create(reg, tenant_id=uuid4())
        updated = reg.update_confidence(tid, h.hypothesis_id, -0.5)
        assert updated.confidence == 0.0

    def test_unknown_raises(self):
        reg = _registry()
        with pytest.raises(HypothesisNotFoundError):
            reg.update_confidence(uuid4(), uuid4(), 0.5)


class TestResolveMissingEvidence:
    def test_removes_item(self):
        reg = _registry()
        h, tid, _ = _create(
            reg, tenant_id=uuid4(), missing_evidence=["negative control", "positive control"]
        )
        updated = reg.resolve_missing_evidence(tid, h.hypothesis_id, "negative control")
        assert "negative control" not in updated.missing_evidence
        assert "positive control" in updated.missing_evidence

    def test_no_op_for_absent_item(self):
        reg = _registry()
        h, tid, _ = _create(reg, tenant_id=uuid4(), missing_evidence=["item"])
        updated = reg.resolve_missing_evidence(tid, h.hypothesis_id, "nonexistent")
        assert updated.missing_evidence == h.missing_evidence

    def test_unknown_raises(self):
        reg = _registry()
        with pytest.raises(HypothesisNotFoundError):
            reg.resolve_missing_evidence(uuid4(), uuid4(), "item")


class TestListForEngagement:
    def test_returns_all_for_engagement(self):
        reg = _registry()
        tid, eid = uuid4(), uuid4()
        h1, _, _ = _create(reg, tenant_id=tid, engagement_id=eid)
        h2, _, _ = _create(reg, tenant_id=tid, engagement_id=eid, claim="c2")
        h3, _, _ = _create(reg, tenant_id=tid)  # different engagement
        result = reg.list_for_engagement(tid, eid)
        ids = {r.hypothesis_id for r in result}
        assert h1.hypothesis_id in ids
        assert h2.hypothesis_id in ids
        assert h3.hypothesis_id not in ids

    def test_state_filter(self):
        reg = _registry()
        tid, eid = uuid4(), uuid4()
        h1, _, _ = _create(reg, tenant_id=tid, engagement_id=eid)
        h2, _, _ = _create(reg, tenant_id=tid, engagement_id=eid, claim="c2")
        reg.transition(tid, h2.hypothesis_id, HypothesisState.STALE)
        result = reg.list_for_engagement(
            tid, eid, states=frozenset({HypothesisState.OPEN})
        )
        ids = {r.hypothesis_id for r in result}
        assert h1.hypothesis_id in ids
        assert h2.hypothesis_id not in ids

    def test_wrong_tenant_excluded(self):
        reg = _registry()
        tid_a, tid_b = uuid4(), uuid4()
        eid = uuid4()
        _create(reg, tenant_id=tid_a, engagement_id=eid)
        assert reg.list_for_engagement(tid_b, eid) == []

    def test_active_for_engagement(self):
        reg = _registry()
        tid, eid = uuid4(), uuid4()
        h1, _, _ = _create(reg, tenant_id=tid, engagement_id=eid)
        h2, _, _ = _create(reg, tenant_id=tid, engagement_id=eid, claim="c2")
        reg.transition(tid, h2.hypothesis_id, HypothesisState.STALE)
        active = reg.active_for_engagement(tid, eid)
        ids = {r.hypothesis_id for r in active}
        assert h1.hypothesis_id in ids
        assert h2.hypothesis_id not in ids
