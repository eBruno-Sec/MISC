"""Unit tests for the cleanup verification ledger."""

from __future__ import annotations

from uuid import uuid4

import pytest

from packages.cleanup import (
    CLEANUP_TRANSITIONS,
    TERMINAL_STATES,
    CleanupAttempt,
    CleanupLedger,
    CleanupObligation,
    CleanupState,
)


class TestCleanupStateEnum:
    def test_all_states_present(self):
        states = {s.value for s in CleanupState}
        assert "pending" in states
        assert "attempted" in states
        assert "verified" in states
        assert "failed" in states
        assert "escalated" in states
        assert "waived" in states

    def test_terminal_states(self):
        assert CleanupState.VERIFIED in TERMINAL_STATES
        assert CleanupState.WAIVED in TERMINAL_STATES
        assert CleanupState.PENDING not in TERMINAL_STATES
        assert CleanupState.FAILED not in TERMINAL_STATES
        assert CleanupState.ESCALATED not in TERMINAL_STATES


class TestCleanupTransitions:
    def test_pending_can_go_to_attempted(self):
        assert CleanupState.ATTEMPTED in CLEANUP_TRANSITIONS[CleanupState.PENDING]

    def test_pending_can_be_waived(self):
        assert CleanupState.WAIVED in CLEANUP_TRANSITIONS[CleanupState.PENDING]

    def test_attempted_can_go_to_verified(self):
        assert CleanupState.VERIFIED in CLEANUP_TRANSITIONS[CleanupState.ATTEMPTED]

    def test_attempted_can_go_to_failed(self):
        assert CleanupState.FAILED in CLEANUP_TRANSITIONS[CleanupState.ATTEMPTED]

    def test_verified_is_terminal(self):
        assert len(CLEANUP_TRANSITIONS[CleanupState.VERIFIED]) == 0

    def test_waived_is_terminal(self):
        assert len(CLEANUP_TRANSITIONS[CleanupState.WAIVED]) == 0

    def test_failed_can_retry(self):
        assert CleanupState.ATTEMPTED in CLEANUP_TRANSITIONS[CleanupState.FAILED]

    def test_failed_can_escalate(self):
        assert CleanupState.ESCALATED in CLEANUP_TRANSITIONS[CleanupState.FAILED]

    def test_escalated_can_retry(self):
        assert CleanupState.ATTEMPTED in CLEANUP_TRANSITIONS[CleanupState.ESCALATED]

    def test_escalated_can_be_waived(self):
        assert CleanupState.WAIVED in CLEANUP_TRANSITIONS[CleanupState.ESCALATED]


class TestCleanupObligation:
    def test_default_state_is_pending(self):
        obl = CleanupObligation(
            obligation_id=uuid4(),
            tenant_id=uuid4(),
            engagement_id=uuid4(),
            action_id=uuid4(),
            mutation_class="reversible",
            description="Undo file change",
        )
        assert obl.state == CleanupState.PENDING

    def test_frozen(self):
        obl = CleanupObligation(
            obligation_id=uuid4(),
            tenant_id=uuid4(),
            engagement_id=uuid4(),
            action_id=uuid4(),
            mutation_class="reversible",
            description="test",
        )
        with pytest.raises((AttributeError, TypeError)):
            obl.state = CleanupState.VERIFIED  # type: ignore[misc]

    def test_has_created_at(self):
        obl = CleanupObligation(
            obligation_id=uuid4(),
            tenant_id=uuid4(),
            engagement_id=uuid4(),
            action_id=uuid4(),
            mutation_class="reversible",
            description="test",
        )
        assert obl.created_at is not None


class TestCleanupLedger:
    def _make_obligation(
        self, ledger: CleanupLedger, tenant_id=None, engagement_id=None
    ) -> CleanupObligation:
        tid = tenant_id or uuid4()
        eid = engagement_id or uuid4()
        return ledger.create_obligation(
            tenant_id=tid,
            engagement_id=eid,
            action_id=uuid4(),
            mutation_class="reversible",
            description="test obligation",
        )

    def test_create_and_get(self):
        ledger = CleanupLedger()
        tid = uuid4()
        obl = ledger.create_obligation(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=uuid4(),
            mutation_class="reversible",
            description="Delete temp file",
        )
        found = ledger.get(tid, obl.obligation_id)
        assert found == obl
        assert found.state == CleanupState.PENDING

    def test_get_wrong_tenant_returns_none(self):
        ledger = CleanupLedger()
        tid_a, tid_b = uuid4(), uuid4()
        obl = ledger.create_obligation(
            tenant_id=tid_a,
            engagement_id=uuid4(),
            action_id=uuid4(),
            mutation_class="reversible",
            description="test",
        )
        assert ledger.get(tid_b, obl.obligation_id) is None

    def test_get_unknown_id_returns_none(self):
        ledger = CleanupLedger()
        assert ledger.get(uuid4(), uuid4()) is None

    def test_valid_transition_pending_to_attempted(self):
        ledger = CleanupLedger()
        tid = uuid4()
        obl = ledger.create_obligation(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=uuid4(),
            mutation_class="reversible",
            description="test",
        )
        updated = ledger.transition(tid, obl.obligation_id, CleanupState.ATTEMPTED)
        assert updated is not None
        assert updated.state == CleanupState.ATTEMPTED

    def test_valid_transition_to_verified(self):
        ledger = CleanupLedger()
        tid = uuid4()
        obl = ledger.create_obligation(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=uuid4(),
            mutation_class="reversible",
            description="test",
        )
        ledger.transition(tid, obl.obligation_id, CleanupState.ATTEMPTED)
        updated = ledger.transition(tid, obl.obligation_id, CleanupState.VERIFIED)
        assert updated.state == CleanupState.VERIFIED

    def test_valid_transition_to_failed(self):
        ledger = CleanupLedger()
        tid = uuid4()
        obl = ledger.create_obligation(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=uuid4(),
            mutation_class="reversible",
            description="test",
        )
        ledger.transition(tid, obl.obligation_id, CleanupState.ATTEMPTED)
        updated = ledger.transition(tid, obl.obligation_id, CleanupState.FAILED)
        assert updated.state == CleanupState.FAILED

    def test_invalid_transition_raises(self):
        ledger = CleanupLedger()
        tid = uuid4()
        obl = ledger.create_obligation(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=uuid4(),
            mutation_class="reversible",
            description="test",
        )
        with pytest.raises(ValueError, match="invalid cleanup transition"):
            ledger.transition(tid, obl.obligation_id, CleanupState.VERIFIED)

    def test_transition_from_terminal_state_raises(self):
        ledger = CleanupLedger()
        tid = uuid4()
        obl = ledger.create_obligation(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=uuid4(),
            mutation_class="reversible",
            description="test",
        )
        ledger.transition(tid, obl.obligation_id, CleanupState.ATTEMPTED)
        ledger.transition(tid, obl.obligation_id, CleanupState.VERIFIED)
        with pytest.raises(ValueError, match="invalid cleanup transition"):
            ledger.transition(tid, obl.obligation_id, CleanupState.ATTEMPTED)

    def test_transition_unknown_id_returns_none(self):
        ledger = CleanupLedger()
        result = ledger.transition(uuid4(), uuid4(), CleanupState.ATTEMPTED)
        assert result is None

    def test_waive_from_pending(self):
        ledger = CleanupLedger()
        tid = uuid4()
        obl = ledger.create_obligation(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=uuid4(),
            mutation_class="reversible",
            description="test",
        )
        updated = ledger.transition(tid, obl.obligation_id, CleanupState.WAIVED)
        assert updated.state == CleanupState.WAIVED

    def test_retry_after_failed(self):
        ledger = CleanupLedger()
        tid = uuid4()
        obl = ledger.create_obligation(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=uuid4(),
            mutation_class="reversible",
            description="test",
        )
        ledger.transition(tid, obl.obligation_id, CleanupState.ATTEMPTED)
        ledger.transition(tid, obl.obligation_id, CleanupState.FAILED)
        updated = ledger.transition(tid, obl.obligation_id, CleanupState.ATTEMPTED)
        assert updated.state == CleanupState.ATTEMPTED

    def test_escalate_after_failed(self):
        ledger = CleanupLedger()
        tid = uuid4()
        obl = ledger.create_obligation(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=uuid4(),
            mutation_class="reversible",
            description="test",
        )
        ledger.transition(tid, obl.obligation_id, CleanupState.ATTEMPTED)
        ledger.transition(tid, obl.obligation_id, CleanupState.FAILED)
        updated = ledger.transition(tid, obl.obligation_id, CleanupState.ESCALATED)
        assert updated.state == CleanupState.ESCALATED

    def test_record_attempt(self):
        ledger = CleanupLedger()
        obl_id = uuid4()
        attempt = CleanupAttempt(
            attempt_id=uuid4(),
            obligation_id=obl_id,
            technique="delete_temp_file",
            result="deleted /tmp/artifact.pcap",
        )
        ledger.record_attempt(attempt)
        attempts = ledger.attempts_for(obl_id)
        assert len(attempts) == 1
        assert attempts[0].technique == "delete_temp_file"

    def test_attempts_for_filters_by_obligation(self):
        ledger = CleanupLedger()
        oid1, oid2 = uuid4(), uuid4()
        ledger.record_attempt(
            CleanupAttempt(
                attempt_id=uuid4(),
                obligation_id=oid1,
                technique="t1",
                result="ok",
            )
        )
        ledger.record_attempt(
            CleanupAttempt(
                attempt_id=uuid4(),
                obligation_id=oid2,
                technique="t2",
                result="ok",
            )
        )
        assert len(ledger.attempts_for(oid1)) == 1
        assert len(ledger.attempts_for(oid2)) == 1
        assert len(ledger.attempts_for(uuid4())) == 0

    def test_pending_for_engagement(self):
        ledger = CleanupLedger()
        tid = uuid4()
        eid = uuid4()
        obl1 = ledger.create_obligation(tid, eid, uuid4(), "reversible", "a")
        # obl2/obl3 exist only to populate the ledger; the ledger holds them.
        ledger.create_obligation(tid, eid, uuid4(), "reversible", "b")
        ledger.create_obligation(tid, eid, uuid4(), "reversible", "c")
        ledger.transition(tid, obl1.obligation_id, CleanupState.ATTEMPTED)
        ledger.transition(tid, obl1.obligation_id, CleanupState.VERIFIED)
        pending = ledger.pending_for_engagement(tid, eid)
        assert len(pending) == 2
        ids = {o.obligation_id for o in pending}
        assert obl1.obligation_id not in ids

    def test_pending_for_engagement_excludes_waived(self):
        ledger = CleanupLedger()
        tid = uuid4()
        eid = uuid4()
        obl = ledger.create_obligation(tid, eid, uuid4(), "reversible", "test")
        ledger.transition(tid, obl.obligation_id, CleanupState.WAIVED)
        assert ledger.pending_for_engagement(tid, eid) == []

    def test_pending_for_engagement_different_tenant(self):
        ledger = CleanupLedger()
        tid_a, tid_b = uuid4(), uuid4()
        eid = uuid4()
        ledger.create_obligation(tid_a, eid, uuid4(), "reversible", "a")
        result = ledger.pending_for_engagement(tid_b, eid)
        assert result == []

    def test_all_resolved_true_when_empty(self):
        ledger = CleanupLedger()
        assert ledger.all_resolved(uuid4(), uuid4()) is True

    def test_all_resolved_false_with_pending(self):
        ledger = CleanupLedger()
        tid = uuid4()
        eid = uuid4()
        ledger.create_obligation(tid, eid, uuid4(), "reversible", "test")
        assert ledger.all_resolved(tid, eid) is False

    def test_all_resolved_true_after_verification(self):
        ledger = CleanupLedger()
        tid = uuid4()
        eid = uuid4()
        obl = ledger.create_obligation(tid, eid, uuid4(), "reversible", "test")
        ledger.transition(tid, obl.obligation_id, CleanupState.ATTEMPTED)
        ledger.transition(tid, obl.obligation_id, CleanupState.VERIFIED)
        assert ledger.all_resolved(tid, eid) is True

    def test_count(self):
        ledger = CleanupLedger()
        tid = uuid4()
        eid = uuid4()
        obl1 = ledger.create_obligation(tid, eid, uuid4(), "reversible", "a")
        obl2 = ledger.create_obligation(tid, eid, uuid4(), "reversible", "b")
        ledger.create_obligation(tid, eid, uuid4(), "reversible", "c")
        ledger.transition(tid, obl1.obligation_id, CleanupState.ATTEMPTED)
        ledger.transition(tid, obl1.obligation_id, CleanupState.VERIFIED)
        ledger.transition(tid, obl2.obligation_id, CleanupState.ATTEMPTED)
        counts = ledger.count(tid, eid)
        assert counts.get("verified") == 1
        assert counts.get("attempted") == 1
        assert counts.get("pending") == 1

    def test_count_empty_engagement(self):
        ledger = CleanupLedger()
        counts = ledger.count(uuid4(), uuid4())
        assert counts == {}

    def test_immutable_history_preserved(self):
        """Obligations are replaced, not mutated — old snapshot must not change."""
        ledger = CleanupLedger()
        tid = uuid4()
        eid = uuid4()
        original = ledger.create_obligation(tid, eid, uuid4(), "reversible", "test")
        assert original.state == CleanupState.PENDING
        ledger.transition(tid, original.obligation_id, CleanupState.ATTEMPTED)
        assert original.state == CleanupState.PENDING

    def test_multiple_obligations_independent(self):
        ledger = CleanupLedger()
        tid = uuid4()
        eid = uuid4()
        o1 = ledger.create_obligation(tid, eid, uuid4(), "reversible", "cleanup 1")
        o2 = ledger.create_obligation(tid, eid, uuid4(), "reversible", "cleanup 2")
        ledger.transition(tid, o1.obligation_id, CleanupState.ATTEMPTED)
        ledger.transition(tid, o1.obligation_id, CleanupState.VERIFIED)
        assert ledger.get(tid, o2.obligation_id).state == CleanupState.PENDING
        assert ledger.get(tid, o1.obligation_id).state == CleanupState.VERIFIED
