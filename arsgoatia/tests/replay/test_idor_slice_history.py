"""Validate the IDOR slice history fixture against §37 requirements.

The fixture is a canonical record of the first vertical slice run. These tests
verify its structural integrity and that it encodes every mandatory step from
§37 of the spec — in order — without requiring the Temporal runtime.
"""
from __future__ import annotations

import json
import pathlib

import pytest

HISTORIES_DIR = pathlib.Path(__file__).resolve().parents[1] / "histories"
SLICE_FIXTURE = HISTORIES_DIR / "idor_slice.json"

# Mandatory event types, in the order they must appear in the slice
REQUIRED_EVENTS_ORDERED = [
    "engagement.created",
    "engagement.scope_compiled",
    "engagement.started",
    "recon.endpoints_discovered",
    "identity.bootstrapped",
    "observation.recorded",
    "hypothesis.created",
    "hypothesis.transitioned",
    "policy.decision_recorded",
    "action.proposed",
    "engagement.paused",
    "approval.requested",
    "approval.granted",
    "engagement.resumed",
    "action.executed",
    "evidence.accepted",
    "finding.confirmed",
    "capability.proved",
    "attack_chain.step_created",
    "report.snapshot_created",
    "engagement.completed",
]


@pytest.fixture(scope="module")
def slice_history():
    assert SLICE_FIXTURE.exists(), f"missing fixture: {SLICE_FIXTURE}"
    return json.loads(SLICE_FIXTURE.read_text())


class TestFixtureStructure:
    def test_fixture_exists(self):
        assert SLICE_FIXTURE.exists()

    def test_required_top_level_keys(self, slice_history):
        for key in ("version", "events", "engagement_id", "tenant_id", "target"):
            assert key in slice_history, f"missing key: {key}"

    def test_events_is_list(self, slice_history):
        assert isinstance(slice_history["events"], list)

    def test_events_not_empty(self, slice_history):
        assert len(slice_history["events"]) > 0

    def test_all_events_have_seq_and_type(self, slice_history):
        for i, ev in enumerate(slice_history["events"]):
            assert "seq" in ev, f"event {i} missing seq"
            assert "event_type" in ev, f"event {i} missing event_type"

    def test_seq_is_monotonically_increasing(self, slice_history):
        seqs = [e["seq"] for e in slice_history["events"]]
        for a, b in zip(seqs, seqs[1:]):
            assert b == a + 1, f"seq gap: {a} -> {b}"

    def test_determinism_notes_present(self, slice_history):
        assert "determinism_notes" in slice_history

    def test_replay_compatibility_present(self, slice_history):
        assert "replay_compatibility" in slice_history


class TestSliceEventCoverage:
    """Every mandatory §37 step must appear in the fixture."""

    def test_all_required_event_types_present(self, slice_history):
        found = {e["event_type"] for e in slice_history["events"]}
        for event_type in REQUIRED_EVENTS_ORDERED:
            assert event_type in found, f"missing required event: {event_type}"

    def test_events_in_correct_relative_order(self, slice_history):
        """Required events must appear in the correct relative order."""
        ev_types = [e["event_type"] for e in slice_history["events"]]
        last_idx = -1
        for event_type in REQUIRED_EVENTS_ORDERED:
            idx = ev_types.index(event_type)
            assert idx > last_idx, (
                f"{event_type!r} must come after previous required event "
                f"(found at position {idx}, last was {last_idx})"
            )
            last_idx = idx

    def test_engagement_starts_draft(self, slice_history):
        created = next(
            e for e in slice_history["events"] if e["event_type"] == "engagement.created"
        )
        assert created["state"] == "draft"

    def test_engagement_ends_completed(self, slice_history):
        completed = next(
            e for e in slice_history["events"] if e["event_type"] == "engagement.completed"
        )
        assert completed["state"] == "completed"

    def test_finding_confirmed_deterministically(self, slice_history):
        finding = next(
            e for e in slice_history["events"] if e["event_type"] == "finding.confirmed"
        )
        assert finding["state"] == "confirmed"
        assert "validator" in finding

    def test_capability_proven_only_after_confirmed_finding(self, slice_history):
        ev_types = [e["event_type"] for e in slice_history["events"]]
        confirmed_idx = ev_types.index("finding.confirmed")
        capability_idx = ev_types.index("capability.proved")
        assert capability_idx > confirmed_idx, (
            "capability must be proved AFTER finding is confirmed (§18)"
        )

    def test_capability_name_is_read_foreign_object(self, slice_history):
        cap = next(
            e for e in slice_history["events"] if e["event_type"] == "capability.proved"
        )
        assert cap["capability_name"] == "read_foreign_object"
        assert cap["state"] == "proven"

    def test_evidence_immutable(self, slice_history):
        ev = next(
            e for e in slice_history["events"] if e["event_type"] == "evidence.accepted"
        )
        assert ev["immutable"] is True

    def test_evidence_digest_sha256(self, slice_history):
        ev = next(
            e for e in slice_history["events"] if e["event_type"] == "evidence.accepted"
        )
        assert ev["digest"].startswith("sha256:")

    def test_approval_required_for_r2(self, slice_history):
        proposed = next(
            e for e in slice_history["events"] if e["event_type"] == "action.proposed"
        )
        assert proposed["risk_tier"] == "R2"
        assert proposed["state"] == "approval_required"

    def test_pause_before_approval(self, slice_history):
        ev_types = [e["event_type"] for e in slice_history["events"]]
        paused_idx = ev_types.index("engagement.paused")
        granted_idx = ev_types.index("approval.granted")
        resumed_idx = ev_types.index("engagement.resumed")
        assert paused_idx < granted_idx < resumed_idx, (
            "engagement must pause before approval, and resume after"
        )

    def test_four_differential_exchanges(self, slice_history):
        executed = next(
            e for e in slice_history["events"] if e["event_type"] == "action.executed"
        )
        exchanges = executed["exchanges"]
        assert len(exchanges) == 4
        labels = {ex["label"] for ex in exchanges}
        assert "baseline_own" in labels
        assert "differential_cross" in labels
        assert "positive_control" in labels
        assert "negative_control" in labels

    def test_differential_cross_shows_bola(self, slice_history):
        executed = next(
            e for e in slice_history["events"] if e["event_type"] == "action.executed"
        )
        cross = next(ex for ex in executed["exchanges"] if ex["label"] == "differential_cross")
        # The BOLA: Alice's token can read Bob's basket (should be 403, gets 200)
        assert cross["actual_status"] == 200
        assert cross["expected_status"] != 200

    def test_negative_control_denies(self, slice_history):
        executed = next(
            e for e in slice_history["events"] if e["event_type"] == "action.executed"
        )
        neg = next(ex for ex in executed["exchanges"] if ex["label"] == "negative_control")
        assert neg["actual_status"] == 401
        assert neg["token_identity"] is None

    def test_policy_decision_r2_require_approval(self, slice_history):
        policy = next(
            e for e in slice_history["events"] if e["event_type"] == "policy.decision_recorded"
        )
        assert policy["decision"] == "require_approval"
        assert policy["risk_tier"] == "R2"

    def test_report_includes_expected_formats(self, slice_history):
        report = next(
            e for e in slice_history["events"] if e["event_type"] == "report.snapshot_created"
        )
        assert "json" in report["formats"]
        assert "sarif" in report["formats"]

    def test_attack_chain_step_present(self, slice_history):
        chain = next(
            e for e in slice_history["events"] if e["event_type"] == "attack_chain.step_created"
        )
        assert chain["capability"] == "read_foreign_object"
        assert "cut_point" in chain

    def test_cleanup_verified_at_end(self, slice_history):
        completed = next(
            e for e in slice_history["events"] if e["event_type"] == "engagement.completed"
        )
        assert completed.get("cleanup_obligations_verified") is True

    def test_two_identities_bootstrapped(self, slice_history):
        ib = next(
            e for e in slice_history["events"] if e["event_type"] == "identity.bootstrapped"
        )
        assert ib["sessions_established"] == 2

    def test_recon_discovers_basket_endpoint(self, slice_history):
        recon = next(
            e for e in slice_history["events"] if e["event_type"] == "recon.endpoints_discovered"
        )
        endpoints = recon["endpoints"]
        assert any("basket" in ep for ep in endpoints)


class TestDeterminismNotes:
    def test_no_direct_datetime_now(self, slice_history):
        notes = slice_history["determinism_notes"]
        assert notes["no_direct_datetime_now_in_workflow_code"] is True

    def test_all_uuids_from_workflow_context(self, slice_history):
        notes = slice_history["determinism_notes"]
        assert notes["all_uuids_from_workflow_context"] is True

    def test_confirmation_deterministic(self, slice_history):
        notes = slice_history["determinism_notes"]
        assert notes["confirmation_deterministic"] is True

    def test_ai_advisory_only(self, slice_history):
        notes = slice_history["determinism_notes"]
        assert notes["ai_advisory_only"] is True
