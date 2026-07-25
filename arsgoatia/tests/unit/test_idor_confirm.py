"""Deterministic IDOR confirmation (§17). The safety-critical decision."""

from __future__ import annotations

import importlib

idor = importlib.import_module("modules.web.authorization_idor.module")
ExchangeResult = idor.ExchangeResult
confirm_idor = idor.confirm_idor


def _results(diff_status, diff_obj, neg_status=401):
    return {
        "baseline_own": ExchangeResult("baseline_own", 200, observed_object_id="A"),
        "differential": ExchangeResult("differential", diff_status, observed_object_id=diff_obj),
        "positive_control": ExchangeResult("positive_control", 200, observed_object_id="B"),
        "negative_control": ExchangeResult("negative_control", neg_status, observed_object_id=None),
    }


def test_confirmed_when_differential_returns_foreign_object():
    r = confirm_idor(
        _results(200, "B"), target_object_id="B", envelope_verified=True, evidence_complete=True
    )
    assert r.confirmed is True
    assert "PASS:differential_returned_foreign_object" in r.reasons


def test_not_confirmed_when_differential_denied():
    # Auth correctly enforced: A gets 401 on B's object.
    r = confirm_idor(
        _results(401, None), target_object_id="B", envelope_verified=True, evidence_complete=True
    )
    assert r.confirmed is False


def test_not_confirmed_when_negative_control_also_succeeds():
    # If unauthenticated also succeeds, auth is not otherwise enforced -> not a finding.
    res = _results(200, "B", neg_status=200)
    r = confirm_idor(res, target_object_id="B", envelope_verified=True, evidence_complete=True)
    assert r.confirmed is False
    assert "FAIL:auth_otherwise_enforced" in r.reasons


def test_not_confirmed_without_envelope_verification():
    r = confirm_idor(
        _results(200, "B"), target_object_id="B", envelope_verified=False, evidence_complete=True
    )
    assert r.confirmed is False


def test_not_confirmed_without_complete_evidence():
    r = confirm_idor(
        _results(200, "B"), target_object_id="B", envelope_verified=True, evidence_complete=False
    )
    assert r.confirmed is False


def test_incomplete_exchange_set():
    r = confirm_idor({}, target_object_id="B", envelope_verified=True, evidence_complete=True)
    assert r.confirmed is False
    assert r.reasons == ["incomplete_exchange_set"]


def test_extract_object_id():
    assert idor.extract_object_id({"data": {"id": 7}}) == "7"
    assert idor.extract_object_id({"status": "error"}) is None
    assert idor.extract_object_id(None) is None


def test_capability_is_read_foreign_object_and_proven():
    cap = idor.build_capability(
        subject_identity_id="A",
        target_asset_id="asset-1",
        access_context_id="ctx-1",
        origin_finding_id="f-1",
        evidence_refs=["e1", "e2"],
    )
    assert cap["label"] == "read_foreign_object"
    assert cap["capability_type"] == "read_object"
    assert cap["validation_state"] == "proven"
