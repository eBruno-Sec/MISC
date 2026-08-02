"""Family-specific proof gate (CHAD re-audit #5) + adversarial false-positive fixtures. A confirmed
finding may only stand if it carries the proof its class requires; a weak confirm is demoted to a lead."""
from __future__ import annotations

import proof_schema as PS


# ── genuine confirmations that MUST validate (the real oracles' evidence) ──
def test_real_ownership_proven_idor_validates():
    f = {"family": "idor", "confidence": "confirmed", "cwe": "CWE-639",
         "impact": "Read other users' data by changing the object id.",
         "evidence": ("anon /rest/basket/1 -> 401 (denied); 'user_a' and 'user_b' -> 200 identical "
                      "(similarity 1.000); ownership proof: object carries owner identity 'user_a'")}
    ok, missing = PS.validate_confirmed(f)
    assert ok, missing


def test_real_union_sqli_validates():
    f = {"family": "sqli", "confidence": "confirmed", "cwe": "CWE-89", "impact": "Full DB read.",
         "evidence": "payload ' UNION SELECT ... -- extracted 12 rows from the users table (error-based confirmed)"}
    ok, missing = PS.validate_confirmed(f)
    assert ok, missing


def test_lead_carries_no_proof_burden():
    assert PS.validate_confirmed({"family": "idor", "confidence": "lead"}) == (True, [])
    assert PS.validate_confirmed({"family": "xss", "confidence": "candidate"}) == (True, [])


# ── adversarial FALSE POSITIVES that MUST be rejected ──
def test_naked_confirm_rejected():
    ok, missing = PS.validate_confirmed({"family": "sqli", "confidence": "confirmed"})
    assert not ok and "evidence(substantive)" in missing


def test_access_control_confirm_without_ownership_rejected():
    # "returned 200" is not authorization proof — no anon control, no ownership marker
    f = {"family": "idor", "confidence": "confirmed", "impact": "x",
         "evidence": "GET /api/orders/2 -> 200 and it returned a JSON body of some length here"}
    ok, missing = PS.validate_confirmed(f)
    assert not ok
    assert any(m.startswith("evidence_signal") for m in missing)


def test_confirm_missing_impact_rejected():
    f = {"family": "xss", "confidence": "confirmed",
         "evidence": "injected <script>alert(1)</script> marker reflected + executed in html context, unencoded"}
    ok, missing = PS.validate_confirmed(f)
    assert not ok and "impact" in missing


# ── demote_unproven: weak confirm -> lead, genuine confirm untouched ──
def test_demote_downgrades_weak_access_control_confirm():
    findings = [{"title": "weak idor", "family": "idor", "confidence": "confirmed", "evidence": "200 ok"}]
    out = PS.demote_unproven(findings)
    assert out[0]["confidence"] == "lead"
    assert "needs-confirmation" in out[0]["tags"] and out[0].get("proof_gap")


def test_demote_keeps_genuine_confirm():
    findings = [{"title": "real idor", "family": "idor", "confidence": "confirmed", "impact": "read others",
                 "evidence": "anon -> 401 denied; user_a and user_b -> 200 identical; ownership proof owner identity"}]
    assert PS.demote_unproven(findings)[0]["confidence"] == "confirmed"


def test_demote_default_only_enforces_access_control_families():
    # a non-access-control family with a thin confirm is NOT demoted by default (avoids new FNs),
    # but IS demoted under enforce='all'.
    findings = [{"title": "thin cmdi", "family": "cmdi", "confidence": "confirmed", "evidence": "x"}]
    assert PS.demote_unproven(findings)[0]["confidence"] == "confirmed"          # default: left alone
    assert PS.demote_unproven(findings, enforce_families="all")[0]["confidence"] == "lead"
