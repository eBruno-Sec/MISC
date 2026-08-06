"""Evidence-aware business-impact grading (mission Phase-6 discipline): a confirmed finding states
what was DEMONSTRATED, separated from PLAUSIBLE next-step and UNVERIFIED worst-case, so a report never
overclaims. Deterministic; truth-first."""
import report


def test_confirmed_finding_grades_demonstrated_and_caps_worst_case():
    g = report.graded_business_impact({"family": "sqli", "confidence": "confirmed"})
    assert g is not None
    assert g["demonstrated"].startswith("Confirmed on this target:")
    assert "Plausible next step" in g["plausible"]
    # the worst case is always fenced with an explicit do-not-claim caveat (no drama)
    assert "do NOT claim without further evidence" in g["unverified"]
    assert g["confidence"] == "confirmed"


def test_unconfirmed_finding_is_labelled_candidate_not_demonstrated():
    g = report.graded_business_impact({"family": "idor", "confidence": "lead"})
    assert "NOT oracle-confirmed" in g["demonstrated"]
    assert "another account's object" in g["demonstrated"]


def test_family_resolves_via_cwe_when_family_missing():
    g = report.graded_business_impact({"cwe": "CWE-89", "confidence": "confirmed"})
    assert g and "database" in g["demonstrated"].lower()


def test_unknown_family_returns_none_rather_than_inventing_impact():
    assert report.graded_business_impact({"family": "totally_unknown_class"}) is None


def test_proof_and_retest_surfaces_contract_and_retest_method():
    # a GET-oracle family: FP-safety negative control (from #115) + a concrete auto-retest (from #117)
    pr = report.proof_and_retest({"family": "exposure", "target": "http://h/_debug", "confidence": "confirmed"})
    assert pr["negative_control"]
    assert "Re-request GET http://h/_debug" in pr["retest"] and "OPEN if" in pr["retest"]
    # a state-changing family: operator-driven retest, still carries a real negative control
    pr2 = report.proof_and_retest({"family": "sqli", "target": "http://h/login", "confidence": "confirmed"})
    assert "SQL" in pr2["negative_control"] and "Operator-driven" in pr2["retest"]


def test_grading_never_overclaims_demonstrated_equals_worstcase():
    # demonstrated must never be the same statement as the unverified worst case (truth-first)
    for fam in ("sqli", "xss", "ssrf", "cmdi", "vulnerable_component"):
        g = report.graded_business_impact({"family": fam, "confidence": "confirmed"})
        assert g["demonstrated"] != g["unverified"]
