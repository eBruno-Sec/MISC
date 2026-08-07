"""CI gate summary (#111) — fails the check ONLY on a confirmed gating-severity finding, never on a lead,
and renders an evidence-first PR comment."""
import ci_summary as C


def _rep(findings=None, leads=None):
    return {"report_id": "sid1", "findings": findings or [], "leads": leads or [],
            "auth_artery": {"ran": True, "personas": [1, 2], "auth_success": 2, "matrix": {"operations": 14}}}


def test_confirmed_high_fails_the_gate():
    rep = _rep(findings=[{"title": "SQLi", "family": "sqli", "confidence": "confirmed", "severity": "high",
                          "cwe": "CWE-89", "evidence": "boolean-diff confirmed", "target": "http://app/x",
                          "reproduction_steps": ["GET /x?id=1' --", "observe SQL error"]}])
    out = C.summarize(rep)
    assert out["verdict"] == "fail" and out["exit_code"] == 1 and out["gating"] == 1
    assert "SQLi" in out["markdown"] and "reproduction" in out["markdown"] and "boolean-diff" in out["markdown"]


def test_leads_never_fail_the_gate():
    rep = _rep(leads=[{"title": "reflected marker", "family": "xss", "confidence": "lead", "severity": "high"}])
    out = C.summarize(rep)
    assert out["verdict"] == "pass" and out["exit_code"] == 0 and out["confirmed"] == 0 and out["leads"] == 1


def test_confirmed_below_gate_passes():
    # a confirmed MEDIUM does not fail a high/critical gate
    rep = _rep(findings=[{"title": "verbose error", "family": "misconfig", "confidence": "confirmed",
                          "severity": "medium"}])
    out = C.summarize(rep, fail_on=("critical", "high"))
    assert out["verdict"] == "pass" and out["exit_code"] == 0 and out["counts"].get("medium") == 1


def test_fail_on_is_configurable():
    rep = _rep(findings=[{"title": "info leak", "confidence": "confirmed", "severity": "medium"}])
    assert C.summarize(rep, fail_on=("medium",))["verdict"] == "fail"


def test_comment_shows_auth_artery_proof():
    out = C.summarize(_rep())
    assert "Authenticated scan" in out["markdown"] and "2 authenticated" in out["markdown"]
    assert out["verdict"] == "pass"


def test_legacy_string_reproduction_is_tolerated():
    rep = _rep(findings=[{"title": "RCE", "confidence": "confirmed", "severity": "critical",
                          "reproduction_steps": "run the payload"}])
    out = C.summarize(rep)
    assert out["verdict"] == "fail" and "run the payload" in out["markdown"]
