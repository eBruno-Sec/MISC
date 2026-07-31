"""Tests for the deterministic benchmark harness -- pure evaluation against expected-vuln manifests."""
from __future__ import annotations

import benchmark


def test_evaluate_coverage_and_false_negatives():
    findings = [{"family": "sqli", "confidence": "confirmed"},
                {"family": "stored_xss", "confidence": "confirmed"},
                {"cwe": "CWE-639", "confidence": "confirmed"}]      # access_control via CWE fallback
    r = benchmark.evaluate("juiceshop", findings)
    assert "sqli" in r["confirmed"] and "xss" in r["confirmed"] and "access_control" in r["confirmed"]
    assert "business_logic" in r["false_negatives"]                 # expected but missed
    assert any(h["class"] == "business_logic" for h in r["failed_stage"])
    assert r["metrics"]["confirmed_classes"] == 3


def test_leads_count_as_discovery_not_confirmed():
    r = benchmark.evaluate("juiceshop", findings=[], leads=[{"family": "business_logic"}])
    assert "business_logic" in r["discovered"]                      # a lead surfaces the class
    assert "business_logic" not in r["confirmed"]                    # but never confirms it
    assert any(pc["class"] == "business_logic" and pc["as_lead_only"] for pc in r["per_class"])


def test_unexpected_class_is_flagged():
    r = benchmark.evaluate("dvwa", [{"family": "ssrf", "confidence": "confirmed"}])
    assert "ssrf" in r["unexpected"]                                # ssrf isn't in the dvwa manifest


def test_unknown_fixture_is_handled():
    assert "error" in benchmark.evaluate("nope", [])


def test_list_fixtures():
    ids = {f["id"] for f in benchmark.list_fixtures()["fixtures"]}
    assert {"juiceshop", "dvwa", "ginandjuice"} <= ids


def test_prototype_pollution_is_not_collapsed_into_vulnerable_component():
    # regression: prototype_pollution (CWE-1321) and vulnerable_component (CWE-1035) are DISTINCT classes.
    assert benchmark._canon_class({"family": "prototype_pollution"}) == "prototype_pollution"
    assert benchmark._canon_class({"cwe": "CWE-1321"}) == "prototype_pollution"
    assert benchmark._canon_class({"family": "vulnerable_component"}) == "vulnerable_component"
    assert benchmark._canon_class({"cwe": "CWE-1035"}) == "vulnerable_component"


def test_ginandjuice_absorption_confirms_scanned_classes_no_false_positive():
    # the three classes Apolaki actually confirmed against ginandjuice.shop, tagged as the live scan tags them.
    findings = [{"family": "vulnerable_component", "cwe": "CWE-1035", "confidence": "confirmed"},
                {"family": "template_injection", "cwe": "CWE-1336", "confidence": "confirmed"},
                {"family": "prototype_pollution", "cwe": "CWE-1321", "confidence": "confirmed"}]
    r = benchmark.evaluate("ginandjuice", findings)
    assert {"template_injection", "vulnerable_component", "prototype_pollution"} <= set(r["confirmed"])
    assert r["unexpected"] == []                                      # zero false positives holds
