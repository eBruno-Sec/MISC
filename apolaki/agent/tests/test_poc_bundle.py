"""Per-finding PoC evidence bundle (#111): one self-contained, submission-ready artifact combining
reproduction + FP-safety contract (#115) + graded impact + retest recipe (#117) + provenance. Pure."""
import json

import poc_bundle


_F = {"id": "f1", "title": "Sensitive data / credentials exposed", "family": "exposure",
      "severity": "critical", "confidence": "confirmed", "cwe": "CWE-200",
      "target": "http://h/users/v1/_debug", "remediation": "Remove the debug endpoint.",
      "evidence": "Response body contained 3 credential values."}


def test_bundle_is_self_contained_and_covers_every_section():
    b = poc_bundle.build(_F, tool_version="abc123")
    assert b["schema"] == "apolaki.poc-bundle/1" and b["generated_at"]
    assert b["finding"]["id"] == "f1" and b["finding"]["cwe"] == "CWE-200"
    # reproduction: a curl + a rendered markdown PoC
    assert b["reproduction"]["curl"] and "http://h/users/v1/_debug" in b["reproduction"]["curl"]
    assert b["reproduction"]["markdown"]
    # confirmation: the #115 FP-safety contract rode in
    assert b["confirmation"]["negative_control"]
    assert isinstance(b["confirmation"]["evidence_requirements"], list) and b["confirmation"]["evidence_requirements"]
    assert b["confirmation"]["safety"] and b["confirmation"]["cleanup"]
    # impact: evidence-graded; retest: the #117 recipe (exposure is GET-retestable)
    assert b["impact"] and b["impact"]["demonstrated"].startswith("Confirmed")
    assert b["retest"]["retestable"] is True and b["retest"]["method"] == "GET"
    assert b["provenance"]["tool_version"] == "abc123"
    json.dumps(b)   # must be JSON-serializable for the endpoint


def test_build_all_only_bundles_confirmed_findings():
    findings = [_F,
                {"id": "lead1", "title": "maybe xss", "family": "xss", "confidence": "lead",
                 "target": "http://h/s?q=x"}]
    bundles = poc_bundle.build_all(findings)
    assert len(bundles) == 1 and bundles[0]["finding"]["id"] == "f1"   # the lead is excluded


def test_bundle_does_not_leak_raw_auth_secrets():
    f = dict(_F, curl="curl -H 'Authorization: Bearer SECRETTOKEN' http://h/x",
             request="GET /x\nCookie: session=RAWSESSIONVALUE")
    b = poc_bundle.build(f, exchanges=[{"url": "http://h/x", "method": "GET",
                                        "request_headers": {"Authorization": "Bearer SECRETTOKEN"}}])
    # the rendered PoC markdown is produced through poc.py redaction — no raw secret in it
    assert "SECRETTOKEN" not in b["reproduction"]["markdown"]
    assert "RAWSESSIONVALUE" not in b["reproduction"]["markdown"]
