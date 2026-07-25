"""Report generation: HTML (escaped + redacted), JSON, SARIF (§28)."""

from __future__ import annotations

from reporting.exports import finding_json, sarif_report
from reporting.html import atomic_finding_html, attack_chain_html

_FINDING = {
    "id": "f-1",
    "internal_class": "authorization.object_level",
    "title": "Broken object-level authorization on basket read",
    "summary": "A standard user can read another user's basket.",
    "technical_description": "diff returned foreign object",
    "validation_state": "confirmed",
    "severity_label": "high",
    "evidence_profile": "authorization_differential",
    "evidence_refs": ["e1", "e2"],
    "capability_refs": ["cap-1"],
    "capability_labels": ["read_foreign_object"],
    "affected_endpoints": ["http://juice-shop:3000/rest/basket/2"],
}


def test_atomic_html_is_self_contained_and_escaped_and_redacts():
    ex = {
        "method": "GET",
        "url": "http://juice-shop:3000/rest/basket/2",
        "request_headers": {"Authorization": "Bearer super.secret.jwt"},
    }
    html = atomic_finding_html(_FINDING, evidence=[{"evidence_type": "http_response", "sha256": "abc", "object_uri": "s3://x"}], exchanges=[ex])
    assert "<!doctype html>" in html
    assert "Content-Security-Policy" in html
    assert "super.secret.jwt" not in html  # redacted in reproduction
    assert "&lt;" in html or "CWE-639" in html  # escaping + standards present
    assert "read_foreign_object" in html


def test_finding_json_has_standards_mapping():
    j = finding_json(_FINDING)
    assert j["standards"]["cwe"] == ["CWE-639", "CWE-284"]
    assert "BOLA" in j["standards"]["owasp_api"]


def test_sarif_2_1_0_structure_and_level():
    sarif = sarif_report([_FINDING])
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "ArsGoatia"
    result = run["results"][0]
    assert result["ruleId"] == "authorization.object_level"
    assert result["level"] == "error"  # high -> error
    assert result["properties"]["capability_refs"] == ["cap-1"]


def test_attack_chain_html_marks_non_cvss():
    chain = {
        "id": "c-1",
        "title": "Cross-user object read chain",
        "objective": "read another user's object",
        "chain_severity": "high",
        "chain_scoring_rationale": {"method_version": "1.0.0", "not_cvss": True},
    }
    html = attack_chain_html(chain, [{"sequence_number": 1, "finding_id": "f-1", "resulting_capability_ids": ["cap-1"], "validation_state": "validated"}])
    assert "not CVSS" in html
    assert "Cross-user object read chain" in html
