from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from packages.domain.reporting import ReportManifest, render_finding_html, render_sarif


def _finding(**overrides):
    finding = {
        "weakness": "Broken Object Level Authorization",
        "status": "confirmed",
        "affected_object": "/api/v1/users/{id}",
        "confidence": "high",
        "severity": "critical",
        "root_cause": "missing tenant scoping on lookup",
        "validator_digest": "sha256:" + "a" * 64,
    }
    finding.update(overrides)
    return finding


def _evidence():
    return [
        {"kind": "http_transaction", "digest": "sha256:" + "b" * 64, "sensitivity": "restricted"}
    ]


# ---------------------------------------------------------------------------
# render_finding_html
# ---------------------------------------------------------------------------


def test_render_finding_html_produces_doctype_and_structure():
    html_out = render_finding_html(_finding(), _evidence(), nonce="TESTNONCE123")
    assert html_out.startswith("<!DOCTYPE html>")
    assert "<html" in html_out
    assert "</html>" in html_out
    assert "ArsGoatia Finding Report" in html_out


def test_render_finding_html_includes_csp_nonce():
    html_out = render_finding_html(_finding(), _evidence(), nonce="TESTNONCE123")
    assert "Content-Security-Policy" in html_out
    assert "'nonce-TESTNONCE123'" in html_out
    assert 'style nonce="TESTNONCE123"' in html_out
    assert 'script nonce="TESTNONCE123"' in html_out


def test_render_finding_html_generates_nonce_when_omitted():
    html_out = render_finding_html(_finding(), _evidence())
    assert "Content-Security-Policy" in html_out
    # a nonce was generated and used consistently for style + script
    assert "'nonce-" in html_out


def test_render_finding_html_two_calls_generate_different_nonces():
    a = render_finding_html(_finding(), _evidence())
    b = render_finding_html(_finding(), _evidence())
    assert a != b


def test_render_finding_html_escapes_xss_in_title_field():
    malicious = _finding(weakness="<script>alert(1)</script>")
    html_out = render_finding_html(malicious, _evidence(), nonce="N")
    assert "<script>alert(1)</script>" not in html_out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_out


def test_render_finding_html_escapes_xss_in_description_fields():
    malicious = _finding(
        root_cause='"><img src=x onerror=alert(document.cookie)>',
        affected_object="<svg onload=alert(1)>",
    )
    html_out = render_finding_html(malicious, _evidence(), nonce="N")
    assert "<img src=x onerror=" not in html_out
    assert "<svg onload=" not in html_out
    assert "&lt;svg onload=alert(1)&gt;" in html_out


def test_render_finding_html_escapes_xss_in_evidence_rows():
    evidence = [
        {"kind": "<script>evil()</script>", "digest": "sha256:x", "sensitivity": "restricted"}
    ]
    html_out = render_finding_html(_finding(), evidence, nonce="N")
    assert "<script>evil()</script>" not in html_out
    assert "&lt;script&gt;evil()&lt;/script&gt;" in html_out


# ---------------------------------------------------------------------------
# render_sarif
# ---------------------------------------------------------------------------


def test_render_sarif_top_level_structure():
    sarif = render_sarif([_finding()])
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-schema-2.1.0.json")
    assert "runs" in sarif and len(sarif["runs"]) == 1


def test_render_sarif_driver_metadata():
    sarif = render_sarif([_finding()], tool_version="9.9.9")
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "ArsGoatia"
    assert driver["version"] == "9.9.9"


def test_render_sarif_result_mapping():
    sarif = render_sarif([_finding(status="confirmed")])
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "Broken Object Level Authorization"
    assert result["level"] == "error"
    assert result["message"]["text"] == "missing tenant scoping on lookup"
    assert (
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "/api/v1/users/{id}"
    )


def test_render_sarif_non_confirmed_is_warning_level():
    sarif = render_sarif([_finding(status="candidate")])
    assert sarif["runs"][0]["results"][0]["level"] == "warning"


def test_render_sarif_empty_findings_list():
    sarif = render_sarif([])
    assert sarif["runs"][0]["results"] == []


# ---------------------------------------------------------------------------
# ReportManifest.compute_digest
# ---------------------------------------------------------------------------


def _manifest(**overrides):
    kwargs = dict(
        engagement_revision_id=uuid4(),
        coverage_watermark=datetime.now(timezone.utc),
        finding_versions={"f1": 1, "f2": 3},
        attack_path_ids=["p2", "p1"],
        evidence_digests=["sha256:b", "sha256:a"],
        template_digest="sha256:tpl",
        risk_model_version="arsgoatia-chain-severity/1.0.0",
        renderer_digest="sha256:rend",
    )
    kwargs.update(overrides)
    return ReportManifest(**kwargs)


def test_report_manifest_digest_is_deterministic():
    manifest = _manifest()
    assert manifest.compute_digest() == manifest.compute_digest()


def test_report_manifest_digest_starts_with_sha256():
    assert _manifest().compute_digest().startswith("sha256:")


def test_report_manifest_digest_independent_of_list_order():
    shared_id = uuid4()
    shared_time = datetime.now(timezone.utc)
    a = ReportManifest(
        engagement_revision_id=shared_id,
        coverage_watermark=shared_time,
        finding_versions={"f1": 1},
        attack_path_ids=["p1", "p2"],
        evidence_digests=["sha256:a", "sha256:b"],
        template_digest="sha256:tpl",
        risk_model_version="v1",
        renderer_digest="sha256:rend",
    )
    b = ReportManifest(
        engagement_revision_id=shared_id,
        coverage_watermark=shared_time,
        finding_versions={"f1": 1},
        attack_path_ids=["p2", "p1"],
        evidence_digests=["sha256:b", "sha256:a"],
        template_digest="sha256:tpl",
        risk_model_version="v1",
        renderer_digest="sha256:rend",
    )
    assert a.compute_digest() == b.compute_digest()


def test_report_manifest_digest_changes_with_content():
    a = _manifest()
    b = _manifest(finding_versions={"f1": 1, "f2": 4})
    assert a.compute_digest() != b.compute_digest()
