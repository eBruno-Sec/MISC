"""Unit tests for PoC rendering (core/poc.py). Pure functions, no DB/network.

Run from the backend dir:  python -m pytest tests/ -q
"""
from core import poc


SAMPLE_EX = {
    "method": "GET",
    "url": "https://target.example/blog?back=javascript:alert(1)&search=x",
    "request_headers": {
        "Host": "target.example",
        "User-Agent": "olympus/1.0",
        "Cookie": "session=SECRET123",
        "Authorization": "Bearer TOP-SECRET",
    },
    "request_body": None,
    "status_code": 302,
    "response_headers": {"Location": "javascript:alert(1)"},
    "response_body": "Redirecting...",
    "notes": "Open redirect on back",
}


def test_redact_headers_masks_only_sensitive():
    out = poc.redact_headers(SAMPLE_EX["request_headers"])
    assert out["Cookie"] == poc.REDACTED
    assert out["Authorization"] == poc.REDACTED
    assert out["User-Agent"] == "olympus/1.0"        # non-sensitive untouched
    assert out["Host"] == "target.example"


def test_to_curl_redacts_and_quotes():
    cmd = poc.to_curl(SAMPLE_EX, redact=True)
    assert cmd.startswith("curl -i -sk")
    assert "SECRET123" not in cmd                     # cookie value gone
    assert "TOP-SECRET" not in cmd
    assert poc.REDACTED in cmd                        # redaction marker present
    # dangerous chars in the URL must be shell-quoted, not raw
    assert "javascript:alert(1)" in cmd
    # Host/Content-Length are set by curl itself, not emitted as -H
    assert "-H 'Host:" not in cmd


def test_to_curl_no_redact_keeps_values():
    cmd = poc.to_curl(SAMPLE_EX, redact=False)
    assert "SECRET123" in cmd


def test_to_curl_post_uses_method_and_body():
    ex = {"method": "POST", "url": "https://t.example/api",
          "request_headers": {"Content-Type": "application/json"},
          "request_body": '{"a":1}'}
    cmd = poc.to_curl(ex)
    assert "-X POST" in cmd
    assert "--data" in cmd and '{"a":1}' in cmd


def test_to_raw_http_has_request_line_and_host():
    raw = poc.to_raw_http(SAMPLE_EX)
    lines = raw.splitlines()
    assert lines[0] == "GET /blog?back=javascript:alert(1)&search=x HTTP/1.1"
    assert "Host: target.example" in lines
    assert poc.REDACTED in raw                        # cookie redacted in raw too


def test_finding_markdown_with_exchange_is_copy_ready():
    finding = {
        "id": "f1", "title": "Open Redirect: back", "severity": "medium",
        "cvss_score": 5.4, "found_by": "ares",
        "description": "Redirect param controls the target.",
        "remediation": "Allowlist redirect targets.",
    }
    md = poc.finding_markdown(finding, [SAMPLE_EX], redact=True)
    assert md.startswith("## Open Redirect: back")
    assert "MEDIUM" in md
    assert "```bash" in md and "curl -i -sk" in md    # curl repro block
    assert "```http" in md                            # raw request block
    assert "Steps to reproduce" in md
    assert "Remediation" in md
    assert "SECRET123" not in md                       # redacted end-to-end


def test_finding_markdown_without_exchange_falls_back_to_evidence():
    finding = {"id": "f2", "title": "SQLi", "severity": "critical",
               "evidence": "sqlmap: param id is injectable"}
    md = poc.finding_markdown(finding, [], redact=True)
    assert "SQLi" in md
    assert "sqlmap: param id is injectable" in md      # evidence used when no exchange


def test_mission_markdown_orders_by_severity_and_counts():
    findings = [
        {"id": "a", "title": "Low thing", "severity": "low"},
        {"id": "b", "title": "Crit thing", "severity": "critical"},
    ]
    md = poc.mission_markdown("target.example", findings, {"b": [SAMPLE_EX]})
    assert "# Security Assessment — target.example" in md
    assert "1 critical" in md and "1 low" in md
    # critical sorts before low
    assert md.index("Crit thing") < md.index("Low thing")
