"""The HTML report renders a Target Intelligence section from a harvested intel snapshot,
filters the noisy encoded bucket, keeps secrets redacted, and stays unchanged without intel."""
from __future__ import annotations

import report


def _intel():
    return {"total": 5,
            "by_kind": {"email": 1, "route": 2, "encoded": 98, "secret": 1},
            "candidates": {"email": ["admin@juice-sh.op"],
                           "route": ["/#recycle", "/administration"],
                           "encoded": ["QUJDDQUJDDQUJDDQUJDD"],   # minified-JS noise — must NOT show
                           "secret": ["<redacted:40>"]}}


def test_report_renders_target_intelligence_section():
    html = report.generate_html_report("P", [], {"in_scope": ["juice-shop"]}, intel=_intel())
    assert "Target Intelligence" in html
    assert "admin@juice-sh.op" in html
    assert "/administration" in html
    assert "redacted:40" in html            # secret surfaced only in redacted form


def test_report_omits_noisy_encoded_bucket():
    html = report.generate_html_report("P", [], {"in_scope": ["x"]}, intel=_intel())
    assert "QUJDDQUJDD" not in html          # encoded noise never rendered


def test_markdown_report_renders_target_intelligence_section():
    f = {"title": "SQLi", "severity": "high", "family": "sqli", "cwe": "CWE-89",
         "target": "http://juice-shop/x", "evidence": "proof", "confidence": "confirmed"}
    md = report.generate_report("P", [f], {"in_scope": ["juice-shop"]}, intel=_intel())
    assert "## Target Intelligence" in md
    assert "admin@juice-sh.op" in md
    assert "QUJDDQUJDD" not in md          # encoded noise omitted in markdown too


def test_report_without_intel_has_no_section():
    html = report.generate_html_report("P", [], {"in_scope": ["x"]})
    assert "Target Intelligence" not in html


def test_report_with_empty_intel_has_no_section():
    html = report.generate_html_report("P", [], {"in_scope": ["x"]}, intel={"candidates": {}})
    assert "Target Intelligence" not in html
