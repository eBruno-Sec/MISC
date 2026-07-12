"""Regression tests for the APOLLO report's embedded export script.

Guards the bug where `export_script` was a normal (non-raw) triple-quoted Python
string, so the JS `\n` string literals were turned into REAL newlines by Python
and landed inside JS '...' quotes — an "Invalid or unexpected token" syntax error
that killed the *entire* inline script, so every export / print / theme button was
silently dead. The fix makes the template a raw string (r\"\"\"), emitting literal
backslash-n for the browser to parse. See agents/apollo.py.
"""
import asyncio
import re

from agents.apollo import Apollo
from core.config import settings
from core.models import Finding


def _render(tmp_path):
    a = Apollo(session=None, mission_id="testmission1234")
    findings = [Finding(title="Vuln", severity="high", found_by="ares",
                        description="d", evidence="line1\nline2", remediation="r")]
    stats = {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0}
    path = asyncio.run(a._generate_html_report(
        "example.com", findings, stats, "Summary.", {"athena": {"mode": "full"}}
    ))
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _script(html: str) -> str:
    m = re.search(r'<script nonce="[^"]+">(.*?)</script>', html, re.S)
    assert m, "export script block not found in report"
    return m.group(1)


def test_export_script_newlines_are_escaped_not_literal(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "reports_dir", str(tmp_path))
    js = _script(_render(tmp_path))
    # Correct form: backslash-n (two chars) inside the JS string literals.
    assert "L.join('\\n')" in js
    assert "f.evidence.split('\\n')" in js
    # Buggy form: a REAL newline inside split('...') / join('...') would break parsing.
    assert "split('\n')" not in js
    assert "join('\n')" not in js


def test_export_script_has_no_unterminated_string_literals(tmp_path, monkeypatch):
    """Every single-quoted JS literal on a line must be balanced — a raw newline
    inside one (the old bug) leaves an odd number of unescaped quotes on that line."""
    monkeypatch.setattr(settings, "reports_dir", str(tmp_path))
    js = _script(_render(tmp_path))
    for i, line in enumerate(js.splitlines(), 1):
        # ignore escaped quotes; count bare single quotes
        bare = len(re.findall(r"(?<!\\)'", line))
        assert bare % 2 == 0, f"unbalanced single-quote (unterminated string) on JS line {i}: {line!r}"


def test_all_export_buttons_wired(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "reports_dir", str(tmp_path))
    html = _render(tmp_path)
    for bid in ("oly-print", "oly-html", "oly-md", "oly-txt", "oly-json", "oly-theme"):
        assert f'id="{bid}"' in html, f"button {bid} missing"
        assert f"getElementById('{bid}')" in html, f"listener for {bid} not wired"
