"""Tests for the Coverage Engine + Root-Cause inference in report.py."""
from __future__ import annotations

import report


def test_root_cause_groups_by_architecture():
    findings = [{"title": "IDOR a", "severity": "high", "family": "idor"},
                {"title": "IDOR b", "severity": "high", "family": "idor"},
                {"title": "SQLi", "severity": "critical", "family": "sqli"}]
    g = report.root_cause_groups(findings)
    by = {x["root_cause"]: x for x in g}
    assert by["Broken object-level authorization"]["count"] == 2      # both IDORs → one root cause
    assert "Unsafe handling of untrusted input (injection)" in by
    assert g[0]["worst"] == "critical"                               # worst-first ordering


def test_coverage_gaps_is_honest():
    gaps = report.coverage_gaps(mode="active", execution={"strategy": "deterministic"},
                                tool_ledger={"authenticated": False}, authenticated=False)
    areas = [a for a, _tag, _exp in gaps]
    assert any("Authenticated" in a for a in areas)                  # no creds → auth-surface gap
    assert any("Intrusive" in a for a in areas)                      # not Full mode → deep-DAST gap
    # a fully-authenticated Full/agentic run suppresses the creds + mode gaps
    g2 = report.coverage_gaps(mode="full", execution={"strategy": "agentic"},
                              tool_ledger={"authenticated": True}, authenticated=True)
    a2 = [a for a, _t, _e in g2]
    assert "Authenticated attack surface" not in a2
    assert "Intrusive / deep DAST" not in a2


def test_gaps_surface_failed_tools():
    gaps = report.coverage_gaps(mode="full", execution={"strategy": "agentic"},
                                tool_ledger={"authenticated": True,
                                             "tools": [{"tool": "run_zap", "status": "failed"}]},
                                authenticated=True)
    assert any(tag == "failed" for _a, tag, _e in gaps)
