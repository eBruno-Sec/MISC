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


def test_root_cause_covers_real_emitted_families():
    # Families the scan tools actually emit must map to a precise architectural cause, NOT dump into
    # "Other". Aliases must MERGE onto their canonical sibling (bola≡idor, stored_xss≡xss, …).
    assert report._ROOT_CAUSE.get("bola") == report._ROOT_CAUSE["idor"]
    assert report._ROOT_CAUSE.get("stored_xss") == report._ROOT_CAUSE["xss"]
    assert report._ROOT_CAUSE.get("git_exposure") == report._ROOT_CAUSE["exposure"]
    for fam in ("jwt", "oauth", "prototype_pollution", "crypto", "race", "upload",
                "cache_poisoning", "graphql", "host_header", "llm_prompt_injection",
                "credential_exposure", "config_exposure", "backup_exposure", "info_disclosure"):
        assert fam in report._ROOT_CAUSE, "emitted family %s falls through to Other" % fam
    # a bola + an idor collapse into ONE broken-object-authz group
    g = report.root_cause_groups([{"title": "a", "severity": "high", "family": "idor"},
                                  {"title": "b", "severity": "high", "family": "bola"}])
    assert len(g) == 1 and g[0]["count"] == 2


def test_report_shows_intelligence_orchestration():
    # the report must make the orchestration VISIBLE: code-intel recon + technique-advisor picks that
    # drove the scan, so "was the intel actually used" is answerable from the report itself.
    orch = {"code_intel": {"endpoints": 21, "added_to_surface": 8, "sensitive_routes": 5, "logic_hypotheses": 6},
            "advisor": [{"id": "sqli_auth_bypass", "name": "Sqli Auth Bypass", "score": 88.0,
                         "reasons": ["matches a confirmed sqli finding", "CISA KEV known-exploited"]}]}
    html = report.generate_html_report("P", [{"title": "x", "severity": "high", "family": "sqli", "cwe": "CWE-89"}],
                                       {"in_scope": ["t"]}, orchestration=orch)
    assert "Intelligence Orchestration" in html
    assert "mined <b>21</b>" in html and "Sqli Auth Bypass" in html
    # backward compatible: no orchestration -> no section, no crash
    assert "Intelligence Orchestration" not in report.generate_html_report("P", [], {"in_scope": ["t"]})


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


def test_orchestration_next_best_renders_in_markdown_report():
    orch = {"advisor": [{"id": "idor_bola_read", "name": "IDOR/BOLA", "score": 71, "reasons": ["object ids"]}],
            "next_best": [{"id": "reflected_xss", "family": "xss", "action": "inject a reflected param"}]}
    # with a confirmed finding -> the Intelligence Orchestration section carries the next-best actions
    f = [{"title": "SQLi", "severity": "high", "confidence": "confirmed", "target": "http://x/",
          "family": "sql_injection"}]
    md = report.generate_report("Demo", f, {"in_scope": ["x"]}, orchestration=orch)
    assert "## Intelligence Orchestration" in md and "reflected_xss" in md
    # with NO findings -> the operator still gets the deterministic path to keep testing
    md0 = report.generate_report("Demo", [], {"in_scope": ["x"]}, orchestration=orch)
    assert "## Recommended Next Actions" in md0 and "reflected_xss" in md0
