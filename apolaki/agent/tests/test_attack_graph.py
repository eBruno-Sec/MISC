"""Tests for the unified attack graph (pure aggregation of the shared engagement state)."""
from __future__ import annotations

import attack_graph as AG


def test_build_links_observations_to_techniques_to_findings():
    obs = {"has_login", "has_object_id"}
    plan = [{"id": "sqli_auth_bypass", "name": "SQLi", "family": "sqli", "score": 75,
             "preconditions_met": ["has_login"]},
            {"id": "idor_bola_read", "name": "IDOR", "family": "access_control", "score": 70,
             "preconditions_met": ["has_object_id"]}]
    findings = [{"title": "SQLi in login", "family": "sqli", "severity": "critical"}]
    leads = [{"title": "maybe IDOR", "severity": "info"}]
    g = AG.build(findings=findings, leads=leads, observations=obs, plan=plan, host="t:3000")
    ids = {n["id"] for n in g["nodes"]}
    assert {"host:t:3000", "obs:has_login", "tech:sqli_auth_bypass", "find:SQLi in login"} <= ids
    rels = {(e["source"], e["target"], e["rel"]) for e in g["edges"]}
    assert ("obs:has_login", "tech:sqli_auth_bypass", "activates") in rels      # evidence -> technique
    assert ("tech:sqli_auth_bypass", "find:SQLi in login", "confirms") in rels  # technique -> finding
    assert g["stats"]["technique"] == 2 and g["stats"]["finding"] == 1 and g["stats"]["lead"] == 1


def test_empty_is_just_the_host():
    g = AG.build(host="x")
    assert g["stats"]["nodes"] == 1 and g["nodes"][0]["kind"] == "host"
