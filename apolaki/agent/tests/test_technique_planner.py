"""Tests for the deterministic evidence-driven technique planner (preconditions gate, no LLM)."""
from __future__ import annotations

import technique_model as TM
import technique_planner as TP


def _tech(tid, cwe, status="proven", conf=80):
    t = TM.blank(tid)
    t.update({"cwe": [cwe], "status": status,
              "confidence": {"score": conf, "tier": "high", "factors": []}, "try_it": "payload"})
    return t


def test_derive_observations_from_code_intel_and_harvest():
    ci = {"endpoints": ["/rest/user/login", "/api/products/search"], "sensitive_routes": ["administration"],
          "bundles": [1], "logic": {"detail": [{"tests": [1]}]}}
    harvest = {"by_kind": {"object_id": 3, "version": 1}}
    obs = TP.derive_observations(harvest=harvest, code_intel=ci)
    assert {"serves_js", "has_api", "has_login", "has_search_param", "has_sensitive_route",
            "has_object_id", "has_versions", "has_workflow"} <= obs


def test_plan_gates_on_preconditions():
    techs = [_tech("idor_bola_read", "CWE-639"), _tech("xxe_file_ssrf", "CWE-611"),
             _tech("sqli_auth_bypass", "CWE-89")]
    obs = {"has_object_id", "has_login"}                 # object-ids + login, but NO xml input
    ids = [x["id"] for x in TP.plan(obs, techs)]
    assert "idor_bola_read" in ids and "sqli_auth_bypass" in ids
    assert "xxe_file_ssrf" not in ids                    # precondition has_xml_input unmet -> gated out


def test_empty_plan_when_no_evidence_and_ranks_when_present():
    techs = [_tech("idor_bola_read", "CWE-639", conf=40)]
    assert TP.plan(set(), techs) == []                   # no evidence -> honest empty plan (exhausted path)
    p = TP.plan({"has_object_id"}, techs, kev_cwes={"CWE-639"})
    assert p and p[0]["preconditions_met"] == ["has_object_id"] and p[0]["score"] > 0
    assert p[0]["action"] == "payload" and "oracle" in p[0]
