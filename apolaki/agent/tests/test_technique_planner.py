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


def test_registry_seed_projects_a_planner_ready_registry():
    seed = TP.registry_seed()
    assert len(seed) >= 30
    by_id = {t["id"]: t for t in seed}
    s = by_id["sqli_auth_bypass"]
    # generalized (>=2 labs) -> proven + top confidence; shape is exactly what plan() consumes
    assert s["status"] == "proven" and s["confidence"]["score"] == 60
    assert isinstance(s["cwe"], list) and s["vuln_class"] == "sql_injection"
    # the seed actually drives a gated plan
    p = TP.plan({"has_login", "has_object_id"}, seed)
    assert any(a["id"] == "sqli_auth_bypass" for a in p)


def test_plan_attaches_filter_bypass_ladder_for_injection_classes():
    # the mutation engine is no longer an island: injection-class plan entries carry a bypass ladder
    p = TP.plan({"has_login", "has_object_id"}, TP.registry_seed())
    sqli = next((a for a in p if a["id"] == "sqli_auth_bypass"), None)
    assert sqli and sqli.get("bypass_ladder")
    assert any("%27" in v for v in sqli["bypass_ladder"])        # a url-encoded bypass variant is present
    # a non-injection class (e.g. idor/access_control) carries no payload ladder
    idor = next((a for a in p if a["id"] == "idor_bola_read"), None)
    assert idor and not idor.get("bypass_ladder")
