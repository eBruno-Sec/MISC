"""Tests for the deterministic evidence-driven technique planner (preconditions gate, no LLM)."""
from __future__ import annotations

import technique_model as TM
import technique_planner as TP


def _tech(tid, cwe, status="proven", conf=80):
    t = TM.blank(tid)
    t.update({"cwe": [cwe], "status": status,
              "confidence": {"score": conf, "tier": "high", "factors": []}, "try_it": "payload"})
    return t


def test_planner_reads_live_graph():
    # CHAD review #7: the planner must read the LIVE canonical graph, not only flat recon lists.
    import asset_graph as AG
    g = AG.AssetGraph("m")
    g.observe("object", "h/api/orders/1", source="live")
    g.observe("endpoint", "h/rest/user/login", label="/rest/user/login", source="live")
    g.observe("capability", "session_acquired", source="scan")
    projected = g.to_observations()
    assert {"has_object_id", "has_login", "has_api", "authenticated"} <= projected
    # derive_observations merges the graph's observations even with EMPTY flat inputs
    obs = TP.derive_observations(surface=[], harvest={}, graph=g)
    assert "has_object_id" in obs and "authenticated" in obs


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


def test_planner_is_graph_authoritative_flat_recon_cannot_drive_it():
    # CHAD capability B: the graph is the AUTHORITY. plan_graph_authoritative takes no surface/harvest
    # argument, so flat recon cannot independently drive it — the facts must live in the GRAPH.
    import asset_graph as AG
    seed = TP.registry_seed()
    # a populated graph (object id + search param + login) yields real observations + a plan
    g = AG.AssetGraph("m")
    g.ingest_intel({"candidates": {"object_id": ["1"], "param": ["q"], "endpoint": ["/rest/user/login"]}})
    out = TP.plan_graph_authoritative(g, seed)
    assert out["graph_authoritative"] is True
    assert out["observations"]                       # the graph drove observations
    assert {"has_object_id", "has_search_param", "has_login"} <= set(out["observations"])
    # an EMPTY graph yields an EMPTY plan — no flat-recon backdoor can populate it
    empty = AG.AssetGraph("m2")
    out2 = TP.plan_graph_authoritative(empty, seed)
    assert out2["observations"] == [] and out2["techniques"] == [] and out2["next_best_actions"] == []
    # None graph is tolerated (compat callers), still no plan
    assert TP.plan_graph_authoritative(None, seed)["observations"] == []


def test_new_session_engines_are_planner_wired_not_islands():
    """Orchestration guard: every confirming engine added this session must be gated by a precondition so
    the planner (and the graph, which shares the table) reasons about it — not left as a sweep-only island."""
    import technique_planner as TP
    new = ["xpath_injection", "ldap_injection", "ssi_injection", "css_injection", "jwt_key_confusion",
           "cache_deception", "waf_bypass", "reverse_tabnabbing", "permissive_crossdomain"]
    for tid in new:
        assert tid in TP._PRECONDITIONS, "%s is a planner island (no precondition)" % tid
        assert all(o in TP.OBSERVATIONS for o in TP._PRECONDITIONS[tid]), "%s uses an unknown observation" % tid
    # the gate really gates: none surface with zero observations, all surface when their obs hold
    techs = [{"id": t} for t in new]
    assert TP.plan(set(), techs) == []
    obs = {"has_search_param", "reflects_input", "authenticated", "serves_js"}
    assert {e["id"] for e in TP.plan(obs, techs)} == set(new)
