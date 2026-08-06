"""Canonical asset/intelligence graph: provenance-carrying merge, confidence, edges, the planner
worklist (untested / enabling), and JSON round-trip persistence. Pure; no network."""
from __future__ import annotations

import asset_graph as AG


def test_observe_merges_and_accrues_provenance():
    g = AG.AssetGraph("m1")
    nid = g.observe("endpoint", "/rest/basket/1", source="recon", confidence=AG.LOW, scope_asset="juice-shop")
    # a second observation of the SAME fact from another source merges, raising confidence
    g.observe("endpoint", "/rest/basket/1", source="authz_matrix", confidence=AG.HIGH)
    n = g.node(nid)
    assert n["confidence"] == AG.HIGH                     # raised to the max seen, never lowered
    assert {s["source"] for s in n["sources"]} == {"recon", "authz_matrix"}
    assert n["scope_asset"] == "juice-shop"
    assert g.stats()["nodes"] == 1                        # merged, not duplicated


def test_edges_and_neighbors():
    g = AG.AssetGraph("m1")
    h = g.observe("host", "juice-shop", source="recon")
    e = g.observe("endpoint", "/rest/basket/1", source="recon")
    assert g.link(h, e, "serves", source="recon") is True
    assert g.link(h, "endpoint:does-not-exist", "serves") is False   # endpoint must be a node
    assert g.neighbors(h, rel="serves") == [e]
    assert g.neighbors(e) == [h]


def test_untested_worklist_and_mark_tested():
    g = AG.AssetGraph("m1")
    a = g.observe("object", "/rest/basket/1", source="recon")
    g.observe("object", "/rest/basket/2", source="recon")
    assert len(g.untested("object")) == 2
    g.mark_tested(a, ok=True)
    rest = g.untested("object")
    assert len(rest) == 1 and rest[0]["id"] != a
    assert g.node(a)["props"]["test_result"] == "confirmed"


def test_enables_capability_query():
    g = AG.AssetGraph("m1")
    f = g.observe("finding", "sqli-login", source="sqli_tool", enables=["database_read"])
    g.add_enable(f, "credential_material")
    assert g.enabling("database_read") and g.enabling("credential_material")
    assert not g.enabling("nonexistent_capability")


def test_persona_stores_vault_ref_not_secret():
    g = AG.AssetGraph("m1")
    # a persona/credential fact must reference the vault, never carry the raw secret
    pid = g.observe("persona", "user_a", source="registration", identity_ref="vault://mission/m1/user_a")
    n = g.node(pid)
    assert n["props"]["identity_ref"] == "vault://mission/m1/user_a"
    assert "password" not in str(n)


def test_build_from_engagement_projection():
    urls = ["http://juice-shop:3000/rest/basket/1", "http://juice-shop:3000/rest/products?q=x"]
    findings = [{"title": "IDOR cross-user", "family": "idor", "confidence": "confirmed",
                 "cwe": "CWE-639", "target": "http://juice-shop:3000/rest/basket/1"}]
    personas = {"personas": [
        {"role": "user_a", "rank": 1, "method": "registered", "has_session": True, "identity": "a@t"},
        {"role": "anonymous", "rank": 0, "has_session": False}]}
    caps = ["second_persona_available", "foreign_object_read"]
    g = AG.build_from_engagement("m1", urls=urls, findings=findings, personas=personas,
                                 capabilities=caps, scope_asset="juice-shop")
    kinds = g.stats()["by_kind"]
    assert kinds.get("host") == 1
    assert kinds.get("object", 0) >= 1                    # /rest/basket/1 is object-bearing
    assert kinds.get("finding") == 1
    assert kinds.get("persona") == 2
    assert kinds.get("capability") == 2
    # the object endpoint + the confirmed IDOR finding both flag they unlock foreign_object_read
    assert "foreign_object_read" in g.nodes("object")[0]["enables"]
    fnode = g.nodes("finding")[0]
    assert "foreign_object_read" in fnode["enables"] and fnode["tested"] is True
    # a finding -> capability "enables" edge exists (the graph knows what the bug unlocked)
    assert any(e["rel"] == "enables" for e in g.edges())
    # a persona with a session has an authenticated_as edge to a session node (vault ref, no secret)
    assert "session:user_a" in g.neighbors("persona:user_a", rel="authenticated_as")
    assert "password" not in str(g.to_dict())


def test_next_best_actions_ranks_the_worklist():
    g = AG.build_from_engagement(
        "m1",
        urls=["http://h/api/orders/1"],
        findings=[{"title": "SQLi login", "family": "sql_injection", "confidence": "confirmed",
                   "target": "http://h/login"}],
        services=[{"host": "h", "port": 6379}],  # redis
        capabilities=[])                          # database_read NOT yet achieved
    acts = g.next_best_actions()
    kinds = [a["action"] for a in acts]
    # a confirmed SQLi enables database_read (unrealized) -> chase it, ranked first
    assert acts[0]["action"] == "chase_capability" and acts[0]["capability"] == "database_read"
    assert "run_service_pack" in kinds            # untested redis service
    assert "cross_user_test" in kinds             # untested object endpoint
    # once the capability exists, it's no longer suggested
    g2 = AG.build_from_engagement("m1", findings=[{"title": "SQLi", "family": "sql_injection",
                                  "confidence": "confirmed", "target": "http://h/login"}],
                                  capabilities=["database_read"])
    assert not any(a.get("capability") == "database_read" for a in g2.next_best_actions())


def test_ingest_intel_gives_graph_the_full_planner_vocabulary():
    import technique_planner as TP
    g = AG.AssetGraph("m")
    intel = {"candidates": {
        "object_id": ["1", "42"],
        "param": ["redirect_url", "q", "filename"],
        "version": ["angular@1.7.7"],
        "credential": ["admin:secretpw"],
        "coupon": ["WMNSDY2023"],
        "endpoint": ["/rest/user/login", "/api/orders", "/admin/config"],
    }}
    assert g.ingest_intel(intel) > 0
    obs = g.to_observations()
    assert {"has_object_id", "has_redirect_param", "has_search_param", "has_file_upload",
            "has_versions", "credentials_exposed", "has_coupon", "has_login", "has_api",
            "has_sensitive_route"} <= obs
    assert "secretpw" not in str(g.to_dict())                 # credential hashed, never raw
    # finding families project to injection observations
    g.observe("finding", "x", label="XSS", source="scan", family="xss")
    assert "reflects_input" in g.to_observations()
    # the planner now reads the FULL vocabulary FROM the graph alone (empty flat inputs)
    pobs = TP.derive_observations(surface=[], harvest={}, graph=g)
    assert {"has_redirect_param", "has_versions", "has_coupon", "has_sensitive_route"} <= pobs


def test_services_routed_into_graph():
    # beyond-web: a discovered non-web service becomes a graph node with what its checks unlock;
    # a web port is excluded (the web engine owns it).
    services = [{"host": "box", "port": 6379}, {"host": "box", "port": 443}]
    g = AG.build_from_engagement("m1", services=services, scope_asset="box")
    svc = g.nodes("service")
    assert len(svc) == 1 and svc[0]["label"] == "redis"
    assert "database_read" in svc[0]["enables"]
    assert "service:box:6379" in g.neighbors("host:box", rel="runs")


def test_provenance_summary_shows_where_intel_came_from():
    # cloud/github/wayback intel enters the graph with provenance; provenance_summary() is what
    # makes that VISIBLE to the operator (per-source counts + the needs-validation worklist).
    import archive_intel as AI
    g = AG.AssetGraph("m")
    g.observe("host", "acme.tld", source="recon", confidence=AG.CONFIRMED)
    AI.ingest_archived_endpoints(g, "acme.tld", ["http://acme.tld/old/admin", "http://acme.tld/legacy"],
                                 source="wayback")
    AI.ingest_repo_findings(g, "acme/app", [
        {"kind": "route", "value": "/internal/debug"},
        {"kind": "secret", "value": "AKIAsupersecretvalue", "ref": "vault://mission/m/repo-0"}],
        source="github")
    ps = g.provenance_summary()
    # per-source contribution is counted
    assert ps["by_source"].get("wayback") == 2
    assert ps["by_source"].get("github") == 2
    assert ps["by_source"].get("recon") == 1
    # passive feeds are broken out from live recon
    assert set(ps["passive_intel"]) == {"wayback", "github"}
    assert "recon" not in ps["passive_intel"]
    # archive/repo facts land on the needs-validation queue (never auto-trusted as live)
    assert ps["needs_validation_count"] == 4
    labels = {n["label"] for n in ps["needs_validation"]}
    assert "/old/admin" in labels and "/internal/debug" in labels
    # a repo SECRET is provenance too — but only its hash/vault ref, never the raw value
    assert "supersecretvalue" not in str(ps)
    # once validated against the current target, it leaves the worklist
    gone_id = ps["needs_validation"][0]["id"]
    AI.mark_validated(g, gone_id, present=True)
    assert g.provenance_summary()["needs_validation_count"] == 3


def test_graph_as_brain_replans_when_graph_changes():
    # graph-as-brain slice 2: the planner queries the graph for its NEXT action, folds the result
    # back in, and REPLANS — a graph change must alter the next decision (not a fixed script).
    g = AG.build_from_engagement(
        "m", urls=["http://h/api/orders/1"],
        findings=[{"title": "SQLi login", "family": "sql_injection", "confidence": "confirmed",
                   "target": "http://h/login"}],
        services=[{"host": "h", "port": 6379}], capabilities=[])
    a1 = g.plan_next()
    assert a1 and a1["action"] == "chase_capability" and a1["capability"] == "database_read"
    # realize the capability -> the SAME graph must now recommend a DIFFERENT action
    g.apply_result(a1, gained_capability="database_read")
    a2 = g.plan_next()
    assert a2 != a1
    assert a2 is None or a2.get("capability") != "database_read"
    # exhaust the remaining actions by folding each result back; plan_next eventually drains to None
    for _ in range(10):
        a = g.plan_next()
        if a is None:
            break
        g.apply_result(a, tested_ok=True, gained_capability=a.get("capability"))
    assert g.plan_next() is None            # a fully-consumed world model has no next action


def test_utility_score_and_decay_factor_formulas():
    # Pentera-style utility: impact/probability/confidence raise it; cost/risk lower it
    hi = AG.utility_score(0.8, 0.9, 1.0, cost=1.0, risk=1.0)
    lo = AG.utility_score(0.8, 0.9, 1.0, cost=2.0, risk=1.5)
    assert hi > lo and hi == round(0.8 * 0.9 * 1.0 / 1.0, 4)
    # Cosmos decay: 0 age = full weight, one half-life = 0.5, huge age floored (never silently zero)
    assert AG.decay_factor(0) == 1.0
    assert AG.decay_factor(14 * AG._DAY, halflife_days=14) == 0.5
    assert AG.decay_factor(10 ** 9) >= AG.CONF_FLOOR and AG.decay_factor(10 ** 9) > 0


def test_confidence_decay_and_utility_ranking():
    now = 1_000_000_000.0
    g = AG.AssetGraph("m")
    # a TESTED fact is ground truth — it does NOT decay even when old
    tf = g.observe("finding", "sqli", source="scan", confidence=AG.CONFIRMED, tested=True,
                   enables=["database_read"])
    g.node(tf)["last_seen"] = now - 60 * AG._DAY
    assert g.decayed_confidence(g.node(tf), now=now) == AG.CONFIRMED
    # an UNVERIFIED fact decays with age: 28 days ~= 2 half-lives (14d) -> ~1/4 the weight
    fresh = g.observe("object", "/a", source="recon", confidence=AG.MEDIUM)
    g.node(fresh)["last_seen"] = now
    stale = g.observe("object", "/b", source="recon", confidence=AG.MEDIUM)
    g.node(stale)["last_seen"] = now - 28 * AG._DAY
    df = g.decayed_confidence(g.node(fresh), now=now)
    ds = g.decayed_confidence(g.node(stale), now=now)
    assert abs(df - AG.MEDIUM) < 1e-6                        # fresh ~ unchanged
    assert abs(ds - AG.MEDIUM * 0.25) < 0.02 and ds < df    # stale ~ quarter weight
    # utility ranking: the confirmed database_read chase tops the list; the FRESH object outranks the
    # STALE one purely because decayed confidence feeds the utility score (decay -> planning weight).
    acts = g.next_best_actions(now=now)
    assert acts[0]["action"] == "chase_capability" and acts[0]["capability"] == "database_read"
    assert all("utility" in a and "utility_factors" in a for a in acts)   # inspectable, no black box
    objs = [a for a in acts if a["action"] == "cross_user_test"]
    assert [o["target"] for o in objs] == ["/a", "/b"] and objs[0]["utility"] > objs[1]["utility"]


def test_content_aware_enables_upgrade_credential_leaks_only():
    # a credentials-leak exposure UPGRADES to credential_material -> a real chase attack-path
    g = AG.build_from_engagement("m", findings=[
        {"title": "Sensitive data / credentials exposed", "family": "exposure",
         "confidence": "confirmed", "target": "http://h/users/v1/_debug"}])
    assert "credential_material" in g.nodes("finding")[0]["enables"]
    acts = g.next_best_actions()
    assert any(a["action"] == "chase_capability" and a.get("capability") == "credential_material"
               for a in acts)
    # a NON-credential exposure of the SAME family does NOT get the upgrade (no false attack-path)
    g2 = AG.build_from_engagement("m", findings=[
        {"title": "API schema exposed", "family": "exposure", "confidence": "confirmed",
         "target": "http://h/openapi.json"}])
    assert "credential_material" not in g2.nodes("finding")[0]["enables"]
    assert not any(a.get("capability") == "credential_material" for a in g2.next_best_actions())


def test_roundtrip_and_persistence(tmp_path):
    g = AG.AssetGraph("m1")
    h = g.observe("host", "juice-shop", source="recon", confidence=AG.CONFIRMED)
    e = g.observe("endpoint", "/rest/basket/1", source="recon")
    g.link(h, e, "serves", source="recon")
    g.mark_consumed(e, "authz_matrix")
    # dict round-trip
    g2 = AG.AssetGraph.from_dict(g.to_dict())
    assert g2.stats()["nodes"] == 2 and g2.stats()["edges"] == 1
    assert g2.node(e)["consumed_by"] == ["authz_matrix"]
    # disk round-trip
    g.save(str(tmp_path))
    g3 = AG.AssetGraph.load("m1", str(tmp_path))
    assert g3.node(h)["confidence"] == AG.CONFIRMED
    assert g3.neighbors(h, rel="serves") == [e]
