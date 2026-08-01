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
