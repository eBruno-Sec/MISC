"""Archive/GitHub provenance flow: recovered intel enters the graph flagged UNVALIDATED, gets a
validation queue, and only after a current check is it treated as present (CHAD review #9)."""
from __future__ import annotations

import archive_intel as AI
import asset_graph as AG


def test_archived_endpoints_flagged_unvalidated():
    g = AG.AssetGraph("m")
    n = AI.ingest_archived_endpoints(g, "t.example", [
        "https://t.example/old/admin", "https://t.example/legacy/api/v1", "https://t.example/"])
    assert n == 2                                              # the bare "/" is skipped
    ep = g.nodes("endpoint")[0]
    assert ep["props"]["archived"] is True and ep["tested"] is False
    assert ep["confidence"] == AG.LOW                          # archived != present -> low confidence


def test_repo_secret_stores_ref_not_raw():
    g = AG.AssetGraph("m")
    AI.ingest_repo_findings(g, "acme/app", [
        {"kind": "secret", "value": "AKIA...", "ref": "vault://mission/m/repo1"},
        {"kind": "route", "value": "/internal/debug"},
        {"kind": "cloud_name", "value": "acme-prod-bucket"}])
    cred = g.nodes("credential")[0]
    assert cred["props"]["identity_ref"] == "vault://mission/m/repo1"
    assert "AKIA" not in str(g.to_dict())                      # raw secret never stored
    # Q-138. This line REQUIRED the defect: it asserted that the harvested route "/internal/debug"
    # -- a bare path -- becomes an `endpoint` node. That node can never resolve to an absolute URL,
    # so `_graph_primary_state` dropped it and recorded a hostless-endpoint row. Under the Q-109
    # rule a path is a `route`; the fact is kept and the CLAIM corrected. `cloud_account` is
    # unchanged and still asserted, so this still proves all three kinds were ingested.
    assert g.nodes("route") and g.nodes("cloud_account")
    assert g.nodes("endpoint") == []                            # nothing here carries a host


def test_validation_queue_and_mark():
    g = AG.AssetGraph("m")
    AI.ingest_archived_endpoints(g, "t", ["https://t/old/panel"])
    q = AI.needs_validation(g)
    assert len(q) == 1 and q[0]["provenance"] == "archive"
    # validate: it's gone on the current target -> retired, drops off the queue
    AI.mark_validated(g, q[0]["id"], present=False)
    assert AI.needs_validation(g) == []
    assert g.node(q[0]["id"])["props"]["current_state"] == "gone"


def test_present_validation_raises_confidence():
    g = AG.AssetGraph("m")
    AI.ingest_archived_endpoints(g, "t", ["https://t/still/here"])
    nid = AI.needs_validation(g)[0]["id"]
    AI.mark_validated(g, nid, present=True)
    assert g.node(nid)["confidence"] >= AG.MEDIUM and g.node(nid)["tested"] is True


# =================================================================================================
# Q-138. THE SECOND HOSTLESS-NODE PRODUCER, found by enumerating every `endpoint` minting site
# instead of waiting for another 6679-URL scan to reproduce the row.
#
# Q-109 established the rule in asset_graph: a harvested route is a PATH, never an ADDRESS, so a
# bare path becomes a `route` node and only a netloc-carrying candidate becomes an `endpoint`.
# That rule was never applied HERE, one file over, and these two sites kept minting `endpoint`
# nodes keyed on bare paths. `_endpoint_url` then refused to resolve them and
# `_graph_primary_state` dropped them and recorded the hostless row -- the reporter was right both
# times, and this was the remaining producer.
#
# It is VOLUME-DEPENDENT, which is exactly what the ticket predicted and why the two field runs
# disagreed: repo-route harvesting needs recon to have found repositories with routes in them.
# 1441 surface URLs -> no row. 6679 surface URLs -> thirty hostless nodes.
# =================================================================================================

def _keys(graph, kind):
    return sorted((n.get("key") if isinstance(n, dict) else getattr(n, "key", n))
                  for n in graph.nodes(kind))


def test_a_harvested_repo_route_is_a_route_node_not_a_hostless_endpoint():
    """`kind="route"` carries a PATH by this module's own documented contract, so every harvested
    repo route used to mint an endpoint node with no host."""
    g = AG.AssetGraph("q138_repo")
    AI.ingest_repo_findings(g, "acme/api", [{"kind": "route", "value": "/admin/login"},
                                            {"kind": "route", "value": "/api/v1/users"}])
    assert _keys(g, "endpoint") == []
    assert _keys(g, "route") == ["/admin/login", "/api/v1/users"]


def test_a_repo_route_that_DOES_carry_a_host_stays_an_endpoint():
    """The other half. Correcting the claim must not discard the addressable ones -- a fix that
    turns everything into a route is not a fix, it is a deletion of probe surface."""
    g = AG.AssetGraph("q138_repo_abs")
    AI.ingest_repo_findings(g, "acme/api", [{"kind": "route", "value": "https://a.example/keep"}])
    assert _keys(g, "endpoint") == ["a.example/keep"]
    assert _keys(g, "route") == []


def test_an_archived_path_with_no_resolvable_host_is_a_route_node():
    """`h = p.netloc or host`. With a relative archived entry AND no host argument, both are empty
    and the node was keyed on the bare path."""
    g = AG.AssetGraph("q138_arch")
    AI.ingest_archived_endpoints(g, "", ["/legacy/panel"])
    assert _keys(g, "endpoint") == []
    assert _keys(g, "route") == ["/legacy/panel"]


def test_an_archived_path_WITH_a_host_still_becomes_an_endpoint():
    g = AG.AssetGraph("q138_arch_ok")
    AI.ingest_archived_endpoints(g, "b.example", ["/ok"])
    assert _keys(g, "endpoint") == ["b.example/ok"]


def test_no_endpoint_node_from_this_module_can_ever_be_keyed_on_a_bare_path():
    """THE INVARIANT, stated once over every entry point here rather than per-case. An endpoint key
    beginning with '/' is by construction unresolvable to an absolute URL."""
    g = AG.AssetGraph("q138_all")
    AI.ingest_repo_findings(g, "acme/api", [{"kind": "route", "value": "/a"},
                                            {"kind": "route", "value": "https://h.example/b"}])
    AI.ingest_archived_endpoints(g, "", ["/c", "https://h.example/d"])
    AI.ingest_archived_endpoints(g, "h.example", ["/e"])
    assert [k for k in _keys(g, "endpoint") if str(k).startswith("/")] == []
