"""Q-109 - the PRODUCER behind `graph_primary_state.hostless_endpoint`.

Q-019 built the REPORTER: `_graph_primary_state` drops an endpoint node it cannot resolve to an
absolute URL and RECORDS the drop naming the producer (see test_hostless_target_guard.py). Q-093
fixed one producer, `planner._addressable`. This is the other one.

`AssetGraph.ingest_intel` keyed an `endpoint` node on a harvested intel candidate, and every
`route` / `endpoint` candidate `intel.py` writes is a BARE PATH by construction -- `intel.py:269`
(the `_PATH` regex is anchored on a leading "/"), `intel.py:327` and `intel.py:365` each prepend one.
So every harvested route became an endpoint node with no host, which the reporter then dropped.

MEASURED on the local juice-shop lab through the real crawl -> code-intelligence -> projection path:
hostless endpoint nodes went 0 -> 3 across exactly one `ingest_intel` call, and every one of them
carried `source='harvest'` -- ingest_intel's own default, used by no other endpoint writer in the
tree.

BOTH HALVES ARE ASSERTED. A fix that merely stopped minting hostless endpoints while also losing
`has_login` / `has_api` would trade a false probe target for a real blind spot, which is the shape
Q-111's gate was written against.
"""
from __future__ import annotations

import agent as agent_mod
import asset_graph as AG


def _hostless(g):
    return sorted(n["key"] for n in g.nodes("endpoint")
                  if not agent_mod.BBHAgent._endpoint_url(n["key"], {}))


def test_ingest_intel_mints_no_hostless_endpoint_node():
    """FAILS BEFORE THE FIX: three bare paths become three unresolvable `endpoint` nodes."""
    g = AG.AssetGraph("q109")
    g.ingest_intel({"candidates": {"route": ["/rest/user/login", "/api/orders"],
                                   "endpoint": ["/admin/config"]}})
    assert _hostless(g) == [], _hostless(g)


def test_the_knowledge_is_kept_as_a_route_never_discarded():
    """The fact is real intel. Only its CLAIM to be an address is refused."""
    g = AG.AssetGraph("q109")
    g.ingest_intel({"candidates": {"route": ["/rest/user/login"], "endpoint": ["/admin/config"]}})
    assert {n["key"] for n in g.nodes("route")} == {"/rest/user/login", "/admin/config"}


def test_the_planner_observations_survive_the_reclassification():
    """THE OTHER HALF. Silencing the drop by dropping the knowledge would be the worse defect."""
    g = AG.AssetGraph("q109")
    g.ingest_intel({"candidates": {"endpoint": ["/rest/user/login", "/api/orders", "/admin/config"]}})
    assert {"has_login", "has_api", "has_sensitive_route"} <= g.to_observations()


def test_an_addressable_candidate_is_still_an_endpoint_keyed_netloc_path():
    """NOT VACUOUS: zero-hostless must not be achieved by minting no endpoints at all. The key is
    the netloc+path convention `_graph_add_url` and `_project_body_params` already use, so a
    harvested absolute URL MERGES onto the node the crawler already made instead of forking a
    second identity for the same asset."""
    g = AG.AssetGraph("q109")
    g.ingest_intel({"candidates": {"endpoint": ["https://h.example/x?a=1"]}})
    assert {n["key"] for n in g.nodes("endpoint")} == {"h.example/x"}
    assert _hostless(g) == []


def test_a_scheme_with_no_host_is_recorded_as_a_path_never_as_an_address():
    """`https:///benchmark/cmdi-Index.html` is the exact string mission 90cee81c produced."""
    g = AG.AssetGraph("q109")
    g.ingest_intel({"candidates": {"endpoint": ["https:///benchmark/cmdi-Index.html"]}})
    assert g.nodes("endpoint") == []
    assert {n["key"] for n in g.nodes("route")} == {"/benchmark/cmdi-Index.html"}


def test_the_reporter_still_fires_when_a_hostless_node_reaches_the_graph_some_other_way():
    """NEGATIVE CONTROL ON THE FIX ITSELF. A producer fix that also disabled the reporter would
    hide the NEXT producer, and the ledger row is the only reason this one was ever found."""
    import asyncio

    import scope as scope_mod

    class _Tools:
        def __init__(self):
            self.graph = AG.AssetGraph("t")
            self.recon = {"target": "h", "domain": "h", "subdomains": [], "live_hosts": [],
                          "forms": []}
            self.urls = []
            self.intensity = "standard"
            self.swallowed = []

        def _swallow(self, exc, where, target=""):
            self.swallowed.append({"where": where, "target": str(target)[:200],
                                   "error": "%s: %s" % (type(exc).__name__, exc)})

        def get_openai_tools(self):
            return []

        def get_claude_tools(self):
            return []

    t = _Tools()
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["h.example"], [], "P")
    a = agent_mod.BBHAgent(eng, t, asyncio.Event(), strategy="deterministic", mission_id=None)
    t.graph.observe("endpoint", "/orphan.html", label="/orphan.html", source="some-other-producer")
    a._graph_primary_state(t.graph)
    rec = [s for s in t.swallowed if s["where"] == "graph_primary_state.hostless_endpoint"]
    assert rec, "the reporter was disabled by the producer fix: %s" % t.swallowed
