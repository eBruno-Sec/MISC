"""Q-120 -- `ingest_intel` was wired one phase too late to steer the mission that feeds it.

MEASURED across a full mission: `graph_primary_state x14` then `ingest_intel x1`. The intel feed
landed after the LAST planner state read (inside `_close_autonomy_loop`, the post-loop "next best
action" advisory), so nothing it contributed -- has_login/has_api/has_sensitive_route/has_object_id,
or a harvested `route` node -- could influence what the mission actually did. It only ever enriched
the report / next-scan suggestion, one step too late for the mission that produced it.

FIX: `_seed_and_project_graph` (agent.py), the projector the primary planning loop calls every
iteration (MEASURED: 14 times in that same mission), now also re-ingests `self.tools.intel` each
time it runs. `AssetGraph.ingest_intel`'s own `observe()` calls merge by key, so re-running it on a
growing intel store every cycle is idempotent and cheap -- the same property `_seed_and_project_graph`
already relies on for hosts/endpoints/findings.
"""
from __future__ import annotations

import asyncio

import agent as agent_mod
import asset_graph as AG
import intel as intel_mod
import scope as scope_mod

HOST = "t.local:3000"
BASE = "http://" + HOST


class _ToolsWithIntel:
    """Same shape as test_live_graph_projection.py's `_Tools`, plus a real IntelStore -- the
    production `ToolRegistry` always has one (tools.py:1631)."""

    def __init__(self):
        self.graph = AG.AssetGraph("t")
        self.recon = {"subdomains": ["t.local"], "live_hosts": [{"url": BASE}], "forms": []}
        self.urls = [BASE + "/x?id=1"]
        self.intensity = "standard"
        self.intel = intel_mod.IntelStore()

    def _swallow(self, exc, where, target=""):
        pass

    def get_openai_tools(self):
        return []

    def get_claude_tools(self):
        return []


def _agent(tools):
    eng = scope_mod.ScopeEngine()
    eng.load_manual([BASE + "/"], [], "P")
    return agent_mod.BBHAgent(eng, tools, asyncio.Event(), strategy="deterministic", mission_id=None)


def test_a_single_projector_call_promotes_harvested_intel_into_the_graph():
    """GATE: intel the harvest already knows about reaches the graph on the FIRST projector call --
    not after the mission's autonomy wrap-up phase."""
    tools = _ToolsWithIntel()
    tools.intel.add("route", "/rest/user/login", source="harvest")
    a = _agent(tools)
    g = AG.AssetGraph("live")
    a._seed_and_project_graph(g)
    assert {n["key"] for n in g.nodes("route")} == {"/rest/user/login"}
    assert a._graph_projection_error is None


def test_the_harvested_route_reaches_the_planner_observation_vocabulary_immediately():
    """THE POINT: `has_login` must be an observation the live loop's OWN `_graph_primary_state` read
    can act on after one iteration, not only after the mission has already ended."""
    tools = _ToolsWithIntel()
    tools.intel.add("route", "/rest/user/login", source="harvest")
    a = _agent(tools)
    g = AG.AssetGraph("live")
    a._seed_and_project_graph(g)
    assert "has_login" in g.to_observations()


def test_repeated_projection_is_idempotent_not_a_growing_duplicate():
    """`_seed_and_project_graph` runs every planning iteration (MEASURED: 14 times in one mission).
    Re-ingesting the same intel each cycle must not multiply nodes."""
    tools = _ToolsWithIntel()
    tools.intel.add("route", "/rest/user/login", source="harvest")
    a = _agent(tools)
    g = AG.AssetGraph("live")
    a._seed_and_project_graph(g)
    n1 = g.stats()["nodes"]
    a._seed_and_project_graph(g)
    n2 = g.stats()["nodes"]
    assert n2 == n1, "re-running the projector grew the graph: %d -> %d" % (n1, n2)


def test_a_tools_stub_with_no_intel_attribute_still_projects_cleanly():
    """NEGATIVE CONTROL / backward-compat: several existing tests (test_live_graph_projection.py)
    drive `_seed_and_project_graph` with a minimal `_Tools` stub that has NO `.intel` attribute at
    all. The fix must not turn that into a projection failure."""
    class _Bare:
        def __init__(self):
            self.graph = AG.AssetGraph("t")
            self.recon = {"subdomains": [], "live_hosts": [], "forms": []}
            self.urls = []
            self.intensity = "standard"

        def _swallow(self, exc, where, target=""):
            pass

        def get_openai_tools(self):
            return []

        def get_claude_tools(self):
            return []

    a = _agent(_Bare())
    g = AG.AssetGraph("live")
    a._seed_and_project_graph(g)
    assert a._graph_projection_error is None, a._graph_projection_error
