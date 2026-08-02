"""Graph-BACKED asset selection in the primary executor (CHAD re-audit). HONEST SCOPE: this proves
the primary executor _execute_plan reads its asset selection (roots/urls) from the mission GRAPH and
fails closed when the graph is empty. It does NOT claim the graph is the complete mission brain — flat
recon still POPULATES the graph via projection, and the legacy next_batch planner is still the action
scheduler. The tests exercise the REAL _execute_plan with the REAL projection (no monkeypatch of it)."""
from __future__ import annotations

import asyncio

import scope as scope_mod
import agent as agent_mod
import asset_graph as AG


class _Tools:
    def __init__(self, recon=None, urls=None):
        self.graph = AG.AssetGraph("t")
        self.recon = recon if recon is not None else {"target": "x", "domain": "x",
                                                      "subdomains": [], "live_hosts": []}
        self.urls = urls if urls is not None else []
        self.intensity = "standard"

    def get_openai_tools(self):
        return []

    def get_claude_tools(self):
        return []


def _agent(tools, in_scope):
    eng = scope_mod.ScopeEngine()
    eng.load_manual(in_scope, [], "P")
    a = agent_mod.BBHAgent(eng, tools, asyncio.Event(), strategy="deterministic", mission_id=None)

    async def _empty(_sid):
        return
        yield
    a._promote_leads = _empty
    a._ai_business_logic_leads = _empty
    return a


def _drive(a):
    calls = []

    async def fake_run_tool(tool, inp, sid):
        calls.append(tool)
        return
        yield
    a._run_tool = fake_run_tool

    async def run():
        async for _ in a._execute_plan("s"):
            pass
    asyncio.run(run())
    return calls


def test_gate_no_primary_action_on_empty_graph_production_real():
    # PRODUCTION-REAL (no monkeypatch of projection): empty scope + empty recon => the real projection
    # adds nothing => the graph is empty => the graph-gated executor issues NO primary action.
    a = _agent(_Tools(), in_scope=[])
    calls = _drive(a)
    assert calls == [], "empty graph still produced a primary action: %s" % calls


def test_execution_runs_from_graph_seeded_by_scope():
    # an in-scope root is projected into the graph by the REAL projection, which is what unlocks
    # primary execution — asset selection came THROUGH the graph.
    a = _agent(_Tools(), in_scope=["*.example.com"])
    calls = _drive(a)
    assert len(calls) >= 1, "scope root in the graph but the planner selected nothing"


def test_selection_is_read_from_the_graph():
    # the executor derives roots/urls from the GRAPH: with an empty graph the selection is empty even
    # though self.tools.recon/urls are richly populated (they only matter once projected in).
    tools = _Tools(recon={"subdomains": ["a.example.com"], "live_hosts": [{"url": "http://a.example.com"}]},
                   urls=["http://a.example.com/x"])
    a = _agent(tools, in_scope=["*.example.com"])
    roots, urls, recon = a._graph_primary_state(tools.graph)      # graph still empty here
    assert roots == [] and urls == [] and recon["subdomains"] == []
    a._seed_and_project_graph(tools.graph)                        # project (scope + flat recon) -> graph
    roots2, urls2, _ = a._graph_primary_state(tools.graph)
    assert "example.com" in roots2 or "a.example.com" in roots2   # roots now come FROM the graph
    assert "http://a.example.com/x" in urls2


def test_graph_content_alters_selection():
    # graph CONTENT changes what the executor selects: adding an endpoint node changes the derived urls
    # (which is what the planner then schedules against).
    tools = _Tools()
    a = _agent(tools, in_scope=["*.example.com"])
    _, urls_before, _ = a._graph_primary_state(tools.graph)
    tools.graph.observe("endpoint", "http://example.com/search?q=1", label="http://example.com/search?q=1", source="x")
    _, urls_after, _ = a._graph_primary_state(tools.graph)
    assert "http://example.com/search?q=1" in urls_after and urls_after != urls_before


def test_projection_error_is_surfaced_not_swallowed():
    tools = _Tools()
    a = _agent(tools, in_scope=["*.example.com"])

    class _Boom:
        def observe(self, *args, **kwargs):
            raise RuntimeError("graph down")

        def nodes(self, *a, **k):
            return []
    a._seed_and_project_graph(_Boom())
    assert a._graph_projection_error and "graph down" in a._graph_projection_error


def test_execute_plan_halts_on_projection_failure():
    # CHAD final #3: if graph projection FAILS, the primary cycle must HALT (no selecting off stale
    # graph state) and record a structured degraded state. Production-real: the real _seed_and_project
    # runs and fails because the graph raises.
    class _BadGraph:
        def observe(self, *a, **k):
            raise RuntimeError("graph down")

        def nodes(self, *a, **k):
            return []
    tools = _Tools()
    tools.graph = _BadGraph()
    a = _agent(tools, in_scope=["*.example.com"])
    calls = _drive(a)
    assert calls == [], "primary tool ran after a graph projection failure: %s" % calls
    assert a._degraded and a._degraded.get("reason") == "graph_projection_failed"
