"""Graph-AUTHORITATIVE primary execution (CHAD re-audit major #1). Exercises the REAL mission
executor _execute_plan (not just plan_graph_authoritative): with an EMPTY graph and richly-populated
FLAT recon, no primary tool action may run — the graph, not flat recon, selects primary actions."""
from __future__ import annotations

import asyncio

import scope as scope_mod
import agent as agent_mod
import asset_graph as AG


class _Tools:
    def __init__(self):
        self.graph = AG.AssetGraph("t")
        # richly-populated FLAT recon — this must NOT be able to drive primary execution on its own
        self.recon = {"target": "x", "domain": "x",
                      "subdomains": ["a.example.com", "b.example.com"],
                      "live_hosts": [{"url": "http://a.example.com"}]}
        self.urls = ["http://a.example.com/x"]
        self.intensity = "standard"

    def get_openai_tools(self):
        return []

    def get_claude_tools(self):
        return []


def _agent(tools):
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["*.example.com"], [], "P")
    a = agent_mod.BBHAgent(eng, tools, asyncio.Event(), strategy="deterministic", mission_id=None)

    async def _empty(_sid):
        return
        yield  # make it an async generator
    a._promote_leads = _empty        # isolate PRIMARY execution from the promotion/AI passes
    a._ai_business_logic_leads = _empty
    return a


def _drive(a):
    calls = []

    async def fake_run_tool(tool, inp, sid):
        calls.append(tool)
        return
        yield  # async generator with no output
    a._run_tool = fake_run_tool

    async def run():
        async for _ in a._execute_plan("s"):
            pass
    asyncio.run(run())
    return calls


def test_execute_plan_no_primary_action_on_empty_graph():
    tools = _Tools()
    a = _agent(tools)
    # DISABLE projection so the graph stays EMPTY despite the rich flat recon above
    a._seed_and_project_graph = lambda g: None
    calls = _drive(a)
    assert calls == [], "flat recon drove primary execution with an empty graph: %s" % calls


def test_execute_plan_runs_once_graph_is_seeded():
    tools = _Tools()
    # a single host projected into the GRAPH is what unlocks primary execution
    tools.graph.observe("host", "a.example.com", label="a.example.com", source="scope")
    a = _agent(tools)
    a._seed_and_project_graph = lambda g: None    # rely only on the pre-seeded graph host
    calls = _drive(a)
    assert len(calls) >= 1, "graph had a host but the planner selected no primary action"


def test_graph_primary_state_reads_graph_only():
    tools = _Tools()
    a = _agent(tools)
    # empty graph -> empty selection, regardless of flat recon
    roots, urls, recon = a._graph_primary_state(tools.graph)
    assert roots == [] and urls == [] and recon["subdomains"] == []
    # project -> the graph now yields the selection
    a._seed_and_project_graph(tools.graph)
    roots2, urls2, recon2 = a._graph_primary_state(tools.graph)
    assert "a.example.com" in roots2 and "http://a.example.com/x" in urls2
