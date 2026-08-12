"""D6 (architecture.md 6.1) -- the run_service_pack action tier could never fire.

MEASURED BEFORE THE FIX, driving the real `BBHAgent._run_service_packs` with ssh:22 and redis:6379
already discovered by a prior nmap::

    services discovered by fingerprint : [22, 6379]
    --- AT DISPATCH (the only window the planner could act in) ---
    service nodes in graph  : []
    untested('service')     : []
    next_best_actions       : []

`AssetGraph.next_best_actions` builds its `run_service_pack` tier from `self.untested("service")`
(`asset_graph.py:300`). That set was empty and the tier was dead.

The audit reads the cause as `tools.py:2810-2812` marking the node tested "two lines later". The
sharper reading, and the one that decides where the fix goes: that block sits at the END of
`_run_service_pack`, AFTER the pack has already executed. The node was never marked tested too
early -- it was CREATED too late, and therefore never existed in the untested state at all. The fix
belongs at fingerprint time, in `agent.py:_run_service_packs`, which is where the ports are
discovered. `tools.py` needs no change: `AssetGraph.observe` is idempotent by `(kind, key)` and its
merge branch never clears `tested`, so the existing observe + mark_tested still transitions the same
node when the pack finishes.

BOTH HALVES ARE TESTED. `test_the_pack_still_marks_the_same_node_tested_when_it_completes` drives
the REAL `ToolRegistry._run_service_pack` over the node this fix seeds, because a fix that armed the
tier and then never disarmed it would recommend the same pack forever -- and a fix that created a
SECOND node would leave the first untested forever. Neither is visible from the arming test alone.
"""
from __future__ import annotations

import asyncio

import agent as agent_mod
import asset_graph as AG
import scope as scope_mod
import service_router as sr
import tools as tools_mod

HOST = "t.local"      # deliberately does not resolve: the socket sweep finds nothing, fast
NMAP = ["22/tcp open ssh", "6379/tcp open redis"]


class _Tools:
    def __init__(self, nmap=None):
        self.graph = AG.AssetGraph("live")
        self.recon = {"target": HOST, "domain": HOST, "subdomains": [], "live_hosts": [],
                      "forms": [], "nmap": {"open_ports": list(NMAP if nmap is None else nmap)}}
        self.urls = []
        self.intensity = "standard"
        self.swallowed = []

    def _swallow(self, exc, where, target=""):
        self.swallowed.append({"where": where, "error": "%s: %s" % (type(exc).__name__, exc)})

    def get_openai_tools(self):
        return []

    def get_claude_tools(self):
        return []


def _scope():
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["http://%s/" % HOST], [], "P")
    return eng


def _dispatch(mode="active", nmap=None):
    """Run the real `_run_service_packs`, capturing what the graph knew AT DISPATCH -- the only
    moment between discovery and testing at which the planner could act on it."""
    tools = _Tools(nmap=nmap)
    a = agent_mod.BBHAgent(_scope(), tools, asyncio.Event(), mode=mode,
                           strategy="deterministic", mission_id=None)
    seen = {}

    async def _fake_exec(tool, inp, sid):
        g = tools.graph
        seen.setdefault("untested", sorted(n["key"] for n in g.untested("service")))
        seen.setdefault("actions", sorted({x["action"] for x in g.next_best_actions()}))
        seen.setdefault("dispatched", []).append((inp.get("service"), inp.get("port")))
        return None

    a._exec_internal = _fake_exec
    a._primary_base = lambda: "http://%s" % HOST
    asyncio.new_event_loop().run_until_complete(a._run_service_packs("s1"))
    return tools.graph, seen


# ── the tier that could never fire ───────────────────────────────────────────────────


def test_a_discovered_service_is_untested_in_the_graph_before_its_pack_runs():
    """NEGATIVE CONTROL for D6. Pre-fix, both of these were empty at this exact moment.

    The middle state -- observed and NOT yet tested -- IS the fix. A test that only checked the end
    state, or that only asserted "a service node exists", passes on the broken code: the broken code
    also produces a service node, just never an untested one.
    """
    g, seen = _dispatch()
    assert seen.get("dispatched"), "no pack was dispatched -- the fixture stopped exercising D6"

    assert seen["untested"] == ["%s:22" % HOST, "%s:6379" % HOST], (
        "untested('service') is still empty by construction at dispatch: %r" % seen["untested"])
    assert "run_service_pack" in seen["actions"], (
        "the run_service_pack tier still never fires; actions were %r" % seen["actions"])


def test_the_pack_still_marks_the_same_node_tested_when_it_completes():
    """The OTHER half. Arming the tier is worthless if nothing disarms it, and a second node under a
    different key would leave the first untested forever. Drives the REAL
    `ToolRegistry._run_service_pack`, whose probe fails against the unresolvable host -- it still
    reaches its graph-write block, which is the part under test.
    """
    g, _seen = _dispatch()
    before = sorted(n["key"] for n in g.untested("service"))
    assert before, "nothing to disarm"

    reg = tools_mod.ToolRegistry(_scope(), mission_id=None, lab_mode=True)
    reg.graph = g                                  # the ONE live graph, as in a real mission
    asyncio.new_event_loop().run_until_complete(
        reg._run_service_pack({"host": HOST, "port": 6379, "service": "redis"}))

    assert len(g.nodes("service")) == 2, (
        "the pack created a SECOND service node instead of merging: %r"
        % [n["key"] for n in g.nodes("service")])
    assert sorted(n["key"] for n in g.untested("service")) == ["%s:22" % HOST], (
        "the completed pack did not mark its own node tested: %r"
        % [n["key"] for n in g.untested("service")])
    assert g.node(AG._nid("service", "%s:6379" % HOST))["tested"] is True


# ── the fix must not arm what it cannot act on ───────────────────────────────────────


def test_no_node_is_written_for_a_service_that_has_no_pack():
    """`run_service_pack` on a web or unknown service is a no-op (`pack_for` returns {}), so seeding
    one would only produce an action the executor cannot honour."""
    g, _ = _dispatch(nmap=["80/tcp open http", "12345/tcp open ???"])
    assert g.nodes("service") == [], [n["key"] for n in g.nodes("service")]
    assert "run_service_pack" not in {a["action"] for a in g.next_best_actions()}


def test_passive_mode_writes_no_service_node():
    """`_run_service_packs` returns before any live contact in passive mode; the graph must not
    claim a service was discovered when nothing was probed."""
    g, seen = _dispatch(mode="passive")
    assert g.nodes("service") == []
    assert not seen.get("dispatched")


def test_enables_come_from_service_router_so_ranking_matches_the_report():
    """The tier scores impact from `s["enables"]` (`asset_graph.py:301`). Reuse the same source
    `build_from_engagement` uses rather than leaving it empty and defaulting the impact."""
    g, _ = _dispatch()
    ref = {"%s:%s" % (r["host"], r["port"]): sorted({e for c in r["checks"]
                                                     for e in c.get("enables", [])})
           for r in sr.route([{"host": HOST, "port": p, "service": s, "banner": ""}
                              for p, s in ((22, "ssh"), (6379, "redis"))])}
    got = {n["key"]: sorted(n["enables"]) for n in g.nodes("service")}
    assert got == ref, "%r != %r" % (got, ref)
    assert any(v for v in got.values()), "every service seeded with empty enables -- impact defaults"


def test_seeding_is_idempotent_across_repeated_discovery():
    g, _ = _dispatch()
    n_before = len(g.nodes("service"))
    a = agent_mod.BBHAgent(_scope(), _Tools(), asyncio.Event(), strategy="deterministic")
    a.tools.graph = g
    a._exec_internal = lambda *_a, **_k: asyncio.sleep(0)
    a._primary_base = lambda: "http://%s" % HOST
    asyncio.new_event_loop().run_until_complete(a._run_service_packs("s2"))
    assert len(g.nodes("service")) == n_before


def test_a_graph_write_failure_is_recorded_not_swallowed():
    """A silent `except: pass` here would put the tier back to dead with no trace."""
    tools = _Tools()

    class _Boom:
        def observe(self, *a, **k):
            raise RuntimeError("graph down")

        def nodes(self, *a, **k):
            return []

    tools.graph = _Boom()
    a = agent_mod.BBHAgent(_scope(), tools, asyncio.Event(), strategy="deterministic")
    a._exec_internal = lambda *_a, **_k: asyncio.sleep(0)
    a._primary_base = lambda: "http://%s" % HOST
    asyncio.new_event_loop().run_until_complete(a._run_service_packs("s3"))
    assert [s for s in tools.swallowed if s["where"] == "service_graph_seed"], tools.swallowed
