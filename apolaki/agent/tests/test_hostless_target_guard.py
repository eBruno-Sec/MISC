"""Q-019 — no component may hand the scope engine a URL with no host, and dropping one must be RECORDED.

MEASURED, mission `90cee81c` (908 persisted log rows): ten `http_probe` calls were aimed at
`https:///benchmark/cmdi-Index.html` — scheme `https`, EMPTY netloc — and `ScopeEngine.validate()`
answered `(False, 'Invalid target')` for every one. Those ten were exactly the category index pages
that link all 2740 test cases. The scope engine was behaving correctly the whole time.

The producer, traced end to end and reproduced in `test_the_exact_mission_shape_is_reproduced_and_fixed`:

  1. `tools._graph_add_url` observes an endpoint keyed `host+path` but LABELLED with the bare `path`.
  2. `agent._graph_primary_state` read the LABEL, so the planner's world-state was 2756 bare paths.
  3. `planner._b("")` returned `f"https://{h}"` == `"https://"` for an empty host, and
     `_b(_host(u)) + _path(u)` concatenated that onto the path.

Three ordinary-looking lines. The failure was invisible for weeks because every layer behaved as
documented and the only trace was a generic `scope_block` that named no producer — which is why these
tests assert the RECORDING as hard as they assert the rejection.
"""
from __future__ import annotations

import asyncio
from urllib.parse import urlparse

import agent as agent_mod
import asset_graph as AG
import planner
import scope as scope_mod

# the exact string mission 90cee81c produced, and the shape of the node that produced it
HOSTLESS = "https:///benchmark/cmdi-Index.html"
BENCH_HOST = "owaspbench:8443"
BENCH_BASE = "https://owaspbench:8443"
INDEX_PATHS = ["/benchmark/", "/benchmark/cmdi-Index.html", "/benchmark/sqli-Index.html",
               "/benchmark/xss-Index.html", "/benchmark/ldapi-Index.html"]


class _Tools:
    """Just enough registry for the graph→planner path, plus the real `_swallow` contract."""

    def __init__(self, urls=None):
        self.graph = AG.AssetGraph("t")
        self.recon = {"target": "owaspbench", "domain": "owaspbench",
                      "subdomains": [], "live_hosts": [], "forms": []}
        self.urls = list(urls or [])
        self.intensity = "standard"
        self.swallowed: list = []

    def _swallow(self, exc, where, target=""):
        self.swallowed.append({"where": where, "target": str(target)[:200],
                               "error": "%s: %s" % (type(exc).__name__, exc)})

    def get_openai_tools(self):
        return []

    def get_claude_tools(self):
        return []


def _agent(tools, in_scope=("https://owaspbench:8443/benchmark/",)):
    eng = scope_mod.ScopeEngine()
    eng.load_manual(list(in_scope), [], "P")
    return agent_mod.BBHAgent(eng, tools, asyncio.Event(), strategy="deterministic", mission_id=None)


def _mission_graph(tools):
    """Reproduce the node shape the live mission built: `tools._graph_add_url` keys by host+path and
    labels by path; `_seed_and_project_graph` keys and labels by the whole URL."""
    for p in INDEX_PATHS:
        tools.graph.observe("endpoint", BENCH_HOST + p, label=p, source="live-recon")
    tools.graph.observe("host", BENCH_HOST, label=BENCH_HOST, source="live-recon")
    return tools.graph


# ── the resolver itself ───────────────────────────────────────────────────────────────────────────

def test_endpoint_url_resolves_a_host_plus_path_key_to_an_absolute_url():
    got = agent_mod.BBHAgent._endpoint_url(BENCH_HOST + "/benchmark/cmdi-Index.html",
                                           {"owaspbench": BENCH_BASE})
    assert got == BENCH_BASE + "/benchmark/cmdi-Index.html"
    assert urlparse(got).netloc, got


def test_endpoint_url_uses_the_scopes_scheme_and_port_not_a_guessed_https():
    """A plaintext app on a non-standard port must not be probed over https:443."""
    got = agent_mod.BBHAgent._endpoint_url("app:42000/x", {"app": "http://app:42000"})
    assert got == "http://app:42000/x"


def test_endpoint_url_refuses_to_manufacture_a_host():
    """THE fix, stated as a rule: no host, no URL. Returning "" is what stops `https://` + `/path`."""
    for key in ("/benchmark/cmdi-Index.html", "", "   ", "https:///benchmark/x.html"):
        assert agent_mod.BBHAgent._endpoint_url(key, {"owaspbench": BENCH_BASE}) == "", key


def test_endpoint_url_passes_an_already_absolute_key_through():
    u = BENCH_BASE + "/benchmark/x.html?a=1"
    assert agent_mod.BBHAgent._endpoint_url(u, {}) == u


# ── the world-state the planner is handed ─────────────────────────────────────────────────────────

def test_graph_primary_state_never_yields_a_hostless_url():
    """FAILS BEFORE THE FIX: reading `label` returned five bare paths straight out of this graph."""
    tools = _Tools()
    a = _agent(tools)
    _mission_graph(tools)
    _roots, urls, _recon = a._graph_primary_state(tools.graph)
    bad = [u for u in urls if not urlparse(u).netloc]
    assert bad == [], "planner world-state still carries host-less entries: %s" % bad[:5]
    assert urls, "the guard must not achieve zero-hostless by returning nothing (vacuous pass)"
    assert BENCH_BASE + "/benchmark/cmdi-Index.html" in urls


def test_an_unresolvable_endpoint_is_RECORDED_naming_the_producer():
    """A silently dropped bad URL is the same invisible failure that hid this for weeks."""
    tools = _Tools()
    a = _agent(tools)
    tools.graph.observe("endpoint", "/benchmark/orphan.html", label="/benchmark/orphan.html", source="x")
    _roots, urls, _ = a._graph_primary_state(tools.graph)
    assert urls == []
    rec = [s for s in tools.swallowed if s["where"] == "graph_primary_state.hostless_endpoint"]
    assert rec, "the drop was silent: %s" % tools.swallowed
    assert "/benchmark/orphan.html" in rec[0]["error"], rec


def test_a_clean_graph_records_nothing():
    """Negative control on the recorder: it must fire on the defect, not on every run."""
    tools = _Tools()
    a = _agent(tools)
    _mission_graph(tools)
    a._graph_primary_state(tools.graph)
    assert [s for s in tools.swallowed if "hostless" in s["where"]] == []


# ── the planner ───────────────────────────────────────────────────────────────────────────────────

def _plan_all(urls, roots=(BENCH_HOST,), bases=None):
    done, steps = set(), []
    for _ in range(40):
        batch = planner.next_batch({"mode": "active", "roots": list(roots), "done": done,
                                    "recon": {"subdomains": [], "live_hosts": []}, "urls": list(urls),
                                    "bases": bases if bases is not None else {"owaspbench": BENCH_BASE},
                                    "zap": False, "nmap_vuln": False, "nuclei_heavy": False,
                                    "intensity": "standard"})
        if not batch:
            break
        for s in batch:
            done.add(s["key"])
        steps += batch
    return steps


def _step_urls(steps):
    out = []
    for s in steps:
        for k in ("url", "base_url"):
            v = (s.get("input") or {}).get(k)
            if isinstance(v, str):
                out.append((s["tool"], v))
    return out


def test_the_exact_mission_shape_is_reproduced_and_fixed():
    """FAILS BEFORE THE FIX with exactly ten `http_probe` steps aimed at `https:///benchmark/...`."""
    steps = _plan_all(INDEX_PATHS)                      # host-less paths, as the graph used to emit
    bad = [(t, u) for t, u in _step_urls(steps)
           if "://" in u and not urlparse(u).netloc]
    assert bad == [], "planner emitted unaddressable step target(s): %s" % bad[:5]


def test_the_planner_still_plans_when_the_urls_ARE_addressable():
    """Non-vacuity: the guard must not be passing by scheduling nothing at all."""
    steps = _plan_all([BENCH_BASE + p for p in INDEX_PATHS])
    urls = _step_urls(steps)
    assert urls, "planner produced no URL-bearing step at all"
    assert all(urlparse(u).netloc for _t, u in urls)
    assert any(u.startswith(BENCH_BASE + "/benchmark/") for _t, u in urls)


def test_every_planner_step_target_is_an_absolute_http_url():
    """The chokepoint contract, over the whole plan and every phase."""
    steps = _plan_all([BENCH_BASE + p for p in INDEX_PATHS] +
                      [BENCH_BASE + "/benchmark/x.html?q=1", "/benchmark/hostless.html"])
    for tool, u in _step_urls(steps):
        p = urlparse(u)
        assert p.scheme in ("http", "https") and p.netloc, "%s -> %r" % (tool, u)


# ── the executor ingress guard + its mutation ─────────────────────────────────────────────────────

def test_executor_refuses_and_records_a_hostless_step():
    tools = _Tools()
    a = _agent(tools)
    assert a._reject_hostless_step({"tool": "http_probe", "input": {"url": HOSTLESS}, "key": "k"}) is True
    rec = [s for s in tools.swallowed if s["where"].startswith("execute_plan.hostless_step")]
    assert rec, "refused silently: %s" % tools.swallowed
    assert rec[0]["where"].endswith("http_probe"), "the record must NAME the producing tool: %s" % rec
    assert HOSTLESS in rec[0]["error"]


def test_mutation_reintroducing_the_hostless_url_is_caught_not_passed_through():
    """MUTATION. Put the defect back — a component that resolves an endpoint the old, label-reading way
    — and the guard must reject it. If this passes with `is False`, the guard is decorative."""
    tools = _Tools()
    a = _agent(tools)
    mutant = "https://" + planner._path("/benchmark/cmdi-Index.html")     # the original concatenation
    assert mutant == HOSTLESS, mutant
    assert a._reject_hostless_step({"tool": "http_probe", "input": {"url": mutant}, "key": "k"}) is True


def test_a_well_formed_step_is_not_refused():
    """The other half of the mutation: a guard that also kills the true positive is a mute button."""
    tools = _Tools()
    a = _agent(tools)
    ok = {"tool": "http_probe", "input": {"url": BENCH_BASE + "/benchmark/"}, "key": "k"}
    assert a._reject_hostless_step(ok) is False
    assert tools.swallowed == []


# ── NEGATIVE CONTROL: the scope gate was not weakened ─────────────────────────────────────────────

def test_scope_still_blocks_a_genuinely_out_of_scope_host():
    """Fixing the producer must not touch the gate. A well-formed URL on a foreign host is addressable,
    so it passes the addressability guard — and must then be REFUSED by scope, exactly as before."""
    tools = _Tools()
    a = _agent(tools)
    evil = "https://evil.example.com/benchmark/cmdi-Index.html"
    assert a._reject_hostless_step({"tool": "http_probe", "input": {"url": evil}, "key": "k"}) is False
    assert planner._addressable({"tool": "http_probe", "input": {"url": evil}, "key": "k"}) is True
    ok, why = a.scope.validate(evil)
    assert ok is False and why, "scope stopped refusing an out-of-scope host: %r" % why
    # ...and the host that IS in scope is still allowed, so this is not a blanket deny
    assert a.scope.validate(BENCH_BASE + "/benchmark/x.html")[0] is True


def test_scope_still_refuses_the_hostless_url_itself():
    """Belt and braces: the guard is an addition, not a replacement. If someone deletes it, scope must
    still be the thing that says no."""
    a = _agent(_Tools())
    assert a.scope.validate(HOSTLESS)[0] is False
