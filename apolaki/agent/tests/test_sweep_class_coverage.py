"""The deterministic sweep's COVERAGE GUARANTEE, asserted as a fact about dispatches rather than as
a declaration about a constant.

`_inject_sweep_surface`'s docstring states the invariant it exists to provide: "a discovered query
input is ALWAYS tested even if the graph-authoritative planner did not select it". MEASURED on the
whole-product run (docs/handoff/selection.md), the invariant held for SQLi, XPath, LDAP and SSI and
did NOT hold for path traversal, IDOR or insecure cookies: `run_web_probes` -- the engine that owns
all three -- had exactly one dispatch site in the whole product, `planner.py`'s per-endpoint batch,
bounded by `CAP_ENDPOINTS = 25`. So 400 endpoints were guaranteed an injection battery and 25 were
guaranteed a traversal test, on a surface where the two numbers should be the same.

These tests drive the REAL `_inject_sweep_surface` with a recording `_run_tool`, so they assert what
was DISPATCHED. Asserting `"run_web_probes" in _SWEEP_HTTP_ENGINES` instead would be a guard that
checks a declaration: it would pass on a tuple that no code path iterates.
"""
from __future__ import annotations

import asyncio

import agent as agent_mod
import scope as scope_mod


class _State:
    identities: dict = {}


class _Tools:
    """Enough registry to drive the sweep. No network: `_run_tool` is replaced by the recorder."""

    def __init__(self, urls, forms=None):
        self.urls = list(urls)
        self.recon = {"forms": list(forms or []), "target": "t", "domain": "t",
                      "subdomains": [], "live_hosts": []}
        self.intensity = "standard"
        self.state = _State()
        self.session_headers = None
        self._enum_known_username = ""
        self._fixation_credential = None

    async def _discover_params(self, _url):
        return []

    def get_openai_tools(self):
        return []

    def get_claude_tools(self):
        return []


def _sweep(urls, forms=None, in_scope=("*.t",)):
    """Run the real sweep; return the (tool, url) dispatches it made."""
    eng = scope_mod.ScopeEngine()
    eng.load_manual(list(in_scope), [], "sweep")
    tools = _Tools(urls, forms)
    ag = agent_mod.BBHAgent(eng, tools, asyncio.Event(), strategy="deterministic", mission_id=None)

    calls = []

    async def fake_run_tool(tool, inp, _sid):
        calls.append((tool, str((inp or {}).get("url") or "")))
        return
        yield

    ag._run_tool = fake_run_tool

    async def run():
        async for _ in ag._inject_sweep_surface("s"):
            pass

    asyncio.run(run())
    return calls


_URLS = ["https://t/app/sec%02d/page%02d.html?p%02d=x" % (i, i, i) for i in range(12)]


def test_the_sweep_actually_dispatches_on_the_parameterized_surface():
    """Non-vacuity. Every assertion below is free if the sweep dispatched nothing at all."""
    calls = _sweep(_URLS)
    swept = {u for t, u in calls if t == "run_sqli"}
    assert len(swept) == len(_URLS), "sweep reached %d of %d parameterized URL(s)" % (
        len(swept), len(_URLS))


def test_every_swept_target_is_also_tested_for_traversal_and_idor():
    """THE invariant. A discovered `?file=` parameter receiving seven engines that cannot read a
    file, and not the one that can, is a selection defect however good the seven are."""
    calls = _sweep(_URLS)
    injected = {u for t, u in calls if t == "run_sqli"}
    traversal = {u for t, u in calls if t == "run_web_probes"}
    missing = sorted(injected - traversal)
    assert not missing, (
        "%d of %d swept target(s) were never handed to run_web_probes (traversal / IDOR / "
        "cookie-flags): %s" % (len(missing), len(injected), missing[:3]))


def test_the_traversal_engine_is_not_restricted_to_the_browser_budget():
    """`SWEEP_BROWSER_CAP` deliberately restricts the two ~19 s browser confirmers to the front of
    the shape-spread order. run_web_probes is HTTP-only and must not inherit that bound -- if it
    did, the guarantee above would silently apply to the first 30 targets only."""
    urls = ["https://t/app/s%03d/p%03d.html?p%03d=x" % (i, i, i)
            for i in range(agent_mod.SWEEP_BROWSER_CAP + 5)]
    calls = _sweep(urls)
    traversal = {u for t, u in calls if t == "run_web_probes"}
    assert len(traversal) > agent_mod.SWEEP_BROWSER_CAP, (
        "run_web_probes reached %d target(s), at or below the browser cap %d"
        % (len(traversal), agent_mod.SWEEP_BROWSER_CAP))


def test_the_sweep_budget_still_bounds_the_traversal_engine():
    """The other direction: a guarantee that ignores the budget is an unbounded sweep. Whatever
    `SWEEP_TARGET_CAP` is, run_web_probes must respect it like every other HTTP engine."""
    cap = agent_mod.SWEEP_TARGET_CAP
    urls = ["https://t/app/s%04d/p%04d.html?p%04d=x" % (i, i, i) for i in range(cap + 25)]
    calls = _sweep(urls)
    traversal = {u for t, u in calls if t == "run_web_probes"}
    assert len(traversal) <= cap, "run_web_probes exceeded the sweep budget: %d > %d" % (
        len(traversal), cap)


def test_the_http_tier_stays_ordered_and_deterministic():
    """Two identical sweeps dispatch identically. Determinism is the platform's standing property
    and a selection change is exactly where it would be lost."""
    assert _sweep(_URLS) == _sweep(_URLS)
