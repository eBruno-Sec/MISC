"""_run_dom_trace renders its parameters concurrently without changing what it finds.

MEASURED (docs/handoff/throughput.md): run_dom_trace cost 7.95 s per call in-mission and
run_dom_audit 29.7 s -- together 16% of a 5329 s benchmark run. Like run_xss, almost all of it is a
fixed settle wait (`wait_for_timeout(600)`) after each render, executed one parameter at a time.

Each parameter's render chain is INDEPENDENT of the others: the plain render decides whether that
parameter gets an attacker-host render and XSS renders, and nothing in the chain reads another
parameter's result. The only shared state was the `seen` dedup set, and that is applied afterwards in
PARAMETER ORDER -- so the parameters can render together while the findings stay exactly the ones the
serial loop produced, in exactly its order.
"""
import asyncio
import sys
import types

import pytest

import tools
import dom_trace as dt
import scope as scope_mod


# ── a fake browser rich enough for _render ───────────────────────────────────
class _FakePage:
    def __init__(self, rec, sinks, settle=0.02):
        self._rec, self._sinks, self._settle = rec, sinks, settle
        self.url = ""
        self._current = ""

    def on(self, event, cb):
        return None

    async def goto(self, u, **kw):
        self._current = self.url = u
        self._rec["visited"].append(u)
        self._rec["inflight"] += 1
        self._rec["peak"] = max(self._rec["peak"], self._rec["inflight"])
        return None

    async def wait_for_timeout(self, ms):
        await asyncio.sleep(self._settle)
        self._rec["inflight"] -= 1

    async def evaluate(self, js, canary):
        return self._sinks(self._current, canary)


class _FakeContext:
    def __init__(self, rec, sinks):
        self._rec, self._sinks = rec, sinks

    async def new_page(self):
        return _FakePage(self._rec, self._sinks)

    async def set_extra_http_headers(self, h):
        return None

    async def add_cookies(self, c):
        return None

    async def close(self):
        self._rec["contexts_closed"] += 1


class _FakeBrowser:
    def __init__(self, rec, sinks):
        self._rec, self._sinks = rec, sinks

    async def new_context(self, **kw):
        self._rec["contexts"] += 1
        self._rec["ctx_live"] += 1
        self._rec["ctx_peak"] = max(self._rec["ctx_peak"], self._rec["ctx_live"])
        return _FakeContext(self._rec, self._sinks)

    async def close(self):
        self._rec["closed"] = True


class _FakeChromium:
    def __init__(self, rec, sinks):
        self._rec, self._sinks = rec, sinks

    async def launch(self, **kw):
        return _FakeBrowser(self._rec, self._sinks)


class _FakePW:
    def __init__(self, rec, sinks):
        self.chromium = _FakeChromium(rec, sinks)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def _install(monkeypatch, rec, sinks):
    mod = types.ModuleType("playwright.async_api")
    mod.async_playwright = lambda: _FakePW(rec, sinks)
    pkg = types.ModuleType("playwright")
    pkg.async_api = mod
    monkeypatch.setitem(sys.modules, "playwright", pkg)
    monkeypatch.setitem(sys.modules, "playwright.async_api", mod)
    monkeypatch.setattr(tools, "_chrome_path", lambda: "/fake/chrome")


def _rec():
    return {"visited": [], "inflight": 0, "peak": 0, "contexts": 0, "ctx_live": 0,
            "ctx_peak": 0, "contexts_closed": 0, "closed": False}


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


URL = "http://t.local/p?alpha=1&beta=2&gamma=3"


def _sinks_reflect(which):
    """The canary reaches rendered DOM text only for the named parameters."""
    def f(current_url, canary):
        hit = any(("%s=" % p) in (current_url or "") and canary in (current_url or "")
                  for p in which)
        return {"in_href": "", "in_src": "", "in_attr": "", "in_text": bool(hit)}
    return f


def _exec(monkeypatch, width, sinks):
    monkeypatch.setenv("BBH_BROWSER_CONCURRENCY", str(width))
    rec = _rec()
    _install(monkeypatch, rec, sinks)
    sc = scope_mod.ScopeEngine()
    sc.load_manual(["http://t.local"], [], "t")
    reg = tools.ToolRegistry(sc, mission_id=None, lab_mode=True)
    # pin the parameter list so the always-on DOM-sink seed + discovery cannot vary the fixture
    res = _run(reg._run_dom_trace({"url": URL, "params": ["alpha", "beta", "gamma", "url", "next"]}))
    return res, rec


def _param_of(title):
    """dom_trace carries the parameter only inside the title: "<what> in '<param>'"."""
    bits = (title or "").split("'")
    return bits[1] if len(bits) >= 2 else ""


def _fp(res):
    """Stable identity of a dom_trace finding set. The canary is random PER RENDER in both the
    serial and the parallel path (pre-existing), so it is deliberately excluded -- what must not
    move is which families were confirmed on which parameters, and in what order."""
    return [(f.get("family"), _param_of(f.get("title")), f.get("severity"), f.get("title"))
            for f in (res.findings or [])]


# ── the oracle: same findings, in the same order, at every width ─────────────
@pytest.mark.parametrize("width", [2, 3, 6, 16])
def test_parallel_finding_set_matches_serial_exactly(monkeypatch, width):
    sinks = _sinks_reflect(["alpha", "gamma"])
    serial, _ = _exec(monkeypatch, 1, sinks)
    par, _ = _exec(monkeypatch, width, sinks)
    assert _fp(par) == _fp(serial), "width %d changed the findings" % width
    assert _fp(serial), "the fixture proved nothing -- serial found no DOM signal either"


def test_findings_stay_in_parameter_order_not_completion_order(monkeypatch):
    """Whichever tab wins the race, the query-source findings must come back in the order
    the parameters were listed -- and the fragment pass must still come after all of them."""
    order = ["alpha", "beta", "gamma", "url", "next"]
    sinks = _sinks_reflect(["alpha", "beta", "gamma"])
    par, _ = _exec(monkeypatch, 6, sinks)
    query = [p for _, p, _, _ in _fp(par) if p in order]
    assert query == sorted(query, key=order.index), _fp(par)
    assert query, "fixture produced no query-source findings"


def test_clean_page_finds_nothing_at_any_width(monkeypatch):
    for w in (1, 2, 6, 16):
        res, rec = _exec(monkeypatch, w, _sinks_reflect([]))
        assert res.findings == [], "width %d invented a DOM finding on a clean page" % w
        assert rec["closed"] is True, "width %d leaked the browser" % w


def test_repeat_runs_are_stable(monkeypatch):
    sinks = _sinks_reflect(["alpha", "gamma"])
    first, _ = _exec(monkeypatch, 6, sinks)
    for _ in range(6):
        again, _ = _exec(monkeypatch, 6, sinks)
        assert _fp(again) == _fp(first)


# ── the speedup is real, and bounded ─────────────────────────────────────────
def test_parameter_renders_actually_overlap(monkeypatch):
    _, rec = _exec(monkeypatch, 6, _sinks_reflect([]))
    assert rec["peak"] > 1, "nothing overlapped -- dom_trace is still one parameter at a time"


@pytest.mark.parametrize("width", [1, 2, 4, 16])
def test_in_flight_renders_never_exceed_the_width(monkeypatch, width):
    _, rec = _exec(monkeypatch, width, _sinks_reflect(["alpha", "beta"]))
    assert rec["peak"] <= width, "peak %d exceeded width %d" % (rec["peak"], width)


def test_width_one_is_still_strictly_serial(monkeypatch):
    _, rec = _exec(monkeypatch, 1, _sinks_reflect(["alpha"]))
    assert rec["peak"] == 1


def test_every_context_is_closed_at_every_width(monkeypatch):
    """Parallel renders must not leak browser contexts -- that is how a scanner ends up
    consuming more of the target's resources than the serial version did."""
    for w in (1, 6, 16):
        _, rec = _exec(monkeypatch, w, _sinks_reflect(["alpha", "beta"]))
        assert rec["contexts_closed"] == rec["contexts"], \
            "width %d leaked %d context(s)" % (w, rec["contexts"] - rec["contexts_closed"])


def test_the_number_of_renders_does_not_grow_with_the_width(monkeypatch):
    """Going faster must not mean hitting the target harder. Same work, overlapped."""
    sinks = _sinks_reflect(["alpha", "gamma"])
    _, s = _exec(monkeypatch, 1, sinks)
    for w in (2, 6, 16):
        _, p = _exec(monkeypatch, w, sinks)
        assert len(p["visited"]) == len(s["visited"]), \
            "width %d issued %d renders vs serial's %d" % (w, len(p["visited"]), len(s["visited"]))


def test_scope_block_and_no_browser_are_unchanged(monkeypatch):
    monkeypatch.setenv("BBH_BROWSER_CONCURRENCY", "6")
    rec = _rec()
    _install(monkeypatch, rec, _sinks_reflect([]))
    sc = scope_mod.ScopeEngine()
    sc.load_manual(["http://t.local"], [], "t")
    reg = tools.ToolRegistry(sc, mission_id=None, lab_mode=True)
    out = _run(reg._run_dom_trace({"url": "http://evil.example/p?a=1"}))
    assert out.error == "SCOPE BLOCK"
    assert rec["visited"] == []

    monkeypatch.setattr(tools, "_chrome_path", lambda: None)
    out = _run(reg._run_dom_trace({"url": URL}))
    assert out.findings == [] and "no headless browser" in out.output
