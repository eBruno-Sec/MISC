"""_run_dom_audit renders its probes concurrently without changing what it confirms.

MEASURED (docs/handoff/throughput.md): run_dom_audit cost 29.7 s per call in-mission -- 505 s, 9.5%
of a 5329 s benchmark run, from only 17 calls. Like the other browser engines almost all of it is a
fixed settle wait after each render (350 ms, or 900 ms plus a networkidle wait for the CSTI class),
paid one probe at a time.

Each probe renders in its OWN isolated browser context and reads nothing from any other probe. The
shared state was the "one confirmation per class is enough" early exit, which is preserved -- applied
at chunk boundaries, with findings folded afterwards in PROBE order.
"""
import asyncio
import sys
import time
import types

import pytest

import tools
import dom_tool as dom
import scope as scope_mod


class _FakePage:
    def __init__(self, rec, confirm, settle=0.02):
        self._rec, self._confirm, self._settle = rec, confirm, settle
        self._nav = ""
        self.url = ""

    def on(self, event, cb):
        return None

    async def goto(self, u, **kw):
        self._nav = self.url = u
        self._rec["visited"].append(u)
        self._rec["inflight"] += 1
        self._rec["peak"] = max(self._rec["peak"], self._rec["inflight"])
        return None

    async def wait_for_timeout(self, ms):
        await asyncio.sleep(self._settle)
        self._rec["inflight"] -= 1

    async def wait_for_load_state(self, *a, **kw):
        return None

    async def evaluate(self, js, *a):
        # window.Object.prototype[PP_KEY] -> the pollution read; confirmed_proto wants MARK
        if "Object.prototype" in js:
            return dom.MARK if self._confirm(self._nav, "proto") else None
        if "outerHTML" in js or "innerText" in js:
            return "49" + dom.MARK if self._confirm(self._nav, "csti") else "nothing here"
        return ""

    async def screenshot(self, **kw):
        return b"\x89PNG fake"


class _FakeContext:
    def __init__(self, rec, confirm):
        self._rec, self._confirm = rec, confirm

    async def new_page(self):
        return _FakePage(self._rec, self._confirm)

    async def set_extra_http_headers(self, h):
        return None

    async def add_cookies(self, c):
        return None

    async def close(self):
        self._rec["ctx_live"] -= 1
        self._rec["contexts_closed"] += 1


class _FakeBrowser:
    def __init__(self, rec, confirm):
        self._rec, self._confirm = rec, confirm

    async def new_context(self, **kw):
        self._rec["contexts"] += 1
        self._rec["ctx_live"] += 1
        self._rec["ctx_peak"] = max(self._rec["ctx_peak"], self._rec["ctx_live"])
        return _FakeContext(self._rec, self._confirm)

    async def close(self):
        self._rec["closed"] = True


class _FakePW:
    def __init__(self, rec, confirm):
        self.chromium = types.SimpleNamespace(
            launch=lambda **kw: _mk(_FakeBrowser(rec, confirm)))

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


async def _mk(v):
    return v


def _install(monkeypatch, rec, confirm):
    mod = types.ModuleType("playwright.async_api")
    mod.async_playwright = lambda: _FakePW(rec, confirm)
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


URL = "http://t.local/page?q=1&view=2"


def _confirm_none(nav, kind):
    return False


def _confirm_proto(nav, kind):
    return kind == "proto"


def _exec(monkeypatch, width, confirm, gadget_pass=True):
    """`gadget_pass=False` spends the mission-wide gadget budget up front, so only the FIRST
    probe loop runs. Needed to measure that loop's early exit on its own: confirming `proto` is
    what UNLOCKS the gadget pass, so a page where everything confirms legitimately costs more
    renders than a clean one, and a naive comparison measures the wrong thing."""
    monkeypatch.setenv("BBH_BROWSER_CONCURRENCY", str(width))
    rec = _rec()
    _install(monkeypatch, rec, confirm)
    sc = scope_mod.ScopeEngine()
    sc.load_manual(["http://t.local"], [], "t")
    reg = tools.ToolRegistry(sc, mission_id=None, lab_mode=True)
    if not gadget_pass:
        reg._gadget_pages = 3
    # no network: the param-discovery probe and the gadget-pass JS harvest both go through _http
    async def _no_http(*a, **kw):
        return {"error": "", "status": 200, "headers": {}, "body": "", "length": 0, "final_url": URL}
    monkeypatch.setattr(reg, "_http", _no_http)
    monkeypatch.setattr(reg, "_discover_params", lambda *a, **kw: _mk([]))
    res = _run(reg._run_dom_audit({"url": URL}))
    return res, rec


def _fp(res):
    return sorted((f.get("family"), f.get("severity"), f.get("title"))
                  for f in (res.findings or []))


# ── the oracle ────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("width", [2, 4, 6, 16])
def test_parallel_confirmations_match_serial(monkeypatch, width):
    serial, _ = _exec(monkeypatch, 1, _confirm_proto)
    par, _ = _exec(monkeypatch, width, _confirm_proto)
    assert _fp(par) == _fp(serial), "width %d changed the confirmations" % width
    assert _fp(serial), "the fixture proved nothing -- serial confirmed nothing either"


def test_clean_page_confirms_nothing_at_any_width(monkeypatch):
    for w in (1, 2, 6, 16):
        res, rec = _exec(monkeypatch, w, _confirm_none)
        assert res.findings == [], "width %d invented a DOM finding" % w
        assert rec["closed"] is True, "width %d leaked the browser" % w


def test_repeat_parallel_runs_are_stable(monkeypatch):
    first, _ = _exec(monkeypatch, 6, _confirm_proto)
    for _ in range(6):
        again, _ = _exec(monkeypatch, 6, _confirm_proto)
        assert _fp(again) == _fp(first)


def test_one_confirmation_per_class_still_holds(monkeypatch):
    """The early exit is the reason this engine is affordable at all -- it must survive."""
    res, _ = _exec(monkeypatch, 6, _confirm_proto)
    fams = [f.get("family") for f in res.findings]
    assert len(fams) == len(set(fams)), "the same class was confirmed twice: %s" % fams


# ── bounded, and no extra traffic ────────────────────────────────────────────
def test_probe_renders_actually_overlap(monkeypatch):
    """Overlap measured DIRECTLY, as occupancy spans: the counter goes up when a render starts
    and down when its settle ends, so `peak` is how many renders were genuinely in flight at
    once. Deliberately run on a CLEAN page -- nothing confirms, so no early exit fires and the
    number of confirmations cannot move this number in either direction."""
    _, rec = _exec(monkeypatch, 6, _confirm_none)
    assert rec["peak"] > 1, "nothing overlapped -- dom_audit is still one probe at a time"


def test_parallel_wall_clock_beats_serial(monkeypatch):
    """The second overlap metric, chosen because NOTHING about the finding set can move it:
    wall clock for the SAME number of renders. A clean page fires no early exit, so width 1 and
    width 6 issue an identical render list; each fake settle is a fixed 20 ms, so a serial run
    costs N x 20 ms and an overlapped one must come in far under that. Renders are asserted
    equal in the same breath, so 'faster' can never be bought by probing less."""
    t0 = time.perf_counter()
    _, s = _exec(monkeypatch, 1, _confirm_none)
    serial = time.perf_counter() - t0
    t0 = time.perf_counter()
    _, p = _exec(monkeypatch, 6, _confirm_none)
    par = time.perf_counter() - t0
    assert len(p["visited"]) == len(s["visited"]), \
        "different render counts (%d vs %d) -- the comparison is meaningless" % (
            len(p["visited"]), len(s["visited"]))
    assert par < serial * 0.6, \
        "width 6 took %.3f s vs serial %.3f s for the same %d renders" % (
            par, serial, len(s["visited"]))


@pytest.mark.parametrize("width", [1, 2, 5, 16])
def test_in_flight_renders_never_exceed_the_width(monkeypatch, width):
    _, rec = _exec(monkeypatch, width, _confirm_none)
    assert rec["peak"] <= width, "peak %d exceeded width %d" % (rec["peak"], width)
    assert rec["ctx_peak"] <= width, "held %d contexts open at width %d" % (rec["ctx_peak"], width)


def test_width_one_is_still_strictly_serial(monkeypatch):
    _, rec = _exec(monkeypatch, 1, _confirm_none)
    assert rec["peak"] == 1
    assert rec["ctx_peak"] == 1


def test_every_context_is_closed_at_every_width(monkeypatch):
    for w in (1, 6, 16):
        _, rec = _exec(monkeypatch, w, _confirm_proto)
        assert rec["contexts_closed"] == rec["contexts"], \
            "width %d leaked %d context(s)" % (w, rec["contexts"] - rec["contexts_closed"])


def test_a_clean_page_costs_the_same_renders_at_every_width(monkeypatch):
    """No early exit fires on a clean page, so the render count must be width-independent --
    going faster must not mean hitting the target harder."""
    _, s = _exec(monkeypatch, 1, _confirm_none)
    for w in (2, 6, 16):
        _, p = _exec(monkeypatch, w, _confirm_none)
        assert len(p["visited"]) == len(s["visited"]), \
            "width %d issued %d renders vs serial's %d" % (w, len(p["visited"]), len(s["visited"]))


def test_the_early_exit_still_saves_renders(monkeypatch):
    """With the gadget pass out of the way, a page where every class confirms must cost FEWER
    renders than a clean one -- that is the 'one confirmation per class is enough' budget."""
    _, hit = _exec(monkeypatch, 6, lambda nav, kind: True, gadget_pass=False)
    _, clean = _exec(monkeypatch, 6, _confirm_none, gadget_pass=False)
    assert len(hit["visited"]) < len(clean["visited"]), \
        "early exit stopped saving renders (%d vs %d)" % (len(hit["visited"]), len(clean["visited"]))


def test_scope_block_and_no_browser_are_unchanged(monkeypatch):
    monkeypatch.setenv("BBH_BROWSER_CONCURRENCY", "6")
    rec = _rec()
    _install(monkeypatch, rec, _confirm_none)
    sc = scope_mod.ScopeEngine()
    sc.load_manual(["http://t.local"], [], "t")
    reg = tools.ToolRegistry(sc, mission_id=None, lab_mode=True)
    out = _run(reg._run_dom_audit({"url": "http://evil.example/p"}))
    assert out.error == "SCOPE BLOCK"
    assert rec["visited"] == []

    monkeypatch.setattr(tools, "_chrome_path", lambda: None)
    out = _run(reg._run_dom_audit({"url": URL}))
    assert out.findings == [] and "no headless browser" in out.output
