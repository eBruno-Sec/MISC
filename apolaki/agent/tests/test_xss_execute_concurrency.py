"""_xss_execute overlaps its settle windows without changing what it finds.

MEASURED (docs/handoff/throughput.md): run_xss was 60.7% of a whole 5329 s benchmark mission, and 82%
of one call was `await page.wait_for_timeout(350)` after every navigation, run serially. The settle
window is what an async payload needs to fire, so it is NOT shortened -- the waits overlap.

An oracle that changes its answer when it goes faster is worse than a slow oracle, so every test here
compares the PARALLEL result against the SERIAL one on the same input.
"""
import asyncio
import sys

import pytest

import tools
import xss_tool as xt
import scope as scope_mod


# ── a fake browser that records what was navigated, and when ─────────────────
class _FakeDialog:
    def __init__(self, message):
        self.message = message

    async def dismiss(self):
        return None


class _FakePage:
    def __init__(self, rec, vulnerable_when, settle=0.02):
        self._rec = rec
        self._vuln = vulnerable_when
        self._handler = None
        self._settle = settle

    def on(self, event, handler):
        if event == "dialog":
            self._handler = handler

    async def goto(self, url, **kw):
        self._rec["visited"].append(url)
        self._rec["inflight"] += 1
        self._rec["peak"] = max(self._rec["peak"], self._rec["inflight"])
        if self._vuln(url):
            self._handler(_FakeDialog(xt.MARK))
        return None

    async def wait_for_timeout(self, ms):
        await asyncio.sleep(self._settle)
        self._rec["inflight"] -= 1


class _FakeContext:
    def __init__(self, rec, vulnerable_when):
        self._rec = rec
        self._vuln = vulnerable_when

    async def new_page(self):
        self._rec["pages"] += 1
        return _FakePage(self._rec, self._vuln)

    async def set_extra_http_headers(self, h):
        return None

    async def add_cookies(self, c):
        return None


class _FakeBrowser:
    def __init__(self, rec, vulnerable_when):
        self._rec = rec
        self._vuln = vulnerable_when

    async def new_context(self, **kw):
        return _FakeContext(self._rec, self._vuln)

    async def close(self):
        self._rec["closed"] = True


class _FakeChromium:
    def __init__(self, rec, vulnerable_when):
        self._rec = rec
        self._vuln = vulnerable_when

    async def launch(self, **kw):
        self._rec["launches"] += 1
        return _FakeBrowser(self._rec, self._vuln)


class _FakePW:
    def __init__(self, rec, vulnerable_when):
        self.chromium = _FakeChromium(rec, vulnerable_when)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


def _install_fake(monkeypatch, rec, vulnerable_when):
    """Stand a fake `playwright.async_api` in front of the real one for this test."""
    import types
    mod = types.ModuleType("playwright.async_api")
    mod.async_playwright = lambda: _FakePW(rec, vulnerable_when)
    pkg = types.ModuleType("playwright")
    pkg.async_api = mod
    monkeypatch.setitem(sys.modules, "playwright", pkg)
    monkeypatch.setitem(sys.modules, "playwright.async_api", mod)
    monkeypatch.setattr(tools, "_chrome_path", lambda: "/fake/chrome")


def _registry():
    sc = scope_mod.ScopeEngine()
    sc.load_manual(["http://t.local"], [], "t")
    return tools.ToolRegistry(sc, mission_id=None, lab_mode=True)


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _new_rec():
    return {"visited": [], "inflight": 0, "peak": 0, "pages": 0, "launches": 0, "closed": False}


URL = "http://t.local/p?a=1&b=2"
PARAMS = ["a", "b"]


def _exec(monkeypatch, width, vulnerable_when):
    monkeypatch.setenv("BBH_BROWSER_CONCURRENCY", str(width))
    rec = _new_rec()
    _install_fake(monkeypatch, rec, vulnerable_when)
    findings = _run(_registry()._xss_execute(URL, PARAMS))
    return findings, rec


def _fp(findings):
    """The comparable identity of a finding set -- title + target + the payload evidence."""
    return sorted((f.get("title", ""), f.get("target", ""), f.get("request", ""))
                  for f in findings)


# ── THE ORACLE: parallel must find exactly what serial found ─────────────────
def test_clean_target_finds_nothing_at_any_width(monkeypatch):
    never = lambda u: False
    for w in (1, 2, 6, 16):
        findings, rec = _exec(monkeypatch, w, never)
        assert findings == [], "width %d invented a finding on a clean target" % w
        assert rec["closed"] is True, "width %d leaked the browser" % w


@pytest.mark.parametrize("width", [2, 3, 6, 16])
def test_parallel_finding_set_is_identical_to_serial(monkeypatch, width):
    """The acceptance test in miniature. Two params are vulnerable to different payloads;
    the parallel run must return the same findings the serial loop returned."""
    def vuln(u):
        return "svg onload" in u or "onerror" in u

    serial, _ = _exec(monkeypatch, 1, vuln)
    par, _ = _exec(monkeypatch, width, vuln)
    assert _fp(par) == _fp(serial), "width %d changed the finding set" % width
    assert serial, "the fixture proved nothing -- serial found no XSS either"


def test_the_reported_payload_is_the_first_one_in_order_not_the_first_to_finish(monkeypatch):
    """Several payloads for the same parameter fire. The serial loop broke on the FIRST in
    EXEC_PAYLOADS order; the parallel run must report that same one, not whichever tab won."""
    def vuln(u):
        return "onerror" in u or "svg onload" in u   # payloads 0,1,2 and 3,4 all fire

    serial, _ = _exec(monkeypatch, 1, vuln)
    for width in (2, 4, 8, 16):
        par, _ = _exec(monkeypatch, width, vuln)
        assert _fp(par) == _fp(serial), "width %d reported a different payload" % width
    # and there is exactly one finding per (where, param), never one per payload
    assert len(serial) == len({(f["title"], f["target"]) for f in serial})


def test_two_parallel_runs_are_byte_identical(monkeypatch):
    """Negative control (c): re-running must yield the same findings AND the same navigations."""
    def vuln(u):
        return "svg onload" in u

    first = _exec(monkeypatch, 6, vuln)
    for _ in range(6):
        again = _exec(monkeypatch, 6, vuln)
        assert _fp(again[0]) == _fp(first[0])
        assert again[1]["visited"] == first[1]["visited"], "the request sequence drifted"


# ── the speedup is real, and bounded ─────────────────────────────────────────
def test_navigations_actually_overlap(monkeypatch):
    never = lambda u: False
    findings, rec = _exec(monkeypatch, 6, never)
    assert rec["peak"] > 1, "nothing overlapped -- this is still the serial loop"
    assert rec["peak"] <= 6, "peak %d exceeded the configured width" % rec["peak"]


@pytest.mark.parametrize("width", [1, 2, 5, 16])
def test_in_flight_navigations_never_exceed_the_configured_width(monkeypatch, width):
    never = lambda u: False
    _, rec = _exec(monkeypatch, width, never)
    assert rec["peak"] <= width
    assert rec["pages"] <= width, "opened %d tabs for a width of %d" % (rec["pages"], width)


def test_width_one_still_visits_exactly_what_the_serial_loop_visited(monkeypatch):
    """Negative control (b): a single-URL / width-1 mission must not change its behaviour."""
    def vuln(u):
        return "svg onload" in u

    _, rec1 = _exec(monkeypatch, 1, vuln)
    assert rec1["peak"] == 1
    assert rec1["pages"] == 1


def test_early_exit_still_saves_requests(monkeypatch):
    """A confirmed parameter must stop paying for its remaining payloads -- otherwise the
    speedup is bought with extra traffic against the target."""
    always = lambda u: True          # every payload fires
    _, rec = _exec(monkeypatch, 4, always)
    full = len(PARAMS) * len(xt.EXEC_PAYLOADS) + len(xt.EXEC_PAYLOADS)
    assert len(rec["visited"]) < full, "early exit stopped working -- every payload was sent"


def test_out_of_scope_targets_are_never_navigated(monkeypatch):
    """Scope is enforced before dispatch, not inside the loop -- prove it still holds."""
    monkeypatch.setenv("BBH_BROWSER_CONCURRENCY", "6")
    rec = _new_rec()
    _install_fake(monkeypatch, rec, lambda u: False)
    sc = scope_mod.ScopeEngine()
    sc.load_manual(["http://t.local"], [], "t")
    reg = tools.ToolRegistry(sc, mission_id=None, lab_mode=True)
    _run(reg._xss_execute("http://evil.example/p?a=1", ["a"]))
    assert rec["visited"] == [], "navigated an out-of-scope target"


def test_no_browser_is_still_a_clean_no_op(monkeypatch):
    monkeypatch.setattr(tools, "_chrome_path", lambda: None)
    assert _run(_registry()._xss_execute(URL, PARAMS)) == []
