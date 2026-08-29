"""Q-113 - the deterministic injection sweep must be BOUNDED and must SAY what it declined.

MEASURED, operator's authorised Shopify engagement: the sweep reached endpoint 69 of 465 in roughly
seven hours (~6 min/endpoint against a Cloudflare-fronted target). The remaining 396 needed another
~46 hours. Nothing was stalling - Q-110's per-call budget never fired (TRUNCATED count 0) and the
heartbeat advanced normally. 465 endpoints x 8 HTTP engines is simply more work than an engagement
has. The operator stopped at 15% holding exactly the findings he already had at 5%.

Two claims that are NOT the same thing:

    "0 confirmed across 465 endpoints"        <- evidence about the target
    "0 confirmed across the 40 we chose"      <- evidence about our budget

The second is the honest one for a capped sweep, and the mission must print which one it is making.
Same discipline as Q-110's `DEGRADED: call budget exhausted, sweep TRUNCATED` and Q-093's rule that
a failed attempt is never reported as a clean result.

EVERY BOUND ASSERTED HERE IS A LITERAL INTEGER, never `agent.SWEEP_TARGET_CAP`. A cap gate that
asserts `len(selected) <= THE_CAP` is self-referential and passes for any value of the thing it
exists to bound - that exact mistake killed 0 of 4 mutants earlier this month.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import agent as agent_mod


# ── the surface, built to discriminate ────────────────────────────────────────────────────────────
#
# 57 ordinary shapes x 8 members = 456, then 9 high-value endpoints APPENDED LAST. Two properties are
# load-bearing and both were got wrong in a first draft:
#
#   * DISTINCT WORDS, not distinct digits. `target_shape` normalises `\d+` to `#`, so `sec01`/`sec02`
#     collapse to ONE shape and the round-robin degenerates into discovery order - the fixture would
#     then pass for free.
#   * 66 shapes against a 40-slot budget, i.e. MORE SHAPES THAN SLOTS. Value ranking and shape
#     spreading only differ when the budget cannot give every shape a slot; with fewer shapes than
#     slots the round-robin alone reaches everything and no ranking is under test.
_ORDINARY_SECTIONS = ["s%s%s" % (a, b) for a in "qrtvwxyz" for b in "qrtvwxyz"][:57]
#: `ref` is deliberately NOT in `agent._HIGH_VALUE_PARAM`, so every ordinary endpoint scores the
#: floor and only the nine appended sinks can be picked on value.
_ORDINARY_PARAM = "ref"

#: Appended AFTER the 456 ordinary endpoints, so discovery order buries every one of them.
_HIGH_VALUE = (
    "https://t.test/admin/execute?cmd=id",
    "https://t.test/manage/backup?file=/etc/passwd",
    "https://t.test/internal/debug?url=http://169.254.169.254/",
    "https://t.test/account/profile?redirect=//evil.test",
    "https://t.test/private/export?path=../../etc/shadow",
    "https://t.test/graphql/gateway?query=%7B__schema%7D",
    "https://t.test/auth/session?uid=1",
    "https://t.test/upload/import?template=%7B%7B7*7%7D%7D",
    "https://t.test/api/rest?callback=cb",
)


def _ordinary_surface() -> list:
    # The eight members of a section differ only by a DIGIT, which `target_shape` normalises to `#`,
    # so a section is exactly one shape. Differing by a letter instead gave 456 shapes and the
    # fixture stopped discriminating - that draft is why this file has a guard-the-guard test.
    return ["https://t.test/%s/leaf%d.html?%s=1" % (sec, i, _ORDINARY_PARAM)
            for sec in _ORDINARY_SECTIONS for i in range(8)]


def _surface_465() -> list:
    urls = _ordinary_surface() + list(_HIGH_VALUE)
    assert len(urls) == 465, len(urls)
    return urls


def _surface_10() -> list:
    """The NEGATIVE CONTROL surface: an ordinary engagement that fits inside any sane budget."""
    return ["https://t.test/%s/leaf0.html?ref=1" % sec for sec in _ORDINARY_SECTIONS[:10]]


#: The param sweep's marker engine. `run_xpath` / `run_ldap` / `run_ssi` are ALSO dispatched by the
#: later HTML-page pass on every crawled page, so counting the whole `_SWEEP_HTTP_ENGINES` tuple
#: counts pages the budget does not govern - measured, it reported 477 "swept endpoints" on a
#: 465-endpoint surface. `run_sqli` is dispatched by the parameterized sweep and nothing else.
_PARAM_SWEEP_MARKER = "run_sqli"


def test_the_fixture_actually_discriminates():
    """GUARD THE GUARD. If the fixture collapses to a handful of shapes, or if the high-value
    endpoints are not genuinely buried, every assertion below passes without the product doing
    anything - which is how a cap gate ends up killing zero mutants."""
    urls = _surface_465()
    shapes = {agent_mod.target_shape(u) for u in urls}
    assert len(shapes) == 66, "the fixture collapsed to %d shape(s)" % len(shapes)
    assert len(shapes) > 40, "fewer shapes than budget slots: the ranking is not under test"
    for u in _HIGH_VALUE:
        assert urls.index(u) >= 456, "high-value endpoint is not buried in discovery order"
        assert agent_mod.target_security_value(u) >= 4, u
    for u in _ordinary_surface()[:20]:
        assert agent_mod.target_security_value(u) == 1, u


# ── GATE 1 · the bound, asserted against a LITERAL ────────────────────────────────────────────────

def test_a_465_endpoint_surface_selects_a_bounded_number_of_targets():
    """The number the operator's seven hours bought was 69 of 465. A bound means the whole sweep is
    smaller than the 15% he could afford to sit through."""
    selected = agent_mod.sweep_targets(_surface_465(), [], lambda _u: True)
    assert len(selected) <= 60, (
        "the sweep selected %d endpoint(s); a 465-endpoint engagement at the measured ~6 min each "
        "cannot finish" % len(selected))
    assert len(selected) >= 25, "a budget this small stops being a scan (%d)" % len(selected)


# ── the ordering, i.e. what the bound actually buys ───────────────────────────────────────────────

def test_the_bounded_selection_keeps_the_high_value_endpoints():
    """MUTATION TARGET. A cap on top of a bad order buys nothing - Q-104b spent a correctly bounded
    recon budget entirely on wildcard-DNS junk because the order underneath it was lexical.

    Kills BOTH degradations of the selection:
      * `targets[:limit]`                       - discovery order, high-value endpoints are last
      * `_spread_by_shape(targets)[:limit]`     - shape order without value, and there are 66 shapes
                                                  for 40 slots, so the 9 high-value shapes (appended
                                                  last) never reach a slot
    """
    selected = set(agent_mod.sweep_targets(_surface_465(), [], lambda _u: True))
    missed = [u for u in _HIGH_VALUE if u not in selected]
    assert not missed, "the budget was spent before reaching the attack surface: %s" % missed


def test_operator_declared_hosts_outrank_discovered_ones():
    """Q-104's operator-assets-first pattern, applied to the sweep. A discovered host that merely
    LOOKS valuable must not displace an asset the operator actually put in scope."""
    declared = ["https://in-scope.test/catalog/leaf%02d.html?ref=1" % i for i in range(50)]
    discovered = ["https://found%02d.test/admin/execute?cmd=id" % i for i in range(50)]
    ranked = agent_mod.rank_targets_for_budget(discovered + declared,
                                               scope_roots=["in-scope.test"])
    assert all("in-scope.test" in u for u in ranked[:50]), (
        "a discovered host displaced every operator-declared asset: %s" % ranked[:3])
    # NEGATIVE CONTROL: with no roots declared, value ranking alone must still put the sinks first,
    # or this test would pass on a function that ignores its inputs.
    plain = agent_mod.rank_targets_for_budget(declared + discovered)
    assert all("found" in u for u in plain[:10]), plain[:3]


# ── GATE 1 (second half) + GATE 2 · what the mission SAYS ─────────────────────────────────────────

class _Tools:
    """Minimal ToolRegistry stand-in. `_swallow` raises, so a silently degraded fixture is a test
    failure rather than a quiet zero."""

    def __init__(self, urls):
        self.urls = list(urls)
        self.recon = {"forms": []}
        self.session_headers = None
        self.state = SimpleNamespace(identities={})

    async def _discover_params(self, _url):
        return []

    def _swallow(self, exc, owner, target):
        raise AssertionError("fixture degraded: %s %s %r" % (owner, target, exc))


class _Scope:
    #: `agent.operator_roots` reads exactly this — the operator's declared assets, which is what
    #: `select_sweep_targets` ranks ahead of anything the crawl merely discovered.
    in_scope = (SimpleNamespace(value="t.test"),)

    @staticmethod
    def validate(url):
        return (str(url).startswith("https://t.test/"), "")

    @staticmethod
    def base_urls():
        return ["https://t.test"]

    @staticmethod
    def base_map():
        return {"t.test": "https://t.test"}


def _drive_sweep(urls):
    """Run the REAL `_inject_sweep_surface` with a recording `_run_tool`. Returns
    (info lines, [(tool, url), ...])."""
    scan = object.__new__(agent_mod.BBHAgent)
    scan.tools = _Tools(urls)
    scan.scope = _Scope()
    scan.stop_event = asyncio.Event()
    scan._scope_origins = lambda: ["https://t.test"]
    dispatched = []

    async def _record(tool_name, tool_input, _session_id):
        dispatched.append((tool_name, tool_input.get("url")))
        return
        yield {}                                  # pragma: no cover - makes this an async generator

    scan._run_tool = _record

    async def _go():
        return [ev async for ev in scan._inject_sweep_surface("q113")]

    events = asyncio.run(_go())
    return [e.get("content", "") for e in events if e.get("type") == "info"], dispatched


def _sweep_line(infos):
    line = next((i for i in infos if "Deterministic injection sweep" in i), None)
    assert line, "the sweep never announced itself: %r" % (infos,)
    return line


def test_the_capped_sweep_dispatches_bounded_work_and_reports_what_it_declined():
    """GATE 1, as EXECUTION. `len(sweep_targets(...))` is a declaration; this counts what the mission
    actually hands to the engines, through the real `_inject_sweep_surface`."""
    infos, dispatched = _drive_sweep(_surface_465())
    swept = {url for tool, url in dispatched if tool == _PARAM_SWEEP_MARKER}
    assert len(swept) <= 60, "the sweep probed %d distinct endpoint(s)" % len(swept)

    injection = [d for d in dispatched
                 if d[0] in agent_mod._SWEEP_HTTP_ENGINES + agent_mod._SWEEP_BROWSER_ENGINES]
    assert len(injection) <= 600, "%d injection dispatches is not a bound" % len(injection)

    line = _sweep_line(infos)
    assert "DECLINED" in line, "the sweep did not report a declined count: %r" % line
    assert "465" in line, "the sweep did not state the surface it declined FROM: %r" % line
    declined = 465 - len(swept)
    assert str(declined) in line, (
        "the sweep declined %d endpoint(s) and did not say so: %r" % (declined, line))


def test_an_ordinary_engagement_is_not_silently_shrunk():
    """GATE 2, the NEGATIVE CONTROL, and the one that matters. A cap that quietly trims a 10-endpoint
    engagement is a new defect, not a fix - and a "0 declined" claim must be printed, not inferred
    from the absence of a warning."""
    infos, dispatched = _drive_sweep(_surface_10())
    swept = {url for tool, url in dispatched if tool == _PARAM_SWEEP_MARKER}
    assert len(swept) == 10, "an ordinary engagement lost %d endpoint(s)" % (10 - len(swept))
    assert swept == set(_surface_10())

    line = _sweep_line(infos)
    assert "DECLINED" not in line, "nothing was declined and the mission said it was: %r" % line
    assert "0 declined" in line, "a full sweep must SAY it declined nothing: %r" % line


def test_the_declined_count_is_durable_on_the_mission_and_not_only_in_a_log_line():
    """A number that exists only inside a formatted string cannot be read by the report. Q-110 made
    its truncation a counted fact for the same reason."""
    scan = object.__new__(agent_mod.BBHAgent)
    scan.tools = _Tools(_surface_465())
    scan.scope = _Scope()
    scan.stop_event = asyncio.Event()
    scan._scope_origins = lambda: ["https://t.test"]

    async def _record(_t, _i, _s):
        return
        yield {}                                  # pragma: no cover

    scan._run_tool = _record
    asyncio.run(_collect(scan))
    budget = getattr(scan, "_sweep_budget", None)
    assert isinstance(budget, dict), "the sweep budget was not recorded on the mission"
    assert budget["candidates"] == 465
    assert budget["declined"] == 465 - budget["selected"] > 0
    assert budget["selected"] <= 60


async def _collect(scan):
    return [ev async for ev in scan._inject_sweep_surface("q113")]


def test_the_one_step_wrapper_is_the_composition_the_mission_actually_runs():
    """NO ISLANDS. The mission call site runs `select_sweep_targets(sweep_candidates(...))` so it can
    hold both the numerator and the denominator; `sweep_targets` is the one-step form six other test
    files drive. Pin them to each other, or the wrapper becomes a second implementation that agrees
    with nothing and every test written against it stops being a test of the product."""
    urls, forms = _surface_465(), []
    for cap in (7, 40, 999):
        composed = agent_mod.select_sweep_targets(
            agent_mod.sweep_candidates(urls, forms, lambda _u: True), cap, ["t.test"])
        assert agent_mod.sweep_targets(urls, forms, lambda _u: True,
                                       scope_roots=["t.test"], limit=cap) == composed, cap
