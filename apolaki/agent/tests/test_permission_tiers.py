"""Q-052 -- CONSENT, not coverage: what an operator's chosen mode actually permits, and whether the
sweep that does 92% of the dispatching can tell a crashed engine from a clean target.

Two defects share one line of code, so they share one test module.

DEFECT A -- the sweep's bare swallow. `_inject_sweep_surface` dispatches through eight
`try: ... except Exception: pass` blocks. MEASURED on a whole-product mission, the sweep is 3350 of
4059 dispatches, so a bare `pass` there dissolves 92% of every engine failure the product can have:
a crashed engine and a clean target produce byte-identical output. `ToolRegistry._swallow` exists
for exactly this and RECORDS the failure. These tests drive the REAL `_inject_sweep_surface` with a
`_run_tool` that raises, and assert the failure is in the ledger -- a fact about what happened, not
a declaration that a handler exists.

DEFECT B -- the tier that permits everything. `_run_tool`'s entire mode enforcement is
`if self.mode == "passive" and perm != PermissionLevel.PASSIVE: block`. `passive` is real; `active`
blocks nothing, so `full` differs from `active` in no way the dispatcher can observe and a
three-tier model collapses to two. `planner._ALLOWED` DOES honour the tier. The tests below record
which mechanism enforces what, so the disagreement is a measured fact in the suite rather than an
argument in a handoff.
"""
from __future__ import annotations

import asyncio

import pytest

import agent as agent_mod
import planner as planner_mod
import scope as scope_mod
import tools as tools_mod
from scope import PermissionLevel


class _State:
    identities: dict = {}


class _Tools:
    """Enough registry to drive the sweep, plus the REAL `_swallow` bound onto it.

    Binding `ToolRegistry._swallow` rather than re-implementing it means these tests assert the
    product's own recording contract (including its 500-entry bound), not a lookalike.
    """

    _swallow = tools_mod.ToolRegistry._swallow

    def __init__(self, urls, forms=None):
        self.urls = list(urls)
        self.recon = {"forms": list(forms or []), "target": "t", "domain": "t",
                      "subdomains": [], "live_hosts": []}
        self.intensity = "standard"
        self.state = _State()
        self.session_headers = None
        self._enum_known_username = ""
        self._fixation_credential = None
        self.swallowed = []

    async def _discover_params(self, _url):
        return []

    def get_openai_tools(self):
        return []

    def get_claude_tools(self):
        return []


def _sweep(urls, raise_on=(), forms=None, in_scope=("*.t",)):
    """Run the REAL sweep with a recording `_run_tool` that raises for the named tools.

    Returns (dispatches, tools) so a test can assert both what was attempted and what the failure
    ledger holds afterwards.
    """
    eng = scope_mod.ScopeEngine()
    eng.load_manual(list(in_scope), [], "sweep")
    tools = _Tools(urls, forms)
    ag = agent_mod.BBHAgent(eng, tools, asyncio.Event(), strategy="deterministic", mission_id=None)

    calls = []
    boom = set(raise_on)

    async def fake_run_tool(tool, inp, _sid):
        calls.append((tool, str((inp or {}).get("url") or "")))
        if tool in boom:
            raise RuntimeError("engine exploded: %s" % tool)
        return
        yield

    ag._run_tool = fake_run_tool

    async def run():
        async for _ in ag._inject_sweep_surface("s"):
            pass

    asyncio.run(run())
    return calls, tools


_URLS = ["https://t/app/sec%02d/page%02d.html?p%02d=x" % (i, i, i) for i in range(6)]


# ── DEFECT A: the sweep's failure ledger ─────────────────────────────────────


def test_the_sweep_dispatches_at_all():
    """Non-vacuity. Every assertion below is free if the sweep dispatched nothing."""
    calls, _ = _sweep(_URLS)
    assert [t for t, _ in calls if t == "run_sqli"], "the sweep dispatched no run_sqli at all"


def test_a_crashing_sweep_engine_is_recorded_not_dissolved():
    """THE defect. `run_sqli` raising on every one of the swept targets must leave evidence."""
    calls, tools = _sweep(_URLS, raise_on={"run_sqli"})
    attempted = [u for t, u in calls if t == "run_sqli"]
    assert attempted, "non-vacuity: run_sqli was never dispatched"
    assert tools.swallowed, (
        "%d run_sqli dispatch(es) raised inside the sweep and NOTHING was recorded -- a crashed "
        "engine is indistinguishable from a clean target" % len(attempted))
    assert len(tools.swallowed) == len(attempted), (
        "recorded %d failure(s) for %d raising dispatch(es)" % (len(tools.swallowed), len(attempted)))


def test_the_record_names_the_engine_and_the_target():
    """A ledger entry that does not say WHICH engine failed on WHICH url cannot be acted on."""
    calls, tools = _sweep(_URLS, raise_on={"run_sqli"})
    entry = tools.swallowed[0]
    assert "run_sqli" in entry["where"], "ledger 'where' does not name the engine: %r" % (entry,)
    assert entry["target"].startswith("https://t/"), (
        "ledger 'target' does not carry the url: %r" % (entry,))
    assert "engine exploded" in entry["error"], (
        "ledger 'error' does not carry the exception message: %r" % (entry,))


def test_a_clean_sweep_records_nothing():
    """The negative control. If the ledger filled up on a healthy run it would be noise, and the
    'engines that have been failing silently' question could never be answered from it."""
    _, tools = _sweep(_URLS)
    assert tools.swallowed == [], "a sweep with no failures recorded %d entr(ies): %r" % (
        len(tools.swallowed), tools.swallowed[:3])


def test_a_crash_does_not_abort_the_sweep():
    """Recording must not change control flow: the handler still swallows, so the engines AFTER the
    crashing one on the same target still run. Losing this would trade blindness for lost coverage."""
    calls, _ = _sweep(_URLS, raise_on={"run_sqli"})
    per_target = {}
    for t, u in calls:
        per_target.setdefault(u, []).append(t)
    for u in [x for x in per_target if "?" in x]:
        assert "run_injection_probes" in per_target[u], (
            "run_sqli crashing on %s stopped the rest of the battery: %r" % (u, per_target[u]))


@pytest.mark.parametrize("engine", ["fetch_openapi", "run_graphql", "run_path_sqli",
                                    "run_encoded_cookie", "run_form_xss"])
def test_every_sweep_dispatch_site_records_its_failures(engine):
    """The sweep has EIGHT dispatch sites, not one. Fixing the big loop and leaving the siblings
    bare would move the blindness rather than remove it, and the seven small ones are exactly where
    a silent failure would be hardest to notice."""
    calls, tools = _sweep(["https://t/api/users/1", "https://t/login.html?q=1"], raise_on={engine})
    attempted = [u for t, u in calls if t == engine]
    if not attempted:
        pytest.fail("non-vacuity: %s is not dispatched by the sweep on this surface" % engine)
    assert tools.swallowed, "%s raised %d time(s) at its dispatch site and nothing was recorded" % (
        engine, len(attempted))
    assert any(engine in e["where"] for e in tools.swallowed), (
        "%s failures were recorded under some other name: %r" % (engine, tools.swallowed[:3]))


# ── DEFECT B: what the two gates actually enforce ────────────────────────────


def _dispatch_perms(mode, perms):
    """Drive the REAL `_run_tool` mode gate for each permission tier under `mode`.

    Returns the set of tiers that reached execution. `tools.execute` is stubbed, so reaching it IS
    the observable 'permitted' -- the assertion is about the gate, not about any engine.
    """
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["*.t"], [], "gate")
    tools = _Tools([])
    executed = []

    class _Result:
        def __init__(self, name):
            self.tool, self.target, self.success = name, "", True
            self.output, self.findings, self.error = "{}", [], None

    async def execute(name, _inp, _sid):
        executed.append(name)
        return _Result(name)

    tools.execute = execute
    ag = agent_mod.BBHAgent(eng, tools, asyncio.Event(), strategy="deterministic", mission_id=None)
    ag.mode = mode
    ag.auto_approve = True          # an autonomous run: the intrusive HITL gate is pre-authorised

    reached = set()
    for tier in perms:
        name = "__probe_%s" % tier.value
        tools_mod.TOOL_PERMISSIONS[name] = tier
        try:
            executed.clear()

            async def run():
                async for _ in ag._run_tool(name, {"url": "https://t/"}, "s"):
                    pass

            asyncio.run(run())
            if executed:
                reached.add(tier)
        finally:
            tools_mod.TOOL_PERMISSIONS.pop(name, None)
    return reached


_TIERS = (PermissionLevel.PASSIVE, PermissionLevel.ACTIVE, PermissionLevel.INTRUSIVE)


def _gate_events(mode, tier, auto_approve, preset_state=None):
    """Drive the REAL `_run_tool` for one tier and report (event types, engines executed).

    The generator is closed as soon as an approval is requested, so an un-answered gate does not
    block the test (`APPROVAL_TIMEOUT` defaults to 0 = wait forever).
    """
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["*.t"], [], "gate")
    tools = _Tools([])
    executed = []

    class _Result:
        def __init__(self, name):
            self.tool, self.target, self.success = name, "", True
            self.output, self.findings, self.error = "{}", [], None

    async def execute(name, _inp, _sid):
        executed.append(name)
        return _Result(name)

    tools.execute = execute
    ag = agent_mod.BBHAgent(eng, tools, asyncio.Event(), strategy="deterministic", mission_id=None)
    ag.mode = mode
    ag.auto_approve = auto_approve
    if preset_state is not None:
        ag.intrusive_state = preset_state

    name = "__probe_%s" % tier.value
    tools_mod.TOOL_PERMISSIONS[name] = tier
    events = []
    try:
        async def run():
            agen = ag._run_tool(name, {"url": "https://t/"}, "s")
            async for ev in agen:
                events.append(ev.get("type") or "_content")
                if ev.get("type") == "approval_required":
                    await agen.aclose()
                    return

        asyncio.run(run())
    finally:
        tools_mod.TOOL_PERMISSIONS.pop(name, None)
    return events, executed


def test_active_mode_ASKS_before_running_an_intrusive_engine():
    """The ticket's premise, tested rather than assumed -- and it does not hold.

    "An operator who selects `active` gets SQL, XPath and LDAP injection fired at their application"
    is FALSE for an interactive run. `active` + `auto_approve=False` reaches `_await_gate`, which
    emits `approval_required` and BLOCKS the mission until the operator answers. That is exactly the
    contract the mode selector advertises: "Active -- + scanning (1 approval gate)".
    """
    events, executed = _gate_events("active", PermissionLevel.INTRUSIVE, auto_approve=False)
    assert "approval_required" in events, (
        "an INTRUSIVE engine ran in `active` with no operator approval requested: %r" % (events,))
    assert executed == [], "the engine executed before the operator answered the gate: %r" % (executed,)


def test_a_denied_gate_stops_the_intrusive_engine():
    """Fail-closed, and the negative control for the test above. `_await_gate` also defaults to
    'denied' on timeout (`agent.py`: `self._approval_result or "denied"`), so silence is refusal."""
    events, executed = _gate_events("active", PermissionLevel.INTRUSIVE, auto_approve=False,
                                    preset_state="denied")
    assert executed == [], "a DENIED intrusive gate still executed the engine: %r" % (executed,)
    assert "scope_block" in events, events


def test_an_autonomous_run_pre_authorises_and_says_so():
    """The other half: `auto_approve=True` IS the operator's pre-authorisation of the intrusive
    phase, and the dispatcher announces it. wp3's 700 `run_sqli` dispatches were consented to here,
    not smuggled past a broken tier check."""
    events, executed = _gate_events("active", PermissionLevel.INTRUSIVE, auto_approve=True)
    assert executed, "a pre-authorised autonomous run failed to execute the intrusive engine"
    assert "approval_required" not in events, (
        "a pre-authorised run still stopped to ask: %r" % (events,))


def test_passive_mode_is_enforced_at_the_dispatcher():
    """The half that works, asserted so a change to the other half cannot quietly break it."""
    assert _dispatch_perms("passive", _TIERS) == {PermissionLevel.PASSIVE}


def _planner_perms(mode):
    """Which tiers `planner._allowed` admits under `mode`, via real registry entries.

    The probe names MUST be registered: `_allowed` falls back to ACTIVE for an unknown tool, so
    unregistered names would make every tier look ACTIVE and the test would assert nothing.
    """
    reached = set()
    for tier in _TIERS:
        name = "__probe_%s" % tier.value
        tools_mod.TOOL_PERMISSIONS[name] = tier
        try:
            if planner_mod._allowed(name, mode):
                reached.add(tier)
        finally:
            tools_mod.TOOL_PERMISSIONS.pop(name, None)
    return reached


def test_the_planner_honours_all_three_tiers():
    """`planner._allowed` is the mechanism that DOES implement the documented three-tier model."""
    got = {m: _planner_perms(m) for m in ("passive", "active", "full")}
    for mode, tiers in got.items():
        assert tiers == set(planner_mod._ALLOWED[mode]), (
            "planner mode %r admitted %r, table says %r" % (mode, tiers, planner_mod._ALLOWED[mode]))
    assert got["active"] != got["full"], "the planner cannot tell active from full either"


@pytest.mark.xfail(strict=True, reason=(
    "Q-052, MEASURED AND UNFIXED BY DECISION, not by oversight. agent._run_tool enforces exactly one "
    "rule -- block non-PASSIVE tools in `passive` mode -- so `active` admits INTRUSIVE and is "
    "indistinguishable from `full` at the dispatcher, while planner._ALLOWED honours all three tiers. "
    "Five of the eight sweep engines are INTRUSIVE and run_sqli fired 700 times in a WP_MODE=active "
    "mission. The fix is NOT a patch: narrowing `active` changes what every existing mission "
    "dispatches, including every published benchmark artifact, so it needs a re-measure and a "
    "product decision about what `active` should MEAN. STRICT so the day that decision lands this "
    "XPASSes, the suite goes red, and the marker must be retired deliberately."))
def test_active_and_full_are_distinguishable_at_the_dispatcher():
    """Q-052's core claim, as an executable fact.

    Two mechanisms gate the same three-tier model and they disagree: the planner refuses INTRUSIVE
    under `active`, the dispatcher admits it. Since the sweep dispatches through `_run_tool` and NOT
    through the planner, the dispatcher is the one that decides what an `active` mission actually
    sends -- which is how an operator who chose `active` got run_sqli fired 700 times.
    """
    active = _dispatch_perms("active", _TIERS)
    full = _dispatch_perms("full", _TIERS)
    assert active != full, (
        "`active` and `full` are indistinguishable at the dispatcher: both admit %r. The mode the "
        "operator selects has no effect above `passive`." % (sorted(t.value for t in active),))


# ── DEFECT C: the gate that a caller can walk around ─────────────────────────
#
# `_run_tool` and `_exec_internal` are the two GATED dispatch paths: both enforce passive-mode and
# the intrusive HITL gate. `ToolRegistry.execute` enforces SCOPE ONLY (tools.py `execute`: a scope
# check, then `getattr(self, "_" + tool_name)`), so any caller that reaches for it directly gets
# neither gate. `_exec_internal` exists precisely because that used to happen -- its own docstring
# says "previously these called self.tools.execute() straight through, skipping both gates".
#
# MEASURED: the candidate-validation pipeline runs for EVERY strategy and has NO mode guard
# (agent.py:2714), and inside it `run_jsonp` is dispatched through the ungated path while its three
# siblings in the same if/elif chain (`run_exposure`, `run_stored_xss`, `run_bfla`) all go through
# `_exec_internal` with a `# gated (#2)` comment. It is the one that was missed.


class _RecordingTools(_Tools):
    """A registry whose `execute` records instead of running. Nothing here reaches the network."""

    def __init__(self, urls=()):
        super().__init__(list(urls))
        self.executed = []

    async def execute(self, name, inp, _sid):
        self.executed.append(name)

        class _R:
            tool, target, success = name, "", True
            output, findings, error = "{}", [], None

        return _R()


def _validate_in_passive(lead):
    """Run the REAL candidate-validation pipeline at `mode='passive'`; return the engines it ran."""
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["*.t"], [], "gate")
    tools = _RecordingTools(["https://t/index.html", "https://t/app.html"])
    ag = agent_mod.BBHAgent(eng, tools, asyncio.Event(), strategy="deterministic", mission_id=None)
    ag.mode = "passive"
    ag.leads = [dict(lead)]

    async def run():
        async for _ in ag._validate_candidates_impl("s"):
            pass

    asyncio.run(run())
    return tools.executed


def test_passive_mode_blocks_the_jsonp_validator():
    """PASSIVE means OSINT only, no direct target contact -- the guarantee `agent.py:2594` states in
    so many words when it skips served-JS harvesting. `run_jsonp` is an ACTIVE engine that fetches a
    live callback endpoint, and the candidate pipeline reached it through the ungated
    `self.tools.execute`, so a passive scan made live requests the operator forbade."""
    ran = _validate_in_passive({"title": "JSONP callback endpoint", "family": "jsonp",
                                "target": "https://t/api?callback=cb"})
    assert "run_jsonp" not in ran, (
        "PASSIVE mode dispatched the ACTIVE engine run_jsonp at a live target: %r" % (ran,))


def test_a_gate_blocked_validator_is_BLOCKED_not_DISMISSED():
    """The half of the fix that is easy to get wrong. A validator the gate refused produced no
    findings, and "no findings" is one line away from "dismissed -- no JSONP wrapper found". Booking
    a refusal as a clean result is a false negative manufactured by a safety fix, so the candidate
    must come back BLOCKED with the reason named."""
    import candidate_pipeline as cp
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["*.t"], [], "gate")
    tools = _RecordingTools(["https://t/index.html"])
    ag = agent_mod.BBHAgent(eng, tools, asyncio.Event(), strategy="deterministic", mission_id=None)
    ag.mode = "passive"
    ag.leads = [{"title": "JSONP callback endpoint", "family": "jsonp",
                 "target": "https://t/api?callback=cb"}]

    async def run():
        async for _ in ag._validate_candidates_impl("s"):
            pass

    asyncio.run(run())
    rec = next((r for r in ag._candidate_assurance if r.get("family") == "jsonp"), None)
    assert rec is not None, "the jsonp candidate produced no assurance record at all"
    assert rec["result"] == cp.BLOCKED, (
        "a gate-blocked validator was booked as %r, not BLOCKED: %r" % (rec["result"], rec))
    assert rec["missing_prerequisite"], "BLOCKED with no named prerequisite is not actionable: %r" % (rec,)
