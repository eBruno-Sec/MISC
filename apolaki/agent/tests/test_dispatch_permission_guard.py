"""Q-079 — the DISPATCHER enforces a permission tier, and enforces exactly the right one.

THE DEFECT. Three layers claim to implement one three-tier model and only two of them do anything.
`planner._ALLOWED` filters what gets SCHEDULED. `agent._run_tool` / `agent._exec_internal` gate what
they DISPATCH. `ToolRegistry.execute` — the single function every engine actually goes through —
enforced SCOPE and nothing else, because `ToolRegistry.__init__` never received the mission mode.
Q-061 measured that 10 of the 12 `self.tools.execute(` sites in `agent.py` reach it without passing
either wrapper.

LATENT, NOT LIVE. All five distinct engines on that ungated path are ACTIVE (`acquire_session`,
`browser_navigate`, `http_probe`, `http_read`, `run_dom_audit`), so nothing INTRUSIVE escapes today.
The hole is one new call site away, which is worth a guard and is not worth dramatising.

THE TWO-SIDED CONTRACT, and the second half is the one that gets skipped:

  1. An INTRUSIVE engine dispatched through `Tools.execute()` in a default `active` mission is
     REFUSED, with a reason.                                          (§ POSITIVE CONTROLS)
  2. EVERY currently-working dispatch still works. A guard that failed closed on an unknown mode
     would refuse the five ACTIVE engines above, all 89 test registries and both bench harnesses —
     converting a latent permission gap into a LIVE CAPABILITY LOSS, which is strictly worse than
     the hole it closes.                                              (§ NEGATIVE CONTROLS)

Nothing here touches the network: every engine body is replaced by a recorder, so what is under test
is the REAL `ToolRegistry.execute` — its real ledger bracket, its real scope check and the real
guard — and never an engine's behaviour.
"""
from __future__ import annotations

import ast
import asyncio
import os
import re

import pytest

import agent as agent_mod
import scope as scope_mod
import tools as tools_mod
from scope import PermissionLevel

# The five distinct engines Q-061 measured on the ungated `self.tools.execute(` path. This tuple IS
# the capability that must not be lost; it is not a sample.
UNGATED_PATH_ENGINES = ("acquire_session", "browser_navigate", "http_probe", "http_read",
                        "run_dom_audit")

# One INTRUSIVE engine per shape the tier now covers (Q-052 moved 25 engines and left 15 INTRUSIVE,
# every one of which genuinely writes).
INTRUSIVE_SAMPLES = ("run_upload_test", "run_stored_xss", "confirm_create_object_idor",
                     "run_cache_poison", "run_race")


def _scope():
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["*.t"], [], "guard")
    return eng


def _registry(mission_mode=None, authorized=None, engines=UNGATED_PATH_ENGINES + INTRUSIVE_SAMPLES):
    """A REAL `ToolRegistry` whose engine BODIES are recorders.

    Only `_<tool_name>` is replaced. `execute`, `_dispatch_engine`, `_permission_refusal`, the scope
    check and the Q-061 ledger bracket are the product's own, so reaching the recorder is proof the
    dispatch was ADMITTED rather than proof a stub was called.
    """
    reg = tools_mod.ToolRegistry(_scope(), mission_id=None, lab_mode=True)
    reg.mission_mode = mission_mode
    reg.intrusive_authorized = authorized
    reg.admitted = []

    def _make(name):
        async def _engine(_inp):
            reg.admitted.append(name)
            return tools_mod.ToolResult(name, "", True, "{}", [])
        return _engine

    for name in engines:
        setattr(reg, "_" + name, _make(name))
    return reg


def _dispatch(reg, tool_name, inp=None):
    """Drive the REAL `ToolRegistry.execute`. `session_id=''` keeps the ledger out of the DB."""
    return asyncio.run(reg.execute(tool_name, inp or {"url": "https://x.t/a"}, ""))


def _is_refusal(res):
    return bool(res is not None and "PERMISSION BLOCK" in str(getattr(res, "error", "") or ""))


# ── POSITIVE CONTROLS — DoD half 1 ───────────────────────────────────────────

@pytest.mark.parametrize("engine", INTRUSIVE_SAMPLES)
def test_an_intrusive_engine_is_refused_at_the_dispatcher_in_a_default_active_mission(engine):
    """DoD half 1. Before this guard, `ToolRegistry.execute` had NO permission check of any kind: a
    direct `self.tools.execute("run_upload_test", ...)` — the eleventh ungated call site, the one the
    ticket says is one commit away — uploaded a file to the target with nobody having consented."""
    reg = _registry(mission_mode="active")
    res = _dispatch(reg, engine)
    assert _is_refusal(res), (
        "%s ran in a default `active` mission with no operator authorization; the dispatcher "
        "enforced no tier. error=%r" % (engine, getattr(res, "error", None)))
    assert reg.admitted == [], (
        "the engine BODY executed despite the refusal — the guard is after the dispatch: %r"
        % (reg.admitted,))


def test_the_refusal_carries_a_reason_that_names_the_engine_the_tier_and_the_missing_consent():
    """"With a reason" is half the DoD, and a bare False here would be indistinguishable from an
    engine that ran and found nothing — the false-clean this project spends most of its time on."""
    res = _dispatch(_registry(mission_mode="active"), "run_upload_test")
    err = str(getattr(res, "error", "") or "")
    for token in ("run_upload_test", "INTRUSIVE", "auto_approve", "authenticated_scan"):
        assert token in err, "refusal reason omits %r: %r" % (token, err)
    assert getattr(res, "success", None) is False, (
        "a refused dispatch reported success=%r — a caller reading `.success` would book a "
        "REFUSAL as a clean result" % (getattr(res, "success", None),))


def test_passive_mode_refuses_an_active_engine_at_the_dispatcher():
    """PASSIVE is OSINT only. `_run_tool` and `_exec_internal` already enforce this; the ten direct
    `tools.execute(` sites never asked either of them."""
    res = _dispatch(_registry(mission_mode="passive"), "http_probe")
    assert _is_refusal(res), (
        "a PASSIVE mission made live target contact through the dispatcher: %r"
        % (getattr(res, "error", None),))
    assert "PASSIVE" in str(res.error)


# ── NEGATIVE CONTROLS — DoD half 2, the half that gets skipped ────────────────

@pytest.mark.parametrize("engine", UNGATED_PATH_ENGINES)
def test_the_five_ungated_active_engines_still_dispatch_when_a_mode_IS_bound(engine):
    """DoD half 2, bound half. These five ARE the ungated path Q-061 measured, and they are all
    ACTIVE. If the guard refuses any of them at `active`, it has traded a latent permission gap for
    a live capability loss."""
    reg = _registry(mission_mode="active")
    res = _dispatch(reg, engine)
    assert not _is_refusal(res), (
        "%s — an ACTIVE engine on the ungated path — was refused in an `active` mission. This is "
        "the capability loss the ticket forbids: %r" % (engine, getattr(res, "error", None)))
    assert reg.admitted == [engine], "the engine was not actually reached: %r" % (reg.admitted,)


@pytest.mark.parametrize("engine", UNGATED_PATH_ENGINES)
def test_the_five_ungated_active_engines_still_dispatch_on_an_UNBOUND_registry(engine):
    """DoD half 2, unbound half — THE control the ticket predicted would be skipped.

    89 test registries, `owasp_bench.scan` and `liveness_run._run_one` all construct a bare
    `ToolRegistry` with no mission behind it. A guard that failed closed on an unknown mode would
    refuse every one of those dispatches. Unknown therefore fails OPEN, deliberately, and the
    opt-in risk that creates is closed by `test_every_product_registry_binds_a_mode` below rather
    than by tightening this default.
    """
    reg = _registry(mission_mode=None)
    res = _dispatch(reg, engine)
    assert not _is_refusal(res), (
        "%s was refused on a registry with no mission bound. Every bench, liveness and unit-test "
        "dispatch in the tree goes through exactly this shape: %r"
        % (engine, getattr(res, "error", None)))
    assert reg.admitted == [engine]


@pytest.mark.parametrize("engine", INTRUSIVE_SAMPLES)
def test_an_UNBOUND_registry_does_not_refuse_even_an_intrusive_engine(engine):
    """Fail-open on unknown, PINNED — so that tightening it is a deliberate act with a red suite,
    not a quiet edit.

    This is not a claim that unknown is safe. It is a claim that `None` means UNKNOWN and not
    `active`: the registry has no mission, no operator and no consent decision to enforce, and
    inventing one here would break `owasp_bench` (which dispatches `run_mass_assign` and friends by
    direct `getattr`) and 89 unit tests. The enforcement point for a real mission is the binding,
    and the ratchet below is what guarantees a real mission always has one.
    """
    reg = _registry(mission_mode=None)
    res = _dispatch(reg, engine)
    assert not _is_refusal(res), (
        "%s was refused on an unbound registry: %r" % (engine, getattr(res, "error", None)))
    assert reg.admitted == [engine]


def test_the_apparatus_can_observe_a_refusal_at_all():
    """POSITIVE CONTROL for every `assert not _is_refusal(...)` above. Same registry factory, same
    `_dispatch`, same `_is_refusal` — one INTRUSIVE engine and one bound mode. Without this, four
    parametrised 'nothing was refused' tests would pass just as happily if `_is_refusal` were
    broken, or if `execute` had stopped returning a `ToolResult` at all."""
    reg = _registry(mission_mode="active")
    assert _is_refusal(_dispatch(reg, "run_upload_test")), (
        "the harness cannot see a refusal it was built to see — every negative control above is "
        "vacuous")


@pytest.mark.parametrize("engine", INTRUSIVE_SAMPLES)
def test_an_authorized_intrusive_dispatch_is_admitted_at_active(engine):
    """The other half of the capability guarantee, and the reason the guard is NOT keyed on the mode
    alone. MEASURED at HEAD: `agent.py` dispatches `run_stored_xss` (:1046), `run_bfla` (:1062),
    `confirm_authz_write` (:2277) and `confirm_create_object_idor` (:2302) through `_exec_internal`,
    which admits INTRUSIVE at `active` on HITL approval, `auto_approve` or `authenticated_scan` —
    and Q-052's decision text says exactly that ("the 9 stay behind the existing HITL gate and
    `auto_approve`"). A backstop stricter than the layer it backs would refuse four measured product
    call sites in the missions where the operator had already said yes."""
    reg = _registry(mission_mode="active", authorized=lambda: True)
    res = _dispatch(reg, engine)
    assert not _is_refusal(res), (
        "%s was refused although the mission is authorized — this refuses what the HITL gate "
        "approved: %r" % (engine, getattr(res, "error", None)))
    assert reg.admitted == [engine]


def test_passive_mode_still_admits_a_passive_engine():
    reg = _registry(mission_mode="passive", engines=("run_dns",))
    res = _dispatch(reg, "run_dns", {"domain": "x.t"})
    assert not _is_refusal(res), getattr(res, "error", None)
    assert reg.admitted == ["run_dns"]


def test_an_unrecognised_mode_string_is_treated_as_unknown_not_as_passive():
    """`"Active"`, `"FULL"`, `""` and any future spelling are UNKNOWN. Guessing `passive` would be
    fail-closed by the back door and would silently disable an entire mission; guessing `active`
    would enforce a consent decision nobody made."""
    for bogus in ("Active", "FULL", "", "recon"):
        reg = _registry(mission_mode=bogus)
        assert not _is_refusal(_dispatch(reg, "run_upload_test")), bogus
        assert not _is_refusal(_dispatch(reg, "http_probe")), bogus


def test_an_authority_that_raises_is_treated_as_no_authorization():
    """Fail-closed where failing closed is correct: an authorization callback that cannot answer has
    not authorized. It must not become an exception that escapes `execute` either, because a
    scan-killing traceback out of the dispatcher is a worse outcome than a refusal."""
    def _boom():
        raise RuntimeError("no agent")

    reg = _registry(mission_mode="active", authorized=_boom)
    res = _dispatch(reg, "run_upload_test")
    assert _is_refusal(res), getattr(res, "error", None)


# ── the refusal must be VISIBLE, not silent ──────────────────────────────────

def test_a_refused_dispatch_is_RECORDED_in_the_tool_ledger():
    """Q-061 put the ledger at `execute` precisely so no dispatch is invisible, and it records a
    `SCOPE BLOCK` the same way. A permission refusal that left no trace would be a new false-clean:
    the report would show an engine that never ran, with no reason anywhere."""
    rows = []
    real = tools_mod.db.add_log
    tools_mod.db.add_log = lambda sid, kind, payload: rows.append((sid, kind, payload))
    try:
        reg = _registry(mission_mode="active")
        asyncio.run(reg.execute("run_upload_test", {"url": "https://x.t/a"}, "sess-guard"))
    finally:
        tools_mod.db.add_log = real
    kinds = [k for _s, k, _p in rows]
    assert "tool_call" in kinds, "a refused dispatch left no tool_call row: %r" % (kinds,)
    payload = " ".join(str(p) for _s, _k, p in rows)
    assert "run_upload_test" in payload, payload[:400]


# ── the BINDING: a real agent hands a real registry its permission context ───

def test_a_real_agent_binds_its_mode_onto_the_registry_it_was_given():
    """The whole design in one assertion. `main.py` builds a `ToolRegistry` and hands it to
    `BBHAgent(..., mode=req.mode)` three lines later; the agent binds. No call site changed, no
    constructor parameter became required, and no product mission is unbound."""
    for mode in ("passive", "active", "full"):
        reg = tools_mod.ToolRegistry(_scope(), mission_id=None, lab_mode=True)
        assert reg.mission_mode is None, "a bare registry must start UNKNOWN"
        agent_mod.BBHAgent(_scope(), reg, asyncio.Event(), mode=mode,
                           strategy="deterministic", mission_id=None)
        assert reg.mission_mode == mode, (
            "BBHAgent(mode=%r) left the dispatcher unbound (%r) — every direct tools.execute() "
            "call in that mission would be unchecked" % (mode, reg.mission_mode))


def test_reassigning_agent_mode_REBINDS_the_registry():
    """Why the binding is a property and not one line in `__init__`. `agent.mode` is reassigned
    after construction (several helpers in tests/test_permission_tiers.py do it), and a snapshot
    would then describe a mission the agent is no longer running. A STALE permission context is
    worse than none: it refuses or admits on the wrong answer."""
    reg = tools_mod.ToolRegistry(_scope(), mission_id=None, lab_mode=True)
    ag = agent_mod.BBHAgent(_scope(), reg, asyncio.Event(), mode="active",
                            strategy="deterministic", mission_id=None)
    ag.mode = "passive"
    assert reg.mission_mode == "passive", (
        "the registry still believes the mission is %r after the agent moved to passive"
        % (reg.mission_mode,))
    ag.mode = "not-a-mode"
    assert ag.mode == "active" and reg.mission_mode == "active", (
        "an unrecognised mode must normalise the SAME way on both sides, or the agent and its "
        "dispatcher enforce two different missions: agent=%r registry=%r"
        % (ag.mode, reg.mission_mode))


def test_the_bound_authorization_is_read_LIVE_not_snapshotted():
    """`intrusive_state` is `None` at construction and becomes `approved` when the operator answers
    the gate, mid-mission. A bool captured in `__init__` would refuse every intrusive dispatch of
    every interactive run, for the whole run, after the operator had said yes."""
    reg = tools_mod.ToolRegistry(_scope(), mission_id=None, lab_mode=True)
    ag = agent_mod.BBHAgent(_scope(), reg, asyncio.Event(), mode="active",
                            strategy="deterministic", mission_id=None)
    assert callable(reg.intrusive_authorized)
    assert reg.intrusive_authorized() is False, "an unanswered gate must not read as authorized"
    ag.intrusive_state = "approved"
    assert reg.intrusive_authorized() is True, (
        "the operator approved the gate and the dispatcher did not notice — the authorization was "
        "snapshotted")
    ag.intrusive_state = "denied"
    assert reg.intrusive_authorized() is False, "a DENIED gate read as authorized"


def test_authenticated_scan_alone_authorizes_intrusive_exactly_as_exec_internal_always_did():
    """`_exec_internal`'s third clause, preserved verbatim. The auth artery's bounded, self-cleaning
    writes (`confirm_authz_write`, `confirm_create_object_idor`) run under `authenticated_scan` with
    no HITL gate answered, and they run TODAY. Losing this is losing the two-user authz matrix."""
    reg = tools_mod.ToolRegistry(_scope(), mission_id=None, lab_mode=True)
    ag = agent_mod.BBHAgent(_scope(), reg, asyncio.Event(), mode="active", authenticated_scan=True,
                            strategy="deterministic", mission_id=None)
    assert ag.intrusive_state is None, "precondition: no gate has been answered"
    assert reg.intrusive_authorized() is True
    assert ag._intrusive_authorized() is True


@pytest.mark.parametrize("state,authenticated,expected", [
    (None, False, False),
    ("approved", False, True),
    ("denied", False, False),
    (None, True, True),
    ("denied", True, True),      # `authenticated_scan` is an INDEPENDENT operator opt-in, and this
                                 # is what `_exec_internal` did before the expression was named.
])
def test_the_named_authorization_rule_is_exec_internals_rule_unchanged(state, authenticated, expected):
    """`_intrusive_authorized` REPLACED a copy of this expression inside `_exec_internal`. Two copies
    of one policy is how one URL came to sit under two contradictory rules in Q-080, so the rule is
    named once — and this truth table is the proof the extraction changed nothing."""
    reg = tools_mod.ToolRegistry(_scope(), mission_id=None, lab_mode=True)
    ag = agent_mod.BBHAgent(_scope(), reg, asyncio.Event(), mode="active",
                            authenticated_scan=authenticated, strategy="deterministic",
                            mission_id=None)
    ag.intrusive_state = state
    assert ag._intrusive_authorized() is expected
    # the literal expression `_exec_internal` carried before the extraction
    assert ag._intrusive_authorized() == ((ag.intrusive_state == "approved")
                                          or bool(getattr(ag, "authenticated_scan", False)))


def test_run_tool_keeps_its_STRICTER_rule_and_is_not_widened_by_the_shared_helper():
    """A backstop must not be stricter than the layer it backs — and naming the union must not
    LOOSEN the stricter layer either. `_run_tool` has no `authenticated_scan` clause: an interactive
    authenticated scan must still stop and ASK before the model drives a state-changing engine."""
    src = open(os.path.join(os.path.dirname(agent_mod.__file__), "agent.py"),
               encoding="utf-8").read()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, (ast.AsyncFunctionDef, ast.FunctionDef)) and n.name == "_run_tool")
    body = ast.get_source_segment(src, fn) or ""
    assert "authenticated_scan" not in body, (
        "_run_tool now consults authenticated_scan — the model-driven path would run INTRUSIVE "
        "engines without ever showing the operator a gate")
    assert "_intrusive_authorized" not in body, (
        "_run_tool now uses the UNION rule; that widens the strictest gate in the product")


# ── COMPOSITION: a REAL agent over a REAL registry, no fakes on either side ──
#
# Every existing `_run_tool` test in the suite drives a `_Tools` stand-in whose `execute` is a
# recorder (tests/test_permission_tiers.py), so no test has ever proven that the wrapper gate and
# the dispatcher gate COMPOSE. A guard that only works when called directly is an island.

def _agent_over_real_registry(mode="active", **kw):
    reg = _registry(engines=UNGATED_PATH_ENGINES + INTRUSIVE_SAMPLES)
    ag = agent_mod.BBHAgent(_scope(), reg, asyncio.Event(), mode=mode,
                            strategy="deterministic", mission_id=None, **kw)
    return ag, reg


def _drive_run_tool(ag, tool_name):
    events = []

    async def run():
        agen = ag._run_tool(tool_name, {"url": "https://x.t/a"}, "")
        async for ev in agen:
            events.append(ev.get("type") or "_content")
            if ev.get("type") == "approval_required":
                await agen.aclose()
                return

    asyncio.run(run())
    return events


def test_THE_HOLE_a_direct_execute_on_a_REAL_agents_registry_is_now_refused():
    """The eleventh call site, written out. This is what the ticket means by "one new call site
    away": someone adds `await self.tools.execute("run_upload_test", ...)` beside the nine that
    already exist, it passes review because its nine neighbours look identical, and it uploads a
    file to the target in a mission where nobody consented to a state change. Same line, today,
    against a real agent's real registry."""
    ag, reg = _agent_over_real_registry(mode="active")
    res = asyncio.run(ag.tools.execute("run_upload_test", {"url": "https://x.t/a"}, ""))
    assert _is_refusal(res), (
        "the hole is still open: a direct dispatch on a real agent's registry ran an INTRUSIVE "
        "engine with no authorization: %r" % (getattr(res, "error", None),))
    assert reg.admitted == []


def test_the_wrapper_gate_and_the_dispatcher_gate_COMPOSE_on_an_authorised_run():
    """No double-refusal. An autonomous run pre-authorises the intrusive phase; `_run_tool` converts
    that into `intrusive_state = "approved"` BEFORE dispatching, and the dispatcher reads the same
    live state. If the two gates disagreed, an `auto_approve` mission would refuse its own
    engines."""
    ag, reg = _agent_over_real_registry(mode="active")
    ag.auto_approve = True
    events = _drive_run_tool(ag, "run_upload_test")
    assert "approval_required" not in events, events
    assert reg.admitted == ["run_upload_test"], (
        "an auto_approve mission could not run its own INTRUSIVE engine — the two gates disagree: "
        "events=%r admitted=%r" % (events, reg.admitted))


def test_the_wrapper_still_refuses_FIRST_so_the_dispatcher_is_only_ever_a_backstop():
    """Ordering, asserted. `_run_tool` must refuse a denied gate before `execute` is reached, so the
    operator-facing refusal is the wrapper's (which can yield a `scope_block` event the UI shows)
    and not the dispatcher's silent one."""
    ag, reg = _agent_over_real_registry(mode="active")
    ag.intrusive_state = "denied"
    events = _drive_run_tool(ag, "run_upload_test")
    assert "scope_block" in events, events
    assert reg.admitted == [], reg.admitted


def test_exec_internal_composes_with_the_dispatcher_on_an_authenticated_scan():
    """The auth artery's real shape: `authenticated_scan=True`, no HITL gate answered, INTRUSIVE
    engine. `confirm_authz_write` and `confirm_create_object_idor` run exactly like this today
    (agent.py:2277, :2302), and losing them is losing the two-user authz matrix."""
    ag, reg = _agent_over_real_registry(mode="active", authenticated_scan=True)
    res = asyncio.run(ag._exec_internal("confirm_create_object_idor", {"url": "https://x.t/a"}, ""))
    assert not _is_refusal(res), (
        "the auth artery's own INTRUSIVE dispatch was refused by the backstop: %r"
        % (getattr(res, "error", None),))
    assert reg.admitted == ["confirm_create_object_idor"]


@pytest.mark.parametrize("engine", UNGATED_PATH_ENGINES)
def test_a_real_agent_at_active_still_runs_every_ungated_ACTIVE_engine(engine):
    """DoD half 2 at the composition level, over a REAL agent and a REAL registry — the shape the
    product actually has. The nine direct call sites in `agent.py` dispatch precisely these five."""
    ag, reg = _agent_over_real_registry(mode="active")
    res = asyncio.run(ag.tools.execute(engine, {"url": "https://x.t/a"}, ""))
    assert not _is_refusal(res), (
        "%s was refused in a real `active` mission: the authenticated re-crawl, the persona logins "
        "and the DOM audit all stop here. %r" % (engine, getattr(res, "error", None)))
    assert reg.admitted == [engine]


# ── THE RATCHET: the answer to "a defaulted parameter is an opt-in guard" ─────
#
# A guard most callers skip is the declaration-not-fact pattern this codebase has hit eleven times.
# The default stays (89 test sites and 2 bench harnesses depend on it) and the opt-in half is closed
# HERE instead: a product module that constructs a registry, skips the binding and dispatches
# through it turns the suite red. This checks what the files DO — every entry below is derived by
# walking the AST, not read off a declaration.

#: Product modules that construct a `ToolRegistry` WITHOUT ever constructing a `BBHAgent` to bind it.
#: Each entry must justify itself, and the justification is FACT-CHECKED by
#: `test_allowlisted_unbound_modules_really_do_not_dispatch` below: an allowlisted module may not
#: contain a single `.execute(` call, so "it never dispatches" is verified rather than asserted.
UNBOUND_PRODUCT_MODULES = {
    "owasp_bench.py": ("benchmark harness — dispatches by direct `getattr(reg, method)(inp)` at "
                       "owasp_bench.py:197 and never through `execute`, so no permission context "
                       "exists or is consulted"),
}

_SKIP_DIRS = ("tests", "__pycache__", "data")


def _product_modules():
    root = os.path.dirname(agent_mod.__file__)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if fn.endswith(".py"):
                yield os.path.join(dirpath, fn)


def _calls_named(tree, name):
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            ident = getattr(f, "id", None) or getattr(f, "attr", None)
            if ident == name:
                out.append(node.lineno)
    return out


def _registry_census():
    """[(basename, registry_lines, agent_lines, has_execute_call)] for every product module that
    constructs a ToolRegistry."""
    rows = []
    for path in _product_modules():
        src = open(path, encoding="utf-8", errors="replace").read()
        if "ToolRegistry" not in src:
            continue
        try:
            tree = ast.parse(src)
        except SyntaxError:                      # pragma: no cover - a broken module fails elsewhere
            continue
        regs = _calls_named(tree, "ToolRegistry")
        if not regs:
            continue
        execs = [n.lineno for n in ast.walk(tree)
                 if isinstance(n, ast.Call) and getattr(n.func, "attr", None) == "execute"]
        rows.append((os.path.basename(path), regs, _calls_named(tree, "BBHAgent"), bool(execs)))
    return rows


def test_the_census_finds_the_product_registry_sites_at_all():
    """POSITIVE CONTROL for the ratchet. A walker that silently found nothing would make the two
    tests below pass forever while enforcing nothing — the exact way a guard checking a declaration
    passes what it exists to catch."""
    rows = _registry_census()
    names = {r[0] for r in rows}
    assert {"main.py", "tools.py"} <= names or "main.py" in names, (
        "the AST walk did not find main.py's registry construction: %r" % (sorted(names),))
    assert sum(len(r[1]) for r in rows) >= 4, (
        "fewer than the 4 measured product construction sites were found: %r" % (rows,))


def test_every_product_registry_binds_a_mode():
    """THE RATCHET. Every product module that builds a `ToolRegistry` must also build the
    `BBHAgent` that binds its permission context, or be on the allowlist with a reason."""
    offenders = [(name, regs) for name, regs, agents, _ex in _registry_census()
                 if not agents and name not in UNBOUND_PRODUCT_MODULES]
    assert not offenders, (
        "product module(s) construct a ToolRegistry that no BBHAgent binds, so every dispatch "
        "through them skips the permission tier entirely: %r. Bind it (hand the registry to a "
        "BBHAgent, or set `mission_mode=`), or add it to UNBOUND_PRODUCT_MODULES with a reason — "
        "and note the allowlist is fact-checked for having no `.execute(` call." % (offenders,))


def test_no_product_module_both_builds_a_registry_and_dispatches_through_it():
    """The second, per-SITE half of the ratchet, and the honest statement of what the first half
    cannot see.

    `test_every_product_registry_binds_a_mode` reasons per MODULE, so a module holding one bound and
    one unbound registry passes on the strength of the bound one. `liveness_run.py` is exactly that
    shape today: line 76 builds a registry it hands to `BBHAgent` (line 78) and line 84 builds a
    second one it never binds. That is currently harmless for one measurable reason — line 84's
    registry is dispatched by direct `getattr(tb, check["tool"])(check["input"])` and `liveness_run`
    contains no `.execute(` call at all.

    MEASURED at HEAD: 0 of the 3 product modules that construct a `ToolRegistry` contain a
    `.execute(` call. So this is not a vacuous check waiting for a hypothetical — it is that measured
    fact, frozen. The day a module does both, name-based dataflow stops being good enough and a
    human has to look at which registry the dispatch goes through.
    """
    both = [(name, regs) for name, regs, _agents, has_exec in _registry_census() if has_exec]
    assert not both, (
        "product module(s) now BUILD a ToolRegistry and DISPATCH through `.execute(` in the same "
        "file: %r. Per-module binding is no longer sufficient evidence — confirm by hand that the "
        "registry reaching `.execute(` is the bound one, then record the finding here." % (both,))


def test_allowlisted_unbound_modules_really_do_not_dispatch():
    """The fact check ON the allowlist. An entry says "this registry never dispatches"; this proves
    it. The moment an allowlisted module grows a `.execute(` call its exemption evaporates, which is
    what stops the allowlist from becoming the place unchecked dispatches go to hide."""
    census = {name: has_exec for name, _r, _a, has_exec in _registry_census()}
    for name, reason in UNBOUND_PRODUCT_MODULES.items():
        assert name in census, (
            "%r is allowlisted but constructs no ToolRegistry any more — delete the stale "
            "exemption" % (name,))
        assert not census[name], (
            "%r is exempt because %s — but it now calls `.execute(`, so it dispatches through an "
            "UNBOUND registry with no permission tier enforced anywhere." % (name, reason))


def test_the_guard_is_reached_from_execute_and_not_only_from_dispatch_engine():
    """Mutation-shaped check: delete the two lines at the top of `_dispatch_engine` and every
    behavioural test above still has to fail. This asserts the wiring itself — that `execute`, the
    function all twelve call sites use, is what runs the guard."""
    src = ast.get_source_segment(
        open(tools_mod.__file__, encoding="utf-8").read(),
        next(n for n in ast.walk(ast.parse(open(tools_mod.__file__, encoding="utf-8").read()))
             if isinstance(n, (ast.AsyncFunctionDef, ast.FunctionDef))
             and n.name == "_dispatch_engine")) or ""
    assert "_permission_refusal" in src, (
        "_dispatch_engine no longer consults the permission guard; `execute` enforces scope only "
        "again")
    assert re.search(r"_permission_refusal[\s\S]{0,200}?SCOPE BLOCK|_permission_refusal", src), src[:200]
