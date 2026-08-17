"""Q-061 -- the tool ledger must record the FACT of dispatch, not a wrapper's account of it.

`ToolRegistry.execute()` is the one place a tool dispatch is known: every path that runs an engine
goes through it. It wrote no log row. The rows the report is built from were written by two
WRAPPERS instead -- `agent._run_tool` (whose yielded event `main._drive_mission` persists) and
`agent._exec_internal` (a direct `db.add_log`) -- so ten of the twelve `self.tools.execute(` sites in
`agent.py` produced nothing, and `acquire_session`, `browser_navigate` and `http_read`, which have
no other dispatch path at all, rendered "never dispatched" in every mission Apolaki has ever run.

PROVEN on mission 57cc3b49 (`docs/handoff/arsenal2.md`): it registered two accounts, acquired and
VERIFIED two sessions, re-crawled 13 new endpoints and confirmed 35 authz findings off those
sessions -- while reporting `acquire_session` as never dispatched. The report contradicted itself in
one document. That is the shape these tests pin.

The trap, and why half this module is negative controls: `_run_tool` and `_exec_internal` ALREADY
logged. Logging inside `execute()` as well would double every `calls` number in every report -- the
same class of defect pointing the other way. `execute()` is now the single producer of the four
ledger row types for anything it dispatches, and the wrappers stand down. The three
`*_counts_each_dispatch_once` tests exist to fail loudly if either side starts emitting again.

Nothing here touches the network: the leaf coroutine `execute()` resolves is replaced, so scope
validation, method resolution, dispatch and logging are all the real thing.
"""
from __future__ import annotations

import asyncio
import os
import tempfile

import agent as agent_mod
import db as dbmod
import main as mainmod
import scope as scope_mod
import tools as tools_mod

LOGIN = "http://juice-shop:3000/rest/user/login"


def _fresh(mid: str) -> None:
    dbmod.init(os.path.join(tempfile.mkdtemp(), "q061.db"))
    dbmod.create_mission(mid, "Q-061", "active", "o", {"in_scope": ["juice-shop:3000"]}, {})


def _registry(**leaves):
    """A REAL ToolRegistry with only the leaf engine bodies replaced.

    `execute()` resolves `getattr(self, "_" + tool_name)`, so binding an instance attribute of that
    name substitutes the engine while leaving every line of `execute()` -- scope check, resolution,
    dispatch, logging -- under test. Stubbing `execute` itself would test nothing.
    """
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["juice-shop:3000"], [], "q061")
    reg = tools_mod.ToolRegistry(eng, mission_id="q061")
    for name, fn in leaves.items():
        setattr(reg, "_" + name, fn)
    return reg


def _ok(tool: str, findings=(), output: str = "ok"):
    async def leaf(_inp):
        return tools_mod.ToolResult(tool, LOGIN, True, output, list(findings), None)
    return leaf


def _boom(tool: str, error: str):
    async def leaf(_inp):
        return tools_mod.ToolResult(tool, LOGIN, False, "", [], error)
    return leaf


def _ledger(mid: str) -> dict:
    return {t["tool"]: t for t in mainmod._tool_ledger(mid)["tools"]}


def _agent(reg, mode: str = "active"):
    ag = agent_mod.BBHAgent(reg.scope, reg, asyncio.Event(), strategy="deterministic",
                            mission_id=None, auto_approve=True)
    ag.mode = mode
    return ag


def _drive_run_tool(ag, tool: str, inp: dict, mid: str) -> None:
    """Consume `_run_tool` exactly as production does.

    The intermediate callers drop the `_content` payload (there is no model to feed) and re-yield
    the rest to `main._drive_mission`, which persists them. The persistence decision is the REAL
    one -- `main._persist_event`, the same function the mission driver calls -- not a copy of it,
    because a copy would keep passing after the product's rule changed underneath it.
    """
    async def go():
        async for ev in ag._run_tool(tool, inp, mid):
            if "_content" in ev:
                continue
            mainmod._persist_event(mid, ev)
    asyncio.run(go())


# ── THE DEFECT ───────────────────────────────────────────────────────────────
#
# These two FAIL before the fix. `acquire_session` is the realest case: it is the only engine that
# mints a persona session, all three of its call sites are direct `tools.execute` calls, and a
# mission that demonstrably authenticated still reported it as never dispatched.

def test_a_dispatch_through_execute_alone_reaches_the_ledger():
    """The whole ticket in one assertion.

    No `_run_tool`, no `_exec_internal` -- exactly the path `_do_persona_authz` takes at
    agent.py:1454 / :1915 / :2052. If the ledger is a record of dispatch, this row exists.
    """
    _fresh("q061a")
    reg = _registry(acquire_session=_ok("acquire_session", output="session acquired for user_a"))
    asyncio.run(reg.execute("acquire_session",
                            {"login_url": LOGIN, "username": "u", "password": "p", "role": "user_a"},
                            "q061a"))
    row = _ledger("q061a").get("acquire_session")
    assert row is not None, (
        "acquire_session dispatched and the ledger has no row for it -- the report will say "
        "'never dispatched' about an engine that ran, which is what mission 57cc3b49 did while "
        "holding 35 authz findings taken off the sessions it minted")
    assert row["calls"] == 1
    assert row["status"] == "executed"


def test_the_outcome_of_that_dispatch_is_recorded_too():
    """Half a fix is its own defect: a `tool_call` with no `tool_result` reads as a call that never
    returned, and `_tool_ledger` marks a tool with `calls` but no `ok` as failed/skipped. Both
    halves are asserted, on both outcomes, so a partial fix cannot pass.
    """
    _fresh("q061b")
    reg = _registry(browser_navigate=_ok("browser_navigate", output="12 SPA routes, 31 XHR"),
                    http_read=_boom("http_read", "connect timeout"))
    asyncio.run(reg.execute("browser_navigate", {"url": "http://juice-shop:3000/#/login"}, "q061b"))
    asyncio.run(reg.execute("http_read", {"url": "http://juice-shop:3000/api/x"}, "q061b"))
    led = _ledger("q061b")
    assert led["browser_navigate"]["status"] == "executed"
    assert "SPA routes" in led["browser_navigate"]["note"]
    assert led["http_read"]["status"] == "failed"
    assert "timeout" in led["http_read"]["note"]


def test_a_scope_block_inside_execute_is_a_block_not_a_failure():
    """`execute()` refuses an out-of-scope target before any engine runs. That refusal is CORRECT
    enforcement and `_tool_ledger` already distinguishes it from a crash -- but only if the row it
    writes carries the block. Pins the classification at the new producer.
    """
    _fresh("q061c")
    reg = _registry(http_read=_ok("http_read"))
    asyncio.run(reg.execute("http_read", {"url": "https://evil.example/steal"}, "q061c"))
    row = _ledger("q061c")["http_read"]
    assert row["calls"] == 1
    assert row["status"] == "skipped", "a scope block must never read as a tool failure"
    assert "SCOPE BLOCK" in row["note"] or "not in scope" in row["note"].lower()


# ── NEGATIVE CONTROLS: nothing may be counted twice ──────────────────────────
#
# A ledger that over-counts is not better than one that under-counts. Each of these drives a
# WRAPPER that already logged, and asserts the number is what it was before the fix.

def test_the_run_tool_path_counts_each_dispatch_exactly_once():
    """`_run_tool` yields a `tool_call` event that `main._drive_mission` persists. With `execute()`
    now logging too, three dispatches must still be three calls -- not six.
    """
    _fresh("q061d")
    reg = _registry(run_xss=_ok("run_xss", findings=[{"severity": "low", "title": "reflection"}],
                                output="1 XSS signal"))
    ag = _agent(reg)
    for _ in range(3):
        _drive_run_tool(ag, "run_xss", {"url": "http://juice-shop:3000/search?q=1"}, "q061d")
    row = _ledger("q061d")["run_xss"]
    assert row["calls"] == 3, "run_xss dispatched 3 times, ledger says %d" % row["calls"]
    assert row["findings"] == 3, "findings inflated: %d for 3 single-finding calls" % row["findings"]
    assert row["status"] == "executed"


def test_the_exec_internal_path_counts_each_dispatch_exactly_once():
    """`_exec_internal` wrote its own rows with `via=internal` -- the fix applied last time this
    same defect was found, one wrapper at a time. Two dispatches, two calls.
    """
    _fresh("q061e")
    reg = _registry(run_header_trust=_ok("run_header_trust", output="6 targets, 0 trusted headers"))
    ag = _agent(reg)

    async def go():
        for _ in range(2):
            await ag._exec_internal("run_header_trust", {"url": "http://juice-shop:3000/"}, "q061e")
    asyncio.run(go())
    row = _ledger("q061e")["run_header_trust"]
    assert row["calls"] == 2, "run_header_trust dispatched twice, ledger says %d" % row["calls"]
    assert row["status"] == "executed"


def test_an_errored_dispatch_through_run_tool_is_recorded_once():
    """The error row has the same double-count exposure as the call row, and an error counted twice
    would not change a status -- it would change the count silently, which is worse.
    """
    _fresh("q061f")
    reg = _registry(run_katana=_boom("run_katana", "katana: exec format error"))
    ag = _agent(reg)
    _drive_run_tool(ag, "run_katana", {"url": "http://juice-shop:3000/"}, "q061f")
    logs = dbmod.get_logs("q061f", limit=100)
    calls = [l for l in logs if l.get("type") == "tool_call" and l.get("tool") == "run_katana"]
    errs = [l for l in logs if l.get("type") == "tool_error" and l.get("tool") == "run_katana"]
    assert len(calls) == 1, "%d tool_call rows for one dispatch" % len(calls)
    assert len(errs) == 1, "%d tool_error rows for one dispatch" % len(errs)
    assert _ledger("q061f")["run_katana"]["status"] == "failed"


def test_a_gate_refusal_before_dispatch_is_still_recorded_and_is_not_a_call():
    """The events `execute()` cannot possibly own.

    `_run_tool` blocks a non-passive tool in `passive` mode BEFORE dispatch, so `execute()` never
    runs and cannot log it. That refusal must still reach the ledger (otherwise a blocked engine is
    indistinguishable from one nobody asked for), and it must NOT be counted as a call (otherwise a
    tool that never ran reports calls=1). Both halves, because suppressing wrapper rows wholesale
    is the obvious wrong way to kill the double-count.
    """
    _fresh("q061g")
    reg = _registry(run_xss=_ok("run_xss"))
    ag = _agent(reg, mode="passive")
    _drive_run_tool(ag, "run_xss", {"url": "http://juice-shop:3000/search?q=1"}, "q061g")
    logs = dbmod.get_logs("q061g", limit=100)
    assert [l for l in logs if l.get("type") == "scope_block" and l.get("tool") == "run_xss"], (
        "passive mode refused run_xss and the ledger has no record of the refusal")
    assert not [l for l in logs if l.get("type") == "tool_call" and l.get("tool") == "run_xss"], (
        "a tool blocked before dispatch was counted as a call")
    assert _ledger("q061g")["run_xss"]["status"] == "skipped"


def test_store_finding_still_gets_a_row():
    """`execute()` returns early for `store_finding` / `generate_playbook` before the scope check.
    `_run_tool` logged those calls, so logging must happen ahead of the early return or the model's
    own findings quietly leave the ledger -- a count that drops is as wrong as one that doubles.
    """
    _fresh("q061h")
    reg = _registry()
    asyncio.run(reg.execute("store_finding",
                            {"title": "t", "severity": "high", "target": LOGIN,
                             "confidence": "confirmed", "evidence": "e"}, "q061h"))
    row = _ledger("q061h").get("store_finding")
    assert row is not None and row["calls"] == 1
