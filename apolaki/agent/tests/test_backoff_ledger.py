"""Q-043 done-item 4 -- a target backoff must be VISIBLE in the tool ledger.

A silent sleep and a slow engine are the same picture, and that matters more here than it would in
most tools: every second parked on a `Retry-After` is a second in which the engine recorded nothing.
An unreported backoff is therefore a FALSE NEGATIVE that renders as a clean result -- the failure
mode this whole ticket exists to stop.

MEASURED before the fix (`docs/handoff/backoff.md` GAP-2): the policy's entire public surface was
`clear/observe/remaining/wait_async/wait_sync`, and all eleven call sites discarded the seconds the
wait methods return. Nothing recorded anything.

The consumer, `main._tool_ledger`, is owned by another lane and is NOT edited. So the backoff rides
in on the row the ledger already aggregates. Half of this file is the negative controls for that
decision, because decorating a shared field is exactly how Q-067's typed verdict could be re-broken:
`_tool_ledger` classifies a verdict by PREFIX, and a prepend in front of one would report a correct
"not present" as a broken engine.

Nothing here sleeps for real; the clock and the sleeper are injected.
"""
from __future__ import annotations

import asyncio
import os
import tempfile

import browser_engine as browser
import db as dbmod
import main as mainmod
import scope as scope_mod
import tools as tools_mod

URL = "http://juice-shop:3000/rest/products"


def _fresh(mid: str) -> None:
    dbmod.init(os.path.join(tempfile.mkdtemp(), "q043.db"))
    dbmod.create_mission(mid, "Q-043", "active", "o", {"in_scope": ["juice-shop:3000"]}, {})


def _registry(**leaves):
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["juice-shop:3000"], [], "q043")
    reg = tools_mod.ToolRegistry(eng, mission_id="q043")
    for name, fn in leaves.items():
        setattr(reg, "_" + name, fn)
    return reg


def _policy(seconds="4"):
    """A policy already holding a cooldown, with an injected clock and sleeper."""
    clock = [0.0]

    async def sleep(delay):
        clock[0] += delay

    p = browser.TargetRatePolicy(max_wait=30, clock=lambda: clock[0], async_sleep=sleep)
    p.observe(URL, 429, {"retry-after": seconds})
    return p


def _waiting_leaf(tool, policy, output="ok"):
    """A leaf that does what a real engine's transport does: cross the rate gate, then answer."""
    async def leaf(_inp):
        await policy.wait_async(URL)
        return tools_mod.ToolResult(tool, URL, True, output, [], None)
    return leaf


def _rows(session_id, kind):
    return [l for l in dbmod.get_logs(session_id, limit=4000) if l.get("type") == kind]


def _ledger_row(session_id, tool):
    return next(r for r in mainmod._tool_ledger(session_id)["tools"] if r["tool"] == tool)


# ------------------------------------------------------------------ the wait reaches the operator

def test_a_dispatch_that_waited_says_so_in_the_rendered_ledger():
    _fresh("q043")
    reg = _registry(run_recon=_waiting_leaf("run_recon", _policy("4")))

    asyncio.run(reg.execute("run_recon", {"url": URL}, "q043"))

    row = _ledger_row("q043", "run_recon")
    assert row["status"] == "executed", "a backoff must not be reported as a broken engine"
    assert row["note"].startswith("[backoff 4.0s x1]"), row["note"]


def test_the_backoff_survives_the_ledgers_note_cut():
    """`_tool_ledger` cuts the note at 140 characters. Appending would put the backoff off the end
    of any real engine's output, which is a report nobody can read."""
    _fresh("q043")
    reg = _registry(run_recon=_waiting_leaf("run_recon", _policy("4"), output="x" * 400))

    asyncio.run(reg.execute("run_recon", {"url": URL}, "q043"))

    assert "[backoff 4.0s x1]" in _ledger_row("q043", "run_recon")["note"][:140]


def test_a_typed_backoff_row_is_written_for_the_producer_patch():
    _fresh("q043")
    reg = _registry(run_recon=_waiting_leaf("run_recon", _policy("4")))

    asyncio.run(reg.execute("run_recon", {"url": URL}, "q043"))

    rows = _rows("q043", "tool_backoff")
    assert len(rows) == 1
    assert rows[0]["tool"] == "run_recon"
    assert rows[0]["seconds"] == 4.0 and rows[0]["waits"] == 1
    assert rows[0]["origins"] == ["http://juice-shop:3000"]


def test_the_typed_row_does_not_disturb_the_rendered_ledger():
    """`_tool_ledger` ignores unknown event types. Pinned, because the typed row is inert only for
    as long as that stays true, and it is written on every backoff from now."""
    _fresh("q043")
    reg = _registry(run_recon=_waiting_leaf("run_recon", _policy("4")))

    asyncio.run(reg.execute("run_recon", {"url": URL}, "q043"))

    row = _ledger_row("q043", "run_recon")
    assert row["calls"] == 1, "the typed backoff row was counted as a dispatch"
    assert row["errors"] == 0, "a backoff was counted as a failure"


# ------------------------------------------------------------------------------ negative controls

def test_a_dispatch_that_met_no_rate_limiting_logs_what_it_always_did():
    """THE COMPATIBILITY GUARANTEE. Zero backoff must be byte-for-byte the old behaviour, or every
    existing ledger assertion in this suite is now measuring something else."""
    _fresh("q043")

    async def leaf(_inp):
        return tools_mod.ToolResult("run_recon", URL, True, "ok", [], None)

    reg = _registry(run_recon=leaf)
    asyncio.run(reg.execute("run_recon", {"url": URL}, "q043"))

    assert _rows("q043", "tool_backoff") == []
    assert _rows("q043", "tool_result")[0]["output"] == "ok"
    assert _ledger_row("q043", "run_recon")["note"] == "ok"


def test_a_q067_negative_verdict_is_never_decorated():
    """THE REGRESSION THIS COULD CAUSE. `_tool_ledger` splits a verdict from a fault by PREFIX;
    prepending to one would report a correct "not present" as a broken engine -- precisely the bug
    Q-067 landed to fix."""
    _fresh("q043")
    reg = _registry()
    verdict = tools_mod.NEGATIVE_RESULT_TOKEN + " no OpenAPI spec at this path"
    res = tools_mod.ToolResult("fetch_openapi", URL, False, "", [], verdict)

    reg._ledger_outcome("q043", "fetch_openapi", res,
                        rate_wait={"waits": 1, "seconds": 4.0, "truncated": 0, "origins": [URL]})

    logged = _rows("q043", "tool_error")[0]["error"]
    assert logged.startswith(tools_mod.NEGATIVE_RESULT_TOKEN), logged
    assert _ledger_row("q043", "fetch_openapi")["status"] != "failed"


def test_a_scope_block_is_never_decorated():
    _fresh("q043")
    reg = _registry()
    res = tools_mod.ToolResult("run_recon", URL, False, "", [], "SCOPE BLOCK: out of scope")

    reg._ledger_outcome("q043", "run_recon", res,
                        rate_wait={"waits": 1, "seconds": 4.0, "truncated": 0, "origins": [URL]})

    assert _rows("q043", "scope_block")[0]["error"] == "SCOPE BLOCK: out of scope"
    assert _rows("q043", "tool_error") == []


def test_a_plain_fault_IS_decorated():
    """The positive control for the two tests above. If nothing were ever decorated on the error
    path they would both pass while the feature did nothing."""
    _fresh("q043")
    reg = _registry()
    res = tools_mod.ToolResult("run_recon", URL, False, "", [], "connection reset")

    reg._ledger_outcome("q043", "run_recon", res,
                        rate_wait={"waits": 2, "seconds": 30.0, "truncated": 1, "origins": [URL]})

    logged = _rows("q043", "tool_error")[0]["error"]
    assert logged == "[backoff 30.0s x2, truncated at cap] connection reset"


def test_concurrent_dispatches_are_not_billed_for_each_others_cooldowns():
    """A process-wide counter read either side of a dispatch would attribute one engine's wait to
    another, because engines run concurrently. The ContextVar scope is what makes this true."""
    _fresh("q043")
    policy = _policy("4")

    async def clean_leaf(_inp):
        return tools_mod.ToolResult("run_nuclei", URL, True, "clean", [], None)

    reg = _registry(run_recon=_waiting_leaf("run_recon", policy), run_nuclei=clean_leaf)

    async def both():
        await asyncio.gather(reg.execute("run_recon", {"url": URL}, "q043"),
                             reg.execute("run_nuclei", {"url": URL}, "q043"))

    asyncio.run(both())

    assert _ledger_row("q043", "run_recon")["note"].startswith("[backoff")
    assert _ledger_row("q043", "run_nuclei")["note"] == "clean", "billed for a sibling's cooldown"
