"""Q-142 -- a whole-dispatch deadline, applied at the one boundary every engine crosses.

A PER-REQUEST TIMEOUT DOES NOT BOUND A SERIALIZED MULTI-REQUEST ENGINE. Measured on the operator's
Airbnb mission `4cac266c`: `run_header_trust` walked many requests against one origin, every single
one inside its own timeout, and the mission sat in recon for 2h44m46s with no progress while the API
starved behind it.

Q-110 already solved this for `_run_sqli` / `_run_nosqli` / `_run_cmdi` with `_PROBE_CALL_BUDGET_S`.
Retrofitting a fourth engine would leave the fifth open, so the bound belongs at
`ToolRegistry.execute`, which is the only place a dispatch begins.

A TIMEOUT IS DEGRADED, NEVER CLEAN. The cancelled engine reports `success=False` with an explicit
error, so the execution ledger records a broken instrument rather than a quiet zero -- the same rule
as Q-093, Q-110 and Q-112. A mission continues to the next target; one wedged engine must not end it.

The overrides exist because "slow" and "wedged" are different facts. A thorough ZAP active scan at
turtle speed is legitimately long, and giving it the default would turn a working engine into a
timeout. Each entry is a claim that the engine's honest worst case exceeds the default.
"""
from __future__ import annotations

import asyncio
import os
from typing import Any, Awaitable, Tuple

#: Whole-dispatch budget for an ordinary engine. Ten minutes is far above any engine's measured
#: honest cost and far below the 2h44m wedge this exists to stop.
DEFAULT_S: int = max(30, int(os.getenv("BBH_TOOL_DEADLINE_S", "600") or 600))

#: Engines whose honest worst case exceeds the default. Named individually so adding one is a
#: decision rather than an oversight, and so an unlisted engine cannot inherit a long budget.
OVERRIDES: dict[str, int] = {
    "run_zap": 5400,          # thorough_active + turtle is legitimately ~90 min
    "run_sqlmap": 1800,
    "run_nmap": 1800,
    "run_nmap_vuln": 2700,
    "run_nuclei": 1800,
    "run_subfinder": 900,
    "run_katana": 900,
    "run_dom_trace": 900,     # browser-backed confirmers, ~19 s each, measured
    "run_xss": 900,
    "run_bie": 1200,
}


def budget_for(tool: str, default: int | None = None) -> int:
    """Seconds this engine may spend in ONE dispatch. Env override wins, then the table."""
    # Validated rather than caught: `.isdigit()` is false for "", "-5", "3.5" and "not-a-number"
    # alike, so there is no exception to swallow. A handler here would be one more entry in the
    # silent-failure census for a case a two-token check settles.
    env = (os.getenv("BBH_TOOL_DEADLINE_%s_S" % str(tool or "").upper()) or "").strip()
    if env.isdigit() and int(env) > 0:
        return int(env)
    return OVERRIDES.get(tool, DEFAULT_S if default is None else default)


def timeout_note(tool: str, seconds: int) -> str:
    """The error a timed-out dispatch carries. One wording, so the ledger and report agree."""
    return ("DEGRADED: %s exceeded its whole-dispatch deadline of %ds and was cancelled; "
            "it tested an unknown fraction of its input and this is NOT a clean result"
            % (tool, seconds))


async def run_bounded(awaitable: Awaitable[Any], seconds: int) -> Tuple[Any, bool]:
    """Await with a deadline. Returns `(result, timed_out)`; on timeout `result` is None.

    Cancelling the inner task is the point -- an engine that will not stop must be stopped. Callers
    reset their own ContextVars in a `finally`, so cancellation here cannot leak dispatch state into
    the next engine.

    `asyncio.wait` rather than `wait_for` DELIBERATELY: `wait_for` signals the timeout by raising,
    which needs an `except` whose body returns a constant -- indistinguishable, to the AST census in
    `test_silent_failure_invariant`, from the swallowed failures this repo keeps filing tickets
    about. Here the timeout is a RETURN VALUE, so there is no handler to classify and nothing for a
    future reader to mistake for a discard. The engine's own exception still propagates through
    `.result()` exactly as it did through `wait_for`.
    """
    task = asyncio.ensure_future(awaitable)
    done, _pending = await asyncio.wait({task}, timeout=max(1, int(seconds)))
    if task in done:
        return task.result(), False
    task.cancel()
    return None, True
