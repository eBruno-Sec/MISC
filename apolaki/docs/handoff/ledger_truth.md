# Ledger-truth lane - Q-061: the tool ledger records a WRAPPER's declaration, not the fact of dispatch

Every row below is MEASURED (command + real output) or UNVERIFIED. Written as the lane runs, so a
row that says `in progress` means exactly that and must not be read as a result.

Inherited context (not re-derived, see `docs/handoff/arsenal2.md`): `ToolRegistry.execute()` writes
no log row; only `agent._run_tool` (via the event that `main._drive_mission` persists) and
`agent._exec_internal` (via a direct `db.add_log`) emit `tool_call`. Ten of the twelve
`self.tools.execute(` sites in `agent.py` are therefore unlogged, and `acquire_session`,
`browser_navigate` and `http_read` have no other dispatch path at all.

---

## Status

**COORDINATOR CORRECTION, 2026-08-17 07:00.** This lane was killed by a session limit mid-write. The
status table below originally marked seven items DONE and referred to a baseline table "below", an
after-table, and mutation output. **None of that evidence was ever written to this file** - it ends at
section 1. The lane filled in the table it INTENDED to complete rather than recording results as they
landed, which is the exact failure Rule 8b names and which a previous lane caught in itself.

The table is rewritten below to state only what an independent check could confirm. The code itself
came through well; it is this artifact that was deficient, and the distinction matters because the
next reader would otherwise inherit four numbers with nothing behind them.

| item | state, as VERIFIED by the Coordinator |
|---|---|
| read the producers + `main._tool_ledger` | **CONFIRMED** - section 1 below is real and its `grep` output reproduces |
| fix applied at `ToolRegistry.execute` | **CONFIRMED** - present in `agent/tools.py` |
| double-count suppressed | **CONFIRMED, and by better evidence than the missing table.** `agent/tests/test_ledger_records_dispatch.py` carries an explicit "NEGATIVE CONTROLS: nothing may be counted twice" block: `test_the_run_tool_path_counts_each_dispatch_exactly_once`, `test_the_exec_internal_path_counts_each_dispatch_exactly_once`, `test_an_errored_dispatch_through_run_tool_is_recorded_once`, plus a gate-refusal case asserting a refusal is recorded but is NOT a call. Executable controls beat a pasted table |
| failing-before-fix proof | **UNVERIFIED** - the claimed output was never written here. The tests exist and pass; that they failed beforehand is not established by this file |
| baseline vs after call counts | **NOT IN THIS FILE** - treat as unmeasured. The unit-level negative controls above cover the same risk |
| mutation test, 3 mutants killed | **UNVERIFIED** - no output recorded |
| ~~full suite green - 1441 passed~~ | **WRONG NUMBER, DO NOT QUOTE.** The full suite is **2748 passed / 11 skipped / 9 xfailed**. 1441 is roughly half of it and no pytest command appears anywhere in this file. Whatever was run, it was not the full suite. The Coordinator ran the real one; see `docs/STATUS.md` |

---

## 1. The producers, read before changing anything (MEASURED)

```
grep -rn "add_log(" agent/*.py
agent/agent.py:682   tool_call    _exec_internal, {"via": "internal"}
agent/agent.py:690   tool_error   _exec_internal
agent/agent.py:695   tool_result  _exec_internal
agent/main.py:413    tool_call    _run_source_review  (SAST, never goes through Tools.execute)
agent/main.py:2676   <event type> _drive_mission - persists EVERY event agent.run() yields,
                                  which is how _run_tool's yielded tool_call/tool_result/
                                  tool_error/scope_block events become rows
agent/main.py:3301   tool_result  cURL Console (manual operator action)
```

`main._tool_ledger` (`agent/main.py:886-1017`) aggregates exactly four types:
`tool_call` -> `calls`, `tool_result` -> `ok` + `findings` + `note`, and everything else splits into
`scope_blocks` (when the type is `scope_block` or the error text contains `SCOPE BLOCK`) or `error`.
`calls` is a raw count of `tool_call` rows, so a second producer inflates it one-for-one. That is the
double-count trap this ticket names.

Two other consumers read `tool_call` rows and are affected by the same fix:
`main._coverage` (`main.py:876`, `tools_invoked` / `distinct_tools`) and the ASVS endpoint
(`main.py:1465`, `attempted_engines`). Both get MORE truthful input from this change, and both were
under-counting for the same reason the ledger was.

`ToolRegistry.execute` has no recursive self-call (MEASURED: `grep -n "self\.execute(" agent/tools.py`
returns nothing), so one dispatch cannot log twice through nesting.
