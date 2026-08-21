# Codex Q-088 handoff

Branch: `codex/q088`

## Baseline

- Requested baseline: `e321d36`.
- Actual `main` at worktree creation: `bd912f4cc2324e3018eff54dcbfae8b3a5fbaf78`.
- Clean worktree agent-tree SHA: `0610129e060bd47b7fb0b4da143281e5569d845a`.
- Full isolated suite: in progress.
- Missions before heavy work: 0 running (1 row returned).

## G2 guard scope

### Engine reference guard

Decision: widen. The pre-change guard read engine definitions/specs from `tools.py` and exact engine
literals from `agent.py`; it was not repository-wide. The replacement enumerates production Python
modules, excludes tests and the defining `tools.py`, and counts exact executable `run_*` constants.
Comments and docstrings do not count. This remains explicitly a static invocation-reference census,
not proof of deterministic scheduling.

Negative control: a `run_planted_scope_bypass` reference was placed in a synthetic sibling
`new_scheduler.py`. A semantic mutant narrowed the path census back to `agent.py`. Exact result:
`1 failed`; the intended assertion failed because `new_scheduler.py` was absent from the census.
Restored implementation: targeted G2 result `17 passed in 11.86s`.

### Session identity guard

Decision: rename/clarify, not widen its production assertion. The guard protects the concrete
ToolRegistry identity merge in `tools.py`; `_sessions` on an unrelated class is not the same security
boundary. Its names/docstrings now state that scope, while both detectors accept an explicit source
path so their logic can be falsified outside the former hard-coded path.

Negative controls: synthetic sibling modules plant (1) a raw `self._sessions.get(role)` read and
(2) `{**self.session_headers, **caller_headers}`. Both are detected. A semantic mutant ignored the
supplied source path and read `tools.py` only. Exact result: `1 failed`; the raw-read assertion got
`[]` instead of `['leak (line 3)']`. The production implementation was restored.

## G4 unreached functions

- Qualified dead-code measurement: 44 candidates / ceiling 37 / unaccounted 0.
- Method measurement: 14 candidates / ceiling 14.
- Decision: in progress. The ceiling will not be raised and the strict xfail will remain while the
  honest qualified count exceeds 37.

## Verification

- G2 targeted: `17 passed in 11.86s`.
- G4 targeted: in progress.
- Full isolated suite after final rebase: in progress.
