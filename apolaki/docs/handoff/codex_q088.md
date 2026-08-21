# Codex Q-088 handoff

Branch: `codex/q088`

## Baseline

- Requested baseline: `e321d36`.
- Actual `main` at worktree creation: `bd912f4cc2324e3018eff54dcbfae8b3a5fbaf78`.
- Clean worktree agent-tree SHA: `0610129e060bd47b7fb0b4da143281e5569d845a`.
- Full isolated suite at `bd912f4`: `3409 passed, 11 skipped, 13 xfailed, 0 failed` in 736.10s.
- Rebased cleanly first onto `a650065`, then onto `186f500` after main advanced during the first final
  suite. The 44/37/0 qualified accounting and 14/14 method accounting were unchanged after both.
- Final verified agent-tree SHA: `b6939085242cbc72e8174dd42df1abbb3765c4d8`.
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
- Advertised-tool measurement: 75 specs / 69 exact names in `agent.py` + `planner.py` / 6 advertised
  dispatch methods without deterministic scheduling.
- The exact six are `benchmark_lab`, `list_workflows`, `mission_intel`, `mission_state`,
  `run_external_surface`, and `run_hash_crack`.
- Decision: all six receive an explicit manual-only contract. The four operator utilities expose
  state, workflow metadata, or lab controls that deterministic code already owns or must not infer.
  External-surface expansion remains operator-selected ACTIVE work. Hash cracking remains operator
  selected because the shipped image has neither hashcat nor John.
- Runtime dependency measurement: `hashcat` absent, `john` absent; positive controls `/usr/bin/sqlmap`,
  `/usr/local/bin/ffuf`, and `/usr/bin/nmap` present.
- The contract is executable: all six traverse the real `ToolRegistry.execute` -> `_dispatch_engine`
  -> dynamic method lookup boundary in their declared order. The engine bodies are replaced to avoid
  target traffic, state reads, and optional binary execution; the dispatch boundary is not replaced.
- The ceiling was not raised. The strict xfail remains because the honest qualified count is 44, not
  37. Its stale 61-candidate reason now carries the current measured 44/37/0 accounting.

G4 semantic mutants:

1. Added scheduled `run_sqli` to the manual-only contract. The exact partition test failed with
   `advertised dispatch methods without a deterministic scheduler need an explicit verdict:
   ['run_sqli']` (`1 failed`). Restored.
2. Shifted `benchmark_lab`'s dispatcher citation from `tools.py:1428` to line 1427. The resolver test
   failed on the exact intended assertion because line 1427 is not `ToolRegistry.execute`
   (`1 failed`). Restored.

## Verification

- G2 targeted: `17 passed in 11.86s`.
- G4 targeted: `68 passed, 1 xfailed in 179.82s`.
- First post-rebase full snapshot at `54ad24c`: `3426 passed, 11 skipped, 13 xfailed, 0 failed`
  in 756.82s. Main advanced during the run, so this is evidence but not the handback run.
- Final targeted immutable snapshot: `22 passed, 1 xfailed in 16.07s`.
- Final full immutable snapshot after the last rebase: `3426 passed, 11 skipped, 13 xfailed,
  0 failed, 9 warnings in 719.15s (0:11:59)`.
- Queue gate via Git for Windows bash: `78 headers, 57 distinct hashes cited, 5 ids with >1 header`;
  `queue_gate: OK`, exit 0. The duplicate IDs were Q-019, Q-020, Q-058, Q-065, and Q-069.

## Commits

- `5e8b70b` - G2 repository scope plus falsifiable ToolRegistry-scoped identity detectors (rebased).
- `7c49e80` - G4 checked manual-only contracts for the exact six unscheduled methods (rebased).
- `99bfb86` - rebased measurement record.
- `27429d0` - preserves G3's explicit strict-xfail ticket ownership after the final rebase.

## Integration

Cherry-pick the branch commits in order or merge `codex/q088`. No queue/status files were edited. The
qualified ceiling remains 37 and its strict xfail remains deliberately active at the measured count of
44; closing that residual requires real callers or removal in the owning modules, not a baseline edit.
