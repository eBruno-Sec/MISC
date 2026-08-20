# Codex Q-085 residual / Q-086 handoff

Branch: `codex/q086`

## Baseline and coordination

- The worktree was created from the requested `c5c4db5` baseline. Before edits, `main` advanced to
  `efd1e35` (the Coordinator's bare-429 provenance patch), so this branch was rebased onto that commit
  as instructed.
- The immutable `c5c4db5` archive had agent-tree SHA-1
  `5408e12f8e7f065e473d4185b13a4e59c35e436f`.
- Baseline command used an isolated archive and `--network apolaki_default`; it completed in 674.35s:

```text
3332 passed, 11 skipped, 14 xfailed, 9 warnings in 674.35s (0:11:14)
```

## Part 1 - Q-085 residual

Status: committed as `d58e41a74291ad0da55c44b7a3861fd3c731f44a`; full-suite verification pending.

### Fail-before-fix

The controls were added before production wiring. The first targeted run was red for the intended
facts: all nine owned raw transports remained and the two new chokepoints did not exist.

```text
5 failed, 24 passed, 1 xfailed in 15.73s
```

The discriminating failures were:

- `test_owned_q085_call_sites_route_every_target_send_through_the_policy`: six BIE `page.goto`, two
  `main.py` urllib sends, and one `main.py` AsyncClient were still raw.
- Both sync Playwright controls failed because `rate_limited_goto_sync` did not exist.
- Both urllib controls failed because `rate_limited_urlopen` did not exist.

The missing-helper failures alone only proved the tests were new. The owned-call-site census was the
semantic pre-fix failure: it enumerated the exact nine production bypasses.

### Changes and measured ratchet

- Added a sync Playwright chokepoint using the shared process policy. Its page route calls
  `fallback()` rather than `continue_()` so BIE's context-level mutation route still executes.
- Added a urllib chokepoint that waits before sending and observes both ordinary responses and
  `HTTPError` responses before preserving the caller's exception behaviour.
- Routed all six BIE navigations, both Natas urllib sends, and the retest AsyncClient through those
  chokepoints.
- Converted transport exemptions into exact `(module, function, call) -> reason` records and added a
  guard requiring every exemption to be non-empty and match exactly one measured call site.
- Four benchmark/control-plane rows are explicitly exempt: one-shot compose-lab health checking,
  Apolaki mission-API driving, and the two isolated OWASP benchmark adapters. They are not production
  target transports and the benchmark adapters are fixed to compose-pinned local suites.

Measured census:

```text
before                         21 calls / 12 modules
after owned production wiring 12 calls / 10 modules
after four named exemptions    8 calls / 8 modules
```

The ratchet is now `<= 8` calls and `<= 8` modules. It was not raised or weakened. The strict xfail
remains because these eight genuine target paths are outside this lease:

```text
agent.py:_probe_for_creds
auth.py:login
authz.py:run_matrix
bwapp_solvers.py:prove
codeintel.py:harvest
mutillidae_solvers.py:prove
register.py:register
replay.py:client
```

Current targeted output:

```text
121 passed, 1 xfailed in 20.27s
XFAIL test_every_target_transport_uses_the_shared_rate_policy
  Q-085 LIVE GAP: 8 ungated target calls remain across 8 modules outside this lease
```

### Semantic mutations

All three mutants failed the exact intended assertion, then were reverted:

```text
M1 replace sync Playwright route fallback() with continue_()
   FAIL test_sync_playwright_guard_falls_through_to_existing_context_routes
   observed fell_back=False (the BIE context route was shadowed)

M2 delete rate_limited_goto_sync's pre-navigation wait
   FAIL test_sync_playwright_navigation_waits_and_observes_at_the_shared_chokepoint
   observed starts=[0.0, 0.0], expected [0.0, 2.0]

M3 delete HTTPError observation before re-raise
   FAIL test_urlopen_observes_http_error_before_reraising_it
   observed starts=[0.0, 0.0], expected [0.0, 3.0]
```

No crash, import error, timeout, skip, or unrelated assertion was credited as a killed mutant.

## Part 2 - Q-086 ZAP absence guard

Status: committed as `2813ecd4076dccacfc1d4f08858d151be76a8468`; full-suite verification pending.

### Pre-fix counterexample

A synthetic `tools.py::_run_zap` contained all four expected drivers plus safety configuration, while
its sibling `other_module.py` called `zap.ascan`. The old test still passed because it read only
`tools.__file__`, so the new negative control failed semantically:

```text
FAILED test_zap_guard_rejects_a_duplicate_driver_in_a_sibling_module
Failed: DID NOT RAISE AssertionError
```

This was not an import failure: it demonstrated that the old guard explicitly credited presence in
`_run_zap` while ignoring a duplicate target driver outside that function and file.

### Replacement guard

The replacement parses every production Python module recursively (excluding test/Tier-3 code) and
finds calls to the four public target-driving ZAP APIs by attribute name. Receiver spelling is not a
filter, so `zap.ascan`, `scanner.ascan`, or a chained receiver are all in scope. A call is allowed only
when it is in `tools.py` beneath the `_run_zap` AST subtree.

Measured production inventory:

```text
tools.py:10349:_run_zap>_seed:zap.access_url
tools.py:10378:_run_zap:zap.spider
tools.py:10392:_run_zap:zap.ajax_start
tools.py:10441:_run_zap:zap.ascan
bypasses=[]
```

The guard also requires exactly one call to each driver and verifies that the sole
`configure_target_safety` call is in `_run_zap` and lexically precedes every driver.

Controls:

- A sibling `zap.ascan` makes the actual guard raise; replacing it with non-driving `zap.alerts`
  makes the same fixture pass.
- A renamed receiver `scanner.ascan` remains visible.
- The real repository has exactly four target-driver calls and zero bypasses.

Targeted output:

```text
12 passed, 3 warnings in 13.56s
```

Semantic mutations, both killed by the exact intended assertion:

```text
M4 narrow the corpus back to tools.py only
   FAIL test_zap_guard_rejects_a_duplicate_driver_in_a_sibling_module
   observed DID NOT RAISE because the sibling duplicate became invisible

M5 count only receivers literally named `zap`
   FAIL test_zap_driver_inventory_does_not_depend_on_receiver_variable_name
   observed [], expected renamed_receiver.py:3:scanner.ascan
```

No production ZAP behaviour changed; this slice repairs the guard's claim rather than the scanner.

## Part 3 - engine guard claim

Status: committed as `f55cac877d1fa3c50b92e0e4e9d96009c41b3b7d`; full-suite verification passed.

The old helper was named `_planner_names` but read only `agent.py`; it never opened `planner.py` and
used a quoted-string regex. Measured before the rename:

```text
defined engines:             90
CLAUDE_TOOLS specs:          75
agent.py quoted names:       86
agent.py exact AST literals: 86
planner.py parsed:            0
AST-reference orphans:        0
```

The file now calls this evidence what it is:

- `_agent_literal_names`, not `_planner_names`;
- static invocation-reference census, not reachability scan;
- static invocation reference, not deterministic invocability;
- orphan candidate, not proof that an engine can never execute.

Exact engine-name literals are now collected from the AST, which excludes comments while retaining
the same measured 86 references. The module docstring explicitly states that the guard does not parse
`planner.py` or trace values into `next_batch`.

Targeted output:

```text
4 passed in 2.37s
```

One stale overclaim is in an unowned file and was deliberately not changed:

```text
agent/tools.py:6675
"is dispatched rather than merely defined -- tests/test_engine_reachability.py enforces that."
```

The guard does not enforce dispatch. Coordinator should revise that comment when `tools.py` is free.

## Final verification

Status: complete.

### Combined owned controls

```text
137 passed, 1 xfailed, 3 warnings in 33.65s
```

The sole xfail is the deliberately open Q-085 residual at 8 calls / 8 modules.

### Full suite

No mission was running (`running=0`, `total=100`) before the run. The suite used an isolated
`git archive` of `f55cac877d1fa3c50b92e0e4e9d96009c41b3b7d`, mounted into a throwaway container on
`apolaki_default`. The archived agent-tree object was
`5815d69780600fa32738b25037d04bb28ce207ce`.

```text
3350 passed, 11 skipped, 14 xfailed, 9 warnings in 645.40s (0:10:45)
```

Baseline comparison over the full denominator:

```text
baseline c5c4db5: 3332 passed / 11 skipped / 14 xfailed / 0 failed
branch f55cac8:   3350 passed / 11 skipped / 14 xfailed / 0 failed
delta:            +18 passed / 0 skipped / 0 xfailed / 0 failed
```

### Queue integrity

The bare `bash` command resolved to Windows' WSL shim and could not execute because WSL has no
`/bin/bash`; that environment error was not reported as a gate result. Re-running with the installed
Git Bash executable completed normally:

```text
queue_gate: 76 headers, 51 distinct hashes cited, 5 ids with >1 header
queue_gate: OK
```

### Files changed

```text
agent/bie.py
agent/browser_engine.py
agent/main.py
agent/tests/test_rate_policy.py
agent/tests/test_zap_invocation.py
agent/tests/test_engine_reachability.py
docs/handoff/codex_q086.md
```

`zap_client.py`, `juiceshop_solvers.py`, all benchmark code/data, `tools.py`, `agent.py`, and
`planner.py` were not modified.

### Integration

Cherry-pick these commits in order from `codex/q086`:

```text
d58e41a74291ad0da55c44b7a3861fd3c731f44a  Q-085 owned target-traffic wiring and 8/8 ratchet
2813ecd4076dccacfc1d4f08858d151be76a8468  Q-086 repository-wide ZAP absence guard
f55cac877d1fa3c50b92e0e4e9d96009c41b3b7d  honest engine static-reference naming
```

Then apply the final handoff-only commit that contains this completed verification record.

Coordinator follow-ups:

1. Lease the eight residual target transports listed in Part 1; do not retire the strict xfail until
   the measured census reaches zero.
2. Correct the dispatch overclaim in `tools.py:6675` when that file is free.
3. No queue header was edited here. Q-085/Q-086 state changes remain Coordinator-owned.

No benchmark application, case, label, scoring path, denominator, or artifact was changed. Benchmark
figures were not re-run or claimed; this lane changed transport safety and structural guards, not
detection or scoring logic.
