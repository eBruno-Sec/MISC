# Codex Q-090 handoff

Branch: `codex/q090`

## Baselines

- Requested baseline `dfbb7f0`: `3426 passed / 11 skipped / 13 xfailed / 0 failed`
  in `782.05s`, measured from an immutable `git archive` snapshot with the required
  `apolaki_default` Docker network.
- Main advanced to `1c357c8` before edits. The untouched branch was rebased as required;
  post-rebase baseline: `3445 passed / 11 skipped / 12 xfailed / 0 failed` in
  `782.80s` from a new immutable snapshot.

## I-5 silent-failure architecture

- Coordinator census: `917 total / 562 swallowed`. Independent executable predicate at
  `1c357c8`: `917 total / 570 swallowed`. The prose predicate in the lease does not yield
  562; it yields 570 when `return None` and `return False` are counted as swallowed.
- Pre-fix partition of those 570: `105 load-bearing / 388 optional / 77 control-plane`.
  Load-bearing is 18.4%, so the stop condition (most of the swallowed set) did not fire.
- Post-fix partition: `0 load-bearing / 388 optional / 77 control-plane`. Production now
  has 918 total handlers because durable `_swallow` persistence has one guarded
  control-plane handler; that observer failure writes `_observer_error` rather than vanishing.
- The existing producer was `ToolRegistry._swallow`; its only result-surface consumer at
  baseline was `_run_web_probes`. It now writes the existing durable `tool_error` event,
  and `execute()` prepends a bounded `DEGRADED` note while preserving successful findings.
- 103 measured handlers in `tools.py`/`agent.py` now call `_swallow`. The auth and
  registration JSON fallbacks return explicit degraded notes instead of a plain no-session
  or `n/a` result after transport failure.
- Fail-before-fix: `3 failed / 3 passed`; the failures were the 105-handler guard, missing
  dispatch result degradation, and missing durable out-of-dispatch row.
- Targeted after fix: `29 passed / 1 xfailed / 0 failed` across
  `test_silent_failure_invariant.py`, `test_swallow_ledger.py`, and
  `test_permission_tiers.py`.
- Semantic mutants killed by the exact intended assertions:
  - disabled the result `DEGRADED` branch -> result-observability test failed;
  - changed the `_swallow` row from `tool_error` to `tool_result` -> both durable-ledger
    tests failed;
  - deleted one `_run_sqli` recorder -> repository guard failed on exactly
    `tools.py:_run_sqli`;
  - deleted the auth JSON-error capture -> both the explicit degraded-note test and the
    repository guard failed on exactly `auth.py:login`.

## I-4 confirmed runtime controls

Read-only query of the named `apolaki_bbh_data` volume reproduced all positive controls:

- findings: `1783`
- missions: `156`
- `tool_call` rows: `30173`
- confirmed findings: `1391`
- source-derived: `716`
- behavioural: `675`

The Coordinator's denominator is reproduced exactly when a negative control means a
non-empty `false_positive_check`, `success_oracle`, `timing`, `validation`, or `baseline`:

- recorded control: `372`
- missing control: `1019`
- source-derived missing: `716` (control is not applicable to this proof kind)
- runtime missing: `303`
- SQLi runtime missing: `83`

`database_proof` is intentionally not credited as a negative control. The two SQLi rows
carrying it prove database access, but do not rule out the benign explanation. Including
that positive-proof key would incorrectly change the result to `374 / 1017 / 301 / 81`.

## I-9 cap ordering

In progress.
