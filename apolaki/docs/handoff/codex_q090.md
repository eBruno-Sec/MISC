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

### SQLi emitter slice

- All seven confirmed SQLi builders now retain a canonical, structured
  `negative_controls` artifact: baseline DBMS-signature absence, quote recovery,
  contradictory boolean predicate, benign invalid credential, baseline marker absence,
  zero-delay timing control, or valid-subquery control.
- UNION escalation now refuses to probe when its fixed marker already exists in the
  unmodified baseline. This closes a latent marker-collision false-positive path rather
  than merely adding prose to the finding.
- Fail-before-fix: `2 failed / 2 passed`; the failures were `control_status=not_recorded`
  and the absent concrete quote-control artifact.
- Targeted after fix: `15 passed / 0 failed` across the new invariant tests and the
  existing SQLi builder/structural tests. The full SQLi-related selection was
  `74 passed / 2 xfailed / 0 failed` (3407 deselected); both xfails pre-exist and concern
  the separate bimodal sampling residual.
- Reproducible in-suite semantic mutants:
  - remove `negative_controls` from `_base` output -> the exact per-builder control
    assertion raises on `error`;
  - force `union_hit(baseline)` false -> the baseline-collision test reaches the forbidden
    UNION request and raises on the exact no-probe assertion.

### Remaining runtime producers

- `backup_exposure`: direct harvests now require and retain a randomized not-found
  response; poison-null-byte findings retain the original path's 401/403 refusal. If the
  direct baseline fails, the engine records degraded state and does not confirm.
- `exposure`: both the dedicated exposure pass and content discovery retain their real
  randomized not-found observation. A failed baseline demotes any body-signature result to
  `candidate` and records the proof gap instead of emitting a confirmed false clean.
- `sensitive_exposure`: confirmed output from the production JS/source-review path is now
  typed `source-derived` before emission. Its request-control status is therefore honestly
  `not_applicable`; candidates are not relabelled. The ten historical "working credential"
  rows have no current production title emitter (`rg` finds only test fixtures), so there is
  no emitter to patch and stored rows were deliberately not backfilled.
- `xss`: confirmed structural reflection retains the harmless canary request that located
  the context before the breakout was sent.
- `access_control` / `idor`: header-trust, URL-override, matrix IDOR, created-object IDOR,
  owner-list IDOR and foreign-owner IDOR now carry the exact denial/ownership controls used
  by their production paths. BIE BOLA already carried its three browser controls.
- `vulnerable_component`: the current production caller supplies no behaviour proof and
  therefore emits a lead, not a confirmed finding. The confirmed builder path already
  requires a trigger plus trigger-absent behaviour proof and stores both in its evidence and
  `success_oracle`.
- `security_misconfig` is the documented no-negative-twin family: missing response headers
  and missing cookie attributes are direct absence propositions over the response actually
  received. Constructing a negative twin would require changing the target's configuration;
  it is not a meaningful request differential. TRACE is different and already uses the
  random-marker echo control.
- The one blank-family `Manual: exposed .git` row is operator-authored historical data, not
  a production engine emitter. `main.py` owns manual finding ingestion and is off-limits.

The attempted DOM clean-baseline patch was **not retained**. A real unmodified browser render
correctly invalidated the existing concurrency fixture because its `_confirm_proto` callback
returns the positive marker for every navigation, including the unmodified URL. Five existing
tests then failed: four non-vacuity confirmations and the early-exit budget. Fixing that fixture
requires editing `tests/test_dom_audit_concurrency.py`, which this lease does not own. The honest
follow-up is: teach the fake callback to return clean state for the exact base URL, retain the
single unmodified browser render, then attach it to CSTI/prototype-pollution/open-redirect findings.
No declaration-only artifact was substituted.

Fail-before-fix for the non-SQLi producers was `4 failed / 7 passed`: exposure,
null-byte harvest, reflected XSS and header trust all read `not_recorded`. Targeted after
the retained fixes: `87 passed / 0 failed` across the producer, access-control and source
lane tests. Additional in-suite mutants delete an exposure artifact and delete all three
source-derived markers; the exact control/proof-kind assertions kill both.

## I-9 cap ordering

### Measured census

- Pre-fix AST census over 178 top-level production modules: `821` bounded slices. The
  deliberately conservative remote-work-name heuristic found `27` raw first-N call sites.
  This is not presented as 821 execution budgets: most are byte/parser windows, evidence
  clipping, identifiers, or report previews.
- Post-fix census: `822` bounded slices, `67` with an upper expression whose name contains
  `cap|max|limit|budget`, and `20` unique raw production work-cap contracts. The syntactic
  total rose because an opaque comprehension was replaced by a named, auditable origin
  list; it does not represent more discarded work.
- The repository-wide contract scans every top-level production module, not just
  `agent.py`/`planner.py`. Every one of the 20 survivors has a named ordering reason.
  A planted `targets[:7]` in a previously invisible module is detected.
- The post-rebase I-5 ratchet caught two new silent parse fallbacks introduced by the
  ranking helpers (`optional 390 > 388`). The helpers now parse their small URL facts
  without exception fallbacks; the ratchet returned to `388` without raising a ceiling.
  All three Q-090 invariant files then passed together: `59 passed`.

### Defects closed

- `sweep_targets` still round-robins structural shapes, but now ranks target-observable
  security value before the spread. With more shapes than slots, a late
  `/admin/execute?cmd=id` no longer loses to the first three cosmetic directories.
- Planner inventory is built without an upstream first-1000 cut, then endpoints are
  ranked before `CAP_ENDPOINTS`. Query, page, REST, XML, JS, WebSocket and form budgets
  now see the full candidate set before their value cut.
- Operator roots now precede discovered subdomains for HTTP probing, fingerprinting,
  Katana, login probes, ZAP, Nuclei and SSL scanning. Alphabetical ordering can no longer
  spend a host cap entirely on discovered subdomains.
- Mass-assignment forms are ranked before `CAP_MASS_ASSIGN`; observed read paths are no
  longer cut before `mass_assign_tool.read_views` applies its semantic rank.
- Unauthenticated/authenticated crawl frontiers, browser harvest, header trust,
  candidate promotion, path-SQLi and API-root seeding now rank before truncation.
- Cloud-bucket and confirmed-IDOR lists are deduplicated and ranked before their caps.
  Encoded-cookie probing now caps distinct origins, not endpoint paths mislabeled as
  host bases.

### Proof

- Original fail-before-fix: `4 failed / 3 passed`. The exact failures were a late command
  endpoint dropped before `CAP_ENDPOINTS`, an exact object template dropped before
  `_ma_views`, a one-page crawl budget spent on a cosmetic route, and the static guard's
  raw first-N inventory.
- Additional sweep fail-before-fix: shape-only spreading selected
  `alpha/bravo/charlie` and discarded the late admin command sink.
- Final invariant file: `8 passed / 0 failed`.
- Focused regression selection: `114 passed / 2 xfailed / 0 failed`; the two xfails are
  pre-existing selection residuals.
- Semantic mutants killed by the exact intended assertions:
  - replace `_rank_endpoints` with discovery order -> late command-sink assertion failed;
  - restore the upstream 30-path break -> exact mass-assignment view assertion failed;
  - remove crawl-frontier ranking -> the exact one-page visit assertion failed;
  - restore shape-only sweep ordering -> late high-value-shape assertion failed.
- The planted-bypass detector is a positive control on the guard itself, not a declaration.

No cap number, benchmark case, label, denominator, or expected result was changed. Ranking
uses only target-observable URL/path/parameter facts and stable tie ordering.
