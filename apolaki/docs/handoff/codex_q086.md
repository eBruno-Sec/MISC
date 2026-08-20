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

Status: in progress (owned files complete; semantic mutation and full-suite verification pending).

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

Status: in progress.

## Part 3 - engine guard claim

Status: in progress.

## Final verification

Status: in progress.
