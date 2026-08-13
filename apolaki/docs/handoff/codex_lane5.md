# Codex lane 5 - Q-043 target rate policy

Branch: `codex/rate-policy`

Baseline: `965381cdde7c1767498d775ebfc3a0c72bfbbbed`

## Verdict

Q-043 is closed for every target transport inside the leased files. A shared, thread-safe,
per-origin policy now honors `429` and `503` with either delta-seconds or HTTP-date
`Retry-After`, with a configurable 30-second default cap and an absolute 300-second ceiling.
Concurrent workers observe an extend-only monotonic deadline. The live negative control starts
zero requests inside the target's window at widths 1 and 6.

This is not represented as a repository-wide guarantee. A measured inventory still finds 20 raw
HTTP call sites and seven browser navigation call sites outside the lease; those are listed under
Remaining scope.

## Baseline

- Isolated worktree was clean at the required SHA.
- Mission preflight: 0 missions with status `running`.
- Required throwaway-container suite:

```text
2154 passed, 9 skipped, 4 xfailed, 9 warnings in 310.49s (0:05:10)
```

## Implementation

- `browser_engine.TargetRatePolicy` owns canonical origin keys, parsing, bounded deadlines, and
  sync/async waiting. An in-flight later response can extend an existing wait.
- `browser_engine.rate_limited_async_client` composes safety event hooks with any caller hooks, so
  redirects and reused clients cannot route around the policy.
- All 37 `AsyncClient` constructions in `tools.py` now pass one construction chokepoint: 33 use the
  automatic hooks; `_http`, `_http_send`, and the two race-client alternatives use explicit gates.
  The explicit timing gate is before `_http_send`'s timer, so safety backoff is never credited as
  target latency by a timing oracle.
- All seven target `page.goto` calls in `tools.py` use `rate_limited_goto`; the sole remaining direct
  call there is the deliberate startup navigation to `about:blank`.
- Real Playwright pages install one request/response guard, covering navigation and subresources.
- Browserless `/function` scripts are instrumented with per-origin request interception and response
  observation. The returned private metadata is consumed and removed before callers see the result.
- `screenshot()` now uses that observable `/function` path instead of browserless `/screenshot`,
  whose PNG-only response made a target `429` unknowable. A live local run returned a valid 5,320-byte
  PNG, SHA-256 `d4a164035964d4cd4d1f187fa414f78bc1cfa934f4003e1412c11d4ffaf7c2fa`.
- Proxy replay and synchronized race rounds use the same singleton policy. The existing race release
  primitive was retained; no second scheduler was added.

## Live rate-limit measurement

The exact Lane-4 loopback experiment was rerun. The server, not the client, recorded request start
times. It returned `429 Retry-After: 2` to every request.

| state | width | elapsed | requests | peak | starts inside window | honored | findings / swallowed |
|---|---:|---:|---:|---:|---:|---|---|
| before | 1 | 21.395578 s | 47 | 1 | 6 | NO | 0 / 0 |
| before | 6 | 6.458031 s | 47 | 6 | 14 | NO | 0 / 0 |
| after | 1 | 51.470420 s | 25 | 1 | 0 | YES | 0 / 0 |
| after | 6 | 14.159380 s | 25 | 6 | 0 | YES | 0 / 0 |

The after count is 25 rather than 47 because delayed browser subresources are cancelled when their
short-lived probe contexts close instead of being sent inside the cooldown. The target load fell;
the configured in-flight peaks remained 1 and 6.

- Before artifact SHA-256:
  `fa68d7a4d3245132313f7636d0d32216784b7edd5793c2b8c6c5f9a859539637`.
- Frozen after artifact SHA-256:
  `7a743190bc43a1aad79431f9a0813d82b449c17b6fc4d32b24e97cf799014011`.
- A real browserless subresource control initially reproduced a favicon request 23 ms after a
  limiting navigation, inside a 250 ms cap. With interception it began 256 ms later. On the next
  non-limiting page, navigation-to-favicon spacing was 21 ms, proving the clean path is not serialized.

## Finding-set identity

The scanner was key-blind. The full 504-case OWASP Java SQLi category was checkpointed and sealed
before offline scoring.

| state | cases | finding rows | errors | checkpoint SHA-256 |
|---|---:|---:|---:|---|
| before | 504 | 180 | 0 | `e9a642944cdaf5ca7ca2e64679eae2fd9aa6b76a6f28b70a25c6625afb553ccb` |
| after | 504 | 180 | 0 | `e9a642944cdaf5ca7ca2e64679eae2fd9aa6b76a6f28b70a25c6625afb553ccb` |

The 208,185-byte checkpoints are byte-identical. The larger scan JSON texts are also identical; the
three-byte file-hash difference is solely the earlier artifact's UTF-8 BOM. Offline networkless score:

```text
category         TP    FN    FP    TN       TPR     FPR    score
sqli            180    92     0   232    66.2%   0.0%  66.2%
OVERALL         180    92     0   232    66.2%   0.0%  66.2%
```

No finding changed over the full measured denominator.

## Clean-path cost

- The no-limit control calls neither async nor sync sleeper before or after a `200`.
- Pure policy lookup, 200,000 calls across seven repetitions: 3.469 microseconds added per call.
- Full `AsyncClient` hook path using `MockTransport`, 1,000 requests across eight alternating
  repetitions: raw median 0.119682196 s, guarded median 0.133839822 s, or 14.157626 microseconds added
  per request. There is bookkeeping cost but no target-facing wait on the common path.

## Controls

Nineteen controls now cover: real-loopback `_http` concurrency; `_http_send` `503`; both statuses in
delta and HTTP-date forms; per-origin isolation; in-flight deadline extension; absurd-header cap;
clean-path no-sleeper; Playwright navigation; Playwright subresources; no raw target `page.goto`;
no raw `AsyncClient` in `tools.py`; dynamic specialized-client hooks; browserless response feedback;
observable screenshot routing; proxy replay; and synchronized race rounds.

Fail-before-fix was `12 failed in 3.90s`. Three failures were semantic against existing code:
`_http` started its next six workers 8-18 ms after the limiting response, `_http_send` restarted after
2.4 ms, and seven target `page.goto` calls bypassed any guard. Nine failures were missing-symbol
`AttributeError`s and proved only that the tests were new; none was credited as discrimination.

## Semantic mutations

Each mutant was run against one exact node. A crash, import error, timeout, skip, or unrelated failure
was never counted.

1. Deleted `_http` wait: the real HTTP control failed because a worker started about 10 ms after the
   limiting response instead of at least 60 ms later.
2. Inverted deadline subtraction: both delta-status controls failed with no recorded sleep.
3. Deleted HTTP-date parsing: both date controls failed (`None` instead of 7 seconds).
4. Removed the wait cap: the cap control observed 86,400 seconds instead of 4.
5. Replaced per-origin storage with global storage: host B slept for host A's cooldown.
6. Restored one direct target `page.goto`: the AST guard named that exact line.
7. Replaced the shared singleton with a per-request policy: the real HTTP control sent inside the
   window.
8. Removed the automatic client request hook: the MockTransport starts changed from `[0, 2]` to
   `[0, 0]`.
9. Deleted the Playwright subrequest wait: the route continued but the expected two-second sleep was
   absent.
10. Replaced one `_target_client` with raw `httpx.AsyncClient`: the guard named line 1206.
11. Removed screenshot's `drive()` wiring: the exact screenshot control returned no image instead of
    the recorded eight-byte PNG fixture.

All were restored immediately. Final SHA-256 values are:

- `browser_engine.py`: `bebc630b874de3fcdf3e5029737611aca4a1c1f93bad173667e965baad5cbc70`
- `tools.py`: `70cb41e0dbd3b3650d518d38b04bf296001fa228958f3b49896fe040ddb2148a`
- `proxy.py`: `522b0056011c5ca9e4b79524ee659b7403e599c5e6b4e8ce720545ab97848d3f`
- `test_rate_policy.py`: `76b4b9ce496d3a896af4ce53daa0fc14b702ef286fb471776a6b728511de8a4e`

## Final verification

Targeted, frozen implementation:

```text
...................                                                      [100%]
19 passed in 3.80s
```

Full suite, required throwaway container:

```text
2173 passed, 9 skipped, 4 xfailed, 9 warnings in 277.49s (0:04:37)
```

Tier-3, shared paths mounted read-only and generated artifacts redirected to `/tmp`:

```text
Tier-3: 33/33 controls passed across 15 classes; semantic_sha256=ae9f8a1bc998f97001d5c478304d1b0197c2472ee3619328cf431baad65968ee; artifact_sha256=025d839ca638587970f94ef3788be9b36662ccee9a0bb1e9e9e474d7b80989d4
gate_artifact_sha256=bbbd4f00270553bdbd9783a7bbeb00dcf1836dc055c999be20aa84eecfe816f7
33 Tier-3 control(s) pass; no regression against a baseline of 32
```

## Remaining scope

A final measured production inventory has 25 textual `httpx` constructor/send matches. Two are the
guarded browserless sidecar calls in `browser_engine.py`, one is guarded proxy replay, and two are
test-fixture strings. The remaining 20 raw call sites are outside this lease:

- `agent.py`; `auth.py`; `authz.py`; `bwapp_solvers.py`; `cdp.py`; `codeintel.py`; `dns_recon.py`;
  `intel_connectors.py`; `mutillidae_solvers.py`; `register.py`; `replay.py`; `zap_client.py` (one each).
- `bench_all.py`; `juiceshop_solvers.py`; `main.py`; `owasp_bench.py` (two each).

Not every item is target traffic (the list includes benchmark, feed, lab-solver, and control-plane
clients), so they must be classified before migration. They are not claimed covered.

Seven non-test browser navigation sites also remain outside the lease: five synchronous Playwright
calls in `bie.py`, one browserless script in `cdp.py`, and one lab-only script in
`juiceshop_solvers.py`. The first two are production-capable and should be the next safety review.

No off-limits file, queue, roadmap, Tier-3 registry/baseline, benchmark harness, `validated_on` value,
or liveness data was modified. `race_tool.py` required no change. Integration is a single path-scoped
commit from `codex/rate-policy`; no temporary measurement artifact is committed.
