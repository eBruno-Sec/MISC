# Codex lane 4 - throughput diagnosis

Branch: `codex/throughput`

Baseline: `1839c33c837c9cde874891ace0a3c5faed1fbb6c`

## Baseline

- Isolated worktree: clean.
- Mission preflight: 0 missions with status `running`.
- Full suite, required throwaway container: `2152 passed, 9 skipped, 4 xfailed, 9 warnings in 280.58s (0:04:40)`.

## Repository state found before measurement

The premise that bounded concurrency still needed to be built was stale at this baseline. The four
throughput commits named in `docs/handoff/throughput.md` all exist and are ancestors of `1839c33`:

- `a0d0926` - bounded deterministic `tools.bounded_map` and clamped `browser_concurrency()`.
- `9e7f5aa` - overlapping XSS browser settle windows.
- `91d4d16` - concurrent DOM-trace parameter renders.
- `128c8cd` - concurrent DOM-audit probes.

`agent/tests/test_bounded_concurrency.py` also deliberately distinguishes the two existing contracts:
`_run_race` is a synchronized gate-release primitive whose simultaneity is the TOCTOU signal;
`bounded_map` is a deterministic in-flight ceiling with no simultaneity guarantee. Replacing the latter
with the former would weaken the target-load and ordering guarantees. No second primitive was built.

## Reproducible instrument

`agent/tests/test_throughput_diagnosis.py` wraps the shipping Playwright objects and times browser
launch/close, context/page creation/close, navigation, fixed settle waits, network-idle waits,
evaluation, screenshots, and `ToolRegistry._http`. Its live modes are explicit and never run during
ordinary pytest collection:

```text
python tests/test_throughput_diagnosis.py --live --url URL --width 1 --width 6 --repeats 2
python tests/test_throughput_diagnosis.py --live --rate-limit-control --width 1 --width 6
python tests/test_throughput_diagnosis.py --live --mission --url URL --width 1 --width 6
```

All target traffic below was confined to local Docker labs or a loopback server inside the throwaway
container. Source was mounted read-only for every live run.

## Cost diagnosis

Target: `https://owaspbench:8443/benchmark/`; two runs per engine and width.

Transport is not the bottleneck: TCP connect was `2.673 ms` mean (`n=5`) and TLS handshake was
`3.590 ms` mean (`n=5`).

Serial width-1 breakdown (mean of two complete calls):

| engine | call mean | fixed settle | page goto | networkidle | browser launch | `_http` |
|---|---:|---:|---:|---:|---:|---:|
| `run_dom_audit` | 26.534 s | 13.491 s (50.8%) | 4.593 s (17.3%) | 4.518 s (17.0%) | 0.184 s (0.7%) | 0.141 s (0.5%) |
| `run_xss` | 10.430 s | 8.548 s (82.0%) | 1.055 s (10.1%) | 0 | 0.159 s (1.5%) | 0.028 s (0.3%) |
| `run_dom_trace` | 10.091 s | 6.649 s (65.9%) | 1.220 s (12.1%) | 0 | 0.140 s (1.4%) | 0.021 s (0.2%) |

Measured answer: fixed post-render waits plus serial navigation/network-idle dominate. Network, TLS,
browser startup, the `_http`/proxy path, and retry/backoff do not explain the 8.5-second average.
The settle windows are oracle time and must not be shortened; overlapping independent waits is the
correct optimization.

## Existing bounded implementation, independently reproduced

Same target and mode; only `BBH_BROWSER_CONCURRENCY` changed:

| engine | width 1 mean (n=2) | width 6 mean (n=2) | speedup | findings | swallowed errors |
|---|---:|---:|---:|---|---:|
| `run_dom_audit` | 26.534 s | 7.515 s | 3.531x | 0 / identical SHA | 0 |
| `run_xss` | 10.430 s | 3.066 s | 3.402x | 0 / identical SHA | 0 |
| `run_dom_trace` | 10.091 s | 4.092 s | 2.466x | 0 / identical SHA | 0 |
| three-engine bundle per URL | 47.056 s | 14.674 s | 3.207x | identical | 0 |

The clean OWASP root is a vacuous finding-set comparison, so a non-empty control was run against
`http://domsource:8080/hash`. Three runs at each width all emitted the same four confirmed findings,
the same normalized SHA `3640f9bd3c8865378eec08ad731a0170954efdf67cb0a4edd8fa4b7af5b7d3cb`,
and zero swallowed errors. Mean time fell from `13.865 s` to `6.138 s` (2.259x).

Normalization removes random-by-design browser presentation artifacts and canary nonce values, but
retains family, confidence, evidence shape, target shape, severity, oracle, and CWE. A confidence
change therefore changes the digest.

## Full deterministic mission control

Two paired missions were run against `http://domsource:8080/`, then repeated in reverse width order.
Each run executed 152 tool calls, discovered 162 URLs, emitted the same 15 leads, had the same nine
`fetch_openapi` non-JSON errors, emitted zero findings, and had zero swallowed errors.

| pair/order | width | wall | seconds/URL (162) | probe total | recon total | enum total |
|---|---:|---:|---:|---:|---:|---:|
| first | 1 | 152.524 s | 0.941507 | 22.959 s | 11.531 s | 117.700 s |
| first | 6 | 190.192 s | 1.174027 | 8.881 s | 75.410 s | 105.640 s |
| reverse | 6 | 184.012 s | 1.135874 | 9.191 s | 57.116 s | 117.424 s |
| reverse | 1 | 202.216 s | 1.248248 | 21.970 s | 74.462 s | 105.503 s |

Across both pairs, probe time is stable and materially lower: `22.465 s` width 1 versus `9.036 s`
width 6 (2.486x). Whole-wall time is not: `177.370 s` (`1.094878 s/URL`) versus `187.102 s`
(`1.154951 s/URL`), a 5.49% regression in the two-run mean that flips sign with run order.
External-tool variance dominates the small lab: the instrumented repeat spent 103.8-115.6 s in
`run_katana`, about 43.3 s in `run_subfinder`, 10.9-11.7 s in `run_wayback`, and 1.3-17.7 s in
`run_crtsh`. Those tools and the mission loop are outside this lease.

Therefore the full-mission acceptance oracle is NOT met on this fixture. The browser probe slice is
2.49x faster and deterministic, but this lane does not claim an end-to-end mission speedup. The exact
`owaspbench-q019` whole-product rerun remains the correct test because probe was 5296/5329 seconds in
that mission; running it is a roughly 1.5-hour benchmark-lane operation and was not launched here.

## Rate-limit control - failed

The lane brief says `tools.py:3296` honors `429`/`Retry-After`; that is not true at `1839c33`.
Repository search finds no target-side `Retry-After` parser. Current `tools.py:3418` merely stops the
GitHub code-search loop on `403/429`; general `_http` and Playwright navigation do not delay.

A loopback server returned `429` plus `Retry-After: 2` to every request:

| width | elapsed | requests | peak in flight | new requests inside retry window | honored |
|---|---:|---:|---:|---:|---|
| 1 | 21.705 s | 47 | 1 | 6 | **NO** |
| 6 | 6.282 s | 47 | 6 | 14 | **NO** |

The request count is unchanged and the configured concurrency ceiling holds, but that is bounded
hammering, not backoff. Fixing this once at the general HTTP/browser chokepoint would change every
engine through `tools.py`, which is an explicit stop condition for this lease. It is reported rather
than patched locally in three browser call sites.

## Artifacts

Artifacts are outside the repository under `%TEMP%\apolaki-lane4`:

| artifact | SHA-256 |
|---|---|
| `owasp-widths-1-6.json` | `6784384a31816df8d1db34ddced89ffe33bb557b4f89994716d29893193849f9` |
| `domsource-widths-1-6.json` | `d69e72c1dbd7b7b75c7e842f32723973cc34b056fd2da85c30b475cd6acdc2b0` |
| `rate-limit-widths-1-6.json` | `3579bf8e67d76be5713127c154118e43ac40d72f791ee7033ffa73c5eb6b5d7e` |
| `mission-domsource-widths-1-6.json` | `fd17290d10e410d72c8ba91cc3f0789fc97676e1e3c82356505048f008c20524` |
| `mission-domsource-widths-6-1-repeat.json` | `c5c8968c097480a2340117d35d6f3d5cdf79a827c1dd674b1ea9494a65419540` |

## Test discrimination and mutants

Fail-before-fix for the new test file was collection failure because the file did not exist; that
only proves the tests are new. Two semantic mutants proved the intended assertions discriminate:

1. Removed `screenshot` from `VOLATILE_FINDING_KEYS`. Exact normalization test failed because a
   presentation-only screenshot changed the digest.
2. Changed sample count from `len(samples)` to `len(samples) - 1`. Exact denominator test failed with
   `{'n': 2} != {'n': 3}`.

Both were restored. File SHA-256 before mutation and after restoration was identical:
`8b09eb15001584cbfea8ba12f83eff0c8dbdf9c13df373e415e4637945944725`.
Post-restore targeted result: `2 passed in 1.85s`.

## Decision

No production file was changed. Serialization was the browser-tool bottleneck, but its bounded,
deterministic implementation was already integrated before this lease. A further concurrency change
is not justified by measurement. The remaining actionable defect is missing target `Retry-After`
respect; it needs one cross-cutting owner and tests over both `_http` and browser navigation, not three
call-site patches.

No full benchmark/FPR rerun was performed, so this lane does not claim a newly measured all-category
FPR result. Because production code is byte-unchanged, the lane itself cannot move FPR; serial and
bounded live finding sets were identical in every comparison above.

## Verification

- Targeted: `2 passed in 1.81s`.
- Full suite: `2154 passed, 9 skipped, 4 xfailed, 9 warnings in 277.34s (0:04:37)`.
- Tier-3 gate: `33/33 controls passed across 15 classes`; no regression against baseline 32;
  semantic SHA-256 `ae9f8a1bc998f97001d5c478304d1b0197c2472ee3619328cf431baad65968ee`;
  current artifact SHA-256 `8bcd91e48459d98d26272c35475a48731ccbf5702841eabc5176773c7d41aced`;
  gate artifact SHA-256 `b91a8be7f9b42d0afa90e18c2af44dbba3b0d1dc1a62baa9742f3553830114a6`.
