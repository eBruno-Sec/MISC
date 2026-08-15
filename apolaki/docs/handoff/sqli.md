# BREAKER lane: the sqli recall loss (21 -> 11)

Status header (a killed agent leaves an accurate document):

| sub-question | status |
| --- | --- |
| 1. WHICH cases were lost | MEASURED - answered below |
| 2. WHY | in progress |
| 3. WHEN (commit) | in progress |

Scope: DIAGNOSIS only. This lane fixes nothing.

---

## 1. WHICH 10 cases were lost - MEASURED

Command (throwaway container, repo + scratchpad mounted read-write-only-to-scratch):

```
docker cp apolaki-sel-wp2:/out/wp_claims.json <scratch>/wp2_claims.json
docker run --rm -v <repo>:/repo -v <scratch>:/scratch -w /scratch apolaki-agent python brk5_diff.py
```

Inputs: `docs/benchmarks/baseline_ebd96f45_claims.json` (27 claims, sealed),
`docs/benchmarks/wp1_web_probes_sweep_claims.json` (seal `e6674d6d...`, 31 claims),
`apolaki-sel-wp2:/out/wp_claims.json` (seal `82f55903...`, 29 claims).

**The lost set is IDENTICAL in both reruns.** `base - wp1` and `base - wp2` are the
same 10 ids:

```
BenchmarkTest00335
BenchmarkTest00337
BenchmarkTest00339
BenchmarkTest00341
BenchmarkTest00342
BenchmarkTest00428
BenchmarkTest00429
BenchmarkTest00433
BenchmarkTest00438
BenchmarkTest00494
```

Of these, `00494` is the KNOWN FALSE POSITIVE from the baseline (baseline was
26 TP / 1 FP). So the honest accounting is:

* **9 true positives lost** (00335, 00337, 00339, 00341, 00342, 00428, 00429, 00433, 00438)
* **1 false positive lost** (00494) - a precision *gain*, not a regression.

Nothing else from the baseline's 27 was dropped. `BenchmarkTest00407`
(cmdi-labelled, claimed by sqli in the baseline) is still claimed today.

### The survivors and the lost live in the SAME directory

All 11 surviving sqli claim_rows target `/benchmark/sqli-00/`. My first
inference from that - "the loss is directory-scoped" - is **DISPROVED**.
MEASURED against the lab's own category index pages:

```
docker run --rm --network apolaki_default alpine/curl -sk \
  https://owaspbench:8443/benchmark/sqli-Index.html   (and the other 10)

00335 -> sqli-00/BenchmarkTest00335.html?BenchmarkTest00335=SafeText
00337 -> sqli-00/...   00339 -> sqli-00/...   00341 -> sqli-00/...
00342 -> sqli-00/...   00428 -> sqli-00/...   00429 -> sqli-00/...
00433 -> sqli-00/...   00438 -> sqli-00/...
00494 -> cmdi-00/BenchmarkTest00494.html?BenchmarkTest00494=SafeText
```

Nine of the ten lost cases are in `sqli-00`, the SAME directory as all 11
survivors, reachable by the SAME URL template. Directory is not the
discriminator. (The 10th, 00494, is the cmdi-labelled FP.)

### Counts are otherwise UP, not down

| family | baseline ebd96f45 | wp1 e6674d6d | wp2 82f55903 |
| --- | --- | --- | --- |
| sqli | 21 | 11 | 11 |
| ldap_injection | 5 | 5 | 5 |
| path_traversal | 0 | 12 | 10 |
| dom_data_manipulation | 1 | 1 | 1 |
| sensitive_exposure | 1 | 1 | 1 |
| insecure_cookie | 0 | 1 | 1 |
| weak_random | 0 | 1 | 1 |
| xpath_injection | 0 | 1 | 1 |
| vulnerable_component | 1 | 0 | 0 |
| **findings_total** | **29** | **33** | **31** |
| **distinct cases claimed** | **27** | **31** | **29** |

So this is not a global collapse. 14 (wp1) / 12 (wp2) cases are claimed today
that the baseline never claimed. The sqli family specifically went backwards
while the product as a whole went forwards.

### The two reruns are NOT byte-identical

`wp1 - wp2 = {00023, 00187, 00236}`, `wp2 - wp1 = {00042}`, all in
`path_traversal` (12 vs 10). The sqli set is identical in both. So sqli's
11 is deterministic; path_traversal carries the run-to-run noise.
(Both runs report the same `tool_call: 4059`, same `exit_reason:
step_cap_exhausted`, same `cases_by_phase_n {planner: 25, sweep: 373}`.)

---

## 2. WHY - MEASURED. Never probed. Selection, not oracle.

### 2a. The nine lost true positives received ZERO tool dispatches

From the rerun's own `coverage` block (`apolaki-sel-wp2:/out/wp_claims.json`,
seal `82f55903`), inverting `cases_by_tool` (17 tools) onto each case:

```
BenchmarkTest00335   NOT PROBED BY ANY TOOL
BenchmarkTest00337   NOT PROBED BY ANY TOOL
BenchmarkTest00339   NOT PROBED BY ANY TOOL
BenchmarkTest00341   NOT PROBED BY ANY TOOL
BenchmarkTest00342   NOT PROBED BY ANY TOOL
BenchmarkTest00428   NOT PROBED BY ANY TOOL
BenchmarkTest00429   NOT PROBED BY ANY TOOL
BenchmarkTest00433   NOT PROBED BY ANY TOOL
BenchmarkTest00438   NOT PROBED BY ANY TOOL
BenchmarkTest00494   ['run_csrf']            (touched, never injection-probed)
```

against every survivor, which got the full battery:

```
BenchmarkTest00018   run_css_injection, run_dom_trace, run_injection_probes, run_ldap,
                     run_sqli, run_sqli_structural, run_ssi, run_waf_bypass,
                     run_web_probes, run_xpath, run_xss
BenchmarkTest00033 .. 00204   same list minus the two browser engines
```

This settles the four candidate causes in the brief:

| candidate cause | verdict |
| --- | --- |
| not probed at all | **CONFIRMED** - 9/9 lost TPs, zero dispatches |
| probed but the oracle declined | DISPROVED - the oracle never saw them |
| probed by a different engine | DISPROVED - no engine touched them |
| dispatched but errored | DISPROVED - `claimed_not_probed` is empty, and a dispatch would appear in `cases_by_tool` regardless of outcome |

`run_sqli` made 400 calls reaching 373 cases, and `cases_by_tool['run_sqli']`
is byte-identical to `cases_probed`. The engine ran fine. It was handed a
target list that did not contain these nine URLs.

### 2b. The mechanism: `_spread_by_shape` gives the sqli shape 31 of 456 slots

`agent/agent.py:248 target_shape()` normalizes every digit run to `#`, so
`/benchmark/sqli-00/BenchmarkTest00018.html?BenchmarkTest00018=SafeText`
becomes the shape

```
benchmark/sqli-#/BenchmarkTest#.html|BenchmarkTest#
```

The OWASP Benchmark has exactly 11 category directories and one URL template,
so the ENTIRE 2524-URL query-bearing surface collapses to **11 shapes**.
MEASURED by driving the real `agent.sweep_targets` over the surface published
by the lab's own 11 index pages (no network in the experiment; the index HTML
was fetched once):

```
docker run --rm -v <repo>/agent:/app -v <scratch>:/scratch -w /scratch \
  apolaki-agent python brk5_shapes.py

index links -> 2740 distinct BenchmarkTest urls (2524 with query, 216 without)
=== shape census of query-bearing candidates: 11 shape(s)
   benchmark/cmdi-#/BenchmarkTest#.html|BenchmarkTest#          232
   benchmark/securecookie-#/BenchmarkTest#.html|BenchmarkTest#   60
   benchmark/ldapi-#/BenchmarkTest#.html|BenchmarkTest#          54
   benchmark/pathtraver-#/BenchmarkTest#.html|BenchmarkTest#    241
   benchmark/sqli-#/BenchmarkTest#.html|BenchmarkTest#          456
   benchmark/trustbound-#/BenchmarkTest#.html|BenchmarkTest#    112
   benchmark/crypto-#/BenchmarkTest#.html|BenchmarkTest#        225
   benchmark/hash-#/BenchmarkTest#.html|BenchmarkTest#          214
   benchmark/weakrand-#/BenchmarkTest#.html|BenchmarkTest#      448
   benchmark/xpathi-#/BenchmarkTest#.html|BenchmarkTest#         27
   benchmark/xss-#/BenchmarkTest#.html|BenchmarkTest#           455
```

`_spread_by_shape` round-robins, so the 400-slot budget is split **evenly by
shape, not proportionally by shape size**. Every shape gets the same ~37
slots whether it holds 27 candidates or 456:

```
sweep_targets(limit=400) kept 400
   cmdi          38 of  232      trustbound    37 of  112
   securecookie  38 of   60      crypto        37 of  225
   ldapi         38 of   54      hash          37 of  214
   pathtraver    37 of  241      weakrand      37 of  448
   sqli          37 of  456      xpathi        27 of   27
                                 xss           37 of  455
```

xpathi (27 candidates) is tested **100%**. sqli (456 candidates) is tested
**8.1%**. The three biggest classes - sqli 456, xss 455, weakrand 448 - are
each cut to the same 37 as securecookie's 60.

### 2c. The cut falls exactly between the survivors and the lost

Position of each case inside the sqli shape group, first-seen order preserved:

```
   BenchmarkTest00018     idx   1 of 456      <-- claimed today
   BenchmarkTest00033     idx   7
   BenchmarkTest00192     idx  16
   BenchmarkTest00193     idx  17
   BenchmarkTest00194     idx  18
   BenchmarkTest00195     idx  19
   BenchmarkTest00196     idx  20
   BenchmarkTest00198     idx  22
   BenchmarkTest00199     idx  23
   BenchmarkTest00203     idx  27
   BenchmarkTest00204     idx  28
   ------------------------------- the cut
   BenchmarkTest00335     idx  38 of 456      <-- LOST
   BenchmarkTest00337     idx  40
   BenchmarkTest00339     idx  42
   BenchmarkTest00341     idx  44
   BenchmarkTest00342     idx  45
   BenchmarkTest00428     idx  48
   BenchmarkTest00429     idx  49
   BenchmarkTest00433     idx  53
   BenchmarkTest00438     idx  58
```

11 of 11 survivors below the cut. 9 of 9 lost cases above it. Zero exceptions
in either direction. The separation is perfect, and it is a pure function of
ordinal position in a truncated list - nothing about the cases themselves.

### 2d. Reproduced against the real run

The real rerun's own probe record confirms the cut, at index 30 rather than my
reconstruction's 36 (the live crawl found 2762 candidates vs my 2524 from the
index pages, so the round-robin had slightly less to give each shape):

```
REAL RUN: 31 sqli-shape cases probed; max index = 30
   first 5: [(0,'BenchmarkTest00008'), (1,'BenchmarkTest00018'), (2,'BenchmarkTest00024'),
             (3,'BenchmarkTest00025'), (4,'BenchmarkTest00026')]
   last 5 : [(26,'BenchmarkTest00202'), (27,'BenchmarkTest00203'), (28,'BenchmarkTest00204'),
             (29,'BenchmarkTest00205'), (30,'BenchmarkTest00206')]
   contiguous from 0? True
```

The real run probed sqli indices **0..30 with no gaps and nothing above 30**.
That is a prefix truncation of one shape group, exactly as `_spread_by_shape`
plus `[:limit]` specifies. Reconstruction vs real run over all 11 shapes:
339 of 400 cases in common, Jaccard 0.781 - the residual is crawl-order and
form-page candidates my index-only surface does not have, and it does not
touch the sqli conclusion, which is confirmed from the real run's own data.

**So the leading hypothesis in the brief is CONFIRMED, with one correction:
the shapes did not collapse "20 sqli cases into a handful of slots" by
merging distinct directories. There is only one sqli directory. What
collapsed is the whole 456-URL sqli class into ONE round-robin slot-holder
that is then rationed identically to a 27-URL class.**

### 2e. The FP's disappearance is the same mechanism, not a fix

`BenchmarkTest00494` sits at cmdi index 37 of 232 - one past the boundary in
the real run, one inside it in my reconstruction (`SELECTED`). It was dropped
by the same ordinal cut that dropped the nine true positives. The 96.3% ->
higher precision reading must NOT be credited to an oracle improvement: the
FP was never re-tested.

## 3. WHEN - in progress
