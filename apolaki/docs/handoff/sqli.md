# BREAKER lane: the sqli recall loss (21 -> 11)

Status header (a killed agent leaves an accurate document):

| sub-question | status |
| --- | --- |
| 1. WHICH cases were lost | MEASURED - 9 TP + 1 FP, named below |
| 2. WHY | MEASURED - never probed; the sweep's shape round-robin cut them |
| 3. WHEN | MEASURED - commit `de4c3aa`, 2026-08-11 02:57:09 -0700 |
| regression test | MEASURED - 6 passed / 1 strict xfail, mutation-checked |
| full agent suite with the new file | in progress |

Scope: DIAGNOSIS only. This lane fixes nothing.

**One-line answer.** `de4c3aa` replaced the sweep's discovery-order truncation
with an EVEN round-robin across URL shapes. The OWASP Benchmark's whole surface
collapses to 11 shapes, so the 400-target budget was split 11 ways regardless of
class size: the sqli class holds 456 of 2524 query-bearing candidates and drew
31 slots. The nine lost true positives sit at sqli-class indices 38-58, just
past a cut at index 30. They were never probed by anything.

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

## 3. WHEN - MEASURED. Commit `de4c3aa`, 2026-08-11 02:57:09 -0700

`git log -S` over the four symbols that make up the mechanism returns ONE
commit for each, and it is the same commit:

```
$ git log --oneline -S "_spread_by_shape"    -- agent/agent.py
$ git log --oneline -S "SWEEP_TARGET_CAP"    -- agent/agent.py
$ git log --oneline -S "def target_shape"    -- agent/agent.py
$ git log --oneline -S "limit=SWEEP_TARGET_CAP" -- agent/agent.py
de4c3aa Apolaki: land the browser sensor, hostless guards, and the squad's written evidence (#123)
```

The selection diff inside it:

```
-def sweep_targets(urls, forms, in_scope, limit: int = 20) -> list:
-    return targets[:limit]
+SWEEP_TARGET_CAP  = max(1, int(os.getenv("BBH_SWEEP_TARGETS", "400") or 400))
+SWEEP_BROWSER_CAP = max(0, int(os.getenv("BBH_SWEEP_BROWSER_TARGETS", "30") or 30))
+def target_shape(url: str) -> str:
+def _spread_by_shape(targets: list) -> list:
+def sweep_targets(urls, forms, in_scope, limit: int = SWEEP_TARGET_CAP) -> list:
+    return _spread_by_shape(targets)[:limit]
+       targets = sweep_targets(..., limit=SWEEP_TARGET_CAP)
```

So one commit did three things at once: raised the effective cap 20 -> 400,
introduced shape collapsing, and introduced the even round-robin.

**The commit message does not mention any of it.** `de4c3aa` is described as
"the browser sensor, hostless guards, and the squad's written evidence", and
its body explains `browser_engine`, `cdp`, `liveness_run` and two docs. The
sweep-selection rewrite arrived inside "everything left green-but-uncommitted
after four agents were killed by session limits". That is why a 47%-of-surface
recall change has gone eleven days without an owner: nothing in the log says
it happened.

### The baseline ran before it - chronology and behaviour agree

| fact | value | source |
| --- | --- | --- |
| mission `ebd96f45` created | 2026-08-11T00:19:55Z | `missions.json` record |
| mission elapsed | 5329 s (~89 min), so it ended ~01:48Z | sealed claim file |
| `de4c3aa` authored + committed | 2026-08-11T09:57:09Z | `git log --date=iso` |

The baseline finished about **8 hours before** the mechanism was committed.

Chronology alone is not proof, because the WIP could have sat in the tree
before it was committed. The behavioural argument is the one that closes it.
Under `_spread_by_shape`, reaching the deepest baseline case (00438, sqli-group
index 58) requires the sqli shape to draw at least 59 slots, and MEASURED:

```
=== NEW selection: cap needed for the sqli shape to reach idx 58
   cap   400 -> sqli slots   37 ; baseline-20 recovered 11/20
   cap   500 -> sqli slots   47 ; baseline-20 recovered 16/20
   cap   600 -> sqli slots   58 ; baseline-20 recovered 19/20
   cap   650 -> sqli slots   64 ; baseline-20 recovered 20/20 ALL
```

The baseline's 20 sqli cases are unreachable under shape-spread at any cap
below ~650. `SWEEP_TARGET_CAP` is 400, `BBH_SWEEP_TARGETS` is set nowhere in
the repo and is absent from both rerun containers' env, and both reruns record
`sweep_selection: [{"candidates": 2762, "kept": 400, "limit": 400}]`. So the
baseline cannot have run this code path. Its sweep reached deep into one class
the way an unspread, discovery-order truncation does.

Note the cap-11-of-20 row: at cap 400 the reconstruction recovers exactly the
11 cases the reruns claim. The model predicts the observed number.

### What `de4c3aa` got RIGHT, and must not be reverted

The pre-change code was `return targets[:limit]` with `limit` defaulting to 20
and the call site passing nothing - 20 targets on a 2762-URL surface, all
inside whichever directory the crawl walked first. Illustrating that on the
same candidate list:

```
=== OLD truncation (targets[:limit], discovery order)
   cap    20 -> shape mix {'cmdi-#': 20}
   cap   400 -> shape mix {'cmdi-#': 232, 'securecookie-#': 60, 'ldapi-#': 54, 'pathtraver-#': 54}
```

(Discovery order here is index-page order, which is NOT the live crawl order,
so this row is an ILLUSTRATION of the failure mode - one class monopolises the
budget - not a reproduction of the 08-11 run.)

That is strictly worse as a policy: it makes recall a lottery on crawl order.
`de4c3aa` is a real improvement that carried a real regression. The whole-run
numbers show both halves at once: findings 29 -> 31/33, distinct cases 27 ->
29/31, six families claimed instead of five - and sqli 21 -> 11.

**The defect is the RATION, not the spread.** Even round-robin over shapes
means budget share is 1/11 regardless of whether a class holds 27 candidates
or 456. The fix is a size-aware split, not a revert.

---

## 4. The patch I proposed, MEASURED, and WITHDRAWN

I wrote the proportional-ration patch below and then priced it. **It is not a
fix. Do not ship it.** Recording it because a disproved proposal is a result,
and because it would have looked obviously right to the next person too.

First, what is actually out there to be reached (answer key, read for
diagnosis only - no detection rule is derived from it):

```
=== vulnerable cases available per shape
   cmdi            232 candidates,  115 vulnerable
   securecookie     60 candidates,   33 vulnerable
   ldapi            54 candidates,   23 vulnerable
   pathtraver      241 candidates,  117 vulnerable
   sqli            456 candidates,  241 vulnerable
   trustbound      112 candidates,   74 vulnerable
   crypto          225 candidates,  120 vulnerable
   hash            214 candidates,  119 vulnerable
   weakrand        448 candidates,  189 vulnerable
   xpathi           27 candidates,   13 vulnerable
   xss             455 candidates,  246 vulnerable
   TOTAL          2524 candidates, 1290 vulnerable
```

Vulnerability density is ~51% in EVERY class. That is the fact that kills the
patch: at a fixed budget, any partition of 400 targets reaches ~200-230
vulnerable cases no matter how it is split. Rationing does not create reach.

```
=== cap 400, even ration (today) vs proportional
   even  (today) vuln reached 228 of 1290 (17.7%)
   proportional  vuln reached 226 of 1290 (17.5%)
```

Proportionality is **2 cases WORSE**. And under the macro-averaging this
project mandates for every benchmark number, it is far worse than that:

```
=== MACRO-AVERAGED reachable recall, cap 400
   even  (today)  MACRO  34.1%   micro  17.7%
       per-class {cmdi 17.4, crypto 14.2, hash 20.2, ldapi 69.6, pathtraver 17.1,
                  securecookie 72.7, sqli 9.5, trustbound 32.4, weakrand 11.6,
                  xpathi 100.0, xss 10.2}
   proportional   MACRO  17.8%   micro  17.5%
       per-class {cmdi 17.4, crypto 13.3, hash 17.6, ldapi 17.4, pathtraver 17.9,
                  securecookie 18.2, sqli 17.4, trustbound 16.2, weakrand 18.5,
                  xpathi 23.1, xss 18.7}
```

**The patch would have roughly HALVED the macro-averaged reachable recall,
34.1% -> 17.8%, to gain nothing on micro.** The even round-robin is not an
oversight that happens to hurt sqli; it is the ration that maximises macro
coverage, which is exactly what an equal-weight-per-category scorer rewards.
It buys `xpathi` 100% and `securecookie` 72.7% with slots that would otherwise
disappear into sqli's 456-case tail.

So the sqli 21 -> 11 loss is the PRICE of a policy that is right on the metric
the project scores itself with. That is a trade-off, not a defect, and I was
wrong in section 3 to call the ration "the defect". Section 3's diagnosis of
the MECHANISM stands unchanged; its recommendation does not.

### The only lever that moves both numbers is the cap

```
=== even ration (today), varying SWEEP_TARGET_CAP
    cap   MACRO   micro   sqli class reach
     400   34.1%   17.7%    23 of 241     <-- today
     500   40.8%   22.1%    28 of 241
     650   47.9%   28.4%    38 of 241     <-- recovers all 20 baseline sqli cases
     800   53.2%   34.2%    50 of 241
    1000   61.2%   42.7%    64 of 241
    1500   75.2%   60.1%    94 of 241
    2524  100.0%  100.0%   241 of 241
```

Cap 400 -> 650 is +13.8 points macro and +10.7 micro, costs no class anything,
and is the change that recovers the nine lost cases. Its price is dispatch
time: the sweep was 1603 s of the 2103 s run, and 650/400 implies roughly
+62%, so ~2600 s of sweep and a ~3100 s mission. UNVERIFIED - that is
proportional arithmetic on the measured per-URL costs at `agent/agent.py:185`,
not a timed run.

REACHABILITY IS NOT DETECTION. Every number in this section counts vulnerable
cases HANDED TO the engines. The engines still have to confirm them, and the
baseline's own record shows they do not confirm all of what they reach - it
claimed 20 of the sqli cases it swept, not all of them. Treat these as
ceilings, and pre-register a prediction before running the mission.

### The withdrawn patch, for the record

`agent/agent.py` is not mine to edit, and I am NOT asking anyone to apply this.
It weights each shape's turn by its share of the candidate set. It is correct
code for a policy that measurement says is worse than the one in place.

```python
def _spread_by_shape(targets: list) -> list:
    groups: dict = {}
    for t in targets:
        groups.setdefault(target_shape(t), []).append(t)
    out, order = [], list(groups)
    # PROPORTIONAL, NOT EVEN. An even round-robin gives a 456-candidate class and a
    # 27-candidate class the same slots, so the rarest class is tested exhaustively and the
    # commonest at 8%. MEASURED: that cost nine true positives on the OWASP Benchmark sqli
    # class (docs/handoff/sqli.md, baseline ebd96f45 vs seals e6674d6d / 82f55903).
    sizes = {k: len(groups[k]) for k in order}
    total = sum(sizes.values()) or 1
    credit = {k: 0.0 for k in order}
    while len(out) < len(targets):
        for k in order:
            g = groups[k]
            if not g:
                continue
            credit[k] += sizes[k] / total * len(order)
            while credit[k] >= 1.0 and g:
                credit[k] -= 1.0
                out.append(g.pop(0))
    return out
```

Properties, MEASURED: deterministic, order-stable within a shape, spends the
full budget, reaches every class, and makes budget share track candidate share
within a factor of two for all 11 classes. It does everything it claims. It is
still the wrong policy, for the reason measured above.

Its one legitimate use is as the NEGATIVE CONTROL for the regression test -
it is the mutant that flips the strict xfail, proving that test can detect the
change it names.

---

## Hypotheses killed

| hypothesis | verdict | evidence |
| --- | --- | --- |
| The oracle got stricter and declined these cases | **DISPROVED** | the nine cases got zero dispatches from all 17 tools; the oracle never saw a response |
| A different engine claimed them under another family | **DISPROVED** | they are absent from every `cases_by_tool` list, and absent from both reruns' full 29/31-case claim sets, not merely from `sqli` |
| `run_sqli` errored on them | **DISPROVED** | `run_sqli` made 400 calls / 373 cases; `cases_by_tool['run_sqli']` is byte-identical to `cases_probed`, and `claimed_not_probed` is empty |
| The loss is directory-scoped (survivors in `sqli-00`, lost elsewhere) | **DISPROVED** | all nine lost sqli cases are in `sqli-00`, same directory and same URL template as all 11 survivors |
| Shape collapse merged several `sqli-NN` directories into a few slots | **DISPROVED as stated, CONFIRMED in substance** | there is only ONE sqli directory, so nothing merged across directories. What collapsed is 456 URLs of one class into ONE round-robin slot-holder rationed like a 27-URL class |
| The step cap (`MAX_STEPS`) | **not the cause** (pre-existing finding, re-confirmed) | the sweep dispatches through `_inject_sweep_surface`, whose bound is `SWEEP_TARGET_CAP`; the reruns record `kept 400 of 2762 candidates` |
| The 08-11 code is unrecoverable WIP, so the cause may not be in git | **DISPROVED** | the mechanism is fully present in git as `de4c3aa`, and cap-400 shape-spread reproduces the observed 11 exactly while being arithmetically incapable of producing the baseline's 20 |
| Precision improved because the oracle stopped false-positiving on 00494 | **DISPROVED** | 00494 sits one slot past the same ordinal cut; it was never injection-probed. The FP was dropped by the budget, not by an oracle |

## Regression test

`agent/tests/test_sqli_selection_regression.py` - 7 tests, synthetic URLs
only, no benchmark path/case-id/category name in any assertion.

MEASURED on current code: `6 passed, 1 xfail`.

The xfail is `test_budget_share_tracks_candidate_share`, `strict=True`: the
invariant this diagnosis says is missing.

NEGATIVE CONTROL (the test must be able to detect the fix it names). A
throwaway copy of `agent/` with `_spread_by_shape` replaced by the
size-proportional interleave above:

```
=== REAL CODE       ......x    6 passed, 1 xfailed
=== PROPORTIONAL MUTANT ......F  XPASS(strict) on test_budget_share_tracks_candidate_share
```

Only the xfail flips; the six policy-agnostic tests pass in both worlds. So
the invariant is live, and the file does NOT freeze the defect in place - no
test asserts the 37-of-456 disparity, deliberately, because such a test would
fail on the day it is repaired. The disparity is recorded here instead.

