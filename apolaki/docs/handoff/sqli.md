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

### The shape of the survivors is the whole clue

Every one of the 11 surviving sqli claim_rows targets the SAME directory:

```
sqli | SQL injection (boolean-blind)  in 'BenchmarkTest00033' | .../benchmark/sqli-00/BenchmarkTest00033
sqli | SQL injection (error-recovery) in 'header:BenchmarkTest00018 | .../benchmark/sqli-00/BenchmarkTest00018
sqli | ... 00192 00193 00194 00195 00196 00198 00199 00203 00204  (all sqli-00)
```

11 for 11 in `/benchmark/sqli-00/`. Zero in any other `sqli-NN` directory.
The baseline's 21 sqli findings were NOT confined to sqli-00. Whatever the
mechanism is, it is directory/shape-scoped, not case-scoped.

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

## 2. WHY - in progress

## 3. WHEN - in progress
