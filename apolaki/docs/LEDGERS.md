# Ledger index — which one to reach for

Four ledgers, four different questions. Start here, then open the one that answers what you are asking.

| ledger | answers | when to write to it |
|---|---|---|
| [CODEBASE_REVIEW.md](CODEBASE_REVIEW.md) | *What is wrong with Apolaki, and is it fixed?* | any defect found by sweep, read, or live run |
| [benchmarks/SCORE_HISTORY.md](#score-history) *(below)* | *How good is Apolaki, measured, over time?* | every scored benchmark run |
| [benchmarks/PEER_BASELINES.md](benchmarks/PEER_BASELINES.md) | *Good compared to what?* | when a peer number is verified from a raw artifact |
| Task list (`#1`–`#54`) | *What is queued, in progress, done?* | when work is planned or its state changes |

**Rules that make these worth trusting**

1. **Append, never delete.** A finding is marked RESOLVED with the commit that resolved it. Wrong
   findings stay too, marked wrong, because the error is usually the lesson (see S4, wrong by nine).
2. **MEASURED or UNVERIFIED.** Every claim carries the command that produced it, or says it is unverified.
3. **Raw artifacts are committed** next to the number, so any figure reproduces from a clean clone.
4. **The denominator is always stated.** 58.1% and 30.5% were the same run; only the denominator differed.

---

## Score history

Every scored run. Sealed = the result artifact was hashed **before** the answer key was fetched.

### OWASP Benchmark Java v1.2 — engines called directly (harness)

| date | commit | cases | official (11-cat macro) | FPR | what changed |
|---|---|---:|---:|---:|---|
| 08-09 | `318ba42` | 32 | 4.5% | 0.0% | first blind run |
| 08-10 | `8578c46` | 32 | ~9% | 0.0% | custom request-header vector |
| 08-10 | `91ddb8e` | 120 | ~12% | 0.0% | bigger sample, new seed |
| 08-10 | `5b6fb51` | 120 | 21.7% | 0.0% | page query replayed against form ACTION |
| 08-10 | `2222f96` | 120 | 25.9% | 0.0% | XPath app-level error wrappers |
| 08-10 | `031ae55` | **2065** | **36.5%** | **0.0%** | first FULL suite |
| 08-10 | `d085f46` | **2132** | **41.3%** | **0.0%** | raw Set-Cookie parser (CWE-614) |
| 08-10 | `98912d3` | 67 | *(securecookie 61.1%)* | 0.0% | judge the submitted cookie, not the setup cookie |

Peer context, recomputed from raw artifacts: **ZAP 17.99%**, best published full-suite DAST **26%**,
11-tool DAST mean **~11%**. See PEER_BASELINES.md.

> ### ✅ SUPERSEDED by the full sealed run, 2026-08-11 — and independently reproduced
>
> The retraction below stands as the record of how the 41.3% / 0.0% pair was wrong. It has since been
> replaced by a full-suite sealed measurement, and the Breaker recomputed every figure **twice** —
> once through the project scorer, once with an independent tally straight off the raw jsonl giving
> **TP 960 / FN 372 / FP 0 / TN 1282, cross_family_fp 8**. All five committed seals reproduce.
>
> | Java v1.2 | official | product |
> |---|---:|---:|
> | **DAST only** — the only line comparable to a published tool score | **41.7%** | **41.5%** |
> | **HYBRID** (DAST + code-assisted SAST) | **61.1%** | **60.9%** |
>
> FPR **0.0%** on every category under both conventions. The 2.1% product FPR in the retraction was
> the cross-family artifact; counting it is now built into the scorer and the residue is 8 cases.
>
> ### ⚠ RETRACTION, 2026-08-10 — 41.3% / 0.0% FPR is not the product claim
>
> Adversarial verification **REJECTED** the headline pair. Two separate problems, both MEASURED.
>
> **1. The FPR is 0.0% only because the scorer never looks across families.** `_detected` credits a
> finding only within the case's own category — correct for TPR, wrong for FPR. Measured: **22 clean
> `securecookie` cases carry CONFIRMED `path_traversal` findings** and every one of them scored as a
> true negative. Counting cross-family false positives:
>
> | | 11-cat macro | FPR | securecookie |
> |---|---:|---:|---:|
> | as previously reported | 41.3% | 0.0% | 52.8% |
> | with cross-family FPs counted | **34.9%** | **2.1%** | **−18.2%** (FPR 71.0%) |
>
> **2. The path-traversal oracle confirms on REFLECTION, not traversal.** The negative controls that
> should have caught this were never written:
> ```
> ../bbh-canary.txt            reflected=True
> bbh-canary.txt   (no ../)    reflected=True   <- no traversal at all
> APOLAKI-NOT-A-FILE-9182      reflected=True   <- not even a filename
> ../../../../etc/passwd       body contains 'root:x:0:0'?  False
> ```
> Sampling the pathtraver true positives gives an oracle tally of `{'reflection-only': 22}` — **the
> entire 69.2% pathtraver score rests on reflection.** It reads FPR 0.0% only because the clean
> pathtraver cases happen not to echo (8/8 measured `reflects=False`). That is a signature that
> survives by luck, not a capability.
>
> **What is still defensible.** 41.3% / 0.0% is a correct *Benchmark* figure under the official
> CWE-matching convention, and the lead handling is clean on both sides (a lead is not a TP, and clean
> cases are not dropped from the denominator: `clean cases DROPPED: 0`). **It is not defensible as a
> product claim**, because a real client's report would carry those 22 false positives. Quote **34.9%
> / 2.1%** whenever the question is "how good is Apolaki", and say which convention any other number
> uses.
>
> Standing rule this adds: **a within-family scorer cannot measure a whole-product false-positive
> rate.** Any future FPR must count every confirmed finding on a clean case, whatever family it claims.

### Python v0.1 — the code-assisted lane generalizes · MEASURED 2026-08-11

Sealed `2026-08-11T21:10:34Z`, scored in `apolaki-scorer` started `--network none` — the scanner could
not read ground truth even in principle.

| category | cases | DAST only | **+ code-assisted** | FPR |
|---|---:|---:|---:|---:|
| hash | 151 | 0.0% | **100.0%** | 0.0% |
| weakrand | 326 | 0.0% | **100.0%** | 0.0% |
| trustbound | 37 | 0.0% | 0.0% | — (unmapped by design) |
| **14-category macro** | 1230 | **24.5%** | **38.8%** | 0.0% |

**38.8% is a HYBRID figure (DAST + code-assisted SAST), not a DAST score.** The DAST lane is still
24.5%. Never compare 38.8% against a published DAST number — those tools were not given the source.

The cause was a language gate on a language-independent analysis: `review_source_tree` walked only
`*.java`, so an analyzer measuring 100/100/100 on Java contributed **nothing** to 514 of 1230 Python
cases. The delta is exactly additive (7.14 + 7.14), `cross_family_fp = 0`, and 170 findings across
1236 files each landed on a case of its own category.

**Java is unchanged and it was PROVEN, not asserted**: the re-run through the new dispatcher is
identical row-for-row to the sealed artifact (975/975 cases, 2763 files), still 100.0/100.0/100.0 at
0.0% FPR.

**The load-bearing design decision — the receiver decides the verdict, not the method name.**
`random.getrandbits(32)` is a Mersenne Twister; `random.SystemRandom().getrandbits(32)` is
`os.urandom`. **113 of 326 weakrand cases are the second line.** A name-matching implementation reports
283 findings instead of 170 and takes weakrand from 100.0% to 50.2% — and it passes every positive
test in the file. That mutant was written and killed; it is the reason this lane is trustworthy.

**Recorded against the lane's own evidence, by the lane:** the seven negative controls all fail
pre-fix with `AttributeError`, which proves the tests are NEW, not that their assertions discriminate.
The discriminating evidence is the mutation run — 7 mutants, 7 killed. Fail-first alone was correctly
called weak rather than counted as proof.

### OWASP Benchmark Python v0.1 — foreign-stack generalization check

| date | commit | cases | official | FPR | note |
|---|---|---:|---:|---:|---|
| 08-10 | `7e169ae` | 54 | 34.8% | 3.1% → **0.0%** | first run; exposed a scorer defect (leads counted as detections) |

### Whole-product missions — the real orchestrator, not the harness

This is the measurement that matters, and the one that was never taken until 08-10.

| date | commit | findings | what it proved |
|---|---|---:|---|
| 08-10 | *(pre-fix)* | **0** | mission against 1415 real vulns returned nothing in 40s |
| 08-10 | `3642c6c` | 2 | S11a: seed the scoped path |
| 08-10 | `3642c6c` | 2 | S11b alone did not move it |
| 08-10 | `57afc3f` | **2** | S11c relative links + robots/sitemap — **did not move it either** |
| 08-11 | Q-019 WIP (uncommitted) | **25** | the funnel fix — **12.5×**, and the first time engines reached benchmark cases |

**MEASURED, 08-11 — the funnel fix worked.** Mission `ebd96f45` (`owaspbench-q019`), same target,
same active mode, completed:

```
total findings: 25   (27 high + 2 medium raw, 3 leads)
by family: {'sqli': 21, 'ldap_injection': 1, 'dom_data_manipulation': 1,
            'sensitive_exposure': 1, 'vulnerable_component': 1}
by confidence: {'confirmed': 25}
  high | sqli            | SQL injection (error-recovery) in 'header:BenchmarkTest00018'
  high | sqli            | SQL injection (boolean-blind) in 'BenchmarkTest00033'
  high | ldap_injection  | LDAP injection in form field 'BenchmarkTest00630'
```

Two things make this different from the previous 2:
1. **The findings are ON benchmark cases.** `BenchmarkTest00018`, `00033`, `00630` are real case
   identifiers. The previous run's two findings were generic hygiene (a source-comment credential,
   jquery@2.1.4) that any target would produce; both are still here, so 23 of the 25 are new.
2. **No `path_traversal`.** That matters specifically, because the same day's verification proved the
   pathtraver oracle confirms on mere reflection. A funnel that probes ~10× more URLs would have
   multiplied that false positive if it were firing. It is not in this result.

**SCORED, 08-11 — the first honest whole-product benchmark measurement this project has ever taken.**

Blind discipline held: the mission's claims were extracted and **sealed before the key was fetched**.

```
SEAL sha256: a95670f9c7560b227a234ebeb23c0fba0872cb3100f87e52d0c4d878988660f5
distinct cases claimed: 23
key entries: 2740   (expectedresults-1.2.csv, copied from the lab container AFTER sealing)

TRUE  POSITIVES: 22
FALSE POSITIVES:  1
unknown cases  :  0
by (key category, is_vulnerable): {('sqli', True): 20, ('cmdi', True): 1,
                                   ('ldapi', True): 1, ('cmdi', False): 1}
```

| metric | value | how to read it |
|---|---:|---|
| **Precision** | **22/23 = 95.7%** | when the product speaks, it is almost always right |
| **Recall** | **22/1415 = 1.6%** | it almost never speaks |

**This is the real product number, and both halves matter.** The previous mission scored 0 benchmark
cases; this one scores 22 with one false positive. That is a genuine step and it is nowhere near
100%. Anyone quoting the harness's 41.3% as what Apolaki does to a real target is quoting the wrong
measurement by a factor of ~25 in recall.

**The single false positive is worth more attention than the 22 hits.** `BenchmarkTest00494` is a
**clean `cmdi`** case and Apolaki reported **`sqli`** on it — a cross-family false positive, i.e.
exactly the class the official CWE-matching convention forgives and scores as a true negative. The new
product scorer (`3d41f9a`) counts it. It is also a live defect: an sqli oracle fired on a case with no
sqli, so that oracle has a weakness of the same shape as the path-traversal one, just rarer. Chase it.

**Where the recall goes.** 1415 vulnerable cases, 22 found. The funnel now discovers 2756 URLs, but
throughput is ~100 s/URL, so a run that actually probes everything needs ~76 hours. Recall is
currently bounded by wall-clock, not by the engines. That is the next constraint, and it is a
concurrency problem, not a detection problem.

**MEASURED, 08-10 — the most important negative result in this ledger.** Mission `90cee81c`
(`owaspbench-clean`, active mode) ran **3720 seconds** against `https://owaspbench:8443/benchmark/`
and finished `complete` with **2 findings**:

```
[    0s] running/recon  findings=0
[   50s] running/probe  findings=2
[ 3720s] complete/report findings=2
by family: {'sensitive_exposure': 1, 'vulnerable_component': 1}
   [high]   Credential exposed in a source comment
   [medium] Vulnerable component: jquery@2.1.4 (CVE-2020-11022, +2 more)
```

**Neither finding is one of the 1415 benchmark cases.** Both are generic hygiene findings that would
appear on almost any target. Note also that the count was already 2 at the 50-second mark and did not
change over the following 61 minutes — the run spent an hour producing nothing.

**ANSWERED, same day — the funnel was measured, not guessed** (replayed from the mission's 908-row
persisted event log):

```
Surface crawl: probed 12 page(s), surface 5 -> 2756 URL(s)
tool_call events 433 · scope_block events 34
DISTINCT URLs any tool_call aimed at        : 66
DISTINCT URLs http_probe/http_read touched  : 36
findings: 2 (both from JS recon on the index page)
```

**2756 discovered, 36 probed.** Discovery is NOT the gap — S11b/S11c/S11d genuinely work, the crawl
found all 2740 cases. Three compounding causes downstream, each independently measured:
1. **Hostless URLs.** 10 of 36 probed URLs are `https:///benchmark/cmdi-Index.html` — scheme, empty
   netloc. `urljoin("https://", "/benchmark/x.html")` produces exactly that, and
   `ScopeEngine.validate()` correctly refuses it. Those are the 34 `scope_block` events, and they are
   precisely the category index pages that link to all 2740 cases. The scope engine is right; the
   producer hands it garbage and nothing names the producer.
2. **Only a FETCHED url can become a target.** `sweep_targets` keeps a URL only if `"?" in u` or it
   carries a captured form. The 2740 cases are plain `.html` with no query. Coverage is therefore
   O(pages fetched), not O(surface discovered).
3. **`depth(2) × frontier(30)` = 60 visits** is the only gate between a 2756-URL surface and the
   engines; 12 survived cause (1).

Tracked as **Q-019** (CRITICAL, ready). This supersedes the "fix a sixth suspected defect" plan.

**What the 2-finding result falsifies.** Five orchestration defects were found and fixed (S11a scoped-path seed,
S11b auth-only crawl, S11c relative links dropped, S11d robots/sitemap unread, S12 dead browser
sensor) on the hypothesis that recon was starving the engines. The engines score **41.3%** on this
exact target when handed case URLs directly. The fixes shipped and the whole-product number **did not
move**. So the funnel collapses somewhere *after* discovery, or discovery is still failing for a
reason none of the five addressed. Do not claim the orchestration gap is closed. The next step is to
measure the funnel stage by stage — URLs discovered, URLs parameterized, probes selected, oracles
fired — rather than fixing a sixth suspected defect blind.

**Why the two columns disagree.** The harness hands engines exact URLs; the mission has to *find* them.
41.3% vs 0 findings was never an engine gap — it was three orchestration defects that only a
whole-product run could expose. Quote the mission number, not the harness number, when describing
Apolaki as a product.

---

## Code-assisted lane — MEASURED 2026-08-11. The "unreachable" categories are not unreachable.

**The standing write-off was wrong, and it went unchallenged for weeks.** "100% is unreachable" was
true of the *HTTP* lane and got restated as though it were true of *Apolaki*. Apolaki already ships
`agent/codereview.py` with `scan_weak_crypto`, and the benchmark source is 5480 files sitting in the
lab container. Nobody had ever pointed one at the other.

Evaluated **semgrep** (not previously installed; 9 external tools are wired, this was not one).
Blind-sealed before the key was fetched: `ec71f4335d521f889b7c6b477458a071b65a1cabd5a3be6659d87d2208f17cf2`.
2740 files scanned, 1950 findings, `p/java` ruleset.

| category | cases | TP | FN | FP | TPR | **FPR** | score | previously |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **crypto** | 246 | 130 | 0 | 0 | 100.0% | **0.0%** | **100.0%** | 0.0% |
| **weakrand** | 493 | 193 | 25 | 0 | 88.5% | **0.0%** | **88.5%** | 0.0% |
| **hash** | 236 | 89 | 40 | 0 | 69.0% | **0.0%** | **69.0%** | 0.0% |
| trustbound | 126 | 43 | 40 | 18 | 51.8% | 41.9% | 9.9% | 0.0% |

`weakrand` came from a **12-line custom rule** (`new Random()`, `Math.random()`,
`ThreadLocalRandom.current()`) because `p/java` ships none — the single largest category in the suite
and it needed twelve lines.

**Three categories at 0.0% FPR, where every published DAST scores exactly 0.00% and the 11-tool mean
is 0.0%.** This is not a scanner trick: reading the client's source is what real assessments do.

**Semgrep alone is NOT better overall** — macro 26.8%, because its taint rules have severe FPR
(ldapi 87.5%, pathtraver 78.5%, cmdi 76.8%). The design that follows from the measurement is a
**hybrid**: Apolaki's high-precision DAST for the injection families, semgrep restricted to the
categories DAST structurally cannot see, and only the rules measured at 0% FPR.

**Provisional projection, NOT a claim:** substituting crypto/weakrand/hash into the 11-category macro
in place of three zeros gives roughly **64.7%** against best-published-DAST 26% and ZAP 17.99%. It is
provisional because the DAST side is itself under revision — the pathtraver component was a
reflection signature and is being rewritten, which will lower it. **Re-measure end to end before
quoting any number.**

Standing rule this replaces: *never restate a limit of one lane as a limit of the platform.*

## Standing honesty constraints

- **100% is not reachable on the black-box lane** — but see the code-assisted lane above: the
  constraint is on HTTP, not on Apolaki. A code-derived result must be labelled **code-assisted
  (SAST)** and must never be folded into a DAST figure or compared against ZAP's 17.99%.
- **Never narrow the denominator to raise the number.** The macro divides by every category the suite
  has, unmeasured ones included as 0.
- **Leads are not detections.** Score only gated-confirmed rows.
- **An unmeasured case is not a miss** — it goes to `unscored`, never into a rate.
