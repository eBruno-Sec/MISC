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

> **SUPERSEDED 2026-08-14 — see "The unre-derivable baseline" below.** These two rows undercount by
> four: five `ldapi` findings were collapsed into one by a `finding_fp` param collision, and the key
> says all five are true positives. Re-scored from the same stored rows against a seal recorded
> before the key: **26/27 = 96.3% precision, 26/1415 = 1.84% recall.** Left standing as written,
> because a published number is corrected in the open, not edited out of the record.

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

## ★ CORRECTION — `step_cap_exhausted` was a TRUE label pointing at the WRONG CONSTANT. 2026-08-14

I published "THE ANSWER: `exit_reason = step_cap_exhausted`, 309 steps against a cap of 220." The
label was accurate and my reading of it was not. Third instrumented run, seal `3ee7609d…`,
**byte-identical to the breaker's runs A and B** with 16 wrapped methods attached — so the instrument
does not perturb what it measures:

```
planner_would_schedule_more = 2
batches = [14, 6, 30, 41, 218]
```

The cap is tested at the TOP of the `while`, so the 218-step batch began at step 91 and ran to 309
unimpeded. The planner was **2 steps from fixpoint**. Raising `MAX_STEPS` buys 2 dispatches, ~3
seconds, and **0 cases**. The planner's reach is bounded by `CAP_ENDPOINTS = 25`.

**The lesson is about reading instruments, not about this constant.** An exit reason names the
condition that *held when the loop stopped*, which is not the same as the constraint that *decided
what the run could reach*. A true label answered a question I had not actually asked, and I quoted it
as a cause. Anything reported as an "exit reason", "limit hit" or "timeout" gets the same follow-up
now: **would relaxing it change the outcome?** — a counterfactual, which is cheap to measure and is
the only thing that makes it a lever.

**Where the work actually goes** (percentages of one run):

| phase | calls | tool seconds | cases reached |
|---|---|---|---|
| sweep | 3350 (91.6%) | 1360.5 (75.1%) | 373 |
| planner | 309 (8.4%) | 451.2 (24.9%) | 25 |

Coverage is set by one constant: `SWEEP_TARGET_CAP` keeps **400 of 2762 candidates (14.5%)**. The
85.5%-never-probed figure therefore arrives a second time, from a different direction, which is the
corroboration the first measurement did not have.

**`unique = 0` for EVERY engine.** They all ride one target list, so an added engine buys
classes-per-case and **never** coverage. That single fact reorders the backlog: engine work cannot
move recall on this suite while the target list is the binding constraint.

**The headline recall number is a denominator artifact.** Of 220 vulnerable cases probed, only **51
(23%)** ever received the engine that owns their class:

```
detection on PROBED                : 18/220 =  8.2%
detection on CLASS-CORRECTLY PROBED: 18/51  = 35.3%
```

So the "202-case detection shortfall" is really **33** genuine oracle misses, **56** structurally
invisible to any DAST tool (crypto/hash/trustbound), and **113** whose owning engine exists and never
ran — 56 of those owned by an engine that ran **zero** times.

**The prediction that was wrong in the worse direction.** P5 predicted `run_web_probes` at ~25
dispatches; it is **zero**. `planner._ALLOWED["active"]` excludes INTRUSIVE and `fresh()` drops those
steps, so in the default mode the planner **cannot schedule** `run_web_probes`, `run_cmdi`,
`run_nosqli`, `run_ssrf` or `run_bfla` at all. The sweep dispatches through `_run_tool` instead, which
makes `_SWEEP_HTTP_ENGINES` **the only path to intrusive injection coverage in an active mission** —
an architectural fact nothing in the code says out loud.

**The cost that was priced and deliberately NOT cut.** `run_xss` is 1.5% of dispatches and **41.0% of
tool-seconds**, reaches 50 cases, **0 uniquely**, and produced **0 of 18 claims**; the browser trio is
3.1% of dispatches for 58.5% of tool time and 1 claim. One browser target costs 33 HTTP targets. The
lane refused to cut it: browser confirmation is how XSS becomes proof instead of a lead, and trading
that for corpus coverage on one benchmark is exactly the benchmark-fitting this project forbids.
Priced, recorded, left to an owner. **A cost is not a defect.**

**Still open, and stated as open:** `apolaki-sel-wp1` (the change — `run_web_probes` added to the
sweep) is mid-run with 6 `path_traversal` findings, a class this mission has never produced. It is
**not sealed, not scored, not repeated**, so there is **no after-number** and none may be quoted.
`805a78e` carries the revert condition in advance: if precision moves off 100.0%, revert rather than
defend.

---

## Q-046 — the four true positives were lost to a `rsplit`. 2026-08-14

The cause of the understated baseline, fixed at the root. `finding_fp` recovered the tested parameter
by parsing the rendered title:

```python
m = title.rsplit(" in '", 1)          # every builder renders "... in '<param>'"
```

Every injection builder matches that shape **except** `ldap_tool.finding`, which renders
`LDAP injection in form field 'uid'` — a word between `in` and the quote. The split matched nothing,
`param` fell to `""`, and **`""` is indistinguishable from "this finding has no parameter."** Five
`ldap_injection` findings on five different benchmark cases therefore shared one key and were counted
once. That is the whole distance between a published 22 and a measured 26.

**Every one of the five builders already had `param` as a local variable and threw it away after
formatting it into a sentence.** The value was never missing; it was rendered and discarded. So the
fix is the standing rule rather than a better regex — **bind the value at the point it is known** —
and the parse survives only as a fallback, because ~1052 findings are already stored without the
field and their fingerprints must not move.

**The control that decided it was safe to ship** asserts the parsed key and the bound key are
byte-identical for a title the parse *can* read. If that had failed, every historical diff would have
silently broken.

Four mutants, all killed: ignore the bound field (4 tests fail), let the title win over it (1), stop
emitting it in `ldap_tool` (2), and drop the empty-value fallback (2) — that last one is the
`x or DEFAULT` trap this codebase has now been bitten by three times, so it gets its own control.

**Worth naming: this is the same defect as Q-042 and as the `_POWERED` names above** — a value
recovered from prose instead of carried as data. Three independent instances in one week says the
pattern is the finding, not the three bugs.

---

## The unre-derivable baseline: counts reconciled, seal still dead. 2026-08-14

`ebd96f45` has been carried as "cannot be re-derived; every comparison against it is suspect." The
counts now reconcile. **Independently measured against the store, not taken from the lane's report:**

```
rows                     : 29
confidence               : {'confirmed': 29}          <- zero leads
severity                 : {'high': 27, 'medium': 2}
family                   : sqli 21, ldap_injection 5, dom_data 1, sensitive 1, component 1
distinct finding_fp      : 29   (current code, path in the key)
```

`27 high + 2 medium` is **character for character** the ledger's own raw parenthetical for that
mission. It is the same data. The ledgered **25** is those 29 with the five `ldap_injection`
findings collapsed into one, which also explains why the ledgered by-family line reads `ldap 1` while
`sqli 21` is untouched: `finding_fp` derives `param` by `rsplit(" in '", 1)`, the sqli titles are
`... in 'header:BenchmarkTest00018'` so each keeps a distinct param, and the LDAP titles are
`LDAP injection in form field 'BenchmarkTest00630'` — no `" in '"`, so all five get `param = ""` and
differ only by path.

**One correction to the mechanism as first written, from `git log -L` on `finding_fp`.** The
reconstruction assumed a path-less key. The committed key has included the path since **8714e6a,
2026-08-04** — a week *before* this mission — so the collapse cannot be attributed to the code of
record. The mission also ran on uncommitted Q-019 WIP, which is precisely the state the standing rule
forbids relying on, so *which* counter produced the 25 is **not recoverable**. It does not change the
reconciliation: the 29 stored rows are the run's real output either way. It does change what may be
claimed — this is an explanation that fits, **not a proven cause**.

**Consequences, including the unflattering one.** The five LDAP findings are five distinct claims
about five distinct cases; merging them was a fingerprint collision, not a dedup. So the honest claim
count for the baseline is **27, not 23**, the "class coverage broadened, `ldapi 1 -> 5`" line I wrote
is **zero** — the baseline already had all five — and the whole-product regression is **-9, not -3**.
Worse than published, and published anyway.

**Q-045 DONE — the baseline is re-derivable now.** Rather than move `claimed` alone (which would
raise apparent precision by arithmetic instead of by evidence), the run was re-scored end to end.
Claim set extracted from the 29 stored rows with the same `case_ids()` the reruns use, written to
`docs/benchmarks/baseline_ebd96f45_claims.json`, **committed with its seal in `59d6eb0` before the
answer key was opened**, then scored in a `--network none` container:

```
seal recorded  : fab8a46e13633f6a418a05742b4a49a588acd8e5fb34aa00ceb03f0dedeb9051
seal recomputed: fab8a46e13633f6a418a05742b4a49a588acd8e5fb34aa00ceb03f0dedeb9051
distinct cases claimed : 27
TRUE POSITIVES : 26      FALSE POSITIVES : 1      unknown : 0
PRECISION : 26/27 = 96.3%   (published 95.7%)
RECALL    : 26/1415 = 1.84% (published 1.55%)
by (category, verdict): {('sqli','TP'): 20, ('ldapi','TP'): 5, ('cmdi','TP'): 1, ('cmdi','FP'): 1}
```

**The error ran against us, not for us.** All five `ldapi` cases are TRUE positives in the key, so
the collapsed count did not hide a false positive — it hid **four real detections**. The published
baseline understated the product: **26 TP / 27 claimed / 96.3%**, not 22 / 23 / 95.7%. The one FP is
`00494`, the long-known cmdi false positive, which is exactly where it was expected.

Every published delta measured against 22/23 therefore **understates the regression**: the 08-13
rerun's 18 claims is **−9**, and `ldapi 1 -> 5` is **zero broadening**. `BASELINE` in
`scripts/whole_product_score.py` now carries 26/1/27 — all three moved together, or none would have.

The 08-11 seal `a95670f9…` reproduces under no serialization tried and its sealing script was never
committed. **Abandoned, not explained.** The counts are re-derivable; that seal never will be.

---

## `_POWERED` garbage names — the gate was on the wrong side of the report. 2026-08-14

Carried in QUEUE as a known-unticketed defect since Q-021B: the report and `live_hosts[i]["tech"]`
printed `'a MultiJuicer Kubernetes cluste'`, `'nothing on.'` and (live, against Mutillidae) `'and
that the database username'` as the target's technology stack. Q-021B built the admission rule and
correctly gated **persistence** with it, so none of that was stored — but a reader was still shown it.

**Where the filter goes is the entire decision.** Filtering at extraction cleans the display and
**blinds the ledger**: `tech_facts` reads `detect()` and records every refusal with its reason, which
is the one artifact separating *dropped on a rule* from *never detected*. So `detect()` keeps
everything, and only `public_view` — the projection whose whole job is "what we are willing to show a
human as a product name" — drops rejected names.

**The prior test asserted the opposite, and its reason did not survive checking.** It said narrowing
this "would change `fingerprint()`'s output for every existing caller." Enumerated: there is exactly
**one** consumer, `tools._run_fingerprint`, and it already keeps the evidence-carrying records for the
fact path and uses the projection only for display. That was a scope limit for a lane that owned
neither the callers nor the report, not a finding that the behaviour was right. Test replaced, with
the reversal and its reason written into the docstring rather than deleted.

**A control of mine failed and the failure was the useful part.** I asserted `built with Express`
survives; it is refused `prose_not_a_known_product`, because `_KNOWN_PRODUCTS` is *derived* from the
detection tables and the cookie table spells it `Express/Node.js`. So the filter charges a real price:
**a legitimate powered-by naming a product no table lists is not displayed.** Stated here rather than
discovered later. It is not silent — the fact path still carries it with a named reason.

`_POWERED` itself is unchanged. The fix is an admission rule on a shape, not a cleverer regex over
English prose.

---

## Q-013 / Q-014 CLOSED — the gate did not read the field it was gating. 2026-08-14

`3addb1c` · `42e1544` · `a1cdb8d` · report rendering. Suite **2374 passed, 11 skipped, 1 xfailed**.
No benchmark number moved — this is a proof-integrity fix, not a detection change.

**The first fix was correct and insufficient, and that gap is the finding.** Pass one routed
`db.update_finding` through `db._gate`, closing the raw `UPDATE findings SET data=?` that bypassed the
documented "single write chokepoint" and picking up `agent._triage` and `capture_finding_poc` for
free. Then the lane asked whether the three invariants it had just enforced actually protect the
proof, and read them: SCHEMA #6 normalizes `reproduction_steps`, SCOPE #8 refuses out-of-scope
targets, TRUTH #7 keeps a lead out of the confirmed table. **Not one of them reads `evidence`** — the
field `validate_confirmed` judges. Measured *after* the fix: PUT a gate-demoted row back with
fabricated prose, and `is_confirmed: True`, with no engine having issued a single request.

Generalising: **a chokepoint is only as strong as the fields its invariants inspect.** Three invariants
all passing is not coverage; it is three specific questions being asked, and every field nobody asks
about is still writable. Same family as the island pattern — registration is not invocation, and here,
gated is not inspected.

Two more things worth keeping:

- **Whitelist, not blacklist.** PUT is annotation-only against an explicit allowed set. A blacklist
  leaves every *future* proof field editable, which is precisely how this survived pass one. And a
  PUT-only fix would have been defeatable by DELETE+POST, so both routes were closed.
- **The design answer for Q-014**: operator confirmation is an **attestation on its own axis** —
  who, when, why — never a value of `confidence`. Letting an operator's own text satisfy
  `validate_confirmed` was rejected because that contract is a **substring match over prose**: it
  would award `confirmed` for vocabulary and teach people which words to type. The report now renders
  the attestation in its own column, naming the operator, the date, and *what machine proof is still
  missing*. Additive — an unattested lead renders byte-for-byte as before.

**What this costs, stated plainly:** manual findings now land under Unconfirmed Leads, confirmed
counts drop, and `risk_score` no longer takes severity from them. That is the intended direction.

**Two mutants survived the first outcome control, and both diagnoses are reusable.** M9/M10 survived
because the two mechanisms they mutated are *redundant* — killing either alone changes no outcome, so
an outcome assertion cannot discriminate them. M4 survived because the test lead carried no `impact`,
so the impact gap alone blocked promotion: **the test asserted the right outcome for the wrong
reason**, which is the exact shape of a test that will pass after the fix is deleted. Both repaired;
13 mutants, all killed.

---

## ★ WHAT BOUNDS RECALL, ANSWERED: SELECTION. 2026-08-14

After four of my hypotheses died, the harness that was built to discriminate them answered on its
first use:

```
exit_reason = step_cap_exhausted        309 steps against a cap of 220
85.5% of the recall shortfall was NEVER PROBED
detection on probed vulnerable cases    = 8.2%
```

**The next order of magnitude is selection, not oracles.** We do not fail to confirm what we test; we
never test most of it, and the run is cut off by a step cap it exceeds by 40%. Every engine, payload,
carrier and oracle improvement of the past week was optimising the 14.5% we reach.

**Falsified, in order, all mine**: payload repertoire · carrier delivery · parameter visibility ·
throughput · and now the stability-gate trade below. Five hypotheses, five measurements, five deaths.
The one that survived came from instrumenting the run instead of theorising about it.

**RETRACTION — the "we traded 9 findings for 0 FP" story was WRONG.** I recorded it yesterday as the
leading candidate. Measured: the 21 baseline sqli findings split 15 `error-recovery` / 6
`boolean-blind`; the 9 lost are 5 + 4; `quote_break_recovers` takes three integers so the gate cannot
reach it; and **the 4 eligible cases have baseline self-similarity 1.0000 and confirm WITH the gate on,
3/3 trials. The gate rejects 0 of 9. There was no trade.** The rate policy is also rejected — it is a
reactive 429/503 cooldown that can only *add* time, and the clock fell 64%.

**−3 IS REAL. Variance is zero.** Two full runs of frozen identical code: **jaccard 1.000, identical
seals, identical 309 steps / 3659 tool calls / 373 probed cases.** The only case separating them from
the sealed rerun is `BenchmarkTest00023` — the coin flip. Both predictions were written down before
the runs and both held.

**⚠ THE PUBLISHED BASELINE CANNOT BE RE-DERIVED, AND THIS CONTAMINATES A CLAIM I MADE.** The store
returns **29 findings / 27 cases / ldapi 5** for mission `ebd96f45`, against the ledgered 22/23 with
`ldapi 1`. No dedup explains it; no subset reproduces the seal. **On the store's numbers the
"ldapi 1 → 5 broadening" is ZERO and the loss is −8, not −3.** So the "class coverage genuinely
broadened" line I wrote is **unproven and possibly false**. Treat every comparison against `ebd96f45`
as suspect until its provenance is reconciled. Open.

## Q-040 REALLY FIXED — the reference must REPRODUCE, not merely resemble. 2026-08-14

The two-sample gate was defeated by run-structured alternation: two draws from an alternating source
agree half the time by construction. The fix requires the reference to reproduce **byte-identically**.

Chosen over more samples (alternation defeats consecutive draws) and over a variance floor (measured —
`00023`'s floor is ~0.9495 and the fires sat *at* it, a coin flip on the last decimal, plus a free
parameter). **Byte equality has no free parameter and fails closed.**

- **`00023`: FP/attempt 0.045 → 0.000**, every field, live negative control.
- **Capability cost on this lab: zero.** All five genuine confirmations still fire 3/3.
- Off-benchmark cost is real and deliberate: pages with per-response tokens are now declined rather
  than guessed at. No estimate offered, because none is available.

**The `00494` residual is PROVED UNDECIDABLE at the two-sample signature** — `(A, A, A, B)` arises
from both a genuine injection and a flipped alternation, so **no function of those strings can
separate them.** That is a proof, not a punt. Two additive optional arguments close it and both have
passing tests; the two-call-site patch is in the handoff rather than applied across an ownership line.

`test_sqli_boolean_noise_floor.py`: 4 passed / 3 xfailed → **9 passed / 1 xfailed.**

## Q-021B CLOSED — the fact survives a real mission, and outlives it. 2026-08-14

The producer landed, so the island is closed rather than authored. `_run_fingerprint` runs **one**
detection pass — `fp.detect()` yields evidence-carrying records, `fp.public_view()` projects the four
display keys — so the two cannot disagree and no second copy of the key tuple can drift. `recon`
**declares** `technology` at construction instead of creating it on first write.

**Proved live: producer 12/12 across four labs, oracle 3 at 10/10 across two real missions and one
real sqlite DB.** 5 facts, versioned 5/5, **CVE-eligible 0/5**.

Three things no stub could have shown:
- **PHP 5.5.9 and Apache 2.4.7 are long EOL. Apolaki records the version, quotes the header verbatim,
  and still says `cve_eligible=False`** — because the confidence ladder says a banner is LOW. *Emitting
  CVEs there would look more productive and be less honest.*
- Mutillidae's database-offline page produced `'and that the database username'` — **present** in the
  display path (unchanged by design) and **absent** from the facts with `reason=prose_leading_stopword`
  recorded, in one run.
- Juice Shop returned a real zero: zero facts *and* zero refusals.
- Warm start: mission 2 began with 5 facts already present, each keeping mission 1's `first_seen` to
  the microsecond while advancing `last_seen`.

`self.graph` is deliberately **not** written — that is the graph the planner reads, so technology there
would change which techniques get scheduled. Q-021E's job, and it would move numbers. A test pins it.

**The gate exemption was returned**: qualified dead-code back to exactly **37**, the pre-ticket
baseline, with nothing carrying the difference.

**Two mutants survived first and both mattered**: `recon-keys-not-declared` (the test said
`in (None, [])`, which passes whether or not the keys exist) and `warm-start-overwrites-instead-of-
merging` (indistinguishable *today* because `recon` is empty when warm-start runs — a latent trap, now
pinned). **41 mutants across the ticket, 41 killed.**

## ⚠ THE BLIND-SQLI ORACLE CONFIRMS ON WEAK-RANDOM NOISE — AT SCALE. 2026-08-14

Bigger than the recall drop, and it means **Q-040's stability gate is incomplete**. Three strict xfails
now pin it, each with a measurement:

1. **`BenchmarkTest00494` still confirms** whenever both reference samples land in the same run of the
   alternation — **fires on 3 of 4 form fields with the gate ON**.
2. **`BenchmarkTest00023`, a `weakrand` case, is claimed as CWE-89 boolean-blind.** The body carries a
   fresh PRNG value per response, and **the gate contributes nothing: FP/attempt 0.045 → 0.045.**
3. **It is not a rare coincidence — 9.4% of ordered triples over 123 observed-shape bodies satisfy the
   oracle.** A systematic false-positive mode.

This explains both wrong-class claims from the rerun in one mechanism, and it means the 100.0% loose
precision we just published is flattered by the loose convention. **A page that changes on its own can
confirm blind SQLi**, which is precisely what Q-040 was meant to prevent and only partly does. Do not
treat Q-040 as closed.

**Candidate (3) for the recall drop is DEAD.** Breaker RUN A: *the run does not converge, it exhausts
its budget.* So "it simply probed less before converging" is falsified — the run was budget-limited,
not fixpoint-limited. Two candidates remain live: the stability gate's precision trade, and the rate
policy reducing probe volume.

## Q-023 — ZAP now runs, and it is deliberately lead-only. 2026-08-14

**Proven by the artifact I demanded, not a unit test**: mission `49d413bb`, status complete,
**`run_zap` tool_call rows: 1**. Result: 0 current alerts, 187 retained alerts excluded. First ZAP
invocation in the platform's history — previously 0 across 150 missions and 25,619 tool calls.

**The judgement call, and it is the right one:** ZAP stays **opt-in and lead-only**. *Scanner
confidence cannot become deterministic Apolaki confirmation.* A ZAP alert arrives without the evidence
the proof gate requires, so it is structurally a lead that an Apolaki oracle must independently
confirm. The proof gate was **not** weakened to let alerts through.

**The control is absence-of-bypass shaped**: an enabled mission that finishes **without** a persisted
`run_zap` call now **fails visibly**. That is the check whose absence let this survive 150 missions.

No-DoS held under the new traffic: the acceptance sent exactly one request, observed
`429 Retry-After: 2`, **stopped all producers**, and returned with the shared cooldown active. All 19
benchmark artifacts and `owasp_bench.py` byte-identical; every `tools.py` change confined to
`_run_zap`, which no benchmark family invokes. 8/8 mutants killed.

**Still unexplained, and recorded as such**: the four July-26 missions that carried `enable_zap=True`
and produced zero `run_zap` calls. Targeted rescan remains unwired — it needs the Coordinator-owned
planner, and no off-limits file was touched.

## Q-021B — the version stops being computed and thrown away. 2026-08-14

`fp.fingerprint({'Server':'nginx/1.18.0'})` returns `nginx 1.18.0`; `_run_fingerprint` persisted
`['nginx']`. Now a durable **TechnologyFact**: vendor, product, component, version, confidence,
evidence, source, auth state, timestamps.

Design decisions worth keeping:
- **`confidence` is deliberately NOT a parameter.** It is derived by `version_confidence(source)` and
  fails closed to LOW — **a detector cannot assert its own trustworthiness.**
- `tech_fact_key()` = `host|vendor|product|component` — **identity, never the version.**
- `_KNOWN_PRODUCTS` is *derived* from the detection tables, so **the gate cannot drift from its
  detector**.
- Written to the **existing `component` node kind** with detail as props, following `observe_param`'s
  instinct; graph confidence stops *below* `CONFIRMED` and `tested` stays `False` — **detection is not
  a test**.
- `intel_registry` deliberately untouched, with reasoning: it stages *internet intel*; a
  TechnologyFact is a first-party observation. **Two trust models answering one question is the defect
  Q-021A existed to fix.**

**A control initially passed for the wrong reason** and the lane caught it: `M2_key_drops_product`
survived because the nginx/PHP case was discriminated by the `_VENDOR` field, so the key could drop
`product` entirely and stay green. Fixed with two products that have no vendor hint. **28 mutants, 28
killed.**

A second defect found in the same call: `_POWERED` yields `'a MultiJuicer Kubernetes cluste'` (31
chars — the `{2,30}` bound plus its leading character) and `'nothing on.'`.

**No benchmark number moved — measured, not argued**: 3927 cases compared across 17 header sets × 11
cookies × 21 bodies, **0 differences** — and the lane verified its own differential harness *could*
report a difference, because a negative control that cannot fail proves nothing.

**The producer half is pending**: `tools.py:_run_fingerprint` was Codex's this cycle, so
`recon["technology"]` is not yet populated in a live mission and the chain below it is inert. The
patch is written up in `docs/handoff/tech_intel.md` §4 rather than applied across an ownership line.

## B-020 — JavaScript/Node in the code-assisted lane. Tier 3. 2026-08-14

Third dialect. Weak hash, weak randomness, weak crypto — same finding shape and lane markers as Java
and Python. **26 adversarial controls, all failing before the dialect existed. No accuracy percentage
is claimed and none may be: there is no Node ground-truth corpus, so this is Tier 3.**

**The masker was the ticket, and the regex literal is JS's floor-division trap — controlled in BOTH
directions**: `/md5|sha1/.test(x)` must not read as a call site, *and* `a / b / c` must not blank the
code between the slashes. Template literals mask their text and keep `${…}` as code, exactly as the
Python f-string handling does.

**Q-041 shipped as a precondition rather than as a later defect.** Aliased `require` resolves on
arrival — `const c = require('crypto')`, `node:crypto`, destructured and renamed-destructured, all
three ESM forms. And because widening the receiver must not widen the verdict,
**`require('crypto-js')` — a different library with a different API — resolves to nothing.**

**A dialect difference recorded rather than copied**: the Juliet bare-`AES` disagreement **does not
transfer.** Java's `Cipher.getInstance("AES")` silently means ECB; Node requires an explicit mode and
throws without one, so no implicit-ECB inference is made and a control pins that. `createCipher` is
reported on the **API**, not the algorithm — it derives its key with one unsalted MD5 round, so
`aes-256-cbc` through it is still wrong.

**Real-world sweep, 108 files of Juice Shop: 7 findings, all true call sites, zero misidentified.**
The MD5 at `insecurity.ts:41` and `Math.random()` as the JWT secret at `:53`. Both mandatory negative
controls confirmed in the wild — `crypto.randomBytes` in `utils.ts` not flagged, and
`createHmac('sha256')` at `insecurity.ts:42` **not flagged on the line immediately after the MD5 that
is.** Adjacent lines, one file, opposite verdicts, on code nobody wrote for this test.

**A duplicate the dialect exposed**: `review()` emitted the substring lead *and* the confirmed
call-site finding for the same line — one defect described twice at two confidences, which a client
cannot untangle. The lead now stands down by line where the precise analysis answered, and still fires
for languages the dialects do not cover.

**Two pieces of self-discipline worth keeping as standards:**
- The lane caught itself **mounting the scratchpad — which held the answer keys — into the scanner**,
  and redid the sweep with 0 key files reachable. Blindness is a property you verify, not assume.
- Artifacts were **not** byte-identical this time (`files_scanned` 2763 → 2766), so it made the
  **weaker accurate claim** instead of reusing the stronger phrasing from Q-041/Q-042. Zero differing
  case rows, every number reproduced in a `--network none` container: Java 36.4%, Python 21.4%, all
  four categories 100.0%/0.0%.

`test_source_lane.py`'s "javascript stays out of the lane" assertion was **inverted, not deleted**.

## WHOLE-PRODUCT RERUN — recall did not move, it went DOWN. 2026-08-13

The number the week was aimed at. Claims sealed in history at `8700c99` **before** the key was read;
scored in a `--network none` container; the scorer recomputes the sha256 and refuses to score if the
claims moved. Result at `689b3c9`.

| metric | baseline `ebd96f45` | rerun | delta |
|---|---:|---:|---|
| **recall** (loose) | **1.55%** (22/1415) | **1.34%** (19/1415) | **−0.21 pt** |
| recall (class-matched) | not computed | 1.20% (17/1415) | — |
| **precision** (loose) | 95.7% (22/23) | **100.0%** (19/19) | **+4.3 pt** |
| precision (class-matched) | not computed | 89.5% (17/19) | — |
| elapsed | 5329 s | **1893 s** | **−64%** |

Like-for-like is the loose pair, because the standing baseline is a loose number: **1.55% → 1.34%.**

> **BOTH CLAIMS IN THIS TABLE ARE WRONG, corrected 2026-08-14.** The baseline column is undercounted:
> re-scored, `ebd96f45` is **26 TP / 27 claimed / 96.3% / 1.84%**. So the true delta is
> **1.84% → 1.34%**, a loss of **−9 cases, not −3** — the regression is three times what was
> published. And the "class coverage broadened, ldapi 1 → 5" line immediately below is **zero**: the
> baseline already had all five, and they were only ever counted as one. The paragraph is left intact
> because it is the reasoning that has to be visible for the correction to teach anything.

**Class coverage genuinely broadened — and it still lost.** ldapi **1 → 5**, xpathi **0 → 1**, exactly
what the body-parameter work predicted, since those sinks take body input only. **The entire loss is
sqli: 20 → 11.** Net −3.

**Three candidate causes, ALL UNVERIFIED, listed so none is adopted by default:**
1. the blind-SQLi stability gate is precision-motivated and would reject exactly the marginal blind
   confirmations that made up much of the baseline's 20 — i.e. we may have **traded ~9 sqli findings
   for 0 FP and it worked as designed**;
2. the rate policy cuts requests per unit time, and probe is where sqli lives;
3. the run simply probed less before converging.
(3) is cheapest to discriminate and dies immediately if the run hit a fixpoint rather than a budget —
**but the artifact records neither step count nor exit reason.** That harness gap is the first thing
to close before the next rerun.

**Two wrong-class claims worth chasing**: `BenchmarkTest00023` (key `weakrand`, we claimed sqli — an
sqli oracle firing on a case with no sqli, **the same shape as `00494` and still live**) and
`BenchmarkTest00407` (key `cmdi`, we claimed dom_data_manipulation). The 100.0% vs 89.5% gap is the
honest cost of the loose convention.

**Caveat the lane raised against its own number**: one run, stateful lab, and the baseline was taken
through the API on a baked image. The class-mix shift is large enough that −3 should not be treated as
a stable delta without a repeat. Determinism was verified for VAmPI, **not** for this target.

**MY ORDERING CALL WAS WRONG.** I put schema above throughput and wrote at the time: *"if schema lands
and recall still doesn't move, then throughput was the binding constraint all along and I'll have cost
us a cycle."* Schema landed; recall did not move. But throughput was **also** measured and ruled out.
So neither hypothesis was the constraint — and the class-mix shift shows schema *worked*, it just did
not convert. The honest position is that **we still do not know what bounds whole-product recall**,
and three of my hypotheses (payload repertoire, carrier delivery, parameter visibility) are now
falsified by measurement.

## Q-044 CLOSED — the SAST lane is reachable from a real mission. 2026-08-13

Island number six is closed. `/engage` now accepts `source_root`, and the proof is the one that was
demanded: **a real production mission persisted a confirmed CWE-327 finding** carrying
`provenance: source-derived`, `lane: code-assisted`, `control_status: not_applicable` — not a harness
call, not a unit test.

So **61.1% is no longer a harness-only figure.** It still may never be compared against a published
DAST score, and it is still labelled code-assisted (SAST) at every surface — but a client engagement
can now invoke the capability behind it.

**No benchmark number moved, and that is the point of this ticket**: artifacts byte-identical before
and after — Java SAST 560 TP / 855 FN / **0 FP** / 1325 TN at macro 36.4%; Python SAST 188 TP /
264 FN / **0 FP** / 778 TN at macro 21.4%. Wiring, not detection. Six semantic mutants killed.

The controls that make it trustworthy are absence-of-bypass shaped, which is the form that would have
caught the original island: **malformed analyser output cannot enter a report as DAST**, and legacy
`/codereview` behaviour is byte-unchanged for existing callers — that endpoint also serves source the
recon phase reconstructs from a target's own leaks, and that path had to keep working. Missing source
reports **"no source provided"** and is recorded as *skipped*, never as a clean result: an absent
input is not a passing scan.

Unsupported source-analysis categories stay honestly at zero recall.

## Q-031 CLOSED — an API spec's typed body parameters now reach the planner. 2026-08-13

VAmPI, full mode, identical seed, two consecutive after-runs identical on every field:

| | before | after |
|---|---:|---:|
| body params delivered to the planner | **0** | **9** |
| endpoints made schedulable | **0** | **5** |
| graph params by location | `{}` | `{'body': 9, 'path': 4}` |
| `run_stored_xss` / `run_csrf` / `run_race` | **0 / 0 / 0** | **5 / 3 / 3** |
| `run_form_cmdi` | 10 | 15 |
| tool dispatches | 100 | 116 |

All nine declared body parameters delivered. Three engine classes went from **never firing** to 5/3/3.
The DVWA half proved it on HTML forms; this is the half that matters for recall, because 100% of an
API's parameter surface was previously invisible.

Built in the smallest places that could hold it: one line in `tools.py` keeping the parsed spec; a
**new** `surface.operations_from_openapi()` beside the untouched URL importer (which reads only
`in == "query"`, collapses method to a bool and returns bare strings); and `_project_spec_params()`
minting through the **same** `observe_param` writer and `has_param` edges the form producer uses.
That reuse is the payoff for putting `location` on the param rather than inventing a `schema` kind.

**A mutant survived and exposed a hole in the lane's own tests.** Deleting the `tools.py` line that
persists the spec killed *no* test — the end-to-end test injected `recon["openapi"]` by hand and never
exercised the producer. **A registered producer with no test that runs it is the island shape this
very ticket exists to find, reproduced inside its own fix.** Fixed by driving `_fetch_openapi` with a
stubbed transport; the mutant now dies.

## Q-041 / Q-042 CLOSED — and zero xfails remain. 2026-08-13

All four strict markers removed **by fixing what they pinned**, which is the only legitimate way.

**Q-041 — the binding was computed and discarded.** `_py_imports` produced `modules['r'] = 'random'`
and every rule then matched a hard-coded literal receiver, so `from random import getrandbits as g`
worked while `import random as r; r.getrandbits(32)` was invisible. Widening the receiver must not
widen the verdict, so the controls are the deliverable: `import numpy.random as r` still reports
nothing, and **`r.SystemRandom().getrandbits(32)` — the 113 clean twins, through an alias — is still
a CSPRNG.**

**Q-042 — fixed by binding, not by a longer word list.** Two structural facts: an assignment is at
**paren depth 0**, so `f(token=x)` is a keyword argument and not an assignment; and a compound
identifier means its **head noun**, so `token_expiry` is an expiry while `expiry_token` really is a
token. The Java twin `_CLOCK_TOKEN` had the identical defect and took the identical fix.

| check | result |
|---|---|
| benchmark cost | **0 cases** — re-scan artifacts **byte-identical** to the sealed trustbound run, 0 differing cases of 2740 and 1230 |
| in-the-wild FP | **gone** — CWE-337 across 5150 files of the container's own Python goes **1 → 0**, and the one removed is exactly `token=` at `anthropic/lib/credentials/_workload.py:346` |
| true positives lost | **none** |

**Byte-identical artifacts are a stronger claim than an unchanged score**: the score *cannot* have
moved, because the scorer's input did not.

**Q-041's measured gain is zero on all four corpora, and that is the correct answer.** Only two stdlib
files alias these modules, and the sole aliased digest call is `_hashlib.new(digestmod, …)` in
`hmac.py`, where the algorithm is a caller-supplied variable — no verdict is available and reporting
nothing is right. The lane checked those two files specifically rather than accepting "0 new findings"
as evidence the fix worked. **A fix proven by construction, not by a corpus that happens to exercise it.**

## trustbound — MAPPED, 100.0% TPR at 0.0% FPR on both suites. 2026-08-13

The category deliberately left unmapped now earns the mapping, and the mutant is the proof — not the
score.

| suite | TP | FN | FP | TN | TPR | **FPR** |
|---|---:|---:|---:|---:|---:|---:|
| Java v1.2 | 83 | 0 | 0 | 43 | 100.0% | **0.0%** |
| Python v0.1 | 18 | 0 | 0 | 19 | 100.0% | **0.0%** |

Code-assisted macro: **Java 27.3% → 36.4%**, **Python 14.3% → 21.4%** — exactly additive (100/11,
100/14). crypto/hash/weakrand unchanged at 100.0%/0.0%. Official macro equals product macro on both;
cross-family FPs zero.

**M1 is the result.** The plausible implementation — *flag the sink* — has **identical recall** (83
and 18 TPs, every positive assertion passing) and scores **0.0%**, because it flags all 43 Java and
all 19 Python clean twins, and costs the product macro half its value via 275 / 227 cross-family FPs.
The corpus supplied that control free: **619 of 2740 Java cases carry a session sink and only 126 are
`trustbound`** — the rest is `rememberMe` boilerplate storing a class name and a `SecureRandom`
output. A sink-matcher passes every positive test and is worthless.

**The standing claim was corrected while implementing against it.** Collection laundering: confirmed
and *understated* — the clean twin reads the **tainted** key first, so "does `get("keyB")` appear"
flags both twins. Constant-folded ternary: confirmed, sharpest discriminator. **StringBuilder: WRONG
for this category** — all 19 are built from `param`, so it is a propagator, and treating it as a
launderer would cause false *negatives*. Encoders were pre-registered as non-sanitizing in `39573bc`
**before any key was fetched**; the key agreed, and treating them as sanitizers would have cost 19 TPs.

Two defects and a setup error the measurement found:
- **Arity** — `thing.doSomething(param)` inlined into the file's own `doSomething(request, param)`,
  binding taint to the wrong parameter. All 16 first-run misses were this one shape; fixing it took
  Java 80.7% → 100.0%.
- **`merge_summaries` treated "undecided" as agreement**, letting one accidental constant helper vouch
  for every same-named method tree-wide.
- **A harness error worth more than either**: a first export omitted `src/main/resources`, so
  `properties_resolved` was 0 and every `getProperty(key, DEFAULT)` fell back to its literal — reading
  as crypto 23.3% FPR and hash 69.0% TPR **in two categories the change never touched**. A row-for-row
  diff over 2763 files showed **0 code differences**, which proved the code innocent and sent the hunt
  to the harness. **Check the resolved-input count, not just the file count.**

`test_source_lane.py`'s "trustbound stays unmapped" assertion was **inverted, not deleted** — the
mapping may exist only while a discriminating detector does.

## Typed parameters — the planner could only ever see a URL. 2026-08-13

Q-031 built and measured. Two defects, both the drop-at-a-handoff shape, each with its own control.

**1. No producer could write a non-query parameter.** A `param` node could only ever *mean* a query
parameter. `crawl.extract_forms` already returns each field's name, default value and input type into
`tools.recon["forms"]` — the knowledge existed and had nowhere to be recorded.

**2. The graph→planner handoff dropped forms entirely — unpredicted.** `_graph_primary_state` returned
a recon dict keyed exactly `['domain','live_hosts','subdomains','target']`. Every form-driven planner
branch reads `state["recon"]["forms"]`, so in the deterministic executor it read `[]` regardless of
what the crawl captured: **2 forms captured, 0 delivered.** `run_stored_xss`, `run_csrf` and
`run_race` **never fired at all**. Three other form engines survived only via unrelated fallback
branches that re-discover forms from login-ish paths — **which is exactly what masked the hole.** A
test asserting "form engines run" would have passed the entire time.

Measured on DVWA (full mode, warm):

| | before | after |
|---|---:|---:|
| forms delivered to the planner | **0** | **1** |
| body params delivered to the planner | **0** | **4** |
| graph params by location | `{'query': 0}` | `{'body': 4}` |
| `run_stored_xss` / `run_csrf` / `run_race` | **0 / 0 / 0** | **1 / 1 / 1** |
| tool dispatches | 111 | 115 |

`+4` dispatches accounts for exactly the new work; two consecutive runs identical. Pre-fix: 10 of 11
new tests failed (the survivor is a key-stability guard that must pass both sides); 5 mutants, 5
killed.

**An anomaly chased rather than reported**: a cold pass showed forms 2→1 and dispatches 36→23, reading
as a regression. It was DVWA's own state — the cold run hit `/setup.php` with a fresh DB. Warm, the
change is strictly additive.

**Still blocked, one line**: `_fetch_openapi` (`tools.py:3766-3781`) garbage-collects the parsed spec,
so VAmPI's 9 body params stay invisible. `self.recon.setdefault("openapi", {})[base_url] = spec` feeds
them through the path already built and tested. `surface.py:94-133` separately needs `requestBody` /
`in: body` read with the method preserved.

## Throughput — DIAGNOSED, and the answer is "do not build it". 2026-08-13

The 8.5 s/tool-call figure has been quoted for three days and was never diagnosed. Now it is, and the
verdict is **no production change**.

```
TCP 2.673 ms · TLS 3.590 ms                          <- not the network
browser bundle   47.056 s/URL serial -> 14.674 s/URL bounded   3.207x
non-empty DOM    13.865 s -> 6.138 s, identical 4-finding SHA across SIX runs
mission probe    22.465 s -> 9.036 s                            2.486x
mission WALL     177.370 s -> 187.102 s   <- FLIPPED WITH RUN ORDER
```

**Serialisation was the browser-probe bottleneck — and the bounded implementation was already present
at the baseline.** The 2.5–3.2× is real at the component level and **vanishes end to end**, because
`katana`, `subfinder`, `wayback` and `crtsh` dominate mission variance. Codex made no production
change and explicitly does not claim a mission speedup. That restraint is the result.

**This closes the "recall is bounded by wall-clock" story as stated.** It is bounded by *recon tool*
wall-clock, not by probe concurrency — which is a different ticket and a much less attractive one.
Combined with the schema finding (100% of VAmPI's parameter surface invisible), the evidence now says
recall is limited more by **what we cannot see** than by **how fast we probe it**.

## Q-043 — the no-DoS promise was not implemented, and I said it was. 2026-08-13

Codex's rate-limit control **failed**: with `Retry-After: 2`, both widths sent 47 requests and width 6
started 14 inside the window. Verified independently — **`Retry-After` appears nowhere in `agent/`**,
zero grep hits, and `tools.py:3296` (which I cited as the enforcement point in five lease prompts) is
subfinder argument handling.

I fabricated that citation and propagated it. **A Coordinator citation is a claim, not evidence** —
file:line references in briefs get verified before repetition, and a lane that cannot reproduce a
cited behaviour should treat the citation as the defect. Queued as Q-043.

## Q-040 CLOSED — an unstable page can no longer confirm blind SQLi. 2026-08-13

The GET and POST blind paths now issue a second identical baseline request; a failed or unstable
baseline cannot confirm. Error-based, quote-recovery, UNION and timing oracles untouched.

**Full SQLi denominator, 504 cases (272 vulnerable / 232 clean):**

| run | TP | FN | FP | TN | TPR | FPR |
|---|---:|---:|---:|---:|---:|---:|
| sequential before | 180 | 92 | 0 | 232 | 66.2% | 0.0% |
| sequential after | 180 | 92 | 0 | 232 | 66.2% | 0.0% |

**Byte-identical artifacts**, sha256 `32a06263b3a8eb64cb4a546b5b218213002e8d07587c6383e93a91dd116bae37`.
Exactly the predicted outcome — benchmark pages are static, so stability sampling costs nothing there
while closing the real-world false-positive path. Added cost: one GET per query-bearing endpoint, one
POST per tested form field. **The strict xfail is now a genuine pass; Tier-3 is 33/33.**

**The residual, recorded rather than tuned around.** Adversarial 8-shard runs were volatile: pre-fix
2 FP, post-fix 1 FP, on *different case IDs*. The remaining case **could not be reproduced even with
64 concurrent direct replays**, so it was excluded from the authoritative comparison and documented.
That is the correct handling — an unreproducible result is not evidence in either direction — but it
means **concurrent-load blind SQLi still has an unexplained FP mode.** Open, not closed.

Three semantic mutants killed by their exact assertions: inverted stability condition (stable
vulnerable finding disappears), sample count 2→1 (request-sequence assertion fails), deleted rejection
branch (historical unstable case returns True).

## Q-031 row 4 — schema: 100% of VAmPI's parameter surface is lost. 2026-08-13

MEASURED by the orchestration lane while building the rediscovery trigger table. The architecture
audit predicted schema had no representation; the number is worse than "a gap": **every parameter on
VAmPI's surface is invisible to the planner**, because typed body parameters have nowhere to live in
the graph. This is the single largest named blind spot in the discovery model, and it explains why
`run_bfla` only ever gets scheduled for query-parameterized endpoints.

Also landed: `41b3780` closes the `graph_action` UI island the lane found in its own U1 change — and
the degraded path turned out to be worse than the missing one.

## NIST Juliet Java 1.3 — first Tier-1 suite beyond OWASP Benchmark. 2026-08-13

Pinned: SARD test-suite 111, archive **76,798,417 bytes**,
sha256 `d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60`. Blind scan 131 Java files;
scored scope **119 testcase files / 329 direct `bad()`/`goodN()` methods**; **0 skipped within the
denominator**. Two fresh runs produced byte-identical 131-row checkpoints and identical scores
(checkpoint sha256 `fea6db9e…`).

**CODE-ASSISTED (SAST) ONLY. This is not a DAST figure and not a whole-suite figure.**

| CWE | TP | TN | FP | FN | total | precision | recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| CWE-327 | 34 | 0 | **60** | 0 | 94 | 36.17% | 100% | 53.13% |
| CWE-328 | 51 | 90 | 0 | 0 | 141 | 100% | 100% | 100% |
| CWE-338 | 34 | 60 | 0 | 0 | 94 | 100% | 100% | 100% |
| **overall** | **119** | **150** | **60** | **0** | **329** | **66.48%** | **100%** | **79.87%** |

**Recall is 100% and this is the first non-zero FPR the project has recorded.** Both facts matter and
neither should be smoothed over.

**The 60 false positives are a GROUND-TRUTH DISAGREEMENT, not a detector bug — and the disagreement
was preserved rather than special-cased.** Every one is a Juliet "good" control using bare
`Cipher.getInstance("AES")`. Juliet labels those fixed; Apolaki reports them, because in Java bare
`AES` resolves to **`AES/ECB/PKCS5Padding`**, and ECB is a real weakness. On the security merits
Apolaki's call is defensible and arguably more correct than the label.

**We are not changing the detector to match the label, and we are not changing the label.** Silencing
bare-AES would make the number prettier and the tool worse; editing Juliet's expected results is
forbidden outright. The honest position is to publish 66.48% precision with the disagreement stated —
a scanner that argues with a 2017 benchmark about ECB and can show its reasoning is worth more than
one that scores 100% by agreeing. **Any future "fix" that recovers those 60 points by suppressing
bare-AES detection is to be rejected on sight.**

**109 Juliet CWE families are explicitly UNSUPPORTED by this run** and stay that way until a real
capability covers them. Unsupported is a status, not a gap to paper over.

**The B-002 contract held unchanged under a genuinely foreign suite** — checkpoint/resume,
seal-before-key, raw evidence, dual scoring, full B1 metrics and unresolved-case handling all worked
without modification. That was the actual point of running Juliet: the contract had zero consumers,
and in this codebase a mechanism with no consumer is the shape that has shipped inert four times.

## U1 — MEASURED. The wiring works; the capability is +0 findings. 2026-08-12

The Q-030 gap, as a number from a real run rather than an audit reading. VAmPI, deterministic
executor, identical seed, before = `92e678b^`, after = `92e678b`:

```
before  ranked_dispatched=0  still_open=4  tool_dispatches=52  untested=33
after   ranked_dispatched=4  still_open=0  tool_dispatches=56  untested=25
```

**The graph ranked four actions and ZERO reached dispatch** — they were still sitting unexecuted when
the scan ended. That is `architecture.md` 1.8, measured. After: all four dispatch, `tool_dispatches`
rises by **exactly 4** (so the graph actions are the only new tool calls, which is what makes the
outcome diff attributable), and the ranked list **drains to zero** — `apply_result` marks the nodes
tested, so the loop reaches a fixpoint instead of re-recommending forever.

All four were `cross_user_test -> run_bfla` on object endpoints **the tool planner never covers**: it
schedules `run_bfla` only for PARAMETERIZED endpoints and these carry no query params. Surface the
graph could name and the planner could not.

**Reported as two numbers on purpose, so they are never conflated: wiring 0 -> 4 dispatched;
capability +1 lead, +0 confirmed findings.** Q-030 is complete as wiring. It is not yet a capability
win, and the honest reading is that the ranking is correct while the surface it opened did not yield
a confirmable finding on this target.

## xss carrier — MEASURED +0, and the diagnostic is what makes it an answer. 2026-08-12

120 of 455 xss cases, seed 1337, paired per case against the sealed
`owaspbench_java_v12_DAST_FULL_20260811` artifact. `getsource` gate passed, blind budgets zeroed so
no result depends on case position, sha256 sealed before any key was fetched.

```
PAIRED cases 120 | before 27 | after 27 | NEW 0 | LOST 0 | errors 0
```

**Header names were discovered on 18 of the first 60 sampled pages — so the carrier RAN on roughly 30%
of cases and still confirmed nothing.** That distinction is the whole value of the result: this is not
delivery that never happened, it is delivery that arrived and proved nothing, with the breakout oracle
declining every header-carried reflection it saw — the oracle behaving as specified.

**Carrier delivery is now falsified as the axis on both categories**, exactly as blind-vs-echo was
falsified on cmdi. Two hypotheses tested and rejected with measurements rather than argument. Do not
invest further in carriers or payload shapes for cmdi/xss without a new, differently-grounded reason.

## cmdi probe repertoire — MEASURED +0, and it falsified the brief. 2026-08-12

**Full category, 251 cases, per-case diff against the sealed baseline: before 36, after 36, NEW 0,
LOST 0, errors 0.** The lane's own 50-case hand-sweep predicted +5. The engine delivered +0 and the
lane reported the engine number.

**The Coordinator's hypothesis was wrong, and this is the correction.** The brief said blind/time-based
and OOB were the untested shapes on cmdi. Measured: both use the **same shell separators** as the
output payloads, so they need the **same shell reach**. *Blind-vs-echo was never the axis of failure on
cmdi — shell reach was.* Do not re-try blind or OOB on this category expecting a different answer.

Two measured causes, both **delivery**, not payload:
1. The hand-sweep injected into a parameter named for the test case across four carriers; the engine
   uses form-discovered fields plus two discovered headers and **has no cookie carrier**.
2. The dominant echoing sink is `Runtime.exec("echo " + bar)`, which tokenises argv and prints `id`
   back as a literal string.

**The remaining headroom is CARRIER DELIVERY, not payload repertoire** — reached independently on both
categories. cmdi has no cookie carrier and only two discovered headers; **87 of 455 xss cases are
header-carried.** That is the next ticket, and it supersedes "add more payload shapes".

**Three shapes discarded, each with the measurement that killed it.** The most instructive scored
**20/50 — the best number this lane produced — and was a reflection detector**: the PATH
env-differential compares two probe values that are different strings, so *any* echoing endpoint
satisfies it. Same defect as the retracted 69.2% traversal oracle, caught before it shipped.

**A self-caused defect, self-caught:** the blind-timing latch was bounded once per *process*, and the
harness uses one registry for 251 cases, so it was spent after 6 endpoints. A case at position 150
reported empty while the same case in a short run confirmed. **A result that depends on position in
the run is not a measurement** — no suite figure was published from those runs, and the latch is now
per-endpoint with an explicit budget.

**A harness property recorded so it is never read as evidence:** the native collaborator correlates
in-process, so OOB **structurally cannot confirm** from the CLI harness. That zero says nothing about
any target.

FPR untouched — no confirmed finding was added on any case, so 0.0% stands trivially.

Caveat the lane flagged rather than buried: the seal-and-score-in-isolation step was not completed,
because the run it would have scored is the one the lane argued is not defensible. The conclusion
rests on the per-case diff against the already-sealed baseline artifact.

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
