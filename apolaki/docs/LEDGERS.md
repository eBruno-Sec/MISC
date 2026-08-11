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

**NOT YET VERIFIED, and it is the whole question:** whether those 21 sqli hits land on *vulnerable*
cases or *clean* ones. The finding count is not the score. The oracles involved are two-sided
(`boolean-blind` compares a true-condition against a false-condition response; `error-recovery`
compares against a recovery baseline), which is a reason for optimism and not evidence. **Do not
quote 25 as an improvement in accuracy until it is scored against the answer key with the blind-seal
discipline** — and score it with cross-family false positives counted, per the retraction above.

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

## Standing honesty constraints

- **100% is not reachable on the black-box lane.** crypto + hash + trustbound = 608 Java cases with no
  externally observable signal. ZAP scores 0.00% on all three; all 11 tools in the published study
  average 0.0%. Those need the runtime/IAST lane, and that result must be labelled IAST, not DAST.
- **Never narrow the denominator to raise the number.** The macro divides by every category the suite
  has, unmeasured ones included as 0.
- **Leads are not detections.** Score only gated-confirmed rows.
- **An unmeasured case is not a miss** — it goes to `unscored`, never into a rate.
