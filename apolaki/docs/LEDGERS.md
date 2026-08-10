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
| 08-10 | `57afc3f` | *pending* | S11c relative links + robots/sitemap |

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
