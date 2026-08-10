---
name: benchmark-score
description: The honest protocol for scoring Apolaki against any benchmark (OWASP Benchmark Java v1.2 / Python v0.1, WAVSEP, Juice Shop scoreboard, Natas, GinAndJuice blind recall). Trigger on "score", "run the benchmark", "what's our number", "did we improve", "TPR/FPR", "compare to ZAP", or before quoting ANY percentage. Enforces macro-averaging over all suite categories, blind sealing before the answer key, measured baselines, and peer comparison against real published figures — the four places this project has produced a wrong number.
---

# Benchmark scoring — the honest protocol

Every wrong number this project has published came from one of four mistakes. This skill exists to
make all four impossible. Ledgers: `docs/LEDGERS.md`, `docs/benchmarks/PEER_BASELINES.md`.

## Rule 1 — Macro-average over ALL suite categories. Always.

`Score_c = 100 x (TPR_c - FPR_c)` per category, then the **unweighted mean over every category in
the suite** — including categories we score 0 on. That is the BenchmarkUtils method and it is the
only figure comparable to a published one.

- Micro/pooled averaging is **not** the official method. Do not report it as the score.
- **Never narrow the denominator.** Dropping the categories we cannot see is how 30.5% got reported
  as 58.1%. If a subset figure is genuinely useful, label it explicitly as a subset and give the
  macro number first, in the same sentence.
- Java v1.2: 2740 cases, 1415 vulnerable / 1325 clean, **11 categories**.
- Python v0.1: 1230 cases, **14 categories**.

## Rule 2 — Seal before you look

Blind runs only. Compute the sha256 of the run artifact and record it **before** fetching the answer
key. A score produced after seeing ground truth is not a measurement.

## Rule 3 — Measure the baseline, then measure again

Never claim an improvement without a before number produced by the same harness on the same suite.
"It should help" is not a result. If the after-number is worse, that is the result — write it down.

## Rule 4 — The harness number is not the product number

Two different tracks, tracked separately in `docs/LEDGERS.md`:
- **harness** — `agent/owasp_bench.py` driving engines directly at known case URLs.
- **whole-product** — a real mission with recon, crawl, planner, proof gate.
They diverge wildly (harness 41.3% vs a real mission returning zero findings, once). Say which one
you are quoting, every time.

## Rule 5 — Peer figures come from raw artifacts, never from a summary

A fetched summary once invented a ZAP per-category table whose totals did not match the suite size.
Download the raw CSV, recompute, and store it under `docs/benchmarks/`. Sanity-check totals against
the known case count before believing anything.

Standing peer baselines (recomputed from raw, in `PEER_BASELINES.md`):
| Tool | Official macro |
|---|---|
| OWASP ZAP | 17.99% |
| Best published DAST (HCL AppScan, ARES 2022) | 26% |
| 11-tool mean | ~11% |

## Rule 6 — State the ceiling honestly

Large parts of OWASP Benchmark have **no external signal** (Java: crypto 246, hash 236, weakrand
493, trustbound 126 = 1101 SAST-only cases). Black-box tools score 0.00% on them; the 11-tool mean
is 0.0%. 100% is not reachable black-box. Say so, and say what would be needed (a declared IAST
lane), rather than quietly excluding those categories.

## Procedure

1. Read the last entry in `docs/LEDGERS.md` for the current number and how it was produced.
2. Confirm the target lab is up and reachable **from inside the agent container**.
3. Run the harness with per-case checkpointing so a kill is resumable.
4. Seal the artifact (sha256, recorded).
5. Score: per-category TPR/FPR, then the macro mean over all suite categories.
6. Append to `docs/LEDGERS.md`: date, track, macro score, FPR, per-category table, what changed
   since the previous entry, and the artifact hash.
7. Compare to the peer table. If we beat a peer, say by how much on the same denominator.
