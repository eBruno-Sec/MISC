# Published DAST baselines — OWASP Benchmark Java v1.2

Peer numbers Apolaki is measured against. Every figure here is either recomputed from a raw artifact
(Grade A) or taken from a peer-reviewed full-suite study (Grade B). Nothing is quoted from a vendor page.

## Grade A — recomputed from the official raw artifact

`peer_owasp_zap_v1.2_raw.csv` is OWASP's own published per-case ZAP scorecard (2740 rows, results
generated 2016-09-19). Recomputed locally with the official method — per-category TPR-FPR, then
MACRO-averaged over all 11 categories:

| category     | TP | FN  | FP | TN  |   TPR |  FPR |  score |
|--------------|---:|----:|---:|----:|------:|-----:|-------:|
| securecookie | 36 |   0 |  0 |  31 |100.0% | 0.0% | 100.0% |
| cmdi         | 44 |  82 |  0 | 125 | 34.9% | 0.0% |  34.9% |
| sqli         | 94 | 178 |  1 | 231 | 34.6% | 0.4% |  34.1% |
| xss          | 71 | 175 |  0 | 209 | 28.9% | 0.0% |  28.9% |
| crypto       |  0 | 130 |  0 | 116 |  0.0% | 0.0% |   0.0% |
| hash         |  0 | 129 |  0 | 107 |  0.0% | 0.0% |   0.0% |
| ldapi        |  0 |  27 |  0 |  32 |  0.0% | 0.0% |   0.0% |
| pathtraver   |  0 | 133 |  0 | 135 |  0.0% | 0.0% |   0.0% |
| trustbound   |  0 |  83 |  0 |  43 |  0.0% | 0.0% |   0.0% |
| weakrand     |  0 | 218 |  0 | 275 |  0.0% | 0.0% |   0.0% |
| xpathi       |  0 |  15 |  0 |  20 |  0.0% | 0.0% |   0.0% |

**ZAP official macro = 17.99%.** Invariants check out: 2740 cases, 1415 vulnerable, 1325 clean.

ZAP scores EXACTLY ZERO on seven of eleven categories, including ldapi, xpathi and pathtraver.

## Grade B — Lavens et al., ARES 2022 (11 DAST tools, full 2740-case suite)

HCL AppScan 10.0.4 **26%** | Arachni 1.5.1 **20%** | ZAP 2.10.0 **18%** | Burp Pro 2021.2.1 **16%** |
Rapid7 InsightAppSec **12%** | CrashTest **11%** | Qualys WAS **8%** | Skipfish **7%** | Detectify **4%** |
Wapiti **2%** | Nessus Pro **1%**. **Mean ~11%.**

Per-category DAST means: xss 43.6 | sqli 25.9 | cmdi 22.1 | ldapi 14.1 | securecookie 8.5 |
pathtraver 7.2 | xpathi 4.8 | trustbound/weakrand/hash/crypto **0.0**.

Not Grade A: no raw per-case output, no target commit, and the companion thesis shows several scanners
were run with split categories, multiple profiles and manually merged results. Treat as tuned profiles.

## The bar

- **Beat 19.99%** — the strongest reproducible raw-artifact DAST result (ZAP).
- **Beat 27%** — clear of the best published full-suite DAST result (26%, rounded chart value).

Both must be earned on the FULL suite, sealed before scoring, three clean-reset runs, with no source
access, no runtime agent, no route seeding, and no manual result merging. A sampled projection is a
hypothesis, not a score.

## Python v0.1

No qualifying published DAST score was found. Do NOT write "DAST tools score 0 on BenchmarkPython" —
absence of evidence is not a measurement. A properly attested Apolaki run could become the first baseline.

## Correction on record

An earlier reading of the ZAP CSV via a page-summarizer produced a per-category table showing hash 32%
TPR and crypto 18.7%, and that was used to argue those categories are partially black-box detectable.
The table was FABRICATED by the summarizer; its totals summed to 1500 cases against a 2740-case suite.
The raw data shows 0.00% on both. Always recompute from the artifact; never quote a summarized table.
