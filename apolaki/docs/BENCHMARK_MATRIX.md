# Apolaki multi-ecosystem benchmark & validation matrix

**Status: QUEUED, scheduled BEHIND the current work.** Three lanes are live (probe repertoire,
orchestration Q-036, Breaker verification). Nothing here starts until those land.

This file is the master inventory. It is deliberately grounded in what the repository already runs —
23 compose services and 94 engines — rather than in a wishlist, because the standing rule is that
nothing becomes an island.

Related: [LEDGERS.md](LEDGERS.md) · [QUEUE.md](QUEUE.md) · [QUEUE_ARCH.md](QUEUE_ARCH.md) ·
[benchmarks/PEER_BASELINES.md](benchmarks/PEER_BASELINES.md)

---

## The rule that governs everything below

```
BENCHMARK -> exposes weakness -> diagnose root cause -> generalize the fix
          -> regression test -> rerun benchmark
```

**NOT** `BENCHMARK -> hardcode the answer -> green score.`

Never special-case detection logic on benchmark filenames, payloads, testcase IDs or expected
answers. That invalidates the benchmark and it is the one failure that cannot be walked back. This
project has already caught itself twice: a path-traversal oracle that scored 69.2% purely on
reflection, and a `weakrand` DAST oracle that is **suite-specific and is labelled as such in the
ledger** rather than quietly counted. Benchmark adapters live outside production engines; production
engines never learn that a benchmark exists.

**The LLM is never the source of truth for scoring.** Ground truth plus deterministic observation
decides pass/fail. LLM reasoning may assist analysis; it may not manufacture confirmation.

---

## Tiers — and why the distinction is load-bearing

**TIER 1 — GROUND-TRUTH BENCHMARK.** Known positive **and** negative cases, complete enough to compute
accuracy. Produces TP/TN/FP/FN, precision, recall, F1, FPR, FNR, and per-CWE / per-engine /
per-language breakdowns. Only Tier 1 may produce an accuracy claim.

**TIER 2 — REALISTIC VALIDATION TARGET.** Intentionally vulnerable apps and environments that prove
Apolaki can *operate* against a realistic system. **Never quote benchmark-style accuracy for Tier 2** —
ground truth is incomplete, so recall is unknowable. A Juice Shop scoreboard percentage is a coverage
signal, not a score. (Recorded in memory as "Juice Shop scoreboard = wrong ruler".)

**TIER 3 — APOLAKI ADVERSARIAL REGRESSION CORPUS.** Our own deterministic controls, per vulnerability
class:

| control | required behaviour |
|---|---|
| KNOWN VULNERABLE | must detect |
| KNOWN SAFE | must stay quiet |
| LOOKALIKE / NOISE | must stay quiet |
| AMBIGUOUS | must not claim confirmed |
| WAF / FILTERED | classify correctly |
| NONDETERMINISTIC | establish the noise floor |
| CONFIRMED EXPLOIT CONDITION | deterministic oracle confirms |

**Tier 3 is the highest-value tier and it is already half-built, scattered.** Eleven files now, and
the count keeps rising because every lane produces them as a by-product:

`test_proof_gate_surfaces` · `test_bench_product_fpr` · `test_proof_claim_matches_artifact` ·
`test_codeassisted_negative_controls` · `test_sqli_oracle_negative_controls` ·
`test_liveness_hostless_negative_control` · `test_bie_errored_control` · `test_technique_contract` ·
`test_evidence_contract_by_proof_kind` · `test_set_param_contract` · `test_cmdi_shapes`

None of them has a home, a runner, or per-class coverage reporting. **The first task of this
programme is B-001 — give them one — not adding a new target.** The corpus is growing faster than it
is being organised, which is the good problem, but only until someone assumes coverage exists because
a file does.

Two of these carry lessons the corpus format must preserve, or it will lose the most valuable part:
- `test_cmdi_shapes` asserts the probe **was sent** before asserting nothing was reported, so a
  control cannot pass vacuously by never firing.
- `test_set_param_contract` exists because two modules disagreed about a missing parameter and one
  silently returned the baseline URL — a false negative shaped exactly like a correct non-detection.
A Tier 3 entry must record *what it would fail to catch if written naively*, not just its assertions.

The question Tier 3 answers is the only one that matters:
**can Apolaki reliably distinguish a real security condition from noise?** Not "can it find a lot".

---

## States

`DISCOVERED` → `RESEARCHED` → `APPROVED` → `ADAPTER NEEDED` → `READY` → `RUNNING` → `PASSING` /
`PARTIAL` / `BLOCKED` / `UNSUPPORTED`

Per-target metadata required before `APPROVED`: name · upstream repo · maintainer · pinned
version/commit · language/domain · CWE classes covered · ground-truth quality · licence · setup
requirements · expected runtime · tier.

**No silent downloads.** A vulnerable repo pulled without this record is not a benchmark.

Result vocabulary, kept distinct on purpose: `PASS` · `FAIL` · `FP` · `FN` · `UNSUPPORTED` ·
`INCONCLUSIVE` · `ENVIRONMENT FAILURE`. **An environment failure is never scored as a detection
result in either direction** — that conversion is how a broken lab becomes a fake capability claim.

---

## What already exists — the honest starting inventory

23 compose services stand today. Classified:

| target | tier | state | note |
|---|---|---|---|
| OWASP Benchmark Java v1.2 | 1 | **PASSING** | full 2132 DAST + 975 SAST, sealed. **DAST-only 41.7% off / 41.5% prod** — the only line comparable to a published tool score. **HYBRID 61.1% / 60.9% is DAST + code-assisted SAST** and must never be compared against ZAP 17.99% or best-published-DAST 26%; those tools were not given the source. FPR 0.0% on every category, both conventions |
| OWASP Benchmark Python v0.1 | 1 | **PASSING** | full 1230-case suite. **DAST-only 24.5%**; **HYBRID 38.8% (DAST + code-assisted SAST)**, same non-comparability rule. FPR 0.0% |
| Juice Shop (+ juice-shop-bench) | 2 | RUNNING | scoreboard is a coverage signal, not accuracy |
| DVWA · bWAPP · Mutillidae · WebGoat | 2 | RUNNING | classic web classes |
| VAmPI | 2 | PASSING | API/BOLA — autonomous cross-user BOLA proven here |
| DVGA | 2 | RUNNING | GraphQL |
| clientauthz · domsource · sessionlife | 3 | PASSING | purpose-built controls incl. CWE-613 |
| GinAndJuice (external, authorized) | 2 | PARTIAL | blind recall grind |
| Natas (external, authorized) | 2 | PASSING | full ladder |
| conpot · dnp3-outstation | 2 | PASSING | ICS/OT, real protocol stacks not mocks |
| openldap · smb · snmpd | 2 | PASSING | network services |
| vulnweb family | 2 | **IN FLIGHT** | task #44 |
| crAPI | 2 | `ADAPTER NEEDED` | manifest exists, task #42 |
| WAVSEP | 1? | `RESEARCHED` | task #45 — verify it still builds before planning around it |

**Do not re-litigate these.** They are recorded so the programme extends the estate rather than
rebuilding it.

---

## Backlog, in the priority order the request specifies, adjusted for real capability

Ordering rule: existing Apolaki capability first, then authoritative Tier 1, then realistic Tier 2.
**Do not implement fake support so a row can be ticked.** Where Apolaki genuinely lacks the engine,
mark `UNSUPPORTED` and raise a separate capability item — the benchmark row stays red until the
capability is real.

### P1 — consolidate what we can already measure
- **B-001** Tier 3 corpus: give the existing scattered negative controls a single home and a runner,
  with per-class coverage reporting. No new targets. *(Highest value; lowest cost; blocks nothing.)*
- **B-002** A benchmark **adapter/runner contract** so every future target plugs in the same way —
  seal-before-key, per-case checkpointing, result vocabulary, raw-evidence retention. `owasp_bench.py`
  is the working prototype and the two-lane scorer (official + product FPR) is the reference; extract,
  do not fork.
- **B-003** Fold benchmark results into the quality gate so regressions are caught automatically —
  the liveness ratchet (`agent/liveness.py`) is the existing mechanism to extend.

### P2 — authoritative Tier 1, new ground truth
- **B-010** NIST Juliet (Java) — large, CWE-labelled, pinned release. Tier 1.
- **B-011** NIST Juliet (C/C++) — Tier 1, but **likely `UNSUPPORTED`**: Apolaki has no C/C++ analysis.
  Expect this to become a capability item, not a quick win. Record it as UNSUPPORTED honestly.
- **B-012** NIST SARD subsets by language, as ground-truth quality permits.
- **B-013** OWASP Benchmark: any other maintained language port.

### P3 — language ecosystems, gated on the code-assisted lane
The code-assisted lane now dispatches by language (Java + Python, `100/100/100` and `100/100` at 0.0%
FPR). Each new language is an incremental dialect, **not** a new subsystem:
- **B-020** JavaScript / Node · **B-021** TypeScript · **B-022** PHP · **B-023** Ruby/Rails ·
  **B-024** C#/.NET · **B-025** Go · **B-026** Rust · **B-027** Kotlin/JVM.
Each needs: a masker (comments/strings/interpolation), receiver-aware resolution — *the receiver
decides the verdict, not the method name*, which is what took Python weakrand from 50.2% to 100% —
and the four standing negative controls.

### P4 — appsec classes not yet covered
Cross-reference the existing 94 engines before adding anything. Known genuine gaps from the capability
sweep: **WebSockets/CSWSH**, **`postMessage`**, **server-side prototype pollution**, **request
smuggling** (deliberately excluded under the no-collateral rule — Tier 1 detection only, never Tier 3
queue-poisoning), **API4 resource consumption**. Already covered and **not** to be re-proposed: SSRF,
SQLi, cmdi, XSS, XXE, SSTI, path traversal, deserialization, JWT, OAuth, race conditions, cache
poisoning/deception, subdomain takeover, OOB.

### P5 — infrastructure / AD / network
- **B-040** Active Directory lab (GOAD or equivalent) — Kerberos, SMB, LDAP relationships. Large setup;
  Tier 2. Apolaki has LDAP/SMB/SNMP engines; **Kerberos is UNSUPPORTED today.**
- **B-041** Kubernetes (kube-hunter targets / KaaS labs) · **B-042** Docker/container escape scenarios ·
  **B-043** IaC (Terraform/K8s manifests) — static, fits the code-assisted lane ·
  **B-044** Secrets/SCA/SBOM — `dependency_intel` + `intel_feeds` exist; needs NVD/OSV/GHSA (Q-021D).

### P6 — cloud
- **B-050** AWS (CloudGoat / IAM Vulnerable) · **B-051** Azure · **B-052** GCP · **B-053** cloud
  attack paths / privesc / multi-cloud. `cloud_intel.py` exists with the
  detection→bounded-probe→content-oracle pattern the architecture doc calls the reusable proof-safe
  template. Tier 2 — cloud labs rarely have complete ground truth.

### P7 — ICS/OT depth
- **B-060** segmented IT/OT · **B-061** cloud-connected OT and cloud→OT paths · **B-062** more
  protocol stacks. Existing: Modbus, S7comm, DNP3, ENIP, OpenPLC. **Read-only always**; no write, no
  PLC state change, ever.

### P8 — specialised
- **B-070** mobile/Android · **B-071** iOS *(likely UNSUPPORTED — no capability)* · **B-072**
  IoT/firmware · **B-073** wireless *(only if safely reproducible; likely UNSUPPORTED)* · **B-074**
  AI/LLM app security, prompt injection, agent boundaries · **B-075** WAF-aware testing.

---

## Reporting — separate scorecards, never one number

No single "Apolaki security score" will be produced. Per language, framework, CWE, engine, and lane
(SAST / DAST / API / network / cloud / K8s / AD / ICS-OT / mobile / IoT / AI-LLM). Tier 1 rows carry
TP/TN/FP/FN + precision/recall/F1/FPR/FNR; **Tier 2 rows carry scenarios / confirmed / missed /
inconclusive and no accuracy figure**; Tier 3 rows carry per-control pass/fail.

Every published figure states its convention and its denominator. Macro over **all** suite categories,
never narrowed. Seal before key. A hybrid (DAST+SAST) figure is never compared against a DAST-only
peer number — those tools were not given the source.

---

## First action when this programme starts

**B-001, not a new download.** Collect the Tier 3 controls that already exist, give them a runner and
per-class coverage, and only then extend the estate. The scattered negative controls written this week
are already the most valuable validation asset in the repository; they simply have no address.
