# STATUS — live squad dashboard

Updated by the Coordinator. Numbers here must match [LEDGERS.md](LEDGERS.md); if they disagree, the
ledger wins and this file is stale.

**Last update**: 2026-08-16 evening. The previous update was 08-13 and had rotted badly — it named
lanes closed days earlier and a tree three days out of date. **This file is one of four criteria the
`apolaki-autocontinue` watchdog checks before retiring itself, so leaving it stale silently disables
that retirement.** Updating it is not bookkeeping.

## Lanes right now

| lane | owner | state |
|---|---|---|
| Truthful engines (Q-054/055/055b) | Claude | **live** — the workflow finding sink, metadata's GPS false negative, the bfla mirror |
| Arsenal gap (Erwin's question) | Claude | **live** — run a real mission and READ the coverage sections; classify every idle engine into never-planned / skipped / ran-clean / errored |
| Description gate (Q-056) | — | **CLOSED.** PARTLY gateable: 2 rules at 0 FP over 111 engines, 3 rejected with numbers. `run_metadata` is not gateable by any static rule and only running it catches it |
| Islands soundness (Q-050b) | — | **CLOSED.** 7 verdicts; 3 engines deleted outright |
| Sessions / `Identity` (Q-032) | — | **CLOSED.** The anonymous authz row was carrying the mission's session |
| Tech intelligence (Q-021C) | — | **CLOSED.** One chain end to end; the server/language half is still a version reporter |

Tree at HEAD: **2672 passed / 13 skipped / 10 xfailed / 0 failed** — measured by the description-gate
lane on an isolated `git archive` snapshot of `ece2dbd` plus its own two files, so the delta is
**+14 and nothing else**: exactly that lane's new tests, with skips and xfails unmoved. It edited no
product module, so there was no other way for the count to move. Every xfail is a STRICT marker
pinning a named live defect — removing one without fixing what it pins is forbidden, and when the
defect *is* fixed the marker XPASSes and turns the suite red on purpose, forcing a deliberate
retirement.

## Unproven claims and open blockers — read this before quoting a number

- **Q-052 is a PRODUCT question, not an engineering one, and it is the oldest unresolved item.** Both
  proposals were measured and rejected: narrowing `active` costs 49.5% of the sweep and 7 of 18
  engines including the entire SQLi surface; defaulting to `full` would enable state-changing writes
  and lab-calibrated traversal semantics against production targets. The evidence points at loosening
  `planner._ALLOWED`. **Nobody should ship a third proposal without deciding what `active` means.**
- **`confirm_create_object_idor` declares `ACTIVE:` while registered `INTRUSIVE` (Q-058).** State this
  precisely or it reads as a safety hole, which it is not: `_run_tool` enforces against
  `TOOL_PERMISSIONS`, which correctly says INTRUSIVE. **The enforcement is right and the docstring is
  wrong.** The risk is the next engineer mis-wiring an engine that creates and deletes objects on a
  live target, not a present exposure.
- **`run_hash_crack` advertises a `hash_type` parameter it never reads (Q-058).** Verified: the token
  occurs exactly once in all of `agent/tools.py`, on the schema line. The schema tells the model it is
  "optional; auto-identified if omitted", implying that supplying it does something. It does not.
- **A gate reporting zero is not a clean result until a positive control says it looked at something.**
  I ran the new description gate against the live tree, got 0 flags, and it was my own API misuse (a
  class object where a string was wanted) parsing nothing. With a positive control showing 111 engines
  parsed, the real answer was 2. Any zero quoted anywhere in this project needs its positive control.
- **`00438`** — the ninth of the nine budget-starved sqli cases — is still unprobed at cap 700.
- **Per-URL cost is SUBLINEAR in target count and nobody knows why.** The 400→700 raise predicted
  +57% elapsed from a linear model and measured +22%. Any future budget change priced on the linear
  model will be wrong in the expensive direction.
- **The 08-11 seal `a95670f9` is abandoned, not explained.** Baseline counts are re-derivable
  (`fab8a46e`); that seal string is not, and its sealing script was never committed.
- **The wp2 `00042` traversal FP mechanism was never fully isolated** — the engine returns 0 findings
  standalone. `run_web_probes` remains out of the sweep for that reason.
- **`run_metadata` and `_run_workflow` are known to misreport as of this writing** (Q-055, Q-054, both
  in flight). Until those land, a clean metadata result and a workflow run producing no findings are
  both UNRELIABLE and must not be quoted as evidence of a clean target.

## Three hypotheses tested and FALSIFIED — all three were mine

| hypothesis | verdict | evidence |
|---|---|---|
| cmdi is limited by payload repertoire (blind/time/OOB) | **FALSE** | +0 across 251 cases. Blind and OOB use the *same shell separators* as the output payloads, so they need the same shell reach. Shell reach was the axis, never blind-vs-echo |
| cmdi/xss are limited by carrier delivery | **FALSE** | +0 across 120 paired xss cases — and the carrier **ran** on ~30% of them (header names found on 18 of 60 sampled pages). Delivery arrived and proved nothing |
| the fail-open permission default is reachable | **FALSE** | `agent/agent.py:551` and `:644` both do `TOOL_PERMISSIONS.get(tool_name, PermissionLevel.ACTIVE)` — a fail-open default of the same family that has bitten this project four times. Measured: **advertised-but-unregistered = 0**; every one of the 76 `CLAUDE_TOOLS` names is registered among the 111 permissions. Nothing lands on the default from the model-facing surface. Worth re-checking whenever an engine is added, but it is not a live hole |

Recorded so no future lane spends a night on any of them. A measured "no" changed the plan twice.

**Measured in the same pass, and NOT yet a verdict: 35 of the 111 registered engines are absent from
`CLAUDE_TOOLS`** — registered and dispatchable, but the model is never told they exist. Among them are
two browser-driver engines, `confirm_browser_persona_bola` and `run_dom_trace`, which is precisely the
half of the arsenal Erwin asked about. **This is NOT a claim that those 35 are unreachable.** Apolaki
is deterministic-first: the planner selects from the effects model and the engine descriptor, not from
`CLAUDE_TOOLS`, so "not advertised to the LLM" and "never runs" are different claims and conflating
them would be the island error pointed backwards. It is handed to the arsenal lane as a classification
axis — an idle engine that is planner-reachable-only is an effects-model gap, while an idle engine that
IS advertised may be an LLM-selection gap. Same symptom, different fix.

## Tier-3 adversarial corpus — now has an address (B-001, Codex)

**33 controls across 15 classes, 32/33 passing, 0 regressions, 0 environment failures.** Executable
gate at `scripts/tier3_gate.sh` (LF-normalized and pinned via `.gitattributes`). Known non-pass
`sqli-unstable-page-noise` is **not credited** — it is the Q-040 defect, held by a strict xfail.

## Current numbers

| track | figure | denominator | FPR |
|---|---:|---|---:|
| Java v1.2 — **hybrid** (DAST + SAST) ✅ **now mission-reachable (Q-044)** | **61.1%** off. / **60.9%** prod. | 11-cat macro, full 2132 DAST + 975 SAST | **0.0%** |
| Java v1.2 — **DAST only** | **41.7%** off. / **41.5%** prod. | 11-cat macro, full suite | **0.0%** |
| ~~Java v1.2 — earlier figures~~ | ~~41.3% / 34.9% @ 2.1%~~ | superseded by the full sealed run; the 2.1% FPR was the cross-family artifact, since fixed | — |
| Python v0.1 — **hybrid** (DAST + code-assisted SAST) | **38.8%** | 14-cat macro, full 1230-case suite | **0.0%** |
| Python v0.1 — DAST only | 24.5% | 14-cat macro, full suite | 0.0% |
| ~~Python v0.1 — harness~~ | ~~34.8%~~ | superseded: 54 cases, ~4 per category | — |
| **Whole-product — RERUN 2026-08-13, sealed** | **precision 100.0%** · **recall 1.34%** | 19 TP / 0 FP / 1415 vulnerable | **0 FP** |
| **Whole-product — CURRENT, cap 700 (wp3)** | **precision 96.3% · recall 1.84% · 2576 s** | 26 TP / 1 FP / 1415, seal `951dc0a0` | the baseline's score in **48% of the time**; 8 of 9 starved cases recovered |
| Whole-product — baseline `ebd96f45`, RE-SCORED 2026-08-14 | precision 96.3% · recall 1.84% · 5329 s | 26 TP / 1 FP / 1415, seal `fab8a46e` | the standing comparison point |
| ~~Whole-product — wp1 (`run_web_probes` in the sweep)~~ | ~~precision 96.8% · recall 2.12% · 2103 s~~ | 30 TP / 1 FP, seal `e6674d6d` | **REVERTED — the number was right, the reason was wrong (Q-047)** |

**RECALL WENT DOWN — and by MORE than this said.** Re-scoring the baseline (2026-08-14) puts it at
26 TP, not 22, so the rerun's loss is **−9 findings, not −3**. Everything below still holds; the
regression it describes is three times larger. Original line kept for the record:

**RECALL WENT DOWN. −3 findings. A week of work did not raise it.** Precision reached a clean 100%
and the run is 2.8× faster (5329 s → 1893 s), but the product finds *fewer* benchmark cases. Class
coverage genuinely broadened — **ldapi 1 → 5, xpathi 0 → 1**, consistent with the body-parameter work
reaching sinks that only take body input — and **the entire loss is sqli: 20 → 11**. Net −3.

**My ordering call was wrong and I am recording it as wrong.** Two days ago I moved schema above
throughput and said: *"if schema lands and recall still doesn't move, then throughput was the binding
constraint all along and I'll have cost us a cycle."* Schema landed. Recall did not move. But
throughput was **also** measured and ruled out ("build nothing"), so neither of my two hypotheses was
the constraint. Both were wrong, and the class-mix shift proves schema *worked* — it just did not
convert into net findings.
| **NIST Juliet Java 1.3 — code-assisted (SAST)** | **precision 66.48%** · **recall 100%** · F1 79.87% | 329 methods, 0 skipped in denominator | **60 FP, all bare-`AES`** |

**Juliet's 60 false positives are a ground-truth disagreement we are KEEPING.** Every one is a Juliet
"good" control using bare `Cipher.getInstance("AES")`, which in Java resolves to `AES/ECB/PKCS5Padding`
— and ECB is a real weakness. Apolaki's call is arguably more correct than the 2017 label. We do not
silence the detector to recover the points, and we do not touch the answer key. **Any future change
that recovers those 60 by suppressing bare-AES detection is rejected on sight.** 109 Juliet CWE
families remain **UNSUPPORTED** — a status, not a gap to paper over.

**The gap is the story.** Mission `90cee81c` completed in 3720s with 2 findings — a credential in a
source comment and jquery@2.1.4 — **neither of them a benchmark case**. The count reached 2 at the
50-second mark and never moved again. The same target scores 41.3% when engines are handed case URLs
directly. Five orchestration fixes did not change this number. Quote **2 findings**, not 41.3%, when
describing Apolaki as a product.

Peer context (recomputed from raw artifacts): ZAP **17.99%** · best published full-suite DAST **26%**
· 11-tool DAST mean **~11%**.

**⚠ THE OLD "STANDING CEILING" CLAIM WAS WRONG AND IS RETIRED.** It read: *1101 Java cases (crypto
246, hash 236, weakrand 493, trustbound 126) have no externally observable signal, so closing them
needs IAST.* That was true of **HTTP**, and I restated it as a limit of **Apolaki** for weeks. Erwin
pushed back twice. He was right.

Measured since: **crypto 100.0%, weakrand 88.5%→100.0%, hash 69.0%→100.0%, all at 0.0% FPR**, via the
code-assisted (SAST) lane reading source the operator supplies — a capability `agent/codereview.py`
already half-had. Only **trustbound** (126 Java + 37 Python) is still an honest 0, unmapped on purpose
because its clean twins launder the tainted value and a call-site match would fabricate the score.

**The replacement rule: never restate a limit of one lane as a limit of the platform.** A
code-assisted figure is still labelled SAST and still never folded into a DAST number.

## The funnel — ANSWERED (was the top unknown)

```
surface discovered .......... 2756   (all addressable — proven by the liveness reach check)
pages actually FETCHED ......   12
distinct URLs any tool aimed at 66
distinct URLs probed ........   36
findings ....................    2
```
Every stage after discovery is arithmetic on **12 fetched pages**. Three causes, ranked by leverage:
`sweep_targets(limit=20)` called without a limit · a URL must be FETCHED and carry `?` to become a
target · `depth(2)×frontier(30)` = 60 visits. Plus a hard throughput ceiling: **~100 s per URL**, so
2740 cases would take ~76 hours even with a perfect funnel. Tracked as **Q-019** (CRITICAL, ready).

## Squad state

All six agents hit the API session limit and terminated early (resets 16:50 PT). They wrote before
dying: the Analyst's verification pass and tickets Q-011…Q-020 are in `QUEUE.md`; the Builder left
`agent/session_lifecycle_tool.py` plus edits to `tools.py`/`personas.py`/`agent.py` **uncommitted and
failing `test_deadcode_gate::test_the_method_ratchet_holds`** — do not commit that work until its
owner finishes it or the Breaker verifies it. The Coordinator (main thread) has committed its own
four changes.

## Active agents

| role | agent | assignment | owns |
|---|---|---|---|
| RESEARCH — Watcher | *(assembling)* | capability-gap sweep #2 | `docs/research/INBOX.md` |
| DISTILLATION — Analyst | *(assembling)* | drain INBOX, audit Q-007/Q-008/Q-009 | QUEUE tickets |
| QUEUE — Coordinator | *(assembling)* | rank + assign, keep this file live | `QUEUE.md`, `STATUS.md` |
| IMPLEMENTATION — Builder | *(assembling)* | Q-001 session lifecycle | `tools.py`, `personas.py` |
| VERIFICATION — Breaker | *(assembling)* | Q-000, Q-00A (uncommitted fixes) | `CODEBASE_REVIEW.md` |
| INTEGRATION — Conductor | *(assembling)* | ZAP orchestration + island audit | wiring, no code islands |

## Queue depth

Ready: 4 (Q-001…Q-004) · gated-ready: 2 (Q-005, Q-006) · defects: 3 (Q-007…Q-009) ·
programme backlog: 10 · verification: 2 · blocked: 0

## Blockers

- **Mission `90cee81c` is running** (owaspbench-clean, probe phase). `docker compose build agent`
  SIGKILLs it. No rebuild until it finishes — code edits and tests only.

## Rejected claims — verified by the Breaker, 2026-08-10

- **0.0% FPR: REJECTED as a product claim.** The scorer only credits findings within a case's own
  family, so 22 clean `securecookie` cases carrying CONFIRMED `path_traversal` findings all scored as
  true negatives. Real figures 34.9% / 2.1%. See the retraction in [LEDGERS.md](LEDGERS.md).
- **The pathtraver 69.2% is a signature, not a capability.** Its oracle confirms on *reflection* — a
  payload with no `../`, and even a string that is not a filename, both "confirm". It reads clean only
  because the clean pathtraver cases happen not to echo.
- **`1709f59` (the `max_hostless` reach guard) shipped UNTESTED.** Deleting the whole branch still
  left 30 passing. My own commit, my own miss — the Breaker wrote the negative control I should have.
- **`707b3b9` was incomplete**, in four ways; fixed in `5af0af8`. CSV had no confidence column at all;
  SARIF still emits `level=error` / `security-severity=9.5` for demoted rows with the demotion buried
  in `properties.confidence`, which GitHub code scanning and DefectDojo do not read. **SARIF is still
  open.**
- **BIE errored-control fix: PLAUSIBLE, not confirmed.** The two "surviving mutants" were proven
  *equivalent* (the producer writes `error` on exactly one path and that path hardcodes `status 0`,
  so `_control_ran()==False with status==200` is unreachable). But a **residual live defect** remains
  at `bie.py:292` — `judge()`'s third control still reads `if control is not None and _s(control) == 200`,
  the identical fall-through, reproduced with two personas: control alive → `rejected`, control errored
  → `confirmed`. And the fix is live only via `docker cp`; `grep -c _control_ran` inside the baked
  image returns **0**, so it dies on the next rebuild.

## ZAP — answered, and it is not what anyone assumed

**`run_zap` has never executed in any Apolaki mission.** MEASURED across 150 missions and 25,619
recorded tool calls: zero `run_zap` rows. ZAP's own daemon reports `numberOfMessages: 0` after 10h up.
Three independent gates each suffice to prevent it: the API model default `enable_zap: bool = False`
(`main.py:81`), a mode gate that 422s ZAP outside Full mode (`main.py:336`), and
`PermissionLevel.INTRUSIVE` which is outside the active/passive tiers (`tools.py:138`). The only
writer of `enable_zap=True` in the tree is a UI checkbox that starts unticked.

The planner branch is **not** dead — driving `next_batch` to exhaustion with `mode=full, zap=True`
does schedule the step. Four missions in July did carry `enable_zap=True` and still produced zero
`run_zap` calls; that residue is **UNVERIFIED** and means "flip the flag" is not sufficient without an
end-to-end test asserting a `run_zap` row lands. `recon["zap"]` is a confirmed **dead write** — sole
occurrence in the tree, no reader, no dynamic access. Targeted rescan is **NOT WIRED** (one ZAP call
per host per mission, ever), and the AJAX spider is wrapped in a bare `except: pass`.

## Unproven claims

- Q-000 (report badge / counts) and Q-00A (BIE errored control) are **fixed but unverified** — no
  mutation test, no clean-environment run, not committed.
- The S11c relative-links + robots/sitemap mission number is still `pending` in the ledger.

## Regressions / rollbacks

None this cycle.

## What actually bounds the score now

Recall is **1.6%**, and it is bounded by **wall-clock, not by detection**. The funnel discovers 2756
URLs; probing costs ~100 s/URL; covering 2740 cases therefore needs ~76 hours. Every engine
improvement is capped by that until concurrency lands. Precision is already 95.7%, so the shape of
the problem has inverted: Apolaki is now *accurate and nearly silent*, where a month ago the risk was
the opposite.

Order that follows from the measurement:
1. **Throughput** — diagnose the 8.5 s/tool-call cost, then concurrency. Unlocks everything else.
2. **The two bad oracles** — path-traversal (confirms on reflection; whole 69.2% rests on it) and
   whatever let sqli fire on the clean `cmdi` case `BenchmarkTest00494`.
3. **Q-021A** SCA proof overclaim — in flight, slice 1 landed.

## Next highest-value task

Q-001 session lifecycle invalidation — lowest effort of the six, every primitive already exists, and
it appears in essentially every commercial pentest report.

## ⚠ The hybrid figure is a HARNESS capability, not a product capability (Q-044)

MEASURED 2026-08-13. `codeintel.review_source_tree()` — the analyser producing crypto/hash/weakrand
at 100% / 0.0% FPR, and the entire gap between Java DAST-only 41.7% and hybrid 61.1% — has **one
caller: `owasp_bench.py:231`**. `source_root` appears nowhere in `main.py` or `agent.py`, so a
mission cannot supply a source tree. `GET /codereview?path=` is production-reachable but calls
`codeintel.review()`, a *different, older* function.

**So no client engagement can currently invoke the capability behind 61.1%.** The number is real and
honestly measured; the path to it is benchmark-only. Same distinction the ledger already enforces
between the 41.3% harness number and the 2-findings whole-product number — quote 61.1% as a harness
result until Q-044 wires a production entry point.

Also confirmed while checking: **semgrep is NOT wired** (zero hits in `agent/`). The semgrep run was
a spike that proved the categories were reachable; the lane then built Apolaki's own analyser. The
100% figures are ours, which is a stronger claim — but it does not make them reachable.
