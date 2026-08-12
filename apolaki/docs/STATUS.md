# STATUS — live squad dashboard

Updated by the Coordinator. Numbers here must match [LEDGERS.md](LEDGERS.md); if they disagree, the
ledger wins and this file is stale.

**Last update**: 2026-08-10, squad assembly.

## Current numbers

| track | figure | denominator | FPR |
|---|---:|---|---:|
| Java v1.2 — **hybrid** (DAST + code-assisted SAST) | **61.1%** off. / **60.9%** prod. | 11-cat macro, full 2132 DAST + 975 SAST | **0.0%** |
| Java v1.2 — **DAST only** | **41.7%** off. / **41.5%** prod. | 11-cat macro, full suite | **0.0%** |
| ~~Java v1.2 — earlier figures~~ | ~~41.3% / 34.9% @ 2.1%~~ | superseded by the full sealed run; the 2.1% FPR was the cross-family artifact, since fixed | — |
| Python v0.1 — **hybrid** (DAST + code-assisted SAST) | **38.8%** | 14-cat macro, full 1230-case suite | **0.0%** |
| Python v0.1 — DAST only | 24.5% | 14-cat macro, full suite | 0.0% |
| ~~Python v0.1 — harness~~ | ~~34.8%~~ | superseded: 54 cases, ~4 per category | — |
| **Whole-product mission — SCORED** | **precision 95.7%** · **recall 1.6%** | 22 TP / 1 FP / 1415 vulnerable | 1 cross-family FP |

**The gap is the story.** Mission `90cee81c` completed in 3720s with 2 findings — a credential in a
source comment and jquery@2.1.4 — **neither of them a benchmark case**. The count reached 2 at the
50-second mark and never moved again. The same target scores 41.3% when engines are handed case URLs
directly. Five orchestration fixes did not change this number. Quote **2 findings**, not 41.3%, when
describing Apolaki as a product.

Peer context (recomputed from raw artifacts): ZAP **17.99%** · best published full-suite DAST **26%**
· 11-tool DAST mean **~11%**.

**Standing ceiling**: 100% is not reachable on the black-box lane. 1101 Java cases (crypto 246,
hash 236, weakrand 493, trustbound 126) have no externally observable signal; ZAP scores 0.00% on
all of them and the 11-tool mean is 0.0%. Closing them needs a declared IAST/runtime lane, labelled
as such — never folded into a DAST figure.

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
