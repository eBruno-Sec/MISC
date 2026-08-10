# STATUS — live squad dashboard

Updated by the Coordinator. Numbers here must match [LEDGERS.md](LEDGERS.md); if they disagree, the
ledger wins and this file is stale.

**Last update**: 2026-08-10, squad assembly.

## Current numbers

| track | figure | denominator | FPR |
|---|---:|---|---:|
| OWASP Benchmark Java v1.2 — **harness** | **41.3%** | 11-category macro, 2132 cases | **0.0%** |
| OWASP Benchmark Python v0.1 — harness | 34.8% | 14-category macro, 54 cases | 0.0% |
| **Whole-product mission** (the real number) | **2 findings** | owaspbench, 1415 vulnerable cases | — |

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

## Unproven claims

- Q-000 (report badge / counts) and Q-00A (BIE errored control) are **fixed but unverified** — no
  mutation test, no clean-environment run, not committed.
- The S11c relative-links + robots/sitemap mission number is still `pending` in the ledger.

## Regressions / rollbacks

None this cycle.

## Next highest-value task

Q-001 session lifecycle invalidation — lowest effort of the six, every primitive already exists, and
it appears in essentially every commercial pentest report.
