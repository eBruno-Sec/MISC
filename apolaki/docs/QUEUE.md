# QUEUE — the one canonical, dependency-ordered work queue

**Only the Coordinator (QUEUE agent) changes state in this file.** Everyone else proposes; the
Coordinator ranks, dedupes, assigns and moves. One owner per ticket. No two agents editing the same
files concurrently.

States: `ready` · `active` · `verification` · `blocked (reason)` · `completed (commit)` ·
`rejected (reason)` · `rolled-back (reason)`

Ranking = expected capability gain × coverage gain × proof strength ÷ (risk × cost).

Related: [LEDGERS.md](LEDGERS.md) · [CODEBASE_REVIEW.md](CODEBASE_REVIEW.md) ·
[research/INBOX.md](research/INBOX.md) · [STATUS.md](STATUS.md)

---

## File ownership — this cycle

No two agents may edit overlapping files. A ticket needing a file owned elsewhere is
`blocked (file conflict)` until the owner releases it.

| owner | files | ticket |
|---|---|---|
| **Builder** | `tools.py` · `personas.py` · `register.py` · `techniques.py` · `engine_descriptor.py` · `dom_tool.py` | Q-001, then Q-003 |
| **Breaker** | test files only, plus verdicts in `CODEBASE_REVIEW.md` | Q-000, Q-00A, FPR audit |
| **Main thread / Coordinator** | `report.py` · `bie.py` · `proof_schema.py` · `liveness.py` · `browser_engine.py` · `main.py` · `LEDGERS.md` · `QUEUE.md` · `STATUS.md` | uncommitted fixes |
| **Watcher** | `docs/research/INBOX.md` | research only, read-only on code |
| **Analyst** | QUEUE tickets (`proposed` only) | verification of Q-007/8/9 |
| **Conductor** | `CODEBASE_REVIEW.md` findings | audits only, read-only on code |

---

## Rank 0 — the funnel (supersedes everything below)

### Q-010 · Why does a whole-product mission find 2 things on a 1415-vuln target?
**MEASURED**: mission `90cee81c`, 3720s, 2 findings, neither a benchmark case, count static from
t=50s. Harness on the same target: 41.3%. Five orchestration fixes did not move it.
**This is not a new-engine problem and no new engine should outrank it.** The instruction is to
measure the funnel stage by stage — URLs discovered → URLs parameterized → probes selected → oracles
fired — and find the stage where the count collapses, rather than fixing a sixth suspected defect
blind. Assigned to the Watcher (research line 2). Any ticket claiming to fix this must state which
funnel stage it repairs and show the before/after count for that stage.

---

## Rank 1 — ready

### Q-001 · Session lifecycle invalidation (CWE-613) — WSTG-SESS-06/07/11
- **Root cause**: no engine exists, and logout is *actively avoided*. `tools.py:3074` refuses to
  admit a session-killing endpoint to the surface; `:3673-3696` passes `no_logout` to every katana
  crawl. The platform blinded itself to the one endpoint this class needs.
- **Oracle**: mint a sacrificial persona (`register.py`), capture cookie C, confirm C reaches an
  authed marker, POST logout, replay C. Confirmed iff the replay still returns the authed marker.
- **Negative control**: a freshly invented cookie must be rejected by the same endpoint (proves the
  marker is not served anonymously).
- **Non-destructive**: yes — only touches a session Apolaki itself created.
- **Files**: `agent/tools.py`, `agent/personas.py`, `agent/register.py`, `agent/techniques.py`,
  `agent/engine_descriptor.py`
- **Definition of done**: engine live in a real mission, liveness check added, secure-control lab
  proves no FP, WSTG entries move off `none`.
- **Effort**: lowest of the six. Every primitive exists; the work is a mission-safety carve-out so
  the sacrificial logout cannot kill the live scan session.

### Q-002 · WebSocket security: CSWSH (CWE-1385/346) + WS-frame injection
- **Root cause**: zero coverage. `Sec-WebSocket|websocket` appears only in a report string and the
  WSTG catalog title. WSTG-CLNT-10 is `none`.
- **Oracle**: HTTP/1.1 Upgrade carrying the persona's session cookie **plus** an attacker `Origin`.
  Confirmed iff (a) `101` with a valid `Sec-WebSocket-Accept` derived from our key **and** (b) the
  first server-pushed frame carries the same authenticated marker the HTTP session already proved.
- **Negative control**: identical handshake, cookie stripped, must fail or carry no authed data.
- **Non-destructive**: yes — read-only handshake plus one inbound frame.
- **Files**: new `agent/ws_tool.py`, wired in `agent/tools.py` (seed: `asyncio.open_connection` at
  `tools.py:2770`), `techniques.py`, `engine_descriptor.py`
- **Effort**: moderate-low. Frame injection then reuses the unchanged sqli/xss analyzers over a
  different transport.

### Q-003 · `postMessage` as a DOM-XSS source (CWE-346 → CWE-79) — WSTG-CLNT-11
- **Root cause**: `dom_tool.py` confirms canaries in real Chromium but its only sources are
  `location.hash` and query params (`dom_tool.py:134-136`). `postMessage|MessageEvent|onmessage`
  appears nowhere in `agent/`.
- **Oracle**: enumerate `message` listeners over CDP, load in a controlled parent frame,
  `postMessage` a unique canary, assert it reaches a dangerous sink and **executes** — the same
  browser-confirmed proof `dom_tool.py:250` already emits.
- **Negative control**: same canary with a mismatched `targetOrigin` must not fire.
- **Non-destructive**: yes.
- **Files**: `agent/dom_tool.py`, `agent/cdp.py`
- **Effort**: low-medium. Adding a **source** to a working confirmation engine, not a new engine.

### Q-004 · Unrestricted resource consumption (CWE-770/799) — API4:2023, WSTG-BUSL-05/07
- **Root cause**: a whole OWASP API Top 10 slot with no engine. The only `429` in the codebase is
  Apolaki respecting someone else's limit (`tools.py:3296`).
- **Oracle (preferred, zero volume)**: amplification multiplier — `limit=1` vs `limit=100000` on a
  paginated endpoint; assert row count and byte size scale linearly with the attacker-supplied
  bound. A measured ratio, not a heuristic. Secondary: N bounded idempotent requests, confirmed iff
  all N are 2xx and no `429`/`Retry-After`/`X-RateLimit-*` ever appears.
- **Negative control**: an endpoint on the same host that *does* limit, or an explicit
  "no limiter anywhere on this host" verdict.
- **Non-destructive**: yes when scoped to idempotent reads with a hard cap. Does not collide with
  the no-brute rule — nothing iterates credentials.
- **Files**: `agent/race_tool.py` (already has the synchronized-parallel primitive + status
  accounting), `agent/api_inventory.py`, `agent/tools.py`
- **Effort**: low-medium; the multiplier variant needs no concurrency at all.

## Rank 2 — ready, gated

### Q-005 · Server-side prototype pollution (CWE-1321)
- **Root cause**: `dom_tool.py:283-351` runs real gadget probes but every one is browser-side.
- **Oracle**: behaviour-change, byte-observable — `{"__proto__":{"json spaces":10}}` then confirm the
  **next** response's JSON is indented against a pre-pollution baseline; or
  `{"__proto__":{"status":510}}` and confirm the status changes.
- **Negative control**: the same payload via `constructor.prototype` (defeats naive `__proto__`
  string filters) plus a clean re-request proving the effect **persists** — distinguishes pollution
  from reflection.
- **Non-destructive**: **NO.** It mutates the server's `Object.prototype` for every subsequent
  request until restart. Cross-user blast radius.
- **Decision**: ship gated as `execution: "operator"` (`techniques.py` already supports the field).
- **Effort**: medium. Pure request/response.

### Q-006 · HTTP request smuggling / desync (CWE-444) — detection tiers only
- **Status**: currently a *deliberate* exclusion, not an oversight — `wstg_catalog.py:137` refuses
  WSTG-INPV-15 under the no-collateral rule. That call stands for Tier 3.
- **Tier 1 (safe)**: prove a front-end/back-end pair exists via hop-count and header-mutation
  differentials. Zero risk.
- **Tier 2 (safe-ish)**: CL.TE-shaped timing differential on our own socket with `Connection: close`
  — a repeatable multi-second delta against a control differing only in the framing header, with a
  zero-delta control.
- **Tier 3 (forbidden)**: queue poisoning captures a stranger's request. Not built.
- **Honest product answer**: a **detection** capability with a hard stop before confirmation,
  `execution: "operator"`, reported high-confidence but never "confirmed".
- **Effort**: highest of the six — needs a hand-rolled HTTP/1.1 socket client (`httpx` cannot emit a
  malformed frame). `httpx[http2]` is already a dependency for the H2-downgrade variants.

## Rank 3 — defects, ready

### Q-007 · `weak_password_reset` is a phantom capability
`techniques.py:49` and `:1250` self-admit there is **no production executor**; what fired on the labs
was the lab *solver*. `engine_descriptor.py:74,179` still declares its preconditions and effects, so
**the planner believes it is real**. Either build it for real (CWE-640 reset-token reuse /
non-expiry / predictability — `agent/prng_disclosure.py` already analyses token entropy and could be
pointed straight at a reset token) or strip the descriptor. Do not leave the planner lied to.

### Q-008 · `run_mass_assignment` referenced but does not exist
`asvs_model.py:103` names an engine absent from the `tools.py` name table. A wiring defect, not a
capability gap. Verify, then fix the reference or build the engine.

### Q-009 · Audit findings pending verification (do not act before checking)
Retest scope guard fail-open (`main.py:2578-2602`) · `PUT /findings` bypassing `findings_gate` ·
operator lead-confirmation producing an immediately-demoted finding · `get_logs` oldest-first ·
`risk_signals` unfiltered twin · `_read_controls` returning `[]` on evaluate failure.

## Rank 4 — open programme work (existing task list)

`#54` silent-failure architecture (mechanism shipped, propagation open) · `#50` Codex batch 2
(2 of 9 left: `waf_bypass` decision, `weak_session_token` carriers) · `#53` Python benchmark
(wired, 34.8%) · `#44` vulnweb · `#42` crAPI · `#45` WAVSEP · `#30` dead-code triage ·
`#52` `validated_on` enforcement · `#35` NotebookLM · `#49` research files.

---

## verification

*(nothing yet — Breaker takes items from `active` as they land)*

## completed

### Q-000 · Report un-demoted findings the proof gate had rejected
`proof_schema.demote_unproven` rewrites `confidence` to `"lead"` and keeps the row; the HTML card
stamped a hardcoded `CONFIRMED` on every row, and `_counts()`/`total_conf` counted demoted rows in
the headline severity tally. Fixed: shared `proof_schema.is_confirmed()`, per-finding `_conf_badge`,
confirmed-only `_counts`, matching denominator. **Awaiting Breaker verification + commit.**

### Q-00A · BIE errored-control false positive
`_FETCH_JS` returns `{status: 0, ..., error}` on exception while `judge()` tested only `if c is None`,
so an **errored** control passed as a **satisfied** control. An errored `anon` control also already
failed `_s(anon) == 200`, so it never fired the PUBLIC rejection and fell through to `confirmed` —
tightening the condition alone did not fix it. Fixed with `_control_ran()` plus explicit
missing-control gates in `judge_client_side_authz` and `judge_param_swap`, both returning `lead`.
**Awaiting Breaker verification + commit.**

## rejected

*(Distillation records rejections here with the reason, so the same idea is not re-proposed)*

Already covered — do **not** re-propose (verified against live code): subdomain takeover
(`dns_recon.py:68-110`) · web cache poisoning (`cache_tool.py`, real clean-re-request oracle) · cache
deception · OOB collaborator (`collaborator.py`, wired into SSRF/XXE/cmdi/blind-XSS) · time-based
blind SQLi and cmdi (both with matching zero-delay controls) · mass assignment as a *technique* ·
vulnerable components (`dependency_intel.py`) · host header · JSONP/XSSI · clickjacking (header
level, correctly two-condition) · HTTP parameter pollution (excluded, FP-prone, no clean oracle) ·
padding oracle (excluded, no clean general oracle).
