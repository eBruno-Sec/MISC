# Apolaki systematic codebase review

One file. Every sweep, every finding, every change. Append only — a finding is never deleted, it is
marked RESOLVED with the commit that resolved it, so this doubles as the reviewer's audit trail.

**Scope:** 173 shipping modules / 53,970 lines, plus 172 test files / 19,724 lines.

**Method.** Two tracks, because neither alone is honest:
- **Sweeps** — exhaustive pattern analysis across all 173 modules. Complete coverage, narrow depth.
  Doesn't fatigue, doesn't skip. This is how the silent-failure defect was found.
- **Reads** — full-depth reading of the five hot files that hold 36% of the code and essentially all
  engine execution, orchestration and reporting: `tools.py` (8184), `main.py` (3352), `agent.py` (3100),
  `report.py` (3003), `bie.py` (1725).

A claim in here is either **MEASURED** (a command and its output) or marked **UNVERIFIED**. No finding is
asserted from reading alone when it can be counted.

---

## Severity scale

| | meaning for a *scanner* specifically |
|---|---|
| **CRITICAL** | can turn a real vulnerability into a silent pass, or emit a false positive |
| **HIGH** | capability exists but cannot run, or a result cannot be trusted/attributed |
| **MEDIUM** | correctness or robustness defect with a bounded blast radius |
| **LOW** | hygiene; no effect on findings |

---

## S1 — Silent failure handlers · **CRITICAL** · PARTIALLY RESOLVED (`40f59b7`)

**Measured 2026-08-10**, `agent/` excluding tests:

```
824  except clauses
769  `except Exception` (broad)
328  followed IMMEDIATELY by a bare `pass`
 22  record anything at all
192  broad handlers in tools.py · 104 agent.py · 65 main.py · 48 juiceshop_solvers.py · 46 bie.py
```

**The defect.** Apolaki cannot distinguish *"I checked and found nothing"* from *"my check crashed."* A
swallowed exception produces no finding, and no finding is byte-identical to a clean target. This is the
worst available failure mode for a scanner and it is the root cause behind most of the individual bugs
found this session.

**Not theoretical — five instances in one session:**

| instance | consequence |
|---|---|
| `dt.DOM_SCAN_JS` never defined, eaten by bare except | 3 families silently detected nothing |
| `httpx` unimported in `_graphql_argument_injection` | whole GraphQL tool raised, eaten |
| `poc.redact` never existed behind a `hasattr` | model-visible bodies never redacted |
| my own traversal header pass used `parse_qsl` unimported | would have shipped as dead code **reporting clean** |
| `_run_form_cmdi` probed with invented values | baseline and probe failed identically; vulnerable field read clean, no exception needed |

The codebase already diagnosed this once and never generalised it — `agent.py:1204`: *"swallowed artery
error is invisible and undebuggable."*

**Why it blocks everything else.** Benchmark misses are currently unattributable. cmdi 28.6%, xpathi
40.0% — oracle-declined or crashed? Unknowable. It also partly manufactures our headline precision: when
anything goes wrong, emit nothing.

**Fix shipped (`40f59b7`)** — the *mechanism*, not a mass rewrite. Removing 328 handlers would be wrong;
most are legitimately defensive. The defect is that they are **silent**.
- `ToolRegistry.swallowed`: bounded 500-entry ledger, fields truncated.
- `ToolRegistry._swallow(exc, where, target)`: records instead of discarding.
- `_run_web_probes` reports it: `0 anomaly signal(s) — WARNING: 1 check(s) failed to execute: cookie_flags`.
- Tests both directions: a forced failure must appear; a clean run must NOT carry the warning.

**Remaining (#54):** propagate `_swallow` across all engine paths; liveness gate asserts zero swallows on
standing labs; `except: pass` in an engine path becomes a lint failure like the no-island rule.

---

## S2 — Async correctness · **CLEAN**

Swept all 173 modules for the classic event-loop killers.

| check | result |
|---|---|
| coroutine called without `await` | **none** |
| `time.sleep` inside `async def` | **none** — all 3 sites (`cloud_iam.py` ×2, `intel_feeds.py`) are in sync functions |
| sync HTTP (`urlopen`/`requests`) inside `async def` | **none** — all 5 sites are in sync functions |
| unbounded `communicate()` | 1 found → see S3 |

Conclusion: the "everything hangs" instinct is **not** an event-loop starvation problem. It is S1.

---

## S3 — Fire-and-forget task with no reference · **MEDIUM** · RESOLVED (`40f59b7`)

`main.py:3352` — `asyncio.create_task(proc.communicate())`. asyncio holds only a **weak** reference, so
the task could be garbage-collected mid-execution, and an unbounded `communicate()` on a hung child
leaks it for the life of the process.

Fixed: held in a module-level `_BACKGROUND_TASKS` set with a done-callback discard, and bounded by
`wait_for(300s)` with a kill on timeout.

---

## S4 — Engines with no possible caller · **HIGH** · RESOLVED (`pending commit`)

### First pass was WRONG — recorded because the error is instructive

I first reported **10 unreachable engines**, from: 91 engines defined in `tools.py`, 81 referenced in
`agent.py`, therefore 10 orphans. **That test is invalid.** `execute()` dispatches by
`getattr(self, "_" + tool_name)`, so an engine is reachable if *anything* emits its name — and there are
**two** emitters, not one:

1. the deterministic planner (hardcoded lists in `agent.py`) — the only one I checked;
2. the **agentic path**, via the `CLAUDE_TOOLS` spec handed to the model.

Re-measured against both: **8 of the 10 are in `CLAUDE_TOOLS`** and reachable by the agentic path.
`enumerate_ids` is reachable too — it is advertised under a bare name with a thin `_enumerate_ids`
method (line 1803) forwarding to `_run_enumerate_ids` (line 1759).

**Wrong by nine.** Same failure mode as the two "missing engine" calls earlier in the session:
concluding from one grep. The lesson is now a permanent test rather than a note.

### The real finding: exactly ONE engine

**`run_external_surface`** — implemented (~70 lines, writes `recon["external_surface"]`), registered in
`PermissionLevel` tagged `#114`, and present in **neither** `CLAUDE_TOOLS` **nor** the planner. Nothing
could invoke it. It is the completed feature from task #14 (*external attack-surface recon*): built,
marked done, and it never ran once.

**Fixed:** added to `CLAUDE_TOOLS` so the agentic path can select it.

**Guarded, both directions** (`tests/test_engine_reachability.py`):
- every defined engine has a possible caller, aliases counted;
- **every advertised spec name resolves to a real `_<name>` method** — the stronger direction, which
  catches a rename that updates the method but not the spec, i.e. a tool the model can select that then
  fails at call time;
- plus a non-vacuity assertion, because a scan over empty sets passes for free.

---

## S5 — Falsy-default substitution · **CLEAN**

98 `x or DEFAULT` sites. Refined to those replacing a falsy value with a **non-empty** default — the
shape that silently discards a meaningful empty input: **zero**. All 98 are `or []` / `or {}` / `or ""`,
empty→empty, harmless.

## S6 — Mutable default arguments · **CLEAN** — none.

## S7 — ReDoS / nested quantifiers · **CLEAN**

No true nested-quantifier regexes in shipping code. (The one real instance found earlier this session —
`crawl.py` `_TAG_RE` — was bounded at the time it was written.)

## S8 — Our own command injection (`shell=True`) · **CLEAN**

Only match is `codereview.py:93`, which is Apolaki's own *detector rule* for the pattern, not a use.

## S9 — Proof-gate coverage · **HEALTHY**

54 modules emit `confidence: confirmed`; `demote_unproven` / `get_findings_gated` are applied in
`db.py`, `report.py`, `main.py`, `agent.py` — the four real boundaries. (Regression from #51, where the
gate reached 1 of 14 consumers, has held.)

## S10 — Secret leakage · **HEALTHY**

No logging of `session_headers` / `Authorization` / cookies / passwords / api keys. Nine redaction
helpers across `bie`, `capture`, `poc`, `vault`, `sarif_io`, `field_authz`, `mitm_addon`,
`tool_provenance`, `codereview`.

---

## Standing conclusion

The codebase is **healthier than the S1 headline suggests**. Seven of ten sweeps came back clean or
healthy. There is exactly one systemic defect — **S1, silent failure** — and it is the one that matters,
because it is the mechanism by which every other bug this session stayed invisible.

Ranked by effect on findings:
1. **S1** — silent failures. Mechanism shipped; propagation outstanding (#54).
2. **S4** — one dead engine, now reachable and guarded.
3. Everything else — clean.

---

## Change log

| date | commit | change |
|---|---|---|
| 2026-08-10 | `40f59b7` | S1 mechanism: swallow ledger + `_run_web_probes` reporting; S3 orphaned task |
