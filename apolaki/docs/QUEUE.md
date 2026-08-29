# QUEUE — the one canonical, dependency-ordered work queue

## CYCLE 15 — 2026-08-29 — the Shopify-engagement remainder. OWNERSHIP TABLE, authoritative.

Three lanes, disjoint write sets, declared before spawn. The Coordinator owns this file and
`docs/STATUS.md` and writes no product code this cycle.

| Lane | Shape | Ticket(s) | WRITES (exclusive) | Handoff |
|---|---|---|---|---|
| A | Builder | Q-113 sweep cap + value ranking | `agent/agent.py`, `agent/tests/test_injection_sweep_is_bounded.py` | `docs/handoff/q113_sweep_cap.md` |
| B | Builder | Q-112 middlebox differential, then Q-114 host-header grading | `agent/tools.py`, `agent/web_security.py`, `agent/middlebox.py`, `agent/tests/test_middlebox_is_not_a_clean_result.py`, `agent/tests/test_host_header_grade_needs_a_sink.py` | `docs/handoff/q112_middlebox.md` |
| C | Breaker (READ-ONLY) | Q-109 hostless endpoint nodes -- find the PRODUCER | no product code; diagnosis + exact patch only | `docs/handoff/q109_hostless_producer.md` |

Lane C is read-only deliberately: the producer is unknown, and every plausible home for it
(`agent.py`, `planner.py`, `intel.py`) is either owned by another lane this cycle or shared. A
diagnosis with a measured reproduction is the completable result; the patch lands next cycle.

### Q-114 · Host-header injection is graded MEDIUM with no check for a sink · **READY** · **MEDIUM**

**Filed from the field.** The Shopify run raised 8 host-header injection findings on `linkpop.com`.
Eight of nine survived the structural oracle (Q-106b) and the operator reproduced one by hand:

```
curl -is https://linkpop.com/054470-ee -H 'Host: bbh-evil.example'
HTTP/1.1 301 Moved Permanently
Location: https://bbh-evil.example/054470-ee/index.html?s=1
Server: UploadServer
```

**The behaviour is REAL. The grade is not earned.** Host-header injection is only exploitable
through a sink, and the operator probed both:

- **Shared cache** -- absent. No `Age`, no `X-Cache`, no `CF-Cache-Status`, no `Via` on any
  response. Nothing stores the poisoned redirect, so no second visitor ever receives it.
- **`X-Forwarded-Host`** -- ignored. Supplying it returned a `Location` pointing at the legitimate
  host, so the reverse-proxy route into the same primitive does not exist either.

`Server: UploadServer` is a Google Cloud Storage bucket website, where building the redirect from
the supplied Host is stock platform behaviour rather than an application defect.

**So the correct output was INFORMATIONAL, and Apolaki said MEDIUM unconditionally.** That is the
Q-106 lesson at the grading layer rather than the oracle layer: the detection was sound and the
severity was asserted, not measured. A MEDIUM sent to a mature program on this evidence is closed
N/A, and N/A closures cost the reporter signal.

**FIX.** Before grading, probe for the sink the severity claims: re-request with the spoofed Host and
look for cache indicators (`Age` / `X-Cache` / `CF-Cache-Status` / `Via` / a `Cache-Control` that
permits shared storage), and separately test `X-Forwarded-Host`. Grade MEDIUM only when at least one
sink answers; otherwise INFORMATIONAL with the detail saying which probes came back empty.

**GATE:** the linkpop response shape above, with no cache headers and `X-Forwarded-Host` ignored,
grades INFORMATIONAL. Negative control, and it is the half that keeps this an oracle: the same
redirect **plus** `Age: 0` and `X-Cache: HIT` still grades MEDIUM, so the fix cannot be satisfied by
downgrading everything.

### Q-115 · The Assessment Coverage summary disagrees with the ledger and the heartbeat · **READY** · **MEDIUM**

Every Shopify snapshot carries three counts of the same quantity and no two agree:

```
Assessment Coverage:  Tools Invoked 848 | Distinct Tools 8
Execution ledger:     31 rows, 2181 calls
mission_heartbeat:    dispatches 2181
```

The ledger and the heartbeat agree at 2181 (Q-105 and Q-107 made both cumulative). The report's own
summary header does not, and `Distinct Tools: 8` against 31 ledger rows is the louder half -- the
header is counting a narrower population than it labels.

**Whichever number is right, a report that states the same fact three times with two different
answers is not evidence.** This is the reporting-layer instance of the week's class: a value
measured correctly somewhere and re-derived wrongly at the edge that the reader actually sees.

**NOT INVESTIGATED.** The producer of the header counts has not been located; start from the
`Assessment Coverage` renderer in `agent/report.py` and compare its population to
`db.execution_ledger`.

## STATE SWEEP — 2026-08-17 night, THE TAIL, verified against code. Authoritative; supersedes every marker below.

The tail is no longer UNKNOWN. Two lanes verified every remaining ticket against code rather than its
marker, over ten committed verdict batches in `docs/handoff/tail_sweep.md`. Verdicts:

**DELETE — these are not tickets and the queue should stop carrying them (5):**
- **Q-006** request smuggling — a standing DECISION already enforced in code:
  `wstg_catalog.EXCLUDED["WSTG-INPV-15"]` refuses desync under the no-collateral rule and `coverage()`
  counts it in `tally[excluded]=5` rather than losing it in `none`. Tiers 1 and 2 were never begun.
- **Q-009** audit findings pending verification — two of the four were already fixed.
- **The Q-019 Rank-3b DUPLICATE** at `QUEUE.md:1665` — the same ticket twice, in two states.
- **B-011+** — a roadmap row, not a ticket.
- **the "unexplained sublinear per-URL cost"** — a real and still-interesting OBSERVATION (+22%
  measured against +57% predicted), but not a unit of work. It stays recorded in `agent/agent.py`
  where the number is used; it is not a queue item.

**CLOSED:** Q-001, Q-015, Q-016, Q-021B (shipped and wired at `tools.py:3994`, 47 tests, all three
negative controls pass live), Q-072 (the `00438` claim, corrected in product source).

**OPEN, with the scope corrected:**
- **Q-017 SPLIT** — the logs half is closed; **13 raw vs 7 gated `get_findings` sites** are live.
- **Q-018 do NOT delete.** Only the unscoped branch was disproved. The fail-open reproduces live:
  `load_manual([{...}])` raises, `main.py:2998` sets `_eng = None`, and the guard is skipped.
- **Q-021D** `ingest()` reaches `candidate`, `production()` stays 0, `advance()` has no caller
  outside tests. **Q-021E** re-scoped DOWN: Q-021B already emits `has_versions`; only the consumer is
  missing. **Q-021F** low.
- **Q-022 -> narrowed and re-filed as Q-071**, which is worse than the original.
- **Q-023 REWRITE** — 2 of 3 sub-defects closed, consumer contract met, one live clause left.
- **Q-030 RE-SCOPE** (built except D14/D15), **Q-035** unstarted and an experiment rather than a
  defect, **Q-036 REWRITE** — at least 4 of its 15 defects are already fixed.
- **Q-003 / Q-004 / Q-005** remain open capability work.

**THREE MIS-SPECIFIED ORACLES would each record a FAIL against working code** — Q-019(c), Q-022(2),
Q-021B(1); Q-021B's oracle contradicts its own false-positive section. Rewrites are in the handoff.
**A ticket can be closed by the code while its stated success criterion still reads red, and only
checking BOTH catches it.**

**THREE CONTRADICTIONS INSIDE THIS FILE:** `:1050` vs `:2810` (Q-023), `:1025` vs the bodies
(Q-015/16/17), `:1042` vs `LEDGERS.md:2106` (Q-030). And **Q-030/035/036 have no body here at all** —
they live in `QUEUE_ARCH.md`, so this queue names three tickets a reader cannot open.

## STATE SWEEP — 2026-08-17, the stale tail. Verified against CODE, not against markers.

Erwin asked whether the queue was empty. The honest answer was that I could not tell: everything
below the previous sweep still read `proposed`/`ready` from before six closes. So I checked the claims
instead of the labels. **Every line below is measured, with the probe stated, because two of my first
three probes were wrong and produced false results I nearly recorded.**

**CLOSED — verified in the running container:**
- **Q-008 / Q-011** (`run_mass_assignment` phantom, and `mass_assignment` the "second phantom"):
  `agent/mass_assign_tool.py` exists; `run_mass_assign` is registered, dispatchable AND advertised;
  the phantom name `run_mass_assignment` is absent. Both closed.
- **Q-012** (six ASVS engine names resolve to nothing): **0 unresolvable names across 33 ASVS rows.**
  My first probe said 12 — it was wrong: `engine` may hold a TUPLE of names, and `n/a` is a
  deliberate sentinel. Fixing the probe took the count to zero.

**OPEN and CONFIRMED, with the measurement:**
- **Q-020** (technique records declare no executor, so the no-island guard checks a declaration):
  **CONFIRMED.** All **88 of 88** techniques carry `execution: "auto"` — the field has exactly one
  value across the whole registry — and `agent/tests/test_techniques.py:17` asserts
  `execution in ("auto", "operator")`, a guard that **cannot fail**. My first probe here also lied:
  it read `engine`/`executor` and reported "88 of 88 declare no executor", which was my wrong field
  name, not a finding. The real record key is `execution`.

**NEW, and it upgrades two tickets into one root cause — see Q-066.**

### Q-066 · Two vocabularies for the same thing, and nothing joins them · **CLOSED** `5583ff2` `cea1e2e` `0f735bc` `2ea0c35` `9c9f290` `7a73f7b` `955f08f`

**CONFIRMED IN SUBSTANCE, BUT I HAD THE MECHANISM WRONG, and the wrong mechanism pointed the fix at
the wrong pair of tables.** Recorded prominently because the ticket was mine and a lane spent its
first phase disproving it, which is exactly what it was asked to do.

**My error:** I wrote that `EFFECTS` speaks a capability vocabulary while `PRECONDITIONS` speaks
technique ids. They are the SAME vocabulary — **13 of 13 `EFFECTS` keys and 42 of 42 `PRECONDITIONS`
keys are technique ids**, and 0 of 42 `PRECONDITIONS` keys are engine names either. My two rows were
measured against *different reference sets*, so the contrast was an artifact of the probe.
`jwt_forge` and `jwt_key_confusion` are not a separate vocabulary; they sit in `PRECONDITIONS` too.
That is my third instrument error in this sweep, after the tuple-valued ASVS `engine` field and the
wrong technique field name.

**The real gap, measured properly:** no technique record field holds an engine name — an exact-value
match over all 25 field names on all 88 records — and `descriptor()`/`build()` add none, which is the
part my public-surface probe could not see. Positive control: the identical probe found **29 of 33**
`asvs_model` rows carrying `["engine"]`, so it was capable of finding one. Independently corroborated
by `report.py:1831`, which already tells operators the report cannot link techniques to tools.

**The join, DERIVED not typed:** `engine_descriptor.routes()` builds technique id -> engine from two
tables that already existed — `ALWAYS_ON` reason prose (already mined by `verify_always_on()`) and
`technique["wstg"] -> wstg_catalog.FULL[wstg]`. **75 of 88 routed, 0 phantom.** Two candidate sources
were measured and **rejected**: `wstg_catalog.PARTIAL` (it means "does not confirm", and would have
routed coupon-forgery to `run_hash_id`) and `asvs_model` vuln_class (disagreed with the kept sources
on 22 of 33). Two rules, no per-technique list, so it generalises. The 13 that stay unrouted genuinely
have no engine.

The phantom guard reads source prose **by shape** rather than `routes()` output — filtering candidates
by the registry and then asserting registry membership is the guard-that-cannot-fail trap, and the
lane mutation-verified that applying that trap makes the Q-011 `run_mass_assignment` phantom vanish
and the audit report `ok`.

### Q-020 · Technique records declare no executor · **CLOSED — now FAILABLE**

All 13 unrouted techniques are `auto` + `oracle` + `transferable`, so the no-island guard certified
every one of them as reached while nothing dispatches them. `/orchestration` now serves
`no_islands: True` beside `unroutable: 13` **on one payload**, which is what makes the contradiction
visible instead of arguable.

### Q-065 · `run_jwt` never fires on a JWT-authenticated target · **CLOSED** — both causes

Cause 1 was the missing route (Q-066). **Cause 2 was a second vocabulary mismatch and is the fifth
instance of that shape in this codebase.** `planner.py:641` gates `run_jwt` on
`state["auth_headers"]`; `agent.py:3305` built that state with 13 keys and `auth_headers` was not one.
`auth_headers` is the API REQUEST field (`main.py:59`) and `main.py:554` immediately renames it to
`session_headers`, which is what the registry holds (`tools.py:1155`).

**So the JWT blob was always `{}` plus recon cookies: only a COOKIE-borne JWT could ever schedule
`run_jwt`, and a Bearer token — the normal carrier, and what every SPA holding its token in
localStorage uses, which is Juice Shop's own shape — never could.** The lane measured it by driving
the real `next_batch`: 34 tools with the key, 33 without, difference exactly `{run_jwt}`.

Fixed in `agent.py` by binding `auth_headers` from `self.tools.session_headers`. The lane's pinned
defect test is **inverted, not deleted**, and a negative control asserts a Basic-auth header still
schedules no `run_jwt` — the fix buys reachability, not an unconditional dispatch.

MEASURED via `agent/engine_descriptor.py`'s public surface:

```
PRECONDITIONS  42 keys, 42 of 42 ARE technique ids          -> techniques DO bind here
EFFECTS        13 keys,  0 of 13 are registered engine names -> nothing binds to the registry
  sample EFFECTS keys: browser_persona_bola, default_credentials, exposed_files_harvest,
                       graphql_introspection, jwt_forge, jwt_key_confusion
```

The effects model speaks capability names (`jwt_forge`, `jwt_key_confusion`); the engine registry
speaks engine names (`run_jwt`). **No join was found on the descriptor's public surface.** That is
precisely why the planner can rank a technique it has no route to execute — **Q-065 (`run_jwt` never
fires while the autonomy loop writes "next-best actions: weak_secret_forgery") is not an isolated
gap, it is this.** And `execution: "auto"` (Q-020) is the same hole seen from the technique side:
"something will handle this" without saying what.

**This is the FOURTH instance of one defect shape in this codebase: two vocabularies describing the
same thing that never meet.**
1. `mode` vs `strategy` in the tool ledger — the fallback could never fire (FIXED).
2. ToolResult name vs dispatch name — a false integrity alarm (Q-064).
3. Technique/effect names vs engine names — the planner cannot route (this, Q-020, Q-065).
4. And the same shape produced the original `blocked_by_mode` merge.

DoD: one measured join between the effects model and the engine registry, or an explicit decision
that routing is intentionally indirect plus a guard that FAILS when a technique or effect names
something unroutable. **Do not close Q-020 or Q-065 separately from this.** Note the honest limit of
the current measurement: only the descriptor's public surface was checked, so a join implemented
inside `build()`/`descriptor()` would not have been seen — establish that before building anything.

**STILL UNSWEPT, and I am not guessing:** `Q-001`–`Q-006`, `Q-015`–`Q-019`, `Q-022`, `Q-023`,
`Q-030`/`035`/`036`, `Q-040`–`Q-044`, `B-011+`, the ninth baseline case `00438`, and the unexplained
sublinear per-URL cost. Their markers predate several closes and I have not verified their claims
against code. **Treat every one as UNKNOWN rather than open.** Q-040/041/042 are pinned by strict
xfails that still exist in the tree, which is evidence those three at least are real.


## STATE SWEEP — 2026-08-16 evening. Authoritative. Supersedes every marker below.

**I let this rot again.** Q-050/051/052/053/057 all still read `proposed` further down while being
wholly or partly closed. The rule I wrote after the last rot — *closing a ticket updates this block in
the same commit* — I then broke across six closes. A queue whose state cannot be trusted is the same
declaration-vs-fact defect the code keeps producing, and it is the one artifact every lane reads first.

**CLOSED, with commits:**
- **Q-051** — engine bound at `ToolResult`, per-finding attribution in BOTH renderers, ledger/finding
  cross-check, technique coverage section. `620fcbb` `bc60727` `da798bc` `93ca3dd`
- **Q-053** — all four family gaps + AUTHN-02 now failable. `7ce79bb` `fb6f457` `7fbd1bf` `44a6cbf`
- **Q-057** — three content-discovery adapters deleted entirely (specs, methods, permissions,
  `_bin_discovery`). `466bae8`
- **Q-021C** — one technology-intelligence chain closed end to end (version selects the probe set).
  `2480c75` and the techintel lane's own commits
- **Q-056** — PARTLY gateable, which is the honest answer the DoD allowed for. 2 rules ship at 0 FP
  over 111 engines, 3 rejected with their numbers. `5958de1` `717900c` `5bad1d3`. Coordinator
  re-ran the gate against the LIVE tree (not the lane's pinned snapshot) with a positive control
  showing 111 engines parsed: the lane's 2 flags reproduce exactly, so the gate is not an island and
  the two lanes have not collided.
- **Q-032** — `Identity`: a persona request can no longer carry the mission's session. `4982d3b`
- **Q-050(a)/(b)** — measured and DIAGNOSED in full; seven soundness verdicts landed. The *wiring* is
  deliberately not done and is not a loose end: three engines were deleted, and the rest each need an
  oracle-soundness argument the audit says cannot be made from static reading.

**OPEN, and honestly ranked:**
- **Q-059** the DEPLOYED platform is 59 commits behind the tree and `bake_drift_check.sh` structurally
  cannot see it (it checks container-vs-image, never image-vs-tree). **CRITICAL — read it before
  quoting any live-mission result**, because the running binary lacks the Q-051 reporting code
  entirely and still carries the three adapters Q-057 deleted.
- **Q-060** `_do_transport_posture` / `_do_header_trust` invent a default port from a scope entry that
  has already dropped it, so they cannot audit ANY target on a non-standard port — i.e. the whole
  local lab fleet.
- **Q-054** `run_workflow` finding sink — **CLOSED**, all three sinks. `4bb5d2b` plus the
  `_AUTO_STORE_TOOLS` wiring and the island pins inverted.
- **Q-055 / Q-055b** `run_metadata` GPS false negative **CLOSED** `07710fc`; the bfla mirror **CLOSED**
  `37a3edc` — its "authenticated" row was anonymous, which made the oracle VACUOUS on every target.
- **The ledger `mode` key — CLOSED.** `main._tool_ledger()` never emitted `mode`, so
  `report.arsenal_gap()` classified **zero** engines as tier-blocked and ~40 structurally-barred
  engines were reported to the reader as "available but not selected". Reader half had landed; the
  producer half never did. Fixed with a 5-test negative control, all 5 verified failing against a
  mutant.
- **Q-058** four defects the description gate surfaced, all in `tools.py` — `ready`, blocked only on
  the truthful lane releasing that file. Two are docstrings declaring the wrong permission tier; one
  is an advertised parameter (`hash_type`) the code never reads.
- **Q-052** tier semantics — BOTH proposals measured and REJECTED (narrowing `active` costs 49.5% of
  the sweep; defaulting to `full` would enable state-changing writes and lab-mode traversal semantics
  against production). Evidence points at loosening `planner._ALLOWED`, which needs a decision, not a
  patch. **This is the oldest unresolved item and it is a product question, not an engineering one.**
- **Q-021 (server/language half)** — still a version reporter; needs a probe that makes a request
- **Q-002/003/004/005/006**, **Q-030/035/036**, **B-011+**, the baseline's ninth case `00438`, and the
  unexplained sublinear per-URL cost

---

### Q-054 · `run_workflow` is a FINDING SINK, two sinks deep · **CLOSED** `4bb5d2b` `fd26118`
Pinned by `agent/tests/test_truthful_workflow_findings.py`, green on a HEAD snapshot 2026-08-19.
`IN FLIGHT` was the state of a lane that finished; nothing updated the header for it.

MEASURED by the islands lane. Same engine, same live target, two paths: `enumerate_ids` over
`/api/Products/{id}` emits an `idor` lead on a direct call and **nothing** through `workflow.run`,
which reads `res.output/success/error` and **never `res.findings`**. The same sink swallows
`confirm_idor`'s confirmed CWE-639 finding — the finding the flagship `idor_read` pack is built on.

`_run_workflow`'s docstring claims the opposite, and `asvs_model.py:308` leans on that claim.
**Second sink downstream**: `run_workflow` is not in `_AUTO_STORE_TOOLS`, so repairing `workflow.py`
alone changes nothing. **DoD: both sinks fixed, proven by a finding surviving a real workflow run —
and do NOT wire the engine before that, or it spends real requests on real attacks and reports
nothing.**

### Q-055 · `run_metadata` reports clean on a file proven to leak GPS · **CLOSED** `07710fc` `fd26118`
Pinned by `agent/tests/test_truthful_metadata.py`, green on a HEAD snapshot 2026-08-19.

MEASURED: 59°25'16.17"N 24°48'4.32"E decoded by hand from the GPS IFD of the Juice Shop geo-stalking
photo; the engine returned "No sensitive metadata". Two causes compose — exiftool is absent from the
image, AND the native fallback's only JPEG branch matches the ASCII string `b"GPS"`, which real binary
EXIF never contains (`b"GPS" in data == False` on the file that HAS GPS). Fixing the Dockerfile alone
leaves a fallback that cannot work; fixing the fallback alone leaves the better reader missing.

### Q-056 · FOUR engines describe capability their code does not have · **CLOSED** `5958de1`,`717900c`,`5bad1d3` — PARTLY gateable; 2 rules ship, 3 rejected with numbers

Answered exactly as the DoD allowed: a gate where one is sound, an explicit "review discipline"
where it is not. `agent/description_gate.py` + 14 tests. Rule A (a `--no-X` flag contradicting the
claim) and rule B (a docstring naming a tier other than the registered one) run over all 111
engines with **0 false positives**. Rules C/D/E were designed, measured and **rejected** — E flagged
7 engines of which **6 were false**, because parameters are consumed indirectly via `dict(inp)` and
`_role_headers(inp, ...)`. `run_metadata` is **not gateable at all**: knowing its claim is false
requires knowing the GPS IFD is tag `0x8825` rather than the string `"GPS"`, which is file-format
knowledge held nowhere in this repo. Only running it catches it — see Q-055. Ledger: `docs/LEDGERS.md`.

### Q-059 · The DEPLOYED platform is 59 commits behind the tree, and the bake gate cannot see it · **CLOSED** `d862690` (gate) `e6fb18a` (rescue) + rebuilt and verified 2026-08-17

**RESOLVED AND VERIFIED, not merely rebuilt.** Sequence mattered: the container-only modules were
rescued FIRST (a rebuild would have destroyed them), the mission DB was confirmed to live on the named
volume `bbh_data` at `/app/data/bbh.db` so recreating the container could not lose 151 missions of
history, and `/missions` was checked for a live run before building.

Measured in the running container AFTER `docker compose build agent && docker compose up -d agent`:

```
Q-051 reporting surface   arsenal_gap / technique_coverage / _technique_md /
                          ledger_finding_disagreement / _arsenal_md   -> ALL True   (were ALL False)
Q-057 deleted adapters    run_ferox / run_dirsearch / run_gobuster
                          registered=False dispatchable=False                       (were both True)
newly baked              description_gate, ws_tool, mass_assign_tool  -> import OK
Q-055 second cause       exiftool on PATH: True                                     (was False)
denominators             TOOL_PERMISSIONS 111, CLAUDE_TOOLS 76        (were 112/77 — now match the tree)
bake_drift_check.sh      exit 0 — "running container matches the baked image, and the image matches
                         the source tree (179 modules, 88 techniques)"
```

The gate went from firing on both edges to clean on all three, which is the proof that the fix landed
rather than the assertion that it did. `exiftool` becoming available also closes the half of Q-055
that no code change could reach — the truthful lane added the Dockerfile line and it needed this bake.

**The measurement that motivated all of this is now REPEATABLE for the first time:** the coverage
sections can finally render in a real mission, so the arsenal-gap question is answerable rather than
blocked. Anything measured against the deployment before 2026-08-17 02:40 describes the STALE
platform and must be re-measured, including the arsenal lane's own live-mission ledger extraction.

<details><summary>original ticket, kept for the diagnosis</summary>

MEASURED by the arsenal lane against the live deployment, and this is the single most consequential
finding of the cycle: **none of the Q-051 arsenal-reporting code exists in the running binary.**

```
docker exec apolaki-agent-1 python -c "import report; ..."
arsenal_gap / technique_coverage / _technique_md / ledger_finding_disagreement / _arsenal_md  -> all False
```

All five exist in the tree. `docker-compose.yml` bind-mounts only `./ui:/app/ui:ro`; the Python engine
code is BAKED, so a source commit does not reach a running mission until the image is rebuilt.
**59 commits touched `agent/` since `apolaki-agent-1` started.** File-level, sha256 first 12:
`planner.py` SAME, `tools.py` DRIFT, `report.py` DRIFT. Note the asymmetry — the permission model is
current while the engine registry and the renderer are stale, so a conclusion drawn from one of those
files does not transfer to the others.

Consequences already confirmed: the three content-discovery adapters deleted in `466bae8` (Q-057) are
**still registered and still dispatchable in the running deployment** (container `TOOL_PERMISSIONS`
112 vs tree 111), and `run_mass_assign` / `run_ws_hijack` cannot fire in any current mission.

**WHY THE EXISTING GATE MISSED IT, which is the actual ticket.** `scripts/bake_drift_check.sh`
compares the RUNNING CONTAINER against a fresh container from the BAKED IMAGE. Both of those can be
identical while the image itself is months behind `HEAD` — and in that state the gate prints
`bake OK`. It was built for a real incident (code `docker cp`-ed into a container and never baked) and
it closes that direction only. **The missing edge is IMAGE vs SOURCE TREE.** DoD: extend the gate with
a third comparison, tree `HEAD` vs baked image, so "deployed" is a measured claim. A gate that checks
two of the three edges is the declaration-vs-fact pattern in a shell script.

DO NOT fix this by rebuilding mid-cycle: `docker compose build` SIGKILLs a running mission and three
have died that way. Check `curl -s http://localhost:8000/missions` first.

**GATE EXTENDED — `d862690`.** `bake_drift_check.sh` now checks all three edges and reports both
classes before exiting, since they have different fixes. Verified by firing on the state it used to
pass: edge 1, 17 modules differing; edge 2, **39 modules differing between tree and image** plus five
never baked at all (`bench_contract.py`, `bench_juliet.py`, `description_gate.py`,
`mass_assign_tool.py`, `ws_tool.py`). The description gate shipped hours earlier has never existed in
a mission.

**BEFORE ANYONE REBUILDS — already handled, `e6fb18a`, but read it.** The same edge found four modules
that lived ONLY in the running container and in no commit: `acceptance.py`, `measure_browser.py`,
`measure_cost.py`, `mission_breakdown.py`. The rebuild this ticket prescribes would have destroyed
them. They are rescued into `scripts/measure/` with a README. **Re-run the gate and check the
"modules DELETED from the tree but still live in the image" and container-only lines before every
rebuild** — that is now the gate's most valuable output, not an aside.

</details>





### Q-078 · Triage the entries Q-077 made visible · **HIGH** · `ready` · **51 -> 44**, and the island was FAIL-OPEN `643a5ca`

#### Coordinator, 2026-08-20 — the structural cut nobody had taken

Five lane runs triaged this one function at a time. Grouping the 51 by MODULE first answers seven of
them in one measurement, and finds the thing the ticket exists to find.

**First, the hypothesis that was WRONG, stated because ruling it out is what made the next cut
obvious.** "A whole module is dead" -- **disproved**: all 36 modules holding a flagged function are
imported by production. There is no dead module. The 51 are genuinely per-function.

**Then the one that was right.** Resolving calls by AST across every production module, handling
BOTH `import x as y` and `from x import f`:

    ics_fingerprint     0 call sites, all 8 public functions unreachable
    POSITIVE CONTROL    db 153 call sites; service_router 7

**My FIRST pass was wrong and the correction matters.** It looked only for `mod.attr(` and reported
zero for `service_router` too. `service_router` actually has 7 call sites, reached through import
forms that pattern cannot see -- the same instrument error this project has paid for repeatedly. The
corrected instrument still reports **0 for `ics_fingerprint`**, and that zero has a working positive
control beside it.

`service_router.py` imports the module and uses exactly **one dict** from it, `PROTO_PORTS`. Nothing
calls any of its eight functions.

**AND IT WAS CITED AS A SAFETY CONTROL.** `service_router.py:35` read:

> "Apolaki NEVER writes to them -- `ics_fingerprint.is_write_frame` is the safety self-check that
> proves every industrial frame it builds is read-only."

That names a function that never runs. **The protection is real and was verified before anything was
concluded** -- it lives in two other places, in two different correct forms:

    modbus_audit_tool.py   safety by CONSTRUCTION: builds only 0x2B/0x0E and 0x03. Writes are
                           categorically absent from the code, not gated. This is what
                           `_run_modbus_audit` actually dispatches.
    ics_dnp3_s7.py         safety by RAIL: `_send_recv` calls `is_write_frame` on every frame
                           immediately before the wire, returning "REFUSED: a frame failed the
                           read-only safety rail" instead of sending.

So there is **no safety hole**. There was a false citation, in the corner of the product where being
wrong moves a valve or trips a breaker, and an auditor following that comment would have landed on
dead code and concluded the rail was live. **Corrected in place**, naming the code that executes,
with the measurement inline. 85 passed / 1 skipped / 1 xfailed across the ICS, service-router,
dead-code and mutation-gate tests.

**STILL OPEN, and deliberately not done on momentum**: `ics_fingerprint.py` is a dead DUPLICATE of
live functionality -- its own `is_write_frame`/`is_read_only` pair, its own probe builders. Removing
it would drop the ratchet 51 -> 44 in one commit. It carries six tests, and `PROTO_PORTS` must
survive and move to a live owner. **Eight functions with tests in safety-adjacent code is not
something to delete on a roll**; the evidence is here and the decision is explicit. Whoever takes it:
keep `PROTO_PORTS`, prove the tests are testing the dead copy rather than the live rail before
deleting them, and do not touch `ics_dnp3_s7.py`.

Q-077 switched the dead-code resolver from regex over source text to AST resolution, so comments and
string literals stopped counting as calls. **The count went 35 to 61 against a ceiling of 37.** The
code did not rot; the measurement got honest, and 27 entries that were always dead became visible.

**The ceiling was NOT raised.** Raising 37 to 61 would be weakening a ratchet to make a change pass.
The ratchet is pinned by a STRICT xfail carrying the measurement, and it XPASSes the day a triaged
baseline lands.

**The real island count is LOWER than 27, and nobody may quote 27 as it.** At least four are resolver
blind spots rather than dead code:

- `deadcode_gate.scan`, `scan_methods`, `scan_qualified` - the gate EXCLUDES ITS OWN FILE (correctly,
  to avoid the self-read that took the method count to 0), so its own public API reads as uncalled
  while tests and `scripts/liveness.sh` call it.
- `mitm_addon.request`, `mitm_addon.response` - framework callbacks. The proxy container mounts
  `mitm_addon.py` and **mitmdump invokes them by name** (`docker-compose.yml:419`); no Python code in
  `agent/` calls them and none should.
- `sqli_tool.is_inconclusive` - re-exported by `nosqli_tool` as the shared third-outcome convention
  from Q-070, so the caller reaches it through the other module.
- `description_gate.audit` - called by its own test file, which the resolver does not scan.

The full 27: `api_protocols.inventory`, `archive_intel.needs_validation`, `bench_all.bench`,
`bie.observe`, `capability_matrix.state_rank`, `cloud_iam.collect_live`, `codereview_graph.hypotheses`,
`codereview_graph.link_runtime_to_source`, `deadcode_gate.scan`, `deadcode_gate.scan_methods`,
`deadcode_gate.scan_qualified`, `description_gate.audit`, `engine_descriptor.effects_audit`,
`exposure_tool.paths`, `fingerprint.fingerprint`, `ics_dnp3_s7._dnp3_crc_table`,
`ics_fingerprint.finding`, `intel.harvest`, `mitm_addon.request`, `mitm_addon.response`,
`report.control_ran`, `saml_tool.finding`, `service_router.plan`, `sqli_tool.is_inconclusive`,
`ssrf_tool.bypass_payloads`, `techniques.classes`, `tool_provenance.argv_hash`.

DoD: classify every one as REAL ISLAND, FRAMEWORK ENTRY POINT (called by something outside `agent/`),
or RESOLVER BLIND SPOT, each with the evidence. Then either wire the real islands or record the
non-islands in an allowlist that states WHO calls them and from where. **The allowlist must name the
caller** - an unexplained allowlist entry is how a gate becomes decorative, which is the defect this
whole line of work exists to prevent.

### Q-077 · A COMMENT mentioning a function makes it look alive to the dead-code gate · **HIGH** · **CLOSED** `1a6de59`

Found by the postMessage lane while clearing an island the gate had flagged. **The gate under counted
its own finding.**

`scan_qualified` regex matches the bare name anywhere in the defining module, **comments included**.
`find_message_listeners` and `wm_scan_hint` were BOTH uncalled and both absent from the failure list,
because both are named in an explanatory comment. The island was **seven functions, not five**.

That is the declaration versus fact pattern living inside the instrument built to detect it: prose
about a function counts as a use of the function. It also means the recorded baselines (35 qualified,
13 method) are floors rather than truths, and any module carrying a well commented helper is
systematically under reported.

The lane's own new tests read identifiers **off the AST**, so a comment cannot pass for wiring. That
is the fix shape, applied to the gate itself.

DoD: `scan_qualified` and `scan_methods` resolve references from the AST rather than by regex over
source text, then re baseline both sets and record the delta. **Negative control:** a function
mentioned ONLY in a comment must appear as dead; a function actually called must not.

Related and already closed: Q-075 fixed the same file printing a slice instead of a delta. This is
the other half, and the two together mean the gate was both mis reporting WHICH entries changed and
missing entries entirely.

### Q-076 · `test_proof_gate_reach` has 3 slack and names ZERO of its findings · **HIGH** · **CLOSED** `b092a18`

Found by the Q-075 anti-idle audit, and it is the worst instance of the count-instead-of-delta shape
still live.

MEASURED: **11 raw `db.get_findings()` sites against a ceiling of 14 — slack 3** — and the failure
message names **none** of them, while `_raw_call_count()` has every `file:line` in hand and throws it
away.

**The damage is not hypothetical and the file records it in its own comment:** SARIF sat raw while
its sibling export was gated, and the count stayed under the ceiling, so the gate said nothing. With
3 slack, one site can be resolved and a new one introduced **at constant count** and this gate is
structurally incapable of noticing.

DoD: record the baseline SET, not just the ceiling, and print the true set difference — the same fix
Q-075 applied to the dead-code ratchet, and the same shape `liveness.py::evaluate()` has had all
along (`regressions = base - confirmed`, named). **Negative control:** resolve one site and add
another in the same run, and confirm the message names both while the count is unchanged.

Also from that audit: `test_mutation_gate.py` is MILD (46 uncovered vs ceiling 46; it prints all 46
names, so the delta is present but must be eyeball-diffed, and it already keeps a partial recorded
set of 8). `test_description_gate.py` and `test_island_soundness.py` are CLEAN.

### Q-075 · The dead-code gate names the WRONG functions · **CLOSED** `4c50007` `dce91a3`

The ratchet fired correctly and then misdirected the reader, which is the part worth fixing.

MEASURED. It reported `qualified dead-code count rose to 40 (baseline 37)` and listed as
"New entries": `technique_store.stats`, `techniques.techniques_for_lab`, `waf_bypass_tool.pad`,
`web_security.is_url_in_scope`, `xxe_tool.looks_like_xml`. **None of those is the delta.** The actual
newly-dead set, obtained by running `deadcode_gate.scan_qualified()` on the worktree and on a clean
`git archive HEAD` snapshot and diffing the `unused` lists, is five entirely different names:

```
worktree  count 40  baseline 37  ok False
HEAD      count 35  baseline 37  ok True
newly dead: dom_tool.wm_family, wm_finding, wm_lead_finding, wm_payloads, wm_reportable
```

The message appears to print a slice of the sorted list rather than the set difference against the
previous state. **Cost: four probes chasing five files this cycle never touched**, plus a wrong
hypothesis that a reference had been removed somewhere.

Why it matters beyond tidiness: this gate exists to catch islands, and it CAUGHT ONE correctly. A
gate whose alarm is right but whose message points elsewhere trains its readers to distrust it, and a
distrusted gate gets silenced -- the same fate this project has already reasoned about for the
`errored` class and for `ledger_finding_disagreement`.

DoD: the failure message prints the true set difference. Negative control: introduce a deliberate
island and confirm the message names THAT function and no other.

### Q-074 · The negative-effects model is now EMPTY, which is honest but not informative · **MEDIUM** · `ready`

Successor to Q-007, and stated plainly so nobody reads that close as "the planner now knows about
conflicts". Coordinator-verified after the fix: `conflicts()` returns **0 rows** (was 6), `EFFECTS`
holds **11** entries (was 13), and `weak_password_reset` is gone.

**We did not gain conflict information. We stopped having FALSE conflict information.** Every one of
the six rows was generated by an engine that cannot run, so removing it is strictly correct — but the
Sussman half of the planner model is now empty, and an empty model and a correct model produce the
same plan for different reasons.

The mirror defect named in Q-007 is still open: **`session_lifecycle` actually destroys sessions and
declares no effects at all.** That is the real invalidation the model was missing while it carried a
fictional one. DoD: populate `invalidates` from engines that genuinely have them, starting with
`session_lifecycle`, each backed by a measurement of what the engine does to state rather than an
assertion about what it should.

The guard that shipped with Q-007 must keep failing on a phantom — check it still does after any
entry is added, because a guard written against an empty set is the easiest kind to satisfy
vacuously.
### Q-073 · A test-ordering dependency hid behind `asyncio.get_event_loop()` · **CLOSED** — same commit

Not a product defect, and worth recording precisely because it LOOKED like one: an 11-failure red
suite arriving in the same cycle as a transport change is the shape of a real regression.

`tests/test_bbh.py` ran its coroutines on whatever loop happened to be ambient
(`asyncio.get_event_loop()`). That held for as long as nothing else closed one. `test_backoff_ledger.py`
sorts BEFORE it and uses `asyncio.run()`, which closes its loop and leaves the current loop unset —
and on Python 3.12 `get_event_loop()` then raises `There is no current event loop`.

**The diagnostic that settled it in one command: `test_bbh.py` passes 244/244 in isolation while 11
of its tests fail in the full suite.** That signature — green alone, red in company — is an ordering
dependency, never a defect in the code under test, and it is worth reaching for before reading any
diff.

Fixed by giving the module a loop it OWNS, kept module-wide rather than per-call because objects
built in one `_run` are used by the next. **The semantics the tests were written against are
unchanged; only the dependency on ambient global state is gone.** The last direct
`asyncio.get_event_loop()` caller in the file was routed through the same helper, so there is one
loop policy in the file instead of two.
### Q-071 · The Q-022 fix reports "no control recorded" on the ONLY findings that have one · **HIGH** · **CLOSED** `b2b5051`

Found by the tail sweep, **independently re-measured by the Coordinator against the live database**
before filing, because it accuses a shipped fix:

```
POSITIVE CONTROL total stored findings: 1057
carry a real nested control (browser_evidence.negative_controls):  3
carry a TOP-LEVEL negative_controls:                               0
control_status() -> RECORDED:                                      0
```

`control_status` scans **top-level keys only**. The sole producer that records negative controls is
BIE, and it writes them **nested** under `browser_evidence.negative_controls`. So the report prints
**"NO NEGATIVE CONTROL WAS RECORDED"** directly beside a table listing three real controls for that
same finding. The document contradicts itself on the page.

**Two things make this worse than an ordinary bug.**

1. **The test is vacuous, and vacuous in the way this project has been bitten by three times.** Its
   fixture invents a **top-level** shape that no producer emits, so the suite is green while the
   feature is inverted in production. A fixture copied from a real BIE finding would have failed on
   day one.
2. **The ticket's own number does not reproduce.** Q-022 says 34 findings carry a control; the
   database says **3**. The problem was worse than filed, and the fix was measured against a
   population that does not exist.

DoD: read the nested location (and any other real producer shape, established by measurement, not
assumption); **rebuild the fixture from a stored BIE finding**; and keep the mandatory negative
control from Q-022 — a finding with genuinely no control must still report none. A fix that makes
everything read RECORDED is strictly worse than the bug.

### Q-072 · `00438` was never unprobed, and the false claim was pinned in product source · **CLOSED** — comment corrected

Recorded rather than silently fixed, because the failure was mine and it is instructive.
`agent/agent.py:219` carried, for days, "00438, the ninth case, is still unprobed", and every budget
discussion since was priced against it.

MEASURED against mission `ebd96f45`: `00438` was probed by **eight** engines (`run_sqli`,
`run_sqli_structural`, `run_injection_probes`, `run_xpath`, `run_ldap`, `run_ssi`,
`run_css_injection`, `run_waf_bypass`) and produced a **confirmed** `sqli` finding, identically to
the other eight cases. Negative control: the paired mission `90cee81c` shows 0 log rows and 0
findings for it. The selection model picks it at index 58 with the cap at 700 — **12 slots to
spare** — so raising the cap could never have been the fix for a case the cap already covered.

**Where the claim came from, which is the part worth keeping:** the wp3 seal has 0 mentions of
`00438`. But that seal's keys carry **claims only, with no probed-cases list**, so "unprobed" was an
inference from "no claim". **Absence of a claim is not evidence of absence of a probe** — the same
mistake as reading a zero from an apparatus that was never looking.
### Q-070 · One repeat cannot establish stability on a BIMODAL page · **CLOSED** end to end `cd5ac90`

Two halves. The second was carried by the Coordinator because the lane could not edit `tools.py`
under its ownership and said so rather than reaching.

**The confirmation criterion was the real fix, not the sample count.** The 18 residual false
confirmations were exactly ONE shape: the OPERATOR response byte-identical to the baseline with only
the CONTROL diverging, which is not a broadening at all. When a body is not a bare JSON array,
`_row_fragment` returns the WHOLE body and `frag in op` degenerates into "operator equals baseline" -
something a bimodal page satisfies for free about half the time. The containment oracle's
precondition is now ENFORCED rather than merely documented.

**Shipped at N=3, not the 4 the handoff proposed, on the handoff's own table:** N=3 reaches
**0.000 FP/attempt** with **5 of 5** live true positives still confirming, and N=4 buys nothing
measurable. The extra request is not free - the POST carrier samples INSIDE the field loop, so the
cost is per FIELD and does not amortise, on the lane that carries every boolean-blind confirmation on
this benchmark. **Ship the number the measurement supports, not the rounder one.**

Seven tests went red on the patch and only two kinds existed:
- **Two SPELLING pins** (`assert "baseline_repeat" in keywords`) - red on a change that STRENGTHENED
  the property they guard. Re-aimed at the property, so a carrier supplying NOTHING still fails.
- **Five REQUEST-COUNT pins** - correctly red, re-aimed to the new contract and deliberately kept
  EXACT rather than made flexible: extra reference requests are the price of this fix, and a silent
  drift upward is a cost nobody would notice.

A strict xfail asserting BOTH halves XPASSed and was retired in the same commit - the signal it was
written to send. **The nosqli carrier still supplies no reference, so its gate stays inert and stays
pinned**, rather than being retired alongside the sqli half it does not share.

Process note worth keeping: the targeted run passed 273 and the full suite still found 7, because
`test_sqli_stability.py` pinned the same carrier contract from a second file that nothing in the
selection would have revealed.

### Q-069 · The ledger keeps only the LAST error per tool · **CLOSED** `b3bef1c` `5dc11ed`

Measured across **all 153 missions**, and the worst case is far worse than the one that prompted the
ticket: `http_probe` in mission `5102527f` rendered **48 failed dispatches — 31x NXDOMAIN plus 17x
no-address — as a single sentence**, indistinguishable from one flaky request.

Adds `errors` and `error_kinds` beside the Q-067 counters without disturbing them, keyed on the FULL
message so distinctness is not an artifact of the 140-char display budget. Executed rows trade the
vague "1+ call errored" for real counts, and every row now carries `errors` / `error_distinct` /
`error_kinds` for the JSON export.

The detail worth keeping: `_rank_errors` sorts **count desc, message asc**, because two identical
runs must not print two different sentences. A deterministic-first tool has to be deterministic in
its prose too, and a dict-ordering-dependent digest would have been a quiet violation nobody noticed
until two reports of the same target disagreed.

### Q-058 · Four defects the description gate surfaced, in `tools.py` · **CLOSED** `6e16197` `ea7f0cb` `2b6e3ec` `552215e`

All four. Verified by the Coordinator after landing: the gate now flags **0** (was 2) with a positive
control showing 111 engines parsed, and `hash_type` went from **1 occurrence to 8** — the schema line
plus the code that now actually reads it.

Items 1 and 2 landed with the ratchet emptied in the same commit, as designed. Both docstrings now
open with the registered tier as a **bare token** and keep the qualifier in prose after it, because a
hyphen-softened tier reads softer than the tier it names and that is the entire defect.

Item 4 became more than a docstring edit: **an engine whose tier is written down nowhere is now a
suite failure**, so the gap the gate was deliberately silent about is closed by a test rather than by
a convention.

One cosmetic artifact recorded so it is not mysterious later: commit `6e16197`'s SUBJECT carries a
stray `@ ` prefix from shell mangling — a known failure mode in this project. The body is intact and
the commits were not yet pushed when found, but rewriting seven commits mid-cycle to fix a cosmetic
prefix was the worse trade.

### Q-069 · superseded by the entry above · `CLOSED`

Found while measuring Q-067. `main._tool_ledger` stores `a["error"] = <latest>` with no count and no
histogram, so `fetch_openapi`'s row showed a single message while the log held **5 SSL faults + 5
verdicts**. The mixed-outcome row now says "1+ call errored", which is honest but coarse.

Worth doing because the whole Q-063/Q-067 line of work is about a reader being able to tell "never
tested" from "tested, found nothing" — and "failed 10 ways" from "failed once" is the next rung of the
same ladder. DoD: an error COUNT at minimum, ideally a small histogram of distinct messages, without
inflating the note into a wall of text.

### Q-068 · The same target yields DIFFERENT report evidence depending on the image · **MEDIUM** · **CLOSED** `1ec46fc`

Found by the Q-059 rebuild, and it is the kind of thing only a rebake could reveal. `run_metadata`
prefers `exiftool` when installed and falls back to a native pure-python reader. Both are correct and
both recover the same GPS point — but they **format it differently**, so the evidence string in a
client-facing finding depends on which image the operator happens to be running:

```
native reader   GPSLatitude: 59 deg 25' 16.17" N
exiftool        GPSLatitude: 59.4211583333333
```

For a **deterministic-first** tool that is a real defect, not a cosmetic one: two installs scanning
the same target produce different report text, and nothing in the suite noticed until baking
`libimage-exiftool-perl` flipped the preferred path and turned a green test red — **a test going red
because the product got better.**

The test was the first casualty and is fixed
(`test_the_engine_now_reports_the_leak_end_to_end` now pins the POINT to 4 dp rather than one
reader's spelling, which is a strictly stronger assertion — it would catch a reader returning
plausible numbers for the wrong location, and a substring match never could; a paired test asserts
the two readers agree). **But the product half is NOT fixed:** the engine should normalise coordinates
to one canonical representation before they reach a finding. DoD: one format in the evidence
regardless of which reader ran, with the existing agreement test extended to assert it.

### Q-067 · A NEGATIVE RESULT is recorded as a tool FAILURE · **CLOSED** `006c5b0` + producer/engine fix

**MY TICKET WAS WRONG IN THE DIRECTION THAT CAUSES HARM, and the lane measured it before writing a
line of code.** I wrote that `fetch_openapi` "probed 10 candidate paths and correctly found no spec".
The DB says otherwise:

```
fetch_openapi rows: 20      Counter({'tool_call': 10, 'tool_error': 10})
error histogram:
   5  [SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1010)
   5  Response is not valid JSON (not an OpenAPI spec)
```

**Five of the ten dispatches spoke TLS at a plaintext port and never reached the target at all.**
They are genuine transport faults. The blanket "mark this row executed" my ticket implied would have
**buried five real faults** — precisely the invisible-false-negative class Q-063 built the `errored`
class to expose. The ticket was aimed at making an alarm quieter and would have made it lie.

The row showed only one of the ten because `_tool_ledger` keeps the LAST error string per tool and no
error count. **That is a second, smaller defect and it is still open** — an engine failing ten
different ways reports one of them.

**Why a TYPED TOKEN and not a rule over the error text.** Measured by driving the real engine against
the real lab: the verdict and the fault are **byte-identical in every `ToolResult` field except the
English of `error`** (both `success=False`, `output=''`, `findings=[]`), and the persisted row carries
only `{type, tool, error, ts}`. No producer-only classifier can separate them without reading
language — the Q-056 rule-C shape, measured at 5 false positives in 6 and rejected.

**The concept already existed; this was one mispacked site.** A response that IS valid JSON but not a
spec already returns `success=True` / `"0 endpoints imported"`. The not-JSON case was the same answer
sent down the error channel.

Fixed in both halves: `tools._fetch_openapi` emits `NOT PRESENT: ...`, and `main._tool_ledger` gains
a `negatives` counter beside `ok`/`scope_blocks`/`error`, matching the token as a **prefix** (stricter
than the `"SCOPE BLOCK" in err` test it is modelled on) or a typed `tool_negative` row. Ten tests,
including the mandatory negative control that a genuinely broken engine **still reads `failed`**, and
an anti-regex guard that fails if anyone later "fixes" this with a phrase list.

Surfaced by Q-063 on its first real ledger, and **verified against the live mission before filing,
which changed the ticket completely.** `fetch_openapi` shows `status=failed, calls=10, findings=0` —
which reads like a broken engine. The recorded error is:

```
Response is not valid JSON (not an OpenAPI spec)
```

That is a **negative result**: the engine probed 10 candidate paths on Juice Shop and correctly
established that none serves an OpenAPI spec. The engine is fine. `main._tool_ledger` marks a row
`failed` whenever an error string is present with no successful call, and "this is not a spec"
arrives as an error string.

**This exact defect was already fixed once, for scope blocks** (`936f6bd`: a SCOPE BLOCK is correct
enforcement, not a tool failure, and a tool that ran on its in-scope targets must not read "failed").
The same argument covers a negative finding. Fix in the PRODUCER, not the engine: an engine that ran,
reached its targets and concluded "not present" is `executed` with a note, never `failed`.

Why it matters more now than it did yesterday: Q-063 just made `errored` a first-class reported class
precisely because a broken engine is an invisible false negative. If negative results land in that
class, the class fills with noise and stops being read — the fate of every alarm that cries wolf.

Recorded because it nearly went the other way: "failed 10 of 10 dispatches" is a far more exciting
ticket than the true one, and would have sent someone to fix an engine that works.

### Q-061 · The tool ledger records a WRAPPER's declaration, not the fact of dispatch · **CRITICAL** · **CLOSED** `5c466a2`

**This is the instrument every arsenal-coverage number is computed from, and it measures the wrong
thing.** Independently verified by the Coordinator: `Tools.execute()` (`agent/tools.py:1227`) resolves
the method and returns `await method(tool_input)` **without writing a log row**. Only `_run_tool`
(`agent/agent.py:682`) and `_exec_internal` emit `tool_call`. So the ledger records dispatch performed
*through two particular wrappers*, and is blind to every other path. **10 of the 12
`self.tools.execute(` sites in `agent.py` are unlogged.**

`browser_navigate`, `acquire_session` and `http_read` have no other dispatch path at all, so they
render **"never dispatched" in every deterministic mission** whether they ran or not.

PROVEN rather than inferred, in one mission: it registered two accounts, acquired and **verified** two
sessions, re-crawled 13 new endpoints and confirmed **35 authz findings** off those sessions — while
reporting `acquire_session` as never dispatched. The report contradicts itself in the same document.

This is the declaration-vs-fact family for the ninth time, now **inside the measuring instrument**.
DoD: log the dispatch at the one place it is known — inside `Tools.execute()` — so the ledger records
the fact rather than a wrapper's account of it. Then re-derive the arsenal classification, because
every "never dispatched" count in every report predating the fix is an upper bound, not a measurement.

### Q-062 · Two browser worlds; the CDP sidecar served ZERO sessions · **CLOSED — PREMISE DISPROVED** `11c5a52`

**The ticket's measurement was right and the conclusion drawn from it was not.** The sidecar has
served **509 successful sessions**, not zero. `GET /metrics` retains 2922 five-minute periods across
2026-08-10..08-20; 68 are non-zero. The most recent product-code cluster is 2026-08-20T03:05Z -- five
`POST /function` calls whose `launch={"ignoreHTTPSErrors": true}` is the byte-for-byte signature of
`browser_engine.drive()`, **19 hours before the lane that checked**. Q-062 sampled 60 minutes of a
curve that fell off a cliff on 2026-08-13.

**The apparatus note is the transferable part.** `/metrics` returns only COMPLETED periods, so driving
the sidecar and re-reading it immediately shows `delta=0`. The lane **reproduced that false zero
deliberately** before trusting anything, then took every session claim from the ingress log instead.
The original ticket did not have that control, which is the entire reason it resolved the wrong way.
**A zero with no positive control is not a measurement** -- this queue has now had it both ways: zeros
that were real defects, and a zero that was the instrument.

Both worlds are consumed and they are DISJOINT, proven at the sidecar's own ingress rather than from a
counter: `browser_engine.observe()` produced exactly one `POST /function`; `bie.run_persona_swap()`
then confirmed 2 real findings against `clientauthz` with the sidecar seeing no request at all.

**Why a mission never touches it is not "not selected"**: all six sidecar call sites are HTTP endpoint
handlers or a lab solver, none on the autonomous mission path. And the confusion has a root cause
worth keeping -- `browser_engine.py` also houses the Q-043 rate policy, so **eleven of its thirteen
importers import it for `target_rate_policy` and never call `drive()`**. A module that is two things
reads as one thing being used.

Nothing removed, nothing rewired. Evidence only.

MEASURED with a properly closed control. Every browser ENGINE call site uses `pw.chromium.launch()` —
a chromium local to the agent container. **`connect_over_cdp` appears zero times in the tree**
(Coordinator-verified). The `apolaki-headless-chrome-1` sidecar served **0 sessions across 12
consecutive periods** spanning a full mission.

The control is what makes it a finding: the counter has non-zero history, the lane drove the sidecar
manually from inside the agent container, and the counter went 0, 0, **1**. So the sidecar is healthy,
reachable and simply not selected — **reachability does not imply consumption**, which retires run 1's
"the sidecar is reachable so this is not a sidecar problem" as insufficient.

**PRECISION REQUIRED, and the lane's framing needs one correction before anyone acts on it:** the CDP
path is NOT dead code. `CDP_BROWSER_URL` is consumed by `agent/cdp.py:86` and
`agent/browser_engine.py:306`, which drive browserless over its HTTP `/function` endpoint rather than
`connect_over_cdp`. `agent/capability_preflight.py:51` reports the capability from the env var alone.
So the honest statement is **"wired and reachable but not selected during a deterministic active
mission"**, not "unused". The decision is a product one: route browser work to the sidecar, or drop
the sidecar and stop advertising a capability nothing exercises. Do not "fix" it by deleting a path
that a non-deterministic strategy may use.

Meanwhile the browser world is emphatically NOT idle, and the report should say so:
`confirm_browser_persona_bola` drove two real contexts, issued 95 runtime requests and confirmed a
cross-user finding; `run_dom_trace` 20 calls, `run_dom_audit` 18, `run_client_checks` 12,
`run_js_review` 20 findings.

### Q-063 · The Arsenal SUMMARY merges "errored" into "ran and found nothing" · **MEDIUM** · **CLOSED** `4d3b51d`

The per-tool table is honest and renders FAILED/SKIPPED correctly; the summary line above it is not.
An engine that ERRORED is counted as silent, i.e. as a clean result. That is the same
merge-two-classes defect as the `blocked_by_mode` one just fixed, one level up: a silent failure is
the single most valuable class in the four-way classification and the summary hides it inside the
class that means "nothing to see".

### Q-064 · `ledger_finding_disagreement()` raises a FALSE integrity alarm · **CLOSED** `676923a` + stamping fix

**VERIFIED BY THE COORDINATOR on the live records**, because the lane died mid-sentence and its own
last words understated what it had finished:

```
pre-stamp (historical)  unlogged: ['browser_persona_bola', 'xss']   productive: []
stamped by the product  unlogged: []   productive: ['confirm_browser_persona_bola', 'run_xss']
```

`agent._stamp_dispatch` binds the dispatch name onto every finding at the wrapper that knows it, and
the checker prefers `dispatch` over `engine`.

**The historical rows still disagreeing is DELIBERATE and is the best decision in the change.** A
finding written before the stamp existed, or stored outside a dispatch, has only its self-declared
`engine` name — and those are exactly the records whose provenance cannot be corroborated, so they
stay reportable. Retiring the check for them would silently drop the real case it exists to catch.
`test_the_LIVE_pre_stamp_records_still_disagree_and_that_is_correct` pins that on purpose.

15 tests, including the ones that matter most: a finding whose engine never appears in the ledger is
**still reported**; a STAMPED dispatch the ledger never recorded is **still reported**; a wrong stamp
is **not excused** by a matching engine name (dispatch is judged alone, never given a second chance);
a blank dispatch stamps nothing; the warning reaches BOTH renderers only when it should. Plus a
ratchet that no agent function consumes dispatch findings without stamping them — **and a test that
the ratchet can actually see the shape it is looking for**, which is the second time this week a lane
wrote that pairing unprompted.

**The measurement is much worse than the ticket.** I filed this as one engine's naming quirk. AST over
`tools.py` against `TOOL_PERMISSIONS`: **only 15 of 111 engines emit a `ToolResult` whose name equals
their dispatch name.** So the alarm fires on every finding **95 engines** will ever produce.

Reproduced on the LIVE records rather than a fixture — the real 46-row ledger for mission `57cc3b49`
against the real findings table for the same mission. **Both halves are wrong there:** two engines
that plainly ran are reported `produced_but_unlogged`, and `productive` is **EMPTY on a mission that
produced two findings**.

**And it independently vindicates the instruction not to prefix-strip:** three distinct dispatches —
`run_sqli`, `run_path_sqli`, `run_sqli_structural` — all emit `sqli`. The map is **many-to-one**, so
no normaliser could resolve a finding back to its ledger row even if loosening the check were
acceptable. The forbidden fix was not merely against policy; it could not have worked.

The fixture pairing is right: `findings_57cc3b49.json` is the verbatim findings table for the same
mission as the existing verbatim ledger fixture, so the two files are the **two independent records
of one run** rather than two hand-written halves that agree by construction. Grepped for credentials
before committing.

The two records use different vocabularies. Findings carry the **ToolResult** name
(`browser_persona_bola`, bound at `ToolResult.__post_init__`) while the ledger carries the **dispatch**
name (`confirm_browser_persona_bola`), so the engine is reported as `produced_but_unlogged` on a run
where it plainly ran. An integrity check that cries wolf gets ignored, which costs more than the check
was worth.

**Do NOT fix this by prefix-stripping in the checker** — loosening a check to stop it complaining is
the move this project forbids, and it would also mask the real `produced_but_unlogged` case the
function exists to catch. Fix it by **binding the dispatch name at the point it is known**, the same
discipline as Q-042/Q-046/Q-051: stamp the dispatch name onto the finding when it is stored, and
compare like with like. Note this interacts with Q-061 — fix that first, since it changes what the
ledger contains.

### Q-065 · `run_jwt` never fires on a JWT-authenticated target that the platform itself flagged · **MEDIUM** · **CLOSED** `c04c13b`

The mission's own autonomy loop wrote *"next-best actions: ... weak_secret_forgery"* while `run_jwt`
was never dispatched against a target authenticating with JWTs. **The ranking model and the dispatch
vocabulary do not meet** — the planner can name a technique it has no route to execute. That is the
effects-model gap in its clearest form and is a better first case than the other 14 in class B3.

### Q-060 · Two engines cannot test ANY target on a non-standard port · **HIGH** · **CLOSED** `3dca74c`

MEASURED live, root-caused, and reproduced deterministically in isolation by the arsenal lane. Both
engines were DISPATCHED, so this is not a planner gap:

| engine | calls | results | scope_blocks | findings |
|---|---|---|---|---|
| `run_transport_posture` | 1 | **0** | 1 | 0 |
| `run_header_trust` | 6 | 5 | 1 | 0 |

`run_transport_posture` is **100% dead on this target**; `run_header_trust` is only partially affected
(it still tested 5 discovered URLs, which carry their port) and must not be reported as dead.

Not a per-engine constant — `_run_transport_posture` derives the port correctly itself. The defect is
in the two CALLERS, `agent/agent.py:2355` and `agent/agent.py:2395`:

```
u = s if "://" in s else "https://" + s.split("/")[0]   # _do_transport_posture
u = s if "://" in s else "http://"  + s.split("/")[0]   # _do_header_trust
```

Both rebuild an origin from `scope.to_dict()["in_scope"]`, which has ALREADY dropped scheme and port,
so the caller re-adds a default scheme and thereby **invents a port the operator never authorised**;
the scope engine then correctly refuses it. Reproduced: `['http://juice-shop:3000']` normalises to
`['juice-shop']`, becomes `https://juice-shop`, and `validate()` returns False.

**Every Apolaki local lab runs on a non-standard port**, so `_do_transport_posture` has been incapable
of auditing the pinned origin across the entire lab fleet. Capabilities lost with it, per
`agent/engine_descriptor.py:135-139`: `tls_posture`, `cookie_scope_posture`, `http_security_headers`,
`http_methods_audit`. Fix at the caller by carrying the scheme+port through, not by widening scope.

### Q-058 · Four defects the description gate surfaced, in `tools.py` · **MEDIUM** · **CLOSED** `552215e`

Blocked only on lane ownership of `tools.py`; all four are mechanical and none is a description edit
(rewording the claim to fit the code is the same defect wearing a different hat).

1. **`_confirm_create_object_idor` docstring says `ACTIVE:`, registered `INTRUSIVE`.** Found by the
   gate itself, not by the audit that motivated it. **The enforcement is CORRECT** — `_run_tool`
   reads `TOOL_PERMISSIONS`, which says INTRUSIVE — so this is not a present exposure; it is a
   docstring that would mislead whoever next decides where to dispatch an engine that creates and
   deletes objects on a live target. Fix the docstring, not the registration.
2. **`_run_external_surface` docstring opens `PASSIVE/ACTIVE-light`, registered `ACTIVE`.** It
   fetches the target's favicon over HTTP; ACTIVE is right. Keep the nuance in prose AFTER the tier
   token, never inside it.
3. **`run_hash_crack` advertises `hash_type` and never reads it.** Verified independently by the
   Coordinator: `hash_type` occurs exactly once in all of `agent/tools.py` — the schema line — while
   `cands = hid.identify(h)` auto-identifies unconditionally. The schema tells the model the
   parameter is "optional; auto-identified if omitted", which implies supplying it does something.
   Either honour it or drop the property. **Not gated** (rule E is 86% false and unshipped).
4. **Four engines declare no tier at all** — `run_dom_trace`, `run_form_xss`, `run_jsonp`,
   `store_finding`. Rule B is deliberately silent on absence, because conflating a documentation gap
   with a contradiction is how a gate earns the noise that gets it silenced.

Patches 1 and 2 each require dropping that engine from `KNOWN_OPEN` in
`agent/tests/test_description_gate.py` — the ratchet fails when a recorded contradiction STOPS
firing, so a fix cannot silently shrink the allowlist.

<details><summary>original ticket text</summary>

The cross-cutting result of the islands audit, and worth more than any single verdict: `run_ferox`
advertises recursion while passing `--no-recursion`; `run_metadata` advertises EXIF it cannot read;
`_run_workflow`'s docstring claims findings it discards; `run_external_surface` is described PASSIVE
and registered ACTIVE. **A reachability gate cannot catch any of these — every engine is present,
registered and implemented.** The gap is between what an engine SAYS and what it DOES, and only
running it closes that. DoD: a check that compares each engine's advertised behaviour against its
measured behaviour, or an explicit decision that this is a review discipline rather than a gate.

</details>

### Q-057 · DELETE the three content-discovery adapters · **CLOSED** `466bae8` — specs, methods, permissions and `_bin_discovery` all removed; test_bbh asserts their absence

Purely subtractive, no oracle argument needed. All three binaries absent from the image; the
capability is already wired natively with a soft-404 baseline the adapters lack; only coverage is a
declaration test. Apolaki advertises content discovery to the model in three `CLAUDE_TOOLS` entries
and cannot perform it. Patch handed to the lane holding `tools.py`.

---

## LANE OWNERSHIP — cycle 7, 2026-08-16. TWO lanes, and the count is the point.

`agent/tools.py` is the universal bottleneck: every engine-wiring ticket needs it, and exactly one
lane can hold it. Spawning a third and fourth Builder would have produced collisions, not throughput
— rule 1, agents are a budget and two lanes answering into one file are one lane.

| owner | files it may WRITE | ticket |
|---|---|---|
| **Builder · techintel** | `agent/fingerprint.py` · `agent/dependency_intel.py` · `agent/memory.py` · `agent/tools.py` · their tests · `docs/handoff/techintel.md` | **Q-021C–F** — detected technology drives no testing; mid-fix on a real regression |
| **Breaker · islands** | `docs/handoff/islands.md` · `agent/tests/test_island_soundness.py` (new) | **Q-050(b) soundness** — a verdict per island, wiring NOTHING |
| **Coordinator (main thread)** | `docs/*` · `agent/report.py` · `agent/main.py` · `agent/db.py` · `agent/asvs_model.py` · `agent/mutation_gate.py` · `scripts/` | ledgers, recovery, sequencing |

The islands lane is deliberately diagnosis-only and therefore collision-free: the six engines cannot
be wired until someone can argue their oracles are sound, and **an engine that has never run has never
had its false-positive behaviour measured**. wp1 is the precedent — an engine added to the always-on
sweep on a coverage argument scored the best headline the project had produced and was reverted on a
pre-registered condition, because only 5 of its 12 confirmed findings were class-correct.

**AUTOMATED CONTINUATION, 2026-08-16.** Scheduled task `apolaki-autocontinue` runs every 3h: recovers
uncommitted work from killed lanes, continues the top open item, no-ops on a clean tree. It **retires
itself** after three consecutive runs where the queue is empty, the tree is clean, the suite is green
and STATUS carries no unproven claims — then records the retirement in LEDGERS. Six lanes were killed
by session limits in one session; the noticing is now automated, the commit-per-slice discipline is
not and stays in every prompt.

---

## STATE SWEEP — 2026-08-16. Authoritative. Updated in the same commit as the closes.

**CLOSED this cycle**, with commits: `Q-051` (engine bound at `ToolResult` + report attribution +
ledger/finding cross-check) `620fcbb`/`bc60727` · `Q-053` all four gaps `7ce79bb`/`fb6f457`/`7fbd1bf`
+ AUTHN-02 `44a6cbf` · `Q-052` slice 1 (nine bare swallows) `b8cf4ef`, slice 3 (**a PASSIVE mission
was making live requests**) `2707caa`, and the **DECISION** `f3eb1cb`.

**Q-052 REMAINING — the decision is made, the change is not.** The lane's measured recommendation:
the tier is an **aggression/cost axis, not a consent axis**. Do NOT narrow `active` (49.5% of the
sweep and 7 of 18 engines disappear, including the entire SQLi surface, and it still permits account
creation and credential rotation). Instead: **default to `full` and have `_run_tool` honour
`planner._ALLOWED`** — zero dispatches move and `active` starts meaning something — then put
side-effect consent on a separate orthogonal flag. Also: four engines' docstrings disagree with their
own `TOOL_PERMISSIONS` entry, which is its own small ticket.

**Q-050(b) REMAINING** — engines reachable at their tier that are simply never selected (`run_jwt`,
`run_saml`, `run_enumerate_ids`, `run_default_creds`, `run_metadata`, `run_jsonp`,
`run_session_lifecycle`, `run_workflow`, `run_external_surface`, dirsearch/ferox/gobuster). A
selection/precondition problem, NOT a permission one. Diagnose before fixing.

**Still open from before**: Q-021C–F · Q-032/033/034 · Q-002 (WebSocket engine exists, not in the
sweep) · Q-004 · Q-005/006 · Q-030/035/036 · B-011+ · the baseline's ninth case `00438` · the
unexplained sublinear per-URL cost.

---

## LANE OWNERSHIP — cycle 6, assigned 2026-08-15. Declared BEFORE spawning.

Cycles 3-5 lost every lane to session limits and lost nothing of substance, because each committed
per slice. Same discipline. `tools.py` is again the bottleneck, so exactly ONE lane holds it.

| owner | files it may WRITE | ticket |
|---|---|---|
| **Builder · tiers** | `agent/agent.py` · `agent/planner.py` · `agent/tests/test_permission_tiers.py` (new) · `docs/handoff/tiers.md` | **Q-052** — `active` and `full` are the same mission, and the sweep swallows every engine error |
| **Builder · provenance** | `agent/tools.py` · `agent/tests/test_finding_provenance.py` (new) · `docs/handoff/provenance.md` | **Q-051 part 2** + **Q-053 GAP-1/GAP-2** — bind the producing ENGINE and the missing FAMILY at the point the finding is built |
| **Builder · families** | `agent/sqli_tool.py` · `agent/transport_posture.py` · their tests · `docs/handoff/families.md` | **Q-053 GAP-3/GAP-4** — a confirmed auth bypass labelled `sqli`; one family shared across three properties |
| **Coordinator (main thread)** | `docs/*` · `agent/report.py` · `agent/main.py` · `agent/db.py` · `agent/web_security.py` · `agent/techniques.py` · `agent/mutation_gate.py` · `scripts/` | the report half of Q-051, the technique coverage matrix, ledgers, recovery |

Sequencing note: the provenance lane binds `engine` onto findings; the report half that PRINTS
per-finding attribution is mine and lands after it, because rendering a field nothing writes is the
island defect in the other direction.

---

## LANE OWNERSHIP — cycle 5, assigned 2026-08-15. Two lanes RESUMED, not respawned.

Cycles 3 and 4 were each wiped by a single session limit. **Resuming beats respawning**: an agent
carries its own 200k-token context, so the asvs lane keeps the source-derived producer map it spent
its whole session building and the massassign lane keeps its oracle design. A cold spawn would pay
for both again.

| owner | files it may WRITE | ticket |
|---|---|---|
| **Builder · asvsproducers** (resumed) | `agent/asvs_model.py` · `agent/tests/test_asvs_model.py` · `docs/handoff/asvsproducers.md` | **Q-048** — repairs + the ratchet, on the map it already measured |
| **Builder · massassign** (resumed) | `agent/mass_assign_tool.py` · `agent/tools.py` · `agent/engine_descriptor.py` · `agent/wstg_catalog.py` · `agent/mutation_gate.py` · `agent/tests/test_mass_assign_tool.py` · `docs/handoff/massassign.md` | **Q-011 LIVE VALIDATION** — the driver exists; it is proven only against fixtures |
| **Breaker · validated** | `docs/handoff/validated.md` · `agent/tests/test_validated_on.py` (new) | **`validated_on` is minted by hand, counted as capability, guarded vacuously** — measure it |
| **Coordinator (main thread)** | `docs/QUEUE.md` · `docs/STATUS.md` · `docs/LEDGERS.md` · `docs/benchmarks/` · `agent/report.py` · `agent/web_security.py` · `agent/agent.py` · `agent/main.py` · `agent/db.py` · `agent/liveness.py` · `scripts/` | ledgers, sequencing, recovery |

The `validated` lane is deliberately diagnosis-only: it audits a promise that two engines shipped this
week are currently unable to keep honestly (`run_ws_hijack` validated against a local paired server,
`run_mass_assign` against fixtures), so whatever rule it proposes must be one they can satisfy
TRUTHFULLY rather than one that retroactively blesses them.

---

## LANE OWNERSHIP — cycle 4, assigned 2026-08-15. Declared BEFORE spawning.

Cycle 3's three lanes were all killed by one session limit; each had committed a slice first and all
of it was recovered. Same shape again, re-aimed at what is actually open. `tools.py` is the perennial
bottleneck, so exactly ONE lane holds it.

| owner | files it may WRITE | ticket |
|---|---|---|
| **Builder · massassign** | `agent/mass_assign_tool.py` (new) · `agent/tools.py` · `agent/engine_descriptor.py` · `agent/wstg_catalog.py` · `agent/tests/test_mass_assign_tool.py` (new) · `docs/handoff/massassign.md` | **Q-011** — `mass_assignment` is declared in three catalogs and implemented nowhere |
| **Builder · asvsproducers** | `agent/asvs_model.py` · `agent/tests/test_asvs_model.py` · `docs/handoff/asvsproducers.md` | **Q-048** — an objective whose `violated_by` family has no producer can never FAIL |
| ~~**Breaker · fp42**~~ | **CLOSED** — root cause was the TRANSPORT (`_http` builds a new client per request, so a stateful page is fresh-random every time), a determinism control asking for "no nameable divergence" instead of equality (3.38% false-pass, MEASURED), and Q-047's repeat being a control for state rather than randomness. Fixed both halves; **live 0/40 against a measured 4/40** | |
| ~~**Builder · massassign**~~ | **oracle landed + DRIVER wired by the Coordinator** after the lane died mid-implementation. `_run_mass_assign` does baseline read -> injected write -> SEPARATE re-read -> invented-control write; INTRUSIVE because it writes; advertised in `CLAUDE_TOOLS`; mutant added so the ceiling stays 46 | **Q-011 still needs LIVE VALIDATION against a real app** |
| **Coordinator (main thread)** | `docs/QUEUE.md` · `docs/STATUS.md` · `docs/LEDGERS.md` · `docs/benchmarks/` · `agent/report.py` · `agent/main.py` · `agent/db.py` · `agent/web_security.py` · `agent/agent.py` · `scripts/` | score wp3 against its pre-registered conditions, ledgers, sequencing |

Note `agent/web_security.py` is Coordinator-held this cycle: the fp42 lane will likely want the
traversal oracle, and it must hand me the patch rather than apply it.

---

## LANE OWNERSHIP — cycle 3, assigned 2026-08-15. Declared BEFORE spawning.

Disjoint write sets, docs included. Cross-lane needs go to `docs/handoff/<lane>.md`, never here.

| owner | files it may WRITE | ticket |
|---|---|---|
| **Breaker · sqli** | `docs/handoff/sqli.md` · `agent/tests/test_sqli_selection_regression.py` (new) | **the `sqli` 21 -> 11 regression** — diagnose, do not fix |
| **Builder · asvs** | `agent/asvs_model.py` · `agent/tests/test_asvs_model.py` · `docs/handoff/asvs.md` | **Q-012** — six engine names resolve to nothing; 3 objectives unverifiable on a perfect run |
| **Builder · realtime** | `agent/ws_tool.py` (new) · `agent/tools.py` · `agent/register.py` · `agent/engine_descriptor.py` · `agent/wstg_catalog.py` · `agent/tests/test_ws_tool.py` (new) · `docs/handoff/realtime.md` | **Q-002** — WebSocket CSWSH, a genuine zero-engine class |
| **Coordinator (main thread)** | `docs/QUEUE.md` · `docs/STATUS.md` · `docs/LEDGERS.md` · `docs/benchmarks/` · `agent/report.py` · `agent/main.py` · `agent/db.py` · `agent/web_security.py` · `scripts/` | score wp2, Q-047 close-or-hold, Q-017, sequencing |

Known-conflict hand-offs, issued in advance:
- **Q-012's likely fix is in `tools.py`** (the ledger records `authz_matrix` while dispatch is
  `run_authz_matrix`), which the realtime lane owns. The asvs lane writes that patch into
  `docs/handoff/asvs.md`; the Coordinator applies it after the realtime lane lands.
- **Q-011 (`mass_assignment` phantom) is NOT assigned this cycle.** It needs `tools.py` +
  `engine_descriptor.py`, both held by the realtime lane. It is queued behind it, not forgotten.

---

## STATE SWEEP — 2026-08-14 (second pass, same day). Authoritative.

**The first sweep went stale in under a day** — five more tickets closed while it sat. Sweeping again
is treating the symptom, so the rule that fixes the cause: **closing a ticket includes updating this
block in the same commit.** A queue whose state cannot be trusted is the same declaration-vs-fact
defect we keep finding in the code, and it is the one artifact every lane reads before choosing work.

**CLOSED, with the commit** — ignore any `ready`/`proposed` marker further down:
`Q-000` 5af0af8 · `Q-00A` 65970da · `Q-001` fc91bb0 · **`Q-013` 3addb1c + 42e1544 (two passes — the
first fixed the write path, the second found the invariants never read `evidence` at all)** ·
**`Q-014` a1cdb8d + report rendering** · `Q-019` fc91bb0 · `Q-022` 837b1f0 · **`Q-023` Codex lane 7 / 2ae0007** ·
`Q-031` 8eb42e8 · **`Q-040` cbcba79 (the real fix; the first was incomplete)** · `Q-041`/`Q-042` 9f8707a ·
`Q-043` c02208d · `Q-044` aa3a139 · **`Q-021B` 1f342c9** ·
`B-001`/`B-002`/`B-003` Codex lane 1 · `B-010` Juliet Codex lane 2 · **`B-020` a7aa700**

**IN FLIGHT**: nothing. The selection lane closed its question (`step_cap_exhausted` was a true label
on the wrong constant; the bound is `CAP_ENDPOINTS`/`SWEEP_TARGET_CAP`) and was then killed by a
session limit that **resets 22:40 PT**.

## CYCLE-3 RESULT — 2026-08-15. All three lanes killed by one session limit; all three work landed.

Suite **2463 passed, 11 skipped, 3 xfailed, 0 failed** (was 2401). Recovered on the main thread and
pushed as `b1d56eb`.

- **`sqli` 21 -> 11: ANSWERED and now the top ticket.** Even round-robin over 11 URL shapes rationed
  the sqli class 31 of 400 slots for 456 candidates; the 9 lost TPs sit at indices 38-58, past a cut
  at 30, **never probed**. The 10th lost case is the known FP `00494` — a precision gain.
  **-> Q-049 below.**
- **Q-012 CLOSED.** `not_implemented` status added; the phantom names fixed; `coverage_rollup` gives
  it its own bucket. My briefing's `authz_matrix` premise was **disproved** by the lane.
- **Q-002 landed as an advertised engine**, not an always-on one. Its island was caught by the
  reachability gate after the handoff had already claimed the wiring was done.
- **Q-017 CLOSED**, **Q-045/Q-046 CLOSED**, **Q-015/Q-016 CLOSED**, **Q-013/Q-014 CLOSED**.

### Q-053 · Four findings-plumbing gaps the Q-048 lane refused to paper over · **MEDIUM** · `ready` · **GAP-1 CLOSED** `fb6f457` `c03e1e9`

#### GAP-1 CLOSED, and it was a both-halves defect rather than the gap the ticket described

The ticket said `takeover` is DETECTED and can never be REPORTED. **The producer half had already
shipped** in `fb6f457` -- `ToolRegistry._takeover_finding` stamps family `takeover` and
`check_takeover` is in `agent._AUTO_STORE_TOOLS`, so detection -> family -> store is real and pinned
by `tests/test_finding_provenance.py`. **The ASVS half never moved.** MEASURED at `8c7065c` with the
producer already live:

    takeover finding + engine ran  -> failed | not_implemented_reason STILL ATTACHED
    CLEAN run, engine RAN          -> not_implemented   <- "verified" unreachable
    engine never ran               -> not_implemented   <- indistinguishable from the row above

`failed` outranks `not_implemented`, so the FAIL direction worked **by accident** and hid the rest.
The flattering direction is the damaging one: a clean run of a capability that EXISTS reported the
PRODUCT as lacking it, and `not_implemented` stopped discriminating "no engine" from "engine ran
clean". The attached reason string had gone false in both clauses while still rendering on the row --
telling a reader "we found this" and "we have no engine for this" at once.

**Fourth instance of one shape this week**: Q-051's mode key, Q-050's auto-store lines, Q-084's
ignored parameter, this. Producer and consumer are two halves and only one of them is ever enforced.

Two tests updated deliberately, each gaining a POSITIVE CONTROL in the opposite direction, because a
test asserting a SMALLER not-implemented set is equally satisfied by a model that quietly dropped the
objective -- which is what this change could plausibly have broken. Tally moves **27 -> 28 verified
against 2 -> 1 not_implemented, in opposite directions by one**, and that pairing is the evidence the
capability was WIRED rather than unlabelled.

#### STILL OPEN: GAP-2, GAP-3, GAP-4, plus one the lane found on its way

**24 findings are invisible to the entire ASVS model**, including 4 genuine session-cookie hardening
findings against a real target. `security_misconfig` and `transport_posture` carry NO objective keys
at all. **Q-048's refusal was correct and is not to be undone**: it narrowed SESS-02 to
`insecure_cookie` and explicitly refused `security_misconfig`, because a missing Permissions-Policy
would otherwise fail "session cookies carry Secure" (`asvs_model.py:127-131`). That correct refusal
left the 4 stranded. The fix is a key those families can carry honestly, not a re-point of SESS-02.

Handed over as tickets rather than quiet re-points, with patches already written in
`docs/handoff/asvsproducers.md`. Each is a real product gap, not a mapping preference.

- **GAP-1 · `takeover` is DETECTED and can never be REPORTED.** Subdomain-takeover candidates carry no
  `family`, so they never become findings. COMM-04's `violated_by` is therefore unreachable by
  construction — the objective was honest and the plumbing was not.
- **GAP-2 · UNFALSIFIABLE FROM DATA, and that is itself the finding.** The corpus holds **ZERO**
  dalfox findings in 1783 (positive control: 1782 of 1783 carry a family; the single exception is
  "Manual: exposed .git"). So "dalfox findings carry no family" can be neither confirmed nor denied
  from storage -- there is nothing to inspect. The real question underneath is different and nobody
  has asked it: **has `run_dalfox` ever produced a finding at all**, and if not, is that because it
  never ran or because its output was dropped? That is a Q-050-shaped question (reachability), not a
  classification one. Answer it before writing any mapping code.
- **GAP-3 · CLOSED, and it was closed before I read the ticket.** `sqli_tool.auth_bypass_finding`
  emits `family: "auth_bypass"` today -- verified by CALLING IT -- and
  `tests/test_sqli_tool.py::test_auth_bypass_finding_fails_authn02_and_not_val01` has been pinning
  the exact target behaviour all along: AUTHN-02 failed, VAL-01 NOT failed. `asvs_model.py`'s
  AUTHN-02 comment already records the landing.
  **I re-opened it by mistake and the lesson is worth more than the fix.** I verified the claim
  against the STORED CORPUS -- 21 rows titled "SQL injection (auth-bypass)" carrying `family: sqli`
  -- and concluded the defect was live. Those rows are dated **2026-07-25 to 08-06**, i.e. written
  BEFORE the producer was fixed. **Stored data is historical; the emitter is current.** Asking the
  corpus whether a producer defect exists answers a question about the past.
  I then built a fix (read `tags` as additional properties) that made the auth-bypass finding fail
  VAL-01 as well -- **exactly the false positive `asvs_model.py:64` says was REJECTED on purpose**,
  and exactly what the pre-existing test forbids: "a login bypass is not evidence about every query
  parameter in the app." Reverted whole. The existing guard caught it on the full suite.
- **GAP-4 · `transport_posture` shares `security_misconfig`** across cookie, header and methods
  findings, so no objective can key on any one of them without catching the other two.

**Common root**: `family` is assigned per-MODULE rather than per-FINDING, so one engine that proves
three different properties emits one label — and an objective keyed to that label either over-fails or
cannot be keyed at all. **Do not fix by adding families to the ASVS map**; fix where the finding is
built, which is the same "bind the value at the point it is known" rule as Q-046 and Q-051.

---

### Q-082 · The report hands a client 716 FABRICATED curl reproductions for static findings · **CRITICAL** · **CLOSED** `9dba899`

Found by proving Q-044, and it is the only one of that lane's three findings that **reaches a reader
today**. Live in the client-facing artifact.

Mission `2fb87a3a` stored **716 source-derived findings**, and the renderer gave **716 of 716** of them
a `curl` command to run. Those findings are `analysis=static-call-site`: they were derived by reading
source, **no request was ever sent**, and the curl reproduces nothing. A client who runs one gets a
result unrelated to the finding.

**The store-side contract already blocks exactly this.** `_canonical_source_finding` (`main.py:392`)
FAILS CLOSED so a source result cannot enter reports under DAST semantics, requiring
`provenance=source-derived`, `lane=code-assisted`, `analysis=static-call-site`. The renderer then
re-introduces DAST semantics downstream of the gate that exists to prevent it. **A guard at the store
does not bind the presenter** - the same both-halves failure as Q-051's mode key, where the reader
landed and the producer never did, pointed the other way.

DoD: a finding whose `analysis` is `static-call-site` renders its file and line, never a request to
replay. **Negative control:** a genuine DAST finding must KEEP its curl - a fix that strips
reproduction from everything trades a false claim for a useless report.

### Q-088 · `validated_on` — MY FRAMING WAS WRONG; the four markers do NOT share a closing condition · **MEDIUM** · `ready` · owner: unassigned

#### CORRECTED 2026-08-21 by the claim-integrity lane, which measured before building and did not build

I filed this as "four consumers of one missing chokepoint, fix the chokepoint and three close by
construction". **Three of that sentence's premises are false**, measured against HEAD:

    the chokepoint is MISSING          ->  `techniques.known_labs()` ALREADY EXISTS
    4 ids resolve to nothing           ->  2, not 4
    /packs needs the technique_status  ->  `main.py:/packs` ALREADY calls `T.is_proven`

Only two call sites remain unconverted. The lane applied the patch **in an isolated copy** rather
than half-landing it, and measured the result: markers 2 and 3 XPASS, and it then **fails
`tests/test_technique_pipeline.py:17` with `assert 'unverified' == 'proven'`** -- the OLD rule is
pinned as a live assertion in a currently-passing test, in a file outside that lane's lease. Landing
the chokepoint fix therefore requires deciding what that test is for, which is a separate call.

**And one marker can never close as written.**
`test_packs_and_techniques_report_the_same_proven_number` **re-implements the old rule inline instead
of calling `/packs`**, so it cannot XPASS however the product changes. It is MISWRITTEN, not
measuring a defect, and should be retired as such -- with a replacement that actually calls the
endpoint if the disagreement is still worth pinning.

**The four markers therefore have four different closing conditions**, not one:

    no vocabulary / invented ids accepted   two call sites + a decision about test_technique_pipeline
    /packs vs /techniques disagreement      blocked behind the same decision
    the miswritten marker                   RETIRE, it measures nothing
    34 of 48 claims unasserted              needs ~30 recorded artifacts; unrelated to the others

**This ticket is downgraded HIGH -> MEDIUM** because the capability-integrity hole it was filed on is
narrower than measured: the vocabulary exists, and the invented-id acceptance is the part that still
bites. Whoever takes it should re-read this section first -- the original filing below is retained
only so the correction has something to point at.

**Filed as ONE ticket for FOUR strict xfails**, because they are four consumers of one missing
chokepoint, not four defects. Each marker's reason is already measured; this gives them the ticket
the release invariant requires.

    tests/test_validated_on.py  x4 strict markers, all MEASURED, none previously ticketed

1. **No vocabulary.** `techniques.all_labs()` derives the set from the claims themselves, so a claim
   validates itself. 4 ids name a target the agent cannot resolve.
2. **The negative control fails today**: two INVENTED lab ids yield `status='proven'`, confidence
   90/100 in the HIGH tier, a two-entry evidence list, `generalized=True`, and a CLEAN schema
   validation. A fabricated capability claim is indistinguishable from an earned one.
3. **Two published "proven" numbers differing by 32.** `/packs` sums `len(validated_on) > 0` = **48**;
   `/techniques` reports the liveness-earned **16**. The same product serves both.
4. **34 of 48 claims are named by no test assertion at all.**

**The chokepoint is (1).** Fix the vocabulary and (2) closes by construction; (3) is one of the two
call sites adopting `technique_status()`, which Q-012 already established and never propagated
(`technique_model.from_registry:256`, `technique_planner.registry_seed:172`, `main.py:/packs:2129`).
**Do not fix these as four separate re-points.**

**Definition of done**: a lab id resolves against a real registry or the claim is rejected; the
invented-id negative control passes; `/packs` and `/techniques` agree; the four markers XPASS and are
retired in the commit that closes them.

### Q-096 · The SCOPE REGEX is used as a target hostname, so a whole engagement can run without ever contacting the target · **CLOSED** `a28e7bd` `dde4023` · **CRITICAL**

**CLOSED, and the defect was WORSE than this ticket stated.** Verified by the Coordinator on
snapshots either side of the fix:

```
BEFORE 08158c2   validate('https://^.*\.shopify\.com$')  -> True    (the regex matches itself)
                 validate('https://www.shopify.com')      -> False   (a REAL Shopify host, BLOCKED)
                 base_urls()  -> ['https://^.*\.shopify\.com$']
AFTER  HEAD      load_manual RAISES ScopeConfigurationError
```

**The predicate was INVERTED, not merely leaky.** This ticket said the regex was used as a target; the
other half is that a genuine in-scope host was REFUSED. There was no path by which that engagement
could have reached Shopify even had recon worked.

Patterns are now typed `pattern` and held in `in_scope_patterns`, absent from `in_scope`. That one move
fixes all three `agent.py` drivers that read `in_scope` as a target list (including `:3758`, the recon
roots) **without editing `agent.py`**, and it is why the junk `run_asn` / `run_dns` rows stop too.
Patterns still match, now as anchored `re.fullmatch`. `base_urls()` / `base_map()` moved from a negative
filter to a positive one. An all-pattern scope raises at `load_manual`, following the discipline already
written at `main.py:3081`: "Unknown is not permission".

ORIGINAL TICKET FOLLOWS.

### Q-096 (as filed)

**FOUND IN THE FIELD, not in a lab.** Operator ran a full deterministic assessment against the Shopify
HackerOne program on 2026-08-24. **Apolaki never contacted Shopify once.** Report:
`C:\Users\voice\Desktop\HackerOne\Shopify\target_full-det_20260824@0739PST.md`.

Scope is stored as anchored regex patterns (`^.*\.shopify\.com$`). Something downstream feeds those
PATTERNS to engines as if they were hostnames. The generated reproduction command is, verbatim:

```bash
curl -i -sS -k --path-as-is 'https://^.*\.shopifycs\.com$'
```

**A regex is a FILTER, not an address.** It can never resolve. Corroborating ledger rows from the same
mission, all consistent with zero contact:

```
http_probe        failed   15 calls  [Errno -2] Name or service not known (same error x15)
fetch_openapi     failed   30 calls  [Errno -2] Name or service not known (same error x30)
run_httpx         executed  1 call   0 live hosts
run_katana        executed 15 calls  0 crawled URLs   [insane: depth 5]
run_subfinder     executed 15 calls  0 subdomains found
run_crtsh         executed 15 calls  0 CT log entries
Surface Urls: 0
run_transport_posture -> {"ran": true, ..., "tls": {"reachable": false, ...}}
```

**The failure is self-amplifying.** Recon (`subfinder`, `crtsh`) is ALSO seeded with the regex, so it
discovers nothing, so no real host ever enters the mission, so every later engine falls back to the
only "target" string it was given: the pattern. One bad seed silently voids the entire engagement.

**Note the two junk-but-nonzero rows**, which are their own small defect: `run_asn` reported
`15 findings / 0 IP(s)` and `run_dns` reported `15 findings / SPF MISSING, DMARC MISSING, 0 CAA` for a
hostname that does not exist. "SPF missing" on an unresolvable name is not a result.

**FIX:** scope patterns must never be usable as a target. The target list comes from RESOLVED hosts
discovered by recon or supplied explicitly by the operator, and scope is applied as a PREDICATE over
those. A candidate target that is not a syntactically valid host must be refused at the ingress that
builds the target list, not at the engine.

**GATE:** feed a mission a regex-shaped scope with no explicit hosts and assert it dispatches ZERO
active engines and reports a hard configuration error. The negative control matters as much: a mission
given real resolvable hosts must be unaffected. Today the first case produces an 18-finding report.

---

### Q-097 · `_run_transport_posture` reports every security header MISSING when the connection never opened · **CLOSED** `d199364` `b6e524d` · **CRITICAL**

**CLOSED.** `transport_posture.findings_for` gained `http_observed` (default `True`, so a real response
with no headers still reports all six), and `_run_transport_posture` now records `http_ok` / `http_err`
in the `except` that previously only swallowed. Neither channel observed means `ran=False`, zero
findings, and an error naming the transport cause. TLS reachable but the GET failed is handled as its
own case: TLS/cert findings stand, cookie/header/method findings are withheld, and the summary says
which half is missing. All three stale swallow labels fixed (this ticket named one).

**The gate surfaced evidence this ticket did not have.** On the dead path `res.output` literally read
`DEGRADED: 3 load-bearing check(s) failed to execute; latest=... {"ran": true...}`. **The dispatch knew
all three calls had died, said so in its own output, and emitted the findings anyway.** Visibility
without enforcement, stated in the engine's own words.

ORIGINAL TICKET FOLLOWS.

### Q-097 (as filed)

**This is Q-092/Q-093's defect family in a THIRD place, and it is the one that manufactures false
positives rather than hiding true ones.** All 18 findings in the Shopify report are fabricated by it.

`tools.py:3348` (in `_run_transport_posture`, defined at `tools.py:3326`):

```python
headers, set_cookies = {}, []
try:
    r, _ = await self._http_send("GET", origin + "/", {}, None, True)
    headers = dict(r.headers or {})
    ...
except Exception as _apolaki_swallowed_2960:
    self._swallow(_apolaki_swallowed_2960, 'tools:_run_transport_posture:2960', "")
    pass
```

The connection fails, the exception is swallowed, **`headers` stays `{}`**, and the header analysis then
runs against an empty dict and declares every protective header absent. **An empty dict from a dead
socket is indistinguishable from a response that carried no headers.** Falsy default on the failure
path, exactly like `r.get("body","") or ""` in Q-093.

**ARITHMETIC PROOF that this produced all 18:** the emitter checks 6 headers (HSTS, CSP,
X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) and the mission carried 3
pseudo-hosts. **6 x 3 = 18**, and `run_transport_posture` is the ONLY engine in the ledger with a
nonzero finding count: `executed | 3 | 18`. Shopify does send HSTS, CSP and XFO in reality.

**The signal to gate on is ALREADY MEASURED and ALREADY IGNORED.** `transport_posture.py:502` seeds
`out["reachable"] = False` and `:513` sets it True only on a successful handshake. The mission's own
stored result reads `"tls": {"reachable": false}` while emitting 18 header findings. **The outcome was
measured correctly and not consulted** - the same sentence as `_cmd`, `_http`, Q-089 and Q-090.

**Q-093's fix does NOT reach this.** That fix instrumented `_http`; this path goes through
`_http_send` wrapped in its own `try/except`. The I-5 work does make the swallow VISIBLE in the ledger,
but nothing gates finding emission on it. **Visibility is not enforcement.**

**FIX:** no header finding may be emitted from a request that did not complete. When the GET fails,
return `ran=False` naming the transport error, exactly as Q-093 did for `_http`. Absence of a response
is not absence of a header.

**GATE:** point the engine at an unresolvable host and assert ZERO findings plus `ran=False`. Negative
control, and this is the half that makes it a real test: a live lab host that genuinely lacks a header
must STILL produce that finding. A gate that only checks the dead case can be satisfied by an engine
that never reports anything.

**MINOR, while in here:** the swallow label reads `'tools:_run_transport_posture:2960'` but the call
site is line **3359**. The label's line number is stale and will misdirect anyone grepping it.

---

### Q-098 · Evidence-graded impact text is bound to CWE, so a missing header claims a CONFIRMED file exposure · **CLOSED** `0d207ad` `be19e0f` · **MEDIUM**

**CLOSED, and it was 24 instances rather than the one this ticket named.** The impact block now binds
to `_graded_family`: a declared family is authoritative (optionally through a small curated
`_FAMILY_ALIAS`), and the CWE map is consulted only when no family is declared.

**MEASURED: 24 family+CWE pairs took the old path.** The worst was `base64_param` + CWE-89 inheriting
*"Confirmed on this target: an injectable parameter confirmed by a control-vs-payload differential"*.
Not fixed by deletion: `security_misconfig` got its own entry whose unverified slot says the thing the
defect denied.

Diagnostic that makes this checkable: Referrer-Policy is the ONLY one of the six header rules mapped to
CWE-200, which is exactly why the field report carried three of these and not eighteen.

ORIGINAL TICKET FOLLOWS.

### Q-098 (as filed)

Findings 11, 14 and 17 of the Shopify report are titled **"No Referrer-Policy"** and carry this body:

> _What it is:_ Sensitive files or source are reachable directly over the web.
> _Demonstrated:_ Confirmed on this target: a sensitive file/resource served directly over the web (a
> control path 404s)
> _Confidence:_ confirmed

**None of that happened.** No file was served, no control path was probed, nothing was confirmed. The
narrative is attached to **CWE-200**, which the Referrer-Policy check also uses, so an information-
exposure story is glued onto a missing-header finding and stamped `confirmed`.

This is the most reputationally dangerous item of the three: Q-096 and Q-097 produce findings that a
careful reader can dismiss, but this one **asserts a demonstrated exposure that was never demonstrated**.
Submitted to a program, it is a false claim of evidence.

**FIX:** bind the evidence-graded impact block to the FINDING FAMILY that produced it, never to the CWE
alone. A CWE is a taxonomy label shared by unrelated checks; it cannot carry a claim about what this
run observed.

**GATE:** assert that no finding whose family is `security_misconfig` can emit a `Demonstrated:` line
containing a claim of file or source exposure. Non-vacuity control: a genuine exposure finding must
still emit exactly that line.

### Q-110 · No budget on a probe CALL: one endpoint ate 6h43m while 427 were never reached · **CLOSED** · **CRITICAL**

The operator's overnight Shopify run stopped producing anything at 07:22 and was still "running" at
14:05. Not the network, and not a crash.

**MEASURED from the ledger.** The injection sweep covers **465 parameterized endpoints** and runs its
engines per endpoint, in order:

```
run_injection_probes 37   run_css_injection 37   run_ldap 37   run_ssi 37
run_sqli_structural  37   run_waf_bypass    37   run_xpath 37
run_sqli             38   <-- STARTED a 38th and never returned
```

Every sibling had finished 37. `run_sqli` had begun one more. It sat there **6 hours 43 minutes**.
Endpoints 39-465 were never touched.

**It also explains the frozen live page.** The generator was blocked inside that call, so it yielded
no events. The stream was not broken; it had nothing to emit. The report kept re-rendering because it
reads the database, which had not changed since 07:22.

**Per-request timeouts existed and were never the problem.** Each request had `timeout=seconds + 20`.
Nothing bounded the SUM: up to 40 parameters x several payloads each is hundreds of requests, and
every `http_probe` in that run answered **403** -- a target that tarpits pushes each request toward
its timeout and the call runs for hours.

**FIXED** with `_PROBE_CALL_BUDGET_S = 240` and a wall-clock deadline checked BETWEEN requests, so a
probe in flight keeps its own timeout and nothing is cut mid-response. Applied to **all three engines
that share the shape** -- `_run_sqli`, `_run_nosqli`, `_run_cmdi` -- not only the one that happened to
hang, because fixing one route and leaving two open is how this comes back.

**Exhaustion is REPORTED, never silent.** The engine returns `success=False` and appends *"DEGRADED:
call budget exhausted, sweep TRUNCATED"*. "0 confirmed" after probing every parameter and "0
confirmed" after stopping partway are different facts about the target, and only one is evidence.

**GATE** (11 passed): a mutant that drops the deadline from **only `_run_cmdi`** is killed by both
parametrised tests for that engine -- which is precisely the fixed-one-route-missed-another failure.

### Q-113 · The injection sweep ignores `CAP_ENDPOINTS`, so a real engagement cannot finish · **READY** · **HIGH**

The operator's Shopify run reached **endpoint 69 of 465 in roughly seven hours** of active sweeping,
about six minutes each. At that rate the remaining 396 take **another ~46 hours**. Nothing was
stalling: Q-110's budget never fired (`TRUNCATED` count 0), and the heartbeat advanced normally. It is
simply doing 465 endpoints x ~8 engines against a Cloudflare-fronted target where every request is
slow.

The mission announces it plainly:

> "Deterministic injection sweep: directly probing 465 parameterized endpoint(s) ... **(coverage
> guarantee, planner-independent)**"

**`CAP_ENDPOINTS = 25` exists and this path deliberately bypasses it.** Every other phase in
`planner.py` is capped -- `CAP_HOSTS 30`, `CAP_JS 40`, `CAP_ZAP 3`, and Q-104's `CAP_RECON_ROOTS 25`.
This one opted out to guarantee coverage.

**A coverage guarantee with no time bound is not a guarantee, it is a promise the run cannot keep.**
The operator stopped at 15% and got the same findings he had at 5%; the other 85% was never evidence,
it was intention.

**FIX -- and the ordering is the point.** Do not simply apply `CAP_ENDPOINTS` here: truncating
lexically would repeat Q-104b, where a cap spent its whole budget on wildcard-DNS junk. Rank
endpoints by value first (parameters that look like sinks, distinct shapes, hosts the operator
declared) and cap the total, so the sweep tests the most promising 25-50 rather than the
alphabetically first 25. Then say so: a capped sweep must report **how many endpoints it declined**,
because "0 confirmed across 465" and "0 confirmed across the 40 we chose" are different claims.

**GATE:** a mission with 465 parameterized endpoints dispatches a bounded number of injection steps
and REPORTS the count it skipped. Negative control: a mission with 10 endpoints probes all 10 and
reports no skips, so the cap cannot silently shrink an ordinary engagement.

**RELATED:** Q-110 bounds one CALL; this bounds the SWEEP. Both are needed -- Q-110 alone stops a
single endpoint eating a night, and still permits 465 well-behaved endpoints to eat a week.

### Q-112 · A middlebox eating our own payloads is indistinguishable from a clean target · **READY** · **HIGH**

**Reported by the operator from his ISP router's app, mid-scan.** His own gateway IPS was dropping
Apolaki's probes OUTBOUND, before they ever left his network:

```
16:50  HTTP URI Comment Characters SQL Injection was blocked
16:50  HTTP URI 1=1 SQL Injection was blocked
16:50  HTTP URI Equal To SQL Injection was blocked
16:54  HTTP URI Union Select SQL Injection was blocked
17:08  (same three again)          17:12  Union Select again
```

Those are `sqli_tool`'s payloads. Meanwhile the report read:

```
run_sqli            | executed | 70 | 0 | tested 3 param(s), 0 confirmed SQLi
run_sqli_structural | executed | 69 | 0 | 0 structural SQLi finding(s)
run_xpath / run_ldap / run_ssi / run_css_injection | 69 each | 0
```

**Every one of those zeros is a blocked request, not a tested parameter.** The engines reported a
clean result for a probe that never reached the target.

**THIS IS THE WHOLE WEEK'S DEFECT CLASS, ONE LAYER OUT.** Q-092 was `_cmd` discarding an exit code,
Q-093 `_http` discarding a transport outcome, Q-097 an empty header dict from a dead socket. Each
time the fix was: **a failed attempt must not be reported as a clean result.** Here the failure
happens on the operator's OWN path, so nothing inside the process sees an error at all -- the request
is answered, or times out, and the engine records a legitimate-looking zero.

It also silently costs time: a dropped request sits until timeout, which is part of why the sweep was
running at ~6 minutes per endpoint.

**WHAT DETECTION LOOKS LIKE.** Do not try to fingerprint IPS vendors. The general, target-agnostic
signal is a DIFFERENTIAL the engines already have the pieces for:

- a benign request to the same endpoint succeeds, AND
- every payload-bearing request to it fails in the same way (reset / timeout / a block page that is
  not the app's own 4xx), AND
- the pattern holds across UNRELATED hosts

One host behaving that way is a WAF on the target, which is a finding about the target. **The same
behaviour across unrelated hosts is a middlebox on OUR side**, which is a fact about the run and
invalidates every injection result in it.

**REPORT IT AS DEGRADED, NEVER AS CLEAN.** The mission must say "injection testing was intercepted
upstream; these results are void" and the affected engines must return `ran=False`. A run whose
payloads never left the building is not evidence of a secure target.

**GATE:** with every payload-bearing request failing and the benign control succeeding across two
unrelated hosts, the injection engines report DEGRADED and NOT "0 confirmed". Negative control, and
it is the one that matters: a genuinely clean target -- benign AND payload requests both answered
normally -- must still report a plain zero, or the check turns every quiet scan into a false alarm.

**OPERATOR WORKAROUND until this lands:** disable the gateway IPS for the scan window, or run from a
VPS. Any run where the router logs blocked probes has void injection results.

### Q-111 · Phantom parameters: `&amp;` never decoded, so a HIGH was raised on a parameter that does not exist · **CLOSED** · **HIGH**

`intel._add_ref` mined hrefs straight out of markup with no HTML unescaping. An attribute in real
markup is entity-encoded, so `?a=1&amp;language=en` was split on the LITERAL text into two
parameters: `a` and **`amp;language`**.

**From the operator's run, four findings on parameters that do not exist:**

```
Finding 8:  Server-side template injection on 'amp;language'      <-- HIGH
Finding 19: Reflected DOM data manipulation in 'amp;language'
Finding 20: Reflected DOM data manipulation in 'amp;signup_page'
Finding 21: Reflected DOM data manipulation in 'amp;signup_types[]'
```

A **HIGH SSTI against a parameter the server has never heard of.** Every probe fired at these was
wasted budget, and every finding from them was false -- the same category as Q-106, reaching the
report by a different road.

**FIXED** with `html.unescape` at `_add_ref`, the one boundary where markup becomes a URL. Deliberately
there rather than in each consumer: a decode repeated per-engine is a decode someone forgets.

**GATE** (part of the same 11): removing the unescape kills three tests. The second half is asserted
too -- the real parameters BEHIND the entity must be RECOVERED (`language`, `signup_page`), because a
fix that merely stopped emitting `amp;language` while also losing `language` would trade a false
positive for a blind spot.

### Q-109 · 30 graph endpoint nodes carry no host, every run · **READY** · **MEDIUM**

Present in every one of the operator's Shopify snapshots:

```
graph_primary_state.hostless_endpoint | failed | DEGRADED: swallowed exception at
graph_primary_state.hostless_endpoint: ValueError: 30 graph endpoint node(s) carry no host, so no
absolute URL exists for them
```

**THE REPORTER IS NOT THE BUG.** `agent.py:3452` deliberately drops an endpoint it cannot resolve,
records the drop through `_swallow` with a count and the first offenders, and its own comment states
they "were NOT faked onto a bare scheme". That is Q-093's discipline working exactly as intended --
the alternative, inventing `https:///path`, is the defect that hid for weeks.

**The open question is what MINTS them.** Q-093 fixed `planner._addressable`, which lost the netloc
when building steps. Something else is still creating endpoint NODES with no host, and 30 endpoints
per run are therefore never probed. That is a real coverage loss, silently bounded.

**NOT INVESTIGATED.** I confirmed the reporter is correct and stopped there rather than guess at the
producer while the operator was asleep. The next reader should start from the recorded offenders --
`_swallow` carries the first three verbatim in the mission record, so the shape of the bad keys is
already captured and needs no new instrumentation.

**Do NOT "fix" this by relaxing the drop or by silencing the ledger row.** The row is the only reason
anyone knows 30 endpoints are missing. An engine that ERRORED is correctly reported as a broken
instrument rather than a clean result; the honest resolution is to stop producing hostless nodes, not
to stop counting them.

### Q-108 · `res.ran` on a ToolResult that has `success`: one typo, one engine lost every run · **CLOSED** · **HIGH**

Visible in the operator's live log as exactly one line:

```
session-lifecycle artery error: AttributeError: 'ToolResult' object has no attribute 'ran'
```

`agent.py:2311` built the session-lifecycle result with `bool(res.ran)`. `ToolResult` exposes
`success`. So **every mission raised AttributeError there**, the artery's `except` turned it into an
info line, and **the entire session-lifecycle leg (CWE-613) was discarded on every run**. The engine
executed; nothing it produced ever reached a report.

**THE ARTERY HANDLER MADE IT WORSE, and it is still right to keep.** It exists so one broken leg
cannot kill a scan. But it converts a crash into prose, and prose scrolls past. The mission looked
healthy, the suite was green, and the only evidence was one line in a live log nobody diffs. **A
swallowed AttributeError is indistinguishable from an engine that found nothing** -- the same shape as
Q-092, Q-093, Q-097 and Q-105.

**GATE** (`tests/test_toolresult_attribute_contract.py`, 4 passed). The durable half is an **AST**
scan for `.ran` as an ATTRIBUTE access in `agent.py`. Deliberately not grep: `"ran"` is a legitimate
DICT KEY throughout this codebase -- the session-lifecycle result publishes one -- and a text search
cannot tell a key from an attribute, so it would either miss the defect or drown in false hits.
Verified by restoring `res.ran` in production: the guard fails, naming the line. A fourth test plants
the same shape in a parsed snippet so the scan cannot pass by finding nothing.

Fixing the call site fixes today. The guard is what stops the next `.ran` / `.ok` / `.ran_ok` from
costing another engine in silence.

### Q-107 · A running mission has NO heartbeat: three separate signals all read flat while it works · **CLOSED** · **HIGH**

**CLOSED.** `db.mission_heartbeat(mid)` returns `{"last_dispatch", "dispatches"}` from a single
indexed SQL aggregate over `tool_call` rows -- independent of findings, of phase, and of the ledger.
Surfaced as `**Last activity:**` in the report header and as `heartbeat` on `GET /missions/{id}`, so
an operator can poll one number instead of resorting to `docker stats`.

**GATE** (`tests/test_mission_heartbeat.py`, 7 passed): activity with ZERO findings advances it (the
case all three existing signals fail); a mission with no activity does NOT advance (the control that
stops it being another clock); and `dispatches` only ever rises, applying Q-105's lesson before it
could repeat.

**The last test exists because I nearly shipped this useless.** `generate_report` has a separate
short path for a mission with no confirmed findings, and I had added the heartbeat only to the full
report -- so it would have been **absent from the exact document the waiting operator reads**. A
mission that has found nothing yet is precisely when "is it still working?" gets asked.


**Reported by the operator mid-run, and he was right to keep asking.** He could not answer "is it still
working or has it hung?" from anything the platform publishes. Measured across 85 minutes of a live
mission:

| signal | reading | why it cannot answer the question |
|---|---|---|
| `Latest evidence` | moved 2 min in 85 | derived from FINDINGS only (Q-102). A scan whose job is mostly to find nothing shows a flat line while working perfectly. |
| `Tools Invoked` | 573 -> 570 | **decreases.** The ledger is not cumulative (Q-105), so the one counter that should monotonically rise goes backwards. |
| `Surface Urls` | 4823 -> 4823 | grows during crawl, flat during probe. Correct, and useless once the phase it tracks has ended. |

`Report generated` advances, but that is a fact about the RENDERER, not the mission -- it advances
identically for a wedged run.

**Q-102 is mine and it is half a fix.** I built `Latest evidence` yesterday to answer exactly this
question and bound it to findings, which is the one thing a healthy scan may legitimately produce none
of for hours. The operator then had to fall back on `docker stats` to see whether his own tool was
alive.

**FIX:** publish a mission HEARTBEAT that is independent of findings, of phase, and of the ledger --
the timestamp of the last TOOL DISPATCH, plus a monotonic count of dispatches. Both come from rows the
`logs` table already holds (`tool_call` events carry `created_at`), so this is surfacing data, not
instrumenting new. Put it in the running report's header beside `Report generated`, and expose it on
`GET /missions/{id}` so an operator can poll one number.

**GATE:** a mission with tool activity but ZERO findings must show a heartbeat that ADVANCES between
two renders. That is the exact case all three current signals fail. Negative control: a mission with
no activity at all must show a heartbeat that does NOT advance, or the field is just another clock and
answers nothing.

**RELATED:** fix Q-105 first or the dispatch count inherits the same non-cumulative defect. A heartbeat
that can go backwards is worse than none, because it looks authoritative.

### Q-106 · The CRLF oracle reported a HIGH on an ECHO, against a live bug-bounty target · **CLOSED** · **CRITICAL**

**This one nearly went to Shopify.** The operator's engagement produced two HIGH findings,
"CRLF / response-header injection", on `linkpop.com` (an in-scope asset). He verified by hand and they
did not reproduce:

```
curl -is 'https://linkpop.com/480cd2?fbclid=1%0D%0AX-bbhcrlf%3A+bbhcrlfpwned'
Location: https://linkpop.com/480cd2/index.html?fbclid=1%0D%0AX-bbhcrlf:+bbhcrlfpwned
```

The marker sits INSIDE the `Location` value and **`%0D%0A` is still percent-encoded**. Note that
`%3A` decoded to `:` while the newline did NOT -- the server declining to decode a CRLF, which is the
defence working exactly as intended. Nothing split.

**The oracle:**

```python
if CRLF_MARKER in kl or f"{CRLF_MARKER}pwned" in vl:      # web_security.py:793
```

with a docstring justifying it as *"the marker cannot occur naturally"*. **It can, and routinely
does.** Our payload is in the request URL, and any app that echoes that URL into a header hands the
marker straight back. A redirect preserving the query string is the most ordinary behaviour on the web.

**The oracle checked a WEAKER property than the one it reported.** "The marker appears somewhere in
the response headers" is not "the marker became its own header", and only the second is a
response-splitting primitive.

**FIXED.** A KEY match stays HIGH and is the sound test -- a genuine split is parsed by the client as
a separate header, so the marker becomes a header NAME. A VALUE match now has to rule out the
still-encoded payload first (`%0d%0a` and the overlong-UTF-8 variant `%e5%98%8a%e5%98%8d` that
`build_crlf_probes` also sends). The Set-Cookie value-split sink, where the CRLF genuinely decoded,
still reports.

**GATE** (`tests/test_crlf_oracle_needs_a_split.py`, 6 passed): a mutant restoring the old permissive
oracle is **killed by exactly the 3 tests that encode the false positive**, while the 3 that must
survive -- a real split is still HIGH, a decoded Set-Cookie split is still HIGH, a clean response is
silent -- correctly do. The sharpest is
`test_the_same_value_differs_only_by_whether_the_crlf_decoded`: identical marker, identical header,
identical position, the only difference being whether the server decoded the newline. That is the
line between a defence that held and a primitive that exists.

**WHY THIS ONE MATTERS MOST.** Every other ticket this week hid a true positive or wasted budget.
This one manufactured a HIGH severity claim about a specific company's specific endpoint, with a
copy-paste reproduction that disproves itself in one command. Submitting it would have cost the
operator standing with the program. **A false negative is a missed bug; a false HIGH is a false
accusation.**

**STILL SUSPECT, not yet examined:** the same run produced two MEDIUM "Host header injection" findings
on the same two endpoints, from the same `run_injection_probes` pass. Same shape, same reflection
source. Verify that oracle before trusting it.

### Q-104 · Phase A feeds itself and starves every later phase: 14 hours, 1000 calls, zero active engines · **CLOSED** · **CRITICAL**

**Found in the field.** The operator's 2026-08-27 Shopify engagement, two snapshots of ONE mission:

```
22:10 UTC   12 tools dispatched, run_transport_posture had run,  67 calls per recon tool
03:49 UTC    7 tools dispatched, ALL passive recon,             286 calls per recon tool
             1000 invocations - 6 of 9 in-scope targets never probed - 0 active engines
```

`_graph_primary_state` (`agent.py:3402`) makes a recon root out of **every host node in the graph**:

```python
hosts = sorted({n.get("label") for n in g.nodes("host") if n.get("label")})
```

Planner phase A runs **seven passive tools per root**, and what those tools discover becomes more host
nodes. Phase A ends with `if a: return a`, so **while one fresh recon step exists, no later phase runs
at all.** Roots had grown to ~41 and the mission could not reach phase B in fourteen hours.

**Every other phase in `planner.py` has a cap** -- `CAP_HOSTS 30`, `CAP_ENDPOINTS 25`, `CAP_JS 40`,
`CAP_ZAP 3`. Phase A, the only SELF-FEEDING one, had none.

**Q-100 did not cause this. It UNMASKED it.** Before Q-100 a regex-only scope produced an empty
`in_scope`, so the graph was never seeded, phase A had nothing to expand, and the mission did nothing
at all (Surface URLs 0). The moment scope worked, the unbounded fan-out was free to run. Worth stating
because the tempting conclusion was "the new feature broke it" -- the new feature revealed it.

**FIXED.** `CAP_RECON_ROOTS = 25`, and roots are ranked with the OPERATOR's declared assets first (a
new `scope_roots` in the planner state, distinct from `roots`, which is everything the graph has
learned). The cap trims discovered hosts and can never crowd out an asset the operator actually put in
scope -- which would be a worse bug than the fan-out, since the mission would skip what it was pointed
at.

**GATE** (`tests/test_recon_fanout_is_bounded.py`): pristine 4 passed; a mutant restoring the
unbounded behaviour is **killed by 2 of the 4**, reporting `43` roots and "phase A never drained after
360 discovered hosts". The other two are non-vacuity controls (a small engagement is not capped;
operator assets are never trimmed) and correctly survive a cap-removal mutant.

**MY FIRST VERSION OF THAT GATE WAS VACUOUS, and the mutant proved it: 0 of 4 killed.** Two causes,
both worth remembering. It asserted `len(targets) <= planner.CAP_RECON_ROOTS` -- **a bound that tracks
the thing it bounds is not a bound**, so raising the constant raised the assertion with it. And the
progression test marked one whole batch done at once, which drains even uncapped; the real mission's
roots GREW BETWEEN BATCHES, and a test that holds the root set still is testing a mission that never
existed.

### Q-105 · The tool ledger is not cumulative: rows vanish and notes go backwards · **CLOSED** · **MEDIUM**

**CLOSED.** `_tool_ledger` folded `db.get_logs(session_id, limit=4000)`, and `get_logs` keeps the
NEWEST rows when that limit bites -- correct for a log VIEW (Q-017 made it that way so a truncated
tail could not make a live mission look stopped) and wrong for an AGGREGATE. Early rows fell out of
the window, which is exactly why `run_transport_posture` ran in the first minute and was absent from
the second render.

Fixed with a SECOND accessor rather than by changing `get_logs`, because both behaviours are right
for their own caller. `db.iter_logs(mid)` yields every event oldest-first as a GENERATOR, so a
mission with tens of thousands of rows costs nothing to fold into running totals. It also skips a
malformed row instead of raising -- the old path would have taken the whole report down with one
unreadable event, which the gate now pins.

**GATE** (`tests/test_ledger_is_cumulative.py`, 6 passed): a mutant restoring the windowed read is
**killed by 5 of the 6**, including a `JSONDecodeError` proving the old path crashed rather than
skipped. The load-bearing one is
`test_a_tool_that_ran_early_survives_a_long_tail_of_later_events`, which reproduces the field
failure directly: one early tool, then 5200 rows of noise past the old window.


**MEASURED across the operator's two snapshots of one running Shopify mission:**

| | 22:10 UTC | 03:49 UTC |
|---|---|---|
| tools listed | 12 | **7** |
| `run_transport_posture` | executed, 3 calls, 10 findings | **absent entirely** |
| `run_crtsh` note | 2 CT log entries | **0 CT log entries** |
| `run_subfinder` note | 2 subdomains found | **1 subdomains found** |
| `run_subfinder` calls | 67 | 286 |

**Calls climb while the note goes DOWN**, and tools that stopped running disappear. So the `note`
column is the **most recent call's** note rendered as if it summarised the tool -- a per-call value
presented as a per-tool fact, the same shape as every other ticket this week.

**Apolaki caught it itself**, which is the encouraging half:

> Ledger disagreement: `run_transport_posture` produced findings but the tool ledger has no record of
> running them. Two independent records of this mission do not agree, so one of them is wrong.

**Why it matters beyond tidiness:** the Arsenal-coverage section reads the ledger to decide what "ran
and found nothing" versus "was never dispatched". With rows vanishing, an engine that RAN is reported
as never dispatched -- exactly the invisible false negative this document elsewhere refuses to
tolerate.

**FIX:** the ledger accumulates over the mission rather than being rebuilt from a window. A note that
summarises a tool must aggregate its calls, or say plainly that it is the latest of N.

**GATE:** snapshot a mission twice with more calls in between; no tool row may disappear and no count
may decrease. Negative control: a tool that genuinely never ran must still be absent.

**RELATED, still unresolved and deliberately not guessed at:** `run_subfinder` reports 40094 findings
beside a note reading 2 subdomains found, and `run_asn` 286 findings beside 1 IP. The `findings`
column appears to count DATA ITEMS for recon tools. Read the data model before changing anything; a
numeric-mismatch rule invented here would flag every recon row.

### Q-103 · The integrity checker reported a WIRING GAP as a clean bill of health · **CLOSED** `see commit` · **HIGH**

**From the operator's 2026-08-27 Shopify run.** The Report Integrity block said:

> ✓ **Consistent** — 5 of 10 automated consistency checks applied and passed
> _Not applicable to this report: ... ledger-note-contradiction (the report carries no tool ledger
> rows to cross-check)_

**The report printed a full tool ledger two sections above that sentence.**

`report.py:675`, the MARKDOWN renderer, called `check_report_consistency(findings, leads, risk,
counts)` with four arguments, so `tool_ledger` and `chains` arrived as `None`. `applicable()` treated
`None` and empty as the same answer and rendered both as "not applicable to this report". **A plumbing
mistake was laundered into reassurance.** The HTML renderer at `:3480` had always passed six
arguments; only the markdown one, which is what an operator actually reads, went unchecked.

**FIXED, both halves.** The renderer now passes `tool_ledger` and `chains`. And `applicable()`
distinguishes `None` (the caller never supplied it) from empty (the report genuinely has none), so a
future wiring gap reports itself as **"NOT SUPPLIED to the integrity check by this renderer -- this is
a wiring gap, not a clean result"** instead of as a pass.

**The second half is the one that matters.** Passing the argument fixes today's bug; teaching the
checker that ABSENT and NOT-SUPPLIED are different answers is what stops the next one. Reassurance is
the single output a verifier must never invent, and this project has now shipped this exact shape in a
guard (I-4/I-5/I-9), an engine (`_cmd`, `_http`), a parser (dalfox) and now a report.

**GATE** (`tests/test_integrity_wiring.py`, 6 passed): not-supplied is named a wiring gap; a genuinely
empty ledger still reads as not-applicable (the non-vacuity control, or every skip would become
noise); a contradictory ledger is caught; a consistent one is not; and the markdown renderer end-to-end
both emits the contradiction and never claims a ledger it was not given.

**NOT FIXED, and deliberately not guessed at.** The same run shows `run_subfinder | 40094 findings |
"2 subdomains found"` and `run_asn | 67 findings | "1 IP(s)"`. The ledger's `findings` column appears
to count DATA ITEMS for recon tools rather than findings, which is a different defect in the ledger's
own vocabulary. `_zero_re` only catches "no X confirmed" wording and would not see it. Needs the data
model read before anything is changed; guessing a numeric-mismatch rule here would produce false
contradictions on every recon row.

### Q-102 · A running assessment carries no per-event timestamps, so nothing can be placed in time · **CLOSED** · **MEDIUM**

**VERIFIED.** Full suite GREEN at `ce59bad`: **3671 passed / 11 skipped / 12 xfailed / 0 failed**, `PYTEST_EXIT=0`, on a clean `git archive HEAD` snapshot attached to `apolaki_default`. Baseline before this batch was 3604.

`db.get_findings` attaches `observed_at` from the row's own `created_at` -- the column the statement was already ORDERING BY and never SELECTing. The report prints `Observed:` per finding and `First/Latest evidence` in the header, all read from stored rows and never from a render clock. The gate that matters renders the same mission twice and asserts every evidence line is byte-identical while `Report generated` differs: a report that stamps ITSELF would pass every other assertion while telling the reader nothing, and would look authoritative doing it.

ORIGINAL TICKET FOLLOWS.

### Q-102 (as filed)

**Operator-reported, 2026-08-27, during a live Shopify run.** The report carries exactly ONE time: the
`**Date:**` header of the snapshot. Every finding, every tool-ledger row and every event in the live
view is undated.

**Why this is not cosmetic:**

- **A live run is unreadable.** A snapshot taken mid-scan shows 10 findings and 478 tool calls with no
  way to tell which arrived a minute ago and which have been sitting for an hour. The operator cannot
  see whether the run is progressing or wedged, which is precisely the question a running report exists
  to answer.
- **A finding without a time cannot be retested honestly.** The `Retest / closure` block already tells
  an operator to re-run the confirming request, and "was this observed before or after that deploy?"
  is unanswerable. A target's posture changes; a finding is a claim about a MOMENT.
- **Duration is evidence.** Timing-based oracles (time-based blind SQLi, the traversal differential)
  are argued from elapsed time, and the report never states any.
- **It is how you catch the wedged engine.** Three lanes and one full-suite run were lost this week to
  a wedged Docker backend, and the tell was always "nothing has moved in N minutes". With no
  timestamps, a stalled mission and a slow one look identical, which is this project's oldest defect
  shape wearing yet another costume.

**FIX:** every finding carries the UTC instant it was CONFIRMED (not when the report was rendered);
every tool-ledger row carries first-dispatch and last-completion, so per-tool duration is derivable;
the running report states the mission start and the age of the snapshot. Prefer the timestamps the
DB rows and event log ALREADY hold over adding new clocks -- check `logs`/`exchanges` first, since the
data is very likely present and simply not surfaced, which would make this a reporting fix rather than
an instrumentation one.

**GATE:** a finding rendered from a stored row carries that row's own confirmation time, not the render
time. The negative control is the one that matters: freeze the clock, render the same mission twice a
minute apart, and assert every finding timestamp is IDENTICAL across both renders. If they move, the
report is timestamping itself rather than the evidence, which is worse than no timestamp because it
looks authoritative.

### Q-101 · An ECDSA P-256 certificate is reported HIGH "weak key" against an RSA threshold · **CLOSED** · **CRITICAL**

**VERIFIED.** Full suite GREEN at `ce59bad`: **3671 passed / 11 skipped / 12 xfailed / 0 failed**, `PYTEST_EXIT=0`, on a clean `git archive HEAD` snapshot attached to `apolaki_default`. Baseline before this batch was 3604.

`_key_bits` returns `(size, algorithm)` and the threshold is per-algorithm: RSA/DSA/DH 2048, EC 256, Ed25519/Ed448 not judged on size at all. The single `_MIN_RSA_BITS` is gone, so a non-RSA key cannot be measured against it by accident. `key_algo` defaults to `""` rather than `"rsa"` deliberately -- a guessing default would rebuild the bug for any call site not yet updated -- and an unrecognised algorithm is not flagged, because a finding is a claim and failing to identify a key is not evidence about it.

Its `except` now RECORDS: returning `(0, "")` means "say nothing about this key", so a certificate it could not parse produced the same silence as a healthy one.

ORIGINAL TICKET FOLLOWS.

### Q-101 (as filed)

**A FALSE POSITIVE AT HIGH SEVERITY, ON A LIVE BUG-BOUNTY TARGET.** The operator's 2026-08-27 Shopify
run produced three of these against `partners.shopify.com`, `accounts.shopify.com` and
`your-store.myshopify.com`:

> Weak TLS certificate key: the public key is 256 bits, below the 2048-bit minimum. **Severity: HIGH.**

**All three are wrong.** 256 bits is **ECDSA P-256**, a modern strong curve roughly equivalent to
RSA-3072. Shopify sits behind Cloudflare (`AS13335`, confirmed in the same report's `run_asn` row) and
serves ECDSA certificates. The run also recorded `"negotiated": "TLSv1.3"`, so this is a current,
healthy TLS configuration being reported as a critical weakness.

**Submitting this to a program is worse than submitting nothing.** It is a confident HIGH about
cryptography, aimed at a mature security team, and it is trivially disprovable in one command.

**ROOT CAUSE, and it is this codebase's most repeated defect for the FIFTH time: the producer measured
the discriminator and discarded it at the return edge.**

`transport_posture._key_bits` (`:603`) ALREADY knows the algorithm. It branches on it explicitly:

```python
if isinstance(k, rsa.RSAPublicKey):
    return k.key_size
if isinstance(k, ec.EllipticCurvePublicKey):
    return k.curve.key_size      # <- knows it is EC, returns a bare int
return getattr(k, "key_size", 0) or 0
```

and the caller (`:129`) compares that int against a constant whose NAME says what it is for:

```python
_MIN_RSA_BITS = 2048             # :41
if key_bits and key_bits < _MIN_RSA_BITS:
```

Nothing is broken about either half in isolation. The type existed, was computed, and was dropped
between the two. Same sentence as `_cmd` discarding `proc.returncode` (Q-092), `_http` discarding
`status`/`error` (Q-093), and the DB writers of Q-089/Q-090.

**FIX:** `_key_bits` returns the algorithm alongside the size, and the threshold is chosen per
algorithm: RSA/DSA >= 2048, EC >= 256, Ed25519 always acceptable. Rename `_MIN_RSA_BITS` so the
constant cannot be applied to a non-RSA key by accident again. An UNKNOWN algorithm must NOT be
flagged: unknown is not evidence, and a finding is a claim.

**GATE:** an ECDSA P-256 certificate produces NO weak-key finding; a genuine RSA-1024 certificate
still DOES. Both halves, or the fix is indistinguishable from deleting the check. Use fixtures, not a
live host, so the gate does not depend on what a CDN serves this week.

**WATCH FOR THE SAME SHAPE ELSEWHERE IN THIS FILE.** The defect is not the number 2048, it is comparing
across a discriminator that was thrown away. Audit every other certificate and cipher assertion in
`analyze_certificate` for the same pattern before closing.

### Q-100 · A Burp scope file is REFUSED whole when its patterns contain 9 concrete scannable hosts · **CLOSED** · **HIGH**

**VERIFIED.** Full suite GREEN at `ce59bad`: **3671 passed / 11 skipped / 12 xfailed / 0 failed**, `PYTEST_EXIT=0`, on a clean `git archive HEAD` snapshot attached to `apolaki_default`. Baseline before this batch was 3604.

A Burp/HackerOne export yields **9 concrete targets and 6 recon roots** instead of a refusal, confirmed on the operator's real file (committed as a fixture). Patterns stay the predicate; alongside them an anchored literal becomes a `domain` entry and a subdomain wildcard becomes a `*.apex` wildcard entry -- both vocabulary this codebase already had, so `base_urls()` dials the first and refuses the second while `agent.py:3758` seeds recon from it. Un-escaping is not guessing: only `\.` is unescaped and any surviving metacharacter derives nothing, so `^a\.b\.com$` resolves and `^a.b\.com$` does not. The parser also honoured `enabled: false` rules, treating a disabled EXCLUDE as protection the operator did not have.

**LIVE CONFIRMATION** from the operator's rerun: Surface URLs 0 -> **6213**, subfinder 0 -> 2 subdomains, crtsh 0 -> 2 CT entries, `run_dns` "SPF MISSING" -> **SPF set, DMARC set**, `run_asn` 0 IPs -> AS13335 Cloudflare, TLS `reachable: false` -> **`reachable: true, TLSv1.3`**.

ORIGINAL TICKET FOLLOWS.

### Q-100 (as filed)

**Q-096 stopped the harm. It did not deliver the capability.** The operator's real HackerOne/Burp scope
export (`shopify20260827T16_04_11Z.json`) is the input that produced the 18 fabricated findings. After
Q-096 that file is now REFUSED at `load_manual` with `ScopeConfigurationError`, which is correct and
safe. **But the operator still cannot scan Shopify, and the file contains everything needed to.**

`_parse_burp_json` (`scope.py:648`) correctly unwraps `target.scope` and reads `item["host"]`. Every
host it hands on is an anchored regex, so all of them are now typed `pattern`, `in_scope` ends up
EMPTY, and the mission is refused.

**MEASURED from the operator's file. 15 unique include hosts (x2 for http/https = 30 entries):**

| kind | count | examples |
|---|---|---|
| **anchored LITERAL, directly scannable today** | **9** | `^partners\.shopify\.com$`, `^accounts\.shopify\.com$`, `^admin\.shopify\.com$`, `^shop\.app$`, `^shopify\.plus$`, `^linkpop\.com$`, `^shopifyinbox\.com$`, `^arrive-server\.shopifycloud\.com$`, `^your-store\.myshopify\.com$` |
| **true wildcard, a RECON ROOT and not an address** | **6** | `^.*\.shopify\.com$`, `^.*\.shopifycs\.com$`, `^.*\.shopify\.io$`, `^.*\.pci\.shopifyinc\.com$`, `^.*\.shopifykloud\.com$`, `^.*\.shopifycloud\.com$` |

**An anchored literal regex IS a hostname with extra punctuation.** `^partners\.shopify\.com$`
un-escapes to `partners.shopify.com` mechanically and without guessing: strip `^`/`$`, unescape `\.`,
then confirm no metacharacter survives. That is 9 real assets available with NO recon at all, one of which (`your-store.myshopify.com`) is
the program's placeholder for the tester's OWN store; it IS in the include list, so it is derived like
any other and simply will not resolve. REVERSED ON IMPLEMENTATION: this ticket first said to exclude
it by name, and special-casing one hostname is the hardcoding this project forbids everywhere else.
The scope says in-scope, so the code says in-scope. The 6 wildcards give apex roots to seed `subfinder`/`crtsh` with, which is exactly
what the failed mission's recon needed and never got.

**FIX, and the ordering is the point.** Scope patterns stay patterns and remain the PREDICATE.
Alongside them, derive:

1. **concrete seeds** from anchored-literal patterns by un-escaping. Never by guessing, and never by
   stripping `.*` off a wildcard, which would invent `shopify.com` as a target from a rule that only
   ever authorized its SUBdomains.
2. **recon roots** from wildcard patterns, fed to `subfinder`/`crtsh`, with every discovered host
   validated back through the predicate before anything is dialled.

Refuse only when BOTH sets come back empty. `ScopeConfigurationError` would then mean "nothing here can
be turned into a target", which is true, rather than today's "no entry is literally a hostname", which
is a different and weaker claim.

**SECOND DEFECT IN THE SAME PARSER, a scope-SAFETY issue rather than a coverage one.**
`_parse_burp_json` reads ONLY `host`. The operator's file also pins `"protocol"`, `"port": "^80$"` /
`"^443$"`, and `"file": "^/.*"` on every entry, and **all three are discarded**. Port and path pinning
already exist in `ScopeEntry` (SEC-1, SEC-2) and are simply never populated from Burp JSON, so a Burp
scope authorizing only `:443` is silently widened to every port. **The 14 EXCLUDE entries parse through
the same path**, so `cdn.shopify.com`, `community.shopify.com`, `academy.shopify.com` and the rest must
survive as patterns too. An exclude that fails to match is far worse than an include that does.

**GATE:** load the operator's real file (commit it as a fixture, no network) and assert it yields
**9 concrete targets, 6 recon roots, 7 exclude patterns**; that `cdn.shopify.com` is refused by the predicate; and that port and path pinning survive.
Negative controls: an all-wildcard scope yields 0 concrete targets and still does not raise so long as
it yields recon roots; a genuinely unusable scope (`[::1]`, `my host.com`) still raises.

### Q-099 · `findings_gate` FAILS OPEN in exactly the two states where scope is broken · **CLOSED** · **HIGH**

**VERIFIED.** Full suite GREEN at `ce59bad`: **3671 passed / 11 skipped / 12 xfailed / 0 failed**, `PYTEST_EXIT=0`, on a clean `git archive HEAD` snapshot attached to `apolaki_default`. Baseline before this batch was 3604.

Both fail-open arms of `findings_gate.off_scope` reversed. The deeper finding was that `load_manual` raising is CORRECT and three callers mishandled it three different ways: `off_scope` swallowed and ADMITTED, `main._scope_for` leaked a 500 into the UI, `retest_findings` handled it but wrote its own sentence. `scope.build_boundary` is now the one evaluation and the one sentence. `_scope_for` answers 409; `GET /missions/{id}` still answers 200 carrying `scope_error`, so a historical mission with invalid scope still OPENS and only the surfaces that would send traffic refuse.

The `off_scope` handler now RECORDS its swallow through `tools._ACTIVE_REGISTRY`: failing closed keeps the finding out of the report, but a boundary that silently stopped answering looks identical to a scope that legitimately refuses everything.

ORIGINAL TICKET FOLLOWS.

### Q-099 (as filed)

Surfaced as a residual by the Q-096/097/098 lane and confirmed by the Coordinator. The function returns
`True` to BLOCK an out-of-scope finding, so every `return False` ADMITS it. There are two:

```python
if not _host_of(target):
    return False          # findings_gate.py:93  "no host to judge -> admit (fail-open)"
...
except Exception:
    return False          # findings_gate.py:104 "scope engine unavailable -> do not block"
```

**Both fail open precisely when scope is least trustworthy.** A target with no parseable host is exactly
the Q-096 regex case. And since Q-096 made `load_manual` RAISE on an all-pattern scope, the second arm
now catches that raise and admits every finding from a mission whose scope could not be built at all.

**This is the wrong direction for this particular gate.** An engine failing closed loses a finding; a
SCOPE gate failing open puts an out-of-scope finding in a report submitted to a bug bounty program.
That is a program-rules violation and a reputational hit, not a missed bug. The comments show both were
deliberate, so the fix is a decision to reverse, not a bug to patch quietly.

**FIX:** unbuildable scope or unparseable target means REFUSE the finding and surface a mission-level
error, following `main.py:3081` ("Unknown is not permission"). Do not silently admit.

**GATE:** a mission whose scope cannot be built must emit ZERO findings, not all of them. Negative
control: a well-formed scope must still admit every in-scope finding and block a genuinely out-of-scope
one, or the fix has simply broken the gate in the other direction.

**RELATED, needs the same decision:** `main.py:197 _scope_for()` now RAISES when reopening a stored
all-pattern mission (such as the Shopify run that produced Q-096). That is the correct direction, but it
means a historical mission may fail to open in the UI. Decide whether it should surface as a clean
"this mission's scope was invalid" state rather than an exception.

### Q-095 · Param mining yields NAMES, not VALUES, and 81.2% of dispatches probe a valueless parameter · **CLOSED** · **HIGH**

**VERIFIED.** Full suite GREEN at `ce59bad`: **3671 passed / 11 skipped / 12 xfailed / 0 failed**, `PYTEST_EXIT=0`, on a clean `git archive HEAD` snapshot attached to `apolaki_default`. Baseline before this batch was 3604.

`planner.merge_observed_params` upgrades a blank-valued parameter to the OBSERVED one. `have` counted a blank as "already have it", so the value `observed_param_values` had already recovered was dropped. Nothing is synthesised: a parameter never observed with a value keeps its blank. The byte-for-byte no-op branch is load-bearing, not tidiness -- re-encoding unconditionally rewrites `?q` as `?q=`, the same request on the wire but a different STRING, churning dedup keys across all 9873 valueless dispatches for endpoints this does not help.

ORIGINAL TICKET FOLLOWS.

### Q-095 (as filed)

**A baseline-dependent engine handed `?q` instead of `?q=apple` reports CLEAN on a genuinely
vulnerable endpoint.** Proven on sqlmap by the Q-092 audit, then measured corpus-wide by the
Coordinator and found to be general.

**THE PROOF, same tool, same endpoint, same flags, one difference:**

```
sqlmap -u "http://juice-shop:3000/rest/products/search?q"        --batch --level 5 --risk 3 ...
  -> "all tested parameters do not appear to be injectable"      is-vulnerable: 0

sqlmap -u "http://juice-shop:3000/rest/products/search?q=apple"  --batch --level 3 --risk 2 ...
  -> Parameter: q (GET)  boolean-based blind + time-based blind, back-end DBMS: SQLite
                                                                 is-vulnerable: 1
```

**Why the empty value is fatal, measured in raw bytes:** `?q` and `?q=` both return **16578 bytes**
(the whole product list, an UNFILTERED query) while `?q=apple` returns **921**. With an empty value the
baseline IS the unfiltered response, so sqlmap's dynamicity check concludes the parameter does not
change the page and **stops before injecting anything.** The parser is fine. The tool is fine. The
input was never capable of producing a result.

**Root cause:** the URLs come from param-mining, which yields parameter NAMES and never carries an
observed VALUE. Corpus examples, verbatim: `?q`, `?key&name`, `?current`, `?email`,
`?callback&format&key`, `?EIO&sid&t&transport`.

**SCALE, measured by the Coordinator over all `tool_call` rows carrying a query string:**

```
CORPUS TOTAL: 2283 valued, 9873 VALUELESS of 12156 query-bearing dispatches (81.2%)
5 tools whose EVERY query-bearing dispatch was valueless:
    run_sqlmap 0/58 valued   run_param_mine 0/56   run_ssrf 0/23   (+2)
worst by volume: run_xss 1059 valueless (77%), run_sqli 863 (75%),
    run_injection_probes 863 (75%), run_anomaly_scan 731 (94%), run_dom_audit 474 (94%)
```

**DO NOT OVERCLAIM THIS, and do not "fix" all 9873.** Valuelessness is **not** universally harmful,
and that was MEASURED, not assumed: the Q-092 audit A/B'd the **value-overwriting** engines, which
substitute their payload for whatever the value is, and found them **identical on both sides**. For
those, `?q` is harmless.

**The discriminator is whether the engine needs a working BASELINE.** An engine that compares a probed
response against an unprobed one is destroyed by an empty value, because the empty-value baseline is a
different page. An engine that overwrites the value does not care. Classify every engine on that axis
before changing anything; the fix is worthless if it is applied where it was never needed, and a
generalized change here would touch the highest-traffic engines in the tool.

**FIX: thread the OBSERVED value.** Crawl and traffic capture already see real parameter values;
param-mining discards them. **Never synthesize one.** `?q=apple` is the right value here only because
it was OBSERVED against this app; inventing a plausible-looking value is the failure mode that has
already bitten three engines in a single day, because an invented value can make baseline and probe
fail identically and the engine then reports clean on a vulnerable field.

**GATE:** a baseline-dependent engine, handed a valueless param for an endpoint it confirms with a
value, must be RED today and green after. The non-vacuity control matters as much: a value-overwriting
engine must be unaffected in both directions, or the fix has been applied where it was not needed and
the test cannot tell the two classes apart.

**RELATED:** this is the same defect family as Q-093 (a dispatch that could never have produced a
result, reported as a clean scan). Q-093 is the transport never opening; **Q-095 is the transport
opening and carrying input incapable of proving anything.** Both end in "0 findings" that reads as a
clean bill of health.

### Q-094 · The documented test command omits `--network`, and 10 tests answer by SKIPPING · **READY** · **HIGH**

MEASURED by the I-11 lane, same tree, same commit, only the docker flag differs:

```
without --network apolaki_default:   2 failed, 3526 passed, 19 skipped
with    --network apolaki_default:   0 failed, 3536 passed, 11 skipped
```

**The networkless run does not merely fail more. It TESTS LESS.** Ten tests convert from real
assertions into skips, and only the failing half is visible. Failures get chased; a skip count prints
as a number nobody diffs. This is the concrete mechanism behind the standing rule that **SKIPPED is
never a pass**, and it has been silently shrinking every suite run made with the documented command.

**The two failures actively misattribute themselves.** `test_truthful_metadata.py::
test_the_engine_now_reports_the_leak_end_to_end` and `::test_the_engine_reports_ONE_canonical_
coordinate_whichever_reader_ran` print `assert 0 == 1` FIRST and bury `[Errno -2] Name or service not
known` inside a `ToolResult` repr further down. **That reads as a broken oracle, not a missing
network.** A reader chases the assertion.

Attribution settled in both directions, which is what makes this environmental rather than a code
defect: pristine `66a7012` (containing none of the lane's work) fails IDENTICALLY networkless, and
current HEAD with the lane's commits passes 56/56 networked.

**FIX, two parts, and the second matters more:**
1. Add `--network apolaki_default` to the documented container command everywhere it appears
   (CLAUDE.md, the avengers-assemble skill, docs). Cheap, and stops the misattribution.
2. **Make the skips LOUD.** A test that skips for want of an environment must not be
   indistinguishable from a test that ran. Ratchet the skip count so a rise is red, or mark these
   `pytest.fail` when the network is expected. A guard that answers "skipped" to a question it exists
   to answer is a guard that cannot fail, which is the same defect class as I-4/I-5/I-9.

**GATE:** assert the skip count does not exceed the networked figure. The negative control is a run
without the network, which must go red rather than quietly reporting a smaller suite as green.

### Q-093 - `_http` drops the transport outcome the same way `_cmd` drops the exit code, and 3241 dispatches never reached a target - **CLOSED** `1d85fe3` `c08db26` `8df4535` `86c8dfb` - **CRITICAL**

**CLOSED. Both root causes fixed, each gate filed RED first, and 0 engines edited.** Verified
INDEPENDENTLY by the Coordinator on a clean `git archive HEAD` snapshot attached to `apolaki_default`:
**3581 passed / 11 skipped / 12 xfailed / 0 failed**, against a 3562 baseline, so `+19` is exactly the
new tests and nothing was lost.

**(A) The transport outcome, fixed at the chokepoint.** A `ContextVar` tally set per dispatch in
`execute`, `_http_record` at BOTH of `_http`'s return points, and `_http_failure(tally, produced=None)`
as the single shared predicate (sibling of `_cmd_failure`). Three deliberate rejections:

- **`ContextVar`, not the ticket's own suggested `self._http_dead` delta.** My drafted patch was wrong:
  a counter delta mis-bills one engine for another's dead requests when dispatches overlap. That is the
  stated reason `_ACTIVE_TOOL_DISPATCH` is already a ContextVar.
- **Recording is unconditional; only the predicate judges.** The Q-092 mistake, a rule that never fired
  on sqlmap's banner, deliberately not repeated.
- **`produced` is LOAD-BEARING, and omitting it would have shipped DATA LOSS as a fix.** `agent.py:874`
  guards auto-store with `if not result.error`. Stamping an error on a dispatch that DID produce
  findings would have **deleted them from the mission.**

Live on the lab over real sockets: `run_waf_bypass` / `run_sqli_structural` / `run_css_injection` at
`https://juice-shop:3000` now return `success=False` NAMING `WRONG_VERSION_NUMBER`, while their
`http://` twins are unchanged. `run_path_sqli` (the case that cost the real VAmPI SQLi) now writes a
**different durable row type per scheme**, `tool_error` vs `tool_result` - exactly where the audit
showed the 1687 dispatches were hiding.

**(B) The empty-netloc builder was STILL LIVE, and Q-019 appeared to have closed it.** All 1495 corpus
dispatches genuinely predate Q-019 (last `2026-08-10T16:28Z`, fix landed `2026-08-11T05:05Z`), so the
evidence said closed. **Driving the real `next_batch` still emitted
`run_js_review urls=['/static/app.js', 'https:///static/b.js']` the same day.**

`planner._addressable` inspected `("url", "base_url")` while the module declares FOUR target keys - and
**Q-019's own guard file collects the same two keys, so its coverage is exactly congruent with the
code's blind spot.** A guard that restates the code's assumptions inherits the code's blind spots.
Fixed by deriving from `_TARGET_KEYS`/`_TARGET_LIST_KEYS` instead of restating them, plus filtering at
the `js_urls` build site so one bad bundle cannot cost nine good ones.

**Adversarial verification:** four mutants, all killed, each with a DIFFERENT signature - including one
proving the gate requires the error to NAME the cause, and one proving the bare-host exemption
(`run_nmap_vuln`, `run_dork_gen`) stays pinned.

**HELD, with reasons rather than guesses:**
- `_run_hash_crack` NOT attempted: hashcat and john are both absent from the image, so no fix is
  verifiable in the real execution path, **and the naive fix is wrong anyway because hashcat exits 1
  for "exhausted"** - ran fine, cracked nothing. Only marker-derived reasons are exit-code-independent.
- `agent._reject_hostless_step` skips the `urls` list and fires only on values containing `"://"`.
  Checked rather than assumed: graph-directed steps do use that ingress and never emit a `urls` list,
  so after (B) it is a backstop hole with **no live producer**.

ORIGINAL TICKET FOLLOWS.

### Q-093 (as filed) - **CRITICAL**

**This is Q-092 in the HTTP path.** Q-092 is about 14 wrappers that shell out. `_http` is the
transport for **all 21 pure-Python engines**, and it has the identical defect with a wider blast
radius. Found while auditing Q-092's 22 remaining zero-histogram tools
(`docs/handoff/tool_liveness_audit.md`).

**MEASURED, live, on `apolaki_default`:**

```
reg._http("https://juice-shop:3000/rest/products/search?q=apple", "GET", capture=False)
  -> {'status': 0, 'error': '[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1010)',
      'body': ''}                       # 0 bytes
reg._http("http://juice-shop:3000/rest/products/search?q=apple", "GET", capture=False)
  -> {'status': 200, 'body': <921 bytes>}
reg._http("https:///.well-known/ai-plugin.json", "GET", capture=False)
  -> {'status': 0, 'error': "Request URL is missing an 'http://' or 'https://' protocol.", 'body': ''}
```

`_http` is honest -- it RETURNS `status` and `error`. **The callers never read either.** Every
engine does `r.get("body", "") or ""`, so an empty body from a dead connection is the same value as
an empty body from a clean page. This is the falsy-default failure mode on the return edge, the
same invariant `FindingWriteId` (Q-089) and `FindingUpdateResult` (Q-090) exist to satisfy.

**MEASURED: the wrappers report a completed scan over a connection that never opened.** Every
request in each run below failed with `SSL: WRONG_VERSION_NUMBER`, dispatched through the real
`ToolRegistry.execute`, url = `https://juice-shop:3000/rest/products/search?q=apple`:

```
run_waf_bypass       -> success=True  '0 WAF-bypass finding(s)'       error=None   <-- SILENT
run_sqli_structural  -> success=True  '0 structural SQLi finding(s)'  error=None   <-- SILENT
run_css_injection    -> success=True  '0 CSS injection finding(s)'    error=None   <-- SILENT
run_ssi              -> success=True  'DEGRADED: 1 load-bearing check(s) failed ...'
run_nosqli           -> success=True  'DEGRADED: 8 load-bearing check(s) failed ...'
```

**The Q-08x swallow ledger cannot close this.** It catches two of the five, because those two wrap
their requests in a `try/except` that reaches `_swallow`. The other three never raise: `_http`
catches the transport error itself and returns a dict, so the failure arrives **as data** and is
dropped by a default. There is no exception for a ledger to catch. The ledger is the right
mechanism aimed at the wrong half of the problem.

**SCALE, two populations, both stated with their denominator:**

| population | empty host | https to plaintext host | unreachable | of | rate |
|---|---|---|---|---|---|
| the 19 url-bearing tools of the Q-092 audit | 679 | 1008 | **1687** | 6622 | **25.5%** |
| corpus-wide, all tools | 1495 | 1746 | **3241** | 27222 | **11.9%** |

Host reachability was verified live before the classification was trusted:

```
juice-shop:3000        http-> 200 (9903B)   https-> ERR SSL: WRONG_VERSION_NUMBER
juice-shop-bench:3000  http-> 200 (9903B)   https-> ERR SSL: WRONG_VERSION_NUMBER
vampi:5000             http-> 200 (271B)    https-> ERR SSL: WRONG_VERSION_NUMBER
dvga:5013              http-> 200 (8136B)   https-> ERR SSL: WRONG_VERSION_NUMBER
dvwa:80                http-> 302 (0B)      https-> ERR SSL: WRONG_VERSION_NUMBER
owaspbench:8443        http-> 400 (62B)     https-> 404 (682B)      <- genuinely TLS
benchmarkpython:8443   http-> ERR ReadError https-> 302 (227B)      <- genuinely TLS
```

**These dispatches are NOT hiding in an error table.** `agent.py:840` logs a `ToolResult` with an
`error` as `tool_error`/`scope_block` and everything else as `tool_result`. There are 4
`tool_error` rows for all 22 audited tools. The 1687 unreachable dispatches sit in `tool_result`
wearing a clean-scan summary.

**THE CASE THAT MAKES IT CONCRETE -- `run_client_checks`.** A tool proven to work, whose single
zero histogram is two different phenomena:

```
corpus split of its 348 dispatches:
    DOOMED    275   https://vampi:5000 (167), https://juice-shop:3000 (96),
                    https://juice-shop-bench:3000 (12)
    REACHABLE  73   https://ginandjuice.shop (36), https://owaspbench:8443 (24),
                    http://vampi:5000 (13)

live A/B, same engine, same page, one reachable scheme and one that cannot open a socket:
    https://vampi:5000/       success=True  '0 client/config finding(s)'  error=None
    http://vampi:5000/        success=True  '0 client/config finding(s)'  error=None
    https://juice-shop:3000/  success=True  '0 client/config finding(s)'  error=None
    http://juice-shop:3000/   success=True  '0 client/config finding(s)'  error=None

the same engine on a target that DOES have the defect:
    run_client_checks {"url": "http://dvwa/index.php"} (authenticated)
      -> success=True  '1 client/config finding(s)'  n=1
         "Reverse tabnabbing - target=_blank link without rel=noopener"
         (DVWA /index.php carries 7 unprotected cross-origin target=_blank links)
```

The engine has three real states -- reachable+finding, reachable+clean, unreachable -- and the last
two produce byte-identical results. **79.0% of this tool's history is "never ran" being read as
"clean".**

**TWO ROOT CAUSES, TWO FIXES. They are independent and must not be conflated.**

**(A) `_http` does not carry the transport outcome to the ToolResult edge.** Fix at the chokepoint,
not in 21 engines. The carrier must be the thing callers already read (Q-089's lesson), so this
adds no out-parameter callers can ignore:

```diff
--- a/agent/tools.py
+++ b/agent/tools.py
@@ class ToolRegistry:
+    # I-2b, HTTP path. A transport failure returns `status == 0` with an `error` and an EMPTY
+    # body. Every engine reads `r.get("body", "") or ""`, so a dead connection and a clean page
+    # are the same value. Count the dead ones at the single choke point every engine already
+    # goes through, and let `execute` fail the ToolResult when a dispatch made NO successful
+    # request at all. Mirrors _cmd's exit-code fix: outcome fidelity on the return edge.
+    async def _http(self, url, method="GET", headers=None, body=None, capture=False, **kw):
+        res = await self.__http_inner(url, method, headers, body, capture, **kw)
+        if not res.get("status"):
+            self._http_dead = getattr(self, "_http_dead", 0) + 1
+            self._http_dead_last = {"url": url, "error": res.get("error")}
+        else:
+            self._http_live = getattr(self, "_http_live", 0) + 1
+        return res
@@ async def execute(self, tool_name, tool_input, session_id):
+        dead_before = getattr(self, "_http_dead", 0)
+        live_before = getattr(self, "_http_live", 0)
...
-        swallowed_count = getattr(self, "_swallowed_total", 0) - swallowed_before
+        swallowed_count = getattr(self, "_swallowed_total", 0) - swallowed_before
+        # A dispatch that made requests and had EVERY one fail did not scan anything. Reporting
+        # success=True with zero findings there is the false-clean this ticket exists to kill.
+        dead = getattr(self, "_http_dead", 0) - dead_before
+        live = getattr(self, "_http_live", 0) - live_before
+        if res is not None and dead and not live:
+            res.success = False
+            res.error = "NO REQUEST COMPLETED: %d request(s) failed; last=%s" % (
+                dead, (getattr(self, "_http_dead_last", {}) or {}).get("error"))
```

Note the `dead and not live` condition: a dispatch where SOME requests failed is degraded, not
dead, and the existing `DEGRADED:` line already covers it. Only "made requests, every one failed"
becomes `success=False`. A dispatch that made no requests at all is untouched.

**(B) The target builder emits URLs that cannot be requested.** This is a SEPARATE root cause with
a separate fix, and (A) only makes it visible -- it does not stop it happening.

Two distinct malformations, both MEASURED in `logs.etype='tool_call'`:

1. **Scheme mismatch -- 1746 corpus-wide.** `https://` is attached to lab hosts that serve only
   plaintext (`vampi:5000`, `juice-shop:3000`, `juice-shop-bench:3000`, `dvga:5013`, `dvwa`). The
   builder is upgrading or defaulting the scheme without regard to what the host answers on.
2. **Lost netloc -- 1495 corpus-wide.** URLs recorded literally as `https:///`,
   `https:///.well-known/ai-plugin.json`, `https:///.well-known/assetlinks.json`,
   `https:///.well-known/gpc.json`. A builder joined a path onto an origin that was the empty
   string, producing a URL with **no host at all**. httpx rejects these before any connection
   (`Request URL is missing an 'http://' or 'https://' protocol`). Worst hit:
   `run_form_cmdi` 318/568 and `run_upload_test` 318/566 -- **56% of both tools' entire history.**
   `run_oauth` 37, `run_llm_probe` 6.

   The empty-netloc case is the more dangerous of the two because it is unconditional: no target
   configuration can make `https:///` resolve, so those dispatches were never capable of doing
   anything, on any target, ever.

**GATE.** Three properties, each with the negative control that must fail before the fix:

1. A dispatch whose every request failed yields `success=False` with an `error`, not
   `success=True, "0 findings"`. Negative control: it must FAIL today -- measured above, today it
   is `success=True, error=None`.
2. A dispatch where some requests succeeded and some failed stays `success=True` and keeps its
   existing `DEGRADED:` line. This must PASS today and after, so the fix cannot be "fail
   everything".
3. No product code path constructs a URL with an empty netloc. Fact-checked against real builder
   output, not against a declaration -- this project has shipped guards that check declarations
   eleven times.

**RELATION TO Q-092.** Same invariant (I-2b, outcome fidelity on the return edge), different
transport. Q-092's `_cmd` fix does NOT touch this: `_http`'s failures never reach a subprocess.
Fixing one and calling the class closed would leave the larger half open.

### Q-092 · `_cmd` discards the exit code, so a failed external tool is byte-identical to a clean scan · **CLOSED** `5f50857` `196dfda` · **CRITICAL**

**CLOSED.** Verified in code by the Coordinator at HEAD: `CmdResult` is a 2-length tuple subclass
carrying `exit_code` on the return edge, and the single shared `_cmd_failure()` predicate is used at
**13** sites. Every wrapper now distinguishes "the tool failed" from "the tool ran and found nothing".

ORIGINAL TICKET FOLLOWS.

### Q-092 (as filed)

**Q-091 (dalfox) is not a one-off. It is one of at least 24.** This is the shared root cause, and it is
one line.

`tools.py:1594 _cmd` MEASURES the exit code and then throws it away at the return edge:

```python
_out_text, _exit = out.decode(errors="replace"), proc.returncode
return _out_text, err.decode(errors="replace")      # <- _exit is not returned
```

`_exit` is used only by the provenance record in the `finally` block. **No caller can check the exit
status, because `_cmd` never hands it back.** 14 wrappers check `err.startswith("__MISSING__")`, which
catches only a MISSING BINARY; 2 check a returncode anywhere in the file. A tool that runs and fails is
indistinguishable from a tool that runs and finds nothing.

**This is I-2b, in the external-tool path.** Outcome fidelity lives in a VALUE on the RETURN edge --
the exact invariant `FindingWriteId` (Q-089) and `FindingUpdateResult` (Q-090) were built to satisfy
for DB writes. `_cmd` has the identical defect and it is why 24 engines have never produced anything.

**TWO CONFIRMED LIVE, both against authorized targets:**

| tool | corpus | live reproduction | verdict |
|---|---|---|---|
| `run_dalfox` | **0 findings / 171 runs** | emits a JSON ARRAY (`[
{}]`), parser reads JSONL; every line invalid standalone | parser can never yield >0 (Q-091) |
| `run_nuclei` | **0 findings / 155 runs** | `nuclei -json` -> `EXIT=2`, stdout 37 bytes: `flag provided but not defined: -json` | **has never run at all in this build** |

nuclei v3 renamed `-json` to `-jsonl`. nuclei exits 2 before scanning, writes the error to STDOUT (so
`err` is empty and the `__MISSING__` check passes), and `json.loads("flag provided but not defined:
-json")` raises into a bare `except Exception: pass`. 155 invocations, every one reported as a clean
scan. **nuclei is Apolaki's primary breadth scanner.**

**EVERY external-binary wrapper in `agent.py:143 _CONFIRMED_BY_TOOL` is in the zero list:**
`run_nuclei` 0/155, `run_dalfox` 0/171, `check_takeover` 0/140, `run_sqlmap` 0/58. The tools Apolaki
trusts MOST as confirmatory have collectively never confirmed anything.

**CORPUS CENSUS -- 24 tools with >=10 runs and a zero histogram with no outlier** (runs in parens):
`run_ssi`(940) `run_waf_bypass`(592) `run_sqli_structural`(592) `run_css_injection`(592)
`run_form_nosqli`(464) `run_oauth`(416) `run_client_checks`(348) `run_nosqli`(342)
`run_deserialization`(335) `run_github_recon`(316) `run_form_cmdi`(238) `run_upload_test`(236)
`run_dalfox`(171) `run_nuclei`(155) `check_takeover`(140) `run_session_token`(82) `run_exposure`(59)
`run_sqlmap`(58) `run_path_sqli`(58) `run_cache_poison`(57) `run_llm_probe`(46)
`run_cache_deception`(24) `run_ssrf`(23) `run_username_enum`(15).

**A zero histogram is a SIGNATURE, not a verdict.** Some of these are legitimately zero: a target with
no LLM yields nothing from `run_llm_probe`, and that is correct behaviour. The census says only that
these 24 share dalfox's signature, and dalfox and nuclei both turned out structurally broken when
reproduced. **Each needs the same treatment: run it live, capture the RAW tool output, and compare it
against what the parser yields.** Do not mark any of them broken or healthy from the histogram alone.

**CORRECTION TO THIS TICKET, from the live audit (`d40374e`, `ddb4d78`). I filed the framing above
and it was wrong in a way that would have sent readers hunting in the wrong place.**

**21 of the 22 remaining zero-histogram wrappers never shell out at all.** They are pure Python, so
`_cmd`'s discarded exit code cannot be their cause. `_cmd` explains dalfox, nuclei and sqlmap. It does
not explain the rest, and looking for subprocess bugs in a tool that never spawns a subprocess is
wasted effort. The census signature was right; my attribution of its cause was not.

**The actual dominant cause is `_http`, which has the identical defect for HTTP.** It reaches all 21
pure-Python engines rather than the 14 that shell out. `_http` does the honest thing and RETURNS
`status` and `error`; the callers do not read them. Same shape as `_cmd`, same shape as Q-089/Q-090:
**the outcome is measured correctly and dropped at the return edge.**

MEASURED by the audit lane over its 19 tools: 1008 doomed + 679 empty-host = **1687 of 6622 dispatches
(25.5%)** could not have reached their target, every one reported as a completed scan. INDEPENDENTLY
RE-MEASURED by me over ALL tools: 27222 url/target dispatches, 1495 with an empty `https` host, 1746
`https` to a plaintext-only lab host, **3241 unreachable (11.9%)**. Different denominators, not a
conflict: the lane's rate is higher because it scoped to the zero-histogram tools, and the corpus-wide
absolute count is nearly double. Quote whichever, but always with its denominator.

Transport reality, reproduced by me on `apolaki_default`:

```
http://juice-shop:3000/rest/products/search?q=a   -> 200 (16578B)
https://juice-shop:3000/rest/products/search?q=a  -> ERR ConnectError
https:///.well-known/ai-plugin.json               -> ERR UnsupportedProtocol
```

**TWO DISTINCT ROOT CAUSES, needing separate fixes** (do not conflate them):
1. **Scheme mismatch** - `https://` fired at a plaintext-only host. 1746 dispatches.
2. **A URL builder that lost its netloc** - targets recorded literally as `https:///`,
   `https:///.well-known/ai-plugin.json`, `https:///.well-known/gpc.json`. 1495 dispatches.

**`run_client_checks` is the case that proves the two phenomena are distinct**, and it is the one to
lead with: the tool demonstrably WORKS and produced a live true positive on DVWA (`e003f55`), yet 275
of its 348 corpus runs were fired at `https://` URLs for plaintext hosts. **Its zero histogram is not
one phenomenon, it is two** - 73 honest true negatives and 275 requests that never opened a socket.

Confirmed CORRECTLY QUIET so far, which shrinks the real blast radius: `run_ssi`, `run_waf_bypass`,
`run_sqli_structural` (`3f24850`). Confirmed BROKEN: `run_sqlmap` exits 2 reported clean, and all 58
corpus runs used valueless params that miss a SQLi the same command confirms with a value (`8377afd`).

**`_http` gets its own ticket (Q-093), being drafted by the audit lane.** Fixing `_http`'s honesty is
what makes the remaining engines' real behaviour VISIBLE; it does not by itself fix any engine.

**FIX, at the chokepoint (do this first, it is what makes the other 22 findable):**
1. `_cmd` returns the exit status as a value on the return edge. Do not add a second out-parameter that
   callers can ignore -- Q-089's lesson is that the carrier must be the thing they already read.
2. A non-zero exit with unparseable output becomes `ToolResult(..., ran=False, error=...)`, never
   `ran=True, "0 findings"`.
3. Every bare `except Exception: pass` around a tool-output parse records a `_swallow`.

**GATE:** an engine-liveness test asserting that a tool which exits non-zero produces `ran=False`. The
negative control is the one that matters: it must FAIL against today's `_cmd`, which cannot express the
distinction at all.

### Q-091 · dalfox has NEVER produced a finding: a JSONL parser reading JSON-array output · **CLOSED** `f9a8815` · **HIGH**

**CLOSED.** `_dalfox_rows(out)` returns `(rows, parse_error)`. A parse failure is RETURNED, never
swallowed, and `_run_dalfox` answers `"dalfox output could not be parsed (N bytes) - this is NOT a
clean result"` instead of `0 XSS signals`. The empty-dict filter is present: `{}` is dalfox's
"nothing found" placeholder, so admitting it would have converted 171 silent zeros into 171 empty-dict
FALSE POSITIVES. JSONL is still accepted, because a parser that understands only the one shape we
happened to measure is this same defect rebuilt.

ORIGINAL TICKET FOLLOWS.

### Q-091 (as filed)

**This closes Q-053 GAP-2, which was unfalsifiable as posed.** "Why are there zero dalfox findings in
1783?" cannot be answered from the corpus. The answerable form is Q-050-shaped: does the producer
produce? It does not, and it never has.

**MEASURED, live, on an authorized lab and an authorized host.** `dalfox --format json` emits a JSON
ARRAY, not JSONL:

```
$ dalfox url http://juice-shop:3000/rest/products/search?q=test --silence --format json
[
{}]                      <- 6 bytes, 2 lines, exit 0, stderr empty
```

`tools.py:_run_dalfox` parses it line by line:

```python
for line in out.strip().split("
"):
    try: findings.append(json.loads(line))
    except Exception: pass
return ToolResult("dalfox", url, True, f"{len(findings)} XSS signals", findings)
```

`json.loads("[")` raises. `json.loads("{}]")` raises. Both are swallowed. **This is structural, not
data-dependent:** with real results the lines become `[`, `{...},`, `{...}]`, and the array wrapper plus
the trailing commas guarantee that EVERY line is invalid JSON on its own. `len(findings)` is pinned at
0 for every possible dalfox output. Fed the real bytes above, the exact parser yields **0** while the
array holds **1** entry.

**CORPUS CONFIRMATION, 171 invocations, no outlier:** `logs` holds 171 `tool_call` + 171 `tool_result`
rows for `run_dalfox`. The `N XSS signals` histogram is `{0: 171}`. Zero rows say "dalfox not
installed" (the binary is at `/usr/local/bin/dalfox`). If the parser had ever worked, one run against
Juice Shop, DVWA or ginandjuice would have been nonzero. **findings mentioning dalfox: 0 of 1783.**

**Why nobody noticed: this is an I-5 silent swallow.** `ran=True` and `"0 XSS signals"` are exactly what
a clean scan looks like. A totally broken integration and a target with no XSS are byte-identical in
the log, the report and the ledger. `agent.py:143` compounds it by listing `run_dalfox` in
`_CONFIRMED_BY_TOOL`, so its output is trusted as CONFIRMED while carrying nothing.

`asvs_model.py:193` (Q-048) reported the downstream half of this -- raw dalfox lines carry no `family`
key so nothing they report can fail an objective. That was true but moot: there were never any lines.

**PATCH** (owner: whoever holds `tools.py`; do not apply concurrently with the I-5 lane):
parse the document, not the lines, and make the failure VISIBLE rather than returning a clean-looking
zero. Accept both shapes, since older dalfox builds do emit JSONL:

```python
findings = []
body = out.strip()
if body:
    try:
        doc = json.loads(body)
        findings = [f for f in doc if isinstance(f, dict) and f] if isinstance(doc, list) else [doc]
    except Exception:
        for line in body.split("
"):          # legacy JSONL builds
            try: findings.append(json.loads(line))
            except Exception: pass
        if not findings:
            _swallow("dalfox.parse", ...)       # a parse failure is NOT a clean scan
            return ToolResult("dalfox", url, False, "dalfox output unparseable", [])
```

Note the empty-dict filter: the measured array was `[{}]`, and `{}` is not a finding. Without the
filter the fix would turn 171 silent zeros into 171 empty-dict false positives.

**GATE (required, or this regresses invisibly):** a test that feeds `_run_dalfox`'s parser the REAL
bytes `b"[
{}]"` and asserts 0 findings, plus a real multi-entry array asserting n>0. Both must fail
against the current parser. A test asserting only "0 findings on empty output" passes today and proves
nothing.

### Q-090 · Four multi-outcome write paths that report success they did not achieve · **CLOSED** `9c8f3a9` `977c4b2` `ef0db16` · **HIGH**

Found by the **I-2b outcome-fidelity guard** (`tests/test_outcome_fidelity.py`, `aa01373`), which
derives multi-outcome owners rather than listing them. **I-2 measured "0 unowned" CORRECTLY and could
never have seen any of these**: I-2 counts EDGES; these defects live in a VALUE on the return edge.

**The denominators, because the guard is only worth its cost if it found more than the one we knew
about**: 178 modules · 2469 functions · 88 transitive writers · **14 multi-outcome owners · 11
truthiness-ambiguous · 8 violating call sites**. `db.add_finding` (Q-089) was NOT the only one --
`db.update_finding` carries the same defect one function over: its reroute branch DELETEs the row,
appends to leads, and returns `True`, indistinguishable from a real UPDATE; a scope refusal returns
`False`, indistinguishable from "no such finding".

**Q-090-A · CLOSED `9c8f3a9` · it was LIVE DATA LOSS.** `POST /leads/{sid}/{lid}/confirm` on an
off-scope lead: `add_finding` refuses, writes no row, returns a falsy id -- and the lead was removed
from the mission context anyway. MEASURED end to end: **0 findings rows, 0 leads**, HTTP 200
`{"promoted": true, "machine_proof": true, "finding_id": ""}`. The lead and the operator's
attestation both destroyed, reported as success, on the endpoint Q-014 built specifically so an
operator's decision is never silently discarded. Now gated on `fid.stored`; a refusal keeps the lead
and answers 409 naming the verdict.

**Q-090-B · CLOSED** `977c4b2`. `PUT /findings/{sid}/{fid}` ANSWERED `404 "finding not found in this mission"`
**with the row present in the table** -- `update_finding`'s scope refusal was `False`, and the handler
read that as absence. Now: 409 on a refusal, 404 only on a genuine miss, and a REROUTE returns
`{"ok": true, "updated": false, ...}` naming where the row went.

**Q-090-C · CLOSED** `977c4b2`. `POST /findings/{sid}/{fid}/poc` DISCARDED the write return entirely and answered
`{"ok": true, "bytes": 4, "attached_to": "f1"}` **with nothing attached**. Now reads `.updated` --
NOT `bool(res)`, because a REROUTED write is truthy and leaves no row for a screenshot to attach to.

**Q-090-D · CLOSED** `ef0db16`. It was the last MEASURED-STATIC pin, and a pin nobody has executed is a claim, so it was reproduced through the real generator and the real db before being closed. Annotating a row that predates the Q-013 gate makes TRUTH (#7) fire on the way back in: the row is DELETED from findings, appended to leads, and the emitted event still says "Triage complete: 2 findings" while the table holds ONE. Nothing in the stream said a row left. `agent.py:4322` now binds the result and reads `written.verdict`, never `bool(...)`. VERIFIED BY COORDINATOR at `66a7012`: `_KNOWN_OPEN` in tests/test_outcome_fidelity.py is now EMPTY, and that ratchet is red in BOTH directions, so a stale pin cannot hide in it. ORIGINAL NOTE FOLLOWS.

**Was: MEASURED-STATIC, deliberately NOT reproduced.** `agent.py:BBHAgent._triage` writes back
blind. Recorded as static-only rather than claimed as a live defect.

**Reachability was checked, not assumed** -- the mark of the lane that filed it. `is_lead` reads only
`confidence` and no caller can set it, so the REROUTE verdict is unreachable from all three endpoints
today; the reproduced defect in each case is the SCOPE refusal. Both patch options for the reroute
path are in `docs/handoff/outcome_fidelity.md` §4.

**B and C are one fix**: teach the two handlers to distinguish `update_finding`'s outcomes, the way
`confirm_lead` now distinguishes `add_finding`'s. **Do not fix them as two independent handlers** --
that is the symptom-grouping failure this queue keeps recording.

### Q-089 · `db.add_finding` returns truthy from `add_lead` · **CLOSED** `7b82202` `1c357c8` · verified by Coordinator mutation

**MEASURED 2026-08-18 against the running agent**, and it is a PERSISTENCE-OWNERSHIP defect rather
than a reporting one -- which is why invariant I-2 measured 0 unowned and still missed it. The
ownership is not absent; it is **ambiguous at the boundary**.

`db.add_finding` returns a TRUTHY id from `add_lead` when the TRUTH invariant reroutes a
lead-confidence finding into the mission's leads list. `_run_source_review` counts
`sum(1 for f in findings if db.add_finding(...))`. So a canonical source finding carrying
`confidence='lead'` yields:

    status=complete   stored_findings=1   rejected_findings=0
    findings table:   0 rows
    leads list:       1

**The `/engage` response and the mission context both tell the operator a finding was stored.** The
reroute is correct behaviour; the RETURN VALUE makes it indistinguishable from a store, and the
counter believes it.

**Definition of done**: the caller can tell a store from a reroute -- either a distinguishable return
or a separate count. `stored_findings` must equal rows in the findings table, asserted end to end
against a real mission, with a negative control proving a genuine store still counts. The marker in
`tests/test_source_lane_persistence.py` XPASSes and is retired in that commit.

### Q-086 · A guard named "remain inside" proves PRESENCE, never ABSENCE elsewhere · **CLOSED** `e9e253a`

**Fixed by the Codex lane that found it.** `test_zap_target_drivers_remain_inside_one_guarded_function()` is now `test_zap_target_drivers_are_absent_outside_the_guarded_run_zap_subtree()` and does a repository-wide AST absence check instead of slicing one function body. **The name now states what the assertion proves**, which was the whole ticket.

**Coordinator's independent negative control, because production was already clean on that call shape and a passing guard proves nothing on a clean tree.** I planted a duplicate ungated driver in `api_inventory.py` -- a module the old guard could never see:

    def _coordinator_zap_plant(zap, target):
        zap.ascan(target)
        return zap.spider(target)

    FAILED test_zap_invocation.py::test_zap_target_drivers_are_absent_outside_the_guarded_run_zap_subtree

Caught. The same lane also took the third audit item: `test_engine_reachability.py` proved *possible invocability* while its name claimed deterministic scheduling, and it now says what it proves.

**Two of four one-file guards are now honest, one was already aligned** (`test_session_identity.py`, whose narrow scope genuinely matches its mechanism). That closes the audit Q-085's third DoD item asked for.

### Q-085 · A guard that parses ONE file made that file's boundary the boundary of compliance · **CLOSED** `8a59a96` `e9e253a` `388fa8b` · 25/13 -> **0/0**

#### Closed 2026-08-20. Every target transport in the tree goes through the shared rate policy.

    ungated target-call sites   25 -> 21 -> 8 -> 0
    modules bypassing           13 -> 12 -> 8 -> 0

The strict xfail `test_every_target_transport_uses_the_shared_rate_policy` is **retired**, in the
commit where it XPASSed.

**A retirement is the claim that needs the most checking, not the least**, because a strict xfail
that XPASSes because the DEFECT WAS FIXED and one that XPASSes because the MEASUREMENT DRIFTED are
indistinguishable in a green suite. Coordinator mutation, verified as landed before the result was
believed: an ungated `httpx.Client` planted in an existing production module fails **two** tests --
the ratchet, and the retired-xfail test now running live:

    FAILED test_repository_wide_rate_policy_inventory_is_non_vacuous_and_ratcheted
    FAILED test_every_target_transport_uses_the_shared_rate_policy

So the retirement is a fixed defect. The final eight were gated in the files that had been outside
every earlier lease: `agent.py`, `auth.py`, `authz.py`, `bwapp_solvers.py`, `codeintel.py`,
`mutillidae_solvers.py`, `register.py`, `replay.py`.

**The whole arc, because the shape is the lesson.** This began as Q-043 -- "Apolaki does not honour
`Retry-After`" -- and the interesting part was never the missing feature. It was that **both AST
guards parsed `tools.__file__` and nothing else**, so `tools.py` was 100% compliant and every other
module drifted freely. The guard's scope had become the boundary of compliance. Widening the guard
turned one clean file into 25 real violations across 13 modules, none of which were new.

**Also closed by the same arc**: the live no-DoS breach (ten concurrent `threading.Thread` workers
posting to `/rest/products/reviews` ungated), Q-086 (a guard proving presence and calling it
absence), and the bare-429 half of Q-043 -- honoured now, with the ledger recording whether a
cooldown was `header`-supplied or `inferred`.

#### Landed 2026-08-20 by an external Codex lane, on its own branch, merged after ownership verification

**The live no-DoS breach is CLOSED, and structurally rather than site-by-site.** `juiceshop_solvers.py` no longer builds a raw `httpx.Client`: both constructions now go through `browser_engine.rate_limited_sync_client`, and the raw `urllib.request.urlopen` calls are gone. So all four previously-ungated paths are gated, **including the ten concurrent `threading.Thread` workers** posting to `/rest/products/reviews` that the ticket was filed on.

**The guard now walks the repository** instead of parsing `tools.__file__` alone. Remaining gap, **pinned by a STRICT xfail rather than allowlisted away**:

    ungated target-call sites  25 -> 21
    modules bypassing          13 -> 12

with a ratchet asserting `<= 21` and `<= 12`, and a deliberate note that the raw count is **not** a floor, so removing a bypass is allowed to reduce it.

**Coordinator's independent mutation, harder than the lane's own.** The lane's non-vacuity control plants an ungated call in a brand-new nested package. I planted one in an EXISTING production module instead, which is the realistic drift case, and the guard caught it by name:

    assert 22 <= 21
    'api_inventory.py:115:_coordinator_drift_probe:httpx.Client'

#### Second Codex lane, `e9e253a`: ratchet driven 21/12 -> **8/8**

Thirteen sites gated, via new wrappers in `browser_engine.py` (`rate_limited_urlopen`,
`_guard_playwright_page_sync`, `rate_limited_goto_sync`) rather than site-by-site patches. **The
delta accounts exactly**: `bie.py` 6 `page.goto`, `main.py` 3, `bench_all.py` 2, `owasp_bench.py` 2
= 13, and 21 - 13 = 8.

**Coordinator's independent re-measurement, not the lane's report.** Same mutation as last cycle --
an ungated call planted in an EXISTING production module, which is the realistic drift case rather
than the lane's own brand-new-nested-package control:

    assert len(bypasses) <= 8
    'api_inventory.py:115:_coordinator_drift_probe:httpx.Client'

Caught, at the tightened level. **The strict xfail is still open and was not weakened.**

**THE REMAINING EIGHT, ALL IN FILES THAT WERE OUTSIDE THE LEASE, one per module:**

    agent.py:2883:_probe_for_creds        httpx.AsyncClient
    auth.py:167:login                     httpx.AsyncClient
    authz.py:165:run_matrix               httpx.Client
    bwapp_solvers.py:38:prove             httpx.Client
    codeintel.py:150:harvest              httpx.Client
    mutillidae_solvers.py:41:prove        httpx.Client
    register.py:196:register              httpx.AsyncClient
    replay.py:28:client                   httpx.AsyncClient

Two are lab solvers of exactly the `juiceshop_solvers.py` shape already fixed, and the fix there was
structural (route the client construction through `rate_limited_sync_client`) rather than per-call,
so `bwapp_solvers` and `mutillidae_solvers` should follow the same pattern. `auth.py`, `register.py`
and `authz.py` send credentialed traffic at the target and are the ones a rate-limited host is most
likely to punish. **Each needs an owner; none is blocked on anything.**

**The bare-429 default stays at `0.0`, and the lane was right to stop.** My ruling was that the "an invented cooldown is indistinguishable from one the target asked for" objection is solvable by recording the wait's SOURCE. It is -- inside `TargetRatePolicy.observe()` -- but the durable typed row is built by `tools.py::_ledger_outcome()` against a closed schema `{tool, seconds, waits, truncated, origins}`, and `tools.py` was off-limits to that lane. Adding provenance to the prose notes alone **would produce two ledgers with different epistemics**, which is precisely the Q-084 defect. Encoding the source into `origins` or `truncated` corrupts an existing field rather than adding one. The exact atomic patch is documented in `docs/handoff/codex_q085.md`; **it must land as one change across `browser_engine.py` and `tools.py`, with `test_backoff_bounds.py::test_a_response_without_retry_after_is_never_recorded_as_a_wait` updated deliberately** to assert the new behaviour including that a NON-429 still records no wait. Never deleted.

**MEASURED by the rate-policy lane, 2026-08-20** (`20883a5`, `58f2e81`), by AST census rather than
grep, because a grep for `httpx` counts imports and comments.

    modules sending TARGET traffic THROUGH the policy : 3    tools.py, browser_engine.py, proxy.py
    modules sending TARGET traffic AROUND the policy  : 13
    gated call sites: 207          ungated TARGET call sites: 25

**Both framings are recorded because either alone misleads.** 207 vs 25 flatters the policy (200 of
those sites sit inside one very large module); 3 vs 13 flatters the problem (`tools.py` is where most
engines live). The honest summary: the policy covers the main engine room completely and almost
nothing outside it, with `bie.py` the sharpest case at 6 ungated target navigations.

**The structural cause, which is the actual ticket.** This is not 13 independent oversights. **Both
AST guards parse `tools.__file__` and nothing else**, so `tools.py` is 100% clean and every other
module drifted freely. **The guard's scope became the boundary of compliance.** That is the house
failure mode wearing a new costume: the recorded lesson was that *a guard checking a declaration
passes what it exists to catch*; this is its sibling, **a guard with too narrow a scope passes
everything it cannot see**.

**The sharpest live instance**: `juiceshop_solvers.py:304` fires **ten concurrent
`threading.Thread` workers** posting to `/rest/products/reviews` with **no gate**. That is precisely
the shape Q-043 was filed about, still live, in a module nobody had flagged. A sibling handoff
(`docs/handoff/backoff.md`) lists `juiceshop_solvers.py` as "correctly covered"; it is MIXED, one
`browser_engine.drive` path gated and four direct paths not. **A module can be partially gated, and a
grep that finds the one correct call reports the whole module clean.** That does not make
`backoff.md` wrong -- it made a bounded claim with its method stated, which is the only reason the
discrepancy was findable at all.

**Why the lane did not just widen the guard, and it was right not to**: widening lands RED on 25 call
sites across 13 modules, 11 of them owned by other lanes. Landing a red guard in a shared tree is not
one lane's call.

**Definition of done.**
- Widen the guard's scope to every module that can send target traffic, **and land the resulting red
  deliberately** -- as a strict xfail carrying the measurement if the sites cannot all be fixed at
  once, never by narrowing the guard back.
- **Fix `juiceshop_solvers.py:304` first and separately.** Ten ungated concurrent workers against a
  target is a live no-DoS breach, not a coverage statistic.
- **Then audit the OTHER guards for the same shape.** This ticket is only worth its cost if the
  question "what files does this guard actually parse?" gets asked of every guard in the tree. A
  guard that parses one file and is described as protecting the codebase is a false assurance, and
  false assurance is worse than no guard.
- Negative control, mandatory: after widening, a newly-added ungated target call in a module that was
  previously invisible must FAIL the guard. Prove it by adding one and watching it go red.

### Q-084 · The report tells the client "WSTG active tests: 85/109" and that number is a CONSTANT · **CRITICAL** · **CLOSED** `b2492cc`
Fixed on the main thread. The line now reads "WSTG catalogue: Apolaki has engines for 85/109 active
tests ... This describes this tool, not this mission - unlike the figures above it does not vary with
what ran." The dead `techniques` parameter is removed from `wstg_catalog.coverage()`. Tests written
first: 3 failed before, 7 pass after, including one control that FAILS if someone "fixes" this by
deleting the line and one that FAILS if the catalogue totals move. Full suite on an isolated snapshot:
3273 passed / 11 skipped / 12 xfailed / 0 failed.

**The fix is the sentence, not the number, and that was measured rather than preferred**: `FULL` and
`PARTIAL` map ids to PROSE, so an evidence-driven WSTG tally is not derivable from this module until
the maps carry machine-readable engine references. That is a bigger ticket; until then the report must
not imply a number it cannot compute.

**MEASURED 2026-08-20.** `report.py:2501` renders this into the client HTML, under a heading called
Coverage Overview:

    WSTG active tests: 85/109 covered (60 full, 25 partial), 5 safety-excluded.

"Active tests" asserts activity. The number is a property of a static catalogue and has nothing to do
with the mission. It is 85 for a full-mode scan of Juice Shop, 85 for a passive scan of one static
page, and 85 for a mission in which **zero engines ran**:

    coverage()          tally: {'full': 60, 'partial': 25, 'none': 24, 'excluded': 5}
    coverage([])        tally: {'full': 60, 'partial': 25, 'none': 24, 'excluded': 5}
    coverage(['xss'])   tally: {'full': 60, 'partial': 25, 'none': 24, 'excluded': 5}

    empty mission, zero engines run -> {"tested": 85, "full": 60, "partial": 25,
                                        "not_tested": 24, "excluded": 5, "total": 109}

**Two defects stacked, and the second is why fixing the first is not enough.**

1. `report.py:343` calls `wstg_catalog.coverage()` **with no argument**, so no evidence reaches it.
2. `wstg_catalog.coverage(techniques=None)` **accepts an evidence parameter and ignores it** -- the
   three rows above are the proof: an empty technique list returns the same 60/25 as no list at all.
   So passing the ledger would change nothing. A parameter that does not affect the output is the
   island pattern inside a single function signature.

**The ASVS half, six lines away in the same function, is CORRECT**, which is what makes this a defect
rather than a design choice. `report.py:319` calls
`asvs_model.assess(findings, attempted_engines=_engines_from_ledger(tool_ledger))` -- evidence-driven,
so an engine that never ran yields not-tested rather than a coverage claim. The rendered block puts
the truthful ASVS cells and the constant WSTG line in the same visual group, and a reader cannot tell
that they come from different epistemics. **This is `verify BOTH halves of a fix` again**, and it is
the same family as Q-082 (716 fabricated curl reproductions) and Q-071: the report asserting work
that was never done.

**In mitigation, and it is real but not sufficient:** the function's docstring says "Truth-first: this
is a CURATED-PARTIAL model, never a full-coverage claim", `out["model"]` is `"curated_partial"`, and
the surrounding prose repeats "Never a full-coverage claim". The author knew the model was partial.
That disclaims BREADTH -- "we only model some of WSTG" -- and it does not disclaim ACTIVITY. The
sentence a client reads still says 85 tests were active. A disclaimer about the denominator does not
make the numerator true.

**Definition of done.**
- The rendered line states what it can support. Either it reports what the mission ACTUALLY exercised
  (evidence-driven, which needs defect 2 fixed first), or it stops using the word "tests" for a
  catalogue property and says so plainly -- "Apolaki models 85 of 109 WSTG tests" is true and useful.
- **A negative control: a report rendered from an EMPTY ledger must not claim 85 of anything as
  tested.** Absence of that control is how this survived.
- If `coverage(techniques=...)` is meant to filter, make it filter and pin it with a test where two
  different technique lists give two different tallies. If it is not meant to, delete the parameter
  rather than leave a signature that implies an evidence path.
- Check the sibling numbers in the same block while you are there. `_pp.get('total')` ASVS objectives
  is rendered next to it and is a different mechanism; say which of the two rules it follows.

**Owner: unassigned.** Do not fix this by deleting the line -- the coverage view is genuinely useful
and a competitor-inspired feature. Fix what it claims.

### Q-083 · The code-assisted lane confirms a MEDIUM inside a vendored minified bundle · **HIGH** · `ready`

Same mission. A **confirmed medium** against a minified third-party library the operator does not
maintain, reported at "line 2" because the whole bundle is line 2.

**Measured**: the finding exists, the target is a vendored minified bundle, and the lane has no filter
that would exclude it. `codeintel._SKIP_DIRS` (`codeintel.py:72`) excludes DIRECTORIES named
`node_modules` / `vendor` / `dist` / `build`; `webapp/js/` is none of those, and there is **no
`*.min.js` rule and no vendor-file heuristic anywhere in the walk**.

**Deliberately NOT claimed** - and the lane was right to stop here: whether this particular
`Math.random()` feeds a security-relevant value is UNKNOWN. Proving it a false positive means binding
the value's use, which is the Q-042 discipline, and that work was not done. So this is filed as
"reports a finding it cannot justify at that confidence in code the client does not own", not as
"false positive".

DoD: either a vendor/minified heuristic in the walk, or a confidence demotion for third-party code, or
a measured argument that neither is right. **Negative control:** first-party code containing the same
call must still be reported - the fix must not silence the analyser on the code that matters.

### Q-081 · `effects_audit` verifies the ENGINE three ways and never checks the KEY · **HIGH** · **CLOSED** `b604709`

Found by the Q-074 lane writing its negative control FIRST, per its brief. The control found a hole in
the guard it was written to exercise, which is the whole argument for writing it first.

MEASURED on the live platform:

```
EFFECTS["csrf_token_missing"] = {"invalidates": ["authenticated"], "engine": ["run_csrf"]}
effects_audit ok    : True     <- run_csrf is real, registered, implemented, dispatchable
build() descriptors : 88, and 'csrf_token_missing' is NOT among them
conflicts() rows    : 6, producers ['race_condition']   <- unchanged
```

`effects_audit` checks the declared ENGINE three independent ways and never checks that the KEY is a
technique. `build()` walks `TECHNIQUES`, so a row keyed on a non-technique **never becomes a
descriptor and no consumer ever sees it**. The declaration is silently inert AND passes its audit.

**That is the Q-007 shape in different clothes**: a guard that confirms the part it was taught to look
at while the part that decides reachability goes unexamined. Eleventh instance of declaration-versus-
fact in this codebase, and the first one found by a negative control rather than by a failure.

DoD: `effects_audit` validates the KEY against `TECHNIQUES` as well as the engine, so an entry that
can never reach a consumer fails the audit instead of passing it. **Negative control:** an entry keyed
on a real technique with a real engine must still pass - a guard that rejects everything is not a fix.

### Q-080 · The DEFAULT scan mode destroys its own session by READING a page, and reports clean · **CRITICAL** · **CLOSED** `928319b`

MEASURED on the running `sessionlife` lab with shipped engines on an isolated HEAD snapshot. Driven,
not read - which matters, because reading is what produced the wrong answer twice on this ticket
already (Q-074 named `session_lifecycle`, which does nothing of the kind).

**`_run_csrf` needs no payload and no POST.** `_http(url, "GET")` merges `session_headers` through
`_merge_identity`, so the engine **destroys the mission session by reading the page it was asked to
audit** - a logout action. It then returns `success=True, "0 CSRF signal(s)"`.

**The door is four engines wide, not one.** Driven with the exact `recon["forms"]` dict `_http_probe`
produced, the shipped planner emits **4 steps against the quarantined URL at `mode=full`** -
`run_csrf`, `run_race`, `run_form_cmdi`, `run_stored_xss` - and **1 at `mode=active`**. Emptying
`recon["forms"]` and changing nothing else drops all four while **47 other steps remain**, which is
the positive control that the rest of planning is untouched.

**All four kill it, 4/4**, each on its own freshly minted session. The paired `/vuln` mount
(`logout_invalidates=False`, one variable changed) leaves **all four alive, 4/4**. That pairing is
what makes this a cause rather than a correlation.

**`run_csrf` is ACTIVE, so this is reachable in the DEFAULT scan mode** - it does not need `full` and
it does not need `auto_approve`.

**Why this is CRITICAL rather than untidy.** Nothing in the platform's own state records the loss:
`session_headers` still holds the dead cookie, so every authenticated probe afterwards silently tests
as ANONYMOUS while the mission keeps running and keeps reporting. A target that is only vulnerable
behind authentication comes back clean. It is a self-inflicted false-negative source that is
indistinguishable, in the report, from a secure application.

**And the filter is not simply absent - it SAW the URL.** `_http_probe`'s own path applies
`_SESSION_KILL_RE`, and `recon["forms"]` is a second, unfiltered door into the same probe surface.
One entrance is guarded and the other is not, which is why the quarantine looks like it works.

DoD: the guard belongs at the DOOR, not on one engine. Every path that turns discovered surface into
planner steps must apply the same session-kill quarantine, and the fix must be proven with the same
4/4-versus-4/4 pairing rather than by a unit test. **Negative control, mandatory:** a form that is NOT
a session-killer must still be probed by all four engines, or the fix trades a false negative for a
capability loss.

### Q-079 · The DISPATCHER enforces no permission tier at all · **HIGH** · **CLOSED** `9dba899` · split out of Q-052

**This was the engineering half of Q-052 and it should never have been bundled with the product
question.** Q-052 asks what `active` should MEAN to an operator, which is a consent decision. This
asks where the answer is ENFORCED, which is a defect with a right answer.

MEASURED:

```
planner._ALLOWED        filters what gets SCHEDULED  (passive={PASSIVE}, active={PASSIVE,ACTIVE})
agent.py:572 / :674     blocks only when mode == "passive", plus a separate INTRUSIVE HITL gate
tools.Tools.execute()   NO permission check of any kind
```

`ToolRegistry.__init__(scope, mission_id, lab_mode, ...)` **does not receive the mission mode**, so the
dispatcher structurally cannot enforce a tier. That is a missing parameter rather than an oversight,
and it is why the check lives one level up.

**LATENT, NOT LIVE - and say so rather than dramatising it.** Q-061 established that 10 of 12
`self.tools.execute(` sites bypass `_run_tool`. All five distinct engines reaching that path are
ACTIVE: `acquire_session`, `browser_navigate`, `http_probe`, `http_read`, `run_dom_audit`. **Nothing
INTRUSIVE escapes today.** The hole is one new call site away, which is worth a guard and is not worth
a panic.

**The design tension, stated because it decides the whole ticket.** There are 4 product construction
sites and **87 test ones**. A REQUIRED `mode` parameter breaks 87 tests. A DEFAULTED one leaves the
guard opt-in, and a guard most callers skip is the declaration-not-fact pattern this project has hit
nine times - the exact thing the guard exists to prevent.

DoD, two-sided and neither half optional:
1. An INTRUSIVE engine dispatched through `Tools.execute()` in `active` mode is REFUSED, with a reason.
2. **Every currently-working dispatch still works.** A guard that fails closed on an unknown mode and
   thereby blocks the 5 ACTIVE engines above is strictly worse than the hole - it converts a latent
   permission gap into a live capability loss.
Prove both. The negative control is the second one and it is the one that will be skipped.

## Q-052 · What `active` means · **CLOSED** `e6a9561` `280ce13` `29d00d2` · it was a taxonomy defect, not a preference
`INTRUSIVE` had grouped two unlike things: engines that CHANGE STATE and engines that merely SEND A
PAYLOAD and read the answer. Sending a payload is how you determine whether an application is
susceptible; it is not a state change. 25 engines moved INTRUSIVE -> ACTIVE, 15 remain INTRUSIVE.
Measured: engines selectable at `active` 71 -> 96 of 111, tier-blocked 31 -> 13, class sum unchanged
at 111, and **zero state-changing engines leaked** into ACTIVE. Slice 2 settled the classification by
COUNTING WRITES rather than reading descriptions, which caught six of my own misclassifications
(`http_request`, `run_mass_assign`, `test_numeric_abuse`, `run_bfla`, `run_form_cmdi`,
`run_web_probes` all write). Enforcement was split out as Q-079 because re-tiering a table does
nothing if the dispatcher never consults it; Q-079 is closed separately. Pinned by
`agent/tests/test_permission_tiers.py` and `agent/tests/test_tier_write_facts.py`, green on a HEAD
snapshot 2026-08-19.

Erwin asked twice why this was his. It was not. I had been calling a judgement call a product
decision, which is an engineer's way of not owning a judgement. Taking it back, with the measurement
that makes it a defect rather than a taste question.

**THE INTRUSIVE TIER GROUPS TWO UNLIKE THINGS.** MEASURED over all 40 INTRUSIVE engines:

- **9 STATE-CHANGING**: `confirm_create_object_idor` (creates and deletes objects), `run_upload_test`,
  `run_race`, `run_cache_poison`, `run_stored_xss`, `confirm_authz_write`, `run_deserialization`,
  `run_workflow`, `run_hash_crack`.
- **31 PAYLOAD-SENDING BUT READ-ONLY**: every SQLi engine, `run_ssrf`, `run_cmdi`, `run_xxe`,
  `run_nosqli`, `run_xpath`, `run_zap`, `run_ffuf`, `run_content_discovery`, and the rest.

That second group is what every operator MEANS by an active scan. Burp and ZAP both send SQLi
payloads under that label and gate destructive actions separately. Apolaki calls them INTRUSIVE, which
is why **a mission in `active` mode cannot test for SQL injection** - and why an unauthenticated
active scan returns leads instead of confirmations.

**Both earlier proposals failed for the same reason: they moved the line without fixing that the line
bundles unrelated risks.** Narrowing `active` cost 49.5% of the sweep. Defaulting to `full` would have
permitted state-changing writes against production. Neither is wrong about its own tradeoff; both were
answering the wrong question.

**THE DECISION.** Split the tier rather than move the boundary:

```
PASSIVE      observe only
ACTIVE       requests + payload-sending READ-ONLY checks   <- the 31
INTRUSIVE    STATE-CHANGING / destructive                  <- the 9
```
`active` = PASSIVE + ACTIVE. `full` = everything. The 9 stay behind the existing HITL gate and
`auto_approve`.

This is not a compromise between the rejected proposals. It recovers the SQLi surface WITHOUT
permitting a single state-changing operation, because those were never the same category.

**PRE-REGISTERED REVERT CONDITIONS, written before measuring, per this project's own discipline:**
1. If re-tiering moves ANY of the 9 state-changing engines into `active`, revert. That is the whole
   safety property.
2. If the benchmark macro drops on any suite category, revert and re-measure - more engines running is
   not automatically better, and a new false-positive source would be paid for in precision.
3. If mission wall-clock at `active` rises more than 2x, treat it as a budget question and re-scope
   rather than shipping it quietly.
4. If any of the 31 turns out to mutate state on a real target, it was mis-classified: move it to the
   9 and record what it wrote. **The classification above is by name and by reading, and has NOT been
   confirmed by observing each engine against a live target.** That is the honest limit of this
   analysis and it is condition 4's reason for existing.

**Erwin's actual input, if he wants one, is narrow:** whether "active" should send payloads at all.
Every mainstream scanner says yes. If he disagrees, the answer is 1 and the ticket closes differently.
He does not need to arbitrate a taxonomy.
### Q-051 · The report cannot say WHICH ENGINE found a finding, and the technique coverage matrix is dead code · **CLOSED** `bc60727` `93ca3dd` `6493417`
The reader half (`arsenal_gap` preferring `mode` then `strategy`) shipped first and the PRODUCER half
did not, so `blocked_by_mode` was permanently empty and every tier-blocked engine was reported to the
client as "available but not selected" -- the report asserting the planner had declined engines the
permission tier had barred outright. `main._tool_ledger()` now emits `mode`. Pinned by
`agent/tests/test_ledger_mode_binding.py`, which builds its ledger from the REAL producer rather than
a literal, because every earlier fixture supplied `mode` by hand and that is exactly why no test
caught it. Green on a HEAD snapshot 2026-08-19.

Erwin's idea, and it is the right one: if the report attributed every check to the tool that performed
it, an unused tool would be **visible in the artifact** instead of requiring a database audit. Q-050
took a SQL query over 151 missions to find that 32 engines never ran. That should have been readable
off a report.

**MEASURED, two gaps:**

**(a) No finding carries its producing engine.** 400 stored findings sampled: **zero** have any key
naming a tool, engine, or source. The mission-level `tool_ledger` block exists and `asvs_model.assess`
already consumes it via `_engines_from_ledger`, so the mission knows WHICH engines ran — but nothing
connects an individual finding to the engine that produced it.

This is the **Q-046 defect again**: the producer is known at the moment of creation (`ToolResult` is
constructed with the tool's own name) and thrown away, exactly as `param` was rendered into a title
and discarded. Bind it at the `ToolResult` boundary, where the name is already in hand.

What it buys, beyond attribution: **an "engines that produced nothing" section falls out for free**,
and so does "engines never dispatched". A reader sees `run_cmdi: not dispatched` in the report rather
than us finding it by hand two years later.

**(b) Technique coverage is computed NOWHERE.** 88 techniques are defined in `techniques.py`. Both
`techniques.coverage_matrix` and `techniques.techniques_for_lab` are in the **qualified-dead-code
list** — the machinery that would answer "which techniques ran" exists and is never called. WSTG,
which is wired, stands at **full 60 / partial 25 / none 24 / excluded 5 of 109 (55.0% full)**, so the
honest coverage picture is available for WSTG and absent for techniques.

**On "all techniques must be used":** not every technique applies to every target, and forcing them all
to fire would manufacture noise. The right invariant is the one Q-012 already established for ASVS —
every technique must either **RUN**, or be recorded as **not applicable with a reason**. Silence is the
defect, not non-execution. A technique that never ran and never explained itself is indistinguishable
from one the product cannot perform.

**DoD**: `engine` bound on every finding at the `ToolResult` boundary; the report prints per-finding
attribution plus a not-dispatched/produced-nothing section; `coverage_matrix` wired and printed; every
technique either runs or carries a reason. **Do not fix (b) by deleting the dead functions** — they
are the answer, not the problem.

---

### Q-050 · **32 of 92 engines have NEVER EXECUTED** — RE-MEASURED, and the answer is 6, not 32 · **HIGH** · `ready`

#### RE-MEASUREMENT, Coordinator, 2026-08-20 — the count is worse and the finding is much narrower

Positive control first, because a zero here would otherwise mean nothing: the corpus is **154
missions, 29,945 `tool_call` rows, 1,773 findings, 66,395 log rows**, 0 unparseable.

    registry (TOOL_PERMISSIONS)          111
    distinct tools ever dispatched        72
    NEVER EXECUTED                        40   (was 32 of 92)

**But "never executed" was the wrong question, and answering it is what made that clear.** An engine
that has not run may simply never have met a matching target -- most of the 40 are network-service
engines (`run_smb_enum`, `run_snmp_audit`, `run_ssh_audit`, `run_vnc_audit`, `run_rdp_audit`,
`run_ntp_audit`, `run_rsync_audit`, `run_ipmi_audit`, `run_modbus_audit`) and every mission in this
corpus targeted a web lab. That is not a defect. The real question is **which of them the
deterministic schedulers can never select at all.** Classified by whether the name appears anywhere
in `agent.py` or `planner.py`:

    schedulable   30      named by a scheduler; simply never met a matching target
    LLM-only      10      named NOWHERE in agent.py or planner.py
    unreachable    0      no dispatch method -- none, which is the good news

**Soundness of the instrument, stated because a regex over source has burned this project before
(Q-077):** the scan includes comments and docstrings, so it can only produce false POSITIVES. A count
of **zero** therefore really means the name is absent. The claim being made here rests only on the
zeros. Positive control: `run_xss` and `run_sqli`, which have both run, appear across `agent.py`,
`planner.py`, `technique_planner.py` and four catalogues.

**Six of the ten LLM-only entries are real detection engines**, each with a working
`ToolRegistry._run_*` dispatch method, reachable ONLY if an LLM picks them out of `CLAUDE_TOOLS`:

    run_mass_assign        named outside tools.py only in asvs_model.py, wstg_catalog.py
    run_hash_id            named outside tools.py only in engine_descriptor.py, wstg_catalog.py
    run_external_surface   named outside tools.py only in description_gate.py
    run_nosqlmap           NAMED NOWHERE
    run_ws_hijack          NAMED NOWHERE
    run_hash_crack         NAMED NOWHERE

The other four (`benchmark_lab`, `list_workflows`, `mission_intel`, `mission_state`) are operator
utilities and being LLM-only is correct for them.

**Why this matters more than a coverage statistic.** Apolaki is deterministic-first. Run a
deterministic mission against any target and those six can never fire. And two of them are cited as
coverage: `asvs_model.py:179` declares an ASVS objective `"engine": "run_mass_assign",
"verifiable": True`, and `wstg_catalog.py:110` and `:132` map WSTG-INPV-20 to `run_mass_assign` and
WSTG-CRYP-04 to `run_hash_id`. **The platform names engines in its control catalogues that its own
deterministic planner cannot select.**

**The irony is exact and worth recording.** Q-011 found `run_mass_assignment` was a phantom NAME and
fixed the spelling so it dispatches. `asvs_model.py:170` still carries the note. Nobody ever put the
correctly-spelled engine into a scheduler. **The name was fixed; the wiring never existed** -- which
is the island pattern surviving its own fix.

**Definition of done**: for each of the six, either give it a deterministic trigger (a precondition
the planner can evaluate) or move it out of the control catalogues, so a coverage claim is never
backed by an engine the deterministic path cannot reach. `run_mass_assign` first: it is the one with
both an ASVS objective and a WSTG test riding on it.

See also Q-084, filed from the same measurement session, on the WSTG coverage NUMBER being a constant.

#### Original filing

Raised by Erwin: "are all tools being used harmoniously?" MEASURED rather than answered — 29,109 tool
calls across 151 stored missions, 67 distinct tools ever executed, 92 engines defined.

**The browser driver and dev tools ARE properly used** and that half of the question is settled:
`run_xss` 1344 calls, `run_dom_audit` 892, `run_dom_trace` 797, plus the CDP/Playwright BIE work. The
browser tier is 3.1% of dispatches for **58.5% of tool-seconds**, which is a cost decision already
priced and deliberately kept (browser confirmation is how XSS becomes proof rather than a lead).

**The other half is not fine. 32 engines have never run once**, and there are TWO distinct causes:

**(a) ~~INTRUSIVE engines are unreachable in the default `active` mode.~~ CORRECTED — see Q-052.**
I wrote that `planner._ALLOWED["active"]` excluding INTRUSIVE is why `run_cmdi` never runs. Measured
one layer down, that is **not** the mechanism: `agent._run_tool` enforces the tier only for `passive`,
so an INTRUSIVE engine dispatched in `active` runs fine — five of the eight sweep engines ARE
INTRUSIVE and `run_sqli` fired 700 times in an `active` mission. The planner honours the tier and the
dispatcher does not.

So the true statement is narrower and worse: **`run_cmdi` is absent from an 8-entry tuple and the
planner will not schedule it, and nothing about its permission level is protecting anyone.** Command
injection — a core OWASP class with a full engine and its own oracle — has executed ZERO times in 151
missions for that reason. Same for `run_zap` and `run_nosqlmap`.

**(b) ACTIVE engines that ARE reachable and simply never get selected**: `run_jwt`, `run_saml`,
`run_enumerate_ids`, `run_default_creds`, `run_metadata`, `run_jsonp`, `run_session_lifecycle`,
`run_workflow`, `run_external_surface`, and the content-discovery trio
(`run_dirsearch`/`run_ferox`/`run_gobuster`). These are a selection/precondition problem, NOT a
permission one, and must not be lumped in with (a).

14 more are network/ICS engines needing a non-web target (`run_nmap`, `run_ssh_audit`,
`run_smb_enum`, `run_modbus_audit`...). Defensible that they have not fired on web missions — but it
also means they are unvalidated in practice, which is the `validated_on` lane's problem.

**DoD**: (a) and (b) separated with a fix for each; a liveness-style ratchet that FAILS when an engine
goes a full mission-suite without executing; and `run_cmdi` executing in a real active mission. **Do
NOT fix this by adding everything to the sweep tuple** — wp1 measured what happens when an unproven
engine joins the always-on path.

**This is the honest answer to "it better be working the way I wanted": two thirds of the arsenal is
wired and firing, and one third has never been asked to do anything.**

---

**TOP OF THE QUEUE — Q-049 first, it is worth nine cases:**

- **Q-049 · FALSIFIED as written, and re-aimed. The lever is `SWEEP_TARGET_CAP`, not the allocator.**
  I proposed proportional allocation; implemented, it broke both invariants the breaker lane had
  already measured (complete coverage of a class that fits — worth 34.1% vs 17.8% macro reachable
  recall — and monotonicity). And there was no slack anyway: a truncated round-robin **is** the
  water-filling optimum `min(size, level)`. MEASURED: the dominant class draws 38 slots at cap 400,
  and **cap 605 is the first that probes all nine** lost cases (~24% of the surface vs 15.8%).
  Reverted; the measurement is pinned in `tests/test_sweep_budget_is_the_lever.py`.
  **CLOSED.** `SWEEP_TARGET_CAP` is now **700**, earned by measurement: wp3 (seal `951dc0a0`, sealed
  before the key, conditions pre-registered) probed **645 cases instead of 373**, took `sqli` from 11
  back to **20**, recovered **8 of the 9** named cases, and scored **26 TP / 1 FP / 27, precision
  96.3%, in 2576 s against the baseline's 5329 s** — the same score in 48% of the time. The one FP is
  `00494`, the known baseline FP, not a new one. Cost prediction was wrong in the good direction:
  +22%, not the +57% a linear model predicted.
  **Left open, named:** `00438` (the ninth case, highest index) is still unprobed, and per-URL cost is
  sublinear in target count — understand that before pricing the next budget change.
- **Q-048 · every objective's `violated_by` families must have a real producer reachable from one of
  its own engines.** MEASURED instances: SESS-02 can never fail (`cookie_flags` has no producer;
  `transport_posture` emits `security_misconfig` instead), and CONF-01 names `run_fingerprint`, which
  cannot emit `vulnerable_component` (only `_run_js_review` does). A `verified` backed by an engine
  structurally incapable of failing it is Q-012 one level down.


- **Q-047 · ORACLE FIXED, sweep entry still out.** Root cause was not reflection: the oracle was
  reading **request order**. On the stateful `weakrand-00/BenchmarkTest00187` the `exists` probe went
  first and got the session-establishing body while both absent probes got the steady state — every
  requirement satisfied by a cookie. `exists` is now repeated and a divergence must survive the
  repeat; without the repeat the verdict is a lead that says why. Validated live: 00187 → **no
  finding**, `pathtraver-00/00040` and `00045` → still **confirmed**. (The other three wp1 traversal
  cases used the **header** carrier, so they are untested here — validated on two, not five.)
  **RE-MEASURED (wp2, seal `82f55903`) — and the ticket STAYS OPEN.** 28 TP / 1 FP / 29 claimed,
  96.6% precision. Against wp1 the fix **lost 2 TPs and did not remove the FP**: it killed `00187`
  and its two lucky twins (`00023`, `00236` — weakrand cases that scored TP by accident), and a NEW
  weakrand FP appeared at `00042`. `pathtraver` is unchanged at 5 TP in both runs. The instance died,
  the class did not. **`run_web_probes` stays out of the sweep; the two strict xfails stay.**
  Unexplained and recorded as such: the real engine against `weakrand-00/BenchmarkTest00042` returns
  **0 findings** standalone, so the mission's claim cannot be reproduced outside a mission. Next step
  is that gap, not another oracle guess.
- **`sqli` 21 → 11.** The whole-product runs keep losing half the sqli detections. Older than the
  wp1 change, survived it, still unexplained, and it is the single largest known recall loss.

**NEW AND UNASSIGNED — raised by the rerun, currently nobody's:**
- **Baseline `ebd96f45` — counts RECONCILED, seal still dead** (see LEDGERS). The ledgered 25/23 is
  the same 29 stored rows with five `ldap_injection` findings collapsed by a `finding_fp` param
  collision. Honest claim count is **27**, the `ldapi 1 -> 5` "class broadening" is **zero**, and the
  regression is **−9, not −3**. Two things remain open and are the actual tickets:
  - **Q-045 · CLOSED** `59d6eb0` (seal) + the scoring commit. Re-scored end to end: **26 TP / 1 FP /
    27 claimed, 96.3% precision, 1.84% recall**, seal `fab8a46e` recorded before the key was opened.
    All five `ldapi` cases are TRUE positives — the old count hid four real detections, so the
    published baseline *understated* the product. `BASELINE` now carries 26/1/27, all three together.
  - **Q-046 · CLOSED.** `finding_fp` derived `param` by parsing prose (`rsplit(" in '", 1)`), so any
    title whose wording did not match yielded `param = ""` — indistinguishable from "no parameter".
    `ldap_tool` renders `in <where> '<param>'`, which the split cannot read, so five findings became
    one. All five injection builders already had `param` as a local and discarded it; they now emit
    it, and the key prefers the field with the title parse kept as a fallback so the ~1052 stored
    findings keep their fingerprints. 9 controls, 4 mutants killed.
- **The `00494` two-call-site patch** — written up, not applied; closes the proved-undecidable residual
  by adding an after-probe sample rather than guessing from two.
- ~~**The `_POWERED` regex yields garbage product names**~~ — **CLOSED** (see LEDGERS). The gate now
  also runs on the display projection, so the report and `live_hosts[i]["tech"]` stop printing
  sentence fragments as the target's technology stack. `detect()` is deliberately left unfiltered so
  the refusal ledger can still name what it dropped.

**OPEN, ranked by value — this is the real backlog:**

| ticket | what | why it matters |
|---|---|---|
| **Q-021B–F** | Technology Intelligence chain: persist TechnologyFacts → identity/ranges → feeds → orchestration → honest UI | detected tech still drives no testing |
| **Q-032/033/034** | credential→session→persona, multi-persona differentials, report chronology | the architecture programme; `session_headers` is still one global raw dict at 50 sites |
| **Q-002/003/004** | WebSockets/CSWSH · `postMessage` source · API4 resource consumption | genuine zero-engine classes |
| **Q-011/012** | second phantom capability; six ASVS engine names resolving to nothing | declaration-vs-fact defects |
| ~~Q-015/016~~ | **CLOSED** — `risk_signals` now shares `risk_score`'s filter; `_read_controls` records why it went dark | a report that contradicted itself, and a crash that read as "no controls" |
| ~~Q-017~~ | **CLOSED** — `get_logs` keeps the NEWEST rows when the limit bites, still returned oldest-first | a truncated tail is indistinguishable from a mission that stopped |
| **Q-005/006** | server-side prototype pollution (gated) · request smuggling (detection tiers only) | deliberately constrained |
| **Q-030/035/036** | canonical cycle design · the model A/B experiment · fold the 15 architecture defects in | Q-030 is designed, not built |
| **B-011+** | Juliet C/C++ (**UNSUPPORTED — no C/C++ analysis**), SARD subsets, remaining language ecosystems | matrix programme |

Roughly **28 open**. Q-023, Q-013 and Q-014 are all closed; the highest-value unstarted work is now
**Q-021B–F** (detected technology still drives no testing) and the **baseline provenance** item above,
which blocks trusting any comparison against `ebd96f45`.


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

**Cycle 2 — assigned 2026-08-10 after the first squad was killed by API session limits.** Four lanes,
deliberately disjoint. Cross-lane needs are written here as **hand-off notes**, never applied directly.

| owner | files it may WRITE | ticket |
|---|---|---|
| **Builder · funnel** | `agent/agent.py` · `agent/crawl.py` | **Q-019** — the funnel (2756 → 36) |
| **Builder · engine** | `agent/tools.py` · `personas.py` · `register.py` · `session_lifecycle_tool.py` · `techniques.py` · `engine_descriptor.py` · `wstg_catalog.py` · `deadcode_gate.py` | **Q-001** — session lifecycle + the deadcode-gate failure it inherited |
| **Breaker** | test files only · `CODEBASE_REVIEW.md` | verify Q-00A (BIE), the 0% FPR claim, and today's four commits |
| **Watcher** | `docs/research/INBOX.md` | ZAP orchestration · the 8.5 s/call throughput ceiling · Q-021 feed quality |
| **Coordinator (main thread)** | `report.py` · `proof_schema.py` · `liveness.py` · `browser_engine.py` · `main.py` · all `docs/` | ledgers, sequencing, Codex-audit intake |

Known-conflict hand-offs, already issued:
- Q-019 may need an `_add_urls` ingress guard in `tools.py` (owned by the engine lane) → the funnel
  Builder writes the patch here instead of applying it.
- Q-001 needs a `liveness.py` CHECKS entry (owned by the Coordinator) → same rule.
- Q-001 may need an `agent.py` change (owned by the funnel lane) → same rule.

**Known failing test that belongs to the engine lane, not to anyone else**:
`tests/test_deadcode_gate.py::test_the_method_ratchet_holds`. Baseline otherwise 1670 passed,
2 skipped. Nobody but the engine-lane Builder touches it, and it must be fixed by wiring the code —
not by silencing the gate.

---

## Lane changes — 2026-08-12

**PROBE LANE STOOD DOWN.** Both of its hypotheses are falsified by its own measurements —
blind-vs-echo on cmdi (+0 over 251 cases) and carrier delivery on cmdi and xss (+0 over 120 paired
xss cases, with the carrier proven to have RUN on ~30% of them). It has nothing queued behind them,
and keeping a lane parked on a dead theory holds its files hostage. **Do not resume agent
`aff3a7dd3d2343dde`.** Its engine work is committed and keeps its value; the lane is closed, not the
code.

Released files: `agent/tools.py` · `agent/cmdi_tool.py` · `agent/xss_tool.py` · `agent/sqli_tool.py` ·
`agent/ssrf_tool.py` · `agent/dom_trace.py` · `docs/handoff/probes.md`.

**LEASED TO CODEX: Q-040 + B-010** from `aa8e26a`. `agent/sqli_tool.py` and its tests, plus all new
Juliet paths, are Codex's until it returns. Claude does not spawn or resume into them.

## Q-044 · The code-assisted lane · **HALF CLOSED** - wired since filing, still UNPROVEN in a mission · **HIGH** · `ready`

Re-measured 2026-08-18 by the Coordinator before starting work, because five tickets this week were
wrong in scope or existence. **Three of this ticket's four core claims are now FALSE.** It was wired
by another lane without the ticket being updated.

| the ticket said | measured now |
|---|---|
| `review_source_tree` has exactly ONE caller, `owasp_bench.py:231` | FALSE - also `main.py:427`, via `_run_source_review` |
| `source_root` appears NOWHERE in `main.py` | FALSE - **10 occurrences**, including a request-model field at `main.py:106` |
| no API parameter invokes the SAST lane | FALSE - `main.py:620` calls `_run_source_review(session_id, req.source_root)` from the engage path |
| `/codereview` calls the OLDER `codeintel.review()` | **STILL TRUE**, and `POST /mission/{id}/codereview` likewise calls `codereview.review()` |

The evidence contract is composed too: `_canonical_source_finding` (`main.py:392`) **fails closed**
before a source result can enter reports under DAST semantics, requiring `provenance=source-derived`,
`lane=code-assisted`, `analysis=static-call-site`.

**WHAT IS STILL OPEN, and it is the half that matters.** The ticket's own DoD is "prove it with a real
mission that produces a source-derived finding, not a harness call". Measured against the live DB:

```
POSITIVE CONTROL findings scanned: 1057   (113 missions)
provenance=source-derived: 0
lane=code-assisted:        0
```

**The path exists and has never carried a finding.** So the correct state is HALF CLOSED, not closed:
the wiring defect this ticket was filed for is fixed, and the capability claim it guards is still
undemonstrated. **61.1% remains a HARNESS figure until one real mission produces a stored
source-derived finding.**

Closing this on the wiring alone would be the island pattern applied to the ticket ABOUT the island
pattern: code that exists, is reachable, and has never run. DoD unchanged - run a mission with
`source_root` against a Java or Python tree, and record the mission id and the finding.
## Q-043 · Apolaki does not honour `Retry-After` · **HALF CLOSED** `0b991e9` `5bb3330` `58f2e81` `20883a5` · the MECHANISM is built, the COVERAGE is not

#### Status 2026-08-20, after two lane runs

**The mechanism half is done and measured.** `Retry-After` is real now: `browser_engine.py:110`
parses RFC 9110 delta-seconds and HTTP-date, a shared per-origin deadline exists, the past-date clamp
that had no test now has one, the ceiling is measured at the boundary, and the "bare-429 gap" a lane
first reported turned out to be **a designed boundary rather than a defect** -- so the fallback ships
OFF, at 0.0 rather than the 2-5s a sibling handoff recommended, because the opposite is held by a
named negative control and the lane would not delete an oracle to make its own change look better.
Two lanes reached the same fix from different directions; turning it on is one constant plus a
deliberate update to that control.

**The coverage half is NOT done, and the number is the ticket's own words: "a policy covering every
engine".**

    modules sending TARGET traffic THROUGH the policy : 3    tools.py, browser_engine.py, proxy.py
    modules sending TARGET traffic AROUND the policy  : 13

That half is now **Q-085**, because its cause is structural and generalises past this ticket: both AST
guards parse `tools.__file__` and nothing else, so the guard's scope became the boundary of
compliance. See Q-085, which also carries the live no-DoS breach at `juiceshop_solvers.py:304` --
ten concurrent threads against the target with no gate.

**Do not close this ticket until Q-085 closes.** "No DoS" is a promise this platform makes in its own
documentation, and a policy covering 3 of 16 modules does not keep it.

#### Original filing — and the Coordinator failure it records

**MEASURED by Codex lane 4**: with `Retry-After: 2` returned by the target, both concurrency widths
sent **47 requests**; width 6 started **14 requests inside the retry window**. The concurrency ceiling
held — the target-side backoff did not, because it does not exist.

**Verified independently: `Retry-After` appears NOWHERE in `agent/`.** A repo-wide grep returns zero
hits. `tools.py:3296` — which I cited as the enforcement point — is `subfinder` argument handling.

**This is a Coordinator failure, recorded as one.** I wrote *"`tools.py:3296` honours `429`/`Retry-After`
and that must survive"* into **five separate lease prompts**, to Claude lanes and to Codex. It was a
fabricated citation: a real-sounding file:line attached to a behaviour that was never implemented.
Nobody challenged it because it arrived from the Coordinator with a line number, which is exactly why
it is dangerous. Codex found it by **testing the behaviour instead of reading the claim** — the same
method that has caught every other load-bearing error in this project.

The standing rule this earns: **a Coordinator citation is a claim, not evidence.** File:line
references in briefs get verified before they are repeated, and a lane that cannot reproduce a cited
behaviour should treat the citation as the defect.

**The ticket**: a cross-cutting target-rate policy covering **both** `_http` and browser navigation —
Codex correctly declined to build it, because a generic fix touches every engine through `tools.py`
and that was its stop condition. Requirements: honour `Retry-After` (delta-seconds and HTTP-date) and
`429` on both paths; bounded and configurable; **and a negative control that fails if the policy is
removed**, since the absence of one is how this went unnoticed. No-DoS is a promise this platform has
been making in its own documentation without keeping.

## Rank 0 — five defects now PINNED by strict xfails, surfaced 2026-08-12

Each is a real defect with a written reason, held by a strict xfail so it becomes a regression test
the moment it is fixed. Removing a marker without fixing the defect is forbidden.

### Q-040 · `analyze_boolean` has no baseline-stability control · **CRITICAL** · `ready`
`tests/test_sqli_oracle_negative_controls.py::test_an_unstable_page_must_not_confirm_blind_sqli`.
**An unstable page confirms blind SQLi.** This is a false-positive path in our strongest category —
sqli is 21 of the 22 whole-product true positives, and FPR is currently 0.0% on every category of
both suites, which is the platform's single best property. Fix: the oracle must re-sample the
baseline and prove stability before crediting a boolean differential. Remove the marker only then.

### Q-041 · aliased module imports are invisible to the source lane · **HIGH** · `ready`
`import random as r` / `import hashlib as hl`. `_py_imports()` computes `modules['r'] = 'random'` and
then **throws the binding away** — `_py_binds_module` can only SUPPRESS a name, never resolve one, and
`_PY_RANDOM_CALL` / `_PY_HASHLIB_CALL` hard-code the literal receivers. The `from X import Y as Z`
half is handled correctly, so this is a half-implemented mechanism, not a missing one. Costs the
benchmark **0 cases** (no aliased imports in the suite) — it is a pure generality hole, and generality
is the whole claim of the code-assisted lane.

### Q-042 · `_PY_CLOCK_TOKEN` fires on a name that merely CONTAINS a security word · **HIGH** · `ready`
Any identifier containing a security word within 90 characters of a clock read is reported as CWE-337
"a security value derived from the clock" — so an audit or expiry timestamp is a false positive.
**Confirmed in the wild**: the single CWE-337 across 5139 files of the container's stdlib is this bug
firing on the keyword argument `token=` in `anthropic/lib/credentials/_workload.py:346`. Costs the
benchmark 0 cases; costs credibility on any real codebase. Fix: bind the value, do not pattern-match
its name — the same "receiver decides, not the name" rule that took Python weakrand from 50.2% to 100%.

## Rank 0a — Q-021A · contain the SCA proof overclaim · **CRITICAL** · `in flight`

Spec: [CODEX_AUDIT_VERDICTS.md](CODEX_AUDIT_VERDICTS.md) verdicts 1–5. Jumps the queue ahead of
Q-019: everything else is a missing capability, this one is a **wrong answer already shipping to
clients**. Owner this cycle: **Builder · SCA**, files `dependency_intel.py` · `proof_schema.py` ·
`retest.py` · `poc_bundle.py` · `candidate_pipeline.py` · `report.py` · `sarif_io.py` · tests.

Measured baseline before the first slice: **1730 passed, 9 skipped, 0 failed** (agent image,
python 3.12). The `test_t7_zero_delta` PRECONDITIONS failure noted in the hand-off is not present in
the baked image.

**Slice log** (each slice: implement → targeted test that failed first → negative control → commit):

| # | slice | state |
|---|---|---|
| 1 | `dependency_intel` — split version-certainty from exploitability-certainty | **done** |
| 2 | `proof_schema` — the proof gate must inspect `vulnerable_component` | **done** |
| 3 | `retest` — a patched component must CLOSE, not stay OPEN | **done** |
| 4 | structured `cves` on the SCA finding so KEV can match it | **done** |
| 5 | `success_oracle` vs `oracle` — one canonical key, normalised at one chokepoint | **done** |
| 6 | SARIF still un-demotes proof-gate-demoted rows (bonus) | **done** |
| 7 | stale-bundle-filename FP — contradictory fingerprints of one library | **done** |

### Slice 1 — `confidence` no longer answers two questions with one word
`vulnerable_component_finding` set `confidence=CONFIRMED` while its own `impact` said exploitability
"was NOT confirmed in this test". Fixed by separating the fields, not by deleting the claim:

* `version_confidence` — `confirmed`/`high`/`low`, how sure we are of the **served version**.
* `component_status` — `affected` / `potentially_affected`, whether the CVE's **own behaviour** was
  observed. New module constants `AFFECTED` / `POTENTIALLY_AFFECTED`.
* `confidence` — the platform-wide proof verdict. `confirmed` **only** when
  `behaviour_proof_ok()` passes; otherwise `lead` + `proof_gap` + a `needs-confirmation` tag.
* `behaviour_proof_ok(proof, cve_ids)` — pure oracle. Requires a CVE **from the matched ranges**, a
  trigger, the observed vulnerable behaviour, a structurally identical **trigger-absent control**,
  and a real differential between the two. Caller performs the requests; this only judges them.
* `CVE_ELIGIBLE` is reused (not reinvented) as the enforcement point: a `LOW` fingerprint is a guess
  and can never be `affected`, however many CVEs a feed returns.

Preserved deliberately: the MEDIUM severity cap and its scanner-inflation comment.

Hand-off note (files owned elsewhere) — none for slice 1; `tools.py:5210` calls
`vulnerable_component_finding(comp, vulns)` positionally and keeps working unchanged, now emitting a
lead instead of a false confirm.

### Slice 2 — the proof gate now inspects SCA findings
`_DEFAULT_ENFORCE` omitted `vulnerable_component`, so `demote_unproven` never looked at an SCA row
and the slice-1 defect reached the client report intact even after the producer was fixed (any other
producer, or a persisted pre-fix finding, still slipped through).

* new `_FAMILY["vulnerable_component"]` proof contract: the exact CVE **and** a behaviour
  differential / negative control **and** what was observed. Presence evidence carries none of them.
* `_CWE_FAMILY` gains `CWE-1104` / `CWE-1035`; `_ALIAS` gains `vuln_component` / `sca`, so a row
  carrying only the CWE routes to the same contract.
* `_DEFAULT_ENFORCE` widened by exactly ONE entry. The narrow default is a **sequencing** rule, not
  a permanent one — a family becomes enforceable once its producers' evidence phrasing has been
  audited. This family has one production producer, audited in slice 1, so enforcement cannot
  manufacture a false negative; the only row it can demote is a presence-only `confirmed`.

Mutation test: reverting `_DEFAULT_ENFORCE`, and separately weakening the family rule to the CVE
signal alone, both leave the stale row `confirmed` — the targeted tests fail in both cases.

### Slice 3 — retest could not tell "patched" from "still there"
`_GET_ORACLE["vulnerable_component"] = "reachable"` asked *is a file still served here*. A patched
library is served from the same URL and returns the same non-empty 2xx, so **every fix came back
OPEN**. New `component_version` oracle re-FINGERPRINTS the replacement:

| replacement | verdict |
|---|---|
| body still declares the affected version | `open` |
| body declares a newer version still inside a known-vulnerable range | `open` |
| body declares a version outside every range | `closed` |
| non-2xx / empty | `closed` |
| body declares **no** version (only the unchanged filename) | `inconclusive` |
| finding predates the structured `component` fields | `inconclusive` |

Content beats filename, deliberately: `/assets/jquery-3.4.0.js` serving 3.6.0 is a fixed finding, and
an in-place patch never renames the file. Where only the path is left as evidence the honest answer
is `inconclusive` — a false OPEN is the remediation lie this slice exists to remove, and a false
CLOSED is the failure the module was written to avoid.

Mutation test: restoring `"reachable"` makes the patched replacement report `open` again.

### Slice 4 — SCA findings reach KEV, and the KEV table stops overstating them
The finding's CVE ids lived only in `title` and `description`. `report.py`'s KEV blob is built from
`cve` / `cves` / `evidence`, so the ids were invisible to it. Fixed at the PRODUCER: the finding now
emits `cves` as a structured list of exactly the ids whose ranges the version matched. The KEV
consumer's regex was deliberately **not** widened to scrape titles — that would make every prose
mention of a CVE a KEV candidate.

Honest note: slice 1 already rewrote the evidence string to name the matched CVEs, so the KEV
*match* was incidentally working before this slice. The structured field is still the right fix —
it survives any future rewording of the prose — and the test that failed first is the one asserting
the structure, not the rendering.

Second, smaller lie fixed in the same place: the KEV table's column header read `Confirmed finding`
and every row landed under it regardless of proof state. It now reads `Finding` + `Our proof state`,
filled from the shared `_confirmed()` helper and the new `component_status`, so a potentially-
affected lead cannot read as a confirmation just because its CVE is in the catalog.

Mutation test: drop `cves` and restore the pre-slice-1 presence-only evidence -> the SCA finding
misses KEV again.

### Slice 5 — one canonical oracle key (platform-wide, not an SCA bug)
Re-measured on this tree: **38** modules mention `success_oracle`, **87** sites write a plain
`"oracle"`. Both are alive, so neither was declared dead. The real defect is that the two CONSUMERS
disagreed with each other — `poc_bundle` read only `oracle`, `report_integrity_check` read only
`success_oracle`, so each was blind to exactly the families the other could see.

* canonical key: `proof_schema.ORACLE_KEY = "success_oracle"`.
* one reader: `proof_schema.oracle_of(finding)` — canonical spelling wins, legacy accepted.
* one chokepoint: `normalize_oracle()` applied inside `demote_unproven`, which is what
  `db.get_findings_gated` (the documented "anything that PRESENTS a finding reads through here"
  accessor) already routes every consumer through. Additive and non-destructive: the legacy key is
  left in place, so both producer spellings keep working.
* consumers fixed: `poc_bundle.py` (both sites) and `report.py:1702`, the latter via a local
  `_oracle_of()` that imports through proof_schema — same discipline as `_confirmed()`, so the
  vocabulary cannot fork a third time.

**Scope note, important for whoever picks this up next**: `oracle` is *also* a key on techniques,
candidate-validation records, retest plans and evidence dicts. Those are different objects with
their own meaning and were deliberately left alone. This slice is about FINDINGS only.

**Hand-off notes — readers in files this lane must not touch:**
- `agent/bie.py:601` writes `"oracle": finding.get("oracle") or ""` into the BIE evidence block. It
  should read `proof_schema.oracle_of(finding)`. One-line change, owned by the BIE lane.
- `agent/agent.py:792` reads `already.get("success_oracle")` only; `proof_schema.oracle_of` would
  also catch legacy-spelling producers. Owned by the funnel lane.
- `agent/blind_benchmark.py:266` and `agent/liveness.py:126` both read `success_oracle` only. Both
  already fall back to `evidence`, so neither is currently wrong — worth switching for consistency.

Mutation test: restrict `_ORACLE_ALIASES` to either spelling alone -> the normalisation returns
`None` and the PoC bundle's oracle goes empty again.

### Slice 6 — SARIF stops un-demoting the proof gate (closes the last export)
`707b3b9` / `5af0af8` fixed HTML, markdown, JSON and CSV. SARIF still emitted `level=error` and
`security-severity=9.5` for a demoted row, with the demotion buried in `properties.confidence` —
which GitHub code scanning and DefectDojo do not read. They route on `level` and
`security-severity`, so that is where the demotion now appears: a demoted row is capped at
`warning` / `5.0`, via the shared `proof_schema.is_confirmed()` rather than a fourth private copy of
"what counts as confirmed".

The cap can only ever LOWER a row (a demoted `low` stays `note`), and the original claim is kept as
`properties.claimed_severity` + `properties.proof_gap` so nothing is lost — it is preserved as data
instead of as an alarm level.

Mutation test: force `_proof_state` to `True` -> the demoted row exports as `error` / `9.5` again.

### Slice 7 — contradictory fingerprints of the same library (the stale-bundle-filename FP)
`/assets/jquery-3.4.0.js` that now SERVES 3.6.0 fingerprints **twice** — 3.6.0 from the body
(CONFIRMED) and 3.4.0 from the path (HIGH). Different `(name, version)` keys, so both survive the
caller's dedupe and the stale one raises a `vulnerable_component` finding for a library that was
already patched. New pure `dependency_intel.reconcile_components()` keeps the strongest evidence per
`(name, location)`.

Two deliberate limits, both with a negative control: reconciliation is per LOCATION (one page really
can ship two versions from two bundles), and two EQUALLY strong contradictory readings are both kept
— dropping the vulnerable one would be a false negative, dropping the patched one would be the FP.

**The no-island guard earned its keep here.** The first version of this slice left
`reconcile_components` uncalled and `test_deadcode_gate.py::test_the_ratchet_holds` failed
immediately (37 -> 38). Rather than raise the baseline, the function was wired into slice 3's retest
oracle, which had been hand-rolling the same "content beats filename" preference inline — so the
rule now lives in exactly one place and the ratchet is back at 37.

**Hand-off note — `agent/tools.py:5202` (engine lane).** Detection-time reconciliation is still
missing: that line builds `comps = dep.fingerprint_js_content(text, label) + dep.fingerprint_url(label)`
and the FP above is raised there. One-line patch:

```python
comps = dep.reconcile_components(dep.fingerprint_js_content(text, label) + dep.fingerprint_url(label))
```

Until it lands, the FP is caught at RETEST (the finding closes) but is still raised at detection.

---

## Rank 0 — the funnel (supersedes everything below)

### Q-019 · ANSWERED Q-010 · 2756 URLs discovered, 36 probed · **CLOSED** `55c035b`
**All three root causes verified fixed in source with positive controls on both scope gates.** The
ticket's own four-part acceptance oracle was run against verification mission `ebd96f45` and baseline
`90cee81c`: (a) hostless URLs 10 -> 0 PASS, (b) scope_block 34 -> 20 PASS, (d) findings 2 -> 29 PASS,
**(c) distinct `http_probe` URLs 36 -> 36 FAIL**. Clause (c) measures the wrong stage and would record
a FAIL against a fix that worked: `http_probe` is a recon tool dispatched 37 times in BOTH missions and
never was the funnel. The stage that widened is the injection sweep -- `run_xpath`/`run_ldap`/`run_ssi`
went 32 -> 412, distinct URLs any tool 63 -> 432. **Clause (c) is superseded by "distinct URLs reaching
an injection engine > 200", which measures 432.** The residual 20 `scope_block`s were sampled verbatim
and are correct refusals: `run_subfinder`/`run_crtsh`/`run_wayback` handed a bare host under a
path-pinned scope. The 76-hour projection is disproved -- fixed pre-sweep overhead (~27 min) averaged
over 8x more calls, plus `SWEEP_BROWSER_CAP=30` capping the ~19s browser confirmers; per-call cost
inside the sweep window is 11.39s before and 1.41s after.
Promoted out of `proposed` — this is the measured answer to Q-010 and it retires the standing belief
that surface discovery is the gap. Full ticket below under the Distillation pass. Three compounding
root causes: hostless `https:///benchmark/...` URLs that scope correctly refuses (34 `scope_block`
events, and they are exactly the category index pages linking to all 2740 cases); `sweep_targets`
admitting a URL only if it was FETCHED and carries `?`, making coverage O(pages fetched) not
O(surface discovered); and a `depth(2) × frontier(30)` = 60-visit cap standing alone between a
2756-URL surface and the engines. **Blocked on `tools.py` until the Builder releases it.**

#### Q-019 refinements — MEASURED by the Coordinator, 2026-08-10 (read before implementing)

1. **The crawl is CLEAN. The hostless URLs come from a different producer.** Ran the surface liveness
   check standalone against the same lab:
   `VERDICT: confirmed | surface grew to 2756 URL(s) (needed 8), all addressable` — **zero** hostless
   entries out of 2756. So `_surface_crawl` is not the producer of `https:///benchmark/...`; something
   on the mission path is (candidates: `crawl.parse_sitemap`/`parse_robots` with a hostless `at`, or
   the seeding path). **Do not "fix" `_surface_crawl` — it would be a null change against a green
   test.** Find the producer first; the `_add_urls` ingress guard in the ticket is still right because
   it names whoever it is.
2. **The hard cap is `limit=20`, not the frontier.** `agent.py:175` — `sweep_targets(urls, forms,
   in_scope, limit: int = 20)` — and `agent.py:2829` calls it **without passing `limit`**. The
   deterministic injection sweep therefore probes at most **20** endpoints against a 2756-URL surface.
   That single default explains the 36 distinct URLs better than the frontier cap does.
3. **Throughput, not just selection, is a ceiling.** The probe phase ran 50 s → 3720 s for 433
   `tool_call` events ≈ **8.5 s per tool call**, ≈ 12 calls per URL, ≈ **100 s per URL**. Even with a
   perfect funnel, 2740 cases at 100 s/URL is ~76 hours. **So "raise the cap" is not by itself the
   fix, and anyone who raises it and declares victory will have built a mission that never finishes.**
   Q-019 must ship with a budget-aware selection (representative-per-signature under an explicit
   time/count budget) and a separate ticket for probe concurrency. Add both numbers — URLs probed and
   wall-clock — to the acceptance oracle, not just findings.
4. Root cause #2 stands and is the deepest one: a discovered URL that was never FETCHED can never
   become a target, because `sweep_targets` keeps a URL only when `"?" in u` or a captured form names
   it, and forms only exist for fetched pages. The 2740 cases are plain `.html`. Coverage is
   O(pages fetched) = 12, and everything downstream is arithmetic on that 12.

### Q-010 · Why does a whole-product mission find 2 things on a 1415-vuln target? — **ANSWERED by Q-019**
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

### Q-021 · Technology Intelligence Engine — detected tech must drive targeted testing · **HIGH** · `ready`
*Erwin, 2026-08-10. An overlooked capability: recon fingerprints a technology and then nothing
happens to it. Detection must feed vulnerability intelligence, which must feed targeted probes.*

**This is an INTEGRATION ticket, not a new scanner.** Four of the five pieces already exist and are
disconnected. Building a fresh `tech_intel.py` beside them would be island #89 and is rejected in
advance. What exists, measured:

| piece | file | what it does today | gap |
|---|---|---|---|
| fingerprinting | `agent/fingerprint.py` (138 lines) | headers, `Set-Cookie`, `<meta generator>`, "powered by", JS-lib and body signatures → a flat tech list | shallow; no CMS plugins/themes, no evidence record, no persistence, no confidence |
| version confidence | `agent/dependency_intel.py` (266 lines) | **already has the ladder**: `CONFIRMED` (version proven from served content) / `HIGH` (from filename or CDN path) / `LOW` (heuristic), and `CVE_ELIGIBLE = {CONFIRMED, HIGH}` — LOW is **never** CVE-eligible | JS libraries only; no CMS, server, framework or plugin ecosystem |
| feeds | `agent/intel_feeds.py` (406 lines) | KEV, CAPEC, ATT&CK, ExploitDB snapshots; `exploits_for_finding()` | **no NVD/CPE, no OSV, no GHSA, no WPScan** |
| state ladder | `agent/intel_registry.py` | `candidate → validating → validated → fixture_backed → production` with confidence weights | not applied to technology facts |
| the missing piece | — | — | **nothing turns an advisory match into a scheduled probe** |

`dependency_intel.CVE_ELIGIBLE` is already the enforcement point for the proof rule below. Extend it;
do not reinvent it.

**TechnologyFact** (new, persisted, deduped across detectors): vendor · product · component/plugin ·
observed version · version confidence · detection evidence · source URL/request · authentication
state · first_seen · last_seen.

**Detect**: CMS platforms · plugins, themes, extensions · frameworks and libraries · web servers and
reverse proxies · hosting platforms and site builders · API gateways · auth products · JS packages ·
third-party services · exposed admin products. (WordPress core/plugins/themes, Drupal modules, Joomla
extensions, Magento extensions, Apache, nginx, IIS, PHP, Laravel, Rails, Django, Next.js, …)

**Enrich**: WPScan (WordPress core/plugins/themes) · NVD/CPE for general products · OSV for
open-source packages and precise version ranges · GitHub Security Advisories · CISA KEV for
exploitation priority (already loaded) · vendor advisories as authoritative confirmation.

**Orchestration — recon cycle 1**: fingerprint from headers, cookies, HTML, scripts, assets, routes,
generator metadata, error pages, **browser/CDP telemetry, ZAP**, and the existing detectors → record
evidence and confidence → query intelligence → emit **candidates, never findings** → into the
canonical graph and planner.
**Recon cycle 2**: revisit endpoints and authenticated states that expose hidden components or better
version evidence → inspect JS bundles, source maps, manifests, lockfiles, changelogs, readmes, asset
paths, API responses, plugin-specific routes (in scope only) → resolve ambiguous identities and
version ranges → trigger technology-specific **safe** probes through the planner → **recrawl** when a
discovered component introduces new routes, APIs, states or surface.

**PROOF RULE — detection or a database match is NEVER a confirmed vulnerability.** State ladder:
`DETECTED_TECHNOLOGY → VERSION_SUSPECTED → ADVISORY_MATCHED → APPLICABILITY_CONFIRMED →
SAFELY_PROBED → ORACLE_CONFIRMED`. **Version unknown ⇒ `POTENTIALLY_AFFECTED`, never proven.**
A confirmed finding still requires: reliable component identity · affected-version match or
configuration applicability · a deterministic oracle · a negative control · evidence and replay ·
false-positive-safe reporting. *A hosting platform being detected creates a lead. Only an authorized
deterministic test proves a vulnerability.* This is the same rule `proof_schema.demote_unproven`
already enforces — route technology candidates through it rather than around it.

**Planner priority**: detection confidence · version confidence · CVSS and technical impact · KEV
status · exploit prerequisites · authentication requirements · reachability · whether a deterministic
oracle exists at all · scope and safety · expected information gain.
**Anti-spam (hard requirement)**: hundreds of theoretical CVEs against an unknown version must never
flood the queue or the report. An unknown version yields at most one `POTENTIALLY_AFFECTED` row per
product, not one per CVE.

**Engine requirements**: dedupe identities across detectors · map aliases safely (`dependency_intel`
already has `_FLEX_ALIAS`/`_CDN_NAME_FIX`) · understand version ranges · record database source and
update time · handle conflicting advisories · cache feeds with provenance · **re-evaluate existing
facts when feeds update** · route actionable candidates into the planner · keep unproven matches out
of confirmed reports · show technology, version confidence, advisory match, proof status and evidence
in the UI.

**Breaker must attack**: false matches · spoofed banners · **backported patches** (Debian/RHEL ship a
patched 1.2.3 that every version-range check calls vulnerable — this is the single largest FP source
in the whole class) · ambiguous versions · duplicate CVEs across feeds · stale advisories.

**Negative controls**: (a) a target running a **patched** version of a detected product yields zero
advisory matches; (b) a product detected with `LOW` version confidence produces
`POTENTIALLY_AFFECTED` and **zero** confirmed findings, no matter how many CVEs the feed returns;
(c) a spoofed `Server:` banner claiming an ancient version, with the real behaviour of a current one,
must not confirm.

**Acceptance gate**: Apolaki detects a component, produces evidence for its identity *and* version
confidence, maps only applicable advisories, schedules an authorized targeted probe, confirms or
rejects deterministically, and never reports a database match alone as proven.

**Files**: `agent/fingerprint.py`, `agent/dependency_intel.py`, `agent/intel_feeds.py`,
`agent/intel_registry.py`, `agent/technique_planner.py`, `agent/engine_descriptor.py`, the graph and
the UI coverage view.
**Dependencies**: sequence **after Q-019** — a technology fact is worthless if the crawl only reaches
36 URLs, and cycle-2 recrawl depends on the same `_surface_crawl` path Q-019 repairs.
**Role split**: Watcher identifies trustworthy ecosystem databases (licence, update cadence,
machine-readable format, provenance) · Analyst rejects low-quality or unmaintained feeds · Coordinator
splits this into dependency-ordered sub-tickets (it is too large for one commit) · Builder integrates
into recon and the canonical graph · Breaker attacks the FP list above · Conductor verifies
fingerprinting → enrichment → planning → probing → evidence → UI → reporting is ONE pipeline.

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

## Distillation verification pass — 2026-08-10 (Analyst)

Q-007 / Q-008 / Q-009 were **assertions from an audit**. Every one is now settled MEASURED or
DISPROVED against the live code, the running platform (`apolaki-agent-1`) and all 151 stored missions.
Verdicts are evidence, not state — the Coordinator still owns state.

| claim | verdict |
|---|---|
| Q-007 `weak_password_reset` has no production executor | **MEASURED — true** |
| Q-008 `run_mass_assignment` absent from the name table | **MEASURED — true, and 5 more names with it** |
| Q-009 retest scope guard fails open | **DISPROVED in practice** — guard active on 151/151 missions |
| Q-009 `PUT /findings` bypasses `findings_gate` | **MEASURED — true, all three invariants, live** |
| Q-009 lead-confirmation is immediately demoted | **MEASURED — true**, plus a second defect beside it |
| Q-009 `get_logs` oldest-first | **MEASURED — true; the stated 4000-cap consequence DISPROVED** |
| Q-009 `risk_signals` unfiltered twin | **MEASURED — true** |
| Q-009 `_read_controls` returns `[]` on failure | **MEASURED — true** |

**Q-007 recommendation: STRIP, do not build.** Reasons, in order of weight.
1. Orchestration is the measured bottleneck this cycle (see Q-019). A new CWE-640 engine is the
   lowest-value thing that could be added.
2. `weak_password_reset` is the **only** `invalidates` entry in the whole `EFFECTS` table, so it is the
   sole source of every row `conflicts()` returns — the entire Sussman-anomaly demonstration rests on
   an engine that does not exist. That is worse than having no negative-effects model.
3. The honest move keeps the model: drop it from `PRECONDITIONS` and `EFFECTS`, set
   `solver_only=True` (the field exists; `technique_status()` already returns `solver_only` for it),
   and **re-home `invalidates: ["authenticated"]` onto Q-001's session-lifecycle engine**, which
   really does destroy a session. Q-001 is Rank-1 ready, so the negative-effects half of T6 survives
   on a technique with a real executor. Dependency: Q-001.

**Q-008 direction: it UNDER-reports ASVS and OVER-reports WSTG — the same missing engine, both ways.**
`_engine_ran()` returns False for an unresolvable name, so status falls to `not_tested`, which is
strictly conservative — an unresolvable name can never manufacture a "verified". But `violated_by` is
independent of `engine`, so a real finding still fails the objective. Net: ASVS under-reports.
Meanwhile `wstg_catalog.FULL["WSTG-INPV-20"] = "mass_assignment (authz)"` claims **full** coverage for
the same non-existent engine, and that entry is inside the published `full_pct: 52.3`.

---

## Rank 3b — proposed (Distillation, 2026-08-10). All `proposed`; Coordinator ranks.

**Ranking rationale, stated because the assignment demanded it.** Mission `90cee81c` ran 3720s against
1415 known-vulnerable cases and returned 2 findings, while the same target scores 41.3% when engines
are handed case URLs directly. I measured where the mission actually loses the target (Q-019) and it is
neither the engines nor — contrary to the standing belief — the crawler. **Every ticket below is
wiring, orchestration or reporting-integrity. None is a new engine. Q-019 should outrank Q-001…Q-006.**

### Q-019 (original filing, retained for its measurements) · **CLOSED** `55c035b` · see the Rank 0 entry
NOT a second ticket. This is the original Q-019 body; the live header is at Rank 0 above. It is kept
because it carries the baseline measurement of mission `90cee81c` that the fix was scored against, and
deleting it would delete the before-figures. Its state is whatever the Rank 0 header says.
- **MEASURED**, mission `90cee81c` (908 log rows, replayed from the persisted event log):
  ```
  Surface crawl: probed 12 page(s), surface 5 -> 2756 URL(s)
  tool_call events            : 433        scope_block events : 34
  DISTINCT URLs any tool_call aimed at : 66
  DISTINCT URLs http_probe/http_read touched : 36
  run_xss 45 · run_xpath 32 · run_ldap 32 · run_ssi 32 · run_sqli 20 · run_sqli_structural 20
  findings: 2  (jquery CVE + a credential in a comment — both from JS recon on the index page)
  ```
- **This retires the standing belief that surface discovery is the gap.** S11b/S11c/S11d are genuinely
  fixed: the crawl found all 2740 test cases plus the indexes. The surface is 2756. The scan probed 36.
- **Three compounding root causes, each independently measured:**
  1. **Hostless URLs poison the surface.** 10 of the 36 probed URLs are
     `https:///benchmark/cmdi-Index.html` — scheme `https`, **empty netloc**. Measured:
     `urljoin("https://", "/benchmark/x.html") == "https:///benchmark/x.html"`, and
     `ScopeEngine.validate()` correctly answers `(False, 'Invalid target')`. So the crawl aimed at the
     category index pages — *the exact pages that link to all 2740 test cases* — with a broken URL and
     scope refused every one. That is the 34 `scope_block` events. `crawl.parse_sitemap` reproduces the
     same shape when its `at` argument is hostless. **The scope engine is behaving correctly; the
     producer is handing it garbage, and nothing names the producer.**
  2. **A URL only becomes an injection target if it was FETCHED.** `agent.sweep_targets` keeps a URL
     only when `"?" in u`, plus pages carrying a captured form. The 2740 discovered links are plain
     `.html` with no query, so a discovered-but-never-fetched URL can never reach an engine. Coverage
     is therefore O(pages fetched), not O(surface discovered).
  3. **`_surface_crawl` is capped at `depth(2) x frontier(30)` = 60 visits** against a 2756-URL
     surface, and only 12 survived (1). The cap is defensible per-round; being the *only* gate between
     a 2756-URL surface and the engines is not.
- **Producer/consumer contract**: producer = `_surface_crawl` / `_http_probe` / `crawl.parse_*`
  writing into `tools._add_urls`; consumer = `sweep_targets` and the probe phase. The contract that
  does not exist today: *a URL admitted to the surface has a host, and a URL on the surface is a
  candidate target whether or not it was fetched.*
- **Oracle (deterministic)**: re-run the same mission against `owaspbench`; assert
  (a) **zero** surface URLs with an empty `urlparse(u).netloc`, (b) `scope_block` count drops to 0 for
  hostless causes, (c) distinct URLs reaching `http_probe` rises above 200, (d) findings > 2.
- **Negative control**: a mission against a **single-page** in-scope target must NOT gain targets —
  proves the change widens reach from real discovery and does not invent URLs. Plus: a genuinely
  out-of-scope host must still be `scope_block`ed, proving (1)'s fix did not weaken the scope gate.
- **Tests / mutations**: unit — `_add_urls` rejects `https:///x` and records it via `_swallow` naming
  the producer; mutation — reintroduce the hostless URL and the assertion must fail. Whole-product —
  the missing test named in `CODEBASE_REVIEW` S11b: engage against a standing lab, assert findings > 0
  **and** assert `probed >= N`, because findings > 0 already passes today on 2 incidental findings.
- **Files**: `agent/agent.py` (`_surface_crawl`, `sweep_targets`), `agent/crawl.py`, `agent/tools.py`
  (`_add_urls` ingress guard). Overlaps `tools.py`, owned elsewhere this cycle — sequence after it.
- **Dependencies**: none. **Definition of done**: the four oracle assertions above, both negative
  controls, and the whole-product smoke test in the suite.

### Q-020 (original filing, retained for its measurements) · **CLOSED** `7a73f7b` · see the entry above
NOT a second ticket. The live header is above. Kept for the `_REQUIRED`-field measurement that
established the root cause. Its state is whatever that header says.
- **Root cause, and it is the parent of Q-007, Q-008 and Q-011.** MEASURED: `techniques._t()` has no
  `engine` field — `_REQUIRED` is `(id, vuln_class, cwe, owasp, permission, summary, detect, exploit,
  oracle, transferable)` and none of the `setdefault`s adds one. Nothing anywhere maps a technique to
  the tool that runs it. So `orchestration_audit()` can only ask *"is this id present in
  `PRECONDITIONS` or `ALWAYS_ON`?"* — a declaration — and answers `islands: []` for 41 gated + 45
  always-on techniques including two proven phantoms.
- **The asymmetry is already half-fixed and nobody noticed.** `engine_descriptor.verify_always_on()`
  exists precisely to check the FACT behind the declaration, and MEASURED it iterates
  `sorted(ALWAYS_ON.items())` only: `checked: 45, unwired: [], ok: True`. It fact-checks 45 of 86
  techniques and **0 of the 41 evidence-gated ones**. Every phantom found so far is on the unchecked
  side. This is the recorded "guards that check declarations, not facts" failure mode, one branch deep.
- **Honest scoping — I am not accusing 39 techniques.** A name heuristic flags 33 gated techniques with
  no `run_<id>` engine, but the heuristic is wrong: `sqli_auth_bypass` -> `run_auth_sqli`,
  `idor_bola_read` -> `confirm_idor`, `xxe_file_ssrf` -> `run_xxe` all have real engines under other
  names. Exactly **2** are MEASURED phantoms (Q-007, Q-011). The other 31 are **UNDETERMINED**, and
  making them determinable is the whole point of this ticket.
- **Producer/consumer contract**: producer = the technique record gains `engine: <tool name | tuple>`;
  consumer = `orchestration_audit` and a new `verify_gated()` mirroring `verify_always_on`, plus
  `asvs_model` and `wstg_catalog` which can then resolve against ONE table instead of hand-copied
  strings (Q-011).
- **Oracle**: for every auto + oracle + transferable technique, its declared `engine` resolves to a
  name in `TOOL_PERMISSIONS` or `CLAUDE_TOOLS` **and** to a real `_<name>` method. Fails today on
  `weak_password_reset` and `mass_assignment`; must be green after Q-007 and Q-011 land.
- **Negative control, mandatory — this is the exact bug being fixed**: a **non-vacuity** assertion
  (the scan must have checked > 0 techniques; a scan over an empty set passes for free) **and** a
  mutation that points one technique's `engine` at `run_does_not_exist` and requires the guard to fail.
  `tests/test_engine_reachability.py` already carries the non-vacuity pattern — reuse it.
- **Files**: `agent/techniques.py`, `agent/engine_descriptor.py`, `agent/technique_planner.py`,
  `agent/tests/test_engine_reachability.py`. **Blocks**: Q-007, Q-011, Q-012.

### Q-011 · `mass_assignment` is the SECOND phantom — same shape, same backfill · **HIGH** · `proposed`
- **MEASURED**: no mass-assignment executor exists anywhere. `def .*assign` in `tools.py` -> nothing;
  the only code that ever over-posts a privileged attribute is `juiceshop_solvers.py:67`
  (`_register(c, ..., role="admin")  # Admin Registration`) — the **lab solver**, exactly as with
  `weak_password_reset`. And `_JUICESHOP_PROVEN["mass_assignment"] = ["Admin Registration"]` backfills
  the solver's behaviour onto the technique, again exactly as with `weak_password_reset`.
- Meanwhile it is declared live in three places: `engine_descriptor.PRECONDITIONS` (`has_api`),
  `asvs_model` ATHZ-04 (`run_mass_assignment`), and `wstg_catalog.FULL["WSTG-INPV-20"]`.
- **This reverses a standing QUEUE rejection.** The `rejected` list says "mass assignment as a
  *technique*" is already covered. Measured: the technique record is covered; the capability is not.
- **Decision, consistent with Q-007**: this one is worth BUILDING rather than stripping — unlike
  `weak_password_reset` it needs no email/reset flow, the oracle is clean, and it is a whole OWASP
  API-Top-10-adjacent property that currently reads as covered in two published catalogs.
- **Oracle (deterministic, byte-observable)**: create or update an object with an extra privileged
  attribute (`role`/`isAdmin`/`deluxeToken`), then **read the object back** and assert the injected
  attribute persisted with the injected value. Persistence on readback, not a 200.
- **Negative control**: the identical write with a **nonsense** attribute name (`apolaki_marker_xyz`)
  must NOT appear on readback — proves the server is not simply echoing every field, which is the
  single false positive this class produces. Second control: the same readback before the write.
- **Non-destructive**: NO — it writes. Ship on a self-created object only (`register.py` /
  `create_object_idor.py` already mint sacrificial objects), never on a discovered third-party object.
- **Files**: new `agent/mass_assignment_tool.py`, wired in `agent/tools.py` as `run_mass_assignment`
  (the name both catalogs already expect), `techniques.py`, `engine_descriptor.py`.
- **Dependencies**: Q-020 for the `engine` field. **Definition of done**: engine live in a real
  mission, liveness check added, ATHZ-04 reaches `verified` on a clean paired lab, WSTG-INPV-20's
  `FULL` claim becomes true rather than aspirational.

### Q-012 · Six ASVS engine names resolve to nothing; two objectives can never be verified · **MEDIUM** · `proposed`
- **MEASURED** (cross-check of `asvs_model.OBJECTIVES` against `tools.TOOL_PERMISSIONS` (111 keys) +
  `CLAUDE_TOOLS` (77 names) + 201 methods):
  ```
  UNRESOLVABLE: ['authz_matrix', 'bizlogic_graph', 'dependency_intel',
                 'header_analysis', 'run_deser', 'run_mass_assignment']
  assess(findings=[], attempted_engines=EVERY registered tool name)
    tally  {'verified': 27, 'attempted': 1, 'failed': 0, 'not_tested': 3, 'blocked': 2}
    still not_tested with a PERFECT run: ['AUTHN-04', 'ATHZ-04', 'BUSL-01']
  ```
- `authz_matrix` is the instructive one and it is why this needed measuring twice: the engine **is**
  real and **is** dispatched — as `run_authz_matrix` (`TOOL_PERMISSIONS:168`, `agent.py:1863`). It
  returns `ToolResult("authz_matrix", ...)` at `tools.py:1831,1998`, but the ledger records the
  *dispatch* name, not the ToolResult name, so the ASVS spelling never matches. A pure name drift.
- **Net effect**: ATHZ-04 (mass assignment) and BUSL-01 (business logic) are permanently
  `not_tested` — a hard **6.1-point** ceiling (2/33) on `verified_pct`, in the conservative direction.
  AUTHN-04 is `verifiable: False` so its unresolvable name is harmless.
- **The over-report half**: `wstg_catalog.FULL["WSTG-INPV-20"] = "mass_assignment (authz)"` claims
  **full** coverage for the engine that does not exist, inside the published `full_pct: 52.3`.
  Also `FULL["WSTG-IDNT-02"] = "create_account / registration engine"` — `create_account` resolves to
  no registered tool either (`register.py` exists; confirm the live name before touching this one).
- **Oracle**: a test asserting every non-`n/a` `engine` name in `asvs_model.OBJECTIVES` and every
  `run_*`/`confirm_*`/`check_*` token in `wstg_catalog.FULL` resolves against the ONE table Q-020
  introduces. Green only after the six names are corrected.
- **Negative control**: the same test must FAIL when a deliberately bogus name is injected — and a
  non-vacuity assertion, because the WSTG half of this check silently scanned 0 tokens on my first
  attempt (I pointed it at `CATALOG` instead of `FULL` and it reported a clean "none" over an empty
  set — the exact vacuous pass this control exists to catch).
- **Files**: `agent/asvs_model.py`, `agent/wstg_catalog.py`, `agent/tests/test_asvs_model.py`.
  Note `tests/test_asvs_model.py:78` already puts `run_mass_assignment` in a `ran` set — a test
  asserting behaviour for a name that can never appear in a real ledger.
- **Dependencies**: Q-020 (the table), Q-011 (so ATHZ-04/WSTG-INPV-20 become true rather than deleted).

### Q-013 · `PUT /findings` bypasses all three `findings_gate` invariants · **HIGH** · `CLOSED` 3addb1c + 42e1544
**Closed in two passes, and pass one was not enough.** `3addb1c` routed `db.update_finding` through
`db._gate`, which is the right chokepoint and covers `agent._triage` and `capture_finding_poc` too.
Then the gate lane asked whether the three invariants actually protect the proof, and measured that
**none of them reads `evidence`** — the field `validate_confirmed` judges. Post-`3addb1c`, a PUT that
put a gate-demoted row back with fabricated prose still returned `is_confirmed: True` with no engine
having issued a single request. `42e1544` made PUT annotation-only against a **whitelist** — a
blacklist leaves every future proof field editable, which is exactly how this survived pass one — and
closed the DELETE+POST route a PUT-only fix would have left open.


- **Root cause**: `db.add_finding` is documented as "the single write chokepoint" and enforces
  schema/scope/truth. `db.update_finding` (`db.py:222`) issues a raw
  `UPDATE findings SET data=?` and calls none of it. `PUT /findings/{sid}/{fid}` (`main.py:3118`)
  and `POST /findings/{sid}/{fid}/poc` both go through it.
- **MEASURED live** against the running platform on a throwaway mission scoped to
  `http://apolaki-testbox:80` (mission deleted afterwards). Each row is a paired test:

  | invariant | POST — gate runs | PUT — gate skipped |
  |---|---|---|
  | SCHEMA #6 | `"1) do a 2) do b"` -> `["do a","do b"]` | persisted as the raw string |
  | SCOPE #8 | off-scope target -> `{"id":""}`, refused | `http://evil.example.com/off-scope` persisted |
  | TRUTH #7 | `confidence:"lead"` -> routed to the leads list | lead-confidence row sits in the findings table |

  The POST column IS the negative control: all three invariants demonstrably fire on the sibling path,
  so the PUT failures are the gate being absent, not the gate being wrong.
- **Composed impact**: severity was also escalated `high -> critical` and `finding_counts()` is
  ungated, so the mission-list badge moves. An off-scope row written this way then reaches `/retest`,
  which is only stopped by the scope guard Q-018 shows is one exception away from being disabled.
- **Fix contract**: route `update_finding` through `findings_gate.normalize` + `off_scope` + `is_lead`,
  or give it an explicit `gated=True` default with the raw path renamed so a bypass must be deliberate.
- **Oracle**: the table above, as three assertions, replayed against the API.
- **Negative control**: the POST column must stay green — proving the change did not just delete the
  distinction. Plus a legitimate PUT (valid list, in-scope target, `confidence: confirmed`) must still
  succeed unchanged.
- **Files**: `agent/db.py`, `agent/main.py` (owned elsewhere this cycle — sequence it).

### Q-014 · Operator lead-confirmation is silently re-demoted, and gate-routed leads cannot be confirmed at all · **HIGH** · `CLOSED` a1cdb8d + report rendering
**The design answer, which is the durable part:** operator confirmation is an **attestation on its own
axis** — who, when, why — and never a value of `confidence`. The tempting fix was to let an operator's
own text satisfy `validate_confirmed`; the lane rejected it because that contract is a **substring
match over prose**, so it would award `confirmed` for vocabulary and teach people which words to type.
A lead is released to confirmed only when the lead's own engine-produced evidence satisfies the
oracle. What this costs, plainly: manual findings now land under Unconfirmed Leads, confirmed counts
drop, and `risk_score` no longer takes severity from them.


Two defects in the same handler. The second is not in the Q-009 list; I found it while proving the first.
- **(a) The confirmation is discarded.** MEASURED, replaying the exact dict `main.py:confirm_lead`
  builds from a realistic IDOR lead:
  ```
  operator clicked CONFIRM. stored confidence = confirmed
  proof_schema.validate_confirmed -> False ['impact', 'evidence_signal:owner', 'evidence_signal:denied']
  after db.get_findings_gated  -> confidence = lead
                                  tags = ['operator-confirmed','needs-confirmation','proof-incomplete']
  ```
  `confirm_lead` never builds an `impact` field, and never requires the lead's `evidence` to carry the
  family's proof signals — so for any family in `proof_schema._DEFAULT_ENFORCE`
  (`idor`, `access_control`, `missing_authentication`, `bola_idor`, `bfla`) the endpoint returns
  `{"ok": true, "finding_id": ...}` and the report shows a lead. The human said "I proved this" and the
  platform silently disagreed. **Negative control, run**: the same finding with `family="xss"`
  (not enforced by default) survives as `confirmed` — so the mechanism is the family gate, not a
  universal reject.
- **(b) Leads created by `db.add_lead` are unaddressable.** MEASURED live: `db.add_lead` stamps
  `lead["id"]`; `confirm_lead`/`dismiss_lead` match on `lead["_lid"]`, which only `main.py:2169` sets.
  `POST /leads/{sid}/nc-lead/confirm` -> **HTTP 404**, and `GET /leads/{sid}` still lists it. Every
  lead that reached the list via the `findings_gate` TRUTH-#7 routing path — i.e. every engine-produced
  lead-confidence finding — is permanently stuck: 404 on confirm, 404 on dismiss.
- **Fix contract**: (a) `confirm_lead` must either collect the operator's `impact` + evidence and
  re-validate before writing, or write `confidence: "operator_confirmed"` as a first-class value the
  proof gate honours — the operator IS the proof for a lead. Decide explicitly; do not paper over it.
  (b) match on `_lid` **or** `id`, and make `add_lead` stamp both.
- **Oracle**: (a) confirm an `idor` lead; `get_findings_gated` must return it confirmed. (b) confirm a
  lead created by `db.add_lead`; must return 200 and remove it from `GET /leads`.
- **Negative control**: (a) a lead confirmed with **no** operator evidence must still be demoted —
  otherwise the fix has deleted the proof gate rather than taught it about operators. (b) confirming a
  `lid` that exists in no mission must still 404.
- **Files**: `agent/main.py`, `agent/db.py`, `agent/proof_schema.py` (all owned elsewhere — sequence).

### Q-015 · `risk_signals` is the unfiltered twin of `risk_score` · **MEDIUM** · `proposed`
- **Root cause**: `report.risk_score` was fixed to filter demoted rows ("THE FILTER IS THE CONTRACT,
  and it was missing"). `report.risk_signals` computes the same quantity 40 lines later and did not
  get the filter: `conf_load = min(100, sum(_SEV_WEIGHT... for f in findings))` — no confidence test —
  and stamps `basis: f"{len(findings)} confirmed finding(s)"`, labelling demoted rows as confirmed.
- **MEASURED**, one gated list, both functions:
  ```
  risk_score(gated)       -> {'score': 0, 'label': 'No Confirmed Risk'}
  risk_signals(gated)[0]  -> {'label': 'Confirmed vulnerability load', 'pct': 25,
                              'basis': '1 confirmed finding(s), severity-weighted'}
  ```
  The same report contradicts itself: headline "No Confirmed Risk", executive dashboard "25% confirmed
  vulnerability load, 1 confirmed finding".
- **Negative control, run**: a genuinely confirmed high scores 25 in *both* — the two agree whenever
  the input is honest and diverge only on demoted rows, which localises the defect to the filter.
- **Fix contract**: both must consume one shared confirmed-only projection. `proof_schema.is_confirmed`
  already exists and was created for exactly this ("three private copies is how the HTML report came to
  stamp CONFIRMED on rows the proof gate had already demoted") — this is the fourth copy.
- **Oracle**: the two-line comparison above, as an assertion, on a demoted list.
- **Negative control**: the confirmed-input case must stay equal — proves the fix did not zero the
  signal. Mutation: re-remove the filter and the assertion must fail.
- **Files**: `agent/report.py` (owned elsewhere this cycle — sequence it).

### Q-016 · `bie._read_controls` returns `[]` on failure — BIE phase 2 cannot report that it went dark · **MEDIUM** · `proposed`
- **Root cause** (`bie.py:1475`): `except Exception: return []`. Every caller path then reads a clean
  empty result — `classify_controls([])` -> `counts.total = 0` -> `probe_targets` returns nothing ->
  phase 2 (CWE-602 client-side authz) emits **zero probes and zero findings**, and the report prints
  `control_surface.counts.total: 0`. A `page.evaluate` that threw is byte-identical to a page that
  genuinely renders no controls.
- **This is S12c at a different layer, and the fourth instance of the shape** (`DOM_SCAN_JS`,
  `parse_qsl`, S12c `localStorage`, now this). `CONTROL_SURFACE_JS` (`bie.py:934`) is a single
  dependency of exactly the kind that went missing in the `DOM_SCAN_JS` case.
- **The idiom already exists in this file**: `_fetch` (12 lines below) returns
  `... | {"error": str(e)[:160]}` on the same failure. `_read_controls` should record the same way.
- **Oracle**: force `page.evaluate` to raise; the run must report a control-surface **error**, not
  `total: 0`, and phase 2's verdict must be `lead`/inconclusive rather than silent-clean.
- **Negative control**: a page that genuinely has zero controls must STILL report `total: 0` with no
  error — the whole point is telling the two apart, and a fix that flags both is no fix.
- **Files**: `agent/bie.py` (owned elsewhere this cycle — sequence it). Composes with `#54`: the
  `tools._swallow` ledger is the natural sink.

### Q-017 · `get_logs` is oldest-first with a LIMIT, so the mission view and the backup export drop the newest events · **LOW** · `proposed`
- **MEASURED**, all 151 stored missions. The claimed consequence is **half disproved**:
  - `db.get_logs`: `ORDER BY id LIMIT ?` keeps the **oldest** n rows. Confirmed on mission `54155d4b`
    (1287 rows): `get_logs(limit=500)[-1].ts = 22:31:01` vs the true last event `22:35:20`.
  - **DISPROVED**: the 4000-row caps at `_tool_ledger` (`main.py:694`) and `asvs_coverage`
    (`main.py:1251`) have **never truncated** — the largest mission ever recorded is 1287 rows, and
    distinct tool names visible at `limit=4000` equals the unbounded count (49 = 49, 0 lost). The
    "ASVS under-reports because of log truncation" theory does not hold today.
  - **CONFIRMED and firing**: the 500-row caps at `main.py:551` (`GET /missions/{sid}` — the UI's
    mission detail) and `main.py:3304` (`GET /backup/{sid}`) truncate on **12+ missions**, dropping
    259–787 of the most recent events. For a backup that is data loss on export.
- **Adjacent, same handler, worth folding in**: `mission_detail` and `/backup` both call
  `db.get_findings` (RAW, ungated) — `get_findings`' own docstring says to prefer the gated accessor
  for "anything a human or a model will read". Needs a UI check before it is called a defect; I did
  not run one, so this half is **UNVERIFIED**.
- **Oracle**: on a mission with > 500 log rows, the newest event's timestamp appears in the response.
- **Negative control**: a mission with < 500 rows returns byte-identical output to today.
- **Files**: `agent/db.py`, `agent/main.py` (owned elsewhere — sequence it).

### Q-018 · Retest scope guard — DISPROVED as a live defect; hardening only · **LOW** · `proposed`
Filed so it is not re-raised as a CRITICAL. **Do not treat the audit's framing as fact.**
- **MEASURED**: replayed `main.py:2578-2602` verbatim against the real `scope` dict of **all 151**
  stored missions.
  ```
  element type handed to load_manual : {'str': 151}
  GUARD ACTIVE                       : 151
  GUARD OFF (load_manual raised)     : 0
  GUARD OFF (no in_scope)            : 0
  ```
  Negative control: three sampled active guards all answer
  `validate('http://evil.example.com/x') -> False`. `in_scope` is a required field on
  `EngageRequest`, so the unscoped branch is unreachable through the product.
- **What survives**: two `_eng = None` paths silently *disable* a safety guard instead of refusing to
  retest. Reachable only with a non-string element in `scope["bases"]`/`["in_scope"]` — measured:
  `load_manual([{'nested':'dict'}])` raises `AttributeError: 'dict' object has no attribute 'strip'`,
  and `main.py` turns that into an unguarded retest. Latent, never fired.
- **Fix contract**: fail **closed** — if the mission is scoped and the engine cannot be built, every
  retest returns `inconclusive: "scope engine unavailable"`. Never proceed unguarded.
- **Oracle**: inject a dict into `scope["bases"]`; every retest must return `inconclusive`, not a GET.
- **Negative control**: a normal mission's retest behaviour must be byte-identical to today.
- **Files**: `agent/main.py` (owned elsewhere — sequence it).

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

---

# Codex claim verification — pass 2 (Analyst, 2026-08-10)

The five claims already settled in [CODEX_AUDIT_VERDICTS.md](CODEX_AUDIT_VERDICTS.md) are **not**
re-verified here. What follows is the remaining eight, each with the command output that settles it.
Environment: `apolaki-agent-1` healthy, **no mission running**, 151 stored missions / 29,109
`tool_call` rows / 64,513 log rows in `/app/data/bbh.db` (read-only `mode=ro` connections throughout).

| # | Codex claim | verdict |
|---|---|---|
| 1 | `run_whatweb` is an isolated island | **CONFIRMED-WITH-CORRECTION** — reachable, never scheduled, output never normalized |
| 2 | `browser_engine.to_observations()` drops `framework` | **CONFIRMED** |
| 3 | `codeintel.versions` is ignored by mission code | **CONFIRMED** |
| 4 | NVD/GHSA/CVE-v5 end in an in-memory registry with no consumer | **CONFIRMED, and worse than stated** |
| 5 | `asset_graph.build_from_engagement()` never projects recon technology | **CONFIRMED, and worse than stated** |
| 6 | No `vulnerable_component` route in `candidate_pipeline._ROUTES` | **CONFIRMED, but unreachable until Q-021A** |
| 7 | `report.proof_and_retest()` asserts a control it never checked ran | **CONFIRMED — 626 of 660 stored findings** |
| 8 | `test_asset_graph.py:106` injects a synthetic version | **CONFIRMED** |

### 1 · `run_whatweb` — CONFIRMED-WITH-CORRECTION. Two of Codex's sub-claims are wrong.

Both emitter tables were checked, per the standing "wrong by nine" rule.

```
tools.py:72    TOOL_PERMISSIONS["run_whatweb"] = PermissionLevel.ACTIVE     <- table 1: present
tools.py:396   CLAUDE_TOOLS  {"name": "run_whatweb", ...}                   <- table 2: present
tools.py:3493  async def _run_whatweb(...)                                  <- getattr("_" + name) resolves
agent.py:76    PHASE_OF["run_whatweb"] = "enum"                             <- UI phase mapping
$ docker exec apolaki-agent-1 which whatweb
/usr/bin/whatweb                                                            <- the binary IS installed
$ grep -n whatweb agent/planner.py
(no output)                                                                 <- never scheduled
```

- **WRONG**: "isolated island". It is in *both* dispatch tables with a real `_run_whatweb` method, so
  an agentic model can call it. It is not unreachable.
- **WRONG**: the implied "the binary is missing". `/usr/bin/whatweb` exists in the image.
- **RIGHT, and this is the real defect**: nothing deterministic ever calls it, and its output goes
  nowhere. `_run_whatweb` returns `ToolResult("whatweb", ..., findings=[raw JSON])` and, unlike
  `_run_fingerprint` which at least writes `lh["tech"]`, **writes nothing into `self.recon`**. It is
  absent from `_AUTO_STORE_TOOLS`, from `asvs_model`, and from `wstg_catalog`.
- **MEASURED consequence**: `run_whatweb` calls across 151 missions and 29,109 `tool_call` rows = **0**
  (`run_fingerprint` = 2,641 over the same corpus).

**Correct one-line statement**: *`run_whatweb` is a model-only tool with no normalizer, so in 151
deterministic missions it has never run and could not have contributed if it had.*

### 2 · `browser_engine` drops `framework` — CONFIRMED

`browser_engine.py:53` computes it in-page (`window.angular` / React roots / `window.Vue`), `:56`
returns it, `:89` declares it in the empty-result shape. `grep -n framework agent/browser_engine.py`
returns lines **8, 53, 56, 89 only** — `to_observations()` (`:177`) never mentions it, and neither
does `agent.py:_browser_harvest_surface`. `grep framework agent/technique_planner.py
agent/asset_graph.py agent/planner.py` returns **no output**. The sensor detects the SPA framework and
no consumer exists.

### 3 · `codeintel.versions` ignored — CONFIRMED

`codeintel.py:236` `out["versions"] = sorted(versions)[:50]` (mined at `:166` by an `name@x.y.z` regex
over served JS). Consumers:

```
$ grep -rn '["versions"] | get("versions")' agent/*.py | grep -v test
agent/codeintel.py:236        <- the write
agent/intel_connectors.py:182 <- unrelated (GHSA advisory.affected[].versions)
```

`agent._recon_code_intelligence` (`agent.py:1034-1094`) reads `endpoints`, `sensitive_routes` and
`logic` and nothing else; `technique_planner.derive_observations` reads `ci["endpoints"]`,
`ci["sensitive_routes"]`, `ci["bundles"]`, `ci["counts"]`. **A component+version harvested from the
target's own JS is computed on every non-passive mission and discarded** — the same stage-2 loss the
baseline recorded for `fingerprint`, in a second producer.

### 4 · Intel connectors terminate in an in-memory registry — CONFIRMED, and the island is deeper

`intel_connectors._PARSERS` normalizes `epss / nvd / ghsa / cve_v5 / cisa_kev` (`:134-204`). The only
consumer chain in the repo:

```
$ grep -rn "intel_connectors / intel_registry" agent/*.py  (excluding the modules themselves)
agent/main.py:2785  /intel/audit
agent/main.py:2790  /intel/registry        (stats only)
agent/main.py:2803  /intel/fetch/{source}  -> _ir.ingest(...)
```

Three read-only HTTP endpoints. No scan, planner, report, SARIF or graph consumer. Three additional
facts Codex did not state, each of which makes the ticket smaller and more honest:

```
$ docker exec apolaki-agent-1 python -c "intel_sources.allowlist(); intel_registry.stats()"
allowlist: all 18 sources -> enabled=False   (cve_v5, nvd, cisa_kev, epss, ghsa, cert_cc, ... all off)
registry stats: {'total': 0, 'by_state': {}}   production: 0
```

- Every source is **disabled by default**, and `fetch()` hard-gates before any network I/O.
- `intel_registry._STORE` is a module-level dict — **not persisted**; a container restart erases it.
- `intel_registry.advance()` is called **only from `agent/tests/test_intel_registry.py`**. There is no
  endpoint and no code path that promotes a record. So `production()` — documented as "the only
  trusted knowledge safe to drive engines" — is **structurally always empty**. Even a fully wired
  consumer would read `[]`. **Q-021D must therefore ship the promotion path, not just a consumer.**

### 5 · `asset_graph` never projects recon technology — CONFIRMED, and `recon=` is a dead parameter

Every occurrence of the name `recon` inside `build_from_engagement`, dumped from the live module:

```
$ docker exec apolaki-agent-1 python -c "inspect.getsource(asset_graph.build_from_engagement)"
  1 def build_from_engagement(mission_id, *, recon: dict = None, ...)   <- the parameter
 12 recon, urls, findings = recon or {}, urls or [], findings or []      <- the default coercion
 24 25 28 30 32 34 35 79   source="recon"                                <- string literals only
```

The `recon` argument is accepted, defaulted, and **never read**. It is not merely that technology goes
unprojected — no part of `tools.recon` reaches the canonical graph through this function.

Warm start, same claim, also CONFIRMED — but note what already works, because Q-021B must not rebuild
it: `memory.py:112-119,173,185,211` **does** collect and persist `tech` across missions.

```
sqlite> select kind, count(*) from memory_assets group by kind
endpoints 3156 | tech 13 | hosts 10 | subdomains 8
```

`main.py:_warm_start` (`:199-238`) reads `assets["subdomains"]`, `assets["hosts"]`,
`assets["endpoints"]` and `db.get_prior_snapshot` — **never `assets["tech"]`**. Technology is written
to cross-mission memory and never read back.

**NEW DEFECT, not in the Codex audit — the persisted `tech` is partly garbage prose.** 6 of the 13
stored rows are English sentence fragments:

```
sqlite> select target_key, value from memory_assets where kind='tech'
('js-bench:3000',   'a MultiJuicer Kubernetes cluste')
('js-bench:3000',   'in safety mode')
('js-bench:3000',   'on.')
('juice-shop:3000', 'a MultiJuicer Kubernetes cluste')   ...
```

Producer identified and reproduced byte-for-byte offline:

```
fingerprint.py:71   _POWERED = re.compile(r"(?:powered by|built with|running)\s+([A-Za-z][\w .\-]{2,30})", re.I)
fingerprint.py:108  out.append({"name": m.group(1).strip(), ..., "category": "generic"})

>>> fp.fingerprint({}, '', "<p>You are running a MultiJuicer Kubernetes cluster instance.</p>"
...                        "<p>The application is running in safety mode.</p><p>Continue running on.</p>")
[{'name': 'a MultiJuicer Kubernetes cluste', 'source': 'powered-by text', 'category': 'generic'},
 {'name': 'in safety mode.', ...},
 {'name': 'on.', ...}]
```

The `{2,30}` bound truncates mid-word at exactly 31 characters, which is why the stored value ends
`...cluste`. **This is a hard input-quality gate for Q-021B/C/D**: a TechnologyFact keyed on
`a MultiJuicer Kubernetes cluste` would be sent to NVD/OSV as a product name.

### 6 · No `vulnerable_component` route — CONFIRMED, but it is unreachable today

`candidate_pipeline._ROUTES` (`:59-72`) has 12 keys; `vulnerable_component` is in neither `_ROUTES`
nor `PRIMARY_HANDLED` (`:77-86`), so such a lead terminates `UNSUPPORTED`.
**Scoping correction Codex could not have made without running anything**: `dependency_intel` emits
SCA at `confidence: CONFIRMED` (audit claim 1), and the candidate pipeline only ever sees *leads*.
**A `_ROUTES` entry added today would never execute.** Q-021A (demote SCA to lead) is a hard
prerequisite for the route, not a parallel item — this reverses the dependency arrow Codex drew.

### 7 · `report.proof_and_retest()` — CONFIRMED. **The priority item, and the largest of the eight.**

`report.py:1204-1219` builds a **fresh synthetic record** from the finding's family alone and never
looks at the finding's evidence:

```python
nc = _tm.proof_contract({"vuln_class": fam or str(finding.get("cwe") or ""), "oracle": ""}).get("negative_control")
```

`technique_model.proof_contract` → `_neg_control_for(vc)` → a canned per-class string
(`technique_model.py:161-166`). Rendered verbatim, present-indicative, under **"How this was confirmed
(false-positive safety)"** at `report.py:2128-2131` (HTML) and `report.py:459-461` (Markdown).

MEASURED on a finding carrying **no evidence, no controls, no request and no response**:

```
>>> report.proof_and_retest({'family':'sqli','confidence':'confirmed','target':'http://x/?id=1'})
{'negative_control': "An inert control of the same shape but without SQL metacharacters does NOT
                      reproduce the error/boolean/time differential; the unmodified baseline behaves
                      normally.", ...}
>>> report.proof_and_retest({'family':'idor', ...})       # no controls either
{'negative_control': "A negative-control request WITHOUT the trigger does NOT reproduce the confirming
                      signal (differential measured over a stable baseline)."}
```

Scale, across every stored finding in all 151 missions:

```
confirmed findings stored                                     : 660
carry ANY recorded control artifact                           :  34   (dom_link_manipulation 32, bola 2)
carry NONE, yet the report prints a declarative control claim : 626   (94.8%)
top families with no artifact: sqli 89 · backup_exposure 84 · vulnerable_component 56 · csti 56 ·
                               prototype_pollution 50 · crlf 46 · dom_data_manipulation 46 ...
```

A representative confirmed `sqli` row's entire evidence is one request and one response —
`evidence: 'SQLite error triggered by "\')"'` — **no baseline, no inert control**. The report
nonetheless tells the client the inert control was run and did not reproduce.

**Be precise about what is wrong.** Several engines DO run a differential internally (boolean-blind
compares true against false; error-recovery compares against a recovery baseline). The claim is
therefore often *true* — but it is **never checked and never evidenced**, so it is unfalsifiable from
the report, and for any engine that does not run a control it is simply false. Same defect family as
the badge bug fixed in `707b3b9`: **a surface asserting a property the gate never verified.**
Filed as **Q-022** below.

### 8 · `test_asset_graph.py:106` proves ingest, not wiring — CONFIRMED

`test_ingest_intel_gives_graph_the_full_planner_vocabulary` constructs the dict literal
`intel = {"candidates": {..., "version": ["angular@1.7.7"], ...}}`, hands it to `g.ingest_intel()`,
and asserts `has_versions` in `to_observations()`. It exercises `asset_graph.py:215`
(`for v in cands.get("version", [])`). The only production caller is `agent.py:1202`
(`_g.ingest_intel(self.tools.intel.to_dict() ...)`) and the test never touches it. The test is green
whether or not any producer ever populates `candidates["version"]` — precisely the recorded
**"guards that check declarations, not facts"** shape. Any Q-021 ticket adding a producer must add the
paired **producer-side** assertion, not extend this one.

---

## Rank 3c — Q-021 family, implementation-ready (Distillation, 2026-08-10). All `proposed`.

**Read this preamble before any of B–F.** Three constraints apply to every ticket in the family.

1. **Q-021A has LANDED** — six slices, `177cb5c`/`77ae1de`/`5c1ee66`/`2f071a8`/`fb64d7b`/`30006f4`.
   MEASURED consequences that change the scoping Codex assumed:
   - `dependency_intel.vulnerable_component_finding` now emits `"confidence": CONFIRMED if ok else
     "lead"` (`dependency_intel.py:334`) where `ok` requires a CVE-specific behaviour differential
     through `behaviour_proof_ok`.
   - `proof_schema._DEFAULT_ENFORCE` now contains `"vulnerable_component"` (`proof_schema.py:160-161`).
   - So **every SCA finding is a LEAD by default today**, and leads flow into `candidate_pipeline`.
     Q-021's remaining job is to make that lead *resolvable*, not to demote it again.
2. **PRESERVE, do not rebuild.** Fingerprinting exists and RUNS — `planner.py:277` schedules
   `run_fingerprint` for every live host, and 2,641 calls are recorded across 151 missions.
   `dependency_intel` already owns the `CONFIRMED / HIGH / LOW` ladder with
   `CVE_ELIGIBLE = {CONFIRMED, HIGH}` (`dependency_intel.py:20-23`) and `cve_eligible()` (`:205`) is
   already the enforcement point for *unknown version ⇒ POTENTIALLY_AFFECTED*. Four tier-A feeds
   already exist in `intel_feeds.py`. A new `tech_intel.py` beside any of these is rejected in advance.
3. **The reusable proof-safe shape is the cloud one**, and it is three named files, not a slogan:
   `cloud_intel.analyze()` (`cloud_intel.py:65`, pure detection from headers/CNAME/URL) →
   `agent._cloud_exposure_probe` (`agent.py:1588-1610`, orchestration that calls the gated
   `_exec_internal("run_cloud_probe", ...)`) → `tools._run_cloud_probe` (`tools.py:2606`, ACTIVE,
   scope-gated, read-only GET whose verdict comes from `cloud_intel.storage_exposure(status, body)` —
   a **content-signature** oracle, never a status-code heuristic). Q-021E copies this shape.

---

### Q-021B · Stop discarding the version — persist a canonical TechnologyFact · **HIGH** · `proposed`

**Repository-proven gap.** The version is computed and thrown away one line later, in three separate
producers, and the one place it is persisted is polluted with English prose.

| producer | computes | what survives |
|---|---|---|
| `fingerprint.fingerprint()` → `tools._run_fingerprint` (`tools.py:3521`) | `{name, version, source, category}` | `lh["tech"] = [name, ...]` — **bare strings**; `version`, `source`, `category` dropped |
| `codeintel.harvest()` (`codeintel.py:236`) | `out["versions"]` (`name@x.y.z` from served JS) | **nothing** — no reader in the repo |
| `browser_engine.observe()` (`browser_engine.py:53-56`) | `framework` (angular/react/vue) | **nothing** — `to_observations()` never reads it |
| `memory.py:112-119,173` | persists `tech` across missions (13 rows live) | written, **never read back** — `main.py:_warm_start` skips `assets["tech"]` |

**Root cause.** There is no technology *record type*. Every producer emits an ad-hoc shape and every
consumer reads the lowest common denominator, which is a display string. `dependency_intel` has the
right record (`make_component`, `dependency_intel.py:117`) but is scoped to JavaScript libraries only.

**MEASURED input-quality defect that must be fixed in the same ticket** (see verification §5): 6 of 13
persisted `tech` values are sentence fragments produced by `fingerprint._POWERED`
(`fingerprint.py:71`, `{2,30}` truncating at 31 chars). Reproduced offline byte-for-byte:
`fp.fingerprint({}, '', "...running a MultiJuicer Kubernetes cluster...")` →
`[{'name': 'a MultiJuicer Kubernetes cluste', 'source': 'powered-by text'}, {'name': 'in safety mode.'},
{'name': 'on.'}]`. **Persisting these as TechnologyFacts would send them to NVD/OSV as product names.**

**Producer/consumer contracts.**
- *Producer*: `fingerprint`, `codeintel`, `browser_engine` and `dependency_intel` all emit a
  `TechnologyFact` through **one** constructor. Extend `dependency_intel.make_component` rather than
  writing a new one — it already carries `name / version / source / confidence / evidence / location`.
  Add: `vendor`, `category`, `component` (plugin/theme/module), `authenticated` (bool), `first_seen`,
  `last_seen`, `detector`.
- *Contract A*: **a TechnologyFact with no version is legal**; it carries `confidence: LOW` and is
  therefore never CVE-eligible (`cve_eligible()` already enforces this). Do not synthesise a version.
- *Contract B*: **a fact whose `name` fails the identity gate is not admitted.** Gate = the name must
  match a known-product table or a conservative token shape (no spaces-plus-articles, no trailing `.`,
  not truncated at exactly the regex bound). `_POWERED` hits become `evidence`, never `name`.
- *Consumer*: `tools.recon["technology"]` (a list of facts, alongside the existing
  `live_hosts[i]["tech"]` display list, which is **kept** so nothing that renders it breaks);
  `asset_graph.build_from_engagement` projects them as `component` nodes; `_warm_start` re-seeds them.

**Dependencies.** Q-019 (a technology fact is worth little at 36 probed URLs) — but B is otherwise
independent and can be built in parallel with Q-019's verification.

**Likely files.** `agent/fingerprint.py` · `agent/dependency_intel.py` · `agent/tools.py`
(`_run_fingerprint` only) · `agent/asset_graph.py` · `agent/memory.py` · `agent/main.py`
(`_warm_start`) · `agent/browser_engine.py`. **`tools.py` is owned by the engine-lane Builder this
cycle — the `_run_fingerprint` change is a hand-off note, not a direct edit.**

**Deterministic oracle.** Against a standing lab with a known banner (`apolaki-testbox`, or
`owaspbench` for `Server:`):
1. `recon["technology"]` contains a fact with `name`, a non-empty `version`, `confidence in
   CVE_ELIGIBLE`, and an `evidence` string quoting the exact header/byte that proved it.
2. `asset_graph.build_from_engagement(...)` produces ≥ 1 `component` node for that fact.
3. A second mission on the same target warm-starts with that fact already present
   (`_warm_start()["technology"] >= 1`).

**Negative control (three, all mandatory).**
- **(a) Prose is refused.** Feed the exact MultiJuicer body above; `recon["technology"]` must gain
  **zero** facts and the run must record *why* (a `_swallow`-style rejection naming the detector), not
  silently drop them. A fix that merely stops *storing* them without recording the rejection has moved
  the blindness, not removed it.
- **(b) A versionless detection stays LOW.** A `Server: nginx` with no version must produce a fact
  with `version: ""`, `confidence: LOW`, and `cve_eligible(fact) is False`.
- **(c) Empty means empty.** A target that serves no identifying header, cookie, generator or script
  must produce **zero** facts and **no error** — the same "tell a real zero from a broken detector"
  requirement Q-016 exists for.

**Mutation tests.**
- Re-widen `_POWERED` to accept prose → control (a) must fail.
- Drop `version` from the fact constructor → oracle assertion 1 must fail.
- Point `_warm_start` back at the three original kinds → oracle assertion 3 must fail.
- Make `cve_eligible` return True for LOW → control (b) must fail. *(This mutation also guards
  Q-021C/D, so it belongs in a shared test module.)*

**Regression tests.** `live_hosts[i]["tech"]` keeps its current string-list shape (the UI and
`report.py:1422,2585` delta section read it); `agent/tests/test_fingerprint*.py` stay green;
`memory_assets` gains no new `kind` value that existing readers would choke on.

**False-positive risks.** Spoofed `Server:`/`X-Powered-By` banners (a fact is an *observation*, so
record the header verbatim as evidence and never call it proof); CDN-injected headers attributed to
the origin; the same product detected under two aliases (`dependency_intel._FLEX_ALIAS` /
`_CDN_NAME_FIX` already exist — reuse, do not re-implement).

**Definition of done.** All three oracle assertions and all three negative controls in the suite; a
`liveness.py` CHECKS entry (hand-off to the Coordinator) that fails when `recon["technology"]` is
empty on a target with a known banner; the 6 prose rows purged from `memory_assets` by the identity
gate on next write; **no new module created**.

**Expected benefit.** Unblocks C, D, E and F — none of them can be built on a bare string. Also
retires the 6 garbage rows currently poisoning cross-mission memory.

---

### Q-021C · Canonical identity, version ranges, and applicability · **HIGH** · `proposed`

**Repository-proven gap.** Nothing in `agent/` computes a CPE or a PURL, and nothing evaluates a
version *range*. `dependency_intel._ver_tuple` / `_vlt` (`:187-203`) implement a numeric-tuple
comparison — enough for `< 3.5.0`, wrong for `>= 1.2, < 1.4 || >= 2.0, < 2.1`, wrong for ecosystem
semantics (npm `^`/`~`, Python PEP 440 `rc`/`post`, Debian epochs and `-1ubuntu2` revisions).
Applicability validation does not exist at all (baseline stage 4).

**Root cause.** Identity and comparison were both solved *just enough* for a single ecosystem
(JavaScript CDN filenames) and were never generalised, so every other product has no way to be matched
against an advisory at all.

**Producer/consumer contracts.**
- *Producer*: a TechnologyFact (Q-021B) gains `purl` and/or `cpe` **when they can be derived
  confidently**, and `identity_confidence` when they cannot. A guessed CPE is worse than none.
- *Consumer*: a range evaluator `applies(fact, advisory) -> (verdict, reason)` returning exactly one
  of `AFFECTED / NOT_AFFECTED / UNKNOWN`, where **`UNKNOWN` is the default**, not `AFFECTED`.
- *Contract*: `applies()` must return `UNKNOWN` — never `AFFECTED` — when the ecosystem is unknown,
  the range syntax is unparsed, or the version is `LOW` confidence.

**Backported patches are the single largest FP source in this class and must be handled explicitly.**
Debian/RHEL ship a patched `1.2.3` that every naive range check calls vulnerable. Contract: when the
fact's `source` indicates a distro-packaged product (a distro revision suffix, a distro-specific
banner), the verdict is capped at `UNKNOWN` with `reason: "distro backport possible"` unless a
behaviour probe (Q-021E) resolves it.

**Dependencies.** Q-021B (needs the record). **Blocks** Q-021D and Q-021E.

**Likely files.** `agent/dependency_intel.py` (extend `_ver_tuple`/`_vlt`, add the range evaluator) ·
a small pure `agent/version_ranges.py` **is acceptable here** — it is a new *algorithm*, not a second
copy of an existing capability — provided `dependency_intel` is its only caller.

**Deterministic oracle.** A table-driven test over fixtures per ecosystem, each row
`(ecosystem, version, range, expected)`, including: `npm ^1.2.3` vs `1.2.4` → AFFECTED;
`PEP 440 2.0rc1` vs `< 2.0` → AFFECTED (rc precedes release); `1:1.2.3-1ubuntu2` vs `< 1.2.4` →
UNKNOWN (backport); an unparseable range → UNKNOWN.

**Negative control.** **(a)** A **patched** version of a detected product yields zero AFFECTED
verdicts against the same advisory set. **(b)** A spoofed `Server:` banner claiming an ancient version
while the real behaviour is current must not reach AFFECTED — with Q-021E absent it must sit at
UNKNOWN, which is the correct answer, not a failure. **(c) Non-vacuity**: the table must assert
`len(rows_evaluated) > 0`; a range test over an empty fixture set passes for free, which is exactly
the vacuous pass Q-012 recorded.

**Mutation tests.** Flip the `UNKNOWN` default to `AFFECTED` → control (a) and (b) must fail. Strip
the distro-suffix branch → the `1ubuntu2` row must fail. Make `applies()` ignore
`identity_confidence` → a LOW-confidence fact must wrongly reach AFFECTED and a test must catch it.

**Regression tests.** Every existing `dependency_intel` assertion stays green; `cve_eligible()`
semantics are unchanged (this ticket adds a *second* gate, it does not relax the first).

**False-positive risks.** Ambiguous product names across ecosystems (`jquery` the npm package vs
`jquery` the CDN bundle); a range expressed against a fork; duplicate CVEs arriving from two feeds
with different ranges — record both, take the **narrower** verdict, never the union.

**Definition of done.** The fixture table green with the non-vacuity assertion; all three negative
controls; `applies()` is the only place a version is compared to a range anywhere in `agent/`.

**Expected benefit.** Converts "a feed returned 40 CVEs for jquery" into a defensible per-CVE verdict,
and is the only thing standing between Q-021D and a report full of theoretical CVEs.

---

### Q-021D · Connect governed feeds to components — and ship the missing promotion path · **MEDIUM** · `proposed`

**Repository-proven gap, and it is two gaps, not one.**

*Gap 1 — no product→advisory resolution.* `intel_feeds.py` (406 lines) carries exactly four tier-A
sources — KEV, CAPEC, ATT&CK, ExploitDB — and matches by **exact CVE** or an exact product-version
key (`exploits_for_finding`, `exploitdb_for_product`). There is no NVD/CPE, OSV, GHSA or WPScan
resolution, so `nginx 1.18.0` cannot be turned into a CVE list at all.

*Gap 2 — the governed connectors that DO parse NVD/GHSA/CVE-v5 terminate in an unreachable store.*
MEASURED (verification §4): `intel_connectors._PARSERS` handles `epss / nvd / ghsa / cve_v5 /
cisa_kev`; the only consumers are three read-only endpoints (`main.py:2785, 2790, 2803`);
`intel_registry._STORE` is a module-level dict wiped on restart; and **`intel_registry.advance()` is
called only from `agent/tests/test_intel_registry.py`** — no endpoint, no code path. Live check:

```
allowlist: all 18 sources -> enabled=False
registry stats: {'total': 0, 'by_state': {}}   production: 0
```

`production()` is documented as "the only trusted knowledge safe to drive engines" and is
**structurally always empty**. **A consumer wired to it today would read `[]` forever.** Any ticket
that only adds a consumer is a null change against a green test — this is the same shape as Q-019
refinement #1.

**Root cause.** `#114` built the *governance* half of the connector story (allowlist, rate limit,
audit log, provenance, staged trust) and stopped before the *promotion* half, so the trust ladder has
a top rung nothing can climb to.

**Producer/consumer contracts.**
- *Producer*: a resolver `advisories_for(fact) -> [advisory]` that consults, in order, the local
  feed snapshots then the governed connectors, and **always records which source and which snapshot
  timestamp** produced each advisory.
- *Consumer*: `applies()` from Q-021C decides `AFFECTED / NOT_AFFECTED / UNKNOWN` per advisory. The
  resolver never decides applicability itself.
- *Promotion contract*: `intel_registry.advance()` gains a caller — an explicit, evidence-carrying
  step. **Do not auto-promote to `production`**; the existing rule (a human `reviewed_by`) is correct
  and stays. What must be built is the path to `validated` / `fixture_backed`, and a consumer that
  reads `validated`-and-above rather than `production`-only, with the confidence weight carried
  through (`_CONF`, `intel_registry.py:15-16`) so a `candidate` advisory can never outrank a
  `fixture_backed` one.
- *Persistence contract*: `_STORE` must survive a restart, or the registry must be documented as
  per-process and the consumer must tolerate a cold empty store without failing open.

**ANTI-SPAM, hard requirement, restated because it is the failure mode this ticket most invites.**
An unknown or LOW-confidence version yields **at most one** `POTENTIALLY_AFFECTED` row per product —
never one per CVE. The row names the count (`"jquery 2.1.4 — 41 advisories match this version range,
none applicability-verified"`), it does not enumerate them into the findings list.

**Dependencies.** Q-021B (the fact) and Q-021C (the range evaluator). Also the **Watcher's feed-quality
review** — licence, update cadence, machine-readable format, provenance. Feeds rejected in advance and
the reason, so they are not re-proposed:

| feed | verdict |
|---|---|
| NVD 2.0 API | accept — already parsed (`_parse_nvd`), allowlisted, tier A |
| OSV.dev | accept — the only source with real per-ecosystem range semantics; it is what Q-021C needs |
| GHSA | accept — already parsed (`_parse_ghsa`), carries `first_patched_version` |
| CVE Program v5 | accept — already parsed (`_parse_cve_v5`) |
| CISA KEV | already loaded twice (`intel_feeds` snapshot + `_parse_kev`) — **de-duplicate, do not add a third** |
| WPScan | **defer** — key-gated, non-commercial licence terms, and Apolaki has no WordPress plugin/theme detector yet (Q-021B does not add one). Revisit only after a CMS detector exists |
| scraped vendor advisory pages | **reject** — no machine-readable format, no provenance, unmaintained parse surface |
| "CVE aggregator" blogs / GitHub CVE-list mirrors | **reject** — no provenance, stale, duplicate |

**Likely files.** `agent/intel_feeds.py` · `agent/intel_connectors.py` · `agent/intel_registry.py` ·
`agent/intel_sources.py` · `agent/dependency_intel.py`. *(No `agent/` file in this list is held by
either Builder this cycle.)*

**Deterministic oracle.** Fully offline, using recorded feed fixtures and the injectable `http=`
hook `intel_connectors.fetch` already exposes:
1. A fact for a product with a known CVE resolves to ≥ 1 advisory carrying `source` and
   `snapshot_at`.
2. That advisory reaches the consumer at `validation_state >= validated` after an explicit advance
   with evidence, and **not** before.
3. One product with 40 matching CVEs at LOW version confidence produces exactly **1** row.

**Negative control.** **(a)** With every source disabled (the default), the resolver performs **zero**
network I/O and returns an empty result *labelled* `disabled` — not an empty result labelled clean.
**(b)** A record that was never advanced must **not** be visible to the consumer — this is the
mutation that proves the ladder is load-bearing. **(c) Non-vacuity**: assert the fixture set is
non-empty before asserting "no spam", or the anti-spam test passes over zero advisories.

**Mutation tests.** Make the consumer read `by_state("candidate")` → control (b) must fail.
Remove the per-product collapse → oracle 3 must fail with 40 rows. Delete the `snapshot_at` stamp →
oracle 1 must fail. Re-enable a source in the test env without a credential → the hard gate must still
refuse and control (a) must stay green.

**Regression tests.** `exploits_for_finding` / `exploitdb_for_product` behaviour unchanged; KEV
matching stays **exact-CVE-only, never inferred from CWE** (a preserved capability); the
`/intel/audit` log still records every outward request.

**False-positive risks.** The same CVE arriving from NVD and GHSA with different ranges (take the
narrower, per Q-021C); a stale snapshot presenting a since-withdrawn advisory (hence `snapshot_at`);
ExploitDB product-version matches being read as proof rather than as a lead (the existing distinction
is a preserved capability — do not flatten it).

**Definition of done.** All three oracle assertions plus all three negative controls; at least one
record demonstrably reaching `validated` through product code rather than through a test; the
`/intel/registry` endpoint showing a non-zero `by_state` after a governed fetch in the demo path.

**Expected benefit.** The first time a detected non-JavaScript product can be resolved to an advisory
at all — and the first time `#114`'s trust ladder has a rung above `candidate` that product code uses.

---

### Q-021E · Technology drives safe orchestration — copy the cloud pattern · **MEDIUM** · `proposed`

**Repository-proven gap, with the architecture corrected.** Codex and the baseline both frame this as
"`derive_observations` has no `recon` parameter". That framing invites the wrong fix. The module
itself says so:

```
technique_planner.py:144-146
  This entry point takes NO surface/harvest argument, so flat recon CANNOT independently drive it —
  an empty graph yields an empty plan no matter what recon found elsewhere. That is the proof the
  graph is the brain: facts must be projected INTO the graph to influence the plan.
```

**So adding a `recon=` parameter to `derive_observations` is REJECTED in advance** — it would feed the
compatibility path while the graph-authoritative path (`plan_graph_authoritative`, the one the mission
actually leads with) stayed blind. The correct wiring is Q-021B projecting TechnologyFacts into the
graph as `component` nodes; `asset_graph.to_observations()` already maps `component` → `has_versions`
(`asset_graph.py:234-235`).

**And here is the measured catch that makes this ticket necessary rather than free:**

```
$ grep -n has_versions agent/engine_descriptor.py
43:    ... "has_versions", ...        <- present in the OBSERVATIONS vocabulary
$ grep -n has_versions <PRECONDITIONS body>
(no match)                            <- gates ZERO techniques
```

`has_versions` is a **declared observation with no consumer**. Projecting facts into the graph
therefore changes nothing on its own. Q-021E's real work is (i) product-conditioned observations and
(ii) a probe that can act on them.

**Producer/consumer contracts.**
- *Producer*: `asset_graph.to_observations()` emits product-conditioned observations derived from
  `component` nodes — e.g. `wordpress_detected`, `nginx_detected`, `component_advisory_matched` —
  added to `engine_descriptor.OBSERVATIONS` (the single vocabulary) and to `PRECONDITIONS` for the
  techniques they gate.
- *Consumer*: one new engine following the cloud triplet **exactly**:
  - `dependency_intel.probe_plan(fact, advisory) -> {trigger, control, signature} | None` — pure,
    the analogue of `cloud_intel.analyze()`. Returns `None` when no safe deterministic probe exists,
    which must be the **common** answer.
  - `agent._technology_probe(session_id)` — the analogue of `agent._cloud_exposure_probe`
    (`agent.py:1588-1610`): iterates candidate facts, calls the gated
    `_exec_internal("run_tech_probe", ...)`, skipped in passive mode.
  - `tools._run_tech_probe` — the analogue of `tools._run_cloud_probe` (`tools.py:2606`):
    scope-gated, read-only, one bounded request, verdict from a **content signature**, never a status
    code.
- *Contract, non-negotiable*: `probe_plan` returning `None` leaves the finding at
  `POTENTIALLY_AFFECTED`. **Detection plus a database match is never a confirmation.** This is already
  enforced downstream by `behaviour_proof_ok` (`dependency_intel.py:223`) which Q-021A shipped — route
  through it, do not add a second gate.

**Dependencies.** Q-019 · Q-021B · Q-021C · Q-021D.

**Also in scope, because Q-021A made it live.** `candidate_pipeline._ROUTES` has no
`vulnerable_component` entry. MEASURED today:

```
>>> cp.canonical_family(sca_lead)  -> 'vulnerable_component'   (classifies correctly)
>>> 'vulnerable_component' in cp._ROUTES        -> False
>>> 'vulnerable_component' in cp.PRIMARY_HANDLED -> False
>>> cp.normalize(sca_lead)['validator'] -> None
    cp.normalize(sca_lead)['oracle']    -> 'no validator implemented yet'
```

Before Q-021A this was unreachable (SCA emitted `confirmed`, and only leads enter the pipeline).
**It is reachable now, and every SCA lead terminates `UNSUPPORTED` — 56 stored `vulnerable_component`
findings would take that path.** The `_ROUTES` entry is
`("run_tech_probe", "<CVE> behaviour differential reproduced; trigger-absent control did not", None)`
and it must land in this ticket, not a later one.

**Likely files.** `agent/dependency_intel.py` · `agent/asset_graph.py` · `agent/engine_descriptor.py`
· `agent/technique_planner.py` · `agent/candidate_pipeline.py` · `agent/agent.py` ·
`agent/tools.py`. **Both `tools.py` and `candidate_pipeline.py` are Builder-owned this cycle — those
two edits are hand-off notes.**

**Deterministic oracle.** On a lab running a product with a *behaviourally observable* CVE:
detection → advisory match → `probe_plan` returns a plan → the probe runs → the content signature is
present → the finding is `confirmed` / `AFFECTED`, carrying the trigger, the observed signature, the
control, and the control's observed value (the fields `dependency_intel.py:290-296` already
formats).

**Negative control (four).** **(a)** Structurally identical request with the trigger **absent** must
not produce the signature — this is already the shape `behaviour_proof_ok` demands, so the test is an
assertion, not new machinery. **(b)** A **patched** version of the same product on the same URL must
NOT stay `OPEN` on retest (Q-021A slice 3 fixed the retest oracle — this control proves it holds for
the new engine too). **(c)** A product detected with `LOW` version confidence produces
`POTENTIALLY_AFFECTED` and **zero** confirmed findings however many CVEs the feed returns.
**(d)** A spoofed `Server:` banner claiming an ancient version, with current behaviour, must not
confirm — the probe is the arbiter, not the banner.

**Mutation tests.** Make `probe_plan` return a plan for every advisory → control (d) must fail.
Let the probe judge on status code instead of the content signature → control (a) must fail (the
control request usually returns the same status). Remove the `_ROUTES` entry → the SCA lead must go
back to `UNSUPPORTED` and a test must catch it. **Non-vacuity**: assert the probe actually executed
(a `run_tech_probe` `tool_call` row exists), because a no-op engine passes every control above for
free — this is the Q-020/`verify_always_on` lesson and the ZAP lesson in Q-023.

**Regression tests.** Zero new confirmed findings on a clean paired lab; the mission's finding count
on `owaspbench` does not change (no product there has a behaviourally observable CVE, so the correct
outcome is *no new findings* — a ticket that "improves" that number is misbehaving).

**False-positive risks.** WAF or CDN responses matching the content signature; a probe that mutates
state (forbidden — read-only only, and `probe_plan` must return `None` for any CVE whose trigger is
not idempotent); a signature so loose it matches the patched build.

**Definition of done.** All four negative controls plus the non-vacuity assertion; the `_ROUTES`
entry; a `liveness.py` CHECKS entry; **a `run_tech_probe` `tool_call` row observed in a real mission**
— the declaration that the engine is registered is not evidence that it ran (Q-023 is the same lesson
measured at scale).

**Expected benefit.** The first path in the platform from *"we detected nginx 1.18.0"* to a defensible
confirmed-or-rejected verdict, and it closes the `UNSUPPORTED` terminal state Q-021A opened.

---

### Q-021F · Expose the technology lifecycle honestly · **LOW** · `proposed`

**Repository-proven gap.** `report.py:1422,2585` surface `("tech", "New Technology")` in the **delta**
section only — technology appears in a report only when it *changes* between scans. There is no
technology inventory, no version-confidence column, no advisory-match column, no proof-status column,
in the report or the UI. `asvs_model.py:151` maps an ASVS objective to
`("run_fingerprint", "dependency_intel")`, which is the only place the two are named together.

**Root cause.** Stage 8 was built for *findings*, and technology never became a first-class object, so
there was nothing to render.

**Producer/consumer contracts.**
- *Producer*: the TechnologyFact list (Q-021B) plus each fact's advisory verdicts (Q-021C/D) and probe
  outcome (Q-021E).
- *Consumer*: one shared projection used by **all four** surfaces — HTML report, Markdown report,
  `GET /missions/{sid}` (UI coverage view), SARIF and the PoC bundle. **One projection, not four
  private copies** — the four-copies-of-`is_confirmed` history (Q-015, `707b3b9`) is why this is
  stated as a contract rather than a suggestion.
- *Contract*: every row states its **proof status** in the six-state ladder
  `DETECTED_TECHNOLOGY → VERSION_SUSPECTED → ADVISORY_MATCHED → APPLICABILITY_CONFIRMED →
  SAFELY_PROBED → ORACLE_CONFIRMED`, and the rendered badge is computed from the stored state, never
  hardcoded. **A row above `ADVISORY_MATCHED` that carries no probe evidence must render as
  unproven** — the badge bug (`707b3b9`) and Q-022 are both instances of getting this wrong.

**Dependencies.** Q-021B through Q-021E.

**Likely files.** `agent/report.py` · `agent/sarif_io.py` · `agent/poc_bundle.py` · `agent/main.py`
(the coverage view) · `ui/`. **`report.py`, `sarif_io.py` and `poc_bundle.py` are Builder-owned this
cycle** — sequence after that lane releases them.

**Deterministic oracle.** For a mission with ≥ 1 TechnologyFact: the HTML report, the Markdown report,
the mission JSON and the SARIF export all show the **same** count of facts and the **same** proof
state per fact. A cross-surface equality assertion, not four independent ones.

**Negative control.** **(a)** A mission with zero technology facts renders the section as an explicit
"no technology identified" rather than omitting it — an omitted section is indistinguishable from a
broken renderer. **(b)** A fact at `ADVISORY_MATCHED` with no probe must render **unproven** on every
surface; mutate one surface to hardcode "confirmed" and the cross-surface equality assertion must
fail. **(c)** The existing delta section keeps working — a genuinely new technology between two scans
still appears there.

**Mutation tests.** Hardcode a badge on the HTML surface → oracle equality must fail. Point one
surface at a private copy of the projection → the same. Drop the "no technology identified" branch →
control (a) must fail.

**Regression tests.** Existing report snapshot tests; `full_pct` / `verified_pct` unchanged (this
ticket adds a view, it must not move a coverage number); SARIF schema validation still passes.

**False-positive risks.** A reader mistaking an inventory row for a finding — hence the mandatory
proof-status column and a visually distinct section. Do not let technology rows enter
`finding_counts()` or the severity tally.

**Definition of done.** Cross-surface equality assertion green; all three negative controls; the UI
coverage view shows technology, version confidence, advisory match and proof status; **no coverage
percentage changes**.

**Expected benefit.** Makes the whole Q-021 family auditable from the outside — which is the only way
a client can tell Apolaki's technology intelligence from a scanner's version-table guess.

---

## Rank 3d — new tickets from today's measurements (Distillation, 2026-08-10). All `proposed`.

### Q-022 · "How this was confirmed" is a template, not a record — 626 of 660 findings · **CRITICAL** · `proposed`

*The platform's differentiator is that its proofs are real. This is the one place the report says a
proof happened without checking that it did.*

**Repository-proven gap.** `report.proof_and_retest()` (`report.py:1204-1219`) constructs a synthetic
record from the finding's **family alone** and asks the technique model to describe a control:

```python
nc = _tm.proof_contract({"vuln_class": fam or str(finding.get("cwe") or ""), "oracle": ""}).get("negative_control")
```

`technique_model.proof_contract` (`:169`) → `_neg_control_for(vc)` (`:161-166`) → a canned per-class
string. The finding's `evidence`, `browser_evidence`, `request`, `response`, `negative_control` and
`proof_gap` fields are **never read**. The result is rendered verbatim under
**"How this was confirmed (false-positive safety)"** at `report.py:2128-2131` (HTML) and
`report.py:459-461` (Markdown).

**MEASURED** — a finding with no evidence at all still gets a confident sentence:

```
>>> report.proof_and_retest({'family':'sqli','confidence':'confirmed','target':'http://x/?id=1'})
negative_control: "An inert control of the same shape but without SQL metacharacters does NOT
                   reproduce the error/boolean/time differential; the unmodified baseline behaves
                   normally."
>>> report.proof_and_retest({'family':'idor', ...})     # no controls either
negative_control: "A negative-control request WITHOUT the trigger does NOT reproduce the confirming
                   signal (differential measured over a stable baseline)."
```

**MEASURED scale**, every stored finding across all 151 missions:

```
confirmed findings stored                                     : 660
carry ANY recorded control artifact                           :  34   (dom_link_manipulation 32, bola 2)
carry NONE, yet the report prints a declarative control claim : 626   (94.8%)
sqli 89 · backup_exposure 84 · vulnerable_component 56 · csti 56 · prototype_pollution 50 ·
crlf 46 · dom_data_manipulation 46 · broken_auth 33 · dom_xss 28 · security_misconfig 24 ...
```

A representative confirmed `sqli` row's whole evidence is one request and one response:
`evidence: 'SQLite error triggered by "\')"'`, `request: 'GET .../search?q=%27%29'`,
`response: 'HTTP 500 ... SQLITE_ERROR'`. **No baseline. No inert control.** The report tells the
client the inert control was run.

**Root cause.** Exactly the same as `707b3b9`: a **rendering surface asserting a property the gate
never verified**. `proof_contract` is a *specification* of what a technique's control ought to be —
correct for the technique registry, wrong as a per-finding statement of what happened. The two were
never distinguished, and `proof_and_retest` uses the specification as if it were a record.

**Be precise about what is false.** Several engines genuinely do run a differential (boolean-blind
compares a true-condition against a false-condition response; error-recovery compares against a
recovery baseline). For those, the sentence is *true but unevidenced and unfalsifiable from the
report*. For engines that run no control, it is *false*. Both are unacceptable in the section whose
entire purpose is false-positive safety, and the report cannot tell them apart. **The ticket is not
"delete the sentence" — it is "make the sentence a function of what was recorded."**

**Producer/consumer contracts.**
- *Producer*: an engine that runs a control **records it** on the finding, in one canonical shape.
  The shape already exists in two places — pick one and make it the contract: `browser_evidence.
  negative_controls` (a dict of `{label: {url, status, len}}`, rendered by `report.py:1157-1164`) or
  `dependency_intel`'s Q-021A fields (`control`, `control_observed`). The BIE dict is the more
  general of the two.
- *Consumer*: `proof_and_retest` reads the finding and returns one of three shapes:
  - a control **was recorded** → describe the recorded control, quoting its actual values;
  - a control **was not recorded** → *"Negative control not recorded for this finding"* plus the
    technique-registry expectation clearly labelled as **expected**, not **performed**;
  - the family is in `proof_schema._DEFAULT_ENFORCE` and no control was recorded → the finding should
    already have been demoted by `demote_unproven`; assert that, and surface the `proof_gap`.
- *Contract*: **no string in this section may be in the past or present indicative unless it is
  derived from a stored artifact.** Everything else is phrased as an expectation.

**Dependencies.** None — this is a truth-containment fix with no prerequisites, exactly like Q-021A.
It should be ranked with Q-021A's urgency for the same reason: everything else in the queue is a
missing capability; this is a **wrong answer already shipping to clients**.

**Likely files.** `agent/report.py` (owned by the Coordinator this cycle) · `agent/technique_model.py`
· `agent/proof_schema.py` (Builder-owned — the `proof_gap` read is a hand-off note) ·
`agent/tests/test_report*.py`.

**Deterministic oracle.**
1. A finding with a recorded control renders the **recorded** values (url/status/length), and those
   values appear in the output.
2. A finding with no recorded control renders the not-recorded wording, and the string
   `"does NOT reproduce"` (or any indicative claim) does **not** appear.
3. HTML and Markdown produce the same verdict for the same finding — one projection, two renderers.

**Negative control (three, all mandatory).**
- **(a) The honest case must not regress**: the 34 findings that *do* carry a control must still show
  a full control description. A fix that renders "not recorded" for everything has deleted the section
  rather than repaired it.
- **(b) A demoted finding must not display a confirmation narrative at all** — it is a lead.
- **(c) Non-vacuity**: assert the test corpus contains ≥ 1 finding of each kind (control recorded /
  control absent), because a test over a single-kind corpus passes for free.

**Mutation tests.** Restore the family-only `proof_contract` call → oracle 2 must fail. Strip the
recorded-control branch → control (a) must fail. Make the Markdown renderer use its own copy of the
projection and change it → oracle 3 must fail.

**Regression tests.** `technique_model.proof_contract` keeps its current behaviour for the **technique
registry** and its guard test (`every proven technique declares its FP-safety differential`) — that
use is correct and must not change. Report snapshot tests updated with the reason stated in the commit
message, because "the test changed" is what weakening looks like from the outside.

**False-positive risks (of the fix).** Over-flagging: an engine that records its control in a shape
the reader does not recognise would render "not recorded" on an honest finding. Mitigation: enumerate
the recorded-control shapes in one table and add a test per producer that actually records one.

**Secondary observation, UNVERIFIED — do not queue as fact.** The same function's retest string reads
*"(Apolaki auto-retests this)"*. `/retest` (`main.py:2561`) is an operator-invoked endpoint; I found
no scheduler that calls it. Whether "auto" is accurate needs a UI/behaviour check I did not run.

**Definition of done.** All three oracle assertions, all three negative controls, the two mutations;
a re-render of an existing stored mission's report showing "not recorded" on the findings that carry
no control; and the count of findings displaying an unbacked control claim measured before and after.

**Expected benefit.** Removes 626 unbacked proof claims from client-facing output and creates the
back-pressure that makes engines record their controls — which is the only route to the 34/660 figure
improving for real.

---

### Q-023 · ZAP has never executed in any mission, and three flags do not explain it · **HIGH** · `proposed`

**MEASURED, whole corpus.** `run_zap` tool calls across 151 missions and **29,109** `tool_call` rows:
**0**. (`run_fingerprint` 2,641 · `http_probe` 4,542 over the same corpus, so the counter works.)

**Three independent gates, each sufficient on its own** — all three confirmed by reading:

```
main.py:81    enable_zap: bool = False                     <- default off
main.py:336   if enable_zap and req.mode != "full": 422    <- Full mode only
tools.py:138  "run_zap": PermissionLevel.INTRUSIVE         <- outside the active/passive tiers;
                                                              planner.fresh() -> _allowed() drops it
```

**The planner branch is LIVE — measured, not assumed.** Driving `planner.next_batch` directly with
`mode=full, zap=True`:

```
urls=1     batches=8  total_steps=55   run_zap first scheduled at (batch 7, step 54)
urls=30    batches=8  total_steps=287  run_zap first scheduled at (batch 7, step 286)
urls=300   batches=8  total_steps=287  run_zap first scheduled at (batch 7, step 286)
```

Note the third row: phase E is internally capped, so **phase F is reachable in a bounded number of
steps regardless of surface size**. "The mission never gets that far on a big target" is therefore
**DISPROVED** as an explanation.

**THE RESIDUE THAT DEFINES THIS TICKET — flipping the flag is NOT a sufficient fix.** Four missions
carried `enable_zap` truthy in their stored context and fired **zero** `run_zap` calls:

```
c7bfe8e8  ginandjuice.shop              full  2026-07-26  tool_calls=222  run_zap=0
ce35b361  ginandjuice.shop              full  2026-07-26  tool_calls=222  run_zap=0
6771ec21  G&J-FULLBLOWN-26Jul2026@1243  full  2026-07-26  tool_calls=333  run_zap=0
94e8b564  OWASP-JS-FULLBLOWN            full  2026-07-26  tool_calls=375  run_zap=0
```

All four reached `status=complete, phase=report` and all four ran INTRUSIVE tools
(`run_sqlmap`, `run_ffuf`, `run_dalfox`), so `_allowed(INTRUSIVE, full)` passed and the mission was in
Full mode. `run_nuclei` (phase F1, immediately before ZAP) is also absent from all four. **There is a
fifth cause and it is unidentified.** It is `CANNOT_VERIFY_STATICALLY` today because those missions ran
on 2026-07-26 code and the plan loop has since moved to the graph-authoritative path
(`agent.py:2820-2841`, `_graph_primary_state`). Candidate hypotheses for the implementer, in order:
`self.enable_zap` not propagating from `EngageRequest` into the agent · `_zap_configured()` false at
the time (today it is `True`: `ZAP_ADDR=http://zap:8090`, `zap_client.configured() -> True`) ·
`_graph_primary_state` returning a `g_roots`/`g_urls` pair that ends the loop before phase F.

**Root cause (of the ticket's existence).** Nobody ever asserted that ZAP *ran*. `docs` and the report
describe a "ZAP Executed — Safe Active" state; no test and no liveness check requires a `run_zap` row
to exist. This is the **"guards that check declarations, not facts"** shape at the orchestration layer.

**Also in scope — three confirmed sub-defects.**

1. **`recon["zap"]` is a dead write.** `tools.py:8470`
   `self.recon.setdefault("zap", []).extend(findings)` is the sole occurrence. Repo-wide search for
   `recon["zap"]` / `recon.get("zap")` finds no reader (`planner.py:167`'s `state.get("zap")` is the
   *enable flag* on a different dict). ZAP's own alerts reach the report only via the ToolResult /
   `_AUTO_STORE_TOOLS` path, never via recon.
2. **Targeted rescan is NOT WIRED.** The planner key is `f"run_zap:{h}"` (`planner.py:601`) and
   `fresh()` (`planner.py:219-234`) drops any step whose key is in `done`. **One ZAP call per host per
   mission, ever** — a second, narrower ZAP pass against a newly discovered path is unrepresentable.
3. **The AJAX spider fails silently.** `tools.py:8413-8416`:
   ```python
   try:
       await zap.ajax_start(url, context=name)
       await zap.wait_str(lambda: zap.ajax_status(), cap=120, stop_event=self.stop_event)
   except Exception:
       pass
   ```
   A bare swallow, and the SPA crawl is exactly the part that matters on a modern target. **The correct
   idiom is 50 lines below in the same function**: the active scan's `except Exception as _ae:
   ascan_err = ...` is surfaced in the ToolResult note. Mirror it.

**MEASURED CORRECTION to the intake brief — do not use `numberOfMessages` as the oracle.** The brief
records `numberOfMessages: 0` after 10h up. Today:

```
GET /JSON/core/view/version/          -> {"version":"2.17.0"}
GET /JSON/core/view/numberOfMessages/ -> {"numberOfMessages":"4411"}
```

The daemon has now seen 4,411 messages while `run_zap` calls remain **0**, so that counter is
contaminated by something other than Apolaki's ZAP engine. **The oracle must be a `run_zap`
`tool_call` row plus a ZAP-sourced finding, never a daemon-side counter.**

**Producer/consumer contracts.** Producer = `tools._run_zap`, which must (i) write its alerts
somewhere with a reader or stop writing `recon["zap"]`, and (ii) report AJAX-spider failure in its
note. Consumer = the report's "ZAP Executed" state, which must be computed from the presence of a
`run_zap` result, not from the `enable_zap` flag.

**Dependencies.** None. Independent of Q-019 and the Q-021 family.

**Likely files.** `agent/tools.py` (`_run_zap`) and `agent/planner.py` — **`tools.py` is Builder-owned
this cycle; write the patch as a hand-off note.** Plus `agent/agent.py` (flag propagation),
`agent/liveness.py` (Coordinator-owned — hand-off), `agent/tests/`.

**Deterministic oracle — end-to-end, and nothing less counts.** Run one real mission in Full mode with
`enable_zap=True` against a standing lab, then assert **from the persisted event log**:
1. ≥ 1 `tool_call` row with `tool == "run_zap"`;
2. its paired `tool_result` is `success=True` with a note beginning with a policy token;
3. the mission's ZAP state in the report is derived from (1), not from the request flag.

**Negative control (four).** **(a)** The same mission with `enable_zap=False` produces **zero**
`run_zap` rows and a report that does not claim ZAP ran. **(b)** With the ZAP daemon **stopped**, an
`enable_zap=True` mission must degrade *visibly* — a recorded unreachable-daemon error, not a silent
skip and not a crash. **(c)** With the AJAX spider forced to raise, the ToolResult note must say so
while the passive alerts survive (mirroring the existing `ascan_err` behaviour). **(d) Non-vacuity**:
assert the mission actually completed and produced > 0 tool calls, so an aborted mission cannot pass
control (a) for free.

**Mutation tests.** Set `enable_zap=False` in the e2e fixture → oracle 1 must fail. Re-introduce the
bare `except: pass` around the AJAX spider → control (c) must fail. Remove the `run_zap:{host}` key
uniqueness change (if targeted rescan is implemented) → the second, narrower pass must be dropped and
a test must catch it.

**Regression tests.** Missions in `active`/`passive` mode still never schedule ZAP; the 422 for
`enable_zap` outside Full mode is preserved; `require_zap` still blocks when the daemon is absent.

**False-positive risks.** ZAP's own alerts are `_CONFIRMED_BY_TOOL` (`agent.py:117`) — confirmed by
construction. Turning ZAP on for the first time in 151 missions will introduce a **new false-positive
source into the report that has never been measured.** The DoD must include an FPR check on a clean
paired lab before ZAP is enabled by default anywhere, and this ticket must **not** change the default.

**Definition of done.** The three oracle assertions from a real mission's event log; all four negative
controls; the dead write and the bare swallow fixed; a `liveness.py` CHECKS entry that fails when a
ZAP-enabled mission produces zero `run_zap` rows; **and the fifth cause named, with the measurement
that identified it.** Closing this ticket by flipping `enable_zap` is explicitly not acceptable.

**Expected benefit.** Either a whole DAST capability the platform ships and has never run, or —
equally valuable — a measured decision to remove the claim. Both beat the current state, where the
product describes a capability that has executed zero times in 151 missions.

---

## LANE OWNERSHIP — cycle 9, 2026-08-17. Declared BEFORE spawning, three lanes, disjoint by file.

Erwin: *"Auto start finish the queue. Automate this shit. I shouldn't have to keep telling you."*
Everything `ready` is now assigned. The autocontinue watchdog was also rewritten so this does not
depend on anyone asking: a clean tree with ready tickets is no longer a reason to stop, and it now
spawns lanes instead of grinding the queue serially.

| lane | owns (WRITE) | tickets |
|---|---|---|
| engines | `agent/tools.py`, `agent/upload_tool.py`, `agent/tests/test_description_gate.py`, `agent/tests/test_truthful_metadata.py`, `docs/handoff/engines.md` | Q-068 (canonical coordinates), Q-058 (two tier docstrings, `hash_type`, four untiered engines) |
| provenance | `agent/agent.py`, `agent/report.py`, `docs/handoff/provenance.md` | Q-060 (origin rebuilt from a port-stripped scope entry), Q-064 (false integrity alarm, fix by binding the dispatch name) |
| ledger-status | `agent/main.py`, `docs/handoff/ledger_status.md` | Q-067 (a negative result recorded as a failure) |

Coordinator keeps `docs/QUEUE.md`, `docs/STATUS.md`, `docs/LEDGERS.md` and does not work inside a lane.

**Remaining after these land:** Q-052 (a PRODUCT decision for Erwin, not an engineering one — both
proposals measured and rejected), plus the UNSWEPT tail recorded in the 2026-08-17 sweep block, which
is marked UNKNOWN rather than open because its markers predate several closes and I have not verified
their claims against code.

---

## LANE OWNERSHIP — cycle 10, 2026-08-17 evening. The tail, declared before spawning.

The engineering backlog above is empty. What is left is the tail whose markers predate several
closes, which the last sweep recorded as UNKNOWN rather than open because guessing a total is the
same defect this queue keeps producing. Three lanes, disjoint by file.

| lane | owns (WRITE) | scope |
|---|---|---|
| tail-sweep | `docs/handoff/tail_sweep.md` ONLY, read-only on product code | verify Q-001..Q-023, Q-030/035/036, B-011+, `00438`, the sublinear per-URL cost against CODE; verdict + evidence per ticket |
| source-lane | `agent/codereview.py`, `agent/tests/test_source_lane_*.py`, `docs/handoff/source_lane.md` | Q-041 (aliased imports invisible - a false NEGATIVE in a scanner), Q-042 (`_PY_CLOCK_TOKEN` matches a substring - a false POSITIVE) |
| boolean-oracle | `agent/sqli_tool.py`, `agent/nosqli_tool.py`, `agent/tests/test_sqli_boolean_noise_floor.py`, `docs/handoff/boolean_oracle.md` | Q-040 (no baseline-stability control - a false POSITIVE in a CONFIRMATION oracle) |

All three tickets are pinned by STRICT xfails, so each fix must INVERT its pin in the same commit
rather than delete it. Q-041 and Q-042 pull in opposite directions on purpose - one under-matches and
one over-matches - so a fix that trades one error class for the other is not a fix, and both lanes
were told so.

Held for the next cycle because they collide on `agent/tools.py`, which the boolean lane may need:
**Q-043** (`Retry-After` unhonoured, and the Coordinator once asserted it was honoured) and **Q-044**
(the code-assisted lane is benchmark-only; 61.1% is not reachable in an engagement).

**Still the only item that is genuinely Erwin's and not mine: Q-052.** Both proposals measured and
rejected. 40 of 111 engines are structurally unselectable at `active`, which is why an unauthenticated
active scan yields leads rather than confirmations. Nobody should ship a third proposal without a
decision about what `active` is supposed to mean to a user.

---

## LANE OWNERSHIP — cycle 11, 2026-08-17 late. Three lanes, disjoint by file.

| lane | owns (WRITE) | scope |
|---|---|---|
| effects | `agent/engine_descriptor.py`, `agent/techniques.py`, `agent/effect_search.py`, `docs/handoff/effects.md` | Q-007 - the negative-effects model is generated entirely by a phantom |
| backoff | `agent/tools.py`, `agent/browser_engine.py`, `agent/zap_client.py`, `docs/handoff/backoff.md` | Q-043 - `Retry-After` documented but not implemented |
| tail-sweep run 2 | `docs/handoff/tail_sweep.md` ONLY, read-only on product code | Q-003/004/005, Q-015..Q-018, Q-021B/D/E/F, Q-022, Q-023, Q-030/035/036, B-011+, `00438`, the sublinear cost |

`weak_password_reset` also appears in `report.py` and `benchmark.py`; the effects lane may not edit
those and hands the patches over instead. Q-043's ledger visibility may need `main.py`, which it also
may not edit - same rule.

**Q-044 is HELD, not forgotten.** It touches `main.py`, `codereview.py`, `codeintel.py`,
`owasp_bench.py`, `bench_juliet.py`, `poc_bundle.py` and `proof_schema.py` - it would collide with
two live lanes at once. Declaring that beats discovering it in a merge, which is what cost a night
earlier this week.

**Q-052 remains Erwin's**, and is the only queue item nobody should close on his behalf: 40 of 111
engines are structurally unselectable at `active`, both proposals were measured and rejected, and
what `active` should MEAN to an operator is a product decision rather than an engineering trade.

---

## LANE OWNERSHIP — cycle 12, 2026-08-18. Three lanes, disjoint by file.

| lane | owns (WRITE) | tickets |
|---|---|---|
| controls | `agent/report.py`, `docs/handoff/controls.md` | Q-071 - `control_status` reports "no control recorded" on the only 3 findings that have one |
| bimodal | `agent/sqli_tool.py`, `agent/nosqli_tool.py`, `agent/tests/test_boolean_oracle_stability.py`, `agent/tests/test_sqli_boolean_noise_floor.py`, `docs/handoff/bimodal.md` | Q-070 - one repeat cannot establish stability on a bimodal page; 18 of 120 triples still confirm on clean responses |
| scope-guard | `agent/main.py`, `docs/handoff/scope_guard.md` | Q-018 - the retest scope guard FAILS OPEN; Q-017 - 13 raw vs 7 gated `get_findings` sites |

Each brief carries the two-sided DoD, because all three tickets can be "fixed" by breaking the other
direction: Q-071 by reporting RECORDED for everything, Q-070 by refusing to confirm anything, Q-018
by refusing every retest. **A fix that trades one error class for the other is not a fix**, and this
project has already paid for that once.

Q-018 first within its lane: a scope guard that fails OPEN removes the check keeping a retest inside
the target the operator authorised, which is the boundary between authorised testing and touching
something nobody asked for. The `scope.load_manual` raise is CORRECT; the caller mishandles it, so
the fix belongs in the caller and the lane is told not to loosen `scope.py`.

**Still open after these, and honestly ranked:** Q-074 (the effects model is now empty rather than
wrong - populate `session_lifecycle`'s real invalidations), Q-021D/E/F, Q-003/004/005 (genuine new
capability), the re-scoped Q-023/Q-030/Q-036, Q-035 (an experiment, not a defect), and **Q-044**,
still held because it touches seven files and would collide with two live lanes.

**Q-052 is unchanged and remains Erwin's.** 40 of 111 engines are structurally unselectable at
`active`; both proposals were measured and rejected; what `active` should MEAN to an operator is not
an engineering trade.

---

## LANE OWNERSHIP — cycle 13, 2026-08-18. Three lanes, disjoint by file.

| lane | owns (WRITE) | tickets |
|---|---|---|
| effects run 2 | `agent/engine_descriptor.py`, `agent/techniques.py`, `agent/effect_search.py`, `docs/handoff/effects2.md` | Q-074 - the negative-effects model is EMPTY rather than wrong; populate `session_lifecycle`'s real invalidations |
| findings-gate | `agent/main.py`, `docs/handoff/findings_gate.md` | Q-017 - 13 raw vs 7 gated `get_findings` sites; Q-023 - ZAP's one remaining live clause |
| postMessage | `agent/dom_tool.py`, `agent/tools.py`, `docs/handoff/postmessage.md` | Q-003 - `postMessage` as a DOM-XSS source (CWE-346 -> CWE-79) |

**Q-003 is the first genuine CAPABILITY ticket in a long run of correctness fixes**, and its brief
carries the standard that makes it worth doing: a static match on `addEventListener("message")` is a
LEAD, not a finding. Detect the listener, check whether `event.origin` is validated, and CONFIRM by
driving a real message into the sink. If confirmation is not reachable this cycle, ship the lead and
say so - **do not grade an unconfirmed static match as `confirmed`**, because a false confirmation is
the most expensive defect class here.

All three lanes were told to measure before building. Four tickets in four days turned out wrong in
scope, mechanism, or existence - one was already implemented and this file listed it CLOSED and
`ready` simultaneously - so each brief says plainly that disproving its own ticket is a full result.

**Still open after these:** Q-021D/E/F, Q-004/Q-005, the re-scoped Q-030/Q-036, Q-035 (an experiment
rather than a defect), and **Q-044**, still held because it touches seven files including `main.py`,
which the findings-gate lane holds this cycle.

**Q-052 remains Erwin's and nothing this cycle touched it.**

---

## LANE OWNERSHIP - cycle 14, 2026-08-18. Three lanes, disjoint by file.

| lane | owns (WRITE) | ticket |
|---|---|---|
| gate-truth | `agent/deadcode_gate.py`, `agent/tests/test_deadcode_gate.py`, `docs/handoff/gate_truth.md` | Q-077 - a COMMENT mentioning a function makes it look alive, so both baselines are floors not truths |
| proof-reach | `agent/tests/test_proof_gate_reach.py`, `docs/handoff/proof_reach.md` | Q-076 - 11 raw sites vs ceiling 14, slack 3, names ZERO of them while holding every file:line |
| tech-intel | `agent/intel_registry.py`, `agent/intel_extractor.py`, `agent/archive_intel.py`, `docs/handoff/tech_intel2.md` | Q-021D (ingest reaches candidate, production stays 0, advance has no caller outside tests), Q-021E (re-scoped DOWN: Q-021B already emits has_versions, only the consumer is missing), Q-021F |

Two of the three are the SAME defect shape in different instruments: a gate that reports a count or a
slice instead of naming what changed. Q-075 closed the first instance and `liveness.py::evaluate()`
has had the right shape all along, so this is convergence on a pattern the project already owns
rather than three inventions.

`agent/main.py` is held by NO lane this cycle and stays free for the Coordinator. The tech-intel lane
hands over any `main.py` patch rather than taking it.

**Still open after these:** Q-004, Q-005 (the postMessage lane already checked Q-005 before anyone
starts it - read its handoff first), the re-scoped Q-030/Q-036, Q-035, and Q-044.

**Q-052 remains Erwin's.**
