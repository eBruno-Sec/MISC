# STATUS — live squad dashboard

Updated by the Coordinator. Numbers here must match [LEDGERS.md](LEDGERS.md); if they disagree, the
ledger wins and this file is stale.

**Last update**: 2026-08-21. **This file is one of four criteria the `apolaki-autocontinue` watchdog
checks before retiring itself, so leaving it stale silently disables that retirement.** Updating it is
not bookkeeping. It rotted three cycles running (08-13, 08-16, 08-19) before that was written down.

# RELEASE-STABILIZATION MODE — since 2026-08-20

Feature work is FROZEN. The unit of progress is a **measured invariant closed with its denominator**,
not a ticket closed. Two lists, and new discoveries do not interrupt a live lane unless they are
reproducible release blockers.

## The release-invariant matrix — measured at `9c8f3a9`

    full suite   3507 passed / 11 skipped / 12 xfailed / 0 failed   isolated snapshot at 2957031
                 +33 over 3474 accounts exactly: the three new guards define 8+17+8 = 33 tests
    gates        queue_gate OK (79 headers, 60 hashes) · bake_drift OK · liveness 17/17

| # | invariant | measured | denominator |
|---|---|---|---|
| I-1 | scheduler / parent / **executable** manual contract | ✅ | 6 manual-only of 110 engines, contract traverses the real dispatch boundary |
| I-2a | exactly one persistence owner | ✅ 0 unowned | 62 finding-producing engines |
| **I-2b** | **outcome fidelity** | ✅ guard shipped; 3 defects fixed, 1 pinned | 14 multi-outcome owners of 2469 functions; violating sites **8 -> 3** |
| I-3 | shared rate policy | ✅ 0 ungated | 178 production modules |
| I-8 | guard scans its claimed scope | ✅ 4 of 4 | one was RENAMED not widened, deliberately |
| I-10 | strict xfail has reason + ticket | ✅ 12 of 12 | AST count, not `grep -c` |
| I-4 | control per confirmed finding | ⏳ CLAIMED closed, NOT yet verified | was 303 runtime of 1391; guard `test_runtime_control_invariant` 17 tests |
| I-5 | no swallowed clean | ⏳ CLAIMED closed, NOT yet verified | was 562 of 917 handlers; guard `test_silent_failure_invariant` 8 tests |
| I-9 | caps preserve highest-value ordering | ⏳ CLAIMED closed, NOT yet verified | never measured by us; guard `test_cap_ordering_invariant` 8 tests |
| I-11 | reachable / framework-invoked / retained-with-reason | ❌ **44 vs ceiling 37** | pin held; three lanes declined to force it |

## SHIP GATE GREEN: 3581 passed, 11 skipped, 12 xfailed, 0 failed - Q-093 CLOSED

Independently verified by the Coordinator on a clean `git archive HEAD` snapshot on `apolaki_default`.
Q-093 closed both root causes with 0 engines edited, each gate filed RED before its fix.

**The near-miss worth remembering: the fix nearly shipped DATA LOSS.** `agent.py:874` guards auto-store
with `if not result.error`, so stamping a transport error on a dispatch that DID produce findings would
have **deleted them from the mission**. The `produced` parameter exists solely to prevent that. A fix
at a chokepoint inherits every downstream consumer of the field it starts setting.

**And Q-019 had appeared to close the empty-netloc bug.** All 1495 corpus dispatches genuinely predate
it, yet the real `next_batch` still emitted `https:///static/b.js` the same day. `planner._addressable`
read 2 of the module's 4 target keys, **and Q-019's guard collects the same 2** - its coverage exactly
congruent with the code's blind spot. **A guard that restates the code's assumptions inherits the
code's blind spots.** That is the fourth instance of this pattern this week and the sharpest.

### Previously (Q-092 cycle): 3562 passed

Verified INDEPENDENTLY by the Coordinator on a clean `git archive HEAD` snapshot attached to
`apolaki_default`, matching the lane's own figure exactly. Lane-open baseline was 3519 passed:
**+43 passing, none lost, and all 8 failures HEAD was carrying are gone.**

Both groups were closed **by fixing production**. Neither guard file was edited, no baseline was
raised, no exemption was added. That is the distinction that matters: the guards did not become
satisfiable, the code became correct.

**`_cmd` now returns `CmdResult`, a 2-length tuple subclass** - every `out, err = await self._cmd(...)`
unpack still works, `result == (out, err)` still holds, and the exit status rides on
`result.exit_code`. Same family as `FindingWriteId` (Q-089) and `FindingUpdateResult` (Q-090): **the
carrier is the thing callers already read.** A third tuple element was rejected because 6 of the 18
sites ignore `err` today and would ignore a third slot as easily. Twelve scattered
`err.startswith("__MISSING__")` checks collapsed into one shared `_cmd_failure()` predicate, defaulted
so the safe direction is what you get by not thinking about it.

### The first fix was wrong, and a DIFFERENT lane's guard caught it

The initial attempt carried the status only in an `__EXIT__` sentinel fired when the exit was non-zero
**and** stdout was empty. The measured sqlmap case exits 2 with an **ASCII banner on stdout**, so the
rule never fired. **Non-empty stdout is not the same as a produced result.**

This is the week's thesis landing in practice: a guard written by one lane caught a defect in a fix
written by another, one turn before it would have shipped looking correct. It is the strongest
available argument for the rule that **a guard does not count until someone who did not write it has
made it fail** - and here, for its converse: a fix does not count until a guard someone else wrote has
had a chance at it.

### Ceilings: none raised, and one stopped being a budget

Verified against `66a7012`. `_swallowed optional` **388 -> 387** (lowered). Literal-return
`load-bearing` **`<= 15` -> `== 0`** - tightened from a budget into an equality, so a single new
load-bearing swallow is now red rather than absorbed. The other three were already touching their
measured count, so every ceiling now sits on its real value with **zero slack anywhere**.
`_SWALLOW_RECORDERS` is a FLOOR and was raised 80 -> 95 owners, which tightens.

### Owed, stated rather than rounded up

Four `_run_hash_crack` call sites consume the swallow's DEGRADED visibility but do not yet report
`ran=False`. `_run_metadata` is correctly left alone because it has a genuine native fallback.
**Q-093 (`_http`) remains open and is the larger half of this defect class.**

## RELEASE BLOCKER, CRITICAL: engines that never ran, reported as clean scans

Chasing one stale queue question (Q-053 GAP-2, "why zero dalfox findings in 1783") opened the largest
defect class this project has found. **Confirmed, live, on authorized targets:**

| tool | corpus | what is actually wrong |
|---|---|---|
| `run_nuclei` | **0 / 155 runs** | nuclei v3 renamed `-json` to `-jsonl`. `nuclei -json` exits **2 before scanning** and writes the error to STDOUT, so `err` is empty and the `__MISSING__` check passes. **It has never run in this build.** It is the primary breadth scanner. |
| `run_dalfox` | **0 / 171 runs** | emits a JSON ARRAY; the parser reads JSONL. Every line of a multi-line array is invalid standalone, so the yield is pinned at 0 for ANY output. |
| `run_sqlmap` | **0 / 58 runs** | exits 2, reported clean; and all 58 corpus runs used valueless params that miss a SQLi the same command confirms with a value. |

**Every external-binary wrapper in `_CONFIRMED_BY_TOOL` is in the zero list** (nuclei, dalfox,
check_takeover, sqlmap). The tools Apolaki trusts MOST as confirmatory have collectively never
confirmed anything.

**One root cause, two chokepoints, both the SAME defect as Q-089/Q-090: the outcome is measured
correctly and dropped at the return edge.**
- `_cmd` captures `proc.returncode` into `_exit`, uses it only for the provenance record in its
  `finally` block, and returns `(out, err)` without it. **No caller CAN check exit status.**
- `_http` returns `status` and `error` honestly; **the callers do not read them.** This one is bigger:
  it reaches all 21 pure-Python engines rather than the 14 that shell out. **3241 of 27222 corpus
  dispatches (11.9%) could not have reached their target** - 1746 `https` fired at plaintext-only hosts
  and 1495 with an empty host (`https:///`, a URL builder that lost its netloc). Every one was reported
  as a completed scan.

**The sharpest single case is `run_client_checks`:** it demonstrably WORKS and produced a live true
positive on DVWA, yet 275 of its 348 runs were fired at URLs that never opened a socket. **Its zero
histogram is not one phenomenon, it is two.** That is why a zero histogram is a SIGNATURE and never a
verdict: `run_ssi`, `run_waf_bypass` and `run_sqli_structural` were reproduced live and are CORRECTLY
QUIET.

**I filed the original ticket with the wrong attribution** - I blamed `_cmd` for all 24, and 21 of the
remaining 22 never shell out at all. The census signature was right; the cause was not. Corrected in
`0f343aa`.

**Nothing anywhere in the pipeline could tell a failed tool from a quiet one.** The log, the report and
the ledger are byte-identical either way, which is how this survived 155 and 171 invocations unnoticed.

## ALL THREE CODEX GUARDS WERE UNFALSIFIABLE. Measured, not suspected.

Codex shipped three guards closing I-4, I-5 and I-9, then became unavailable. Each was mutation-tested
by a lane that did not write it. **Each one fired on its positive control and not on the same defect
expressed slightly differently.** Three for three.

| invariant | the positive control | the defect it could NOT see |
|---|---|---|
| I-4 | pinned emitters it NAMED | deleting `negative_controls` from an emitter it did not name -- full suite stayed **byte-identical at 3507** |
| I-5 | handler ending `return None` | the same deletion ending `return out` -- **one token**. `_swallowed()` applies `_constant()` to its Assign branch and not its Return branch, so `out = []` is seen and `return []` is not. **89 handlers already exploit this at HEAD, 15 load-bearing**; the 160 `_swallow` nodes across 80 owners were pinned by nothing |
| I-9 | `param_eps[:8]` -> `[:6]` | swapping two comprehensions at `planner.py:720` evicts the operator-authorized root from the DOM audit -- the exact thing the contract forbids -- and the inventory stays **byte-identical**. `planner.py:720` was executed, mutated, and still green |

**The pattern is not sloppiness.** Every one was written alongside a correct fix by a careful lane, and
every one pins exactly the sites its author had just touched. That reads as complete and is not. **A
guard is scoped to its author's attention unless someone else tries to break it.**

All three now follow the I-4 repair shape: an AST inventory of real production sites, ratcheting in the
**DELETION direction only**, message names the owner -- and none asserts the strong claim, because all
three strong claims are false. Adding is never blocked; removing is red.

**This is why ⏳ CLAIMED exists in this table.** All three were one turn from ✅ on the strength of a
passing new test.

**I-5/I-9 residue, recorded rather than closed**: 19 of 20 I-9 cap contracts are still prose-only, and
the 15 named literal-return handlers are capped but not fixed (the patch routes each through
`_swallow`; production was not writable by that lane). And its three-container concurrent full-suite
run was **OOM-killed, exit 137 on all three**, so "no OTHER test notices the hunt mutants either" is
**UNVERIFIED** -- not green. Re-run sequentially; three concurrent full suites do not fit in this VM.

### Instrument fact: `git archive` emits CRLF on this machine, so that is never your explanation

A lane died holding the conclusion that ~107 snapshot differences were *"CRLF vs LF -- `git archive`
emits LF, the working tree has CRLF."* **Measured, that is false:**

```
git archive HEAD -> agent/exposure_tool.py : 231 CR bytes
working tree     -> agent/exposure_tool.py : 227 CR bytes   (delta 4 == the 4-line paths() deletion)
```

Both are CRLF under `core.autocrlf`, and the only gap is real edited content. The censuses are
`ast.parse(path.read_text(encoding="utf8"))`, and Python text mode translates newlines anyway, so line
endings cannot move an AST count in either direction.

The real cause was that the lane built its snapshot with `cp -r` of the SHARED working tree while other
lanes had uncommitted edits in it -- **a torn read, exactly the hazard rule 8c exists for.** It then
attributed real cross-lane signal to an encoding artifact and was one step from dismissing it.

**This is the dangerous shape of a wrong instrument reading: it does not look like an error, it looks
like an explanation.** A benign-sounding cause for an unexplained delta is the single easiest way to
retire a real finding. Snapshots come from `git archive HEAD`, never `cp -r`.

**I-2b is the invariant this week earned.** I-2 counted EDGES and measured 0 unowned *correctly* —
Q-089's defect lived on the RETURN edge, which an ownership census does not traverse. `db.add_finding`
answered "id" when the caller asked "stored". **An invariant that counts structure cannot see a defect
that lives in a value.**

## Lanes right now

| lane | scope | state |
|---|---|---|
| Codex (external) | I-4 · I-5 · I-9 | DELIVERED and merged `55016f4`; unavailable for the rest of the week |
| Claude A | verify the 3 new guards by mutation, then Q-090-D | LIVE |
| Claude B | I-11: the 7 uncalled, then as many of the 37 as resolve | LIVE |
| Coordinator | queue · STATUS · integration · mutation-verification of every returned lane | — |

**CODEX IS OUT FOR THE WEEK.** Its value was INDEPENDENCE, and a Claude lane I brief is not independent
of me. The substitute is not another agent -- it is mutation on every claim, including my own, with the
same suspicion I apply to a returned lane. Five of the last ten instrument errors here were mine and
every one was caught by RUNNING something, not by reasoning about it.

**Nothing merged is trusted until mutated.** I-4/I-5/I-9 are marked CLAIMED, not closed, precisely
because 1690 lines and three new guards arrived with no independent check. A guard that cannot fail is
worse than no guard: it converts an open question into a false assurance, and four have shipped here.

## The recurring shape, five instances in one week

Producer and consumer are two halves and only one is ever enforced: Q-051 (mode key), Q-050
(auto-store), Q-084 (a parameter nothing read), Q-053 (a stale reason on a live capability),
report-integrity (`checks_run` = the checklist's size). Q-089 is the sixth and the sharpest, because
the two halves were a value and its reader.

## Method failures worth more than the fixes

- **A mutant that "survives" because the mutation never applied is a false all-clear.** Six times in
  two days, four of them mine. Verify the edit landed — grep it, or assert through the imported
  module — *before* believing any mutation result.
- **`grep -c` counts LINES, AST counts NODES.** I reported a wrong strict-xfail delta by mixing them
  when the AST tool was already built.
- **A zero from an instrument that cannot see the common case is not a measurement.** Four of mine
  this week: `mod.attr(` missing aliased imports, a guessed finding-key vocabulary, a hardcoded
  "2 of 10", `reason=` bound to a module constant.
- **Grouping by symptom and calling it a root cause.** Q-088 was filed as "four consumers of one
  chokepoint"; three of its premises were false and the four markers have four closing conditions.
  Committed by the Coordinator two turns after writing the opposite rule into three lane briefs.
- **One snapshot, one run.** Never rebuild a directory a container still has mounted.

## Lanes — 2026-08-20, ALL STOOD DOWN, cycle folded

Every lane below ran to a verdict and its work is merged. **No lane is live.** Six Claude lanes were
killed by three separate session limits during this cycle and every one of them was recovered,
because each committed per slice.

| lane | ticket | verdict |
|---|---|---|
| Vendor scope | Q-083 | **CLOSED.** Blast radius measured at 1 of 716 findings (0.141%) BEFORE any fix, and the obvious `*.min.js` rule proven to miss every modern bundle. Found a SECOND tree walk with the same blind spot at 175x the radius. The marker now reaches the operator's screen, not just the API |
| Island triage | Q-078 | **Ratchet still pinned** by a strict xfail, correctly. Two runs refused to raise `QUALIFIED_BASELINE` to make it pass. Its own anti-rot check caught `payloads_for` |
| Negative effects | Q-074 | **CLOSED: "it is decoration."** ONE production reader, `POST /orchestration/audit`. `agent.py` and `planner.py` import neither the module nor `effect_search`. No scheduling decision changes because a row exists |
| Deterministic reach | Q-050 | **CLOSED.** Real detection engines a deterministic mission cannot select: **5 -> 2**, and neither of the two is cited by any control catalogue, so no coverage claim is backed by an unreachable engine. `run_nosqlmap` deleted as a proven duplicate (111 -> 110 engines) |
| Rate policy | Q-043 | **HALF CLOSED.** Mechanism built and measured; the "bare-429 gap" turned out to be a designed boundary. Coverage half moved to Q-085 |
| Codex Q-085 | Q-085 | **PARTIAL, merged `8a59a96`.** Live no-DoS breach closed structurally; guard widened repository-wide; 25 -> 21 ungated calls, 13 -> 12 modules, pinned by a strict xfail |

Queue: **76 ticket headers, 51 cited hashes all real, 0 contradictions** (`scripts/queue_gate.sh`,
now wired into CI with a shallow-clone guard that exits 2 rather than reporting 45 false failures).

Open and unowned: **Q-085** (21 ungated target calls across 12 modules; `bie.py` sharpest at 6
`page.goto`), **Q-086** (the ZAP guard proves presence and calls it absence), **Q-078** (ratchet at
51 vs ceiling 37), **Q-044**, **Q-053**, **Q-062**, plus the seven untriaged auto-store engines held
by a strict xfail in `test_auto_store_reach.py`.

Tree: **3331 passed / 11 skipped / 14 xfailed / 0 failed** at the Codex merge, measured on an
isolated snapshot. Later commits are re-measured per commit rather than assumed.

**Two things worth carrying forward from how this cycle went wrong.**

A lane started its final suite TWICE against the same snapshot directory and rebuilt the directory
between the two starts, so the first container had its mount recreated underneath it. It caught
itself and derived a better rule than the one we had: **one snapshot, one run, and never rebuild a
directory a container still has mounted.** `docker inspect -f '{{range .Mounts}}{{.Source}}{{end}}'`
is how the duplicate was found. Adopted.

And a mutation of mine SURVIVED, then turned out never to have been applied - the `perl` substitution
silently matched nothing. **A mutant that "survives" because the mutation never landed is a false
all-clear**, and it would have let me claim a test catches something I had not tested. Verify the
edit landed (grep it) before believing a surviving mutant.

**The queue itself grew a gate today, because it had gone stale eleven times.** Closing a ticket and
updating its header are two actions and only one was ever enforced. The eleventh sweep found the
mechanism behind the other ten: the file carried a SECOND copy of some tickets, and Q-020 read
**CLOSED** at line 102 and `proposed` at line 2119 simultaneously. `scripts/queue_gate.sh` now checks
that every cited hash exists in history and that no ticket id carries two headers whose states
contradict. Its negative control is the only reason to believe it: run against `docs/QUEUE.md` as it
stood at HEAD before the fix, it exits 1 and names Q-020 with both line numbers.

## Lanes, earlier cycles

| lane | owner | state |
|---|---|---|
| Routing (Q-066/020/065) | — | **CLOSED, 7 commits.** Disproved my ticket's mechanism, then built the join anyway: 75/88 techniques routed, 0 phantom. Found and fixed a fifth vocabulary mismatch that made `run_jwt` unreachable on any Bearer-token target |
| Ledger truth (Q-061) | — | **LANDED** `5c466a2` after recovery. Killed having committed nothing; its handoff claimed 7 items DONE with the evidence never written, corrected in place |
| Report honesty (Q-063) | — | **LANDED** `4d3b51d` after recovery. Killed having committed nothing and written no handoff at all; reconstructed from the diff |
| Truthful engines (Q-054/055/055b) | — | **CLOSED.** All three sinks shut, metadata reads binary EXIF, and the bfla engine's "authenticated" row is no longer anonymous |
| Arsenal gap (Erwin's question) | — | **CLOSED by measurement**, killed by a limit but wrote as it went. Found the deployment is 59 commits stale and two engines cannot test a non-standard port |
| Description gate (Q-056) | — | **CLOSED.** PARTLY gateable: 2 rules at 0 FP over 111 engines, 3 rejected with numbers. `run_metadata` is not gateable by any static rule and only running it catches it |
| Islands soundness (Q-050b) | — | **CLOSED.** 7 verdicts; 3 engines deleted outright |
| Sessions / `Identity` (Q-032) | — | **CLOSED.** The anonymous authz row was carrying the mission's session |
| Tech intelligence (Q-021C) | — | **CLOSED.** One chain end to end; the server/language half is still a version reporter |

Tree at HEAD: **2799 passed / 11 skipped / 9 xfailed / 0 failed** (531s, `--network apolaki_default`,
pytest's own exit code captured directly). The **+31 over 2768 accounts exactly**: `test_engine_routing`
18, `test_effect_search_routing` 10, `test_planner_jwt_gate` 3. The `auth_headers` fix added no test —
it INVERTED the lane's pinned defect test rather than deleting it, and added a negative control inside it.

Previous step: **2768** (+20 over 2748 — 8 ledger-dispatch, 11 arsenal-class, 1 metadata).

**A test went red because the product got better, and that is worth remembering.** Baking `exiftool`
into the image (Q-059) flipped `run_metadata` from its native reader to exiftool. Both recover the same
GPS point; they spell it differently (`59 deg 25' 16.17" N` vs `59.4211583333333`). The end-to-end test
asserted the DMS substring — it was pinning one reader's spelling, not the disclosure — so it failed on
an improvement. It now pins the POINT to 4 dp, which is strictly stronger: it would catch a reader
returning plausible numbers for the wrong location, and a substring never could. **The product half is
NOT fixed** — see Q-068; a deterministic-first tool must not emit different evidence text on two
installs.

Previous baseline for reference: 2748 passed / 11 skipped / 9 xfailed.
Measured twice: once on a tree I edited mid-run, then again on a stable tree to clear the torn read,
with pytest's own exit code captured directly rather than through a pipe. Identical both times.

The **+76 over the 2672 baseline accounts exactly**, which is the point of writing it down: 73 new
tests (`test_truthful_metadata` and `test_truthful_bfla_identity` both collect more than their `def`
counts — parametrized), plus 2 strict xfails retired when the defects they pinned were fixed, plus 1
test that had been SKIPPED off-network and now runs. Every xfail is a STRICT marker
pinning a named live defect — removing one without fixing what it pins is forbidden, and when the
defect *is* fixed the marker XPASSes and turns the suite red on purpose, forcing a deliberate
retirement.

## Unproven claims and open blockers — read this before quoting a number

- **Q-052 is a PRODUCT question, not an engineering one, and it is the oldest unresolved item.** Both
  proposals were measured and rejected: narrowing `active` costs 49.5% of the sweep and 7 of 18
  engines including the entire SQLi surface; defaulting to `full` would enable state-changing writes
  and lab-calibrated traversal semantics against production targets. The evidence points at loosening
  `planner._ALLOWED`. **Nobody should ship a third proposal without deciding what `active` means.**
- **The deployment WAS 59 commits behind the tree — FIXED and verified 2026-08-17 02:40 (Q-059).**
  `bake_drift_check.sh` now checks image-vs-tree and reads `exit 0` on all three edges. In the
  running container: the five Q-051 reporting functions are present (all were absent), the three
  adapters deleted in `466bae8` are gone (both were still dispatchable), `description_gate` /
  `ws_tool` / `mass_assign_tool` import, `exiftool` is on PATH (closing the half of Q-055 no code
  change could reach), and the denominators are 111/76 matching the tree rather than 112/77.
  **STILL LOAD-BEARING FOR READERS: anything measured against the deployment BEFORE that timestamp
  describes the stale platform and must be re-measured** — including the arsenal lane's own
  live-mission ledger extraction from mission `6ddc56f6`.
- **Counting xfails: the lab network moves the number, so quote it with the network state.** 9 strict
  markers, 9 xfailed. The prior baseline read 10, and the difference is NOT a lost pin: two
  `test_island_soundness.py` xfails were retired when Q-054/Q-055 landed (−2), while one
  network-dependent test that had been SKIPPED off-network now runs and xfails (+1). Skips moved
  13 → 11 in the same direction, which is the corroboration. Note also that `grep -c 'xfail(strict=True'`
  over-counts: `test_sweep_class_coverage.py` contains that exact string inside a comment, so it
  reports 3 markers where 2 exist.
- **A red test is a hypothesis about the code, not a fact about it (2026-08-17).** A full suite read
  `1 failed / 2741 passed` and I nearly attributed it to the slice I had just written. The failing
  test drives the live lab by compose DNS name; my throwaway container was on the default bridge, so
  `juice-shop` did not resolve. On `--network apolaki_default` it passes 39/39. **Every suite run
  needs `--network apolaki_default`.**
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
