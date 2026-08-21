# Guard verification lane — Q-090 (independent, Breaker-first)

Baseline: HEAD `55016f4` (merge of `codex/q090`). Nothing in this document is read from
`docs/handoff/codex_q090.md`; every number below was re-measured here, and every mutant was
verified to have landed before its result was believed.

## Method

All runs use a throwaway container over an **immutable snapshot** of the agent tree taken with
`git archive HEAD apolaki/agent` (8.1 MB, 178 top-level production modules). `apolaki-agent-1` was
never touched, nothing was `docker cp`-ed into it, and no image was rebuilt. Mutants each get their
own snapshot directory; a directory is never edited while a container has it mounted.

```
MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default \
  -v "<scratch>/snap_<id>:/app" -w /app apolaki-agent \
  python -m pytest <files> -p no:cacheprovider -rfE
```

Every patch is applied byte-wise with CRLF preserved and asserted to match **exactly once**, then
diffed against the pristine snapshot so the diff is the mutation and nothing else, then verified a
second time *through the imported module inside the run container* (`inspect.getsource` /  calling
the mutated function) — because a mutant that "survives" a mutation that never applied is a false
all-clear, and that has happened seven times in this repo in three days.

Pristine baseline for the three guard files:

```
tests/test_silent_failure_invariant.py tests/test_runtime_control_invariant.py \
tests/test_cap_ordering_invariant.py   ->  33 passed in 14.53s, EXIT=0
```

## Result summary

| # | Guard | Mutation planted in production code | Outcome |
|---|-------|--------------------------------------|---------|
| M1 | I-5 | `tools.py` `_run_enumerate_ids`: `_swallow` recorder reverted to a bare `except:` | **KILLED** |
| M2 | I-4 | `xss_tool.reflection_finding`: emitter drops its `negative_controls` artifact | **KILLED** |
| M3a | I-9 | `agent.sweep_targets`: raw `targets[:7]` planted (syntactic) | **KILLED** (static) |
| M3a2 | I-9 | `crawl.bfs_frontier`: raw `frontier[:5]` in a module owning no contract | **KILLED** (static) |
| M3b | I-9 | `planner._rank_endpoints` returns discovery order (cap unchanged) | **KILLED** (execution) |
| M3c | I-9 | `agent.sweep_targets`: `list(targets)[:limit]` — truncate **before** rank | **KILLED** (execution) |
| M4 | I-4 | `tools._confirm_read_object_idor`: emitter drops its `negative_controls` | **SURVIVED** |

All three guards can fail. None of them is a guard that cannot fail. One of them has a
coverage boundary that matters (M4, below).

### M1 — I-5 kills a new silent swallow on a load-bearing path

Diff (single hunk, `tools.py:2354`):

```
-        except Exception as _apolaki_swallowed_2307:
-            self._swallow(_apolaki_swallowed_2307, 'tools:_run_enumerate_ids:2307', "")
+        except Exception:
             rbase = None
```

The protected block is `await self._http_send("GET", ...)` — a real load-bearing request, not a
fixture. Verified in the imported module (`_apolaki_swallowed_2307` absent from
`inspect.getsource(tools.ToolRegistry._run_enumerate_ids)`), then:

```
FAILED tests/test_silent_failure_invariant.py::test_partition_is_non_vacuous_and_matches_the_measured_rebased_tree
E   AssertionError: ['tools.py:2354:_run_enumerate_ids']
E   assert 1 == 0
1 failed, 7 passed
```

The assertion names the exact planted line. This is also the strongest possible proof the mutation
landed: the guard reported the file, line and function that were mutated.

### M2 — I-4 kills an emitter that drops its control artifact

`xss_tool.reflection_finding` no longer attaches the `harmless-reflection-canary` control. Verified
in the imported module by calling the emitter: the finding still grades `confirmed` and carries no
`negative_controls`.

```
FAILED tests/test_runtime_control_invariant.py::test_reflected_xss_retains_the_harmless_canary_control
E   AssertionError: assert 'not_recorded' == 'recorded'
1 failed, 16 passed
```

### M3 — I-9 kills both shapes it claims to cover

* **M3a / M3a2 (static inventory).** `raw first-N work caps without the measured contract:
  [('agent.py', 'sweep_targets', 'targets', '7')]` and
  `[('crawl.py', 'bfs_frontier', 'frontier', '5')]`. M3a2 matters more than M3a: `crawl.py` owns no
  entry in the contract table, so the scan demonstrably reaches production modules that were never
  part of the original inventory. **Disclosure:** M3a is *syntactic only* — it was planted where
  `targets` is still empty, so it changed no behaviour. It proves the inventory sees a new raw cut;
  it does not prove a behavioural kill. M3a2 is behavioural (it really truncates the frontier).
* **M3b (execution).** `planner._rank_endpoints` reduced to `list(endpoints or [])`; the cap constant
  was not touched.
  `E AssertionError: the endpoint cap discarded a command sink because it was discovered last`.
* **M3c (execution, the defect the lease names).** `sweep_targets` truncates before ranking:
  `_spread_by_shape(rank_targets_for_budget(list(targets)[:limit]))`. Two kills —
  `E AssertionError: assert {'alpha'} == {'alpha', 'beta', 'gamma'}` and
  `E AssertionError: early low-value shapes consumed the cap before the attack surface`.

  M3c is also the clearest measurement of the static guard's boundary: the static inventory did
  **not** fire on it, because the sliced value is a `Call`, not a bare `Name`. The execution tests
  caught it. Cut-before-rank is covered by execution, not by the inventory.

### M4 — I-4 SURVIVES an uncovered emitter dropping its control

`tools.ToolRegistry._confirm_read_object_idor` (owner-list IDOR) had its
`{"kind": "attacker-list-absence", ...}` control artifact deleted. Verified absent from the imported
module's source. Result:

```
tests/test_runtime_control_invariant.py  ->  17 passed, EXIT=0
```

This is a **coverage boundary, not a broken guard**. `test_runtime_control_invariant.py` is a list of
named emitters (7 SQLi builders, `exposure.classify`, `exposure.harvest_finding`,
`xss.reflection_finding`, `header_trust.finding_header_trust` / `finding_url_override`,
`_not_found_control`, `_mark_source_derived`). Every emitter it names is genuinely pinned. Emitters
it does not name — matrix IDOR, created-object IDOR, owner-list IDOR, foreign-owner IDOR, BIE BOLA —
can drop their control artifact and this file stays green. There is no repository-wide "every
confirmed behavioural emitter attaches a control" scan of the kind I-5 and I-9 both have.

**The whole suite misses it too.** Two full runs, same command, one snapshot each, run
concurrently:

```
pristine 55016f4   3507 passed, 11 skipped, 12 xfailed, 0 failed  in 1064.21s   EXIT=0
M4 mutant          3507 passed, 11 skipped, 12 xfailed, 0 failed  in 1060.46s   EXIT=0
```

Byte-identical outcomes. A confirmed runtime IDOR emitter can be shipped with its negative control
deleted and **not one of 3507 tests notices**. That is the honest scope of I-4 today: it is a pinned
list of emitters, not an invariant over emitters.

(The pristine number is also worth recording on its own: the `tools.py:1428` stale-dispatcher failure
the Codex handoff reports as its one remaining red is **not** red at the merge commit — the suite is
0 failed at `55016f4`.)

## Denominators, re-measured independently

### I-4 (prior: 1391 confirmed, 303 runtime with no recorded control)

Read-only over the named volume (`-v "apolaki_bbh_data:/data"`, `file:/data/bbh.db?mode=ro`). Key
names were **enumerated off the corpus**, never guessed.

Positive controls that the apparatus was looking: `findings=1783`, `missions=156`,
`tool_call logs=30173`, and a synthetic finding carrying `negative_controls` is classified
`recorded` by the same predicate used for the census.

```
confirmed                 1391
proof_kind  behavioural    675   source-derived   716
```

Reproduced exactly under the handoff's key set (`false_positive_check`, `success_oracle`, `timing`,
`validation`, `baseline`): **recorded 372 / missing 1019 / source-missing 716 / runtime-missing 303**.
Sensitivity to the definition, which is the reason this number needs stating with its predicate:

| key set | recorded | missing | source-missing | runtime-missing |
|---|---|---|---|---|
| 5-key (handoff) | 372 | 1019 | 716 | **303** |
| + `database_proof` | 374 | 1017 | 716 | 301 |
| + `oracle` | 1142 | 249 | 0 | 249 |
| + `oracle` + `database_proof` | 1144 | 247 | 0 | 247 |

Excluding `oracle` is correct: adding it drives source-missing to 0, i.e. it is present on every
source-derived row, so it is not evidence that a runtime control ran.

**Finding — the shipped predicate gives a different number.** Production decides this question in
`proof_schema.control_status`, whose `CONTROL_KEYS` are
`("negative_controls", "controls", "control", "control_evidence", "control_response")`. None of the
five keys the denominator is built from is in that tuple. Measured over the same corpus with
production's own function:

```
control_status over the 1391 confirmed rows:  {'not_recorded': 675, 'not_applicable': 716}
behavioural confirmed with a production-recognised control:      0
stored rows carrying ANY proof_schema.CONTROL_KEYS key at all:   0   (of 1783)
```

So the honest statement of the historical gap is **675 of 675 behavioural confirmations carry no
control that `report.control_ran` can see**, not 303. The 372 "recorded" rows are recorded only
under an offline key set that the report path never reads. This does not undercut the Q-090 emitter
work — that work is forward-looking and stored rows were deliberately not backfilled — but the
matrix should not carry `303` without naming the predicate, because the number a reader will
reproduce from production code is `675`.

### I-5 (prior: 917 handlers, 562 silent)

AST **node** counts over the same 178 production modules (`grep -c` counts lines and is reported
separately so the two instruments are never mixed):

```
total except handlers (ast.ExceptHandler nodes)          918
  swallowed, strict pass/continue/break                  322
  swallowed, + return None/False                         388
  swallowed, + literal fallback assign (guard predicate) 465
grep 'except' LINE count, same files, for contrast       952
```

918 total reproduces the guard's post-fix expectation. 465 = 388 optional + 77 control-plane, which
is exactly the two ceilings the guard ratchets, with load-bearing at 0. The Coordinator's pre-merge
`562 / 61.3%` is **not reproducible at HEAD** under any of the three predicates and should be
retired rather than carried forward: the merge converted ~105 load-bearing handlers into `_swallow`
recorders, which by construction removes them from the swallowed set.

### I-9 (no prior — measured first here)

```
production modules scanned                                        178
top-level modules in the guard's root.glob('*.py') scope          178
production .py the guard never scans                                0
bounded slices (upper bound present), whole tree                  822
  upper expression names cap|max|limit|budget                      67
  raw first-N over a bare Name in the 15-word work vocabulary      25 nodes -> 20 unique contracts
  bounded slices over a NON-Name value (invisible to the scan)    425
  break-at-limit loop caps (first-N with no slice node at all)     22
```

`25 nodes -> 20 contracts` is an instrument distinction, not a discrepancy: the guard collects a set
of `(owner, name, upper)` tuples, so repeated identical cuts collapse. The contract table has 20
entries and the measured set matches it exactly.

The scan's in-scope fraction is `25 / 822` bounded slices. That is by design (most of the other 797
are hash digests, uuids, parser windows and report previews, not target work), but two shapes carry
real work caps and are structurally outside it:

* **Non-`Name` sliced values (425).** Includes `agent.py:sweep_targets`
  `_spread_by_shape(rank_targets_for_budget(targets))[:limit]` — the sweep budget itself. The static
  contract cannot see the very cut whose ordering M3c proves matters; only the execution tests hold
  it. That is fine today and fragile tomorrow: delete those two execution tests and the sweep cap
  has no guard at all.
* **`break`-at-limit loop caps (22).** `crawl.bfs_frontier` caps the crawl frontier at `limit` in
  first-occurrence order with a `break`; no slice node exists, so no inventory entry can. MEASURED:
  both production call sites (`agent.py:2154`, `agent.py:2216`) rank with
  `rank_targets_for_budget(...)` *before* calling it, so this is correct today — but a future
  regression that drops that ranking is invisible to the I-9 contract.

## Verdict

* **I-5 — CLOSED and falsifiable.** Kills a real silent swallow on a load-bearing request path and
  names the exact site. Ratchet ceilings (388 optional / 77 control-plane) mean any *added* silent
  handler trips something even when the classifier would mislabel it.
* **I-9 — CLOSED and falsifiable, in two independent halves.** The static inventory kills new raw
  work cuts repository-wide (proven in a module owning no contract). The execution tests kill
  cut-before-rank, including the shape the static inventory cannot see. Neither half covers the
  other; both are load-bearing.
* **I-4 — falsifiable for every emitter it names, but NOT a repository-wide invariant.** M4 shows a
  confirmed runtime emitter can drop its control artifact and leave the file green. Combined with
  the predicate gap in the denominator above, I-4 should be recorded in the matrix as
  *"closed for the enumerated emitters"* rather than *"runtime confirmations carry controls"*.

## Part 2 — Q-090-D closed, and reproduced through a live path first

`agent.py:BBHAgent._triage` wrote CWE/OWASP annotations back with `db.update_finding(...)` as a bare
statement and discarded every return. It was the last `_KNOWN_OPEN` entry in
`tests/test_outcome_fidelity.py`, pinned MEASURED-STATIC — A, B and C had each been reproduced
through their real endpoint, D never had. A pin nobody has executed is a claim.

**Reproduced first (section 5 of `test_outcome_fidelity.py`).** The real generator, the real db,
nothing stubbed between them; the only thing built by hand is the two attributes `_triage` reads off
`self`. A mission holds two rows: one ordinary confirmed finding and one row that predates the Q-013
gate (`update_finding` was a raw `UPDATE` until then, so lead-confidence rows really do sit in old
confirmed tables; `add_finding` cannot create one today). Annotating the pre-gate row makes TRUTH
(#7) fire on the way back in — the row is DELETED from `findings` and appended to the leads list —
and `bool()` of that result is True, exactly as for a real in-place update.

MEASURED before the fix, on a pristine `git archive HEAD` snapshot carrying only the new test:

```
FAILED tests/test_outcome_fidelity.py::test_q090d_triage_must_not_report_a_set_the_findings_table_no_longer_holds
E   AssertionError: the operator is told a count the findings table does not hold:
E   'Triage complete: 2 findings (2 critical/high), 3 attack-path chain(s) synthesized.
E    All findings preserved; annotations are advisory only.' vs 1 row(s)
1 failed, 29 passed
```

The verdict says two findings. The table holds one. Nothing in the event stream says a row left.

**The fix.** `_triage` binds the write result and reads `written.verdict` — never `bool(...)`,
because a REROUTE is truthy and left no row:

* `UPDATE_REROUTED` / `UPDATE_MISSING` -> the finding is dropped from the reported set;
* `UPDATE_REFUSED` -> the row survives with its stored data, so it stays in the set and the lost
  annotation is recorded;
* `UPDATED` -> normal.

If anything left the table, `verdict` and `chains` are recomputed over the rows that are actually
there, so the count the operator is given is one the table can back. The gap is named on the emitted
event as `annotation_gap`; `main.py:2891` persists every streamed event under its own type
(`db.add_log(session_id, event.get("type", "info"), event)`), so this is durable through the existing
`triage` etype rather than a new log vocabulary. No new write call site was added — the
`test_proof_gate_reach._RAW_BASELINE` count for `agent.py::BBHAgent._triage` is still 1.

**Retired in the same commit**, as `test_no_pinned_violation_is_stale` requires:

* the `_KNOWN_OPEN` entry for `("agent.py", "BBHAgent._triage", "discarded-return",
  "db:update_finding")` — the table is now **empty**, which is the state that guard exists to reach;
* the non-vacuity floor in `test_the_violation_census_is_non_vacuous`, `3 -> 2`, with the removed
  site named on the line. The two survivors are exactly the two `_DISTINGUISHED` entries, so the
  floor and that table now agree: every measured site is an accepted read and a third would be a new
  defect.

Targeted verification after the fix (`tests/test_outcome_fidelity.py`, `test_proof_gate_reach.py`,
`test_gate_write_paths.py`, `test_finding_write_verdict.py`, `test_bbh.py`):
`319 passed, EXIT=0`.

## Part 3 — the I-4 hole closed with a measured artifact ratchet

`test_runtime_control_invariant.py` gains an inventory of every production site that **attaches** a
`negative_controls` artifact, counted as AST nodes (subscript assignment or dict-literal key), owner
by `(module, enclosing function)`. MEASURED on the current tree: **19 owners, 20 nodes**.

Only `negative_controls` is counted. The other `proof_schema.CONTROL_KEYS` names collide with
unrelated dictionaries — `cmdi_tool.time_payloads` uses `control` for a timing payload,
`main.defense_catalog` uses `controls` for D3FEND rows — and the raw scan over all five keys returns
41 nodes / 28 owners, most of it noise that would make the inventory move for reasons unrelated to a
finding's proof. Narrowing was a measurement, not a guess: both totals were computed before choosing.

Deliberately a **deletion-direction ratchet** (`measured >= pinned` per owner), not an equality:

* it is honest — it does not claim every confirmed emitter has a control, which would be false and
  would make this the fifth guard here that cannot fail;
* a lane that *adds* a control is never blocked, so it creates no friction during stabilization;
* removing one is red, and the message names the exact `(module, function)` and both counts.

Two controls ship with it: a positive control planting both attachment shapes plus an emitter with
no control (the scanner must see the first two and not the third), and a pin-liveness test requiring
every pinned module to still exist.

Verified both ways:

```
clean tree                    tests/test_runtime_control_invariant.py  ->  20 passed, EXIT=0
M4 re-planted (same mutation) ->  FAILED test_no_emitter_quietly_stops_attaching_its_control
E  {('tools.py', '_confirm_read_object_idor'): {'pinned': 2, 'measured': 1}}
1 failed, 19 passed
```

The mutation that survived 3507 tests now dies on the exact site.

## Recommended follow-ups (not done in this lane)

1. State the predicate next to the I-4 number in the matrix (`303` under the 5-key analysis set,
   `675` under `proof_schema.control_status`). Do not carry a bare `303`.
2. The ratchet in Part 3 protects controls that exist; it does not make "every confirmed behavioural
   emitter attaches one" true. Deriving that set requires an emitter census (which call sites build a
   `confidence == "confirmed"` finding on a behavioural path) with a measured exemption table. That is
   a Builder job for the lane owning `tools.py`, and it should not be rushed — a census that returns a
   wrong denominator is how this repo got a false `0 of 1391`.
3. Neither item needs a `db.py`, `main.py` or `tools.py` patch. No patch is owed from this lane.
