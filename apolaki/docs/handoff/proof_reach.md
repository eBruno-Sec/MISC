# proof-reach lane - Q-076

`agent/tests/test_proof_gate_reach.py` had 3 slack and named ZERO of its findings.

Owned files: `agent/tests/test_proof_gate_reach.py`, `docs/handoff/proof_reach.md`. Nothing else is
edited by this lane; product-code changes are PATCHES below.

---

## 1. Baseline, MEASURED at HEAD `e66f4ca`

`git status --porcelain agent/` is empty, so the worktree agent tree IS HEAD. Scan run in a throwaway
container against the real `agent/` mount, replicating `_raw_call_count()` exactly:

```
COUNT 11
  agent.py:3889   main.py:745    main.py:792    main.py:1078   main.py:1640   main.py:2033
  main.py:2115    main.py:2223   main.py:3434   main.py:3783   main.py:4023
```

11 raw `db.get_findings(` sites against `_KNOWN_UNGATED = 14`. **Slack 3, confirmed.**

## 2. `file:line` is the wrong key, MEASURED

The ticket says `_raw_call_count()` "has every `file:line` in hand and throws it away". It does - but
`file:line` cannot be the recorded baseline key. Ten of the eleven sites are in `main.py`; inserting
one function near the top of that file renumbers every site below it and the whole set becomes a
false `newly_raw`. That is the exact rot direction Q-075 forbids ("rot runs one way only, into
`resolved`, never into a false `newly_raw`").

So the key is the ENCLOSING SCOPE, which is stable under line drift and is also what a human needs -
the name of the consumer, not a coordinate. MEASURED, same run:

```
SITES 11   DISTINCT SCOPES 11   (no scope holds two sites)
  agent.py  3889  BBHAgent._triage
  main.py    745  get_status              main.py   792  _report_bundle
  main.py   1078  _tool_ledger            main.py  1640  asvs_coverage
  main.py   2033  blind_benchmark_run     main.py  2115  technique_plan
  main.py   2223  attack_graph_view       main.py  3434  cloud_posture_ingest
  main.py   3783  capture_finding_poc     main.py  4023  backup
```

The mapping is 1:1 today, but the baseline is recorded as a MULTISET (`key -> n`) rather than a set
anyway. With a plain set, a second raw call added inside an already-recorded scope is invisible to
`newly_raw`, which is the same blind spot in a smaller box. `file:line` is still printed in the
message - as diagnostics, not as identity.

## 3. SECOND DEFECT FOUND: `_RAW_IS_CORRECT` is a dead allowlist

MEASURED - `grep -rn "_RAW_IS_CORRECT" agent/` returns exactly two hits, both inside the same file:
its own definition, and the word appearing inside the failure-message string. **No code reads it.**

Both of its entries are also non-sites, so it does not describe the measured world:

- `"db.py"` - db.py's two raw calls (`db.py:235`, `db.py:290`) are bare-name `get_findings(mid)`
  calls, excluded STRUCTURALLY by the scanner's `if fname == "db.py" and isinstance(f, ast.Name)`
  branch. The exclusion is real; the dict entry is not what implements it.
- `"agent.py:_close_autonomy_loop"` - MEASURED, `grep -n "get_findings" agent/agent.py` returns two
  lines: 3859 `get_findings_gated` and 3889 `get_findings`. Both are in `BBHAgent._triage`.
  `_close_autonomy_loop` (agent.py:1326) holds NO `get_findings` call at all. The entry is stale.

Consequence for the failure message: it advised "if it is [raw-correct], add it to `_RAW_IS_CORRECT`
with a reason", and doing that changed **nothing** - the count is unaffected by the dict, so the only
way to make the gate pass was to raise the ceiling. The gate told the reader to do a thing that does
not work. This is the guards-that-check-declarations shape.

**Deliberately NOT fixed by making `_RAW_IS_CORRECT` an exclusion.** Excluding an entry would remove
its name from the diff, and Q-017 established that a gate may annotate a reader, never hide it. Every
site stays counted and named; `_RAW_IS_CORRECT` becomes an ANNOTATION printed beside a name, and the
message now says what actually clears the gate.

## 4. The slack decision (DoD item 4): ceiling comes DOWN, 14 -> 11

Measured, not preferred. Three independent reasons:

1. **No documented reason for slack exists.** The file's own comment says the opposite, twice:
   "Lower this as each is moved to `get_findings_gated()`" and "Lower this every time a reader is
   migrated." 14 is stale bookkeeping from the 20 -> 15 -> 14 ratchet, not a deliberate allowance.
2. **Slack 3 is the exact window that let SARIF sit raw**, which the file records in its own comment.
3. The set-diff and the ceiling are **complementary, not redundant**. The set diff catches a SWAP at
   constant count. It does not catch three silent ADDITIONS on its own if the additions are permitted
   to pass under a ceiling - so the ceiling has to be the true count for the two to agree.

The ceiling is LOWERED, never raised. With the count ratchet at the measured 11, the set ratchet and
the count ratchet fire on the same event, which is the point.

## 5. Design: two ratchets, one direction each

Mirrors `liveness.py::evaluate()` (`regressions = base - confirmed`, named, and `gained` never
fails). Here the polarity is inverted because the baseline records what is RAW:

- `newly_raw = now - base`  -> **FAILS**. A new ungated reader is the regression this gate exists for.
- `resolved  = base - now`  -> **NEVER fails**. That is another lane gating a site, i.e. green work.
  There is deliberately no staleness test on the recorded set, for the reason Q-075 gives.
- count `<=` ceiling        -> unchanged in shape, threshold lowered to the measured 11.

`len(BASELINE) <= CEILING` is asserted, which is what makes a firing alarm provably non-empty.

## 6. NEGATIVE CONTROL - MEASURED, and the old gate falsified beside it

Method: `git archive HEAD apolaki/agent` into an isolated snapshot (179 modules), never the shared
tree. Mutation applied inside a throwaway container and verified by grep before any run.

**Mutation A - the exact defect: gate one site, add another, CONSTANT COUNT.**
`main.py:4023` rewritten to `db.get_findings_gated(`, and a new raw reader appended to
`security.py`. Verified landed: `main.py:4023` now gated, `security.py:105 def apolaki_smuggled_reader`.

The pre-Q-076 file (`git show HEAD~1:...`) was restored beside it and run on the SAME mutated tree:

```
########## OLD GATE (pre-Q-076) on the mutated tree ##########
.....                                                                    [100%]
```

**5 passed. Completely silent.** That is the ticket's claim proven rather than asserted: at constant
count the old gate is structurally incapable of noticing, and it was not a near miss - it had nothing
to compare against.

The new gate on the identical tree, count ratchet and set ratchet run together (`F.`):

```
E   AssertionError: raw db.get_findings() call sites: 11 (ceiling 11, recorded baseline 11)
E     NEWLY RAW -- present in this tree, not in the recorded baseline:
E       security.py::apolaki_smuggled_reader         security.py:108
E     resolved since the baseline was recorded (green work, never a failure):
E       main.py::backup
E   assert not ['security.py::apolaki_smuggled_reader']
FAILED tests/test_proof_gate_reach.py::test_no_raw_site_appears_that_the_recorded_baseline_does_not_hold
```

**Count 11 -> 11, the count ratchet PASSED (the `.`), and the set ratchet named BOTH sides** - the
added site with its `file:line`, and the gated one under `resolved`. DoD item 2 satisfied.

Whole-file re-run after the control fix in section 7: **exactly one failure**, the set ratchet.

**Mutation B - pure addition, no site gated.** A raw reader appended to `report.py`:

```
E   AssertionError: raw db.get_findings() call sites: 12 (ceiling 11, recorded baseline 11)
E     NEWLY RAW -- present in this tree, not in the recorded baseline:
E       report.py::apolaki_new_export                report.py:3630
FAILED ...::test_the_number_of_ungated_presentation_readers_never_grows
FAILED ...::test_no_raw_site_appears_that_the_recorded_baseline_does_not_hold
```

Both ratchets fire, and the COUNT ratchet now names the site too. The old text for this same event
was `raw db.get_findings() call sites rose to 12 (tracked ceiling 14)` and stopped there - that is
"names ZERO of its findings", fixed on the count path as well as the set path.

## 7. A defect in my own control, found by running it

The first mutation run turned both control tests into `StopIteration`, not a result:

```
victim = next(s for s in before["sites"] if s["key"] == key)
E       StopIteration
```

`_gate_one_site` pinned the victim to the literal `main.py::backup`, and mutation A gates exactly
that site - so **the control broke on the one tree state it exists to simulate.** It now selects the
victim from what the tree actually holds, preferring that key while it exists. Worth recording
because it is the same class as the bug being fixed: a hardcoded name standing in for a measurement.

## 8. Self-read check (the Q-075 near-miss), MEASURED

Q-075's recorded set nearly silenced a different ratchet because `scan_methods()` read its own source
and matched its own baseline literals. Checked here rather than assumed, and it cannot happen for two
independent reasons, both asserted:

- The scan lists only top-level `agent/*.py`; this file is in `agent/tests/`. Asserted that no scanned
  filename starts with `test_`.
- The scan matches AST `Call` nodes, so a name inside a string or a comment is not a call. Asserted by
  copying THIS FILE into a temp dir as a top-level module and scanning it: **count 0**, and by a decoy
  module holding `"main.py::get_status"` and `"db.get_findings(mid)"` as text: **count 0**, with a real
  call in the same directory still found (**count 1**).

Positive control that the scan can still find something: `count > 0` on the real tree, sites located
in `main.py`, every key well-formed.

## 9. ANTI-IDLE: `test_mutation_gate.py` - VERDICT, it needs the same treatment

The audit graded it MILD. On the NAMING axis that grade is right; on the SWAP axis it is the same
defect as Q-076, and I measured both rather than reading for them.

**State, MEASURED on the isolated snapshot:**

```
producers        53
mutant modules   11   bie, blind_benchmark, cookie_flags, dependency_intel, ics_dnp3_s7,
                      mass_assign_tool, prng_disclosure, proof_schema, transport_posture,
                      web_security, ws_tool
uncovered        46
ceiling          46
slack             0
```

Four of the eleven mutant modules (`bie`, `blind_benchmark`, `dependency_intel`, `proof_schema`) are
NOT confirmed-producers - they are oracle modules. So only 7 of the 53 producers are covered, and
53 - 7 = 46. **Slack is 0**, which is better than Q-076 started at and means a pure ADDITION already
fires.

**Correction to the audit's description.** It reports that the file "already keeps a partial recorded
set of 8". It does not. `named_uncovered` is asserted as `named_uncovered <= producers` - a VACUITY
guard proving the producer scan has not stopped detecting anything. It never enters the ratchet diff
and is not a baseline. The file has no recorded set at all, which is why the swap below is invisible.

**NEGATIVE CONTROL 1 - the swap, constant count.** On a snapshot copy: register a mutant for
`sqli_tool.py` (one of the uncovered) AND add `apolaki_new_engine.py`, a brand-new module emitting
`{"confidence": "confirmed"}` with no mutant.

```
producers 54  covered 12  uncovered 46  ceiling 46
new engine uncovered? True     sqli now covered? True

tests/test_mutation_gate.py::test_confirmed_producers_without_a_mutant_never_grow
.                                                                        [100%]
```

**PASSES.** A new confirmed-producing engine shipped with no mutant and the ratchet said nothing,
because a different module was covered in the same run. Identical in kind to the Q-076 defect.

**NEGATIVE CONTROL 2 - the same addition WITHOUT the compensating mutant.** It fires, which is what
makes control 1 attributable to the swap and not to a broken scan:

```
E  AssertionError: confirmed-producing modules without a mutant rose to 47 (measured ceiling 46):
   ['apolaki_new_engine.py', 'cache_deception_tool.py', 'client_checks_tool.py', ... 47 names ...]
```

The delta IS in that list - and it is one name among 47, sorted alphabetically. It landed first here
only because it is called `apolaki_*`; a module named `zzz_tool.py` would sort last. There is nothing
to diff the list against, so "eyeball-diff" means diffing against memory.

**Verdict: apply the same treatment.** It costs no new friction, because at slack 0 an addition
already fails the gate - the recorded set only changes WHICH names get printed (the delta instead of
all 47) and additionally catches the swap that currently passes.

## Status

- [x] baseline measured (11 sites, 11 scopes) at HEAD
- [x] `_RAW_IS_CORRECT` staleness measured
- [x] set-diff implementation + message
- [x] self-read positive control
- [x] mandatory negative control (resolve one + add one at constant count)
- [x] full suite green on an isolated HEAD snapshot
- [x] anti-idle: `test_mutation_gate.py` assessed
