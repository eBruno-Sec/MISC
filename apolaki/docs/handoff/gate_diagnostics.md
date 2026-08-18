# Gate diagnostics lane -- Q-075

The dead-code ratchet's alarm is right and its message points elsewhere.

## The defect, MEASURED

`agent/tests/test_deadcode_gate.py:116` built its "New entries" list as `q["unused"][-5:]` -- the
last five of an ALPHABETICALLY SORTED list. It is not a set difference against anything. It cannot
be: nothing in the process knew what was dead before.

Reproduced against a clean `git archive HEAD apolaki/agent` snapshot (HEAD 9650c76) extracted to a
scratch dir and mounted into a throwaway container, so the other lane's in-flight `dom_tool.py` edits
could not move the number under the measurement.

    HEAD snapshot:  count 35  baseline 37  ok True
    worktree:       count 40  baseline 37  ok False
    set difference: dom_tool.wm_family, wm_finding, wm_lead_finding, wm_payloads, wm_reportable

    sorted(unused)[-5:] on either tree:
      technique_store.stats, techniques.techniques_for_lab, waf_bypass_tool.pad,
      web_security.is_url_in_scope, xxe_tool.looks_like_xml

The five names the ticket says cost four probes are the alphabetical TAIL of the list. They are the
same five whether the tree is clean or dirty, which is the tell: a message that does not change when
the finding changes is not reporting the finding. Note the worktree's five genuinely new entries sort
into the MIDDLE of the list (`d...`), so the tail slice could not have named them under any
circumstances.

## The design point the ticket asked to be stated plainly, not smuggled

`QUALIFIED_BASELINE` is a COUNT (37). A count cannot be diffed. There was no set to subtract, which
is why a slice was printed instead of a difference -- the diagnostic the gate needed did not exist in
its inputs. Printing "the true set difference" is therefore NOT a formatting fix; it requires
recording the baseline SET.

So this lane records one: `QUALIFIED_BASELINE_SET`, the 35 module-resolved dead functions measured on
the HEAD snapshot above, and `METHOD_BASELINE_SET`, the 13 uncalled methods measured the same way.

Three properties keep the added state honest:

1. **The count ratchet is untouched.** `QUALIFIED_BASELINE` stays 37 and `METHOD_BASELINE` stays 14.
   The SET is a diagnostic reference, never the threshold. `ALLOWED_UNUSED_QUALIFIED` is unchanged.
2. **`len(SET) <= BASELINE` is asserted by a test.** This is what makes the message provably
   non-empty: if the flagged set were entirely contained in the recorded set, the count could be at
   most `len(SET) <= baseline` and the ratchet would not have fired. So whenever the alarm sounds,
   there is at least one newly-dead entry to name. A rise cannot produce a silent message.
3. **A stale entry cannot corrupt the message.** Rot only ever runs one way: someone wires a recorded
   entry, so `SET` holds a name that is no longer dead. That inflates `resolved`; it can never invent
   a `newly_dead`. Which is why there is deliberately NO hard staleness test on the set -- see below.

## Why no staleness test on the baseline set

`ALLOWED_UNUSED` has one (`test_the_allowlist_does_not_rot`), so the precedent exists. It was
rejected here on the ticket's own reasoning. That list holds 6 hand-written entries and changes
rarely. The baseline SET holds 35 and moves every time ANY lane wires ANY function -- the good
direction. A hard staleness test would turn a lane's successful wiring red and demand an edit to a
file that lane does not own, which is exactly the "gate that cries wolf, gate that gets silenced"
failure this ticket exists to prevent. Instead `resolved` is reported in the message, so drift is
visible at the moment someone is already reading the gate's output. UNVERIFIED-by-design: nothing
forces the set to be re-recorded; it is a diagnostic, and its rot direction is provably harmless.

## The message now

Built inside `scan_qualified()` / `scan_methods()` as `result["message"]`, not in the test. Any
caller -- the test, a liveness script, an operator at a REPL -- gets the same correct text rather
than each re-deriving it. The test asserts `q["ok"], q["message"]`.

## The defect this fix INTRODUCED, caught by a control rather than by a test

Worth more than the ticket. Recording `METHOD_BASELINE_SET` **silenced the method ratchet entirely**,
and the whole test file stayed green.

`scan_methods()` joins every `.py` file into one corpus INCLUDING ITS OWN SOURCE, and counts `.name`
on any receiver as a call. The recorded entries are strings shaped `"vault.py::Vault.purge"`. The
attribute rule matched `.purge` inside that literal. All 13 recorded methods read as called.

    same HEAD snapshot, scan_methods()
      original gate ................... count 13   ok True
      + METHOD_BASELINE_SET recorded ... count  0   ok True      <-- silenced
      + self-exclusion fix ............ count 13   ok True   examined 396

Nothing went red. `0 <= 14` passes the ratchet; `methods_examined` counts DEFINITIONS so it stayed at
396; every other method test asserts that specific things are ABSENT from the flagged list, which an
empty list satisfies perfectly. This is the project's own "every zero needs a positive control" rule
collecting a debt: there was no assertion that the scan could still find anything.

`scan()` already excludes itself for exactly this reason, and its docstring says so -- the hazard was
documented one function above the one that had it. `scan_qualified()` is immune structurally, since it
resolves through imports and `deadcode_gate` imports no project module. Only `scan_methods()` was
exposed. Fixed by the same one-line exclusion `scan()` uses.

Also closed by that line: `ALLOWED_UNUSED_QUALIFIED` holds `"saml_tool.confirm_bypass"`, so any METHOD
named `confirm_bypass` was already being marked used by the allowlist's own text. Pre-existing, small,
and gone now.

Two tests added, both with teeth:

* `test_the_method_scan_does_not_read_its_own_findings` -- synthetic, isolates the mechanism.
  MEASURED against the pre-fix gate extracted from HEAD: `unused == set()`, i.e. it FAILS before the
  fix and passes after.
* `test_the_method_scan_can_still_find_something` -- the missing positive control, asserts `count > 0`.

## Negative control (mandatory, specified by the ticket)

Ran against a COPY OF THE REAL TREE, not a toy directory. Against a toy directory every flagged name
is new, so `newly_dead` is trivially the whole list and the assertion proves nothing about a populated
baseline -- which is exactly the condition the bug lived in.

    === BEFORE: count 35 ok True newly []
    === AFTER island added: count 36 ok True
    === newly_dead: ['security.apolaki_deliberate_island']
    === MESSAGE:
    qualified dead-code count rose to 36 (baseline 37).
    NEWLY DEAD -- in this tree, not in the recorded baseline set of 35:
      security.apolaki_deliberate_island

One name, the right one. The island was appended to `security.py` -- a live, widely imported module,
not a fresh file -- so the resolver had every chance to mark it used through one of that module's real
importers and did not. `before` names nothing, which is the "remove it and it stops being reported"
half: the restored file is the same bytes `before` measured.

Held as `test_a_deliberate_island_is_named_and_nothing_else_is`, which also asserts by name that the
five innocents the old slice printed CANNOT appear -- all five are in the recorded set, so a true
difference can never surface them however the list sorts.

    tests/test_deadcode_gate.py  27 passed

## ANTI-IDLE: the same defect in the project's other ratchets

Looking for the Q-075 shape specifically -- an alarm that reports a COUNT, or a slice of a full
population, rather than the specific thing that changed. Note that `bad[:5]` under an `assert bad ==
[]` is NOT this defect: those lists are the delta by construction, and truncating one is only
truncation. The defect needs a ratchet, where the flagged population is mostly pre-existing debt.

Five gates examined. Counts measured in the container, not read off comments.

**`test_proof_gate_reach.py` -- WORST, worth its own ticket.**

    REAL _raw_call_count() = 11   ceiling _KNOWN_UNGATED = 14   slack 3

The failure message names ZERO call sites. It reports a number and gives instructions. Yet
`_raw_call_count()` walks the AST with `fname` and the node in hand -- it has every `file:line` and
throws them all away to return an int. The eleven are recoverable in one pass:

    agent.py:3889, main.py:745, 792, 1078, 1640, 2033, 2115, 2223, 3434, 3783, 4023

Three points of slack means three new ungated readers can be wired today with nothing going red. And
this is not hypothetical -- the file's own comment records it happening: "SARIF sat raw while its
sibling poc_bundle_export was gated, and the count stayed under 15 so nothing failed." A recorded SET
would have shown one resolved and one new AT CONSTANT COUNT, which is precisely the leak a count
ceiling cannot express. Same fix as Q-075: record the site set, diff it, name the delta.

**`test_mutation_gate.py` -- MILD, real but lower value.**

    uncovered 46   ceiling _KNOWN_UNMUTATED_CONFIRMED_PRODUCERS = 46   slack 0

Prints `sorted(uncovered)` -- all 46 names. Better than Q-075 (the delta IS in the list; it was not in
the dead-code gate's) and better than the proof gate (some names beat none), but the reader still
eyeball-diffs 46 entries to find the one that moved. Slack 0 means any rise is a genuine addition. It
already carries a partial recorded set (`named_uncovered`, 8 entries) used as a vacuity control, so
the pattern is half-present and completing it would be cheap.

**`liveness.py` `evaluate()` -- CLEAN, and it is the model this project already had.**

Its baseline is a SET of technique names. It computes `regressions = base - confirmed` and
`gained = confirmed - base`, and the statement names the regressed techniques outright. In other
words the correct shape was sitting in the repo the whole time; the dead-code gate diverged from it by
recording a count. Worth saying plainly, because it reframes Q-075: the fix is not an invention, it is
bringing one gate back in line with another.

**`test_description_gate.py` -- CLEAN.** `KNOWN_OPEN` is a recorded SET (currently empty, which the
comment correctly calls the strongest state rather than an absence of checking). The tier ratchet
prints `silent`, which is the exact delta by construction, and it carries a positive control
(`len(registered) > 100`) proving the registry was actually read.

**`test_island_soundness.py` -- CLEAN.** No count ratchet; assertions are membership and behavioural,
each naming its own subject.

One cross-cutting note, not a ratchet defect but found while reading: `scan_qualified()`'s own-module
rule counts ANY mention in the module, including prose. `deadcode_gate.scan`, `scan_qualified` and
`scan_methods` are never flagged despite having no production caller, because their own docstrings and
comments name them. Harmless here, under-reports in general.

## Status

- [x] Root cause measured and reproduced on a clean snapshot (both trees)
- [x] Baseline SET recorded for functions and methods
- [x] Message prints the true set difference
- [x] Negative control on a real-tree copy
- [x] ANTI-IDLE audit of the project's other ratchets
