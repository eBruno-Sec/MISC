# Q-088 handoff -- `validated_on` vocabulary + invented-id rejection (Builder Lane B, CYCLE 16)

Working from HEAD `7cfa162` (main, before this lane's commits). Re-verifying the 2026-08-21
correction against current HEAD as instructed, since >1 week of unrelated commits have landed.

## Re-measurement against current HEAD (before any edit)

MEASURED, command:
```
MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default -v "C:/Users/voice/Desktop/GitHub/MISC/apolaki/agent:/app" -w /app apolaki-agent python -m pytest tests/test_validated_on.py -p no:cacheprovider -v -rA
```
Result: `7 passed, 5 xfailed`. All 5 strict xfails still genuinely xfail (not XPASS) -- the suite is
currently green, so nobody has half-landed this fix.

**Correction's premises re-checked, drift found in both directions:**

- `techniques.known_labs()` -- EXISTS, and is now a fully derived, non-circular vocabulary
  (registry union + liveness-vouched labs). This is MORE complete than the 2026-08-21 correction
  described -- `known_labs()` was apparently built out further since then.
- `techniques.is_proven()` -- EXISTS (the shared predicate the ticket asked for).
- `main.py:/packs` -- confirmed calling `T.is_proven(t)` directly (main.py:2459), with a comment
  explicitly citing the old 48-vs-16 defect. Already fixed. Matches the correction.
- **`technique_model.py:from_registry` (line 256 at correction time, now line 256 still) --
  STILL runs the old rule: `"status": "proven" if validated else "catalogued"`.** Confirmed NOT
  fixed.
- **`technique_planner.py:registry_seed` (line ~172 at correction time, now line 200) -- STILL
  runs the old rule: `"status": "proven" if vo else "catalogued"`.** Confirmed NOT fixed.
- So: 2 of the original 3 non-chokepoint call sites remain broken, exactly as the correction said.
  `main.py` is done; `technique_model.py` and `technique_planner.py` are not.

**Vocabulary-resolution re-measurement** (not what the stale xfail reason string says):
```
all claimed lab ids: ['clientauthz','conpot','domsource','dvga','dvwa','ginandjuice','juiceshop',
  'natas','openfmb','openldap','sessionlife','smb','snmpd','vampi']
unresolved vs test's own _known_lab_ids() helper: ['domsource', 'natas', 'openfmb', 'sessionlife']  (4)
unresolved vs production techniques.known_labs():                ['natas', 'sessionlife']            (2)
```
The test file's private `_known_lab_ids()` helper (BA.LAB_URLS | B.MANIFESTS | L.LABS) does NOT
include the liveness-vouched-labs path that `techniques.known_labs()` already has. `domsource` and
`openfmb` resolve in PRODUCTION (both are named by techniques that a liveness CHECK has actually
confirmed: `dom_link_manipulation`/`dom_data_manipulation` -> domsource, `dnp3_exposed` -> openfmb),
but the test's stand-in vocabulary doesn't know that path, so it still reports them unresolved. This
is the same "test re-implements a stale copy of the real rule instead of calling it" shape flagged
elsewhere in this very file's own comments (see the `test_packs_and_techniques_now_report_the_SAME_
proven_number` docstring). FIX: point the test at `T.known_labs()` directly.

After that fix, the REAL, current remaining defect is 2 ids, not 4: `natas` (an external OverTheWire
target `natas_ladder.py` climbs generically for a different benchmark -- `header_trust_authz`'s
Level-4 claim on it has no test, no liveness check, nothing behind it) and `sessionlife` (an
untracked `labs/sessionlife/` dir exists in the working tree -- not committed, no compose service, no
registry entry, no liveness check). Both are genuinely unresolved claims and should stay rejected
until someone actually proves them.

## Conflict found and resolved: technique_planner.py fix does NOT break test_technique_planner.py

Before editing `technique_planner.registry_seed()`, checked whether `test_technique_planner.py`
(NOT in this lane's ownership -- cannot be edited) depends on the old rule. It has an assertion at
line 81: `assert all(t["status"] == "proven" for t in lab)` where
`lab = [t for t in seed if t.get("validated_on")]`.

MEASURED: `registry_seed()`'s output dicts never set a `"validated_on"` key at all (only `id, name,
vuln_class, cwe, status, confidence, try_it, payloads, detection_logic`). So `t.get("validated_on")`
on every element of `seed` is always `None` -- `lab` is always `[]`, the assertion is vacuously true,
and the `for u in seed` monotonic-score loop above it (line 69-73, also keyed off
`t.get("validated_on")` on the *seed* dicts) is equally vacuous (`n` is always 0 for every entry).
Changing `registry_seed()`'s `status` computation cannot affect either assertion. Confirmed by running
`tests/test_technique_planner.py` green both before and after the edit (see Verification below) --
not just reasoned about.

`test_planner_confidence_is_a_function_of_lab_COUNT` in `test_validated_on.py` (currently PASSING,
mine to keep green) pins the CONFIDENCE SCORE formula (60/40/20 by lab count), not the `status`
field -- so the fix only touches the `status` line, the score formula is untouched.

## Plan

1. `agent/tests/test_validated_on.py`: point `_known_lab_ids()` at `T.known_labs()` (the product's
   own vocabulary) instead of re-implementing a stale subset. This is the fix for marker 1's "4 of 13
   ids" claim being wrong (really 2).
2. `agent/technique_model.py`: `from_registry` -- compute `status` via
   `techniques.technique_status(rec) == "proven"` (the shared predicate) instead of
   `bool(validated_on)`; filter `evidence` entries to labs `techniques.known_labs()` actually
   resolves, so a fabricated id can never become an evidence entry. Lazy `import techniques` inside
   the function (same pattern `techniques.py`'s own `_t()` already uses) to avoid the circular
   import (`techniques.py` -> `technique_model.py` at `_t()` time).
3. `agent/technique_planner.py`: `registry_seed` -- same `status` fix, one line, score formula
   untouched.
4. `agent/tests/test_technique_pipeline.py:17` -- decide in writing (see below), fix if warranted.
5. Retire `test_packs_and_techniques_report_the_same_proven_number` (miswritten, re-implements the
   old rule inline, cannot XPASS however the product changes) -- the correction's own instruction.
   Its replacement, `test_packs_and_techniques_now_report_the_SAME_proven_number`, already exists in
   the file and already calls the real predicate/`/packs` arithmetic -- so "replace" here means
   delete the miswritten one, since a correct replacement is already present and passing.
6. Item 4 (34/48 unasserted claims) -- re-measure only to confirm scope, do not attempt to close it.

## Decision: test_technique_pipeline.py:17

`test_from_registry_projects_canonical_shape` builds a SYNTHETIC rec with
`id="sqli_auth_bypass", validated_on=["juiceshop","dvwa"]` and asserts
`t["status"] == "proven"` and (later) `t["confidence"]["tier"] == "high"`.

MEASURED: `sqli_auth_bypass` is a real production technique id, but it is NOT in the current
`tests/liveness_baseline.json` "live" set (checked directly). Under the shared rule
(`techniques.technique_status`), it is `unverified`, not `proven` -- exactly like most of the
registry today (this is already true of `techniques.taxonomy_view()` itself via the currently-PASSING
`test_technique_status_is_the_fixed_rule_and_still_holds`, which the Q-012 lane shipped earlier).
This test is pinning the OLD behavior this ticket exists to remove: "validated_on truthy -> proven",
the exact rule the negative-control xfail says must NOT hold.

Decision: FIX the test, don't touch the product to keep it passing. Rationale: the negative control
(`test_a_fabricated_validated_on_is_rejected_by_the_canonical_model`, in this lane's own
`test_validated_on.py`) explicitly requires `TM.from_registry` to refuse "proven" for an unearned
`validated_on`, and the "one rule for proven" xfail explicitly requires `TM.from_registry`'s status to
agree with `techniques.technique_status` for every record in the real registry -- both would be
violated by leaving `from_registry` alone. Coupling the unit test's `id` to the real registry's
liveness ledger would make it flaky against future liveness runs, so instead of changing the `id` to
some already-proven real technique (fragile the same way), the test now `monkeypatch`s
`techniques._liveness_verified` to return `{"sqli_auth_bypass"}` for the duration of the test -- this
makes the "proven" path deterministic and independent of the shared ledger file, while still
exercising the real `from_registry -> techniques.technique_status` wiring rather than a mock of it.
Confidence-tier math is re-derived from the new (still-proven, still 2-lab, still-KEV) inputs and
reasserted against the ACTUAL computed value (not guessed), per the "measured, not guessed" house
rule.

## Commits

1. `32adfa5` -- technique_model.from_registry + technique_planner.registry_seed adopt the shared
   `is_proven`/`technique_status` predicate; test_validated_on.py's `_known_lab_ids()` now calls
   `techniques.known_labs()` instead of a stale re-implementation; test_technique_pipeline.py:17
   fixed by monkeypatching the liveness ledger for its one synthetic id rather than pinning the old
   rule or depending on the live ledger file. Two xfail markers XPASSed and were retired:
   `test_a_fabricated_validated_on_is_rejected_by_the_canonical_model`,
   `test_one_rule_for_proven_across_every_module`.
2. `cdf8157` -- retired the miswritten `test_packs_and_techniques_report_the_same_proven_number`
   marker per the correction's explicit instruction (its correct replacement already existed and
   already passes).

## Final state of tests/test_validated_on.py

11 tests: 9 passing (5 original + 2 newly-un-xfailed + the pre-existing correct replacement + the
existing-guards test), 2 strict xfails remaining, both genuine and correctly still red-if-fixed:

- `test_every_validated_on_lab_id_names_a_target_the_agent_can_resolve` -- 2 of 14 claimed lab ids
  (`natas`, `sessionlife`) still resolve to nothing the agent's registries or liveness ledger can
  vouch for. NOT closed in this ticket: closing it requires either standing up `labs/sessionlife/`
  as a real registered/liveness-checked target, or removing/earning the `natas` claim on
  `header_trust_authz` -- both are new work, not a vocabulary-chokepoint fix, and outside this
  ticket's file ownership (labs/, docker-compose.yml, benchmark registries are not mine to touch
  here). Left as an honest, still-measuring xfail.
- `test_every_validated_on_claim_is_backed_by_a_recorded_artifact` -- re-measured, still red (34 of
  48 claims named by no test/liveness artifact). Confirmed out of scope per the ticket's own DoD
  note ("needs ~30 recorded artifacts unrelated to the others"). NOT attempted.

## Definition of Done -- honest accounting

- "A lab id resolves against a real registry or the claim is rejected" -- PARTIALLY true: the
  vocabulary (`known_labs()`) already rejects (reports as `unresolved`) anything that doesn't
  resolve, and `is_proven`/`is_generalized`/`from_registry` now all refuse to treat an unresolved id
  as evidence or as "proven". What is NOT done: nothing yet strips an unresolved id OUT of
  `validated_on` at write time or refuses to construct a technique record carrying one -- an
  unresolved id is reported honestly everywhere, not silently accepted, but it is not physically
  rejected at construction. The negative-control test only requires the CONSEQUENCES of a fabricated
  claim to be refused (proven/high-confidence/evidence/generalized), which is what is fixed; it does
  not require the field itself to be scrubbed, and no marker asks for that either.
- "the invented-id negative control passes" -- DONE, measured (test now un-xfailed).
- "/packs and /techniques agree" -- DONE (was already true at main.py before this lane; confirmed
  the two remaining non-chokepoint call sites now agree too, via the one-rule-for-proven test).
- "the four markers XPASS ... or ... RETIRED" -- 2 of 4 XPASSed and retired; 1 (miswritten) RETIRED;
  1 (vocabulary) genuinely still open on 2 real ids (natas, sessionlife) for reasons above, correctly
  left red rather than forced closed.
- Item 4 (34/48 unasserted claims) -- explicitly NOT attempted, per the ticket's own permission to
  treat it as a separate follow-on. Re-measured only, still 34/48 (30/48 widened).

## Verification

- Targeted slice (test_validated_on.py + test_technique_planner.py + test_technique_contract.py +
  test_technique_pipeline.py + test_evidence_contract_by_proof_kind.py): 49 passed, 3 xfailed
  (before marker retirement) / after retirement: test_validated_on.py alone 9 passed, 2 xfailed.
- Broader sweep (15 more files touching technique_planner/technique_model/technique_status/
  registry_seed/is_proven/taxonomy_view/coverage_matrix): 320 passed, 0 failed.
- Full isolated-snapshot suite, command:
  ```
  git -C "C:/Users/voice/Desktop/GitHub/MISC" archive cdf81579ef51736f5a4ca2925cfc800852651fdc -- apolaki | tar -x -C <scratchpad>/q088_snap
  MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default -v "<scratchpad>/q088_snap/apolaki/agent:/app" -w /app apolaki-agent python -m pytest tests/ -p no:cacheprovider -q
  ```
  Run against a git-archive snapshot of commit `cdf8157` (this lane's final commit), never the
  shared working tree (a concurrent lane -- Q-021D -- has uncommitted changes of its own in it).
  Result: `[exited with code 0]`, zero `F` (failure) markers anywhere in the progress output
  (verified by direct count, not eyeballing), only `.` (pass) / `x` (xfail) / `s` (skip) characters
  across the entire run. The exact final summary line was not captured (the run took long enough
  that the terminal tool moved it to a background task partway through, and the very last summary
  line landed just past what got flushed to the captured output file before the notification
  fired) -- the exit-code-0 + zero-F evidence is direct and sufficient, but the missing line is
  disclosed here rather than papered over.

## Status: DONE for the scope this lane could close. Two xfails remain in test_validated_on.py, both
correctly still red (vocabulary: natas/sessionlife need new registered targets, out of
file-ownership scope here; 34/48 unasserted claims: separate larger scope, explicitly deferred per
the ticket). Full isolated suite green (exit 0, zero failures) at final commit `cdf8157`.
