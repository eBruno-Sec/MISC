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

## Status: IN PROGRESS -- see commits below as they land.
