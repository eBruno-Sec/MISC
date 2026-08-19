# Q-081 - the audit-key lane: the KEY check, verified rather than inherited

Owner: audit-key lane (Builder). Files I may write: `agent/engine_descriptor.py`,
`agent/techniques.py`, `agent/effect_search.py`, tests under `agent/tests/`, this file. Patches for
files I do not own go at the bottom, unapplied.

Every claim below is **MEASURED** (command + real output) or **UNVERIFIED**. Every zero carries a
positive control naming the fields the instrument read.

---

## 0. THE FIRST THING I MEASURED WAS THE TICKET

Q-081 is marked `ready` in `docs/QUEUE.md`. **It is not open.** DoD items 1 and 2 landed one commit
before the ticket's own predecessor commit:

```
$ git log --oneline -3
29d00d2 Apolaki: Q-052 slice 2 settled by counting writes, and two new criticals filed (#123)
db150c1 Apolaki Q-074 run 4: the effects guard interrogated the engine and took the KEY on trust
0276ae0 Apolaki Q-074 run 4: run_csrf kills the session too, and the door is four engines wide
```

`db150c1` added `unknown_technique` to `effects_audit`, put it in the `ok` clause, added `bool(known)`
to the non-vacuity clause, and shipped `agent/tests/test_effects_key_is_a_technique.py` (8 tests,
including the "real technique + real engine still passes" negative control DoD 2 asks for).

So this lane's work is **not to write the fix again**. It is to (a) verify the landed fix
adversarially rather than take its commit message on trust, (b) run the corrected audit and report
the count, (c) decide `csrf_token_missing`, and (d) sweep the sibling guards for the same shape.
Re-implementing a landed fix and reporting it as new work is its own kind of declaration-versus-fact.

---

## 1. THE APPARATUS

Two other lanes are live in this tree, so every probe runs against an **ISOLATED SNAPSHOT of HEAD**,
never the shared worktree:

```
git archive HEAD apolaki/agent | tar -x -C <scratchpad>/snap        # HEAD = 29d00d2
MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default -e PYTHONPATH=/app \
  -v "<scratchpad>/snap/apolaki/agent:/app" -v "<scratchpad>/probe:/probe" \
  -w /app apolaki-agent python /probe/<probe>.py
```

**Fields and attribute names read**, stated so a later reader can tell the instrument from the code:
`engine_descriptor.EFFECTS` / `.PRECONDITIONS` / `.ALWAYS_ON` (dict KEYS);
`effects_audit()["ok" | "checked" | "unknown_technique" | "technique_table_size" | "registry_size" |
"implementations_size" | "no_engine_declared" | "unregistered" | "unimplemented"]`;
`build()` (dict keys); `conflicts()` (list of 3-tuples, element 0 = producer);
`routes()[tid]` (dict engine -> source set); `techniques.TECHNIQUES` (dict keys) and each record's
`"id"` field. Probe source: `probe/p1_key_fact.py`, grep-confirmed (4 hits on `csrf_token_missing`)
before it was allowed to run.

---

## 2. DoD 3 - THE CORRECTED AUDIT, RUN. The count is ZERO, and here is the proof it was looking.

MEASURED, probe section A:

```
A_shipped   ok                     : True
            checked                : 12          <- EFFECTS rows
            technique_table_size   : 88
            registry_size          : 111
            implementations_size   : 166
            unknown_technique      : []          <- THE COUNT: 0
            no_engine_declared     : []
            unregistered           : []
            unimplemented          : []
```

**A zero from a guard is worth nothing without a positive control**, so the same instrument, same
call, one row added:

```
B_positive_control  EFFECTS + {"csrf_token_missing": {"invalidates": ["authenticated"],
                                                      "engine": ["run_csrf"]}}
            ok                     : False
            unknown_technique      : ['csrf_token_missing']
            unregistered           : []          <- the engine half stayed silent, so the
            unimplemented          : []             failure is attributable to the KEY alone
```

**VERDICT: `csrf_token_missing` was the only bad key, and it was never in the shipped table** - it
was the Q-074 lane's probe fixture. All 12 shipped keys are real techniques. The apparatus is
demonstrably able to say otherwise.

## 2b. The three non-vacuity numbers are real, not defaults

`88 / 111 / 166` are the technique table, `tools.TOOL_PERMISSIONS`, and `ToolRegistry._<name>`
implementations. A guard scanning an empty fact table passes for free; these are the numbers proving
it did not.

---

## 3. IS `TECHNIQUES` THE FACT THAT DECIDES REACHABILITY, OR ONE HOP AWAY FROM IT?

The guard reads `set(techniques.TECHNIQUES)` - dict KEYS. `build()` keys descriptors on each record's
`"id"` FIELD and drops any record whose id is falsy (`if t.get("id")`). Those are two different
expressions, and this project has been bitten three times by an instrument reading a neighbouring
field. MEASURED, probe section C:

```
C_instrument_vs_fact
  len_TECHNIQUES_keys        : 88
  len_record_id_field        : 88
  len_build_descriptors      : 88
  keys_minus_built           : []      <- no key the guard accepts that build() drops
  built_minus_keys           : []
  records_where_key_ne_id    : []
  records_with_falsy_id      : []
```

The two expressions agree today **by construction**: `techniques.py:88` is
`TECHNIQUES: dict[str, dict] = {t["id"]: t for t in [...]}`, so the key IS the id field. That is a
real structural guarantee, not a coincidence - but it is a guarantee held by a line in a different
file, so section 6 pins it.

---

## 4. DoD 4 - WHAT HAPPENS TO `csrf_token_missing`

MEASURED, probe section F, on the shipped tree:

```
F_csrf  csrf_in_TECHNIQUES   : True     csrf_in_build      : True
        csrf_preconditions   : ['has_login']
        csrf_routes          : {'run_csrf': ['wstg_full']}
        csrf_in_EFFECTS      : False
        run_csrf_registered  : True     run_csrf_implemented : True
        csrf_record          : id=csrf  vuln_class=csrf  permission=ACTIVE  wstg=WSTG-SESS-05
                               execution=auto  transferable=True
```

So the re-key target exists and is fully reachable: `csrf` is a technique, it is evidence-gated on
`has_login`, it routes to `run_csrf`, and `run_csrf` is registered and implemented. An entry
`"csrf": {"establishes": [], "invalidates": ["authenticated"], "engine": ["run_csrf"]}` would pass
the corrected audit and WOULD become a descriptor.

**Decision and its reasoning are in section 6**, after the adversarial verification, because the
decision turns on a measurement I had not taken when I wrote this section.

---

## 5. THE LANDED GUARD, VERIFIED BY MUTATION RATHER THAN BY ITS COMMIT MESSAGE

A guard nobody has tried to break is a declaration. `db150c1`'s message claims a `weakened_guard`
mutant; I re-ran it independently on my own copy rather than inheriting the claim.

**MUTANT: the check stays, the `ok` clause forgets it.** This is the one that matters for a NEW
check, because the shipped table is clean, so removing the term leaves every older test green:

```
sed  'and not (no_engine or unregistered or unimplemented or unknown_technique),'
  -> 'and not (no_engine or unregistered or unimplemented),'
grep confirm  new clause present : 1        original clause present : 0
```

```
CONTROL  (unmutated HEAD snapshot, same 3 files)
  tests/test_effects_key_is_a_technique.py + test_effects_engine_fact.py
  + test_effects_negative_half.py            -> 30 passed

MUTANT
  FAILED test_effects_key_is_a_technique.py::test_the_guard_fails_on_a_key_that_is_not_a_technique
  FAILED test_effects_key_is_a_technique.py::test_the_guard_fails_on_a_key_that_is_a_near_miss_of_a_real_technique
  2 failed
```

**VERDICT: the check is load-bearing and cannot be removed silently.** The two tests that die are
exactly the two negative controls written for it, and no unrelated test fires - so the kill is
attributable to the mutation and the blast radius is the intended one.

**INSTRUMENT ERROR, recorded because I walked into the one `effects4.md` documented.** A
`python - <<PY` heredoc on the HOST printed `Python was not found; run without arguments to install
from the Microsoft Store`, exit non-zero, file unmodified - the sixth instance of this shape in this
project's probe harnesses. The `grep -c` guard immediately after it returned **0**, so the unpatched
copy never ran and no stale output was read as a new result. Every subsequent edit was applied by the
container's interpreter and grep-confirmed before use.

---

## 6. DoD 4 - DECISION: re-key onto `csrf`. Correct by every substantive check, blocked on ownership.

### 6a. The effect is true and `csrf` is its home

`csrf_token_missing` was never in the shipped table, so there is nothing to delete. The question DoD 4
actually asks is where the TRUE fact goes. Q-080 / `effects4.md` measured `run_csrf` ending the
mission session 4/4 on the `sessionlife` `/secure` mount with a clean 4/4 paired control on `/vuln`.
`run_csrf` is the only engine `routes()` derives for technique `csrf` (`{'run_csrf': ['wstg_full']}`),
so the entry attributes the effect to the engine that has it.

### 6b. It survives the checks that matter, MEASURED on a copy carrying the entry

```
effects_audit  ok True   checked 13   unknown_technique []   unregistered []   unimplemented []
descriptors    88        csrf routable=True  engines ['run_csrf']
                         routed_by {'run_csrf': ['effect_engine', 'wstg_full']}
                         invalidates ['authenticated']   requires ['has_login']
conflicts()    6 -> 12 rows, producers ['csrf', 'race_condition']
               csrf consumers: cache_deception, jwt_forge, jwt_key_confusion,
                               session_fixation, session_lifecycle, weak_2fa_bypass
chains()       46, unchanged
differs_from_derived_route  ['sqli_structural: ...']   <- UNCHANGED, no new noise
```

The declared engine agrees with the independently derived `wstg_full` route, so the cross-check adds
no disagreement.

### 6c. Why the prior lane's "why the other three are not added" does NOT cover `csrf`

That comment names a counter-engine for two of its three: `command_injection`'s primary engine is
`run_cmdi` on query params and `stored_xss`'s is `run_xss`, and neither has this behaviour, so
declaring the effect on those families would mis-attribute it. **It names no counter-engine for
`csrf`, because there is none** - `run_csrf` is that technique's only route. For `csrf` the argument
reduces to "the door fix will make it false", which is equally true of `race_condition`, the entry
that stayed.

**And one measured asymmetry decides it.** `run_csrf` is `PermissionLevel.ACTIVE` and `run_race` is
not: the model today records the session-killer that needs `mode=full` and omits the one that fires
in the DEFAULT mode. The commoner case is the missing one. By the table's own stated rule - an
over-approximated `invalidates` costs completeness, never soundness - the conservative direction is
to declare it.

`command_injection` and `stored_xss` stay OUT, upholding the prior lane's reasoning where it applies.

### 6d. Why it is NOT applied in this commit

MEASURED - the one-line addition turns 7 tests red, in **five files this lane may not write**:

```
FAILED test_effects_key_is_a_technique.py::test_a_non_technique_key_is_measurably_inert_...
FAILED test_effects_engine_fact.py::test_every_row_the_planner_can_emit_names_a_dispatchable_engine
FAILED test_effects_negative_half.py::test_race_condition_is_the_only_declared_negative_effect
FAILED test_effects_negative_half.py::test_conflicts_are_exactly_the_techniques_that_require_authentication
FAILED test_engine_descriptor.py::test_the_shipped_conflict_set_is_exactly_the_measured_race_rows
FAILED test_engine_descriptor.py::test_the_sussman_machinery_sees_a_SECOND_negative_effect
FAILED test_engine_descriptor.py::test_audit_endpoint_actually_serves_the_effects_layer
```

**Every one is a PIN, not an oracle**, and `csrf` passed the substantive assertions inside them - the
producer had a non-empty `engines` list and every name was in `TOOL_PERMISSIONS`. The pin that fired
says so itself:

```
assert {p for p, _o, _c in cf} == {"race_condition"}, \
    "a second negative effect shipped; it needs a measurement before it is pinned here"
```

That is a pin doing its job: it demands a coordinated, deliberate update. Applying the EFFECTS line
alone would leave HEAD red; editing five test files I do not own would collide with two live lanes.
So the patch and its exact new pin values are handed off in section 9, complete enough to apply
without re-deriving anything. **Nothing true was deleted to keep a guard green.**

---

## 7. ANTI-IDLE - the same predicate applied to every sibling registry. 7 blocks, 2 findings.

**THE PREDICATE, stated once:** for a table keyed by X whose consumer resolves X against fact table
F, count the keys (or declared values) not in F. Those rows are silently inert - the Q-081 shape.
Each block names the CONSUMER and the line that makes F the deciding set, so a reader can check I
measured the code rather than the instrument.

| # | table | consumer (the line that decides) | inert rows |
|---|---|---|---|
| S1 | `EFFECTS` / `PRECONDITIONS` / `ALWAYS_ON` keys | `build()` walks `T.TECHNIQUES.values()` | **0 / 0 / 0** (of 12 / 42 / 45) |
| S2 | `EFFECTS` keys never selectable | planner ranks `PRECONDITIONS` ∪ `ALWAYS_ON` only | **0** of 12 |
| S3 | `wstg_catalog.FULL` / `PARTIAL` / `EXCLUDED` keys | `coverage()` iterates `CATALOG.items()` | **0 / 0 / 0** (of 60 / 25 / 5) |
| S4 | technique record's `wstg` field | `coverage()` buckets from FULL/PARTIAL/EXCLUDED | **3** of 47 distinct ids |
| S5 | `asvs_model.OBJECTIVES[].engine` | `assess()` -> `_engine_ran(obj, ran)` | **0** of 33 |
| S6 | `asvs_model.OBJECTIVES[].violated_by` | `map_findings()` matches a finding's family | **6** of 52 |
| S7 | `proof_schema._ALIAS` / `_CWE_FAMILY` / `_COUNTER_EXAMPLE_BY_CWE` values | `family_of()` -> `_FAMILY.get(fam, _DEFAULT)` | **0 / 0 / 0** |

Positive controls for the zeros, naming what the instrument placed: `build()` returned **88**
descriptors; `coverage()` placed **109 of 109** CATALOG ids into a bucket and put the known-`FULL`
`WSTG-SESS-05` in `full`; `engine_registry()` held **111** names; `family_of({"family":"sqli"})`
returned `sql_injection` (the alias resolved) and `family_of({"family":"not_a_family"})` returned
`not_a_family` (the default path). S2's zero carries its own control: **one** technique
(`find_hidden_route`) IS in neither gate, so the set difference was not empty for want of anything to
find - no EFFECTS row is keyed on it.

### S4 - 3 WSTG ids a technique CLAIMS that the coverage map reports as untested

All three are in `CATALOG`, none is in `FULL`/`PARTIAL`/`EXCLUDED`, so `coverage()` buckets each as
`none` with reason `"not yet implemented"` - while the technique registry has an `auto` technique with
an oracle claiming it:

```
WSTG-CLNT-11  "Web Messaging"                claimed by jsonp_info_leak  routes ['run_jsonp']    always_on
WSTG-CLNT-13  "Cross Site Script Inclusion"  claimed by csti             routes ['run_dom_audit'] always_on
WSTG-INPV-16  "HTTP Incoming Requests"       claimed by crlf_injection   routes []                always_on
```

This is the **under-report** half of the Q-011 defect (which was the over-report half: `FULL`
naming a technique id where an engine belonged). `coverage()` validates its own three maps against
`CATALOG` exhaustively and **never consults the technique registry's `wstg` column**, which is the
second declaration of the same fact. The two disagree in three places and nothing notices.

**Graded honestly: this is a LEAD, not a proof that coverage is understated.** `FULL` is deliberately
conservative ("only where a deterministic confirming engine exists"), so a technique claiming an id
is not by itself evidence of a confirming engine - and one of the three looks like the technique
record being wrong rather than the catalog: **`csti` is client-side TEMPLATE injection and WSTG-CLNT-13
is cross-site SCRIPT INCLUSION, which are different tests.** `crlf_injection`'s claim is weaker still
- it routes to no engine at all. What is not in doubt is that two independent declarations of the same
taxonomy fact have never been compared. Section 8 adds that comparison.

### S6 - 6 ASVS objectives carry a `violated_by` family no producer writes

`map_findings()` matches a finding's `family`/`vuln_class` against `violated_by`. A family string
nothing emits means the objective **can never read `failed`** - it reads `verified` or `not_tested`
instead, always in the flattering direction. That is exactly the Q-048 defect (`default_creds` vs
`default_credentials`), still live in six places:

```
broken_access_control  -> ATHZ-00           ldap                 -> VAL-07
cleartext_transport    -> AUTHN-04          privilege_escalation -> ATHZ-00, ATHZ-02
information_disclosure -> COMM-03           xpath                -> VAL-07
```

**INSTRUMENT CORRECTED MID-MEASUREMENT, and the first number is retracted rather than reported.** My
first census matched only the dict-literal spelling `"family": "x"` and returned **9**. A direct grep
of the three most suspicious names found `tools.py:6386  f["family"] = "takeover"` - an ASSIGNMENT the
regex could not see, on a family I had just called unproduced. The census now matches 12 spellings
across both fields (dict literal, `kw=`, subscript assignment, `setdefault`, `.get` default, and `==`
comparison), over 179 files, giving a reference set of 113 names, and the count is **6**. Three of the
nine were my instrument: `takeover` (`tools.py`), `auth_bypass` (`sqli_tool.py`), `csti` (`agent.py`).

**Bound it honestly: 6 is a LOWER bound on what is fine and an UPPER bound on the defect.** The census
deliberately counts `family == "x"` consumer comparisons and `.get` defaults as evidence of
production, which is an inference, not a fact - `csti`'s only hit is a comparison in `agent.py`, so
its retraction is the weakest of the three. Controls on the instrument itself:
`default_credentials` (the Q-048 FIX target) present, `default_creds` (the Q-048 DEFECT string)
absent, and an invented family absent.

`asvs_model.py` is not this lane's file. Patch in section 9.

---

## 8. WHAT THIS LANE SHIPPED: `wstg_audit()`, the S4 predicate made permanent

Reporting a defect in a handoff nobody reads again is how S4 would come back. `engine_descriptor.py`
and new tests are mine to write, and `engine_descriptor` already imports `wstg_catalog` inside
`routes()`, so the cross-check has a home that does not touch another lane's file.

`engine_descriptor.wstg_audit(catalog, full, partial, excluded, techniques)` — all five injectable so
the controls need no monkeypatching. THREE HARD FAULTS, each derived from `coverage()`'s one loop and
each fired deliberately by a control before the shipped zero was allowed to mean anything:

| field | what it catches | why it is inert without it |
|---|---|---|
| `map_keys_outside_catalog` | a `FULL`/`PARTIAL`/`EXCLUDED` key that is not a `CATALOG` id | `coverage()` iterates `CATALOG.items()`, so it changes no bucket, tally or percentage |
| `maps_overlap` | an id in two maps | `coverage()`'s `if/elif` decides the bucket by STATEMENT ORDER; nothing records which map should win |
| `claimed_ids_outside_catalog` | a technique's `wstg` field naming an id the catalog does not define | `routes()` resolves `FULL[rec["wstg"]]`; a claim on a nonexistent test can never be confirmed or refuted |

and ONE REPORTED field, `claimed_but_unmapped`, deliberately outside `ok` for the reason
`differs_from_derived_route` and `routing_audit()["unrouted"]` are: `FULL` is conservative by design,
so a technique's claim is not proof a confirming engine exists.

`ok` also requires non-vacuity — catalog non-empty, technique table non-empty, `checked > 0` — so an
unreadable fact table fails closed instead of reporting its own failure as 47 findings.

### 8a. The tests failed before the guard existed

```
tests/test_wstg_key_reachability.py against UNMODIFIED HEAD -> 11 of 12 failed
  (the one that passed is `test_control_the_fake_id_is_really_absent`, the premise the rest rest on)
with wstg_audit()                                           -> 12 passed
```

### 8b. Mutation-killed in BOTH directions, which is the point

A new guard has two ways to be useless, and this project has paid for both. Each mutant was
grep-confirmed in the source before pytest was allowed to run.

```
MUTANT A - the REPORTED term wrongly asserted into `ok` (the guard rejects too much)
  sed 'and not (outside or overlap or claimed_outside),'
   -> 'and not (outside or overlap or claimed_outside or claimed_unmapped),'     grep 1
  4 failed: a_clean_table_still_passes, a_newly_added_clean_row_passes_too,
            the_claimed_but_unmapped_set_is_exactly_the_measured_one,
            the_reported_list_can_grow_and_still_not_fail_the_audit

MUTANT B - the fault clause neutered (the guard accepts everything)
  sed 'and not (outside or overlap or claimed_outside),' -> 'and True,'          grep 1
  5 failed: exactly the five hard-fault negative controls, and nothing else
```

**Neither the "rejects everything" nor the "passes everything" failure can happen silently.** DoD 2
asks for the first half specifically, and `test_a_newly_added_clean_row_passes_too` strengthens it:
the guard accepts a clean row it has never seen, so `ok` is not passing because the shipped tables
happen to be memorised.

---

## 9. PATCHES FOR FILES THIS LANE DOES NOT OWN. Not applied.

### 9a. The `csrf` re-key (DoD 4) — 1 line of mine + 8 pin sites in 4 files that are not

The EFFECTS line, to go directly after `race_condition` in `agent/engine_descriptor.py`:

```python
    # Q-081. Same DOOR as `race_condition` above and the same measurement (effects4.md §1-3): all four
    # engines the `recon["forms"]` loop emits end the mission session on a mount that invalidates on
    # logout, 4/4 with a clean 4/4 paired control on the `logout_invalidates=False` mount. `run_csrf` is
    # this technique's ONLY route, so unlike `command_injection` (run_cmdi) and `stored_xss` (run_xss)
    # there is no primary engine here that lacks the behaviour, and the entry mis-attributes nothing.
    # It matters MORE than the race row: run_csrf is ACTIVE and run_race is not, so without this the
    # model records the FULL-mode session killer and omits the DEFAULT-mode one.
    # WHEN THE FORMS DOOR IS FIXED, RE-MEASURE — this is expected to become false, exactly as the
    # race row is.
    "csrf":                    {"establishes": [], "invalidates": ["authenticated"],
                                "engine": ["run_csrf"]},
```

The pins it moves, with the measured replacement values so nobody re-derives them
(`conflicts()` 6 -> 12 rows, producers `{'csrf', 'race_condition'}`, csrf's six consumers identical
to race's six because both invalidate `authenticated`):

```
tests/test_effects_negative_half.py:129   negative == ["race_condition"]
                                       -> ["csrf", "race_condition"]              (it is sorted())
tests/test_effects_negative_half.py:150   {p for p,_,_ in rows} == {"race_condition"}
                                       -> {"csrf", "race_condition"}
tests/test_effects_negative_half.py:149   [c for _,_,c in rows] == AUTHENTICATED_CONSUMERS
                                       -> AUTHENTICATED_CONSUMERS * 2  (conflicts() sorts by
                                          producer, so csrf's six precede race's six)
tests/test_engine_descriptor.py:79        [t for t,e in EFFECTS.items() if e.get("invalidates")]
                                          == ["race_condition"]   <- INSERTION order, not sorted:
                                       -> ["race_condition", "csrf"] if appended after it
tests/test_engine_descriptor.py:80        {t for t,_,_ in cf} -> {"csrf", "race_condition"}
tests/test_engine_descriptor.py:96        {"fake_rotator", "race_condition"}
                                       -> {"csrf", "fake_rotator", "race_condition"}
tests/test_engine_descriptor.py:141       ef["conflict_count"] == len(ef["conflicts"]) == 6  -> 12
tests/test_engine_descriptor.py:142       {c["technique"] for c in ef["conflicts"]}
                                       -> {"csrf", "race_condition"}
tests/test_effects_engine_fact.py:174     {p for p,_,_ in cf} -> {"csrf", "race_condition"}
tests/test_effects_key_is_a_technique.py:132  {r[0] for r in ed.conflicts()}
                                       -> {"csrf", "race_condition"}
```

Unchanged by the patch, MEASURED, so the reviewer knows what should NOT move:
`build()` 88 descriptors, `chains()` 46 rows, `effects_audit()["differs_from_derived_route"]` still
the single `sqli_structural` row, `unregistered`/`unimplemented`/`unknown_technique` all empty.

### 9b. `agent/asvs_model.py` — the six `violated_by` families nothing produces (S6)

Each of these makes its objective unable to read `failed`, always in the flattering direction. This
is the Q-048 defect, and Q-048's own fix is the template: find the family the engine ACTUALLY emits
and point `violated_by` at that exact string, rather than at the plausible one.

```
ATHZ-00   "broken_access_control"   -> the producer census has "access_control" and "bfla"
ATHZ-00,
ATHZ-02   "privilege_escalation"    -> census has "bfla" (BFLA is the privilege-escalation oracle)
AUTHN-04  "cleartext_transport"     -> census has "insecure_cookie" / transport families; needs the
                                       transport-posture producer read before choosing
COMM-03   "information_disclosure"  -> census has "sensitive_exposure" / "exposure"
VAL-07    "ldap"                    -> census has "ldap_injection"
VAL-07    "xpath"                   -> census has "xpath_injection"
```

**Do not apply this from the table above.** Four of the six have an obvious candidate and two do not,
and the correct move for each is to read the producer that owns the objective's engine and copy the
literal it writes — the same discipline that made Q-048's fix correct. The value here is the LIST and
the measurement, not the guesses.

### 9c. `agent/wstg_catalog.py` / the `wstg` column — the three S4 rows

A lead, not a patch, and deliberately so: two of the three look like the technique record is wrong
rather than the catalog (`csti` claiming "Cross Site Script Inclusion"; `crlf_injection` claiming
WSTG-INPV-16 while routing to no engine), and deciding that needs evidence about what `run_dom_audit`
and the CRLF sweep actually confirm — evidence this lane did not gather. The set is now pinned by
`test_the_claimed_but_unmapped_set_is_exactly_the_measured_one`, so whichever way it is resolved, it
moves on purpose.

---
