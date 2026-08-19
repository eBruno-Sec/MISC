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
