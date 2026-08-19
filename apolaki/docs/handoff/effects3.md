# Effects lane run 3 - Q-074, verifying what run 2 recorded and answering the decoration question

Owner: effects lane run 3 (Builder). Files I may write: `agent/engine_descriptor.py`,
`agent/techniques.py`, `agent/effect_search.py`, tests under `agent/tests/`, this file. Patches for
files I do not own are at the bottom, not applied.

Predecessors: `docs/handoff/effects.md` (run 1, Q-007, removed the phantom) and
`docs/handoff/effects2.md` (run 2, Q-074, found the real invalidation). Run 2 was killed with its
work log showing `S7 full suite: in progress`, so the first job here is to establish **what is
actually recorded**, by measurement rather than by reading run 2's description of it.

Every claim below is MEASURED (command + real output) or UNVERIFIED. Every zero carries a positive
control naming the fields read.

---

## 0. THE APPARATUS, and it failed silently once before it worked

Two other lanes are live in this tree (`agent/tools.py` is modified under me by the permission
re-tiering lane), so **every probe and every test run here goes against an ISOLATED SNAPSHOT of
HEAD**, never the shared worktree:

```
git archive HEAD apolaki/agent | tar -x -C <scratchpad>/snap        # HEAD = bda362d
MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default -e PYTHONPATH=/app \
  -v "<scratchpad>/snap/apolaki/agent:/app" -v "<scratchpad>/probe:/probe" \
  -w /app apolaki-agent python /probe/<probe>.py
```

Fields and attributes read, stated so a later reader can tell the instrument from the code:
`engine_descriptor.EFFECTS / .PRECONDITIONS / .ALWAYS_ON / .build() / .routes() / .routing_audit() /
.effects_audit() / .chains() / .conflicts() / .engine_implementations()`;
`effect_search.plan() / .breaks() / .unlocks() / .applicable() / .frontier() / .successor()`;
`tools.TOOL_PERMISSIONS`, `tools._SESSION_KILL_RE`, `tools.ToolRegistry.session_headers / ._sessions
/ .recon["forms"] / .session_kill_urls / .urls`.

**INSTRUMENT ERROR, recorded because it produced a confident wrong answer first.** My first mutation
run reported all four mutants PASSING - i.e. "the guard is vacuous", the exact conclusion this ticket
was written to test for. It was false. The mutation script drove `python` on the HOST, and MEASURED:

```
$ command -v python
/c/Users/voice/AppData/Local/Microsoft/WindowsApps/python
$ python --version
Python was not found; run without arguments to install from the Microsoft Store, ...
```

The Windows Store stub. It wrote nothing, exited non-zero into a `/dev/null` I had redirected, and
the harness then ran pytest against an **unmodified copy** and reported green. That is the fourth
instrument error in this project's probes and it is the most dangerous shape of it: the apparatus
failing produces the same output as the finding. **Every mutation below is now proved to have landed
by `grep` on the mutant file BEFORE pytest is allowed to run**, and a no-mutation control is run
through the identical harness.

---

## 1. WHAT IS ACTUALLY RECORDED - run 2's work IS landed, and it matches its handoff

Run 2's changes are committed at `3a680db`; nothing of the effects lane is uncommitted in the tree.
MEASURED on the HEAD snapshot, probe `p1_baseline.py`:

```
EFFECTS entries              : 12
EFFECTS non-empty invalidates: ['race_condition']
EFFECTS non-empty establishes: 11
    race_condition -> {'establishes': [], 'invalidates': ['authenticated'], 'engine': ['run_race']}
descriptors built            : 88
conflicts() rows             : 6
    ('race_condition', 'authenticated', 'cache_deception')
    ('race_condition', 'authenticated', 'jwt_forge')
    ('race_condition', 'authenticated', 'jwt_key_confusion')
    ('race_condition', 'authenticated', 'session_fixation')
    ('race_condition', 'authenticated', 'session_lifecycle')
    ('race_condition', 'authenticated', 'weak_2fa_bypass')
distinct producers in conflicts(): ['race_condition']
POSITIVE CONTROL chains() rows: 46 from 10 producers
routing_audit phantom        : [] ok: True
effects_audit ok             : True checked: 12
   effects_audit[unregistered] = []
   effects_audit[unimplemented] = []
NEGATIVE CONTROL 'apolaki_not_a_technique' in EFFECTS: False
```

The 6 rows and 12 entries the Coordinator measured are **exactly** run 2's single `race_condition`
row expanding over the six consumers of `authenticated`. There is no half-written second entry and
no orphan. Run 2's handoff describes its result accurately.

Effects tests on the same snapshot: **82 passed, exit 0**
(`test_effects_negative_half.py`, `test_effects_engine_fact.py`, `test_engine_descriptor.py`,
`test_effect_search.py`, `test_effect_search_routing.py`).

---

## 2. THE GUARD IS NOT VACUOUS - four file-level mutants, all red

DoD item 3, and the ticket's specific worry: *a guard written against a near-empty set is the easiest
kind to satisfy vacuously.* Run 2's controls mutate a `copy.deepcopy` of the table inside the test.
That proves `effects_audit` rejects a dirty dict; it does **not** prove the shipped table is pinned.
So the phantom was planted in the SOURCE FILE, in a fresh copy of the snapshot, and each mutation was
confirmed present by grep before pytest ran.

| mutant | planted in `engine_descriptor.py` `EFFECTS` | grep confirms | pytest |
|---|---|---|---|
| `unrouted` | `business_logic_abuse` invalidates `authenticated`, engine `run_business_logic_abuse` | 1 | **exit 1, 17 FAILED** |
| `phantom_wpr` | `weak_password_reset` re-armed, the Q-007 phantom | 1 | **exit 1, 15 FAILED** |
| `no_engine_key` | `business_logic_abuse` invalidates, **no `engine` key at all** | 1 | **exit 1, 12 FAILED** |
| `deleted` | the real `race_condition` row removed | row gone | **exit 1, 13 FAILED** |
| *(control)* | **nothing changed**, identical harness | - | **exit 0** |

`business_logic_abuse` is not an invented name: it is drawn from the tree's own
`routing_audit()["unrouted"]` list - a real, ranked technique with a real precondition and no
dispatchable engine. The named catchers, per mutant:

```
unrouted      -> test_the_shipped_effects_table_is_clean
                 test_a_phantom_engine_also_fails_the_routing_audit
                 test_the_guard_fails_on_an_invented_engine_name
                 test_every_row_the_planner_can_emit_names_a_dispatchable_engine
                 test_every_conflict_row_names_a_dispatchable_engine
no_engine_key -> test_the_shipped_effects_table_is_clean
                 test_every_conflict_row_names_a_dispatchable_engine
                 test_race_condition_is_the_only_declared_negative_effect
deleted       -> test_the_negative_effect_names_an_engine_that_is_registered_and_implemented
                 test_breaks_now_reports_the_real_cost_of_running_a_race
                 test_successor_actually_removes_the_observation
                 test_the_frontier_reports_the_cost_of_an_always_on_engine
```

**VERDICT: the guard still fails on a phantom with a real entry present, at the file level and not
only inside its own fixture.** A real row did not make it lenient, and the `deleted` mutant proves
the pin is two-sided - the tests also fail if the real entry is quietly dropped, so nobody can
"simplify" the table back to empty and stay green.

### 2a. What the guard CANNOT catch, stated because it bounds the claim

MEASURED: `effects_audit` has **no production caller**. Every reference outside its own definition is
a test, plus one string literal in `deadcode_gate.py:226`'s baseline set:

```
$ grep -rn "effects_audit" --include=*.py . | grep -v "^./engine_descriptor.py"
./deadcode_gate.py:226:    ... "engine_descriptor.effects_audit",   <- a name in a baseline literal
./tests/...                                                          <- everything else
```

(`routing_audit` does have one: `technique_planner.py:58`.) So the guard is a TEST-TIME gate, not a
runtime one - which is fine for its job, and worth writing down so nobody cites it as a runtime
protection.

More importantly: the guard checks that a declared engine is **registered and implemented**. It
cannot check that the declared effect is **true**. A negative effect declared on `run_sqli` would
pass every one of these tests. Only a measurement can reject that, which is why section 3 exists and
why the entry must never be extended on reasoning alone.
