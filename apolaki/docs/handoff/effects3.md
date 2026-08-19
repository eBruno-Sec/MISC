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

---

## 3. THE RECORDED ENTRY IS TRUE - reproduced INDEPENDENTLY, on the shipped lab

DoD item 1: verify the entry against measurement, not against run 2's description of it. Run 2
measured this against a throwaway lab it built in its own scratchpad, which is gone with the session.
So this is not a re-read of run 2's output; it is a second measurement on a **different fixture**,
and the fixture is not invented - it is the SHIPPED `sessionlife` lab (`labs/sessionlife/app.py`,
compose service `sessionlife`), whose `/secure` mount already carries both behaviours in its own
header comment:

```
/secure   logout_invalidates: True   -> the server DELETES the session record
/secure   change_evicts:      True   -> a password change EVICTS every other session
```

Both are that lab's documented SECURE half, and both are what a real application does.

MEASURED, probe `p2_race_kill.py`, driving the shipped `_add_urls` and the shipped `_run_race`:

```
HALF 0 -- POSITIVE CONTROL: the instrument CAN observe a session dying
  freshly logged in                 : (200, True)
  after a direct logout of that cred: (401, False)
  NEGATIVE CONTROL, invented cookie : (401, False)

HALF 1 -- the quarantine that DOES work (the door _SESSION_KILL_RE guards)
  _SESSION_KILL_RE matches logout path: True
  logout in tr.urls (probe surface)   : False   <- must be False
  logout in tr.session_kill_urls      : True    <- must be True
  /api/me reached the surface         : True    <- POSITIVE CONTROL

HALF 2 -- the SECOND door: recon['forms'], which NO session-kill filter guards
  recon['forms'] entries              : [{"action": ".../secure/api/logout", "method": "POST",
                                          "fields": ["csrf"], "page": ".../secure/"}]
  session_headers BEFORE              : {'Cookie': 'slsid=3fc1bf79ffc5465aaae7274966208c6b'}
  mission /api/me BEFORE run_race     : (200, True)
  run_race ok=True findings=1
  mission /api/me AFTER  run_race     : (401, False)
  tr.session_headers UNCHANGED        : {'Cookie': 'slsid=3fc1bf79ffc5465aaae7274966208c6b'}

HALF 3 -- NOT an artifact of that regex: a form the regex CANNOT match
  _SESSION_KILL_RE matches change-password: False
  session A (raced with)  /api/me BEFORE: (200, True)
  session B (a persona)   /api/me BEFORE: (200, True)
  run_race ok=True findings=0
  session A               /api/me AFTER : (200, True)
  session B (the persona) /api/me AFTER : (401, False)   <- the loss
  tr2._sessions STILL RECORDS IT        : {'persona_b': {'Cookie': 'slsid=2820460c...'}}
  authenticated derivable (bool _sessions): True

HALF 4 -- NEGATIVE CONTROL: same engine, same probe, a mount that does NOT evict
  /vuln change_evicts=False
  session A /api/me BEFORE: (200, True)  session B BEFORE: (200, True)
  run_race ok=True findings=0
  session A /api/me AFTER : (200, True)  session B AFTER : (200, True)
```

**VERDICT: the recorded entry is TRUE.** `race_condition` / `run_race` destroys `authenticated`,
confirmed on a second fixture, through two independent routes, with the negative control on the same
instrument staying alive.

### 3a. HALF 3 is a stronger result than run 2 got, and it changes what the defect IS

Run 2 measured "the scan is logged out and `session_headers` still holds the dead cookie" - the
platform's state is SILENT about the loss. HALF 3 measures something worse on the exact derivation
the platform uses. MEASURED (`agent.py:1394` passes `authenticated=bool(self.tools._sessions)` into
`technique_planner.derive_observations`):

```
session B (the persona) /api/me AFTER  : (401, False)      <- the session is DEAD
tr2._sessions STILL RECORDS IT         : {'persona_b': {...}}
authenticated derivable (bool _sessions): True             <- the platform says it is ALIVE
```

**The state is not merely silent, it is WRONG.** `_sessions` is a dict of stored persona headers and
nothing ever revalidates them, so `bool(_sessions)` stays True over a session the server has
already destroyed. Every authenticated probe after that point tests as anonymous while the
observation model reports `authenticated`. That is a self-inflicted false-negative source that looks
exactly like a clean target.

HALF 3 also breaks the last tie to the adjacent regex defect. `/api/change-password` is not matched
by `_SESSION_KILL_RE` (measured False) and could not be without disabling the engine on precisely
the single-use action a race test exists to attack. The negative control in HALF 4 is the same
engine, the same probe, the same identity, one thing different - the mount's `change_evicts` flag -
and it leaves both sessions up, so the instrument does not report a kill where there is none.

Two independent routes to the same effect, one of which survives any fix to the quarantine. The
`invalidates` entry is not a restatement of a fixable bug.

---

## 4. WHAT THE PLANNER DOES DIFFERENTLY: **NOTHING**. The entry is TRUE and INERT.

DoD item 2, answered with the consumer graph rather than with the value delta, because the value
delta is not the question. Run 2 reported that `conflicts()`, `breaks()` and
`frontier()["consequences"]` all change while `plan()` does not, and called that the answer. It is
half of it: **a value that changes in a function nobody calls has not changed anything.**

### 4a. The value delta reproduces exactly

MEASURED, probe `p3_consumers.py`, shipped table vs the same table with the race row deleted (which
is byte-for-byte the pre-Q-074 model), observations `{has_login, authenticated, serves_js}`:

| consumer | before | after |
|---|---|---|
| `conflicts()` | 0 | **6** |
| `breaks(d, obs, race_condition)` | empty | **the 6 consumers of `authenticated`** |
| `frontier()["consequences"]` | 7 keys | **8** (`race_condition` added) |
| `frontier()["always_on_with_effects"]` | 2 | **3** |
| `chains()` | 46 | unchanged |
| `frontier()["applicable_now"]` | 16 | unchanged |
| `plan(-> authenticated)` | `sqli_auth_bypass` | unchanged |
| `plan(-> credentials_exposed)` | `exposed_files_harvest` | unchanged |
| `frontier()["reachable_goals"]` | 4 | unchanged |

Run 2's table reproduces. `plan()` being unchanged is arithmetic and not a defect: `_plan_core`
records a candidate only when the goal appears in a successor state, and `race_condition`
establishes nothing, so a negative-only action can never shorten a plan.

### 4b. The consumer graph, and this is the part that decides it

**INSTRUMENT ERROR, the second one, caught by its own implausibility.** My first consumer sweep
walked every `ast.Name` node and reported `frontier` read at `agent.py:1879`, `intel.py:184` and
`natas_ladder.py:398`. Those are LOCAL VARIABLES named `frontier`; those files do not import the
module at all. Recorded because a bare-name AST match is exactly "a wrong field name" from the
Coordinator's list of instrument-not-code failures, and it would have produced the flattering
answer. Redone by resolving the module ALIAS from each file's own import statements and counting
only qualified access on it, plus `from <mod> import <name>` bindings.

MEASURED, probe `p4_consumers_tight.py` - the COMPLETE production consumer graph of the effects
model, every `.py` in `/app`:

```
main.py   aliases={'ED': 'engine_descriptor', 'ES': 'effect_search'}
    main.py:1342  engine_descriptor.build           \
    main.py:1344  engine_descriptor.chains           >  POST /orchestration/audit
    main.py:1344  engine_descriptor.conflicts       /
    main.py:1426  engine_descriptor.build           \
    main.py:1429  effect_search.frontier             >  POST /orchestration/reachability
    main.py:1432  effect_search.plan                /

scan_scope.py:116        engine_descriptor.build          <- not the negative half
technique_planner.py:58  engine_descriptor.routing_audit  <- not the negative half
technique_planner.py     from engine_descriptor import OBSERVATIONS, PRECONDITIONS, ALWAYS_ON

NEGATIVE CONTROL -- the two files that decide what a scan RUNS:
  agent.py      aliases={}  from-imports={}  qualified reads=[]
                raw substring 'effect_search' present: False | 'engine_descriptor': False
  planner.py    aliases={}  from-imports={}  qualified reads=[]
                raw substring 'effect_search' present: False | 'engine_descriptor': False
POSITIVE CONTROL that the analyser can see an alias: main.py resolves both.
```

Three facts follow, and they are measurements:

1. **`breaks()` and `successor()` have NO production reader.** They are the two functions that
   express the negative half, and the entry's whole effect on them is invisible outside tests.
2. **`agent.py` and `planner.py` import neither module** - not by alias, not by substring. The
   mission runner and the step planner cannot consult the effects model, so no value in it can
   change what a scan does.
3. The model's **PRECONDITION half IS wired** (`technique_planner.py` imports `PRECONDITIONS`,
   `OBSERVATIONS`, `ALWAYS_ON` and calls `routing_audit`). The **EFFECTS half reaches production at
   exactly two places, both read-only HTTP reporting endpoints.**

### 4c. VERDICT, stated the way the ticket demands

**The planner does nothing differently. `race_condition`'s `invalidates` entry changes the JSON of
`POST /orchestration/audit` (`conflict_count` 0 -> 6) and of `POST /orchestration/reachability`
(`consequences` gains a key), and changes nothing a scan does.**

It is **not** decoration in the sense Q-074 feared - the entry is TRUE, measured on two fixtures
through two independent routes, and an operator reading `/orchestration/audit` now sees a real cost
where the field previously read `0` because the model was empty. That is a genuine gain in the
honesty of a published number.

It **is inert**, and calling it a planner improvement would be false. Q-007 removed a false entry and
Q-074 added a true one; both made the model more accurate and **neither changed Apolaki's behaviour,
because the effects half of the model is not connected to the scanner.** That structural fact is
larger than Q-074 and it is measured above, not inferred.

**The consequence for this ticket: `EFFECTS` is now correct on the evidence available, and making it
CONSEQUENTIAL is not an effects-table problem.** It needs `planner.py` to consult `breaks()` before
scheduling a state-changing step, or `tools.py` to revalidate `_sessions` after one. Both are files
this lane must not touch; the patch and the ticket text are in section 7.

**What I deliberately did NOT do.** The tempting move is to add a function to `effect_search.py` that
consumes the negative half - a "safe ordering" helper, a session-risk report. Nothing in `agent.py`
or `planner.py` could call it, so it would be an ISLAND: a new unreachable function declared to
close a gap it cannot reach. This project has shipped that defect repeatedly and the dead-code
ratchet exists because of it. An inert entry honestly labelled is worth more than a second unwired
mechanism.
