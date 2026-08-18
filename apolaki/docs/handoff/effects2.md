# Effects lane run 2 - Q-074, the negative-effects model is EMPTY

Owner: effects lane run 2 (Builder). Files I may write: `agent/engine_descriptor.py`,
`agent/techniques.py`, `agent/effect_search.py`, tests under `agent/tests/`, this file. Patches for
files I do not own are at the bottom, not applied.

Run 1 (`docs/handoff/effects.md`) removed `weak_password_reset`, a phantom with no executor that
generated all six rows of `conflicts()`. That was strictly correct and it left the Sussman half of
the model empty. Q-074 asks for a REAL invalidation, measured rather than asserted, and names
`session_lifecycle` as the candidate.

**Headline, measured before it was written: the ticket names the wrong engine.**
`session_lifecycle` does not invalidate anything - run 1's code-read conclusion is confirmed, now by
driving the engine. **`race_condition` (`run_race`) does**, on a form no filter can exclude without
disabling the engine, and the measurement is in section 3.

Every claim below is MEASURED (command + real output) or UNVERIFIED. Every zero carries a positive
control naming the fields read. Status is what HAPPENED; a row becomes a verdict only under evidence.

---

## 0. THE APPARATUS

Throwaway container against the WORKTREE source, never `apolaki-agent-1`:

```
MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default -e PYTHONPATH=/app \
  -v "C:/Users/voice/Desktop/GitHub/MISC/apolaki/agent:/app" \
  -v "<scratchpad>/probe:/probe" -w /app apolaki-agent python /probe/<probe>.py
```

`PYTHONPATH=/app` is load-bearing (run 1's instrument error; python puts the SCRIPT's dir on
`sys.path`, not the cwd).

Fields and attributes read, stated so a later reader can tell the instrument from the code:
`engine_descriptor.EFFECTS / .PRECONDITIONS / .OBSERVATIONS / .routes() / .routing_audit() /
.effects_audit() / .build() / .chains() / .conflicts()`;
`effect_search.plan() / .breaks() / .unlocks() / .frontier() / .successor()`;
`tools.ToolRegistry.session_headers / ._sessions / ._session_state / .state.capabilities /
.urls / .session_kill_urls / .recon["forms"] / ._sesslife_identity`; `tools._SESSION_KILL_RE`;
`technique_planner.derive_observations`; `asset_graph.AssetGraph.to_observations`.

---

## 1. BASELINE - three live facts, re-measured, one of them stale

MEASURED, probe `q074_baseline.py`:

```
EFFECTS entries          : 11
PRECONDITIONS entries    : 42
OBSERVATIONS vocabulary  : 17
descriptors built        : 88
EFFECTS with non-empty invalidates: []
EFFECTS with non-empty establishes: 11
chains()    rows: 46 from 10 producers   <- POSITIVE CONTROL
conflicts() rows: 0
routes(): techniques mapped = 77 of 88 ; distinct engines = 44
routing_audit phantom: [] ok: True
routing_audit unrouted: 11
effects_audit ok: True checked: 11
PRECONDITIONS keys that ARE technique ids: 42 of 42
NEGATIVE CONTROL 'apolaki_not_a_technique' in technique ids: False
```

The empty `conflicts()` is a real zero, not an instrument that was not looking: the same `build()`
walked by the same code returns 46 chain rows from 10 producers.

**Correction to the handoff I was given.** It states `routes()` maps **75 of 88** to **41** engines.
MEASURED on the worktree at `ddfeed2`: **77 of 88** to **44**. 0 phantoms is unchanged, and so is
`PRECONDITIONS` at 42/42. The two counts drifted under other lanes' routing work; nothing in this
ticket depends on them, and they are recorded here so the next reader does not "reproduce" a stale
number and conclude the tree moved under them.

---

## 2. `session_lifecycle` DOES NOT INVALIDATE ANYTHING - measured, not argued

Run 1 reached this by reading three mechanisms in `tools.py` (`_sl_mint` mints a sacrificial account,
`_sl_req` deliberately does not merge `session_headers`, `_session_kill_is_safe` re-checks value
disjointness before the destructive step). That is a code read. Q-074 asks for a measurement, so the
engine was DRIVEN over real HTTP against the shipped `sessionlife` lab
(`http://sessionlife:8080`, compose service `sessionlife`, host 42097) with a REAL mission session
belonging to a DIFFERENT account.

MEASURED, probe `q074_sesslife_state.py`:

```
POSITIVE CONTROL FIRST: the instrument CAN observe a session dying.
secure mount, freshly logged in : (200, True)
after a DIRECT logout of that same credential (HTTP 200): (401, False)
NEGATIVE CONTROL, an invented cookie  : (401, False)

MEASUREMENT: run_session_lifecycle on /vuln
engine ok=True findings=2
  sacrificed identity   : apolaki_sessionprobe_61db2217@apolaki-test.local
  mission identity      : mission_operator@apolaki.test
  mission /api/me BEFORE: (200, True)
  mission /api/me AFTER : (200, True)
  session_headers changed: False
  _sessions      changed: False
  _session_state changed: False
  capabilities   changed: False | before=0 after=0

MEASUREMENT: run_session_lifecycle on /secure
engine ok=True findings=0   (declines the secure partner)
  sacrificed identity   : apolaki_sessionprobe_11595e8c@apolaki-test.local
  mission /api/me BEFORE: (200, True)
  mission /api/me AFTER : (200, True)
  session_headers changed: False   _sessions changed: False
```

The engine ran for real (it confirmed the vulnerable mount and declined the secure one), it named the
account it sacrificed, and that account is not the mission's. Every engagement-state field read is
byte-identical before and after, and the mission credential still reaches the authenticated marker.
The positive control on the SAME instrument moved (200, True) -> (401, False), so "unchanged" is a
measurement and not a blind read.

**VERDICT: `session_lifecycle` gets no `invalidates` entry.** Confirmed, now by measurement rather
than by inference from the source.

---

## 3. THE REAL INVALIDATION: `race_condition` / `run_race` DESTROYS `authenticated`

Found by asking the question the ticket implies rather than the one it asks: *which engine, if any,
takes an action that ends the ENGAGEMENT's session?* Only two of the 17 observations are destroyable
by an action at all (section 5); `authenticated` is one, and the platform has a purpose-built
protection for it - so the measurement is: does that protection hold everywhere?

### 3a. The protection, and the door it does not cover

MEASURED: `tools._SESSION_KILL_RE` has exactly **one** use site in the tree.

```
$ grep -rn "_SESSION_KILL_RE" --include=*.py .
./session_lifecycle_tool.py:47:   (a comment referring to it)
./tests/test_bbh.py:939,944       (a test)
./tools.py:283                    (the definition)
./tools.py:3515                   (the ONLY use: inside _add_urls)
```

`_add_urls` keeps a logout URL out of `self.urls` and quarantines it into `self.session_kill_urls`.
That door works. **`recon["forms"]` is a second door into the probe surface and no session-kill
filter guards it**: `agent.py:_harvest_rendered_forms` (3556-3579) and `tools.py:3945-3955` both
append any in-scope POST form action to `recon["forms"]` unfiltered, and `planner.py:616-623` emits a
`run_race` step for every one of them. `tools.py:_run_race` merges `self.session_headers` into every
one of its 20-60 concurrent requests.

MEASURED end-to-end, probe `q074_race_logout.py`, driving the shipped `_add_urls` and the shipped
`_run_race`:

```
HALF 1 -- the quarantine that DOES work (positive control for the instrument)
_SESSION_KILL_RE matches '/account/logout': True
  in tr.urls (probe surface) : False   <- must be False
  in tr.session_kill_urls    : True    <- must be True
  /api/me reached the surface: True    <- POSITIVE CONTROL

HALF 2 -- the SECOND door: recon['forms'], which no session-kill filter guards
recon['forms'] entries: [{"action": ".../account/logout", "method": "POST",
                          "fields": ["csrf"], "page": ".../account"}]
planner step -> run_race {"url": ".../account/logout", "method": "POST", "body": "csrf=1"}
mission /api/me BEFORE run_race : (200, True)
run_race ok=True findings=1
mission /api/me AFTER  run_race : (401, False)
tr.session_headers unchanged    : {'Cookie': 'sid=MISSION-SID'}
```

The last line is the whole ticket in one output. The scan is logged out, and `session_headers` still
holds the dead cookie, so nothing in the platform's own state records the loss.

### 3b. It is NOT an artifact of that hole

A quarantine hole is fixable with a regex, and modelling a fixable bug as a capability is exactly the
over-declaration this module forbids. So the effect was re-measured on a form `_SESSION_KILL_RE` does
not match **and could not match without disabling the engine**: a credential-rotation form, the
canonical single-use action a race test exists to attack.

MEASURED, probe `q074_race_pwchange.py`:

```
POSITIVE CONTROL: a harmless state-changing form -> /notes/add
  _SESSION_KILL_RE matches this action: False
  mission /api/me BEFORE: (200, True)
  run_race ok=True findings=1
  mission /api/me AFTER : (200, True)          <- no kill reported where there is none
  server-side hits      : {'pw': 0, 'note': 4}

THE MEASUREMENT: credential rotation -> /account/change-password
  _SESSION_KILL_RE matches this action: False
  mission /api/me BEFORE: (200, True)
  run_race ok=True findings=1
  mission /api/me AFTER : (401, False)
  server-side hits      : {'pw': 4, 'note': 4}
```

Same engine, same identity, same probe, one thing different: what the form does. The harmless form
leaves the session up, so the instrument does not report a kill when there is not one. The rotation
form ends it, and the fix in section 6 does not and cannot cover that action.

**VERDICT: `race_condition` has a real negative effect on `authenticated`, measured on the shipped
engine, surviving the fix for the adjacent defect.**

### 3c. Why the declaration is unconditional when the field behaviour is not

Honest statement of the weakness, because it is the one an adversarial reader will reach for:
`run_race` destroys `authenticated` only when the raced action is session-affecting, and `EFFECTS`
has no conditional-effect formalism - a delete-list entry is unconditional.

Declaring it anyway is the correct direction of error, and the reason is not taste. An
over-approximated delete list costs COMPLETENESS (the search may decline an ordering that would in
fact have worked); an under-approximated one costs SOUNDNESS (the planner emits an ordering that
dies in the field). Section 3a is a measurement of the second failure actually occurring. The
module's standing rule - "over-declaring is worse than not declaring" - was written about
`establishes`, where the arithmetic runs the other way: an over-declared `establishes` makes the
planner chase a capability it does not have, which is unsound. The two halves are not symmetric, and
this file is where that is written down.

---

## 4. WHAT THE PLANNER ACTUALLY DOES DIFFERENTLY

The ticket asks for this explicitly, and for the entry to be called decoration if the answer is
nothing. Measured by running every consumer of the model twice - shipped table, and the same table
with the `race_condition` row deleted, which is byte-for-byte the pre-Q-074 tree.

MEASURED, probe `q074_planner_delta.py`, observations `{has_login, authenticated, serves_js}`:

| consumer | before | after |
|---|---|---|
| `conflicts()` | `[]` | 6 rows, all `race_condition -> authenticated -> {cache_deception, jwt_forge, jwt_key_confusion, session_fixation, session_lifecycle, weak_2fa_bypass}` |
| `breaks(d, obs, "race_condition")` | `[]` | the same 6 technique ids |
| `frontier()["consequences"]` | 7 keys | 8 keys (`race_condition` added) |
| `frontier()["always_on_with_effects"]` | 2 | 3 |
| `frontier()["applicable_now"]` | - | **UNCHANGED** |
| `plan(->authenticated)`, `plan(->credentials_exposed)` | - | **UNCHANGED** |
| `chains()` | 46 | **UNCHANGED** (46) |

**`plan()` is unchanged and that is not a defect - it is arithmetic, and it is stated rather than
hidden.** `_plan_core` records a candidate only when the goal appears in a successor state, and
`race_condition` establishes nothing, so it can never shorten a plan. It can only add expansions. A
negative-only action changes the ordering ADVICE (`breaks`, `conflicts`), not the reachability
answer. `tests/test_effects_negative_half.py::test_the_plan_search_is_deliberately_UNCHANGED_by_the_negative_effect`
pins that, so nobody later "fixes" it into looking like a win.

**The production surface that changes**: `main.py:1306` (`/orchestration/audit`) serves
`effects.conflicts` and `effects.conflict_count`, which go 0 -> 6. `main.py:1391`
(`/orchestration/reachability`) serves `frontier`, whose `consequences` now carries the cost.

### 4a. The gap that would have made the entry decoration, and it PREDATES this ticket

`frontier()["consequences"]` was keyed off `applicable_now`, and `applicable()` returns only engines
with a NON-EMPTY precondition list - correct for the precondition filter's question, and it means an
always-on engine can never appear there whatever it establishes or destroys. `_plan_core` has always
taken the other view (`if a["requires"] and not all(...)` - an action with no requirements is
available in every state), so the two disagreed and `frontier` inherited the filter's view.

MEASURED before the fix, from the failing assertion's own output:

```
frontier(build(), {"has_login","authenticated","serves_js"})["consequences"] =
  ['exposed_files_harvest', 'jwt_forge', 'jwt_key_confusion', 'sqli_auth_bypass', 'target_intel_harvest']
```

`browser_persona_bola` and `graphql_introspection` are missing - **2 of the 11 entries that HAD
effects, dropped silently, before any of this ticket's work**. So the gap is not an artifact of the
negative half; the negative half is just the first thing important enough to notice it. Fixed in
`effect_search.frontier` by adding always-on engines that DECLARE an effect, listing them separately
under `always_on_with_effects` so a consumer can tell a gated consequence from an assumed one, and
leaving `applicable_now` untouched.

---

## 5. ANTI-IDLE: the POSITIVE half has the same defect, and it is 34 of 46 rows

The ticket's audit instruction is "engines whose real state changes are unrecorded". Turning it
around on `establishes` gives the more serious result, so it is reported with counts and with its
uncertainty marked.

An `establishes` row claims the observation HOLDS for the rest of the engagement. That is true only
if the engine writes the fact the OBSERVATION DERIVATION reads. The derivation for `authenticated` is
short and singular, which is why this one can be settled rather than estimated:

* `agent.py:1394` passes `authenticated=bool(self.tools._sessions)` into
  `technique_planner.derive_observations`;
* `asset_graph.to_observations()` (line 356) needs a `capability` node keyed `session_acquired`,
  which MEASURED is written in exactly one place in the tree - `personas.py:197`.

MEASURED by enumerating EVERY method on `ToolRegistry` and matching `self._sessions[` /
`self.session_headers =` over its source:

```
Who writes `_sessions` / `session_headers` anywhere in ToolRegistry:
    __init__
    _acquire_session
    _browser_navigate
```

None of the six engines that declare `establishes: ["authenticated"]` is in that list
(`run_auth_sqli`, `run_default_creds`, `run_jwt` x2, `run_saml`,
`confirm_browser_persona_bola`).

Confirmed LIVE rather than left as a static claim, probe `q074_authbypass_live.py`, driving the
engine against Juice Shop, whose `/rest/user/login` is genuinely bypassable:

```
declared effect: {'establishes': ['authenticated'], 'invalidates': [], 'engine': ['run_auth_sqli']}

BEFORE  _sessions={}  session_headers={}
BEFORE  authenticated derivable: False

run_auth_sqli success=True findings=1
   FINDING: SQL injection (auth-bypass) in 'email' | confidence: confirmed
   output: auth-bypass SQLi CONFIRMED on the login body

AFTER   _sessions={}  session_headers={}
AFTER   state.capabilities: []
AFTER   graph.to_observations(): []
AFTER   authenticated derivable: False

POSITIVE CONTROL -- the ONE writer the enumeration found, driven by hand:
  after writing tools._sessions['probe_role']: authenticated derivable: True
```

The engine produced a **confirmed** finding and the observation it declares still did not hold. The
positive control flips it on the same instrument, so "still False" is a measurement.

**The count.** MEASURED on the shipped registry:

```
chain rows by observation: {'authenticated': 34, 'has_api': 7, 'credentials_exposed': 3,
                            'has_object_id': 2}   total 46
producers of authenticated: browser_persona_bola, default_credentials, jwt_forge,
                            jwt_key_confusion, saml_signature_bypass, sqli_auth_bypass
```

**34 of the 46 chain rows `/orchestration/audit` publishes depend on `authenticated`, and no engine
that declares it writes anything the observation derivation reads.** 6 of the 12 `EFFECTS` entries
are affected. This is Q-074's defect on the other half of the table: not a phantom ENGINE, a phantom
EFFECT - the engine is real, runs, and confirms, and the state transition it declares does not happen.

**Marked UNVERIFIED, deliberately.** The same sweep over `credentials_exposed` (3 rows), `has_api`
(7) and `has_object_id` (2) used a REGEX over each engine body, and that instrument is too weak to
support a verdict: those observations derive from the harvest/intel store, which `_http` populates
for every scoped fetch, so an engine can write the fact without naming it. I am not reporting a
number for the remaining 12 rows. `authenticated` is settled because its derivation is two named
call sites and the writer set was enumerated exhaustively over the class rather than sampled.

**Not filed by me** - `docs/QUEUE.md` is not mine to write, and a grep of it for `session_acquired`
and `establishes` returns nothing, so this is not a known ticket. It is a bigger defect than Q-074
and it should get a number.

---

## 6. PATCHES FOR FILES I DO NOT OWN

### 6a. The logout quarantine has a second door (`agent.py`, `tools.py`)

Section 3a. `_SESSION_KILL_RE` guards `_add_urls` and nothing else, and `recon["forms"]` reaches
`run_race` with the mission session attached. Measured: the scan logs itself out. Two one-line
additions, in the two places a POST form action is appended:

```python
# agent/agent.py, _harvest_rendered_forms, at the top of the `if method == "POST":` branch
            if method == "POST":
                from tools import _SESSION_KILL_RE            # same rule as _add_urls, one door
                _p = urlparse(action)
                if _SESSION_KILL_RE.search((_p.path or "") + ("?" + _p.query if _p.query else "")):
                    self.tools.session_kill_urls.append(action) \
                        if action not in self.tools.session_kill_urls else None
                    continue
```

```python
# agent/tools.py:3955, the http_probe form-capture path, same guard before the append
                        _p = urlparse(act)
                        if _SESSION_KILL_RE.search((_p.path or "") + ("?" + _p.query if _p.query else "")):
                            if act not in self.session_kill_urls and self.scope.validate(act)[0]:
                                self.session_kill_urls.append(act)
                            continue
```

This does NOT remove the `invalidates` entry and must not be read as doing so: section 3b measured
the same session loss on `/account/change-password`, which the regex does not match and could not
match without disabling the engine on exactly the actions a race test exists to attack.

A regression test for it belongs beside `test_the_engines_own_client_never_carries_the_mission_session`
in `tests/test_session_lifecycle.py`; the probe in
`<scratchpad>/probe/q074_race_logout.py` is already in the right shape to become one.

### 6b. `race_condition` carries the wrong WSTG id (`techniques.py`, which I DO own - NOT taken)

MEASURED: `techniques.py:1136` maps `race_condition` to `WSTG-BUSL-09`, whose catalog title is
"Upload of Malicious Files" and whose `wstg_catalog.FULL` engine is `run_upload_test`. The technique
is CWE-362. `wstg_catalog.PARTIAL` already says `WSTG-BUSL-05` is "run_race covers single-use/limit
races", so BUSL-05 (or BUSL-04) is the right id.

The visible consequence: `routes()["race_condition"]` is `{run_race: [always_on_reason],
run_upload_test: [wstg_full]}` - a false route claiming the upload engine runs races.

**NOT taken in this commit, on purpose.** It does not block Q-074 (`effects_audit`'s
`differs_from_derived_route` fires only when the declared and derived sets share NOTHING, and
`run_race` is in both, so the ratchet does not move), and moving a technique between WSTG ids changes
`/coverage/wstg` accounting, which is another lane's ledger. It is a clean, small fix for whoever
owns that ledger.

---

## 7. WORK LOG

| slice | state | evidence |
|---|---|---|
| S0 apparatus + baseline re-measured | DONE | section 1 (incl. a stale count corrected) |
| S1 `session_lifecycle` driven; state unchanged | DONE | section 2 |
| S2 the real invalidation found and measured twice | DONE | section 3 |
| S3 negative controls written and run BEFORE the change | DONE | section 8 |
| S4 the entry + the frontier fix + re-pointed tests | DONE | section 9 |
| S5 planner difference measured | DONE | section 4 |
| S6 anti-idle audit with counts | DONE | section 5 |
| S7 full suite | in progress | - |

---

## 8. THE NEGATIVE CONTROLS, RUN FIRST

The instruction was literal: prove the guard FAILS on a deliberately unrouted engine before trusting
it to pass. `agent/tests/test_effects_negative_half.py` was written and run against the tree with
`EFFECTS` still carrying no negative effect at all. MEASURED, that run:

```
PASSED  test_the_guard_fails_on_a_negative_effect_declared_on_a_deliberately_unrouted_engine
PASSED  test_the_routing_audit_flags_a_phantom_negative_effect_independently
PASSED  test_the_conflict_walk_reports_an_undispatchable_producer
PASSED  test_the_plan_search_is_deliberately_UNCHANGED_by_the_negative_effect
FAILED  test_the_guard_still_fails_on_a_phantom_negative_effect_with_a_real_one_present
FAILED  test_race_condition_is_the_only_declared_negative_effect
FAILED  test_the_negative_effect_names_an_engine_that_is_registered_and_implemented
FAILED  test_conflicts_are_exactly_the_techniques_that_require_authentication
FAILED  test_every_conflict_row_names_a_dispatchable_engine
FAILED  test_breaks_now_reports_the_real_cost_of_running_a_race
FAILED  test_successor_actually_removes_the_observation
FAILED  test_the_frontier_reports_the_cost_of_an_always_on_engine
```

Four controls green before the change - the guards were already catching a phantom negative effect,
including one armed from the tree's own `routing_audit()["unrouted"]` list rather than from an
invented name - and eight shipped-tree assertions red, so none of them can pass vacuously. All 12
green after.

The control that answers the ticket's specific worry -
`test_the_guard_still_fails_on_a_phantom_negative_effect_with_a_real_one_present` - re-arms
`weak_password_reset` alongside the real row and asserts `effects_audit` still names it in BOTH
`unregistered` and `unimplemented` **while verifying `race_condition -> run_race` in the same pass**.
A real row did not make the guard lenient.

---

## 9. WHAT CHANGED IN THE PRODUCT

`agent/engine_descriptor.py`
* `EFFECTS["race_condition"] = {"establishes": [], "invalidates": ["authenticated"],
  "engine": ["run_race"]}` - the first and only negative effect the table has ever carried that
  belongs to an engine which exists. `establishes` is empty on purpose: a race proves a limit can be
  bypassed, which is a finding, not an observation this 17-term vocabulary can express.
* The comment block records both measurements and the asymmetry argument in 3c.
* The `session_lifecycle` PRECONDITIONS note said "it is the one engine that ends a session". That
  is now MEASURED FALSE and is corrected to "the only engine that ends a session ON PURPOSE", with
  the pointer to `run_race`, which ends the mission's own as a side effect and has no carve-out.

`agent/effect_search.py`
* `_always_on_with_effects()` + `frontier()` now reports consequences for always-on engines that
  declare an effect, and lists them separately under `always_on_with_effects`. `applicable_now` is
  untouched. Section 4a.
* Three docstrings that used `weak_password_reset` as their worked example now use the measured one.

Tests re-pointed (all in this lane's own files): `test_effects_engine_fact.py` (the `cf == []` pin,
now a non-vacuity assertion on both halves plus a producer pin), `test_engine_descriptor.py` (the
empty-conflict pin, its negative control - which now proves the walk enumerates the TABLE rather than
the one entry - and the `/orchestration/audit` payload pin), `test_effect_search.py` (the
"no shipped engine has a cost" pin and the frontier coherence pin).
