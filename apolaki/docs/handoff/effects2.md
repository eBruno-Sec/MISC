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

in progress - measured in section 7 once the entry is in.

---

## 5. ANTI-IDLE: the audit of the remaining EFFECTS entries, with counts

in progress.

---

## 6. PATCHES FOR FILES I DO NOT OWN

in progress.

---

## 7. WORK LOG

| slice | state | evidence |
|---|---|---|
| S0 apparatus + baseline re-measured | DONE | section 1 (incl. a stale count corrected) |
| S1 `session_lifecycle` driven; state unchanged | DONE | section 2 |
| S2 the real invalidation found and measured twice | DONE | section 3 |
| S3 negative control: guard still fails on a phantom WITH a real row present | in progress | - |
| S4 the entry, the tests, the full suite | in progress | - |
| S5 planner difference measured | in progress | - |
| S6 anti-idle audit with counts | in progress | - |
