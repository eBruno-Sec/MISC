# Effects lane run 4 - Q-074, and the DOOR is four engines wide

Owner: effects lane run 4 (Builder). Files I may write: `agent/engine_descriptor.py`,
`agent/techniques.py`, `agent/effect_search.py`, tests under `agent/tests/`, this file. Patches for
files I do not own are at the bottom, not applied.

Predecessors, all left intact: `docs/handoff/effects.md` (run 1, Q-007, removed the phantom),
`effects2.md` (run 2, Q-074, found the real invalidation), `effects3.md` (run 3, verified run 2's
entry and measured that the planner does nothing with it). Run 3 was killed mid-investigation. Its
last written words named the thing to chase:

> "The vocabulary admits exactly one destroyable term. But the same unfiltered `recon["forms"]` loop
> emits **two** engines - `run_csrf` shares the door with `run_race`. Let me drive it."

**I drove it. It is not two engines. It is four, and one of them runs at `active`.**

Every claim below is MEASURED (command + real output) or UNVERIFIED. Every zero carries a positive
control naming the fields read.

---

## 0. THE APPARATUS

Two other lanes are live in this tree (`agent/deadcode_gate.py` and `agent/tests/test_deadcode_gate.py`
carry another lane's uncommitted work), so **every probe runs against an ISOLATED SNAPSHOT of HEAD**,
never the shared worktree:

```
git archive HEAD agent | tar -x -C <scratchpad>/snap     # HEAD = 280ce13
MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default -e PYTHONPATH=/app \
  -v "<scratchpad>/snap/apolaki/agent:/app" -v "<scratchpad>/probe:/probe" \
  -w /app apolaki-agent python /probe/<probe>.py
```

Fields and attribute names read, stated so a later reader can tell the instrument from the code:
`tools.ToolRegistry.session_headers / ._sessions / .urls / .session_kill_urls / .recon["forms"]`;
`tools._SESSION_KILL_RE`; the shipped methods `_run_csrf / _run_race / _run_form_cmdi /
_run_stored_xss / _http_probe / _add_urls / _merge_identity`; `planner.next_batch` and each returned
step's `["tool"]`, `["input"]["url"]`, `["key"]`; `engine_descriptor.EFFECTS / .conflicts() /
.effects_audit() / .routing_audit() / .chains()`; `effect_search.plan() / .breaks() / .frontier() /
.successor()`.

**INSTRUMENT ERROR, recorded because run 3 recorded the same one and I walked into it anyway.** A
`python - <<EOF` heredoc to patch a probe on the HOST printed
`Python was not found; run without arguments to install from the Microsoft Store` - the Windows Store
stub, exit non-zero, file unmodified. Had I not grepped the file afterwards I would have re-run an
UNCHANGED probe and read its old output as a new result. Every probe edit below is confirmed by grep
before the probe is allowed to run. This is the fifth instance of this failure shape in this
project's probe harnesses; it belongs in the standing notes, not in a handoff.

---

## 1. `run_csrf` DESTROYS THE MISSION SESSION. Measured, with three controls.

Probe `p5_csrf_kill.py`, driving the SHIPPED `tools.ToolRegistry._run_csrf` against the running
`sessionlife` lab (`labs/sessionlife/app.py`, compose service `sessionlife`). Nothing simulated: the
engine is the shipped method, the transport is its own `_http`, the target is the live container.

```
HALF 0 -- POSITIVE CONTROL: the instrument CAN observe a session dying
  freshly logged in                  : (200, True)
  direct GET /secure/api/logout      : 200   <- GET is accepted
  after that logout                  : (401, False)
  NEGATIVE CONTROL, invented cookie  : (401, False)

HALF 1 -- SHIPPED _run_csrf on a logout action, carrying the mission session
  _SESSION_KILL_RE matches the action: True
  session_headers BEFORE             : {'Cookie': 'slsid=3189f503265cdbe1319cc28f7422e39b'}
  mission /api/me BEFORE _run_csrf   : (200, True)
  _run_csrf ok=True summary='0 form(s), 0 CSRF signal(s)' err=None
  mission /api/me AFTER  _run_csrf   : (401, False)
  tr.session_headers UNCHANGED       : {'Cookie': 'slsid=3189f503265cdbe1319cc28f7422e39b'}
  tr._sessions STILL RECORDS IT      : {'persona_a': {'Cookie': 'slsid=3189f503265cdbe1319cc28f7422e39b'}}
  authenticated derivable (bool)     : True

HALF 2 -- NEGATIVE CONTROL: identical engine+probe on /vuln (logout_invalidates=False)
  mission /api/me BEFORE _run_csrf   : (200, True)
  _run_csrf ok=True summary='0 form(s), 0 CSRF signal(s)'
  mission /api/me AFTER  _run_csrf   : (200, True)

HALF 3 -- NEGATIVE CONTROL: same engine, /secure landing page (not a kill action)
  mission /api/me BEFORE _run_csrf   : (200, True)
  _run_csrf ok=True summary='0 form(s), 0 CSRF signal(s)'
  mission /api/me AFTER  _run_csrf   : (200, True)
```

**VERDICT: YES.** `run_csrf` ends the mission session exactly as `run_race` does. Two negative
controls bound it: the same engine on the mount whose only difference is `logout_invalidates=False`
leaves the session up, and the same engine on a non-kill URL of the same mount leaves it up. So the
kill is attributable to the ACTION, not to the engine merely making a request.

**The mechanism is one line.** `_run_csrf` is `r = await self._http(url, "GET", capture=True)` and
`_http` calls `self._merge_identity(headers)` with `headers=None`, which returns
`{"User-Agent": _UA, **(self.session_headers or {})}`. A GET is enough: the lab's `_route` dispatches
`/api/logout` on any method, which is what a great many real applications do. **`run_csrf` needs no
payload and no POST to do this - it destroys the session by reading the page it was asked to audit.**

The engine also reported `success=True` and `0 CSRF signal(s)` while doing it. From the mission's
point of view that is an engine that ran cleanly and found nothing.

---

## 2. THE DOOR IS FOUR ENGINES WIDE, and one of them fires at `active`

Run 3 expected two. I drove the shipped planner instead of counting call sites, and it is four.

### 2a. The planner, driven (probe `p6_planner_door.py`)

`recon["forms"]` here is **not hand-written**: it is the exact dict the shipped `_http_probe`
produced in section 3 below, pasted character for character.

```
POSITIVE CONTROL -- the planner is producing steps at all
mode=full   recon['forms'] = the measured entry: total steps=51  steps targeting the QUARANTINED logout url=4
    run_form_cmdi          url=http://sessionlife:8080/secure/api/logout
    run_stored_xss         url=http://sessionlife:8080/secure/api/logout
    run_csrf               url=http://sessionlife:8080/secure/api/logout
    run_race               url=http://sessionlife:8080/secure/api/logout

mode=active recon['forms'] = the measured entry: total steps=43  steps targeting the QUARANTINED logout url=1
    run_csrf               url=http://sessionlife:8080/secure/api/logout

NEGATIVE CONTROL -- identical state, recon['forms'] EMPTY (the only variable)
mode=full   recon['forms'] = []: total steps=47  steps targeting the QUARANTINED logout url=0

VERDICT: forms-door steps on the kill url  full=4 active=1 none=0
```

The negative control is the load-bearing row: emptying `recon["forms"]` and changing nothing else
drops all four steps while the planner still emits 47 others. The steps come through that list and
nowhere else.

`run_csrf` is `PermissionLevel.ACTIVE` (`tools.py:179`), so **the session kill is reachable in the
DEFAULT scan mode**, not only in the Full mode that gates the three intrusive ones.

### 2b. The census: all four kill it (probe `p7_door_census.py`)

Each engine gets a FRESHLY MINTED session so one engine's kill cannot be attributed to another. Each
row is paired with the `/vuln` mount, which differs in exactly one server-side behaviour.

```
THE DOOR CENSUS -- every engine the planner emits for a recon['forms'] session-kill action
mount /secure  (logout_invalidates=True)   <- the real behaviour of any correct app
engine          before        after         engine ran              hdrs kept  bool(_sessions)
run_csrf        (200, True)   (401, False)  success=True            True       True
run_race        (200, True)   (401, False)  success=True            True       True
run_form_cmdi   (200, True)   (401, False)  success=True            True       True
run_stored_xss  (200, True)   (401, False)  success=True            True       True

NEGATIVE CONTROL -- mount /vuln (logout_invalidates=False), one variable changed
engine          before        after         engine ran
run_csrf        (200, True)   (200, True)   success=True
run_race        (200, True)   (200, True)   success=True
run_form_cmdi   (200, True)   (200, True)   success=True
run_stored_xss  (200, True)   (200, True)   success=True
```

**Four for four, and the control is clean four for four.** Every one of them reports `success=True`.
Every one of them leaves `session_headers` holding the dead cookie and `bool(_sessions)` reading
True - the derivation `agent.py:1394` feeds to `technique_planner.derive_observations` as
`authenticated`.

---

## 3. THE DOOR ITSELF: the registry holds one URL under two contradictory policies

Probe `p5_csrf_kill.py` HALF 4, both halves driven through the shipped `_http_probe`:

```
HALF 4 -- THE TWO DOORS, both driven through the shipped _http_probe
  A) LINK door  (page <a href=logout>): probe ok=True
     logout in tr.urls                : False   <- must be False
     logout in tr.session_kill_urls   : True    <- must be True
     POSITIVE CONTROL /api/me in urls : True
     recon['forms']                   : []
  B) FORM door  (POST form to logout): probe ok=True
     recon['forms']                   : [{"action": "http://sessionlife:8080/secure/api/logout",
                                          "method": "POST", "fields": ["csrf"]}]
     logout in tr.urls                : False
     logout in tr.session_kill_urls   : True
```

**Read row B carefully, because it is a sharper finding than "the filter never saw it".** The filter
DID see it. `_http_probe`'s link regex is `(?:href|src|action)=`, so the form's action goes through
`_add_urls`, matches `_SESSION_KILL_RE`, and is correctly quarantined into `session_kill_urls` and
kept out of `urls`. **And the very same URL is simultaneously appended to `recon["forms"]` by the
branch twenty lines below, which filters on `self.scope.validate(act)` and nothing else.**

So the registry ends a crawl holding one URL under two policies that contradict each other:

| container | policy | populated at |
|---|---|---|
| `session_kill_urls` | never probe this; only `_run_session_lifecycle` may touch it, with a sacrificial session | `tools.py:3518-3521` |
| `recon["forms"]` | probe this with `run_csrf`, `run_race`, `run_form_cmdi`, `run_stored_xss`, carrying the mission session | `tools.py:3948-3959` |

`_SESSION_KILL_RE` has exactly one use site (`_add_urls`). The quarantine is not bypassed by an
unknown URL; it is **overruled by a second container built from the same response body**.

The fixture in row B is disclosed rather than dressed up: no lab in this tree serves a POST logout
form, so the page is a three-line document I served from the probe process
(`<form method="post" action="…/api/logout"><input name="csrf">`). That markup is the shape Spring
Security, Django, Rails and Laravel all emit for logout, and it is the INPUT to the code under test,
not the behaviour under test - the behaviour under test is which container Apolaki puts it in, and
that is the shipped code's answer. Row A, whose page IS the lab's own, is the positive control
proving the instrument reads the right two fields.

---

## 4. THE DOOR TICKET, for the Coordinator to file

**`recon["forms"]` re-admits session-destroying URLs that `_add_urls` already quarantined, and four
engines then probe them with the mission's own session. Nothing records the loss.** HIGH.

Not "a race engine is impolite". The measured shape:

1. A crawl of any application with a POST logout form puts that action in BOTH `session_kill_urls`
   (quarantined) and `recon["forms"]` (probe surface). MEASURED, section 3.
2. The planner emits 4 steps against it at `full` and 1 at `active`. MEASURED, section 2a, with the
   empty-forms negative control.
3. All 4 end the mission session on a target that invalidates on logout - i.e. on any correctly
   implemented application. MEASURED, section 2b, 4/4, with a 4/4 clean paired control.
4. `session_headers` still holds the dead cookie and `bool(_sessions)` still reads True, so
   `derive_observations` is handed `authenticated=True` over a session the server destroyed.
   MEASURED, sections 1 and 2b.

**The consequence is a self-inflicted false-negative source that is indistinguishable from a clean
target.** Every authenticated probe scheduled after that step silently tests as anonymous, finds
nothing, and reports `success=True`. The scan does not crash, does not warn, and does not record a
single fact about what happened. It is the failure mode this project keeps writing tickets about -
an apparatus failing in a way that produces the same output as the finding - except here the
apparatus is the product.

**The fix belongs at the door, not in either engine**, because four engines share it and the fifth
one added next year will inherit it. Two candidate patches, in files I do not own
(`agent/tools.py`, held by the Q-052 tier-split lane):

**Patch A - filter the forms door with the same predicate that guards the URL door** (`tools.py`,
in `_http_probe`, the POST branch at ~3956). One line, same regex, same use site pattern:

```python
                if method == "POST":
                    if act not in seen_actions:
                        # A session-destroying action is already quarantined out of `self.urls` by
                        # `_add_urls`. Q-074: it must not re-enter the probe surface through the FORMS
                        # door either - MEASURED, four engines (run_csrf/run_race/run_form_cmdi/
                        # run_stored_xss) probe every entry here with the mission session, and all four
                        # end that session on any app that invalidates on logout.
                        _p = urlparse(act)
                        if _SESSION_KILL_RE.search((_p.path or "") + ("?" + _p.query if _p.query else "")):
                            continue
                        forms.append({"action": act, "method": "POST", "fields": fm.get("inputs", [])})
                        seen_actions.add(act)
```

Cost: the CSRF-token check no longer runs on logout forms. That is the correct trade - a missing
CSRF token on `/logout` is CWE-352's weakest instance (login/logout CSRF), and it is not worth
blinding the rest of an authenticated scan to detect.

**Patch B - and this one is worth more, because it survives any regex.** `_SESSION_KILL_RE` is a
name-matching heuristic; section 3 of `effects3.md` already measured a credential-rotation form that
it cannot match and must not match. So the durable fix is not a better filter but a
**revalidation**: after any step whose descriptor declares `invalidates: ["authenticated"]`, re-probe
the session and, if it is dead, clear `session_headers`/`_sessions` or re-acquire. That makes
`bool(_sessions)` an OBSERVATION instead of an assumption and turns a silent false-negative into a
recorded, recoverable event. It needs `agent.py` or `planner.py` to consult the effects model, which
is exactly the wire section 6 measures as absent.

The two are complementary: A stops the common case cheaply, B makes the state honest when A's
heuristic misses.
