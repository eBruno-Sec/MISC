# Q-080 — the door lane. The session-kill quarantine, applied where surface becomes steps.

Owner: door lane (Builder). Files I may write: `agent/agent.py`, `agent/planner.py`, my own tests
under `agent/tests/`, this file. Patches for files I do not own go at the bottom, unapplied.

Predecessor: `docs/handoff/effects4.md`, which measured the defect and filed it as Q-080. Its
numbers are not re-derived here; they are re-DRIVEN, because run 4 drove `planner.next_batch` with a
hand-pasted `recon["forms"]` and the shipped executor does not build that dict the way run 4 did.
Driving the real path found **a second door run 4 could not have seen**, and it makes the blast
radius larger, not smaller.

Every claim below is MEASURED (command + real output) or UNVERIFIED. Every zero carries a positive
control naming the fields read.

---

## 0. APPARATUS

Two other lanes are live in this tree, so every probe runs against an **isolated snapshot of HEAD**
(`29d00d2`), never the shared worktree:

```
git archive HEAD apolaki/agent | tar -x -C <scratchpad>/snap
MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default -e PYTHONPATH=/app \
  -v "<scratchpad>/snap/apolaki/agent:/app" -v "<scratchpad>/probe:/probe" \
  -w /app apolaki-agent python /probe/p1_door.py
```

Probe `p1_door.py` drives the **whole shipped deterministic path**, nothing simulated:

```
live page -> tools.ToolRegistry.execute("http_probe")   real crawl, real csrf_tool.parse_forms
          -> agent.BBHAgent._seed_and_project_graph     real graph projection
          -> agent.BBHAgent._graph_primary_state        real planner world-state (roots/urls/recon)
          -> planner.next_batch, DRAINED to fixpoint    real planner
          -> tools.ToolRegistry.execute(<engine>)       real engines, real mission session
```

Fields and attributes read, so a later reader can tell the instrument from the code:
`tools.ToolRegistry.urls / .session_kill_urls / .recon["forms"] / .session_headers / ._sessions /
.graph`; `tools._SESSION_KILL_RE`; `agent.BBHAgent._project_form_params / ._forms_from_graph /
._graph_primary_state / ._graph_action_steps / ._execute_plan`; `planner.next_batch` and each step's
`["tool"] / ["input"]["url"] / ["key"]`; `asset_graph.AssetGraph.nodes("endpoint") / .params_at("body")`.

**INSTRUMENT ERROR, recorded because it would have produced a confident zero.** My first run of
section 2 reported `total steps=28, AT KILL URL=0` — the defect apparently absent. It was the
instrument: `next_batch` returns the **earliest incomplete phase**, so one call returns phase A
(passive recon) and nothing else. The form-driven steps live in phase E and are unreachable until
every earlier phase is marked `done`. The shipped executor marks each dispatched step done and
re-plans, so the probe now DRAINS the planner the same way (`drain()`, fixpoint or 40 rounds). A
single `next_batch` call is not a measurement of what a mission schedules, and reading one is how
you measure zero form steps on a surface that has forms.

**FIXTURE, disclosed rather than dressed up.** No lab in this tree serves a POST logout form, so the
probe serves one page from its own process. Its two forms are the shape Django/Rails/Spring/Laravel
emit, and both `action`s point at the **running lab**:

```html
<form method="post" action="http://sessionlife:8080/secure/api/logout">
  <input type="hidden" name="csrfmiddlewaretoken" value="x">
<form method="post" action="http://sessionlife:8080/secure/api/change-password">
  <input type="hidden" name="csrfmiddlewaretoken" value="x">
  <input type="password" name="currentPassword"><input type="password" name="newPassword">
```

The page is the INPUT to the code under test. The behaviour under test — which container Apolaki
puts each action in, and which engines it then aims at them — is the shipped code's own answer. The
second form is the **mandatory negative control**: same page, same method, same field shape, not a
session-killer. A quarantine that swallows it has traded a false negative for a capability loss.

---

## 1. BEFORE — the ticket reproduced, and then exceeded

### 1a. Positive control: the instrument can see a session die at all

```
  fresh session /api/me                : (200, True)
  after a plain GET of /api/logout     : (401, False)
  a DIFFERENT fresh session, untouched : (200, True)      <- kills are not ambient
  NEGATIVE CONTROL, invented cookie    : (401, False)     <- 200 is not free
```

### 1b. The crawl: one URL, two containers, two contradictory policies

```
  http_probe ok                        : True
  tools.recon['forms']                 : [{"action": ".../secure/api/logout", "method": "POST",
                                           "fields": ["csrfmiddlewaretoken"]},
                                          {"action": ".../secure/api/change-password", ...}]
  kill url in tools.urls               : False   <- _add_urls quarantined it, correctly
  kill url in tools.session_kill_urls  : True    <- ...into the quarantine list
  kill url in recon['forms'] actions   : True    <- THE SECOND DOOR, same response body
  POSITIVE CONTROL ordinary form there : True    <- the instrument reads a populated list
```

### 1c. The planner, DRAINED, on the graph-derived state the shipped executor builds

```
mode=full    total steps=113   AT KILL URL=6   AT ORDINARY FORM=6
      http_probe  http_probe  run_csrf  run_form_cmdi  run_race  run_stored_xss
mode=active  total steps=103   AT KILL URL=3   AT ORDINARY FORM=3
      http_probe  http_probe  run_csrf
mode=passive total steps=29    AT KILL URL=0   AT ORDINARY FORM=0
```

**Six engines at `full`, three at `active`, and `active` is the DEFAULT scan mode.** `passive` is
clean, and that is a real bound rather than a hope: every engine on the list is ACTIVE or INTRUSIVE.

### 1d. THE SECOND DOOR — `recon["forms"]` is not the only one, and it is in `agent.py`

Emptying `recon["forms"]` and changing nothing else — run 4's positive control — does **not** clear
the kill URL:

```
mode=full    forms=[]  total steps=109  at kill url=4  at ordinary form=4
      RESIDUAL http_probe       <- NOT via recon['forms']
      RESIDUAL http_probe       <- NOT via recon['forms']
      RESIDUAL run_form_cmdi    <- NOT via recon['forms']
      RESIDUAL run_upload_test  <- NOT via recon['forms']
mode=active  forms=[]  total steps=101  at kill url=2  at ordinary form=2
mode=passive forms=[]  total steps=29   at kill url=0  at ordinary form=0

      kill url in tools.urls (quarantined) : False
      kill url in state['urls'] (planner)  : True     <- the quarantine, overruled
      graph endpoint nodes : ["127.0.0.1:9111/", "http://127.0.0.1:9111/",
                              "sessionlife:8080/secure/api/change-password",
                              "sessionlife:8080/secure/api/logout"]   <- minted from the form action
```

The chain, all of it in files this lane owns:

| step | code | what it does |
|---|---|---|
| 1 | `tools._add_urls` | quarantines the logout URL **out of** `tools.urls`, into `session_kill_urls` |
| 2 | `tools._http_probe` | appends the same URL to `recon["forms"]`, filtered on `scope.validate` alone |
| 3 | `agent._project_form_params` | `g.observe("endpoint", "sessionlife:8080/secure/api/logout")` — the form action becomes a graph **endpoint node** |
| 4 | `agent._graph_primary_state` | turns **every** endpoint node into a planner URL -> `state["urls"]` |
| 5 | `agent._forms_from_graph` | rebuilds `recon["forms"]` from the graph's body params -> the form door |
| 6 | `planner.next_batch` | 6 steps at `full`, 3 at `active` |

So the quarantine is not bypassed by an unknown URL and it is not overruled by one container. It is
overruled by **two**, and the second one (`state["urls"]`) re-admits the URL to *every* URL-driven
engine the planner has, not to the four the form loop names. Run 4 could not see this because it
hand-fed `recon["forms"]` into a state whose `urls` it had built by hand.

### 1e. The census: every one of the six kills the session, with the paired control

Each engine gets a **freshly minted** session (real register + real login on the lab), so no
engine's kill can be attributed to another.

```
mount /secure  (logout_invalidates=True)      <- the behaviour of any correct application
      http_probe       before=(200, True)   after=(401, False)  success=True   KILLED=True
      run_csrf         before=(200, True)   after=(401, False)  success=True   KILLED=True
      run_race         before=(200, True)   after=(401, False)  success=True   KILLED=True
      run_form_cmdi    before=(200, True)   after=(401, False)  success=True   KILLED=True
      run_stored_xss   before=(200, True)   after=(401, False)  success=True   KILLED=True
      run_upload_test  before=(200, True)   after=(401, False)  success=True   KILLED=True
      -> 6/6 killed

mount /vuln  (logout_invalidates=False, ONE variable changed)
      all six           before=(200, True)   after=(200, True)   success=True   KILLED=False
      -> 0/6 killed

NEGATIVE CONTROL — the same six engines on the ORDINARY form (/api/change-password)
      all six           before=(200, True)   after=(200, True)   success=True   KILLED=False
      -> 0/6 killed
```

**6/6 against 0/6 against 0/6.** The paired mount makes it cause rather than correlation; the
ordinary form makes it the ACTION rather than the engine making a request. Every one of the six
reported `success=True`.

**`http_probe` is the sharpest entry on that list.** It is the crawler. It needs no payload, no
form, no POST and no injection surface — it destroys the mission session by *fetching a URL the
crawl discovered*, and the URL that `_add_urls` had already quarantined for exactly that reason.

---

## 2. THE FIX — applied at the two structural chokepoints

See sections 3-4 for the after-measurement. Code:

* `planner.py` — `is_session_kill_url()` + `_session_kill_target()`, applied inside `fresh()`, the
  ONE function every planner-emitted batch passes through. This closes both doors at once, because
  it filters on the step's TARGET rather than on the state field that produced it.
* `agent.py` — `_graph_primary_state` and `_forms_from_graph` no longer hand the planner a URL the
  registry quarantined (the state stops contradicting itself), and `_execute_plan` gained
  `_reject_session_kill_step`, an ingress guard that records the refusal — the door
  `_graph_action_steps` uses never passes through `planner.fresh()`.

The regex is **imported, never restated**. `tools._SESSION_KILL_RE` stays the single definition; a
second copy of the rule is how one URL came to sit under two policies in the first place.

`run_session_lifecycle` is explicitly ENTITLED to a quarantined URL (it mints a sacrificial session
and `tools._session_kill_is_safe` re-checks that as a fact). The entitlement is a named set, not an
accident of the guard's placement.
