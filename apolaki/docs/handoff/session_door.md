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

## 2. THE FIX — one predicate, applied wherever surface becomes a request

`planner.is_session_kill_url()` / `planner.session_kill_target()` are the single predicate.
`tools._SESSION_KILL_RE` remains the single definition of the RULE and is **imported, never
restated** — a second copy is how one URL came to sit under two policies in the first place, and
`test_the_rule_has_ONE_definition` fails if anyone inlines a pattern.

| # | door | code | guard |
|---|---|---|---|
| 1 | `recon["forms"]` -> planner form loops | `planner.fresh()` | refuse the step |
| 2 | `state["urls"]` <- graph endpoint nodes | `agent._graph_primary_state` | not promoted to probe surface; `_swallow`-recorded |
| 2b | the form door's own rebuild | `agent._forms_from_graph` | action dropped |
| 3 | graph-directed steps (`_graph_action_steps`) | `agent._reject_session_kill_step` | executor ingress, `_swallow`-recorded |
| 4 | code-intel routes appended past `_add_urls` | `agent._recon_code_intelligence` | not appended; `_swallow`-recorded |
| 5 | the planner-INDEPENDENT injection sweep | `agent.sweep_targets` | not swept |

Doors 4 and 5 are the anti-idle sweep and they are covered in section 5 — door 5 was live and
measured, door 4 is a structural bypass I could not get a real target to exercise.

`planner.fresh()` filters on the step's **TARGET**, not on the state field that produced it. That is
the whole design: it is why one predicate closes doors 1 and 2 together, and why the engine added
next year inherits the guard instead of needing to be remembered.

`run_session_lifecycle` is explicitly ENTITLED (`planner._SESSION_KILL_ENTITLED`). It mints a
sacrificial account and `tools._session_kill_is_safe` re-checks, as a fact, that the credential it
destroys is disjoint from every live session. Blocking it would replace a false negative with a lost
vulnerability class (CWE-613), so the entitlement is NAMED rather than left to the accident that the
planner does not currently schedule it.

**Quarantine, not deletion** — the distinction `tools._add_urls` already makes. The logout endpoint
stays a node in the mission graph and stays in `tools.session_kill_urls`. Only its promotion to
PROBE SURFACE is refused.

---

## 3. AFTER — the same probe, the same lab, the same pairing

Same `p1_door.py`, run against HEAD + my two files, `tools.py` byte-identical to the snapshot
(verified by md5 before the run).

```
                                  BEFORE            AFTER
steps AT THE LOGOUT URL   full      6                 0
                          active    3                 0     <- the DEFAULT mode
                          passive   0                 0
steps at the ORDINARY form full     6                 6     <- NEGATIVE CONTROL, unchanged
                          active    3                 3
total plan size           full    113               107     <- exactly the 6, nothing else
                          active  103               100     <- exactly the 3
                          passive  29                29
forms-door EMPTIED,
residual at the kill url  full      4                 0     <- door 2, invisible to run 4
                          active    2                 0
kill url in tools.urls            False             False
kill url in state['urls']          True             False   <- the state stops contradicting itself
```

### 3a. The mission-level question, driven (`p2_drive.py`, both trees)

Not "does the planner emit fewer steps". **After Apolaki executes the steps its own planner
scheduled against a discovered logout form, is the mission session still alive?** The session is
minted AFTER planning, so it cannot influence the plan.

```
SECTION A -- mount /secure (logout_invalidates=True), i.e. any correct application
  BEFORE  mode=full    steps=6  before=(200,True)  after=(401,False)  SESSION ALIVE=False
          executed: http_probe, http_probe, run_csrf, run_form_cmdi, run_race, run_stored_xss
  BEFORE  mode=active  steps=3  before=(200,True)  after=(401,False)  SESSION ALIVE=False
          executed: http_probe, http_probe, run_csrf
  AFTER   mode=full    steps=0                     after=(200,True)   SESSION ALIVE=True
  AFTER   mode=active  steps=0                     after=(200,True)   SESSION ALIVE=True

SECTION B -- MANDATORY NEGATIVE CONTROL, the identical procedure on the ORDINARY form
  BEFORE  mode=full    steps=6  after=(200,True)   SESSION ALIVE=True
  AFTER   mode=full    steps=6  after=(200,True)   SESSION ALIVE=True   <- 6 steps, still executed
          executed: http_probe, http_probe, run_csrf, run_form_cmdi, run_race, run_stored_xss
  AFTER   mode=active  steps=3  after=(200,True)   SESSION ALIVE=True
```

The capability is intact to the step. Not "the ordinary form still gets some steps" — it gets the
**same six**, and `test_the_rest_of_the_plan_is_untouched` asserts the whole plan is step-for-step
identical to one built on a surface where the logout form was never discovered.

### 3b. The ingress guard, and the refusal actually recorded

```
  _reject_session_kill_step exists            : True
  graph-directed step at the LOGOUT url       : True    <- refused
  POSITIVE CONTROL, ordinary url              : False   <- allowed
  ENTITLED engine (run_session_lifecycle)     : False   <- allowed
  and the refusal is RECORDED, not silent     : 1 row(s) in tools.swallowed
      where  = execute_plan.session_kill_step:http_probe
      target = http://sessionlife:8080/secure/api/logout
      error  = ValueError: planner step 'http_probe' targets the session-destroying URL ...
```

I claimed "recorded" once before verifying it and my first probe read the wrong field, printing
`[]`. `_swallow` writes to `tools.swallowed`, not to `recon`. The row above is the corrected read.

### 3c. The asset survives the quarantine

```
  logout endpoint node still in the graph     : True    <- the world model keeps it
  logout url in tools.session_kill_urls       : True    <- run_session_lifecycle still finds it
  logout url in the planner's state['urls']   : False
```

---

## 4. TESTS — `agent/tests/test_session_kill_door.py`, 17 tests

Every fixture pasted verbatim from the driven run (`_MEASURED_FORMS`, `_MEASURED_URLS`,
`_MEASURED_BASES`, `_MEASURED_ENDPOINT_KEYS`, `_MEASURED_BODY_PARAMS`).

**They fail on the unfixed tree: 12 of the first 14.** The 2 that pass on BOTH trees are
`test_the_ordinary_form_is_still_probed_by_every_engine` and
`test_the_world_model_still_holds_the_logout_endpoint` — the capability-preservation controls, which
are supposed to pass before and after. That is what they are for: they encode what must NOT change.

The test module carries the same instrument warning the probe does. `_drain()` exists because
`next_batch` returns only the earliest incomplete phase, and a test that read one batch would assert
"no steps at the logout URL" against a plan that had not reached phase E — green, vacuous, and
indistinguishable from a fix.

---

## 5. ANTI-IDLE SWEEP — other doors of the same shape

The question asked of every path: *does discovered surface reach a request from here without passing
the quarantine `_add_urls` applies?*

### Door 5 — `agent.sweep_targets`, LIVE and now closed (`agent.py:331`, call site `agent.py:3727`)

The deterministic injection sweep, which the code itself calls **planner-independent** — so neither
`planner.fresh()` nor the executor ingress guard reaches it. It dispatches `run_path_sqli`,
`run_encoded_cookie`, `run_xss`, `run_dom_trace` and `run_default_creds` through `_run_tool`, all
carrying `session_headers`.

Its docstring says a form contributes its `page` and **not** its `action`. That is not what happens:

```
  form keys the shipped crawl actually produces : ['action', 'fields', 'method']
  ...so `fm.get('page') or fm.get('action')` falls back to the ACTION every time
  BEFORE  sweep targets : [".../secure/api/logout", ".../secure/api/change-password"]
          KILL url is a sweep target : True
  AFTER   sweep targets : [".../secure/api/change-password"]
          KILL url is a sweep target : False
          POSITIVE CONTROL ordinary form is a target : True   (unchanged)
```

A comment describing a safety property the code does not have is worse than no comment, because it
is what stops the next reader from checking. Also guarded: the separate branch that replays the
page's query against the ACTION, which the `page` guard does not cover.

### Door 4 — `agent._recon_code_intelligence` (`agent.py:1245`), structural, guarded anyway

`self.tools.urls.append(u)`. `_add_urls` is the **only** writer to that list inside `tools.py`
(MEASURED: one `self.urls.append` in 10,558 lines, and no assignment to `.urls` anywhere in
`agent/*.py`), which is what lets ~10 other call sites treat it as quarantine-clean. This line
appends past it.

**MEASURED: the bypass is structural — there is no filter on that path. UNVERIFIED that a real
target yields a session-killing route.** Driving the real `codeintel.harvest`:

```
  http://juice-shop:3000    endpoints=21  routes=53  SESSION-KILL among endpoints=0 routes=0
  http://sessionlife:8080   endpoints=0   routes=0   SESSION-KILL among endpoints=0 routes=0
```

That is a **weak negative and it is reported as one**: juice-shop's logout is client-side, and
`harvest` mines "client routes (including unlinked/sensitive ones)" from SPA bundles, where a
`/logout` route is unremarkable. Guarded regardless — the invariant is what the other readers depend
on, and restoring it costs one comparison.

### Checked and CLEAN, with the reason

* **~10 direct `self.tools.urls` readers** in `agent.py` (lines 1392, 1640, 1903, 1937, 1956, 2190,
  2583, 2603, 3028, 3161, 3671, 3696, 3739, 3781, 3863). Safe **by the invariant above**, not by
  their own checking — which is exactly why door 4 was worth closing rather than arguing about.
* **`agent._project_form_params`** — writes the graph, not the probe surface. The node is *supposed*
  to exist (see "quarantine, not deletion"). The promotion is what is guarded, one level down.
* **`planner`'s `run_session_lifecycle`** — never scheduled by the planner today; entitled anyway.
* **`passive` mode** — 0 steps at the kill URL before the fix as well. Not luck: every engine on the
  6-wide list is ACTIVE or INTRUSIVE, so `_ALLOWED` already excluded them.

### NOT swept — say so rather than imply coverage

* The **agentic (ReAct) path**. `_run_tool` is its dispatcher and I did not add a guard there. A
  model that asks for `http_probe` on a logout URL is not covered by any of the six doors above.
  `_run_tool` is in `agent.py` (mine), so this is a choice, not a blocker: the ingress guard belongs
  at `_run_tool` to cover both executors, but every `_exec_internal` caller shares that layer and
  `run_session_lifecycle` reaches the target through it, so the change needs its own measurement of
  the internal-phase dispatches before it is safe. Ticket text in section 6.
* **`browser_engine` / BIE crawl frontier** (`agent.py:3595-3628`) — it re-enters through
  `tools._add_urls`, so it is quarantined by construction, but I did not DRIVE that claim.
