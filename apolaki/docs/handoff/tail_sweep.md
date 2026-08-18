# Tail sweep - the unswept tail of docs/QUEUE.md, verified against CODE

Lane: tail-sweep (Breaker shape, READ-ONLY on product code). Started 2026-08-17.
Scope: every ticket below the engineering backlog whose marker predates several closes.
Rule for this file: a row is written only after its measurement exists. `in progress` is a state,
not a verdict. Every claim is MEASURED (command + real output) or UNVERIFIED.

Proposed QUEUE.md edits live at the bottom. This lane does not touch QUEUE.md.

---

## 0. THE APPARATUS - read this before trusting any number below

Three instrument facts were measured first, because two of them would have silently corrupted
every later result.

### 0.1 The container is NOT at HEAD. Three versions of the code are in play.

MEASURED - md5 of the same file in three places (`git show HEAD:...`, `docker exec ... md5sum`,
local worktree), at HEAD `b242405`:

```
tools.py                   HEAD=63e32362 IMAGE=eab17583 WORKTREE=ad1364ed   IMAGE != HEAD
agent.py                   HEAD=25b83498 IMAGE=c8b8b591 WORKTREE=3f17836b   IMAGE != HEAD
report.py                  HEAD=6d373c06 IMAGE=d87760a0 WORKTREE=6d373c06   IMAGE != HEAD
db.py                      HEAD=a673518b IMAGE=d641cb47 WORKTREE=d641cb47   IMAGE != HEAD
zap_client.py              HEAD=6ca73764 IMAGE=1d62d53c WORKTREE=1d62d53c   IMAGE != HEAD
main.py                    HEAD=4d50eb1e IMAGE=74634322 WORKTREE=c7304e33   IMAGE != HEAD
planner.py                 HEAD=bf5d640c IMAGE=dc296fee WORKTREE=dc296fee   IMAGE != HEAD
ws_tool.py                 HEAD=2fef0a04 IMAGE=2fef0a04 WORKTREE=2fef0a04   (equal)
session_lifecycle_tool.py  HEAD=bbf3b5cd IMAGE=bbf3b5cd WORKTREE=bbf3b5cd   (equal)
techniques.py              HEAD=ca233e1c IMAGE=ca233e1c WORKTREE=ca233e1c   (equal)
bie.py                     HEAD=1388e9e2 IMAGE=1388e9e2 WORKTREE=1388e9e2   (equal)
```

Consequence, applied throughout this file: **"does the code do X" is answered from the
worktree/HEAD source; "what happened in a mission" is answered from the container DB** (the DB is
the object of study there, so the image version is irrelevant). Where a live probe runs inside the
container, the file it exercised is named and its IMAGE hash is stated.

This is Q-059's shape recurring. Q-059 is marked CLOSED with "rebuilt and verified 2026-08-17";
the rebuild is real (image `tools.py` is dated Aug 17 04:15) but commits have landed since, so the
gate does not hold the invariant continuously. Not re-opened here - noted for the Coordinator.

### 0.2 Git Bash mangles container paths. My first container probes returned empty, not zero.

MEASURED - `docker exec apolaki-agent-1 md5sum /app/tools.py` returns
`md5sum: 'C:/Program Files/Git/app/tools.py': No such file or directory`. MSYS rewrites a
leading-slash argument into a Windows path. The error goes to stderr and captured stdout is
**empty**, so a command substitution yields the empty string and a naive comparison reports
"differs" for every file. Every container command in this file is prefixed
`export MSYS_NO_PATHCONV=1`.

### 0.3 `docker exec -i` inside a shell loop eats the loop's stdin.

MEASURED - the same md5 loop with `-i` produced one result and then blank rows. `-i` is dropped
from every non-interactive probe here.

### 0.4 The dispatch instrument, and its known blind spot

All "did this engine ever run" numbers come from one query:

```
select mission_id, data from logs where etype='tool_call'   ->  json['tool']
```

MEASURED: **29,944 tool_call rows, 153 missions, 71 distinct tool names.**
The `via` field is present on only 59 of 29,944 rows (`via: internal`); the other 29,885 carry no
`via`. That 59 is the Q-061 fix (`_exec_internal` now logs) and it dates from this week, so
**pre-Q-061 internally dispatched calls are invisible to this instrument, and every zero below is
an upper bound on absence rather than a proof of it.** Where that mattered (Q-023) an independent
instrument was used and is named.

POSITIVE CONTROL for the histogram: it resolves single dispatches - `run_session_lifecycle` = 1
call in 1 mission, `browser_navigate` = 1, `run_race` = 2. An engine that ran once is visible, so
a count of 0 is not the apparatus failing to look.

---

## VERDICTS

### Q-001 - session lifecycle invalidation (CWE-613) - CLOSED (engine), with one unshipped dependency

MEASURED, source:

- `agent/session_lifecycle_tool.py` exists (26,154 bytes) and emits three findings keyed
  `WSTG-SESS-06` (line 379), `WSTG-SESS-11` (line 403), `WSTG-SESS-07` (line 428), family
  `session_lifecycle`, `cwe: CWE-613` - the exact three sub-tests the ticket asked for.
- Registered: `tools.py:210  "run_session_lifecycle": PermissionLevel.ACTIVE`.
- Dispatchable: `ToolRegistry._run_session_lifecycle` exists (`tools.py:9080`).
- Wired into the artery, not left an island: `agent.py:1447` (comment: third leg, runs last on
  purpose), `agent.py:1453` `sevents = await self._do_session_lifecycle(session_id)`, and
  `agent.py:1995` `self._exec_internal("run_session_lifecycle", ...)`.
- Preconditions declared: `engine_descriptor.py:102`
  `"session_lifecycle": ["has_login", "authenticated"]`.
- Technique record: `techniques.py:143` `_t(id="session_lifecycle", cwe="CWE-613",
  wstg="WSTG-SESS-06", permission=ACTIVE, transferable=True, validated_on=["sessionlife"])`.
- The ticket's stated root cause is addressed in place: `tools.py:3467` QUARANTINES the
  session-killing endpoint into a list only `_run_session_lifecycle` reads, instead of refusing to
  admit it to the surface at all.
- Sacrificial persona exists: `personas.py:32`.
- Tests: `agent/tests/test_session_lifecycle.py`, including a positive/negative lab pair driven
  through `tr._run_session_lifecycle` (lines 365, 394, 402).

MEASURED, live - it has actually executed. Exact DB record:

```
mission 57cc3b49  {'tool': 'run_session_lifecycle',
                   'input': {'base_url': 'http://juice-shop:3000',
                             'register_urls': [10 urls], 'login_urls': [10 urls]},
                   'permission': 'active', 'via': 'internal'}
```

1 dispatch, 1 mission ("Q-051 arsenal-gap run2", 2026-08-17T09:34Z), through the real artery on a
real target, not a test.

Not advertised in `CLAUDE_TOOLS` (76 advertised names; `run_session_lifecycle` is not one). That
is consistent with its dispatch path - it is an artery leg reached by `_exec_internal`, not a
model-selected tool - so it is not the `run_external_surface` island shape. Recorded, not raised.

**Residual, and it needs a decision rather than more measurement.** The paired validation lab this
technique names is not in the repository:

```
git ls-files apolaki/labs/sessionlife   ->  0 files
git status --porcelain                  ->  ?? apolaki/labs/sessionlife/
                                            M  apolaki/docker-compose.yml   (+20 lines)
grep -n sessionlife docker-compose.yml  ->  lines 225,233,234,240 (service `sessionlife`)
docker ps                               ->  apolaki-sessionlife-1   Up 4 days
```

`techniques.py` at HEAD carries `validated_on=["sessionlife"]` pointing at a lab that exists only
in one working tree and one running container. `agent/tests/test_validated_on.py:156` already says
so in its own text ("sessionlife has no compose service and no tracked source at HEAD"). The claim
was true when made and is unreproducible by anyone else.

**DECISION WANTED: commit `labs/sessionlife/` plus the docker-compose service, or drop
`sessionlife` from `validated_on`.** This lane owns neither file and did not touch them.

### Q-002 - WebSocket CSWSH + WS-frame injection - HALF CLOSED, needs a scope decision

**Half A, CSWSH: CLOSED.** MEASURED:

- `agent/ws_tool.py` exists (26,447 bytes), docstring `Cross-Site WebSocket Hijacking --
  CWE-1385 / CWE-346, WSTG-CLNT-10`.
- Registered `tools.py:203 "run_ws_hijack": PermissionLevel.ACTIVE`; method `_run_ws_hijack` at
  `tools.py:8568`; socket work in `_ws_handshake` at `tools.py:8501`.
- ADVERTISED: `tools.py:617 {"name": "run_ws_hijack", ...}` is in `CLAUDE_TOOLS`.
  Registry probe over the three surfaces: `advertised=True perm=True method=True`.
  POSITIVE CONTROL `run_mass_assign` = True/True/True; NEGATIVE CONTROL `run_nonexistent_zzz` =
  False/False/False.
- The ticket's oracle is implemented as specified, not approximated. `handshake_accepted` computes
  `base64(sha1(key + GUID))` from the key WE sent (RFC 6455), and `evaluate` requires the
  handshake AND an authenticated marker in the pushed frame AND the cookie-stripped control NOT
  carrying that marker (`tools.py:8626` authed leg, `:8634` control leg, `:8645` verdict). The
  negative control the ticket demanded is in the execution path, not only in a test.

**Half B, WS-frame injection: NOT BUILT.** MEASURED - `grep -rn "frame_inject|ws.*inject"
--include=*.py agent/` returns zero hits in `ws_tool.py` or `tools.py`; the only matches are
unrelated (`dom_tool`, `mass_assign_tool`, `css_injection_tool`). The ticket's second half ("frame
injection then reuses the unchanged sqli/xss analyzers over a different transport") has no
implementation.

**Dispatches: 0 in 29,944 tool_calls - and that is NOT evidence of an island.** `run_ws_hijack`
landed 2026-08-15 (`dcd70ab`) and **only 2 of 153 missions have run since 2026-08-11** (both on
2026-08-17, the Q-051 lane). The engine has had essentially no opportunity. Its absence from the
always-on sweep is deliberate and documented in place at `tools.py:584-589`: advertised, but kept
out of the deterministic sweep because "putting a brand-new confirming engine into every mission's
always-on path is the move that produced a measured false positive this week (Q-047)".

**Real gap found:** `grep -n "cswsh|ws_hijack" techniques.py engine_descriptor.py planner.py
agent.py` returns **nothing**. There is no technique record and no `PRECONDITIONS` entry for
CSWSH, so it cannot appear in technique coverage and cannot be routed by
`engine_descriptor.routes()`. WSTG-CLNT-10 has a title in `wstg_catalog.py:39` and no technique
behind it.

**DECISION WANTED: split into Q-002A (CSWSH - close it) and Q-002B (WS-frame injection - still
open, and worth asking whether it is wanted at all), and add the missing technique record so the
shipped CSWSH engine is visible to coverage.**

### Q-023 - ZAP has never executed in any mission - FACT CONFIRMED, ticket's EXPLANATION DISPROVED

**Fact, MEASURED:** `run_zap` appears **0 times in 29,944 tool_call rows across 153 missions**.
`run_zap` is the only ZAP name in the registry (probe over
`CLAUDE_TOOLS | TOOL_PERMISSIONS | _run_* methods`: zap-ish names = `['run_zap']`), so this is not
a name mismatch of the Q-064 shape.

**The tool_call instrument alone could not settle this** - see 0.4, internal dispatch was unlogged
before Q-061. So an independent instrument was used: **the ZAP daemon itself.**

```
docker logs apolaki-zap-1 | tail
  ... Spider - Starting spidering scan on Context: bbh-c2f8a55c-9185 at 2026-08-14T10:55:55
  ... spiderAjax.SpiderThread - Running Crawljax (with firefox-headless): API - Context: bbh-...
  ... API - API key incorrect or not supplied: null in request from 172.22.0.8

ZAP API (with apikey), from inside apolaki-agent-1:
  version           {"version":"2.17.0"}
  sites             ["http://apolaki-zap-lane7-live:42888","http://domsource:8080"]
  numberOfMessages  447
  numberOfAlerts    191
  contextList       16 contexts: bbh-lane7-live-468e, bbh-zap-rate-live-{a716,ae3d,7a86,8f16,
                    ce56,7188,a40d,4983,1bd7,97f8,9d79}, bbh-05a27c3d-fb00, bbh-628976e3-a28c,
                    bbh-c2f8a55c-9185, bbh-49d413bb-5066
```

POSITIVE CONTROL for that probe: the first attempt returned `RemoteDisconnected`, and the ZAP log
line `API key incorrect or not supplied: null in request from 172.22.0.8` is that same request.
The channel was proven live, and proven to be the thing I was talking to, before any conclusion
was drawn from it.

So **ZAP has been driven by Apolaki's own client - 447 messages, 191 alerts, 16 Apolaki-named
contexts - just never from a mission.** None of the `bbh-<8hex>-<4hex>` context ids resolve to a
row in `missions` (`select ... where id like 'c2f8a55c%'` -> `[]`, same for `49d413bb`), and no
mission exists between 2026-08-12 and 2026-08-17, so those were lane test harnesses.

**Why, measured - and it is not "three flags".**

1. **The wiring works today.** Live A/B of the real planner inside the container
   (`/app/planner.py`, IMAGE hash `dc296fee`), driving `next_batch` to exhaustion with `done`
   accumulated, identical state except `zap`:

   ```
   phases exhausted.  zap=True steps: 62   zap=False steps: 61
   difference (True - False): ['run_zap']
   POSITIVE CONTROL - distinct tools with zap=False: 36
   ```

   The difference is **exactly `{run_zap}`**. `planner.py:674-679` is phase F2 and schedules it.
   `zap_client.configured()` -> `True`; `ZAP_ADDR=http://zap:8090` is in the agent env
   (`docker-compose.yml:39`).

   INSTRUMENT NOTE: my first A/B returned "no difference". That was my error, not a finding.
   `next_batch` returns only the earliest incomplete phase, so a single call can never reach
   phase F2 - and I had also passed `bases` as a list where the planner reads it as a dict
   (`state.get("bases") or {}`). Corrected before anything was concluded from it.

2. **Almost nothing ever asked for ZAP.** Over all 153 missions: `enable_zap=True` in **4**;
   `mode='full'` in 62; **both in 4**. Mode split: active 83, passive 8, full 62.

3. **Those 4 missions never reached the phase ZAP lives in.** All four ran on **2026-07-26**
   (`c7bfe8e8`, `ce35b361` on ginandjuice.shop; `6771ec21`, `94e8b564` FULLBLOWN), all
   `thorough_active`. In each of them `run_nuclei` was dispatched **0 times** - and nuclei is
   phase F, immediately BEFORE zap's phase F2. POSITIVE CONTROL: `run_nuclei` = **254 calls across
   123 missions** overall, so nuclei is not invisible to the instrument; those four missions
   specifically stopped short of the late phases.

**Verdict: Q-023 should be REWRITTEN, not worked.** There is no wiring defect to fix. The honest
remaining item is a coverage gap - no mission has been run with `enable_zap=True` under the
current planner - and it is closed by running one, not by editing code.
