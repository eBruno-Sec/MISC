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

### Q-003 - postMessage as a DOM-XSS source (WSTG-CLNT-11) - OPEN, unchanged, nothing built

MEASURED:

```
grep -rn "postMessage|MessageEvent|onmessage" --include=*.py agent/     ->  0 hits
grep -rn "postMessage" --include=*.py --include=*.js --include=*.html . ->  0 hits (whole repo)
```

POSITIVE CONTROL that the grep was looking at the right file: the same search over `dom_tool.py`
for its existing sources returns `dom_tool.py:7  "(location.hash / a query param)"` - the two
sources the ticket says are the only ones. They still are.

Live registry probe: techniques mapped to `WSTG-CLNT-11` = `['jsonp_info_leak']`; no record
mentions postMessage anywhere in `id`, `summary` or `detect`.
POSITIVE CONTROL: techniques mapped to `WSTG-SESS-06` = `['session_lifecycle']`, so the same query
does resolve a mapping when one exists.

Live `wstg_catalog.coverage()`: `WSTG-CLNT-11 -> none (not yet implemented)`.

**Verdict: OPEN exactly as written.** The ticket analysis is still accurate; nothing has moved. It
remains the cheapest of the capability tickets - a new SOURCE for a working confirmation engine,
not a new engine.

### Q-004 - unrestricted resource consumption (CWE-770/799) - OPEN, with one partial the ticket did not know about

MEASURED, live registry: the only technique of 88 carrying CWE-770/799/400 is
**`graphql_batching_enabled` (CWE-770, vuln_class `misconfiguration`)** - `graphql_tool.py:254`
reports "Rate-limit bypass and brute-force amplification via batched operations".
POSITIVE CONTROL: techniques whose cwe contains 89 = `['sqli_auth_bypass', 'sqli_union_extract',
'sqli_structural']`, so the filter does resolve real records.

Live `wstg_catalog.coverage()`:

```
WSTG-BUSL-05 -> PARTIAL: run_race covers single-use/limit races
WSTG-BUSL-07 -> none (not yet implemented)
```

The ticket premise ("a whole OWASP API Top 10 slot with no engine") is **slightly overstated and
otherwise correct**: there is no amplification-multiplier engine, no `429`/`Retry-After`/
`X-RateLimit-*` observation engine, and no pagination-bound test. `race_tool.py` does have
`summarize`, `best_round`, `verify_delta`, `analyze_race` - the synchronized-parallel primitive and
status accounting the ticket credits it with - but nothing calls them for a limit question.

**Verdict: OPEN.** Amend the ticket to record the adjacent partial (`graphql_batching_enabled`,
batching amplification only) so the next lane does not rediscover it.

### Q-005 - server-side prototype pollution (CWE-1321) - OPEN, root cause still exactly true

MEASURED: every CWE-1321 site in the codebase is CLIENT-side.

```
dom_tool.py:226          prototype_pollution / CWE-1321 (browser gadget canary)
dom_tool.py:346          dom_xss / CWE-1321 (gadget -> dom-xss)
candidate_pipeline.py:60 "browser prototype-pollution canary (__proto__ write observed at runtime)"
codereview.py:83-86      comment says "client-side prototype pollution"; the rule is a source regex
asvs_model.py:227-229    engine ("run_dom_audit","run_js_review"), violated_by ("prototype_pollution",)
dependency_intel.py:933  family prototype_pollution from a DEPENDENCY advisory, not a live probe
```

Live registry: the single `prototype_pollution` technique (`techniques.py:772`) has
`validated_on=["ginandjuice"]` and `maps_to={"ginandjuice": ["Client-side prototype pollution
(DOM, query)"]}` - it names itself client-side in its own evidence map. No engine sends
`{"__proto__":{...}}` in a body and re-reads a subsequent response.

**Verdict: OPEN, unchanged.** One thing the next lane needs: the ticket already decided the hard
part - ship gated as `execution: "operator"`, because the blast radius is cross-user and persists
until restart. That decision collides with a measured fact recorded under Q-020: **all 88
techniques carry `execution: "auto"`; the field has exactly one value in the whole registry.** A
`operator` record would be the first ever, and that gate has never been exercised. Worth knowing
before the effort estimate is trusted.

### Q-006 - HTTP request smuggling / desync (CWE-444) - DECISION ALREADY MADE AND ENFORCED. Tier 1/2 unbuilt.

MEASURED - the refusal is not a marker, it is live code inside a tested structure:

```
wstg_catalog.py EXCLUDED["WSTG-INPV-15"] =
  "request SMUGGLING desync can affect OTHER users (no-collateral) - refused;
   CRLF/splitting via header_injection is covered"

live coverage():  WSTG-INPV-15 -> EXCLUDED
                  tally {'full': 60, 'partial': 25, 'none': 24, 'excluded': 5}, full_pct 55.0
```

The exclusion is counted deliberately (`tally['excluded']`), not lost in `none`.

MEASURED - Tier 1 and Tier 2 do not exist: no technique of 88 carries CWE-444 or "smuggl" in its id
or summary (`hits: []`). The only CWE-444 in the codebase is `cache_tool.py:67`, which self-labels
"CWE-444-adjacent: cache-key" - a different bug.

**Verdict: this is not a ready ticket, it is a STANDING DECISION plus an unstarted option.** Tier 3
is refused permanently and correctly, and the refusal is enforced where the coverage report can see
it. Tier 1 (hop-count / header-mutation differential) and Tier 2 (CL.TE timing differential) were
never begun.

**Recommend DELETE Q-006 and leave the refusal where it already lives.** If Tier 1/2 are ever
wanted they are a new ticket with a different premise. As written, most of the ticket re-decides
something the code already decided, and it carries the highest effort estimate of the six for a
detection-only capability.

### Q-007 - `weak_password_reset` phantom capability - OPEN, CONFIRMED, now UNBLOCKED

The 2026-08-10 pass recorded "MEASURED - true" and recommended STRIP-not-build, blocked on Q-001.
Q-001 has now shipped. **Nothing else has moved.** Re-measured live:

```
any engine name containing reset/password/passwd across
  CLAUDE_TOOLS | TOOL_PERMISSIONS | _run_* methods        ->  []
POSITIVE CONTROL, same probe, names containing "sqli"     ->  ['run_auth_sqli','run_form_nosqli',
                                                              'run_nosqli','run_path_sqli',
                                                              'run_sqli','run_sqli_structural']

engine_descriptor.PRECONDITIONS["weak_password_reset"] ->  ['has_login']            (still there)
engine_descriptor.EFFECTS["weak_password_reset"]       ->  {'establishes': ['authenticated'],
                                                           'invalidates': ['authenticated']}
EFFECTS entries total                                  ->  13
EFFECTS entries with a NON-EMPTY invalidates           ->  1   (that one)
```

**The consequence, measured rather than argued** - `engine_descriptor.conflicts()` returns:

```
[('weak_password_reset', 'authenticated', 'cache_deception'),
 ('weak_password_reset', 'authenticated', 'jwt_forge'),
 ('weak_password_reset', 'authenticated', 'jwt_key_confusion'),
 ('weak_password_reset', 'authenticated', 'session_fixation'),
 ('weak_password_reset', 'authenticated', 'session_lifecycle'),
 ('weak_password_reset', 'authenticated', 'weak_2fa_bypass')]
```

**6 of 6 conflict rows are produced by the one engine that does not exist.** The entire negative-
effects half of the planner model is generated by a phantom. Row 5 is the sharpest version of it:
the phantom is declared to invalidate the precondition of `session_lifecycle`, the engine that
actually does destroy sessions.

And `session_lifecycle` itself declares no effects at all:

```
engine_descriptor.PRECONDITIONS["session_lifecycle"] -> ['has_login', 'authenticated']
engine_descriptor.EFFECTS["session_lifecycle"]       -> ABSENT
```

So the re-homing recommended on 08-10 has not been done, and its dependency is now satisfied.

**One correction to that recommendation, MEASURED.** It said "set `solver_only=True` (the field
exists)". It does not:

```
"solver_only" in TECHNIQUES["weak_password_reset"]   ->  False
records anywhere carrying a solver_only key (of 88)  ->  []
```

The 25 field names on a technique record are: backfill_claim, cleanup, cwe, detect,
evidence_requirements, execution, exploit, fixture_source, id, maps_to, mitre, needs_fixture,
negative_control, oracle, owasp, pack, permission, refs, replayable, safety, summary, transferable,
validated_on, vuln_class, wstg. What the record DOES carry is `backfill_claim: ['juiceshop']`,
`validated_on: []` and `execution: 'auto'` - the registry already marks the lab claim as a backfill
and the validation list as empty, so the honest signal exists under a different name.

**Verdict: OPEN, high value, and the smallest change on this list.** Three edits, no new engine:
drop `weak_password_reset` from `PRECONDITIONS` and `EFFECTS`; add
`"session_lifecycle": {"establishes": [], "invalidates": ["authenticated"]}` to `EFFECTS`; keep the
phantom out of `conflicts()`. The negative-effects model then rests on a technique with a real,
dispatched executor.

WARNING for whoever takes it: a test pinning `conflicts()` to a non-empty list passes before AND
after, so it certifies nothing. The guard has to assert that every id appearing in `conflicts()`
resolves to a dispatchable engine - otherwise the declaration-vs-fact trap applies to the fix
itself.

### Q-009 - "audit findings pending verification" - DELETE. It is a CONTAINER, fully re-homed.

Q-009 lists six sub-claims. All six were settled by the 2026-08-10 pass and each now has its own
ticket:

| Q-009 sub-claim | now | state |
|---|---|---|
| retest scope guard fails open | Q-018 | DISPROVED as a live defect |
| `PUT /findings` bypasses `findings_gate` | Q-013 | CLOSED `3addb1c` + `42e1544` |
| operator lead-confirmation immediately demoted | Q-014 | CLOSED `a1cdb8d` |
| `get_logs` oldest-first | Q-017 | see below |
| `risk_signals` unfiltered twin | Q-015 | see below |
| `_read_controls` returns `[]` on failure | Q-016 | see below |

**Verdict: DELETE Q-009.** It holds no content of its own. Leaving it is exactly the queue rot the
header warns about: a reader who trusts it re-verifies six things that are already tracked, two of
which are closed.

### Q-015 - `risk_signals` is the unfiltered twin of `risk_score` - CLOSED, and the fix passes the ticket's own oracle

MEASURED, source (`agent/report.py`, WORKTREE == HEAD `6d373c06`): `risk_signals` at line 1413 now
computes `confirmed = [f for f in findings if _confirmed(f)]` and reports
`f"{len(confirmed)} confirmed finding(s), severity-weighted"`. It uses `_confirmed`, the SAME
shared predicate `risk_score` uses at line 1386 - not a private fourth copy, which was the fix
contract. The comment above it names Q-015 and restates why.

MEASURED, live - the ticket's oracle, run verbatim (IMAGE `report.py` `d87760a0`, so source and
running image were checked independently and agree):

```
DEMOTED (proof gate rejected, demote_unproven left the row in the list)
   risk_score      -> {'score': 0, 'label': 'No Confirmed Risk'}
   risk_signals[0] -> {'label': 'Confirmed vulnerability load', 'pct': 0,
                       'basis': '0 confirmed finding(s), severity-weighted'}

CONFIRMED (the ticket's NEGATIVE CONTROL - the fix must not have zeroed the signal)
   risk_score      -> {'score': 25, 'label': 'Medium'}
   risk_signals[0] -> {'label': 'Confirmed vulnerability load', 'pct': 25,
                       'basis': '1 confirmed finding(s), severity-weighted'}
```

The contradiction the ticket recorded (headline "No Confirmed Risk" beside "25% confirmed
vulnerability load, 1 confirmed finding") is gone, and the negative control still reads 25 in both.

**Verdict: CLOSED.** No commit hash is recorded on the ticket, which is why it still read
`proposed`.

### Q-016 - `bie._read_controls` returns `[]` on failure - CLOSED, including the distinction test

MEASURED, source (`agent/bie.py`, HEAD == IMAGE == WORKTREE `1388e9e2`):

- `_read_controls(page, errors=None)` at `bie.py:1487` now appends
  `"%s: %s" % (type(exc).__name__, str(exc)[:160])` to the caller's `errors` list before returning
  `[]`. It still never raises - the ticket asked for the failure to be RECORDED, not to abort.
- The failure reaches the output, so it is not swallowed one level up: `bie.py:1568`
  `ctl_errors = out.setdefault("control_read_errors", [])`, passed at `:1569` and `:1578`, and
  surfaced at `:1665-1666` as `out["control_surface"]["read_errors"]`.
- The docstring names Q-016 and states the consequence it existed to prevent.

MEASURED, test: `agent/tests/test_bie_control_read_is_not_silent.py` exists and is written against
**the distinction**, which is the part that makes it a real guard. It defines two fake pages -
`_Boom` (evaluate raises `RuntimeError("Execution context was destroyed")`) and `_Empty` (evaluate
returns `[]`) - so a fix that flagged both would fail it. That is the negative control the ticket
demanded, and it is in the test rather than only in prose.

**Verdict: CLOSED.** Again no hash on the ticket, hence the stale `proposed`.

### Q-017 - `get_logs` oldest-first with a LIMIT - HALF CLOSED. The logs half is fixed; the ungated-findings half is now MEASURED and still live.

**The logs half: CLOSED.** MEASURED, `agent/db.py:326-344`:

```sql
SELECT etype,data,created_at FROM (
  SELECT id,etype,data,created_at FROM logs WHERE mission_id=? ORDER BY id DESC LIMIT ?
) ORDER BY id
```

Inner `DESC LIMIT` keeps the NEWEST n, outer `ORDER BY id` restores chronological order, so every
existing caller sees the same shape and only WHICH rows survive truncation changed. The docstring
cites Q-017 and carries the original measurement (mission `54155d4b`, 1287 rows, 22:31:01 against a
true last event of 22:35:20). Both truncating call sites the ticket named are unchanged and now
benefit: `main.py:730` (`GET /missions/{session_id}`) and `main.py:3884` (`GET /backup/{session_id}`),
both `limit=500`.

**The half the ticket left UNVERIFIED is now MEASURED, and it is real.** `db.get_findings` is the
RAW accessor; its own docstring says "the proof gate has NOT been applied. Prefer
`get_findings_gated()` for anything a human or a model will read." In `main.py` there are **13 raw
call sites against 7 gated**. Four of the raw ones are unambiguously reader-facing (decorator within
ten lines of the call):

```
main.py:709   @app.get("/status/{session_id}")     "findings_count": len(db.get_findings(...))
main.py:728   @app.get("/missions/{session_id}")   "findings": db.get_findings(...)     <- the UI
main.py:3518  @app.get("/findings/{session_id}")   return {"findings": db.get_findings(...)}
main.py:3882  @app.get("/backup/{session_id}")     "findings": db.get_findings(...)     <- export
```

POSITIVE CONTROL that the distinction is honoured elsewhere in the same file: the retest handler at
`main.py:2981` uses `db.get_findings_gated(session_id)`. So this is inconsistency, not an absent
concept.

CAVEAT, stated because I will not overstate it: the remaining nine raw sites were NOT individually
attributed - a naive "nearest preceding decorator" scan mis-assigned at least one (line 1033 to a
handler 294 lines earlier), so only the four tight ones above are claimed. Several of the rest are
plausibly internal (dedupe at `:3306`, single-finding lookup at `:3648`) and would be correct as
raw reads.

**Verdict: SPLIT.** Close the logs half. The ungated-findings half deserves its own ticket -
`GET /findings/{sid}` returning gate-demoted rows unlabelled is the same class of defect as Q-015,
one layer out, and Q-015 is closed while this is not.

### Q-018 - retest scope guard - the DISPROVED half holds. The hardening half is UNCHANGED and reproduces.

MEASURED, source (`agent/main.py:2988-2999`) - the code is exactly as the ticket described, and the
fail-closed fix contract has NOT been applied:

```python
_eng = None
if _scoped:
    _eng = _scope.ScopeEngine()
    try:
        _eng.load_manual(_sc.get("bases") or _sc.get("in_scope") or [], ...)
    except Exception:
        _eng = None                              # <- fail OPEN
...
if _eng is not None and not _eng.validate(url)[0]:   # <- guard skipped entirely when _eng is None
```

MEASURED, live - the ticket's own oracle reproduced against the real `ScopeEngine`:

```
load_manual([{"nested":"dict"}], [], "Program")
  -> AttributeError: 'dict' object has no attribute 'strip'
  -> main.py:2998 sets _eng = None
  -> the guard `if _eng is not None and ...` is skipped: retest proceeds UNGUARDED

POSITIVE CONTROL, a normally built engine:
  validate("http://evil.example.com/x") -> (False, 'evil.example.com not in scope')
  validate("http://juice-shop:3000/x")  -> (True,  'In scope via juice-shop:3000')
```

The positive control matters here: it proves the engine really does refuse an out-of-scope host, so
"guard skipped" means an actual loss of protection and not a guard that was inert anyway.

The DISPROVED half stands - `in_scope` is a required field on `EngageRequest`, so the unscoped
branch is unreachable through the product, and the earlier replay found the guard active on 151 of
151 missions. The reachable-in-principle path is still the non-string element in
`scope["bases"]`/`["in_scope"]`.

**Verdict: OPEN as filed, LOW, hardening only.** The ticket is accurate and correctly de-escalated;
it simply has not been done. Its real value is the "do not re-raise this as CRITICAL" note at the
top, which is worth keeping in the queue verbatim.

### Q-019 - "2756 URLs discovered, 36 probed" - SUBSTANTIALLY CLOSED. Three of three root causes fixed, and the acceptance oracle is MIS-SPECIFIED.

**The duplicate first.** Q-019 appears twice: `docs/QUEUE.md:1346` (Rank 0, `CRITICAL`, `ready`,
"take this first") and `docs/QUEUE.md:1642` (Rank 3b, `proposed`). They are the SAME ticket - the
Rank 0 entry is a promotion header plus four refinements that points at "Full ticket below under
the Distillation pass". **Recommend: keep the Rank 0 entry, delete the Rank 3b copy.** Two states
for one ticket is the rot itself.

**Root cause 1 (hostless URLs poison the surface): FIXED.** MEASURED live against the real modules:

```
surface.clean_url("https:///benchmark/cmdi-Index.html")   -> False
scope.validate("https:///benchmark/cmdi-Index.html")      -> (False, 'Invalid target')
POSITIVE CONTROL clean_url("https://owaspbench:8443/benchmark/cmdi-Index.html") -> True
POSITIVE CONTROL validate ("https://owaspbench:8443/benchmark/cmdi-Index.html") -> (True, 'In scope via owaspbench:8443')
```

`tools._add_urls` (`tools.py:3477`) admits a URL only if BOTH pass, and `surface.py:42` / `:64`
reject `not p.netloc`. So a hostless URL cannot enter the surface, and the positive controls prove
the two gates still admit a good one.

**Root cause 2 (`limit` default of 20; candidates in discovery order): FIXED.** MEASURED, source:

```
agent.py:220   SWEEP_TARGET_CAP = max(1, int(os.getenv("BBH_SWEEP_TARGETS", "700") or 700))
agent.py:318   def sweep_targets(urls, forms, in_scope, limit: int = SWEEP_TARGET_CAP)
agent.py:3630  sweep_targets(..., limit=SWEEP_TARGET_CAP)     <- passed EXPLICITLY
```

The call site comment names Q-019 and states why the budget is passed rather than defaulted. The
docstring records the second half of the fix, which matters more than the number: the candidate set
is built in full and **round-robined across structural shapes before truncation**, so the budget is
spent across the whole application instead of landing entirely in the first category folder the
crawl walked.

**Root cause 3 (`depth(2) x frontier(30)` = 60 visits): FIXED.** `agent.py:1831`
`depth = max(1, min(int(os.environ.get("BBH_SURFACE_DEPTH", "4") or 4), 8))` and the frontier is now
`limit=budget - visited` (`agent.py:1866`) - a page BUDGET spread over levels rather than a fixed
per-round frontier. The docstring carries the original 12-page measurement and the reason (a BFS
round picks its frontier from what was known when the round started, so everything discovered after
the last frontier was picked was never fetched).

**THE ACCEPTANCE ORACLE, RUN.** Mission `ebd96f45` ("owaspbench-q019", 2026-08-11) is the verification
run against the same lab as the baseline `90cee81c` ("owaspbench-clean", 2026-08-10). Same query,
same field names (`input.url` / `input.target` / `input.base_url` on `etype='tool_call'`):

```
                                          BEFORE 90cee81c   AFTER ebd96f45   target   result
(a) hostless URLs any tool aimed at                   10               0      0       PASS
(b) scope_block events                                34              20      0 (*)   PASS
(c) distinct URLs http_probe/http_read touched        36              36    > 200     FAIL
(d) findings                                           2              29    > 2       PASS
    distinct URLs ANY tool aimed at                   63             432
    tool_call events                                 433            3490
    wall clock                                     3716 s          5329 s
```

(*) (b) passes on the clause that matters: hostless causes are 0. The residual 20 are a DIFFERENT
and correct refusal - sampled verbatim, all three are
`{'tool': 'run_subfinder' / 'run_crtsh' / 'run_wayback', 'error': 'SCOPE BLOCK: owaspbench/ not in
scope (host is in scope, but the request path is outside the pinned scope...'}` - passive recon
tools handed a bare host under a path-pinned scope. Nothing to fix.

**(c) FAILS, and the oracle is wrong, not the fix.** MEASURED: `http_probe` was dispatched **37
times in BOTH missions**, with `input` carrying exactly one key (`url`) in both, touching 36
distinct URLs in both. That number did not move because `http_probe` is a recon/fetch tool and was
never the stage that widened. The stage that widened is the injection sweep:

```
BEFORE top tools: run_xss 45, http_probe 37, run_xpath 32, run_ldap 32, run_ssi 32, run_dom_trace 32
AFTER  top tools: run_xpath 412, run_ldap 412, run_ssi 412, run_sqli 400,
                  run_sqli_structural 400, run_css_injection 400
```

**Distinct URLs reaching an engine went 63 -> 432 (6.9x) and findings went 2 -> 29.** Anyone who
re-runs oracle (c) as written will record a FAIL against a fix that worked. **Recommend rewriting
(c) as "distinct URLs reaching an injection engine > 200", which passes at 432.**

**Verdict: CLOSE Q-019** with the numbers above, delete the Rank 3b duplicate, and correct oracle
(c) in the process so the correction is recorded rather than silently dropped.

**What honestly REMAINS from the ticket, and it is smaller than the ticket implies:** root cause 2
in its deepest form still stands - `sweep_targets` still begins `if "?" not in u or not in_scope(u):
continue`, so a query-less URL can only reach an engine through a captured form, and forms only
exist for pages that were FETCHED. Coverage of plain `.html` cases remains O(pages fetched). The
mitigation is the wider crawl budget, not a change to that rule. If that is wanted it is a new,
narrow ticket, not the reason to keep Q-019 open.

### The unexplained sublinear per-URL cost - EXPLAINED. Two measured causes, no mystery.

The Q-019 refinement recorded "8.5 s per tool call, ~12 calls per URL, ~100 s per URL" and projected
"2740 cases at 100 s/URL is ~76 hours". Re-measured across both missions:

```
                    wall     tool_calls   distinct URLs   s/tool_call   s/URL   calls/URL
BEFORE 90cee81c    3716 s          433              63          8.58    59.0         6.9
AFTER  ebd96f45    5329 s         3490             432          1.53    12.3         8.1
```

URLs rose 6.9x and tool calls rose 8.1x, but **wall clock rose only 1.43x**. Per-call cost fell
5.6x. Two measured causes account for it.

**Cause 1 - a large FIXED cost that does not scale with targets.** From the `phase` events, time
from mission start:

```
BEFORE  recon t+0  enum t+45  probe t+48  scan t+188 ... probe t+1652 | report t+3716
AFTER   recon t+0  enum t+32  probe t+33  scan t+173 ... probe t+1633 | report t+5329
```

Everything before the injection sweep costs **1652 s vs 1633 s - a difference of 19 seconds across a
6.9x change in target count.** That ~27 minutes is fixed overhead. Averaging it over 433 calls
versus 3490 calls alone drops the reported "per call" figure without anything getting faster.

**Cause 2 - the expensive engines are CAPPED while the cheap ones scale.**

```
agent.py:223   SWEEP_BROWSER_CAP = max(0, int(os.getenv("BBH_SWEEP_BROWSER_TARGETS", "30") or 30))
agent.py:3668  for tool in (_SWEEP_HTTP_ENGINES
                            + (_SWEEP_BROWSER_ENGINES if _i < SWEEP_BROWSER_CAP else ()))
```

MEASURED browser-backed dispatch (run_xss, run_dom_trace, run_dom_audit, run_stored_xss,
run_form_xss, browser_navigate, confirm_browser_persona_bola, run_client_checks):

```
BEFORE  119 of 433 calls  = 27.5%
AFTER   139 of 3490 calls =  4.0%
```

The browser confirmers grew by 20 calls while everything else grew by 3037. And inside the sweep
window itself:

```
BEFORE  injection sweep spans t+1652s .. t+3428s    156 calls   11.39 s/call
AFTER   injection sweep spans t+1633s .. t+5068s   2436 calls    1.41 s/call
```

In the BEFORE run the sweep had ~20 targets, all of them under the 30-target browser cap, so every
target paid the ~19 s browser confirmation. In the AFTER run 400+ targets share the same cap of 30,
so roughly 370 of them pay only the cheap HTTP engines.

**Verdict: the sublinear cost is a designed property, not an anomaly, and the "76 hours" projection
is DISPROVED.** The marginal cost of one more target is the HTTP-engine cost of ~1.41 s/call, not
the 59-100 s/URL average that the projection extrapolated from an average dominated by fixed
overhead and an uncapped browser pass. ESTIMATE, clearly labelled as one and not a measurement:
2740 targets at the measured marginal rate plus the measured ~1640 s fixed cost is single-digit
hours, roughly an order of magnitude below the projection. That estimate should be checked by
running it, not quoted.

**Recommend: delete the "unexplained sublinear per-URL cost" item and fold the two causes into the
Q-019 close.** Anyone tuning throughput should be pointed at `BBH_SWEEP_BROWSER_TARGETS` and at the
27-minute fixed pre-sweep phase, which is now the dominant term for any small mission.

---

## RUN 2 (2026-08-17). Run 1 was killed by a session limit; nothing above was redone.

Apparatus re-checked at run 2 start. The container is STILL not at HEAD, and the drift moved:

```
report.py          HEAD=6d373c06  IMAGE=d87760a0  WORKTREE=6d373c06   IMAGE != HEAD
proof_schema.py    HEAD=cbc7129b  IMAGE=f4be54c0  WORKTREE=f4be54c0   IMAGE != HEAD
technique_model.py HEAD=7dd547ca  IMAGE=7dd547ca  WORKTREE=7dd547ca   (equal)
main.py            HEAD=4d50eb1e  IMAGE=74634322  WORKTREE=c7304e33   all three differ
tools.py           HEAD=63e32362  IMAGE=eab17583  WORKTREE=ad1364ed   all three differ
```

`docker-compose.yml:72-77` mounts only `./ui`, `bbh_data` and the feed volumes - **the agent code is
BAKED, not mounted**, so a probe run inside the container exercises the IMAGE unless the file is
copied in. Every live probe below states which file it loaded and its md5. Where worktree code had to
be measured it was `docker cp`-ed to `/tmp/wt` and put FIRST on `sys.path`, and the probe prints
`report.__file__` so the substitution is proven rather than assumed.

Corpus at run 2: **29,944 tool_call rows, 153 missions, 71 distinct tool names, 1057 finding rows** -
byte-identical to run 1, so no mission has run between the two runs. `via` census unchanged:
`{None: 29885, internal: 59}`.

### Q-022 - "How this was confirmed" is a template - FIXED IN CODE, but its own mandatory negative control (a) FAILS. OPEN, narrowed to one line.

**The fix is real and it shipped.** MEASURED, `agent/report.py` (WORKTREE == HEAD `6d373c06`):
`proof_and_retest` (`report.py:1357`) no longer calls `_tm.proof_contract` on the family; it calls
`negative_control_claim(finding)` (`report.py:1284`), which routes on the three-valued
`proof_schema.control_status(f)` (`proof_schema.py:253`). Both renderers go through the same two
functions - markdown `report.py:503`/`:509`, HTML `report.py:2561`/`:2562` - so oracle 3 holds
structurally.

MEASURED, the ticket's oracles run verbatim against worktree `report.py` loaded from `/tmp/wt`
(the probe printed `report.py loaded from: /tmp/wt/report.py`, md5 `6d373c06`):

```
ORACLE 1 (control recorded)   status=recorded
                              heading="How this was confirmed (false-positive safety)"
ORACLE 2 (no control)         status=not_recorded
                              heading="False-positive safety: NOT ESTABLISHED for this finding"
                              text="NO NEGATIVE CONTROL WAS RECORDED for this finding. ..."
THIRD VALUE (source-derived)  status=not_applicable
                              heading="False-positive safety: rule-level counter-example ..."
```

**ORACLE 2 AS LITERALLY WRITTEN WOULD FAIL, and the oracle is wrong, not the fix.** It demands that
the string `does NOT reproduce` not appear. MEASURED: it DOES appear in the not-recorded text, because
that branch deliberately quotes the contract as the experiment that *would* settle the question:
"...The control that would settle it: An inert control ... does NOT reproduce ... -- run it before
treating this as false-positive-safe." The indicative claim is gone from the HEADING and the sentence
is explicitly subjunctive. This is the Q-019 oracle-(c) shape again: re-running the oracle as written
records a FAIL against a fix that worked. **Rewrite oracle 2 as "the heading is not `How this was
confirmed` and the text opens with `NO NEGATIVE CONTROL WAS RECORDED`".**

**THE LIVE DEFECT - the ticket's mandatory negative control (a) FAILS.** The ticket made it
mandatory: "the 34 findings that DO carry a control must still show a full control description. A fix
that renders 'not recorded' for everything has deleted the section rather than repaired it."

MEASURED over all 1057 stored finding rows, walking every JSON path at every depth for the five
`proof_schema.CONTROL_KEYS`:

```
finding rows whose RAW JSON mentions a control token          :    3 of 1057
NON-EMPTY control artifacts, by JSON PATH:
   .browser_evidence.negative_controls              dict   3
   .browser_evidence.negative_controls.control      dict   3
   (family: bola, all 3)
proof_schema.control_status() == RECORDED over ALL 1057 rows  :    0
confirmed findings                                            :  665
control_status census over confirmed  {'not_recorded': 665}   -> heading census:
   "False-positive safety: NOT ESTABLISHED for this finding"       665
```

POSITIVE CONTROL that the apparatus can return RECORDED at all - the SAME dict in two positions:

```
{"negative_controls": {...}}                       -> control_status = recorded
{"browser_evidence": {"negative_controls": {...}}} -> control_status = not_recorded
    and its rendered heading -> "False-positive safety: NOT ESTABLISHED for this finding"
```

**Root cause, one line.** `control_status` / `report.control_ran` scan **TOP-LEVEL keys only**
(`proof_schema.py:271`, `for k in CONTROL_KEYS: v = finding.get(k)`). The only producer in the entire
corpus that actually records controls is the BIE, and it writes them **nested**, at
`browser_evidence.negative_controls`. The ticket itself named that shape as the one to standardise on
("the shape already exists in two places - pick one and make it the contract ... The BIE dict is the
more general of the two"). The fix picked the top-level names and never taught the reader to look
inside `browser_evidence`.

**The report now contradicts itself about the same finding.** MEASURED, rendering the real stored
finding `bola` / `http://juice-shop:3000/rest/basket/6`:

```
negative_control_claim(f).heading -> "False-positive safety: NOT ESTABLISHED for this finding"
negative_control_claim(f).text    -> "NO NEGATIVE CONTROL WAS RECORDED for this finding. ..."

report.browser_evidence_html(f)   -> renders, in the SAME report, a control table containing
      "Negative control - anonymous"             (url, status 401, len)
      "Negative control - implausible id"
      "Negative control - attacker's own object"
      "Negative controls: the same request anonymously, and with an implausible id, do NOT return it."
```

One report, two sections, opposite answers about whether a control was run. That is Q-015's shape
(two projections of one fact disagreeing) one layer out, and for these 3 findings it is a
**REGRESSION**: before the fix they printed an unbacked-but-true sentence, and they now print a
**false** statement about a finding that carries three real recorded controls.

**The green test suite cannot see it.** `agent/tests/test_evidence_contract_by_proof_kind.py:56`,
`_behavioural_with_control()`, sets `f["negative_controls"] = [...]` at TOP LEVEL - a shape **no
producer in the corpus emits**. The fixture invents the vocabulary the code reads instead of using
the one the producer writes, so the suite is green and the defect ships. Same family as the standing
memory note "guards that check declarations, not facts".

**MEASURED CORRECTION to the ticket's headline number.** "626 of 660 ... 34 carry a control
(dom_link_manipulation 32, bola 2)" does not reproduce. The 32 `dom_link_manipulation` rows carry NO
control key at any depth; their complete key set is `title, severity, family, confidence, target,
cwe, cvss_vector, cvss_score, evidence, success_oracle, reproduction_steps, impact, tags, id, owasp,
analyst_notes, source`. The ticket's "34" was measured with a looser instrument, most likely
`success_oracle` - which is a claim, not an artifact. **The true figures are 3 of 1057 rows and
662 of 665 confirmed findings: the problem was WORSE than filed, not better.**

**Verdict: OPEN, and the remaining work is small and precisely located.** The 662 unbacked claims are
gone, which was the CRITICAL part of the ticket. What is left: teach `control_status` to read the
nested BIE shape (or make the BIE also stamp a top-level key), and replace the top-level-only fixture
with one built from a real stored BIE finding so the corpus under test contains the shape the producer
emits. The ticket's non-vacuity control (c) should be strengthened to require >= 1 finding of each
kind **drawn from stored producer output**, not hand-written.

### Q-023 - ZAP has never executed in any mission - the ticket is 2 CLOSED / 1 LIVE / 1 REWRITE. Do not work it as filed.

Run 1 confirmed the FACT and disproved the "three flags" EXPLANATION. Run 2 settles the four
remaining commitments in the ticket body.

**The fact, re-measured at run 2** (same instrument, positive controls restated):

```
run_zap calls: 0      any tool name containing "zap": {}
POSITIVE CONTROL   run_nuclei 254 / run_fingerprint 2699 / http_probe 4650
POSITIVE CONTROL   tools dispatched EXACTLY ONCE all resolve: browser_navigate, http_request,
                   confirm_create_object_idor, confirm_read_object_idor,
                   confirm_browser_persona_bola, run_session_lifecycle    (n=6)
missions with enable_zap truthy: 4     of which mode=full: 4
```

The single-dispatch positive control is the one that matters: an engine that ran once IS visible, so
0 is not the apparatus failing to look. Q-061's caveat still applies (only 59 of 29,944 rows carry a
`via` field), which is why run 1's independent ZAP-daemon instrument remains the load-bearing
evidence and this count is corroboration.

**Sub-defect 1 - `recon["zap"]` is a dead write: CLOSED, the write is GONE.** MEASURED:
`grep -n 'self\.recon' agent/tools.py | grep -i zap` -> **no hits**. The `tools.py:8470`
`self.recon.setdefault("zap", []).extend(findings)` the ticket cited no longer exists anywhere in the
tree. POSITIVE CONTROL that the grep resolves a live recon write: `recon["urls"]` at `tools.py:10095`
and `main.py:2480`, read at `guidance.py:722`.

**Sub-defect 3 - the AJAX spider fails silently: CLOSED.** MEASURED, `agent/tools.py:9889-9902`. The
bare `except Exception: pass` is replaced by exactly the idiom the ticket asked to be mirrored:

```python
if not ajax_ok:
    await zap.ajax_stop()
    degraded.append("AJAX spider incomplete or timed out")
except Exception as exc:
    degraded.append("AJAX spider degraded: %s: %s" % (type(exc).__name__, exc))
```

Both the timeout case and the exception case now reach `degraded`, which is surfaced in the
ToolResult note.

**Sub-defect 2 - targeted rescan is NOT WIRED: STILL LIVE, unchanged.** MEASURED:
`agent/planner.py:678-679` still builds the step with key `f"run_zap:{h}"` - host only, no path - and
`planner.fresh()` (`planner.py:297-312`) still drops any step whose key is in `done`:
`if k in done or k in seen or not _allowed(s["tool"], mode): continue`. **One ZAP call per host per
mission, ever.** A second, narrower ZAP pass against a path discovered later in the mission is
unrepresentable. This is the only clause of the ticket body still true and actionable.

**The consumer contract - "ZAP Executed must be computed from a run_zap RESULT, not from the flag":
CLOSED.** MEASURED, `agent/main.py:1113-1129`: the status is derived from `z = agg.get("run_zap")`,
the ledger entry, and the flag only distinguishes `user_disabled` from `not_invoked`:

```
not _zap_configured -> "not_configured"
not _zap_enabled    -> "user_disabled"
not z               -> "not_invoked"    ("ZAP Not Invoked - enabled but not scheduled for this run")
z["error"]          -> "failed"
else                -> executed_{passive|safe_active|thorough_active}, read from the note's policy=
```

`report.py:1592-1601` renders all nine states including the honest `not_invoked`. The
declaration-vs-fact defect the ticket named at the orchestration layer is fixed at the reporting layer.

**QUEUE.md contradicts itself about this ticket.** `docs/QUEUE.md:1050` states "Q-023, Q-013 and
Q-014 are all closed"; the ticket body at `docs/QUEUE.md:2810` is still headed `**HIGH**`,
`proposed`. Two states for one ticket in one file - the Q-019 duplication rot again.

**Verdict: REWRITE Q-023 down to its one live clause.** Retitle to "ZAP is one call per host per
mission - a targeted rescan is unrepresentable" (`planner.py:679` key, `planner.py:306` dedup); carry
forward run 1's finding that there is no wiring defect and that the coverage gap closes by RUNNING a
mission with `enable_zap=True`, not by editing code; and DELETE sub-defects 1 and 3, the three-gate
explanation, and the "fifth unidentified cause" paragraph - all four are settled. Resolve the
`1050` vs `2810` state conflict in the same edit.

### Q-021B - persist a canonical TechnologyFact - BUILT AND WIRED. CLOSE IT, with two named residuals and a mis-specified oracle.

The ticket is marked `proposed`. It is **shipped**. Every producer/consumer contract in the ticket
body resolves to real code, and it is NOT an island.

MEASURED, source (all files WORKTREE == IMAGE `fingerprint.py` md5 `82d3bee5`, confirmed identical
inside the container before any probe ran):

```
the ONE constructor      dependency_intel.py:210  make_tech_fact(product, *, version, source,
                                                    detector, vendor, component, ...)
                         dependency_intel.py:262  merge_tech_facts()   (dedup by identity)
the fact builder         fingerprint.py:286       tech_facts()  -> (facts, rejected)
the persister            fingerprint.py:320       record_facts() -> mutates recon["technology"]
                                                    and recon["technology_rejected"]
WIRED INTO THE ARTERY    tools.py:3994            fp.record_facts(self.recon, final, ...) inside
                                                    _run_fingerprint  (2,699 dispatches in the corpus)
graph projection         asset_graph.py:610       for fact in recon.get("technology"):
                                                    g.observe_technology(fact, ...)
cross-mission persist    memory.py:207            "technology": sorted(recon.get("technology"))
warm start               main.py:214              _warm_start_technology(scope, tools, prior) -> int
                         main.py:239              merge_tech_facts(prior + current)
tests                    tests/test_tech_fact.py, tests/test_tech_fingerprint_facts.py
```

MEASURED, tests: `docker exec -w /tmp/wt2 apolaki-agent-1 python -m pytest tests/test_tech_fact.py
tests/test_tech_fingerprint_facts.py -q` -> **47 passed** (worktree tree copied to `/tmp/wt2`, not
the image's `/app`).

**The three MANDATORY negative controls, run verbatim and live** (worktree `fingerprint.py`):

**(a) Prose is refused AND the refusal is recorded.** Fed the ticket's exact MultiJuicer body:

```
detect() still sees it (deliberately unfiltered, so the refusal ledger can name what it dropped):
   {'name': 'a MultiJuicer Kubernetes cluste', 'source': 'powered-by text', ...}
record_facts ->  facts admitted: 0     refusals RECORDED: 1
   refused name='a MultiJuicer Kubernetes cluste' detector=fingerprint.body.prose
   reason=prose_leading_stopword
```

This is the control's hard half: the ticket said "a fix that merely stops STORING them without
recording the rejection has moved the blindness, not removed it". The rejection carries a reason AND
names its own detector. PASS.

**(b) A versionless detection stays LOW and is not CVE-eligible.**

```
Server: nginx        -> product=nginx version='' confidence=low  cve_eligible=False
```

PASS.

**(c) Empty means empty, and no error.**

```
record_facts(..., {}, "", "<html><body>hello</body></html>")
   -> facts: 0   rejected: 0   raised: no
```

PASS - a real zero is distinguishable from a broken detector, which is the Q-016 requirement applied
here.

**ORACLE 1 - a fact carries name/version/evidence: PASS. Its CONFIDENCE clause: FAILS, and the
oracle is wrong, not the code.** MEASURED:

```
Server: Apache-Coyote/1.1 ->
 {product: apache-coyote, version: "1.1", source: "Server header", detector: fingerprint.headers,
  evidence: "Server: Apache-Coyote/1.1", location: http://owaspbench:8443/x, host: owaspbench:8443,
  first_seen/last_seen: set, confidence: "low", version_confidence: "low",
  proof_state: "version_suspected", component_status: "potentially_affected"}
```

The name, the non-empty version and the evidence quoting the exact proving byte are all there. But
the oracle also demands `confidence in CVE_ELIGIBLE`, and `CVE_ELIGIBLE = frozenset({'high',
'confirmed'})` while EVERY header-derived fact is `low`:

```
Server header w/ version   nginx 1.18.0    conf=low  cve_eligible=False  proof_state=version_suspected
X-Powered-By w/ version    php   7.4.3     conf=low  cve_eligible=False  proof_state=version_suspected
meta generator             wordpress 5.8   conf=low  cve_eligible=False  proof_state=version_suspected
```

POSITIVE CONTROL that CVE_ELIGIBLE is reachable at all, so this is a deliberate ceiling and not a
broken ladder:

```
di.components_for_artifact("/*! jQuery JavaScript Library v1.7.1 */", ".../jquery/1.7.1/jquery.min.js")
   -> {'name': 'jquery', 'version': '1.7.1', 'confidence': 'confirmed'}  cve_eligible=True
```

So a served-artifact reading reaches CONFIRMED and a banner never does - which is exactly what the
ticket's own false-positive section demanded ("a fact is an OBSERVATION, so record the header
verbatim as evidence and never call it proof"). **The ticket's oracle 1 contradicts the ticket's own
FP-risk section.** This is the THIRD mis-specified oracle in this sweep (Q-019 (c), Q-022 (2), this).
**Rewrite oracle 1 to require `version` non-empty and `proof_state == "version_suspected"`, and move
the CVE-eligibility assertion onto the served-artifact path where it belongs.**

**ORACLE 2 - the graph projects a component node: PASS.**

```
recon with 1 fact -> build_from_engagement("m-test", recon=..., findings=[])
   node kinds {'component': 1, 'host': 1}
   component:owaspbench:8443||apache-coyote|   label "Apache-Coyote 1.1"  confidence 0.3
                                              sources [{'source': 'fingerprint'}]   enables []
NEGATIVE CONTROL, identical call with NO technology -> node kinds {}
```

INSTRUMENT NOTE: my first attempt reported **0 nodes** and that was my apparatus, not a finding.
`g.nodes` is a METHOD, not a container, and my minimal `recon` had no `live_hosts`. Corrected via
`g.to_dict()` before anything was concluded. This is the "read the wrong attribute" failure the brief
warned about, caught by the negative control disagreeing with the positive one.

**RESIDUAL 1 - two of the four producers named in the ticket are still not connected.** MEASURED:
`grep -n "make_tech_fact|record_facts|technology" agent/codeintel.py agent/browser_engine.py` ->
**no hits**. `codeintel.harvest()`'s `out["versions"]` (`codeintel.py:236`, `name@x.y.z` mined from
served JS) and `browser_engine.observe()`'s `framework` (`browser_engine.py:256-259`) still have no
reader and emit no fact. The ticket's producer contract named four producers; two were done. Note
that `codeintel`'s versions are a SERVED-ARTIFACT reading, i.e. the very path that CAN reach
CVE_ELIGIBLE - so this residual is worth more than it looks.

**RESIDUAL 2 - the component node's `enables` is empty.** `enables []` on the projected node means
the fact reaches the durable graph but unlocks no technique. That is deliberate and documented in
place (`tools.py:3986-3992`: "Deliberately NOT written into `self.graph` ... orchestration is
Q-021E"), so it is not a defect - it is the precise statement of what Q-021E still has to do.

**Verdict: CLOSE Q-021B.** Record the two residuals as one small follow-up ("connect the codeintel
and browser_engine producers to make_tech_fact") rather than keeping a HIGH ticket open, and correct
oracle 1 in the same edit so the next reader does not record a FAIL against working code.

### Q-021D - connect governed feeds to components - OPEN, every claim reproduces, and the promotion gap is now proven with a positive control.

MEASURED live (worktree tree at `/tmp/wt2`):

```
intel_registry.stats()      {'total': 0, 'by_state': {}}
intel_registry.production()  0 records
by_state(candidate)=0  (validating)=0  (validated)=0  (fixture_backed)=0  (reviewed)=0  (production)=0
intel_sources.SOURCES        18 sources,  enabled=True: 0
intel_sources.enabled_sources()  ->  []
```

POSITIVE CONTROL that the store is reachable and the emptiness is structural, not a dead import:

```
intel_registry.ingest([{"source":"nvd","id":"CVE-0000-0000","kind":"advisory"}])
   -> stats() {'total': 1, 'by_state': {'candidate': 1}}
   -> production() STILL 0
```

So a record CAN enter, it lands at `candidate`, and nothing in product code can move it up.
MEASURED, `advance()` callers: `grep -rn "advance(" --include=*.py agent/` returns hits in
**`agent/tests/test_intel_registry.py` ONLY** (lines 27-49). No endpoint, no engine, no artery.
`_STORE` is still a module-level dict (`intel_registry.py:13`) cleared by `reset()` at `:20`, so it
does not survive a restart either.

MEASURED, gap 1: there is still no product-to-advisory resolver. `advisories_for` does not exist
anywhere; no CPE and no OSV.

INSTRUMENT NOTE: my first grep for `purl` returned `agent/proxy.py:112,124-126,285-288` and
`tools.py:7058`. Those are **local variables named `purl` holding a PROXY URL** (`purl =
proxy_url(url)`), not Package URLs. Reported here because it is exactly the false-positive shape that
would have produced "PURL support exists". Checked before it was written down.

**Verdict: OPEN, unchanged, and correctly filed.** The ticket's own warning is the important part and
it is now confirmed by measurement rather than by reading: `production()` is structurally always
empty, so **any ticket that only adds a consumer wired to `production()` is a null change that will
pass a green test**. Keep that sentence at the top when this is worked.

### Q-021E - technology drives safe orchestration - OPEN, but SMALLER than filed: Q-021B already built the producer half.

MEASURED, the ticket's central catch reproduces exactly:

```
"has_versions" in engine_descriptor.OBSERVATIONS   -> True
PRECONDITIONS entries                              -> 42
techniques gated by has_versions                   -> []          <- gates ZERO
POSITIVE CONTROL "reflects_input" gates            -> 3 techniques
```

Sharper than the ticket had it: of **17 declared OBSERVATIONS, exactly 2 gate nothing** -
`has_versions` and `sql_error_seen`. So this is a two-item orphan list, not a general rot.

**THE MATERIAL UPDATE: the graph now EMITS the observation.** Q-021B landed after this ticket was
written, and the producer half of Q-021E is done. MEASURED end to end, fingerprint -> fact -> graph
-> observations:

```
Server: nginx/1.18.0  ->  build_from_engagement(...).to_observations()  ->  ['has_versions']
NEGATIVE CONTROL, Server: nginx (NO version)      ->  has_versions NOT emitted
```

`asset_graph.py:342-349` implements exactly the distinction the ticket needed ("`has_versions` must
mean a version is actually KNOWN"). **What remains is only the consumer**: a `PRECONDITIONS` entry
and an engine. The observation is now produced, correctly, and lands in a vocabulary where nothing
reads it - which is a cleaner statement of the gap than the ticket's.

MEASURED, the "also in scope" half reproduces verbatim:

```
cp.canonical_family(sca_lead)                 -> 'vulnerable_component'
'vulnerable_component' in cp._ROUTES          -> False    (_ROUTES has 12 entries)
'vulnerable_component' in cp.PRIMARY_HANDLED  -> False
cp.normalize(sca_lead)['validator']           -> None
cp.normalize(sca_lead)['oracle']              -> 'no validator implemented yet'
```

And the corpus figure the ticket quotes is confirmed from the DB: **56 stored confirmed
`vulnerable_component` findings** (family census, run 2), every one of which takes the `UNSUPPORTED`
terminal path.

MEASURED, nothing of the engine exists: `run_tech_probe`, `probe_plan` and `_technology_probe` return
no hits (the one `probe_plan` match, `param_discovery.py:85`, is an unrelated local dict and was
checked before being dismissed). `hasattr(ToolRegistry, "_run_tech_probe")` -> **False**.

POSITIVE CONTROL that the pattern the ticket says to copy really is there:

```
hasattr(ToolRegistry, "_run_cloud_probe")  -> True   (tools.py:2978)
hasattr(cloud_intel, "analyze")            -> True
```

**One stale reference to fix while editing.** The ticket names the agent-side analogue as
`agent._cloud_exposure_probe` at `agent.py:1588-1610`. MEASURED: the only cloud method on `BBHAgent`
is **`_probe_cloud_storage`**; `_cloud_exposure_probe` does not exist. An implementer copying the
triplet would hunt for a method that is not there.

**Verdict: OPEN, and it should be RE-SCOPED DOWN.** The producer, the graph projection and the
observation now exist and are proven. The remaining work is the `PRECONDITIONS` consumer, the
`probe_plan`/`_run_tech_probe` triplet and the `_ROUTES` entry. Its dependency on Q-021B is
discharged; its dependencies on Q-021C/D are not.

### Q-021F - expose the technology lifecycle honestly - OPEN, unchanged, and correctly ranked LOW.

MEASURED: technology still reaches a report **only** through the delta section.

```
grep -n "New Technology|technology" agent/report.py
   report.py:1586   ("tech", "New Technology")     <- markdown delta
   report.py:3091   ("tech", "New Technology")     <- html delta
   (no other hit in the whole file)
```

The ticket cited `report.py:1422,2585`; the line numbers moved, the fact did not. There is no
technology inventory, no version-confidence column, no advisory-match column and no proof-status
column on any surface.

MEASURED, the other three surfaces the ticket names: `grep -ln technology agent/sarif_io.py
agent/poc_bundle.py agent/main.py` matches **`main.py` only**, and every hit there is
`_warm_start_technology` (`main.py:214-285`). The mission JSON exposes a warm-start **count**
(`"technology": seeded_tech`), never the inventory. `sarif_io.py` and `poc_bundle.py`: zero hits.
`ui/index.html`: 2 hits, both HELP TEXT describing the graph and the re-scan diff card, not a view.

MEASURED, no shared projection exists to render: `grep -rn "def technology_|def tech_rows|def
tech_inventory|technology_view"` -> no hits.

**The vocabulary the ticket asks the badge to be computed from DOES already exist**, which lowers the
cost: `dependency_intel.py:60-61`

```
TECH_PROOF_LADDER = (DETECTED_TECHNOLOGY, VERSION_SUSPECTED, ADVISORY_MATCHED,
                     APPLICABILITY_CONFIRMED, SAFELY_PROBED, ORACLE_CONFIRMED)
```

and Q-021B already stamps `proof_state` on every fact (measured above: `version_suspected`). So F is a
renderer over an existing model, not a modelling job.

**Verdict: OPEN, unchanged, LOW is right.** One amendment worth making now: record that
`proof_state` and `TECH_PROOF_LADDER` already exist and are populated, so the ticket's contract
("the rendered badge is computed from the stored state, never hardcoded") is implementable today
without waiting on C/D/E. A facts-only inventory at `DETECTED_TECHNOLOGY` / `VERSION_SUSPECTED` is
shippable against Q-021B alone.

### The ninth baseline case `00438` - the word "unprobed" is UNVERIFIED, and the real situation is worse than the item says.

The item is carried in three places, one of them PRODUCT SOURCE:

```
agent/agent.py:219   "# ... -- 00438, the ninth case, is still unprobed."
docs/LEDGERS.md:1001 "`00438` -- the ninth ..."
docs/QUEUE.md:982    "Left open, named: `00438` (the ninth case, highest index) is still unprobed"
```

**FACT 1 - 00438 is not a capability gap. It has been PROBED and CONFIRMED.** MEASURED against the
mission store, mission `ebd96f45` ("owaspbench-q019", 2026-08-11):

```
tool_calls naming BenchmarkTest00438: 8
  run_sqli / run_sqli_structural / run_xpath / run_ldap / run_ssi / run_css_injection /
  run_waf_bypass / run_injection_probes     -- 1 each, all at 01:37:17, all against
  https://owaspbench:8443/benchmark/sqli-00/BenchmarkTest00438.html?BenchmarkTest00438

stored finding: 00438  sqli  CONFIRMED
   https://owaspbench:8443/benchmark/sqli-00/BenchmarkTest00438
```

All NINE named cases got byte-identical treatment in that mission - 8 calls each, the same 8 engines -
and **all nine produced a confirmed `sqli` finding.**

NEGATIVE CONTROL, the paired earlier baseline `90cee81c` ("owaspbench-clean", 2026-08-10): **0 calls
for every one of the nine.** So the instrument discriminates - it is not matching every mission - and
the 08-11 run really is the one that reached them.

**FACT 2 - the selection model says 00438 IS selected at the shipped cap.** MEASURED by running the
pinned test's own fixture and `agent.sweep_targets` at the live default:

```
SWEEP_TARGET_CAP shipped default = 700

cap 400  kept 400  alpha slots 38   lost-indices reached {38: F, 45: F, 51: F, 58: F}
cap 600  kept 600  alpha slots 58   lost-indices reached {38: T, 45: T, 51: T, 58: F}
cap 605  kept 605  alpha slots 59   lost-indices reached {38: T, 45: T, 51: T, 58: T}
cap 700  kept 700  alpha slots 70   lost-indices reached {38: T, 45: T, 51: T, 58: T}
cap 800  kept 800  alpha slots 83   lost-indices reached {38: T, 45: T, 51: T, 58: T}
```

Index 58 is 00438. At the shipped cap of 700 the model selects it with 12 slots to spare.

**FACT 3 - the sealed wp3 artifact does not contain the word the claim needs.** MEASURED,
`docs/benchmarks/wp3_raised_cap_claims.json` (seal `951dc0a0`):

```
occurrences of BenchmarkTest00335/00337/00339/00341/00342/00428/00429/00433 : 13 each
occurrences of BenchmarkTest00438                                          :  0
```

So "8 of the nine recovered" reproduces exactly from the seal. **But the seal's top-level keys are**

```
by_family, claim_rows, claims, coverage, distinct_cases_claimed, effort, elapsed_s,
findings_total, leads_total, mode, phases, seal_sha256, target
```

**There is no probed-cases list.** The artifact records CLAIMS. "00438 produced no claim" is
observed; **"00438 was not probed" is an INFERENCE from the absence of a claim, and the artifact
cannot distinguish the two.** That is precisely the distinction Q-063 exists to enforce elsewhere in
this codebase ("ran and found nothing" is not "never ran"), and it was collapsed here.

**FACT 4 - wp3 cannot be re-verified from the mission store.** The newest owaspbench mission in the
DB is `ebd96f45` (2026-08-11). The wp3 run is not there, so the sealed JSON is the only record and
the probe question cannot be settled retrospectively at all.

**Verdict: REWRITE the item; the current phrasing is UNVERIFIED and it under-states the problem.**
Honest statement: *"`00438` was probed by 8 engines and confirmed as `sqli` in `ebd96f45`, the
selection model selects it at the shipped cap of 700, and it nevertheless produced no claim in wp3.
Whether it was probed in wp3 is unknown because the seal records claims, not probes."*

That is not a budget item. A case the engine demonstrably confirms, which the budget model says is
in-budget, disappeared between two runs - so the remaining hypotheses are a live-surface/model
divergence (the wp3 precondition doc already names "the live surface differing from the modelled
one" as a risk) or a non-deterministic loss of the kind Q-070 describes. **Do not price the next
budget change against this item: raising the cap cannot fix a case the cap already covers.**

**Two concrete follow-ups, both cheap:**
1. Add a probed-cases list to the benchmark seal so "not probed" and "probed, no claim" stop being
   indistinguishable. Without it every future run inherits this ambiguity.
2. Delete the run-specific claim from `agent/agent.py:219`. A source comment asserting the state of
   one benchmark run rots the moment the next run lands, and this one is now measurably wrong in the
   word that matters.
