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
