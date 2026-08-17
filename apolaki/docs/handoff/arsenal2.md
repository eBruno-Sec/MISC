# Arsenal-gap lane, run 2 (Q-051 measurement on a CURRENT deployment)

Question being answered (Erwin's words): "All tools being used by apolaki harmoniously? Apolaki
should be using all tools including browser driver and devtools like an advanced genius pentester."

Run 1 (`docs/handoff/arsenal.md`) could not answer it: the deployed agent was 59 commits behind the
tree and none of the Q-051 reporting functions existed in the running binary. That is now fixed.
**Run 2 exists to produce the first measurement taken on a deployment that matches the tree.**

Every row is MEASURED (command + real output) or UNVERIFIED. Run 1's live-mission numbers describe
a stale 112-engine platform and are NOT carried forward.

---

## Lane parameters (so the numbers are reproducible)

Mission `57cc3b49`, launched 2026-08-17, still running at time of writing.

```
POST /engage {"program_name":"Q-051 arsenal-gap run2",
              "in_scope":["http://juice-shop:3000"],   # port REQUIRED; a portless scope matches nothing
              "mode":"active","strategy":"deterministic",
              "auto_approve":true,"authenticated_scan":true}
 -> {"session_id":"57cc3b49","mode":"active","strategy":"deterministic","status":"created"}
POST /run/57cc3b49 -> {"ok":true,"status":"running"}
```

`auto_approve` + `authenticated_scan` are the project's own autonomous profile (`agent/bench_all.py`
uses exactly this pair). Both matter to this measurement and are deliberate:

- `auto_approve:true` pre-authorizes the INTRUSIVE HITL gate (`agent/agent.py:587`). It does NOT
  relax `planner._ALLOWED["active"]`, so the structural tier gap being measured is untouched; it
  only removes a human modal that no operator is present to answer. This makes the run strictly
  MORE generous to the arsenal - an engine still idle under it is more clearly a gap, not a stall.
- `authenticated_scan:true` is required or `_do_persona_authz` returns early (`agent/bench_all.py`
  comments this explicitly), which would make the auth-gated classes - BOLA, broken-object-authz,
  mass-assignment - structurally unreachable and misattribute their silence to the planner.

`warm_start` seeded 1010 known assets and 3 prior findings from earlier scans of this target. This
is a CONFOUND to note: recon engines may be short-circuited by cached knowledge.

---

## Status of each work item

| item | state |
|---|---|
| deployment-vs-tree drift re-verified | DONE - clean on all three edges |
| denominators re-measured on the current deployment | DONE - 111 / 76 |
| mission `57cc3b49` run to completion at `mode=active` | DONE - `status=complete` |
| four-way classification from the live ledger | DONE - see THE DELIVERABLE |
| `blocked_by_mode` regression check | DONE - **31, not 0**; not regressed |
| browser / CDP engine behaviour | DONE - two browser worlds, one unused |
| both renderers (markdown + HTML) carry the sections | DONE - both, verified live |
| new defects found | 3 (crown jewel, C/D merge, ledger-disagreement false positive) |

---

## PRECONDITION (MEASURED) - the deployment now matches the tree

Run 1's headline blocker is gone. Re-verified at the start of this lane, not taken on trust:

```
sh scripts/bake_drift_check.sh
bake OK - running container matches the baked image, and the image matches the source tree
          (179 modules, 88 techniques)
EXIT=0
```

And directly inside the container that serves missions:

```
docker exec apolaki-agent-1 python -c "import report; ..."
report.arsenal_gap                 True
report.technique_coverage          True
report._technique_md               True
report.ledger_finding_disagreement True
report._arsenal_md                 True
deleted adapters present: []                      # run_ferox/run_dirsearch/run_gobuster gone
new engines present: ['run_mass_assign', 'run_ws_hijack']
```

All five Q-051 functions that were absent in run 1 are present. The three Q-057-deleted content
discovery adapters that were still live in run 1's binary are gone. **So mission `57cc3b49` is the
first mission that CAN render the arsenal sections.**

---

## DENOMINATOR (MEASURED) - state it in the same sentence as any percentage

Measured inside `apolaki-agent-1`, i.e. the binary that actually scans - not the tree.

| surface | count |
|---|---|
| `TOOL_PERMISSIONS` (registered + dispatchable) | **111** |
| `CLAUDE_TOOLS` (advertised to the model) | **76** |
| advertised but NOT registered | **0** |
| registered but NOT advertised | **35** |

```
tier histogram over TOOL_PERMISSIONS (denominator 111):
  passive 15, active 56, intrusive 40
planner._ALLOWED["active"] = {passive, active}
allowed_at_active: 71 of 111
```

**40 of 111 engines (36.0%) are structurally incapable of being planner-selected at `mode=active`.**
Run 1 measured 42 of 112 on the stale build; the shape is unchanged, the numbers are not
interchangeable, and 92 (Q-050) is a third denominator again.

This is the single largest term in the answer to Erwin's question and it is a DESIGN choice, not a
defect: an unauthenticated `active` scan is a lead generator by construction. Whether `active`
should permit more is Q-052, an open PRODUCT question, deliberately not touched by this lane.

### The 35 registered-but-unadvertised engines (MEASURED, full list)

These are dispatchable but never described to the model, so the LLM cannot choose them by name;
only planner/`agent.py` dispatch can reach them. Two of the three browser engines are in here.

```
confirm_authz_write(I)  confirm_browser_persona_bola  confirm_read_object_idor  run_authz_matrix
run_cache_deception  run_client_checks(P)  run_css_injection  run_default_creds  run_dom_trace
run_encoded_cookie(I)  run_form_xss  run_header_trust  run_ipmi_audit  run_ldap(I)  run_ldap_enum
run_modbus_audit  run_ntp_audit  run_path_sqli(I)  run_rdp_audit  run_rsync_audit  run_saml(P)
run_service_pack  run_session_fixation  run_session_lifecycle  run_session_token  run_smb_enum
run_snmp_audit  run_sqli_structural(I)  run_ssh_audit  run_ssi  run_transport_posture
run_username_enum  run_vnc_audit  run_waf_bypass  run_xpath(I)
```

(P)=passive, (I)=intrusive, unmarked=active. This is a SECOND AXIS, not a gap by itself: an idle
engine that is planner-reachable-only is an effects-model gap; an idle engine that IS advertised and
still never fired is an LLM-selection gap. Under `strategy=deterministic` (this mission) the model
does not select at all, so this axis is informational here and becomes load-bearing only for
`low_ai`/`agentic` runs.

---

## CROWN JEWEL (MEASURED) - `browser_navigate` CANNOT appear in the ledger, ever

This is the direct answer to the browser half of Erwin's question, and it means the ledger is the
wrong instrument for it.

**`agent.Tools.execute()` writes no log row.** `agent/tools.py:1227-1249` is the whole method: it
scope-validates, resolves `getattr(self, "_"+tool_name)`, and dispatches. No `db.add_log`.

Only two callers log. `_run_tool` (`agent/agent.py:600`) yields a `{"type":"tool_call"}` event that
`main.py` persists, and `_exec_internal` (`agent/agent.py:687`) calls `db.add_log(..., via="internal")`
- the latter added precisely because twelve internally-dispatched engines were invisible. **The fix
was applied to `_exec_internal` and NOT to direct `self.tools.execute(...)` calls.**

All 12 `self.tools.execute(` sites in `agent/agent.py` (MEASURED, `grep -n`):

```
600   inside _run_tool          LOGGED (tool_call event)
687   inside _exec_internal     LOGGED (via=internal)
861   run_dom_audit             NOT LOGGED
1454  acquire_session           NOT LOGGED
1827  http_probe                NOT LOGGED
1851  http_read (persona)       NOT LOGGED
1856  browser_navigate          NOT LOGGED   <- persona browser pass, captures SPA routes + XHR
1884  http_read (depth-2 BFS)   NOT LOGGED
1915  acquire_session           NOT LOGGED
2052  acquire_session           NOT LOGGED
2078  browser_navigate          NOT LOGGED   <- persona login, drives the real login form
```

**`browser_navigate` has NO other dispatch path.** It is absent from `planner.py` entirely (MEASURED:
`grep -rn browser_navigate agent/planner.py` returns nothing), so its only two call sites are both
unlogged. Consequence:

> A report reading `browser_navigate: never dispatched` is a MEASUREMENT ARTIFACT and is true of
> every mission Apolaki has ever run, including missions in which the headless browser drove a real
> login form and captured SPA routes. The ledger cannot distinguish "the browser driver was idle"
> from "the browser driver ran hard".

This is the same registration-is-not-invocation family the codebase keeps re-finding, one level out:
the ledger records a DECLARATION of dispatch (made by two specific wrappers) rather than the FACT of
dispatch (made by `Tools.execute`). Run 1's conclusion that the dispatch surface is wider than
`planner.py` is correct and understated - part of the surface is invisible to the ledger too.

**Do not report `browser_navigate` in any of the four classes.** It is unmeasurable by this
instrument. Independent evidence is required, and there is one available.

### EMPIRICAL PROOF, not just code reading (MEASURED on mission `57cc3b49`)

The code reading above predicts that engines dispatched only via direct `tools.execute` calls will
be absent from the ledger even when they run. That prediction is now confirmed against a live
mission, using the auth artery as the independent witness.

```
docker exec -i apolaki-agent-1 python -   # over mission 57cc3b49
acquire_session                in ledger: False
browser_navigate               in ledger: False
http_read                      in ledger: False
run_authz_matrix               in ledger: True
confirm_browser_persona_bola   in ledger: True
```

And in the same mission's own context:

```
auth_artery = {"ran": true, "persona_count": 2, "auth_success": 2, "recrawl_new_endpoints": 13,
  "personas": [
    {"role":"anonymous","has_session":false,"verified":true},
    {"role":"user_a","identity":"apolaki_usera_9cf518a0@apolaki-test.local",
     "method":"registered","has_session":true,"verified":true},
    {"role":"user_b","identity":"apolaki_userb_3b4d7ef3@apolaki-test.local",
     "method":"registered","has_session":true,"verified":true}],
  "matrix": {"operations": 41, "findings": 35, "pair": ["user_a","user_b"], "ran": true}}
context.authenticated = True
```

**Two accounts were registered against the live target, two sessions were acquired and VERIFIED, an
authenticated re-crawl surfaced 13 new endpoints, and 35 authz findings were confirmed off those
sessions - while the ledger reports that `acquire_session` was never dispatched.**

`acquire_session` is the only engine that creates those sessions, so this is proof rather than
inference. `browser_navigate` sits in the same `_do_persona_authz` flow (`agent/agent.py:1856`,
between the persona `http_read` sweep and the depth-2 BFS that produced those 13 endpoints); its
dispatch path is PROVEN unloggable, but whether it executed on this specific mission is UNVERIFIED
and cannot be settled with this instrument.

This is what makes the four-way classification trustworthy: the same run that shows 3 engines
"never dispatched" also carries positive evidence that at least one of them did substantial work.

### Independent instrument for browser activity: browserless's own usage metrics

`apolaki-headless-chrome-1` is browserless, and it keeps its own session counter at
`/tmp/browserless-metrics.json`, written every 5 minutes. This is a record Apolaki does not author,
so it is genuinely independent of the ledger.

POSITIVE CONTROL FIRST (the counter is alive and does count):

```
docker exec apolaki-headless-chrome-1 sh -c 'cat /tmp/browserless-metrics.json'
... "sessionTimes":[8591,597,8489,529,8483,6443,8497,530,660,496,588],"successful":8,"units":11 ...
... "sessionTimes":[8500,6434,8515,6463,6429,8533],"successful":6,"units":6 ...
... "sessionTimes":[676,672,1528,1483,6501],"successful":5,"units":5 ...
... "successful":1 ...  and "error":3 in one period
```

Non-zero `successful` and non-zero `error` both appear in history, so a zero in a later window is a
REAL zero and not a dead counter. This satisfies the "every zero needs a positive control" rule for
every browser claim below.

BASELINE, taken after mission `57cc3b49` was launched, while it was still in `recon`:

```
docker logs --since 20m apolaki-headless-chrome-1
Current period usage: {"maxConcurrent":0,"error":0,"successful":0,"units":0,"totalTime":0}   x4 periods
```

Four consecutive 5-minute periods with zero browser sessions. Re-read at mission end and diffed
below.

---

## BOTH RENDERERS CARRY THE SECTIONS (MEASURED)

Rendered from the CURRENT deployment (`curl` against the live API), so this tests the deployed
renderer, not the tree. Archived mission `6ddc56f6` used as the fixture because it already has a
full log; the numbers inside are run 1's stale-platform numbers and are NOT the deliverable - only
the presence and wording of the sections is being checked here.

```
curl -s http://localhost:8000/report/6ddc56f6/md   -> 25551 bytes
curl -s http://localhost:8000/report/6ddc56f6/html -> 82985 bytes

grep -n -i "arsenal coverage|technique coverage" r1.md
341:## Arsenal coverage
354:## Technique coverage

grep -o -i "Arsenal coverage|Technique coverage" r1.html
Arsenal coverage
Technique coverage
```

**Both formats carry both sections.** The island run 1 warned about (markdown-only, absent from the
client-facing HTML) is closed, and `test_report_sections_reach_both_renderers` pins it.

### The sections are also READABLE - here is what they actually say

```
## Arsenal coverage
- Dispatched: 39 engine(s)
- Ran and found nothing: 29 - check_takeover, fetch_openapi, run_anomaly_scan, run_client_checks, ...
- Never dispatched this mission: 72
- Of those, unable to run at this permission tier: 32 - confirm_authz_write, ...
  Available but not selected: acquire_session, benchmark_lab, browser_navigate,
  confirm_browser_persona_bola, confirm_idor, confirm_read_object_idor, http_diff, http_read, ...
```

Two defects are visible in that output, and both are reporting-integrity defects rather than
arsenal gaps.

**Defect 1 - the report merges "ran and errored" into "ran and found nothing".** The report says 29
silent. My independent classifier over the same logs says 27 found-nothing + 2 ERRORED = 29. The two
it hides:

```
fetch_openapi         calls=10 ok=0  find=0 err=10  ERR=Response is not valid JSON (not an OpenAPI spec)
run_injection_probes  calls=11 ok=3  find=0 err=8   ERR=[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1010)
```

`fetch_openapi` failed on 10 of 10 dispatches and `run_injection_probes` on 8 of 11, and the
**Arsenal coverage summary** tells the client both "ran and found nothing". `report.arsenal_gap()`
defines `silent` as `calls>0 and findings==0` (`agent/report.py:1635`), which cannot separate a
clean result from a broken engine - the single most valuable distinction the section exists to draw.
The ledger DOES carry the data (`main._tool_ledger` tracks `error` and `scope_blocks` separately,
`agent/main.py:923-931`); `arsenal_gap` just does not read it.

**SCOPE OF THIS DEFECT, corrected after reading the HTML:** the per-tool ledger TABLE above the
summary is honest - it renders `fetch_openapi` as **FAILED** (red) and `run_github_recon` /
`run_transport_posture` as **SKIPPED** (amber). The defect is confined to the Arsenal-coverage
SUMMARY LINE, which rolls every one of those into "Ran and found nothing: 33". So a reader who
studies the 46-row table can recover the truth; a reader who reads the summary - which exists
precisely so they do not have to - cannot. Worth fixing, but it is a summary bug, not a wholesale
blindness.

**Two of the four silent failures are invisible even in the table.** `run_encoded_cookie` and
`run_form_xss` return `ok` on every call and record their TLS failure only in the note text, so they
render as **EXECUTED** in green with "0 finding(s)". No status field anywhere in the report marks
them as broken.

**Defect 2 - the report states the browser driver was "Available but not selected".** It lists
`browser_navigate` there. Per the crown-jewel section above, that engine has no loggable dispatch
path at all, so the report is making a positive claim about a fact it cannot observe. This is worse
than an omission: a reader sizing the engagement is told the browser was skipped by choice.

**Correctly handled (no defect):** `run_transport_posture` renders as
`skipped | SCOPE BLOCK: juice-shop:443 not in scope (host is in scope, but the operator pinned a
different port)`. That is the known-open Q-060 defect, and the REPORT's treatment of it is honest -
a scope block is shown as enforcement, not as a tool failure. Recorded, not re-diagnosed.

### Technique coverage section (rendered, deployed build)

```
- Techniques in the registry: 88 (87 transferable)
- Proven (a liveness run produced the artifact): 16
- Claimed (validated_on written by hand): 48
- Unverified claims (the honesty debt): 32
- Generalized (2+ resolvable labs AND a liveness artifact): 1
> Not measured here: which techniques ran against THIS target. Technique records carry no engine
> binding, so nothing connects a technique to the tools this mission dispatched.
```

This section is honest about its own limit, and that limit is severe: **it describes the PRODUCT,
not the engagement.** It cannot answer "which techniques did we use on this target", because no
technique record binds to an engine. 32 unverified claims against 16 proven is the real number to
carry forward.

---

## METHOD - how the four-way split is derived, and its positive control

The report's own `arsenal_gap()` cannot produce the four-way split (it merges C and D, see Defect 1),
so the classification is computed independently from the same persisted event log, replicating
`main._tool_ledger`'s aggregation and then splitting on `errors` / `scope_blocks` / `findings`.

Run as a stdin-piped script so that **no file is created inside the container**:

```
docker exec -i apolaki-agent-1 python - <SESSION_ID> < classify.py
```

POSITIVE CONTROL, printed before any classification, so no zero is trusted blind:

```
=== POSITIVE CONTROL ===
log rows by type: {'tool_call': 424, 'tool_result': 380, 'tool_error': 20, 'scope_block': 24,
                   'lead': 49, 'finding': 3, ...}
distinct tools seen in ledger: 39
top 12 by calls: [(54,'http_probe'), (29,'run_fingerprint'), (23,'run_xpath'), (23,'run_ssi'),
                  (23,'run_ldap'), (22,'run_dom_trace'), (18,'run_dom_audit'), (17,'run_xss'), ...]
ledger names that ARE registered engines: 39
ledger names NOT in TOOL_PERMISSIONS: []
```

The extraction demonstrably sees the engines that did run, resolves every one of them against the
registry, and invents none. A `SUM must equal 111` assertion is printed on every run so a
mis-classification cannot hide.

Cross-check against the deployed renderer on the same mission: the report says
`Dispatched: 39` / `Ran and found nothing: 29` / `Never dispatched: 72` / `tier-blocked: 32`; the
classifier says 39 dispatched, 27+2, 72, 32. **The two agree everywhere except the C/D split, which
is exactly the defect being reported.** That agreement is what makes the disagreement meaningful.

### "Never planned" is itself four different things

The single biggest distortion in the headline number. Sub-split, with the basis for each stated:

| sub-class | basis | is it a gap? |
|---|---|---|
| B0 UNMEASURABLE | MEASURED: absent from `planner.py`, only unlogged `tools.execute` call sites | unknowable, not a gap |
| B1 LLM affordance | not a vulnerability engine (`store_finding`, `mission_state`, ...) | no - `deterministic` never selects |
| B2 wrong service | HAND CLASSIFICATION by protocol; Juice Shop is HTTP-only | no - correctly idle |
| B3 REAL GAP | remainder: a web engine, permitted, applicable, never selected | **yes** |

B0 is MEASURED, B1 is definitional, **B2 is my judgement and is labelled as such, not as a
measurement.** B3 is the only number that answers Erwin's question.

MEASURED on the current binary, for the three B0 engines:

```
                    refs in planner.py    advertised in CLAUDE_TOOLS
browser_navigate            0                      True
acquire_session             0                      True
http_read                   0                      True
http_probe                  4                      True    <- has BOTH paths; count is a LOWER BOUND
run_dom_audit               1                      True    <- has BOTH paths; count is a LOWER BOUND
```

All three B0 engines are advertised to the model but absent from the planner, which explains the
design: they were built as LLM affordances and later wired into deterministic code paths by direct
`tools.execute` calls that nobody taught to log. Under `strategy=deterministic` the model never
selects anything, so **these three are guaranteed to render as "never dispatched" in every
deterministic mission Apolaki has ever run**, whether or not they executed. `http_probe` and
`run_dom_audit` have both logged and unlogged paths, so their ledger counts are lower bounds, not
totals.

### Applied to archived mission `6ddc56f6` (run 1, STALE binary - method demo, NOT the deliverable)

```
A. blocked_by_mode       32
B. never planned         40      B0 UNMEASURABLE 3 | B1 affordance 6 | B2 wrong service 11 | B3 REAL GAP 20
C. ran, found nothing    27      C1 really tested 26 | C2 NO-OP/unconfigured 1
D. ran and ERRORED        2
   productive            10
   SUM                  111
```

**The reader-facing headline "72 engines never dispatched" corresponds to a real, actionable gap of
20.** The other 52 are tier-blocked (32), unmeasurable (3), not engines (6), or aimed at services
this target does not run (11). Reporting 72 as the gap is as wrong as reporting 0.

These numbers are from the STALE-binary mission and are shown to demonstrate the method. The
deliverable is the same table computed on mission `57cc3b49`, below.

---

# THE DELIVERABLE - four-way classification, mission `57cc3b49`, denominator 111

Mission complete (`status=complete`, `phase=report`). Positive control printed on the same run:

```
log rows by type: {'tool_call': 411, 'tool_result': 370, 'tool_error': 18, 'scope_block': 24,
                   'finding': 37, 'lead': 49, 'info': 18, ...}
distinct tools seen in ledger: 46      (45 resolve to registered engines)
ledger names NOT in TOOL_PERMISSIONS: ['codeintel.review_source_tree']   <- a lane label, not an engine
top by calls: http_probe 54, run_fingerprint 29, run_xpath 21, run_ssi 21, run_ldap 21,
              run_dom_trace 20, run_dom_audit 18, run_xss 15, run_form_xss 12, run_client_checks 12
```

**THE TABLE (MEASURED, denominator 111 registered engines):**

| class | count | % of 111 | what it means |
|---|---|---|---|
| **A. blocked_by_mode** | **31** | 27.9% | could not run at `active`. NOT a gap. |
| **B. never planned** | **35** | 31.5% | permitted, never selected - but see the split |
| &nbsp;&nbsp;B0 unmeasurable | 3 | 2.7% | ledger-blind; unknowable, see crown jewel |
| &nbsp;&nbsp;B1 LLM affordance | 6 | 5.4% | not a vuln engine; `deterministic` never selects |
| &nbsp;&nbsp;B2 wrong service | 11 | 9.9% | HTTP-only target (my judgement, not measured) |
| &nbsp;&nbsp;**B3 REAL GAP** | **15** | **13.5%** | **web engine, permitted, applicable, never selected** |
| **C. ran and found nothing** | **28** | 25.2% | a RESULT, not a gap |
| &nbsp;&nbsp;C1 really tested | 26 | 23.4% | genuine clean result |
| &nbsp;&nbsp;C2 no-op / unconfigured | 2 | 1.8% | returned clean WITHOUT testing anything |
| **D. ran and ERRORED** | **4** | 3.6% | silent failure |
| scope-blocked (correct enforcement) | 1 | 0.9% | dispatched, every call refused by scope |
| productive | 12 | 10.8% | ran and produced findings |
| **SUM** | **111** | 100% | assertion printed on every run |

### Two corrections I had to make to my own numbers (recorded, not quietly fixed)

Both were caught by reading the rendered HTML ledger table against my classifier, and both moved
numbers I had already written down.

1. **A THIRD error channel exists.** Some engines never emit a `tool_error` row and instead report
   the failure inside a normal `tool_result` note. `run_encoded_cookie` ("fetch error: [SSL:
   WRONG_VERSION_NUMBER]", 6 calls) and `run_form_xss` ("form_xss error: [SSL: WRONG_VERSION_NUMBER]",
   12 calls) both return `ok` on every call while having failed. My first pass put them in C1
   "really tested". **D went 2 -> 4, C1 went 29 -> 26.**
2. **A scope-blocked engine is not a clean result.** `run_transport_posture` shows
   `calls=1 ok=0 sb=1`; my first pass required `calls==0` for the scope-block class, so it landed in
   C1. It tested nothing. **A separate scope-blocked class now holds it.** My earlier note in this
   file that "`run_transport_posture` did not appear at all this mission" was WRONG - it was
   dispatched via internal dispatch and refused by scope. Corrected here.

A third correction went the other way: my embedded-error regex initially matched the TARGET's own
`500 Error: Unexpected path ...` response body and put `http_probe` (48 findings) in the failure
bucket. Target responses are results, not engine errors; the pattern was tightened to engine-side
transport failures only and `http_probe` returned to `productive`. **Recorded because a
false-positive in the instrument is the same class of defect this lane exists to find.**

**`blocked_by_mode` = 31, not 0. The Q-051 mode-key fix is NOT regressed** - this is the first live
`active` mission to render a non-zero tier-block count, which was the specific regression check.

The honest single-sentence answer to Erwin: **of 111 registered engines, 15 (13.5%) are a real,
actionable arsenal gap on this target.** The reader-facing headline "66 never dispatched" overstates
it by more than 4x.

## B3 - the 15 that ARE the gap (MEASURED)

```
confirm_idor        run_cache_deception  run_cloud_probe   run_csrf        run_default_creds
run_external_surface run_hash_id         run_jsonp         run_jwt         run_metadata
run_saml            run_service_pack     run_session_fixation  run_whatweb  run_ws_hijack
```

**`run_jwt` is the headline.** Juice Shop's entire authentication is JWT and it ships JWT-forgery
challenges. It is ACTIVE tier, so permitted, and it never ran. It is not a coincidence: this
mission's own autonomy loop wrote, in the same log,

```
INFO: Autonomy loop closed - 37 confirmed finding(s) recorded ...
      next-best actions: soft_deleted_login, target_intel_harvest, weak_secret_forgery
```

**The platform independently concluded that `weak_secret_forgery` was a next-best action, and the
engine that performs it was never dispatched.** That is a concrete, evidenced effects-model gap -
the ranking model and the dispatch vocabulary do not meet. This is the single most actionable item
in this handoff after the crown jewel, and it is a Coordinator/planner ticket, not this lane's file.

## D - the 4 silent failures (MEASURED)

```
fetch_openapi         calls=10 ok=0  find=0 err=10  ERR=Response is not valid JSON (not an OpenAPI spec)
run_injection_probes  calls=9  ok=3  find=0 err=6   ERR=[SSL: WRONG_VERSION_NUMBER] wrong version number
run_encoded_cookie    calls=6  ok=6  find=0 err=0   NOTE=fetch error: [SSL: WRONG_VERSION_NUMBER] ...
run_form_xss          calls=12 ok=12 find=0 err=0   NOTE=form_xss error: [SSL: WRONG_VERSION_NUMBER] ...
```

`fetch_openapi` and `run_injection_probes` are the same two run 1 found, so those are reproducible
across builds and not a one-off. `fetch_openapi` failed on 10 of 10 dispatches.

**Three of the four are the same TLS error**, and the mission gives strong evidence for why. The
rendered ledger shows `run_header_trust` reporting `"origin": "https://juice-shop:3000"` - an
`https` scheme against a plaintext port, on a scope the operator pinned as `http://juice-shop:3000`.
A TLS handshake to a cleartext port is exactly `WRONG_VERSION_NUMBER`. This is consistent with the
already-open **Q-060** origin-rebuild defect (`agent/agent.py:2355`/`:2395`). **Recorded as
supporting evidence for Q-060's owner; NOT re-diagnosed here per the lane brief.** If Q-060 is
fixed, expect these three engines to start actually testing - which would make it a coverage fix,
not just a correctness fix.

`run_encoded_cookie` and `run_form_xss` are the more dangerous shape: they return `ok` on **every**
call while having failed on all of them, so they are invisible even to the ledger's own FAILED
status. Only their note betrays them.

The HTML ledger TABLE does render `fetch_openapi` as **FAILED** (red) - see Defect 1 for the precise
scope of what is and is not misreported.

## C2 - engines that returned clean WITHOUT testing anything (MEASURED)

```
run_github_recon  calls=8 ok=8  NOTE=Skipped - set BBH_GITHUB_TOKEN ... to enable
run_bfla          calls=3 ok=3  NOTE=0 authorization signal(s); BFLA method differential NOT RUN -
                                     no identity available (no session= role, no headers, no mi...
```

`run_bfla` deserves a ticket. It reports "no identity available" **in a mission where identities
demonstrably existed** - `run_authz_matrix` ran in the same mission with
`roles: ["anonymous","user_a","user_b"]` and confirmed 35 findings. So two engines in one engagement
disagree about whether the engagement has personas. UNVERIFIED as to cause (identity plumbing not
reaching `run_bfla`, or a different identity lookup); flagged, not diagnosed.

Both are counted by the report as "ran and found nothing", i.e. as coverage. They are not coverage.

## Q-060 rows, recorded not re-diagnosed (MEASURED)

```
http_probe   calls=54 ok=48 sb=6  SCOPE BLOCK: hostmaster.hostmaster.hostmaster.juice-shop:443
                                  not in scope (host is in scope, but operator pinned a different port)
run_katana   calls=8  ok=2  sb=6  same
```

Port 443 invented against a scope pinned to `:3000`, exactly as briefed, plus a mangled
`hostmaster.hostmaster.hostmaster.` label from DNS enumeration. `run_transport_posture` did not
appear at all this mission. Recorded for the Q-060 owner.

---

# THE BROWSER / DEVTOOLS HALF OF ERWIN'S QUESTION

## What the browser engines actually did (MEASURED, mission `57cc3b49`)

```
confirm_browser_persona_bola  calls=1  ok=1  find=1  via=internal
     -> {"ran": true, "counts": {"requests": 95, "candidates": 1, "probes": 1, "confirmed": 1}}
run_dom_trace                 calls=20 ok=20 find=0
run_dom_audit                 calls=18 ok=18 find=0
run_client_checks             calls=12 ok=12 find=0
run_js_review                 calls=1  ok=1  find=20
browser_navigate              IDLE  <- MEASUREMENT ARTIFACT, see crown jewel; not a result
```

**The browser world is NOT idle.** `confirm_browser_persona_bola` - the Browser Intelligence Engine's
runtime persona-swap BOLA - drove two real browser contexts, issued 95 runtime requests, and
produced 1 CONFIRMED cross-user finding. In run 1's mission that engine was IDLE; on the current
build it fires. `run_dom_trace` (20) and `run_dom_audit` (18) ran a real DOM source-to-sink pass and
returned clean, which is a RESULT.

So the answer to "is the browser being used like an advanced genius pentester" is: **yes for the
runtime BOLA and DOM engines, and unmeasurable for the browser DRIVER.**

## THERE ARE TWO BROWSER WORLDS, AND ONLY ONE IS USED (MEASURED)

This is the second substantive finding of the lane, and it changes what "the browser sidecar is up"
means.

**World 1 - a LOCAL chromium inside `apolaki-agent-1`.** Every browser call site in the engine code
launches its own browser:

```
grep -n "pw.chromium.launch" agent/tools.py   -> 380, 3029, 4416, 4538, 4936, 5291, 5523, 9445   (8)
grep -n "p.chromium.launch" agent/bie.py      -> 1550, 1767                                       (2)
grep -rn "connect_over_cdp" agent/            -> NOTHING
```

Verified the binary is really there:

```
docker exec apolaki-agent-1 python -c "...p.chromium.executable_path..."
chromium executable: /opt/pw-browsers/chromium-1234/chrome-linux64/chrome
exists: True
```

**World 2 - the REMOTE `apolaki-headless-chrome-1` browserless sidecar**, reached over
`CDP_BROWSER_URL` by `browser_engine.drive()` (POSTs a script to `/function`) and `cdp.py`. Its
consumers are `agent.py:3407` (`_browser_harvest_surface`, the JS-rendered crawl), `main.py` (4
sites), `proxy.py`, and `juiceshop_solvers.py`.

**The two worlds share no code.** `run_dom_trace`, `run_dom_audit`, `run_xss`'s browser confirmation,
`browser_navigate` and the whole BIE all live in World 1 and never touch the sidecar.

### MEASURED: the sidecar served zero sessions for the entire mission

```
docker logs --since 60m apolaki-headless-chrome-1 | grep -o '"successful":[0-9]*,"timedout"' | sort | uniq -c
     12  "successful":0,"timedout"
```

Twelve consecutive 5-minute periods, all zero, spanning the whole mission.

POSITIVE CONTROLS, both required before believing that zero:

1. *The counter is alive.* History in the same file shows `"successful":8`, `6`, `5`, `1` and
   `"error":3` in earlier periods, so it does record real sessions.
2. *The sidecar is functional NOW, from inside the agent container.* Driven directly:

```
docker exec -i apolaki-agent-1 python - <<'PY'
import browser_engine as be
js = "export default async function ({ page }) { await page.goto(%TARGET_JSON%, ...); return { data: { title: await page.title() }, ...}; }"
print(be.drive("http://juice-shop:3000", js))
PY
-> keys: ['title']            # the script executed against the live lab and returned page data
```

3. *That drive REGISTERED on the counter.* This is the control that actually closes the argument -
   it proves the instrument responds to the exact kind of call the mission would have made. The
   next 5-minute flush after the drive above:

```
docker exec apolaki-headless-chrome-1 sh -c 'tail -c 900 /tmp/browserless-metrics.json'
{... "successful":0, "units":0, "date":1786959726688}      <- during the mission
{... "successful":0, "units":0, "date":1786960026658}      <- during the mission
{... "sessionTimes":[1572], "successful":1, "units":1, "maxConcurrent":1, "date":1786960326636}
                                                            ^ my manual drive(), one period later
```

Zero, zero, then one the moment a real call was made. **So the twelve zero periods across the
mission are a real zero, measured on an instrument proven to respond.**

So the sidecar is reachable, healthy, correctly configured (`CDP_BROWSER_URL=http://headless-chrome:3000`),
and demonstrably able to serve Apolaki's own `browser_engine.drive()`. **It simply was not used
during the mission.** The only code that would use it in a deterministic run is
`_browser_harvest_surface`, and it produced no session.

### What this means for Erwin's question

The sidecar being "up" is not evidence the browser world is engaged, and run 1's finding that
`CDP_BROWSER_URL` and all three endpoints are reachable from the agent container - while correct -
does not imply use. Reachability was measured; consumption was not. The engines that do the real
browser work run their own local chromium and would behave identically if
`apolaki-headless-chrome-1` were stopped.

Two consequences worth a ticket, neither of them this lane's to write:

- **The JS-rendered crawl (`_browser_harvest_surface`) contributed nothing to this mission.** On an
  Angular SPA like Juice Shop that is the pass most likely to surface client-rendered parameterized
  endpoints for the injection engines. Whether it was entered at all is UNVERIFIED (see limit
  below); what is measured is that it drove no browser session.
- **One of the two browser worlds is redundant infrastructure.** Either the engines should be moved
  onto the shared sidecar (one browser, poolable, resource-capped, observable from outside) or the
  sidecar should be dropped from the default stack. Running both means the platform pays for a
  browser it does not use while spawning unpooled chromium processes inside the agent container.

### Honest limit on this specific claim

I could NOT confirm from the mission log whether `_browser_harvest_surface` was entered. It yields
an info event either way ("JS-rendered crawl: N ... surfaced" or "JS-rendered crawl skipped"), and
**neither string is in the persisted log** - but neither is `_run_deterministic`'s own opening info
line, which certainly did execute. **Therefore `main.py` does not persist every `info` event, and
absence of that string is NOT evidence.** I nearly reported it as one. The sidecar-side zero stands
on its own instrument; the agent-side reason for it is UNVERIFIED.

## Defect 3 (NEW, MEASURED) - the ledger-disagreement warning is a naming false positive

Mission `57cc3b49`'s rendered report carries a red warning box:

```
> WARNING Ledger disagreement: `browser_persona_bola`, `xss` produced findings but the tool ledger
> has no record of running them. Two independent records of this mission do not agree.
```

Both engines ran. The disagreement is a PREFIX CONVENTION:

```
finding engine values: Counter({'browser_persona_bola': 1, 'xss': 1})
engine browser_persona_bola  in_ledger_exact=False  ledger has confirm_browser_persona_bola = True
engine xss                   in_ledger_exact=False  ledger has run_xss                      = True
```

Findings carry the `ToolResult` name (`agent/tools.py:2718` returns `ToolResult("browser_persona_bola", ...)`)
while the ledger carries the DISPATCH name (`confirm_browser_persona_bola`). `report.arsenal_gap()`
already compensates with `n.replace("run_", "")` (`agent/report.py:1658`);
`report.ledger_finding_disagreement()` (`agent/report.py:1685-1692`) does no normalization at all.

Impact: the client-facing report accuses the platform of an integrity failure on **every mission in
which a `confirm_*` or prefix-renaming engine produces a finding** - which is exactly the missions
where the crown-jewel engines worked. It also devalues the cross-check: a reader who learns the
warning is usually spurious will ignore the one time it is real.

Suggested fix (NOT applied - `agent/**` is not this lane's): normalize both sides through one
shared helper before comparing, and give it a negative control that a genuinely unlogged engine
still trips the warning.

### Suggested patch (NOT applied - `agent/**` is not this lane's to write)

Move the logging into `Tools.execute()` so the ledger records the fact rather than the wrapper, and
delete the now-redundant `db.add_log` in `_exec_internal`. The negative control that would have
caught this: assert that an engine dispatched ONLY via a direct `self.tools.execute` call appears in
`_tool_ledger()`. Every existing test dispatches through `_run_tool` or `_exec_internal`, so the
whole suite is green on a ledger that misses five engines.

---

# THE HONEST LIMITS OF WHAT THESE ARTIFACTS ALLOW

Stated plainly, because every number above is bounded by one of these.

1. **The ledger is not a record of dispatch; it is a record of two wrappers.** Five engines
   (`browser_navigate`, `acquire_session`, `http_read`, `http_probe`, `run_dom_audit`) have
   unlogged dispatch paths. For the first three that is the ONLY path, so they are unmeasurable;
   for the last two, every count in this document is a LOWER BOUND. No conclusion of the form
   "engine X never ran" is safe for those five, and I have not drawn one.
2. **One mission, one target, one mode, one strategy.** Everything here is
   `juice-shop:3000` / `active` / `deterministic` / `auto_approve+authenticated_scan`. B2 ("wrong
   service", 11 engines) would collapse to near zero on a multi-protocol host, and B1 (6 LLM
   affordances) would change entirely under `low_ai`/`agentic`, where the 35 unadvertised engines
   become a live selection question rather than an informational axis. **These proportions do not
   generalize to another target or another strategy** and must be re-measured, not scaled.
3. **B2 is judgement, not measurement.** I classified 11 engines as aimed at services this target
   does not expose, by name. That list is auditable and stated in full in the method section, but it
   was not derived from a port scan of the target. If it is wrong, it is wrong in the direction of
   UNDER-reporting the gap - a mis-parked engine belongs in B3.
4. **`info` events are not fully persisted, so absence of a log line proves nothing.** Confirmed the
   hard way: `_run_deterministic`'s own opening info line is missing from a mission that certainly
   ran it. I nearly reported "the JS-rendered crawl never ran" on that basis. Any future lane
   reading these logs should treat missing `info` strings as no evidence at all.
5. **"Ran and found nothing" is not the same as "tested".** C2 (2 engines) returned clean without
   testing anything, and 2 more in D returned `ok` on every call while failing on every call. The
   ledger's own `ok` counter cannot be trusted as a measure of work performed; only the note text
   distinguishes them, and note text is not a structured field.
6. **Technique coverage is a product statistic, not an engagement one.** The report says so itself.
   Nothing in these artifacts can answer "which techniques were applied to this target", because no
   technique record binds to an engine.
7. **The warm start is a confound I did not isolate.** `/engage` reported
   `warm_start: {seeded: true, subdomains: 6, endpoints: 1001, prior_findings: 3, assets_known: 1010}`.
   Recon engines may have been short-circuited by cached knowledge from earlier scans of this
   target, which would depress the dispatch counts of discovery engines specifically. A cold-target
   run would separate this; it was not done.

## What I did NOT do

- Did not touch `agent/**`, `docs/QUEUE.md`, `docs/STATUS.md`, `docs/LEDGERS.md`. All patches above
  are suggestions in this file only.
- Did not run `docker compose build` (the image was already current; a build kills running missions).
- Did not run the pytest suite - this lane measured a live deployment rather than changing code, so
  there was nothing of mine for it to gate.
- Did not touch Q-052 (whether `active` should permit more) - an open product question for Erwin.
- Did not re-diagnose Q-060; recorded its rows and the supporting TLS evidence for its owner.

## Handover - ranked, with the reason each is ranked there

1. **Log dispatch in `Tools.execute()`, not in its two wrappers.** Until this lands, no arsenal
   measurement on this platform can be trusted, including this one. It is also the cheapest fix
   here. Needs the negative control described above or it will regress silently.
2. **`run_jwt` never fires on a JWT-authenticated target while the platform's own autonomy loop
   names `weak_secret_forgery` as a next-best action.** A concrete effects-model gap with the
   evidence already captured in the mission log. This is the highest-value FINDING gap.
3. **Fix Q-060.** Three of four silent failures are the same `WRONG_VERSION_NUMBER` TLS error, and
   `run_header_trust` is on record building `https://juice-shop:3000`. Fixing it converts four
   engines from broken to testing - a coverage win, not just a correctness win.
4. **Make `arsenal_gap()` read the error and scope-block counters `_tool_ledger` already keeps**, so
   the summary stops calling broken engines clean. Add a status for engines that report failure only
   in note text (`run_encoded_cookie`, `run_form_xss`), which no status field currently catches.
5. **Normalize engine names in `ledger_finding_disagreement()`.** It currently cries wolf on exactly
   the missions where the browser engines succeed.
6. **Decide the two-browser-worlds question.** Either move the engines onto the sidecar or drop the
   sidecar from the default stack. Today the platform runs both and uses one.
7. **`run_bfla` reports "no identity available" in a mission with two verified personas.** Cause
   UNVERIFIED; worth one session of someone's time.
