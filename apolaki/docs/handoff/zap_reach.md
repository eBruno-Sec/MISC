# Q-023 · ZAP reachability lane — measured findings

Lane: **ZAP-reachability** (Breaker first). Baseline `505ed1c` (3366 passed / 11 skipped / 12 xfailed
/ 0 failed). Written as the work happens; every claim carries the probe that produced it.

---

## Headline

**The ticket's central sentence is half true, and the false half is the important one.**

- TRUE: **zero `run_zap` rows exist in the durable corpus**, across all 154 missions.
- **FALSE: "a whole scanner … has produced nothing."** `tools._run_zap` executes, drives the daemon,
  and produces alerts. The ZAP daemon carries **191 alerts, 16 `bbh-*` contexts and a FINISHED spider
  scan** created by `_run_zap`'s own context-naming code. The engine is not dead and is not an island.

The two facts are reconciled by an **apparatus defect, not an engine defect**: the acceptance test
that drives ZAP through a real full mission writes to a `tmp_path` SQLite file and is `skipif`-gated
off by default. It is therefore **structurally incapable of depositing a row in the corpus the ticket
counted**. This is the Q-062 shape one layer over: the measurement channel could not observe the
success even when the success happened.

---

## Measurement channel, with the positive control demanded before any zero

Probe (throwaway container, named volume mounted exactly as production does it):

```
docker run --rm -v "apolaki_bbh_data:/data" … python  →  db at /data/bbh.db
```

| control | expected (brief) | measured | verdict |
|---|---|---|---|
| findings rows | 1773 | **1773** | channel live |
| mission rows | 154 | **154** | channel live |
| `tool_call` rows | 29,945 | **29,945** | channel live |
| unparseable `tool_call` | 0 | **0** | channel live |
| `run_fingerprint` calls | (nonzero) | **2,699** | counter works |
| `http_probe` calls | (nonzero) | **4,650** | counter works |
| **`run_zap` calls** | — | **0** | absence is real |

The bare-`agent:/app` false-zero failure mode is excluded: the same query in the same container
returns the four expected positive controls exactly.

### The absence is upstream of dispatch, not a blocked dispatch

Swept **every** `etype`, not just `tool_call` (16 etypes, 66,395 rows):

- `run_zap` in `tool_call`: **0**
- `run_zap` in `scope_block` (3,506 rows): **0** — top blocked tools are `http_probe` 1035,
  `run_sourcemap` 501, `run_form_cmdi` 318, `run_nuclei` 99. ZAP is absent.
- `run_zap` in `tool_error` (403 rows): **0** — `fetch_openapi` 215, `run_injection_probes` 84.

So `run_zap` was never dispatched, never scope-blocked, and never errored **inside a mission**. It
never reached the dispatcher. Nothing rejected it; nothing ever offered it.

---

## The ZAP-side claim is the opposite of the mission-side claim

A mission-side zero and a ZAP-side zero are different claims. Both were taken.

**First probe was WRONG and is recorded as such.** Unauthenticated `GET /JSON/core/view/version/`
returns `RemoteProtocolError: Server disconnected without sending a response` on all nine endpoints —
which reads exactly like a dead daemon. It is not. ZAP 2.17 drops unauthorized API connections
without a response body. The daemon runs with `-config api.key=bbh-zap`. Re-probed with the key:

```
core/view/version         200 {"version":"2.17.0"}
core/view/numberOfMessages 200 {"numberOfMessages":"447"}
core/view/numberOfAlerts   200 {"numberOfAlerts":"191"}
core/view/sites            200 ["http://apolaki-zap-lane7-live:42888","http://domsource:8080"]
spider/view/scans          200 [{"progress":"100","id":"11","state":"FINISHED"}]
ascan/view/scans           200 []
context/view/contextList   200 16 contexts, all "bbh-*"
```

**Attribution of those contexts to Apolaki code is exact, not inferred.** `agent/tools.py:10301`:

```python
name = f"bbh-{self.mission_id or 'x'}-{os.urandom(2).hex()}"
```

Every one of the 16 contexts matches that template. They partition into:

| context shape | count | producer |
|---|---|---|
| `bbh-zap-rate-live-*` | 10 | `test_zap_rate_policy` / live rate harness (`mission_id="zap-rate-live"`) |
| `bbh-lane7-live-468e` | 1 | lane 7 live harness |
| `bbh-05a27c3d-fb00`, `bbh-628976e3-a28c`, `bbh-c2f8a55c-9185`, `bbh-49d413bb-5066` | 4 | **real `main.engage` missions** — 8-hex session ids |

Those four ids are **absent from the missions table** — checked directly, all four return
`NO MISSION ROW`. They are real missions created by `main.engage(...)` inside
`test_zap_live_acceptance.test_real_full_mission_persists_run_zap_tool_call`, whose fixture does
`db.init(str(tmp_path / "zap-live-mission.db"))`. The mission was real; the ledger it was written to
was thrown away with the temp directory.

**`numberOfMessages` remains a contaminated oracle** and is not used here: the ticket recorded 4,411,
today it reads 447 (the daemon restarted 7 days ago). The oracle used is a `run_zap` `tool_call` row
plus daemon-side context/alert attribution, exactly as the ticket requires.

---

## Status of the ticket's "three flags"

Two of the three have already moved since the ticket was written; only one is still as described,
and it is a deliberate default rather than a defect.

| flag (as filed) | current code | verdict |
|---|---|---|
| `tools.py:138 "run_zap": PermissionLevel.INTRUSIVE` | **`tools.py:232 PermissionLevel.ACTIVE`** | **stale — fixed.** The tier gate the ticket calls "sufficient on its own" no longer exists. |
| `main.py:336 if enable_zap and req.mode != "full": 422` | `main.py:519`, unchanged | live, and **deliberate** — a DAST pass is Full-mode work |
| `main.py:81 enable_zap: bool = False` | `main.py:81`, unchanged | live, and **deliberate** — the ticket itself forbids changing the default |

`planner.py:963-978` schedules `run_zap` in phase F2 gated on `zap_on` and `_HEAVY_FULL_ONLY`. It is
named at 5 sites in `agent.py` and 5 in `planner.py`, so this is **not** the Q-050 island shape,
confirmed.

Q-050's distinction applied: ZAP is **reachable from the deterministic scheduler and has been reached**
(4 real missions drove it to the daemon). It is *not* unreachable. What is missing is a durable
recording of that fact.

---

## Anti-idle: which standing labs has any mission ever targeted?

Same island question one layer down. Measured over all `tool_call` / `finding` / `info` rows, counting
**distinct missions** per target host:

| lab container (up 7 days) | missions that targeted it |
|---|---|
| `juice-shop` | 36 |
| `vampi` | 15 |
| `juice-shop-bench` | 14 |
| `owaspbench` | 7 |
| `dvga` | 4 |
| `dvwa` | 3 |
| `bwapp` | 1 |
| **`webgoat`** | **0** |
| **`mutillidae`** | **0** |
| **`domsource`** | **0** |
| **`clientauthz`** | **0** |
| **`benchmarkpython`** | **0** |
| **`sessionlife`** | **0** |
| **`conpot` / `dnp3-outstation` / `snmpd` / `smb` / `openldap`** | **0** |

(External, in-scope: `ginandjuice.shop` 48 missions.)

**Twelve standing lab containers have never been the target of a single mission.** `webgoat` has
additionally been `unhealthy` for 7 days and nobody noticed, because nothing has ever pointed at it.
That is the same cost-with-no-capability shape as the ZAP ticket, and it is larger.

---

## The verdict: ZAP executes in a real full mission on today's code

The `skipif`-gated oracle was run rather than left skipped, because **SKIPPED is never a pass**:

```
ZAP_LIVE_ACCEPTANCE=1 ZAP_LIVE_TARGET=http://domsource:8080 \
  pytest tests/test_zap_live_acceptance.py
→ 1 failed, 1 passed in 163.95s
```

`test_real_full_mission_persists_run_zap_tool_call` **PASSED**. Verbatim evidence it printed:

```json
{"mission_id": "4f14866f", "status": "complete",
 "tool_call":   {"type":"tool_call","tool":"run_zap","permission":"active",
                 "input":{"url":"http://domsource:8080","policy":"passive",
                          "speed":"normal","aggression":"normal"},
                 "ts":"2026-08-20T23:05:19.174633+00:00"},
 "tool_result": {"type":"tool_result","tool":"run_zap","count":4,
                 "output":"policy=passive; speed=n/a; aggression=n/a; target-rate<=1rps; \
4 ZAP alert(s) [passive] (from 4 current raw) [187 retained alert(s) excluded]",
                 "ts":"2026-08-20T23:07:06.811431+00:00"}}
```

**All three of Q-023's stated oracle assertions are satisfied:**

1. ≥1 `tool_call` row with `tool == "run_zap"` — present, `permission: active`.
2. Paired `tool_result`, `success`, note begins with a policy token — `policy=passive; …`.
3. Mission reached `status: complete`.

The one FAILED test is unrelated to the mission path:
`test_real_zap_retry_after_aborts_before_a_second_target_request` raises
`KeyError: 'ZAP_LIVE_SELF_HOST'` — an env var the live rate harness needs and I did not set. It is a
harness-input gap, not a ZAP defect. **It should not be a bare `KeyError`**; see the patch list below.

`[187 retained alert(s) excluded]` is worth calling out as a control that *works*: the pass-cursor
attribution refuses to claim the 187 alerts left on the shared daemon by earlier harnesses, and counts
only the 4 raised after this pass began. A lesser implementation would have reported 191 findings.

**The alerts are real, not empty ceremony.** Queried from the daemon for that base URL:

| risk | alert | CWE |
|---|---|---|
| Medium | Missing Anti-clickjacking Header | CWE-1021 |
| Medium | Content Security Policy (CSP) Header Not Set | CWE-693 |
| Low | Server Leaks Version Information via `Server` header | CWE-497 |
| Low | X-Content-Type-Options Header Missing | CWE-693 |

### So the ticket's headline is answered

> "ZAP has never executed in any mission, and three flags do not explain it."

Corrected against measurement:

- **ZAP executes in a real full mission on today's code.** Proven above, end to end, `complete`.
- Two of the three flags are **stale** (`INTRUSIVE` → `ACTIVE`) or **deliberate and protected by the
  ticket itself** (`enable_zap` default off; Full-mode 422).
- The reason the **corpus** shows zero is neither a flag nor an island. It is that **the only code path
  that has ever run ZAP through a mission writes its ledger to `tmp_path`**, so the durable corpus is
  structurally incapable of recording it. That is the "fifth cause" for the modern code.

### The fifth cause for the four 2026-07-26 residue missions is separate, and it is NOT ZAP-specific

All four residue missions reproduce exactly as filed (`enable_zap` truthy, `run_zap` 0). The
discriminating measurement the ticket did not take:

| mission | tool_calls | run_zap | **run_nuclei** | **run_nmap_vuln** | phases |
|---|---|---|---|---|---|
| c7bfe8e8 | 222 | 0 | **0** | **0** | recon,recon,enum,probe,scan,probe,enum,probe,report |
| ce35b361 | 222 | 0 | **0** | **0** | (identical) |
| 6771ec21 | 333 | 0 | **0** | **0** | (identical) |
| 94e8b564 | 375 | 0 | **0** | **0** | (identical) |

**Every phase-F tool is absent from all four, not just ZAP.** `run_nuclei` is not gated on `zap_on`,
not on `_zap_configured()`, and not on any ZAP flag — so no ZAP-specific hypothesis can explain its
absence. The four missions ended at `probe → report` and **the plan loop never entered phase F at
all**. The cause is a plan-loop termination condition, and ZAP was simply downstream of it.

This retires all three of the ticket's candidate hypotheses (`enable_zap` propagation,
`_zap_configured()`, `_graph_primary_state`) as *insufficient on their own*: each is ZAP-specific, and
the evidence is not.

---

## Q-023's three sub-defects, measured against code rather than against markers

| # | sub-defect as filed | measured now | verdict |
|---|---|---|---|
| 1 | `recon["zap"]` is a dead write (`tools.py:8470`) | `grep` for `recon.setdefault("zap"` / `recon["zap"]` / `recon.get("zap")` across `agent/*.py` returns **nothing** — writer and all candidate readers gone | **CLOSED** |
| 2 | targeted rescan not wired — one `run_zap:{h}` key per host, ever | `planner.py:976` still `f"run_zap:{h}"`, single occurrence | **LIVE** (planner.py, not mine — see below) |
| 3 | AJAX spider fails silently behind `except: pass` | `tools.py:10402` is now `except Exception as exc: degraded.append("AJAX spider degraded: %s: %s" % …)`, mirroring the `ascan_err` idiom the ticket asked for | **CLOSED** |

Sub-defect 3 is not merely present in source — it was **observed working in production output** this
session: the durable mission's note carried `active scan degraded, passive alerts kept: active scan
incomplete or timed out`. A degradation the old code would have swallowed is now the thing that
exposed a flaw in my own proposed gate.

**Sub-defect 2 remains open and belongs to whoever owns `planner.py`.** The step key is the host, so
`fresh()` (`planner.py:219-234`) drops any later `run_zap` step for a host already scanned — one ZAP
pass per host per mission, forever. A second, narrower pass against a path discovered *after* the
first pass is unrepresentable. Minimal patch, preserving the existing once-per-host default:

```python
# planner.py:975-976 — today the key is the host, so a narrower rescan can never be scheduled.
z_steps = [_step("run_zap", {"url": _b(h), "policy": _zpol, "speed": _zsp, "aggression": _zag},
                 f"run_zap:{h}") for h in host_bases[:CAP_ZAP]]
# → make the key carry what makes the pass DIFFERENT, so a re-scan of the same host with a
#   different scope/policy is a distinct step while an identical repeat is still deduped:
z_steps = [_step("run_zap", {...}, f"run_zap:{h}:{_zpol}:{_scope_digest(h)}") for h in …]
```

Do not land that without a bound: `CAP_ZAP` currently caps hosts, and a per-scope key makes the step
count grow with discovery. The ticket's own mutation test applies — remove the key change and the
second pass must disappear.

---

## The oracle and all four negative controls, from real missions

| | requirement | result |
|---|---|---|
| Oracle 1 | ≥1 `run_zap` `tool_call` row in the persisted log | **PASS** — `b226bc05`, `permission: active`, durable corpus |
| Oracle 2 | paired `tool_result`, success, note begins with a policy token | **PASS** — `policy=safe_active; speed=normal; …`, `errors: 0` |
| Oracle 3 | report's ZAP state derived from the RESULT, not the request flag | **PASS** — `_tool_ledger("b226bc05")["zap_status"] == "executed_safe_active"`, parsed out of the note |
| Control (a) | a ZAP-off mission claims nothing | **PASS** — `_tool_ledger("ebd96f45")["zap_status"] == "user_disabled"`, and 0 `run_zap` rows |
| Control (b) | daemon stopped ⇒ visible degradation, not a silent skip or crash | **NOT RUN** — deliberately. Stopping `apolaki-zap-1` is a shared-service restart and two other lanes plus the Coordinator are live on this network. The code path is `require_zap` → `zap_client.health()` → `HTTPException(422)` at `main.py:538-545`, i.e. fail-closed at engage time. Verify under a lane that owns the daemon. |
| Control (c) | AJAX spider forced to raise ⇒ note says so, passive alerts survive | **PASS** — covered by `test_zap_invocation.py:199`, and independently observed live in the degraded note above |
| Control (d) | non-vacuity: the mission really completed and did real work | **PASS** — `b226bc05` reached `status: complete, phase: report`; the ZAP step alone spent 6m51s and ZAP's own `ascan` recorded `reqCount=302` |

Control (a) is worth a second look because it is the one that would have hidden the ticket: a ZAP-off
mission reports `user_disabled` rather than the ambiguous `not_invoked`. `not_invoked` is reserved for
*enabled but never scheduled* — which is precisely the state Q-023 was filed about, and the report can
now say so out loud.

---

## Recommendation: **KEEP ZAP.** Do not remove it.

The removal option the brief offers is not supported by the evidence. A scanner nobody can reach is
cost with no capability — but ZAP **is** reachable, **does** run end to end, produces attributed
alerts with a working anti-contamination cursor, is correctly tiered `ACTIVE`, is fenced to a
per-mission ZAP context, honours the shared target rate policy, and fails closed under `require_zap`.
The defect is in the *recording*, not the *capability*.

---

## The corpus number is no longer zero — driven through the LIVE agent, not a test

The `tmp_path` finding above says the ticket's zero is an artefact of where the ledger was written.
The way to prove that is to write one to the ledger everybody counts. Driven through the running
`apolaki-agent-1` over its own HTTP API (no rebuild, no restart, no service touched):

```
GET  /zap/status  → {"state":"ready","label":"ZAP Ready (v2.17.0)","configured":true,"running":true}
POST /engage      {"mode":"full","enable_zap":true,"require_zap":true,
                   "zap_policy":"safe_active","strategy":"deterministic",
                   "in_scope":["http://domsource:8080"]}    → session b226bc05
POST /run/b226bc05                                          → {"ok":true,"status":"running"}
```

The live agent's baked image was checked against the working tree **before** trusting the result, so
this measures shipped code and not my editor:

```
tools.py      5ee12b70…  ==  agent/tools.py      5ee12b70…
planner.py    1319d5f8…  ==  agent/planner.py    1319d5f8…
zap_client.py 1d62d53c…  ==  agent/zap_client.py 1d62d53c…
```

Result, read back from `apolaki_bbh_data:/data/bbh.db` — the same volume, same query, same script that
returned `0` at the top of this document:

```
b226bc05  tool_call  2026-08-20T23:11:42Z
  {"tool":"run_zap","permission":"active",
   "input":{"url":"http://domsource:8080","policy":"safe_active",
            "speed":"normal","aggression":"normal"}}
TOTAL run_zap rows in durable corpus: 1
```

The mission then reached `status: complete, phase: report`, and the paired result landed too:

```
b226bc05  tool_result  2026-08-20T23:18:33Z
  {"tool":"run_zap","count":0,
   "output":"policy=safe_active; speed=normal; aggression=normal; target-rate<=1rps; …
             [191 retained alert(s) excluded; active scan degraded, passive alerts kept:
              active scan incomplete or timed out]"}
TOTAL run_zap rows in durable corpus: 2
```

ZAP context `bbh-b226bc05-7844` was created on the daemon by that mission, matching
`tools.py:10301`. **The ticket's headline count is now falsified by construction**: a real mission,
driven by the live agent, in Full mode, reached phase F2, dispatched `run_zap`, completed, and the
corpus recorded both rows. The scanner is reachable and the ledger can see it.

Note the note. `active scan degraded, passive alerts kept: active scan incomplete or timed out` is
Q-023 sub-defect 3 working as specified — a degraded sub-phase **surfaced in the ToolResult** instead
of swallowed. The bare `except: pass` the ticket complained about is gone and its replacement is
visibly doing its job in production output. That same note is what exposed the `min_alerts` trap
below, so the honest reporting paid for itself within one run.

---

## Patch list for lanes that own the files (I do not own these)

**P1 — `agent/tests/test_zap_live_acceptance.py` (I own `agent/tests/`, so this one is mine to fix).**
`os.environ["ZAP_LIVE_SELF_HOST"]` raises a bare `KeyError` that reads like a ZAP failure. It should
skip with an actionable reason, exactly as the module already does for `ZAP_LIVE_ACCEPTANCE`.

**P2 — the liveness entry the DoD asks for. READ THIS BEFORE WRITING IT: the obvious version is a
mis-specified oracle that reports DEAD on a working ZAP.** `agent/liveness.py` is Coordinator-owned,
so the patch is here rather than applied.

First, what is already done and needs nothing: `main._missing_zap_invocation` (`main.py:2842-2859`)
already fails a ZAP-enabled mission closed when no `run_zap` row was persisted, and **both halves are
already tested** — `test_zap_invocation.py:317` (fires when the row is missing) and `:339` (a
zap-off mission still completes with an unchanged log stream). That part of the DoD is closed.

What is missing is a liveness CHECKS entry. **ZAP is absent from `liveness.py` entirely** — `grep -i
zap agent/liveness.py agent/liveness_run.py` returns nothing.

**The trap.** The natural entry, matching every other engine in the table:

```python
{"technique": "zap_dast", "lab": "domsource", "kind": "tool", "tool": "_run_zap",
 "input": {"url": "http://domsource:8080", "policy": "safe_active"}, "family": "zap"}
```

would report **DEAD against a perfectly working ZAP**. MEASURED, not reasoned:

```
zap_client.alert_to_finding(<a real CSP alert>)  →  confidence = 'candidate'
                                                     scanner_confidence = 'High'
                                                     family='zap'  cwe='CWE-693'  evidence=60 chars
liveness._match(f, {"family": "zap"})    → False
liveness._match(f, {"cwe": "CWE-693"})   → False
```

The cause is deliberate design on both sides and neither side is wrong. `liveness._match` requires
`confidence in ("confirmed","high")` and its docstring states the rule outright: *a lead never
satisfies a liveness check*. `zap_client.alert_to_finding` grades every ZAP alert `"candidate"` on
purpose, keeping ZAP's own rating in `scanner_confidence` so a scanner's opinion can never be
mistaken for an Apolaki oracle. **Do not "fix" either one to make the check pass** — loosening
`_match` would let leads satisfy every other engine's check, and promoting ZAP alerts to `confirmed`
would inject an unmeasured false-positive source into the report, which this ticket's own
false-positive section forbids.

**The correct shape is a REACH check, not a proof check** — and the precedent already exists in the
same table. `kind: "surface"` was added for exactly this reason: "can the product still reach a
target" is a different question from "did an oracle fire", and it belongs in the same ratchet. ZAP's
liveness question is the same kind: *did the DAST pass execute and come back with attributed alerts*,
not *did Apolaki prove a bug*.

Suggested patch, for the owner to place in `CHECKS` and implement the arm in `verdict()`:

### …and `min_alerts` is a SECOND mis-specified oracle. I only caught it by running ZAP twice.

My own first draft of this patch was `{"kind": "zap", …, "min_alerts": 1}`. **It is wrong, and the
second live run proved it.** The durable `safe_active` mission returned:

```
count: 0
"policy=safe_active; speed=normal; aggression=normal; target-rate<=1rps;
 0 ZAP alert(s) [safe-active] (from 0 current raw)
 [191 retained alert(s) excluded; active scan degraded, passive alerts kept:
  active scan incomplete or timed out]"
```

Zero alerts — from a pass that worked correctly. Daemon-side, measured:

```
alerts on http://domsource:8080 : 191
ascan scan 0 : reqCount=302  alertCount=0  newAlertCount=0  progress=1  state=FINISHED
spider scan 13 : progress=100 FINISHED
```

Two independent reasons, both of them correct behaviour:

1. **The pass-cursor did its job.** domsource already carried 191 alerts from the earlier passive
   run, and the cursor refuses to claim alerts it did not raise. A pass against an
   already-alerted site legitimately attributes **0 new** alerts. The same control that stopped ZAP
   claiming 191 findings it did not earn also guarantees a repeat run scores zero.
2. **The active scan was capped**, `progress=1` yet `FINISHED` after 302 requests — stopped by the
   engine's own time budget, and *reported* as `active scan degraded, passive alerts kept`.

So `min_alerts: 1` would be **green on a fresh daemon and DEAD on every run after it** — a flaky gate
that blames ZAP for a working cursor. That is the same mis-specified-oracle shape as the
`family: "zap"` version, and I walked straight into it one paragraph after warning about it.

**Corrected oracle: assert EXECUTION and REACH, never newly-attributed alert count.**

```python
# ── DAST: did the ZAP pass actually EXECUTE and reach the target? ────────────────────────────
# Q-023. Two oracles were tried and rejected here; do not "simplify" back into either.
#   family:"zap"   -> DEAD on a healthy ZAP: alerts are graded `candidate` on purpose and
#                     liveness._match refuses leads on purpose. MEASURED.
#   min_alerts>=1  -> DEAD on every run after the first: the pass-cursor correctly refuses to
#                     re-claim alerts already on a long-lived shared daemon. MEASURED (0 new
#                     alerts against a site holding 191).
# The only stable question is the one the ticket actually asked: did the pass RUN and reach a
# real target. `raw + retained > 0` proves reach without ever counting proof.
{"technique": "zap_dast_execution", "lab": "domsource", "kind": "zap",
 "input": {"url": "http://domsource:8080", "policy": "passive"}},
```

```python
if check.get("kind") == "zap":
    res = findings            # the runner passes the ToolResult through for this kind
    note = str(getattr(res, "output", "") or "")
    if not getattr(res, "success", False):
        return {..., "verdict": DEAD, "detail": "run_zap failed: %s" % getattr(res, "error", "")}
    if not note.startswith("policy="):
        return {..., "verdict": DEAD,
                "detail": "run_zap returned without a policy token — the pass did not execute"}
    # reach, not proof: raw-this-pass PLUS retained-excluded. Never `count`.
    seen = _zap_alerts_seen(note)          # parses "from N current raw" + "M retained"
    if seen > 0:
        return {..., "verdict": CONFIRMED,
                "detail": "ZAP pass executed under %s; daemon holds %d alert(s) for the target"
                          % (note.split(";")[0], seen)}
    return {..., "verdict": DEAD,
            "detail": "ZAP pass executed but the daemon holds no alerts for the target — the DAST "
                      "wiring is not carrying a target"}
```

A `degraded` note must **not** be DEAD: `active scan degraded, passive alerts kept` is the engine
correctly reporting a capped active scan, which is the Q-023 sub-defect-3 idiom working as intended.

**Cost and lab choice are measured, not guessed.** `domsource` with `policy: "passive"` is the right
lab: the whole full-mode mission including the ZAP pass took **2m43s**, and it is a compose-pinned
local lab. Use `passive`, not `safe_active` — the `safe_active` durable run took **6m51s**
(23:11:42 → 23:18:33) for the ZAP step alone and ended capped at 1% active-scan progress, so it costs
four times as much and tests less.

**Baseline note.** This ADDS a technique, so `scripts/liveness.sh --update` is required once to take
it into the baseline; `evaluate()` only ever adds, so nothing regresses. Note that `liveness.sh` runs
`docker compose --profile labs up -d … domsource …`, which **recreates `domsource`** — do not run it
while a mission is targeting that lab (it would have killed mission `b226bc05` mid-flight).

**P3 — `agent/main.py` (findings-gate lane owns it).** No change required for Q-023; recorded so the
owner is not left guessing. `_missing_zap_invocation` is correct as written.

## Anti-idle follow-on filed as evidence, not as a patch

`webgoat` returns **404 at `/`** and has been `unhealthy` for 7 days. `mutillidae` (302),
`bwapp` (302), `domsource` (200), `clientauthz` (200) are all alive and all but domsource unexercised.
Twelve standing containers cost RAM continuously to validate nothing.
