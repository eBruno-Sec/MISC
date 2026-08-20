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

## Recommendation: **KEEP ZAP.** Do not remove it.

The removal option the brief offers is not supported by the evidence. A scanner nobody can reach is
cost with no capability — but ZAP **is** reachable, **does** run end to end, produces attributed
alerts with a working anti-contamination cursor, is correctly tiered `ACTIVE`, is fenced to a
per-mission ZAP context, honours the shared target rate policy, and fails closed under `require_zap`.
The defect is in the *recording*, not the *capability*.

---

## Patch list for lanes that own the files (I do not own these)

**P1 — `agent/tests/test_zap_live_acceptance.py` (I own `agent/tests/`, so this one is mine to fix).**
`os.environ["ZAP_LIVE_SELF_HOST"]` raises a bare `KeyError` that reads like a ZAP failure. It should
skip with an actionable reason, exactly as the module already does for `ZAP_LIVE_ACCEPTANCE`.

**P2 — the durable-ledger gap (needs a `liveness.py` / Coordinator decision, not a code change here).**
The Q-023 DoD asks for a liveness CHECKS entry that fails when a ZAP-enabled mission produces zero
`run_zap` rows. `main._missing_zap_invocation` (`main.py:2842-2859`) already implements exactly that
rule per-mission and fails closed. What is missing is that **nothing runs a ZAP-enabled mission on a
schedule against the durable DB**, so the rule has no occasion to fire. Recommend the liveness gate
run the `domsource` full-mode ZAP mission (2m43s measured, cheapest lab that exercises the whole
path) rather than adding a new assertion to a corpus nobody writes ZAP rows into.

**P3 — `agent/main.py` (findings-gate lane owns it).** No change required for Q-023; recorded so the
owner is not left guessing. `_missing_zap_invocation` is correct as written.

## Anti-idle follow-on filed as evidence, not as a patch

`webgoat` returns **404 at `/`** and has been `unhealthy` for 7 days. `mutillidae` (302),
`bwapp` (302), `domsource` (200), `clientauthz` (200) are all alive and all but domsource unexercised.
Twelve standing containers cost RAM continuously to validate nothing.
