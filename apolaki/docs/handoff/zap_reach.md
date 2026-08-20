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

## Open at time of writing

Running the `skipif`-gated live oracle against an authorized local lab to establish whether the
mission path executes ZAP **today**, on the graph-authoritative plan loop, rather than on the
2026-07-26 code the ticket's four residue missions ran.
