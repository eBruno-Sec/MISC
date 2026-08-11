# RESEARCH INBOX — raw, unfiltered

The Watcher appends here. The Analyst drains it into [../QUEUE.md](../QUEUE.md) and records
rejections there. Nothing in this file is a commitment; entries are hypotheses until distilled.

Every entry must carry: **problem solved · evidence and primary sources · Apolaki compatibility ·
expected benchmark or real-world benefit · false-positive risk · a concrete acceptance test.**
Tag each claim **MEASURED** (with the command and output) or **UNVERIFIED**. A disproved hypothesis
is a result — keep it, marked disproved.

---

## 2026-08-10 · Capability-gap sweep #1 — DRAINED into QUEUE Q-001…Q-008

**Measured inventory**: 88 engines (`run_*` in `agent/tools.py`), 85 finding families, technique
registry in `agent/techniques.py`, 109 hand-mapped WSTG tests in `agent/wstg_catalog.py`
(FULL/PARTIAL/EXCLUDED). Residual `none` set computed from the catalog and cross-checked against
live code rather than trusted from the table.

**Coverage verdicts**: ~90% of the PortSwigger Academy topic list. Zero-engine topics: HTTP request
smuggling, WebSockets, server-side prototype pollution, web messaging. OWASP API Top 10 2023: one
empty slot (API4 unrestricted resource consumption); API6 graph-reasoned only. OWASP Top 10 2021:
nothing structurally absent (A02 is the accepted crypto-visibility limit; A09 is not black-box
testable).

Six proposals distilled to **Q-001 … Q-006**; two defects to **Q-007 / Q-008**. Twelve expected gaps
checked and found **already covered** — recorded in QUEUE's `rejected` section so they are not
re-proposed.

---

## 2026-08-10 · LINE 1 — ZAP orchestration: the full trace

**HEADLINE (MEASURED):** `run_zap` has **never executed in any Apolaki mission**. Not once, in
150 missions and 25,619 recorded tool calls. ZAP is reachable, healthy, memory-bounded, and
functionally correct when called by hand — it is simply never called. It is also **not** the reason
the OWASP-Benchmark mission found 2 things in 62 minutes, and turning it on would **not** have
raised that number (see 1e — ZAP alerts cannot become confirmed findings).

### 1a — Is ZAP invoked, or merely reachable? → **REACHABLE, NEVER INVOKED**

**MEASURED — the ledger.** No mission has ever called it:

```
$ docker exec apolaki-agent-1 python -c "<walk logs table, json-parse every tool_call>"
run_zap tool_call count: 0
run_zap results: []
distinct tools ever called: 67
TOP 25 tool_call: [('http_probe', 4505), ('run_fingerprint', 2611), ('run_xss', 1289), ...]
```
Total corpus: 150 missions, 25,619 `tool_call` rows, 21,810 `tool_result`, 362 `tool_error`.
`run_zap` appears in **none** of them.

**MEASURED — ZAP's own side of the story.** The daemon has been up 10h and has processed nothing:
```
$ docker exec apolaki-zap-1 curl -s ".../JSON/core/view/numberOfMessages/?apikey=..."
{"numberOfMessages":"0"}
$ ... /JSON/ascan/view/scans/   ->  {"scans":[]}
```

**MEASURED — the flag's real default and who sets it.** Three independent gates, each sufficient
on its own to prevent invocation:

| # | Gate | file:line | Real value |
|---|------|-----------|------------|
| 1 | API request model default | `agent/main.py:81` — `enable_zap: bool = False` | **OFF** |
| 1b | `BBHAgent` ctor default | `agent/agent.py:237` — `enable_zap: bool = False` | **OFF** |
| 1c | UI checkbox | `ui/index.html:386` — `<input type="checkbox" id="enableZap" …>` (no `checked`) | **OFF** |
| 2 | Mode gate | `agent/main.py:336-337` — `if enable_zap and req.mode != "full": raise HTTPException(422, …)` | ZAP is a **422** outside Full mode |
| 3 | Planner permission gate | `agent/tools.py:138` — `"run_zap": PermissionLevel.INTRUSIVE`; `agent/planner.py:187` `fresh()` → `_allowed(tool, mode)` | INTRUSIVE ∉ active/passive tiers |

The only writer of `enable_zap=True` in the whole tree is `ui/index.html:1328`. There is **no**
script, harness, test fixture or benchmark runner that sets it: a repo-wide grep for
`enable_zap|require_zap` outside `main.py/agent.py/planner.py` returns exactly three UI lines and
one unit test.

**MEASURED — the 2-findings mission specifically.** Mission `90cee81c` (`owaspbench-clean`) ran
`mode="active"`, `context.enable_zap=False`. It could not have run ZAP even if the flag were on
(gate 2 would have 422'd the scan at creation). Across the whole DB only **4 of 150** missions ever
carried `enable_zap=True` (`c7bfe8e8`, `ce35b361`, `6771ec21`, `94e8b564`, all 2026-07-26,
`mode=full`, `strategy=deterministic`, all `status=complete`) — and **even those four produced zero
`run_zap` calls** (222/222/333/375 tool calls each, 38-39 distinct tools, no `run_zap`).

**DISPROVED hypothesis — "the planner branch is dead".** It is not. Driving `planner.next_batch`
to exhaustion with `mode=full, zap=True` schedules the step:
```
$ docker exec apolaki-agent-1 python -c "<loop next_batch until empty>"
RUN_ZAP STEP at batch 5 : {'tool': 'run_zap', 'input': {'url': 'http://bench.local:8080',
  'policy': 'safe_active', 'speed': 'normal', 'aggression': 'normal'}, 'key': 'run_zap:bench.local:8080'}
batches= 7 steps= 58 zap_scheduled= True
```
`agent/planner.py:552-560` (phase F2) is live code. So is `agent/agent.py:2655`
(`"zap": self.enable_zap and _zap_configured()`), and `_zap_configured()` is **True** right now:
```
ZAP_ADDR= 'http://zap:8090'   configured()= True
health()= {'configured': True, 'running': True, 'version': '2.17.0', 'addr': 'http://zap:8090', 'error': ''}
```
So the dead link is exclusively `enable_zap`, whose only possible source is a human ticking a
box that starts unticked. **The July-26 four remain unexplained by static reading** — the flag was
on, the daemon was configured, the mode was full, and the step still never fired. Their planner
state is not recoverable from the DB (no `phase` payloads survived), so I record this as
**UNVERIFIED residue**: a fourth, older gate may have existed on that commit. Do not treat
"flip the flag" as sufficient without an end-to-end acceptance test that asserts a `run_zap`
`tool_call` row lands.

### 1b — Does anything read `recon["zap"]`? → **NO. Write-only. Dead write.**

`agent/tools.py:8470` `self.recon.setdefault("zap", []).extend(findings)` is the **only**
occurrence of the `"zap"` key on the recon dict anywhere in the tree. A repo-wide,
case-insensitive `zap` sweep across every non-test `agent/*.py` file returns 118 hits; I read
every one. Readers checked and cleared:

- `agent/report.py` — renders `ledger["zap_status"]` (a *string* from `main.py:784-800`), never `recon["zap"]`.
- `agent/guidance.py` — `build_guidance(recon)` fans `recon` to every rule in `RULES`; **no rule mentions zap** (zero `zap` hits in the file).
- `agent/memory.py:104 snapshot()` — reads only `live_hosts` / `subdomains` / `urls`.
- `agent/asset_graph.py:444 build_from_engagement()` — reads `urls`, findings, personas, services; no generic key walk.
- `agent/tools.py:8587 _generate_playbook` and `agent/main.py:2130` — both `dict(self.recon)` → `build_guidance`, same dead end.
- **No dynamic access exists**: zero `recon.items()`, `recon.keys()`, or `for k,v in …recon` anywhere in `agent/`.

`recon["zap"]` is initialised nowhere (`agent/tools.py:1008-1012` has no `zap` key), so the
`setdefault` also means an inspector diffing the recon schema will not see the slot until ZAP runs.
**Verdict: dead write, harmless.** ZAP findings escape only via the `ToolResult` at
`agent/tools.py:8482-8484` → `agent/agent.py:465 _auto_store(result)` → `agent.py:557`. That path
is real — but see 1e for what it does with them.

### 1c — WIRED / NOT WIRED table

| ZAP capability | Status | Call site / evidence |
|---|---|---|
| Context creation + scope include-regex | **WIRED** | `tools.py:8391-8393`; `zap_client.py:113-117`; regexes from `zap_client.include_regexes(scope)` |
| Initial "scan" (URL seeding / import) | **WIRED, capped 40** | `tools.py:8395-8401` `access_url(url)` + up to 40 same-netloc `self.urls` |
| Traditional spider | **WIRED** | `tools.py:8409-8412`; `zap_client.py:133-138`; client-side wait cap 180s |
| AJAX spider | **WIRED, silently swallowed** | `tools.py:8413-8417`; wrapped in bare `except Exception: pass` — an AJAX-spider failure is invisible |
| Passive scan | **WIRED, drained only on `policy=="passive"`** | `tools.py:8418-8424` `pscan_remaining()`. Under active policies the pscan queue is never explicitly drained before `alerts()` |
| Active scan | **WIRED** + speed/aggression dials | `tools.py:8425-8463`; `ascan`, `setOptionDelayInMs`, `setOptionThreadPerHost`, `setOptionHostPerScan`, `setPolicyAttackStrength/AlertThreshold` |
| OAST / out-of-band | **WIRED, off by default** | `tools.py:8446-8448`; `ZAP_OAST_SERVICE` is empty in `docker-compose.yml:42` |
| `X-Scanner` attribution header | **WIRED** | `zap_client.py:208-213` via the `replacer` component |
| **Targeted rescan** | **NOT WIRED** | No re-scan of a single URL/param. Planner key is `run_zap:{host}` and `fresh()` dedups against `done` (`planner.py:180-191`) → **exactly one ZAP call per host per mission, ever** |
| **Recrawl** | **NOT WIRED** | Same reason. New URLs found after the ZAP pass are never fed back; `access_url` seeding happens once, before the spider |
| **ZAP as intercepting proxy for Apolaki's own traffic** | **NOT WIRED** | Apolaki has its own `capture.py`/`proxy.py`; nothing routes `http_probe`'s 4,505 requests through `zap:8090`. ZAP's passive scanner therefore never sees Apolaki's traffic — the single largest wasted capability |
| Authentication / session in ZAP | **NOT WIRED** | `zap_client` uses only `core, context, spider, ajaxSpider, ascan, pscan, replacer, oast` (measured: `grep -o '_call("[a-z]*"'`). No `authentication`, `users`, `forcedUser`, `httpSessions`. `self.session_headers` is never passed to ZAP → **an authenticated mission's ZAP pass runs logged-out** |
| OpenAPI / GraphQL / SOAP importers | **NOT WIRED** | no `openapi`/`graphql`/`soap` component calls |
| Alert filters (FP suppression) | **NOT WIRED** | no `alertFilter` component — this is why the pass returns 44 header-hygiene alerts (below) |
| Custom scan policy | **NOT WIRED in practice** | `tools.py:8458` `policy=inp.get("scan_policy") or None`; planner never sets `scan_policy` → always ZAP's Default Policy |
| Spider `maxDepth` / `maxChildren` / `maxDuration` | **NOT WIRED** | only a *client-side* wait cap; the spider keeps running server-side after Apolaki stops waiting |

### 1d — Memory bound → **BOUNDED. Not starving anything.**

The 7.34 GiB regression is already fixed and **committed** (`d50c760` "Apolaki: bound the ZAP
daemon - it took 7.34GiB of a 15.5GiB VM after one scan"), `docker-compose.yml:93-95`:
`mem_limit: 6g` + `JAVA_TOOL_OPTIONS: "-Xmx4g"` (heap deliberately under the cgroup ceiling so the
JVM GCs instead of being OOM-killed).

MEASURED, before / after a real safe-active scan I ran today:
```
apolaki-zap-1   1.331GiB / 6GiB   0.43%      (idle, 10h uptime)
apolaki-zap-1   1.564GiB / 6GiB   0.26%      (immediately before)
apolaki-zap-1   1.606GiB / 6GiB   3.85%      (immediately after a full safe_active pass)
apolaki-agent-1  292.2MiB / 15.5GiB 0.19%
```
**Verdict: ZAP could not have starved the mission.** It grew 42 MiB under load. The real cost of
the current arrangement is that a `profiles: ["dast"]` opt-in service is running permanently,
holding ~1.4 GiB, having processed zero messages.

### 1e — NEW DEFECT found while tracing: ZAP alerts can never become confirmed findings

**MEASURED end-to-end.** I invoked `_run_zap` for real against an authorized local lab
(`http://domsource:8080`), both policies:

```
policy=passive       elapsed= 43.7s  ->  44 ZAP alert(s) [passive]  (from 47 raw)
policy=safe_active   elapsed=229.6s  ->  44 ZAP alert(s) [safe-active] (from 47 raw)
                     severities: {'medium': 22, 'low': 22}
                     DISTINCT titles (all 44 alerts):
                       medium  ZAP: Missing Anti-clickjacking Header
                       medium  ZAP: Content Security Policy (CSP) Header Not Set
                       low     ZAP: Server Leaks Version Information via "Server" header
                       low     ZAP: X-Content-Type-Options Header Missing
```
So a 230-second active scan of a lab yields **four distinct header-hygiene issues and zero
vulnerabilities**, inflated to 44 rows because `dedup_alerts` (`zap_client.py:84-93`) keys on
`(alert, url, param)` and therefore does not collapse the same issue across URLs.

Now the routing. `zap_client.alert_to_finding` (`:78`) sets `"confidence": a.get("confidence","")`,
and ZAP always populates that field:
```
raw alerts: 47   confidence values: {'Medium': 25, 'High': 22}
mapped confidence repr: 'Medium'
```
`agent/agent.py:543-549 _is_confirmed`:
```python
c = str(f.get("confidence", "")).strip().lower()
if c == "confirmed": ...
if c:                                 # candidate / possible / probable
    return False
return tool in _CONFIRMED_BY_TOOL      # no grade + confirmatory tool
```
`c == "medium"` → truthy, not `"confirmed"` → **return False**. Every ZAP alert is routed to
`self.leads`, never to `db.add_finding`. The docstring three lines above
(`agent.py:535`: *"A tool that confirms by construction but emits no grade (nuclei/zap/takeover) is
treated as confirmed"*) describes behaviour the code does not have.

**And the fallback would have failed too — a five-way name mismatch.**
`_CONFIRMED_BY_TOOL = {"run_nuclei", "run_zap", "check_takeover", "run_sqlmap", "run_dalfox"}`
(`agent.py:108`) is compared against `result.tool` (`agent.py:569`), but the ToolResults are
constructed with the *bare* names:

| set member | actual `ToolResult.tool` | file:line |
|---|---|---|
| `run_zap` | `"zap"` | `tools.py:8482` |
| `run_nuclei` | `"nuclei"` | `tools.py:3654` |
| `check_takeover` | `"takeover"` | `tools.py:5337` |
| `run_sqlmap` | `"sqlmap"` | `tools.py:8583` |
| `run_dalfox` | `"dalfox"` | `tools.py:8513` |

**All five entries are unreachable — `_CONFIRMED_BY_TOOL` is effectively the empty set at runtime.**
For sqlmap this is masked (its finding carries `confidence: "confirmed"` explicitly,
`tools.py:8568`). For **non-heavy nuclei** it is not masked: `tools.py:3640-3646` builds a record
with no `confidence` key at all → `c == ""` → falls through to the broken name check → **every
plain-nuclei finding is demoted to a lead**. Same shape for `takeover` and `dalfox` (raw JSON,
no confidence key).

> **PROPOSAL Z-1 — repair `_CONFIRMED_BY_TOOL`'s five names (NOT the ZAP routing).**
> *Problem solved:* nuclei/takeover/dalfox confirmations are silently demoted to leads by a
> string-key typo, so a template match never reaches the report.
> *Evidence:* the table above; `agent.py:108` vs the five `ToolResult(...)` constructors.
> *Compatibility:* one set literal in `agent/agent.py`. No new primitive.
> *Benefit:* restores the intended confirm-by-construction path for three engines.
> *FP risk:* **HIGH if applied to `zap`** — the measurement above shows a ZAP pass emits 22
> `medium` header-hygiene alerts per host; promoting those to confirmed findings would add ~66
> junk mediums per 3-host Full scan. Recommend: fix the four names, and **deliberately leave ZAP
> lead-only**, documenting that as the intent (the current behaviour is right, the comment is wrong).
> *Acceptance test:* a `nuclei` ToolResult with no `confidence` key must land in `db.findings`;
> a `zap` ToolResult with `confidence="Medium"` must land in `leads` and **not** in `db.findings`;
> negative control — the same two assertions must FAIL on the pre-fix code for nuclei and PASS
> for zap (proving the test discriminates).

> **PROPOSAL Z-2 — collapse ZAP's per-URL duplicate alerts before they enter the lead stream.**
> *Problem:* `dedup_alerts` keys on `(alert, url, param)`; 4 real issues became 44 rows on a
> trivial lab. On a 2,740-page benchmark this is thousands of leads.
> *Evidence:* measured above (47 raw → 44 "deduped", 4 distinct titles).
> *Compatibility:* `agent/zap_client.py:84-93` (pure, already unit-tested at
> `agent/tests/test_bbh.py:1143`); `report.py:1520-1531` already has posture-consolidation for
> exactly this, so the report-side primitive exists — the lead stream is what is unprotected.
> *Benefit:* a ZAP pass costs ~4 leads/host instead of ~44.
> *FP risk:* none (collapsing identical titles); FN risk if a title is genuinely per-URL —
> mitigate by keeping an `instances: [urls]` list on the collapsed record.
> *Acceptance test:* feed the 47 real alerts I captured; assert 4 records out, each carrying its
> full URL list, and that no alert *title* present in the input is missing from the output.

> **PROPOSAL Z-3 — decide ZAP's role, then wire the one thing that pays.**
> ZAP's own published OWASP-Benchmark macro score is 17.99%; Apolaki's harness is 41.3%. ZAP is
> therefore **not** a coverage source for Apolaki — it is a *second opinion* and a *passive
> observer*. The single highest-value unwired capability is the one that costs no scan time:
> route Apolaki's existing traffic (4,505 `http_probe` requests in one mission) through ZAP's
> **passive** scanner instead of making ZAP re-crawl on its own.
> *Compatibility:* `agent/proxy.py` already exists as the intercept layer and `PROXY_URL` is
> already an env contract (`docker-compose.yml:60`); ZAP speaks the same proxy protocol.
> *FP risk:* the 22-medium header-hygiene flood — must ship behind Z-2 and lead-only routing.
> *Acceptance test:* after a mission, `core/view/numberOfMessages` on `apolaki-zap-1` is
> greater than the mission's `http_probe` count, and mission wall-clock is within 5% of the
> no-ZAP baseline (passive observation must cost ~nothing).

**Do NOT propose simply defaulting `enable_zap` to True.** Measured consequence on the numbers
that matter: +0 confirmed findings (1e), +44 leads/host (1e), +230s/host wall clock, capped at
`CAP_ZAP = 3` hosts (`planner.py:45`).

---

## 2026-08-10 · LINE 2 — the throughput ceiling: it is a hard-coded sleep, not concurrency

**HEADLINE (MEASURED):** the "~8.5s per tool call" average is an artefact of averaging a bimodal
distribution. **339 of 433 calls cost 60 seconds in total.** 94 calls cost 3,403 seconds. And
**~2,268 of those 3,716 seconds — 61% of the whole mission — is the process sleeping in one
hard-coded `page.wait_for_timeout(350)`.**

### 2a — Where the 3,716 seconds actually went

Reconstructed from `logs` by pairing each `tool_call` with its following `tool_result`/`tool_error`
for mission `90cee81c` (433 calls, 3,716s wall, 2 findings, 13 leads):

```
accounted tool time = 3464s of 3716s wall (93%)

tool                           n  total_s   mean_s    med_s    max_s
run_xss                       45   2637.3    58.61    58.64    59.29
run_dom_audit                 17    511.0    30.06    30.80    31.52
run_dom_trace                 32    254.8     7.96     7.67     8.78
run_subfinder                  1     30.9    30.91    30.91    30.91
run_wayback                    1     12.1    12.08    12.08    12.08
run_ldap                      32      4.1     0.13     0.17     0.27
run_sqli                      20      3.9     0.20     0.18     0.31
run_xpath                     32      3.7     0.12     0.15     0.24
run_ssi                       32      0.8     0.03     0.03     0.16
run_fingerprint               29      0.6     0.02     0.01     0.07
http_probe                    25      0.3     0.01     0.01     0.01
...  (14 further tools, all ≤0.6s total)
```

Three browser engines = **92% of wall clock from 22% of the calls**. The median HTTP-only tool
call is **10-200 milliseconds**. Network latency to the lab is not a factor.

### 2b — DISPROVED: "it's per-call browser startup"

```
async_playwright enter 0.35s | launch 0.17s | ctx+page 0.10s | goto 0.25s | goto(warm) 0.04s | close 0.15s
```
A whole Chromium launch costs **0.17s**. Per-call startup is ~0.6s of a 58.6s call — **1%**.
Recorded as **disproved**.

### 2c — CONFIRMED root cause: 350 ms × 144 serial navigations per `run_xss`

`agent/tools.py:4042-4100 _xss_execute` builds
`targets = params × EXEC_PAYLOADS + fragment × EXEC_PAYLOADS`, `len(xt.EXEC_PAYLOADS) == 12`
(measured). The dedup guard at `:4083` (`if (where, p) in done`) only helps after a hit, because
`done.add((where, p))` at `:4096` sits **inside** the `if fired["msg"]` block — so on a
**non-vulnerable** parameter, which is almost all of them, all 12 payloads are loaded serially.

Scaling measured directly against a real benchmark URL:
```
params= 1 -> targets= 24  _xss_execute=  9.87s  (0.411s/target)
params= 5 -> targets= 72  _xss_execute= 28.63s  (0.398s/target)
params=11 -> targets=144  _xss_execute= 55.55s  (0.386s/target)
```
11 params → 144 targets → 55.6s reproduces the mission's 58.6s (`_discover_params` has
`limit: int = 10` at `tools.py:3934`, so a page with one real param yields 11). The near-zero
variance across 45 different URLs (mean 58.61 / median 58.64 / max 59.29) is explained: every page
saturates the same fixed 10-param wordlist, so every call does exactly the same 144 navigations.

**Negative control — isolate the sleep, change nothing else.** Same URL, same 144 navigations,
same single page, sleep on vs off:
```
wait_for_timeout=350ms -> 144 navigations in  55.22s (0.383s/target)
wait_for_timeout=  0ms -> 144 navigations in   4.43s (0.031s/target)
```
**12.5x.** The navigation itself is 31 ms; the sleep is 350 ms — **91% of per-target cost is
`await page.wait_for_timeout(350)` at `agent/tools.py:4088`.**

Extrapolated to the mission: `run_xss` 2,637s → ~250s; total wall 3,716s → **~1,330s (2.8x)**,
with no concurrency and no behavioural change other than the wait.

The same constant appears five more times, all in serial browser loops:
`tools.py:4088 (350)`, `:4176 (450)`, `:4574 (500)`, `:4880 (600)`, `:5051 (900, CSTI)`,
`:5053 (350)`. `run_dom_audit` measured at 22.5s for **24 probes** (10 redirect / 9 csti / 3 proto
/ 2 xss), each in its own fresh browser context, each ending in a 350 ms or 900 ms sleep plus a
`networkidle` wait — the identical shape.

### 2d — DISPROVED: "concurrency is the fix". Safe ceiling ≈ 4-8, and it buys 1.36x

Once the sleep is gone, parallelism has almost nothing left to recover. Same 144 navigations,
N pages in one browser context, no sleep:
```
pages= 1  144 navs in  4.32s  (0.030s/nav)
pages= 2  144 navs in  4.13s  (0.029s/nav)
pages= 4  144 navs in  3.54s  (0.025s/nav)
pages= 8  144 navs in  3.17s  (0.022s/nav)
pages=12  144 navs in  3.26s  (0.023s/nav)   <- regression; contention
```
**Safe browser-probe concurrency ceiling: 8 pages (knee at 4).** Total available gain: **1.36x**,
against the sleep fix's **12.5x**. The Q-019 Builder was right to be told not to smuggle
concurrency in — it is the wrong lever, and it would have masked the real one.

> **PROPOSAL T-1 (priority) — replace the blind 350 ms sleep with an event wait.**
> *Problem solved:* 61% of a mission's wall clock is spent sleeping after page load.
> *Evidence:* the 55.22s → 4.43s negative control above; `tools.py:4088` and its five siblings.
> *Apolaki compatibility:* pure change inside `_xss_execute`; the dialog handler already exists at
> `tools.py:4073-4079`. The correct primitive is Playwright's own dialog event — `await` a
> short-timeout future resolved by `on_dialog`, rather than a fixed sleep. Fall back to a much
> smaller cap (e.g. 40 ms) when nothing fires.
> *Expected benefit:* mission wall 3,716s → ~1,330s at identical coverage. At the fixed rate this
> is what makes covering 2,740 cases arithmetically possible at all (76h → ~27h before any funnel
> or concurrency work).
> *False-positive risk:* **none for FP — the risk is FN.** A payload whose `alert()` fires from a
> deferred script (`setTimeout`, late `onload`) could be missed if the wait shrinks. This must be
> measured, never assumed.
> *Acceptance test:* (1) build a fixture page that fires `alert(MARK)` at `setTimeout(…, 0)`,
> `…, 100)`, `…, 300)` and `…, 1000)`; the event-wait version must confirm the first three exactly
> as the 350 ms version does, and both must agree on the 1000 ms case. (2) Re-run the full
> `run_xss` suite against every lab with a `validated_on` entry and assert the confirmed-finding
> set is **byte-identical** to the pre-change set. (3) Assert `_xss_execute` wall time for
> 144 targets drops below 10s. (2) is the one that matters — a speedup that changes any verdict
> is not this ticket.

> **PROPOSAL T-2 — `done.add((where, p))` on exhaustion, not only on a hit.**
> *Problem:* `tools.py:4096` marks a (location, param) pair complete only when a payload fires, so
> a clean param always costs the full 12 payloads. Early-exit on the *first* payload that proves
> the param is not reflected/executable would cut the common case.
> *Evidence:* the 0.386s/target × 144 scaling above; 2 findings from 45 calls means ~99% of
> targets are clean.
> *Compatibility:* `agent/tools.py:_xss_execute` only.
> *FP risk:* none. **FN risk is real and this is the whole difficulty** — payload 7 can fire where
> payload 1 does not (different contexts). Do NOT early-exit on "payload 1 didn't fire"; the
> defensible version is to skip payloads whose *context* the reflection pass at `tools.py:4004-4024`
> already proved impossible for that param.
> *Acceptance test:* against every lab with a known XSS in `validated_on`, the confirmed set must
> be unchanged, and at least one lab must exist where a **later** payload is the one that fires
> (proving the test can catch an over-eager exit). If no such lab exists, build the negative
> control before shipping.

> **PROPOSAL T-3 — bounded-parallel browser probes, ceiling 8. Separate ticket, lands AFTER T-1.**
> *Compatibility:* the primitive already exists in-tree four times — `asyncio.Semaphore` at
> `agent/tools.py:5324, 5370, 6142` and `agent/agent.py:1554`. **`agent/race_tool.py` is the wrong
> primitive**: it is a pure summariser for synchronized single-packet bursts (its transport lives
> in `tools._run_race`), designed to make requests land *together*, which is the opposite of what
> throughput probing wants.
> *Expected benefit:* 1.36x on top of T-1. Do not ship before T-1 or the measurement will
> attribute T-1's win to T-3.
> *FP risk:* shared-page state leaking between parallel probes (a dialog fired by probe A being
> attributed to probe B). Mitigate with one page per worker, which is what I measured.
> *Acceptance test:* same confirmed-finding set as serial across all labs, run 3x to catch
> ordering nondeterminism; assert 8 workers ≤ 4.0s for 144 navigations and 12 workers is **not**
> faster than 8 (the measured regression — if it is faster, the harness is wrong).

---
