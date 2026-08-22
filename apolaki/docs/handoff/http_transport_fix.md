# Q-093 — `_http` drops the transport outcome, and a URL builder that lost its netloc

Lane file. Written AS I GO. If this lane is killed, this file is the contribution.

Baseline: HEAD `2dd1f7a`, ship gate GREEN at **3562 passed / 11 skipped / 12 xfailed / 0 failed**.

Two root causes, tracked separately throughout. **Do not read a fix for (A) as a fix for (B).**

| | root cause | corpus dispatches | status |
|---|---|---|---|
| **A** | `_http` returns `{status:0, error, body:""}`; no caller reads `status`/`error`, so a dead connection == a clean page | 3241 unreachable of 27222 (11.9%) | IN PROGRESS |
| **B** | a URL builder emits `https:///` — scheme, no netloc | 1495 | NOT STARTED |

---

## 0. Read-in (MEASURED — from the filed evidence, not re-derived)

`agent/tools.py:3972 _http` is honest: on any transport exception it returns
`{"error": str(e), "status": 0, "headers": {}, "body": "", "length": 0, "final_url": url}`.
Every engine reads `r.get("body", "") or ""`. **The failure arrives as DATA, not as an exception**,
so the Q-08x swallow ledger structurally cannot see it — there is nothing to catch.

`agent/tools.py:79 CmdResult` is the Q-092 pattern to mirror: a 2-length `tuple` subclass so every
`out, err = await self._cmd(...)` unpack keeps working, with `exit_code` riding on the value the
caller already reads. `agent/tools.py:100 _cmd_failure` is the shared predicate, and its docstring
records the lesson this lane must not repeat:

> `parsed` is the caller's own answer to "did I actually get anything out of this run?" ...
> Defaulting `parsed` to None means the safe direction (report the failure) is the one you get by
> not thinking about it.

## 1. Sequencing decision

Per the Coordinator: **commit the gate that FAILS against today's code first**, then the fix. A
partial lane then leaves an executable statement of the defect rather than a description of one.

---

## 2. (A) GATE LANDED FIRST — `agent/tests/test_http_transport_outcome.py`

**MEASURED against HEAD `2dd1f7a`, before any product change:**

```
$ docker run --rm --network apolaki_default -v .../agent:/app -w /app apolaki-agent \
    python -m pytest tests/test_http_transport_outcome.py -p no:cacheprovider -rfE -q
FFF.....F                                                                [100%]
FAILED ...::test_a_dispatch_whose_every_request_failed_is_not_a_clean_scan[run_waf_bypass-WAF-bypass]
FAILED ...::test_a_dispatch_whose_every_request_failed_is_not_a_clean_scan[run_sqli_structural-structural SQLi]
FAILED ...::test_a_dispatch_whose_every_request_failed_is_not_a_clean_scan[run_css_injection-CSS injection]
FAILED ...::test_a_dead_dispatch_does_not_poison_the_next_clean_one
EXIT=1        # captured off `docker run` directly, not off a pipeline
```

The failure text is the defect, verbatim from the run:

```
AssertionError: the dead dispatch stopped being reported: '0 WAF-bypass finding(s)'
 +  where True = ToolResult(tool='waf_bypass', target='http://juice-shop:3000/rest/products/search?q=apple',
                            success=True, output='0 WAF-bypass finding(s)', findings=[], error=None).success
```

**BOTH HALVES, which is the whole design.** 4 fail, and **5 PASS BEFORE THE FIX**:

| test | before | after | what it forbids |
|---|---|---|---|
| every request failed -> `success=False` + error naming the cause | **FAIL** | pass | the false-clean |
| a clean 200 page -> `success=True`, `error=None`, 0 findings | pass | pass | "fail everything" |
| some failed, some succeeded -> `success=True` | pass | pass | degraded read as dead |
| engine sent no requests at all -> untouched | pass | pass | "no evidence" == "failure" |
| dead dispatch then clean dispatch on the SAME registry | **FAIL** | pass | cross-attribution |

A test asserting "0 findings on a dead connection" passes against the broken code and proves
nothing. Every dead-transport assertion here is paired with a reachable-transport assertion on the
SAME engine over the SAME page.

Nothing touches the network: `tools._target_client` is replaced, so `_http`'s real body (including
its real `except Exception` branch) and the whole of `ToolRegistry.execute` are under test.
Substituting `_http` or `execute` itself would test nothing.

**Committed as `xfail(strict=True)`**, following this repo's own `_KNOWN_OPEN` convention in
`tests/test_outcome_fidelity.py`. `strict=True` means the marker XPASSes -> RED the instant the
chokepoint starts carrying the outcome, so it cannot outlive the defect. Suite stays green
(`xxx.....x`, EXIT=0), and the defect is on disk as an executable statement rather than prose.

---

## 3. (A) FIX LANDED — the transport outcome now reaches the ToolResult edge

Three pieces in `agent/tools.py`, all at the chokepoint. **No engine was edited.** 21 engines were
never going to remember to check, and asking them to is how you get 20 that do and one that does not.

1. **`_ACTIVE_HTTP_TALLY`**, a `ContextVar` holding a per-dispatch `{"dead", "live", "last"}`.
2. **`_http_record(url, resp)`**, called at BOTH of `_http`'s return points.
3. **`_http_failure(tally, produced=None)`**, the shared predicate, sibling of `_cmd_failure`.
   `execute` applies it after `_dispatch_engine` and BEFORE `_ledger_outcome`, so the durable
   ledger row records the failure instead of a clean summary.

### Three design decisions, each rejecting the obvious version

**A ContextVar, not `self._http_dead` read as a delta.** The ticket proposed the counter; that is
the `_swallowed_total` shape, and it mis-bills one engine for another's dead requests the moment two
dispatches overlap. They do overlap -- it is the stated reason `_ACTIVE_TOOL_DISPATCH` is already a
ContextVar. A task created inside a dispatch COPIES the context and keeps the same tally object, so
an `asyncio.gather` of probes still lands on its own dispatch. Unset (an engine called directly,
outside `execute`) records nothing: no tally, no verdict, never a guess.

**Recording is UNCONDITIONAL; only the PREDICATE decides.** This is the Q-092 mistake not repeated.
The first `_cmd` fix reported the status only when the exit was non-zero AND stdout was empty;
sqlmap exits 2 with an ASCII banner on stdout, the rule never fired, four guards caught it. **Non-
empty output is not a produced result.** A rule that decides what to RECORD has already thrown away
the evidence needed to question it, so `_http_record` books every outcome and `_http_failure` alone
judges.

**`produced` is load-bearing, not cosmetic.** `agent.py:874` guards auto-store with
`if not result.error and tool_name in _AUTO_STORE_TOOLS`. **Stamping an error onto a dispatch that
DID produce findings would delete them from the mission** — the fix would have caused the exact data
loss Q-090 exists to prevent. A finding produced while every `_http` request died came off another
transport (browser engine, `_cmd`, a private httpx client), so that dispatch is degraded, not dead.
`produced` counts REAL findings, using agent.py's own rule (`vulnerable is False` data-carriers do
not count), and defaults to None so the safe direction is what you get by not thinking about it.
An engine that already refused (SCOPE BLOCK / PERMISSION BLOCK) keeps its own, more specific error.

The rule is `dead AND NOT live`, and its narrowness is the point:

| tally | verdict | why |
|---|---|---|
| `dead=0` | ran | nothing failed |
| `live>0` | ran | something completed; partial failure is DEGRADED, and that line already exists |
| `dead=0, live=0` | ran | the engine sent nothing. **"No evidence" is not "evidence of failure"** — the opposite reading reddens every non-HTTP engine in the registry |
| `dead>0, live=0` | **NOT RUN** | it made requests and completed none of them |

### MEASURED: the gate, after

```
$ pytest tests/test_http_transport_outcome.py -p no:cacheprovider -rfE -q
.........                                                                [100%]
EXIT=0        # 9 passed, 0 FAILED lines; was FFF.....F
```

### MEASURED LIVE — the real execution path, real sockets, authorized lab, no fakes

The exact case from the ticket. `juice-shop:3000` speaks plaintext only, so `https://` cannot open a
socket. Same engine, same page, one reachable scheme and one that is not:

```
=== raw _http, the honest dict nobody reads ===
https://juice-shop:3000/rest/products/search?q=apple  status=0    len=0    err=[SSL: WRONG_VERSION_NUMBER] ...
http://juice-shop:3000/rest/products/search?q=apple   status=200  len=921  err=

=== through the REAL ToolRegistry.execute ===
run_waf_bypass       DEAD-SCHEME  success=False  '0 WAF-bypass finding(s)'       error='NO REQUEST COMPLETED: 3 request(s) attempted, 0 completed; last=https://...'
run_waf_bypass       REACHABLE    success=True   '0 WAF-bypass finding(s)'       error=''
run_sqli_structural  DEAD-SCHEME  success=False  '0 structural SQLi finding(s)'  error='NO REQUEST COMPLETED: 3 request(s) attempted, 0 completed; ...'
run_sqli_structural  REACHABLE    success=True   '0 structural SQLi finding(s)'  error=''
run_css_injection    DEAD-SCHEME  success=False  '0 CSS injection finding(s)'    error='NO REQUEST COMPLETED: 1 request(s) attempted, 0 completed; ...'
run_css_injection    REACHABLE    success=True   '0 CSS injection finding(s)'    error=''

=== negative control: an engine that sends NOTHING (no query params) ===
no-params            success=True   'no query params to test'   error=None
```

The `len=921` matches the byte count in the ticket's independent live measurement exactly. **All
three `SILENT` rows in the ticket are now `success=False` with the cause named, and their reachable
twins are unchanged.** That is the both-halves proof: the change separates the two states rather
than reclassifying everything.

---

## 4. (B) IS A SEPARATE, STILL-LIVE DEFECT — and Q-019 is not it

The obvious conclusion after reading the code is "Q-019 already fixed this." **That conclusion is
wrong, and I only found out by driving the real builder instead of reading it.**

### What IS closed (disproved hypotheses are results)

MEASURED on the corpus (`apolaki_bbh_data:/data/bbh.db`, read-only copy):

```
empty-netloc `https:///` dispatches by tool, and when they stopped:
    http_probe 798 | run_upload_test 318 | run_form_cmdi 318 | run_oauth 37
    fetch_openapi 15 | run_llm_probe 6 | run_graphql 3          = 1495   (matches the ticket)
LAST empty-netloc dispatch : 2026-08-10T16:28:35Z
LAST tool_call overall     : 2026-08-20T23:26:55Z
Q-019's `_b` empty-host fix: fc91bb0, 2026-08-10T22:05-07:00 == 2026-08-11T05:05Z
```

Every one of the 1495 predates the fix. Q-019 made `_b("")` return `""`, added `_abs`, and installed
`planner._addressable` at `fresh()`. MEASURED by driving the real `next_batch`: an empty entry in
`recon["subdomains"]` (filtered at planner.py:609) and an empty `roots` entry now BOTH yield **0**
unaddressable steps. Those paths are closed and pinned in `test_the_already_closed_paths_stay_closed`
so nobody re-fixes them.

### What is NOT closed — MEASURED live against HEAD `1d85fe3`, today

`_addressable`'s docstring says "**Every URL a step targets is built here.**" It inspects
`("url", "base_url")`. Twelve lines above it, planner.py declares:

```python
_TARGET_KEYS      = ("url", "base_url", "target")     # + target: run_nuclei / run_nmap_vuln
_TARGET_LIST_KEYS = ("urls",)                         # the list run_js_review / run_saml fetch
```

**The guard covers 2 of the 4 keys the module itself declares as request targets:**

```
scalar url        hostless value -> _addressable=False  GUARDED
scalar base_url   hostless value -> _addressable=False  GUARDED
scalar target     hostless value -> _addressable=True   *** NOT GUARDED ***
list   urls       hostless value -> _addressable=True   *** NOT GUARDED ***
```

And it is not theoretical. Driving the REAL `planner.next_batch` over a surface with one host-less
`.js` URL, no stubs anywhere:

```
steps=45  unaddressable=2
    ('run_js_review', 'urls', "'/static/app.js'",       'NOT ABSOLUTE')
    ('run_js_review', 'urls', "'https:///static/b.js'", 'NOT ABSOLUTE')
    js_review input: {'urls': ['/static/app.js', 'https:///static/b.js']}
```

**`https:///static/b.js` is the Q-019 string, still being emitted today**, through the one key that
BOTH the planner chokepoint and the executor ingress skip. The path is unfiltered:

```
planner.py:642  js_urls = _rank_urls([u for u in urls if u.split("?")[0].lower().endswith(".js")])
planner.py:662  d.append(_step("run_js_review", {"urls": js_urls[:CAP_JS]}, "run_js_review"))
```

`js_urls` comes straight off raw `state["urls"]` and never passes through `_abs` — the helper Q-019
built precisely so "no host, no URL" would have one definition.

Second half of the same gap: `_b("")` returns `""` since Q-019, so `_step("run_nuclei",
{"target": _b(h)})` builds `{"target": ""}` for a host-less `h`, and nothing looks at `target`.

**Why the existing Q-019 guard is green over this hole.**
`tests/test_hostless_target_guard.py::_step_urls` collects `("url", "base_url")` — the same two keys
the code checks. **The guard's coverage is exactly congruent with the code's blind spot**, so it
passes over the thing it exists to catch. That is this project's most expensive recurring shape, and
it is the twelfth instance. (I did not edit that file; it is correct for what it covers.)

`agent._reject_hostless_step`, the executor ingress, covers `url`/`base_url`/`target` but not `urls`,
and only fires on values containing `"://"` — so `{"target": ""}` and `/static/app.js` pass it too.
**`agent.py` is outside this lane's write scope; recorded here for the Coordinator.**

### The B gate — `agent/tests/test_planner_target_addressability.py`

```
$ pytest tests/test_planner_target_addressability.py -p no:cacheprovider -rfE -q
..FFFF....                                                               [100%]
FAILED ...::test_every_declared_scalar_target_key_refuses_a_hostless_url[target]
FAILED ...::test_every_declared_list_target_key_refuses_a_hostless_url[urls]
FAILED ...::test_an_empty_target_is_refused
FAILED ...::test_the_real_planner_never_emits_a_hostless_js_bundle
EXIT=1
```

4 fail, **6 pass before the fix**: `url`, `base_url`, and four negative controls —

| control | why it must pass BEFORE and after |
|---|---|
| a bare host `target` (`owaspbench:8443`, `example.com`, `10.0.0.5`) is ACCEPTED | `target` is polymorphic: nuclei gets a URL, **nmap_vuln and dork_gen get a bare host**. A rule demanding `http(s)://` on every target would silently delete those whole phases — a latent gap traded for a live capability loss |
| an addressable `.js` bundle list is still planned, non-empty | the guard must not pass by scheduling nothing |
| a full plan still yields >20 steps and keeps its nuclei phase | non-vacuity over every phase |
| the Q-019 paths stay at 0 unaddressable | a fix here must not reopen what Q-019 closed |

The test's own `_unaddressable()` deliberately does NOT reuse `_addressable`'s rule — it states the
property independently (a request target must name a host) while reading the KEY LIST from the
module, so it can never guard less than planner declares.

Landed as `xfail(strict=True)` (`..xxxx....`, EXIT=0), marks applied per-key from an explicit
`_UNGUARDED = ("target", "urls")` so the two already-guarded keys stay real passing assertions.

---

## LANE STATE (updated every commit — read this first if you are picking the lane up)

| slice | state |
|---|---|
| (A) gate `tests/test_http_transport_outcome.py` | **COMMITTED** `1d85fe3` (as strict xfail) |
| (B) gate `tests/test_planner_target_addressability.py` | **COMMITTED** this commit (as strict xfail) |
| (A) fix in `agent/tools.py` + xfail removal | in working tree, green on its own gate and verified live; **HELD until the full suite returns** |
| (B) fix in `agent/planner.py` | NOT STARTED |
| the 4 `_run_hash_crack` sites (brief item 4) | NOT STARTED |

