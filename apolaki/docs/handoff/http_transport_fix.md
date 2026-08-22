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
| (A) gate `tests/test_http_transport_outcome.py` | **DONE** — filed red as strict xfail `1d85fe3`, markers deleted by the fix |
| (A) fix in `agent/tools.py` | **DONE** `c08db26` — gate `FFF.....F` -> `.........`, verified live on the lab, 2 mutants killed |
| (B) gate `tests/test_planner_target_addressability.py` | **DONE** — filed red as strict xfail `8df4535`, markers deleted by the fix |
| (B) fix in `agent/planner.py` | **DONE** `86c8dfb` — gate `..FFFF....` -> `.........`, 2 mutants killed |
| full suite | **GREEN** with (A): 3571 / 11s / 12xf / **0 failed** (baseline 3562 + exactly the 9 new tests). Combined (A)+(B) run on a `git archive HEAD` snapshot: see s12 |
| the 4 `_run_hash_crack` sites (brief item 4) | **HELD, not attempted** — hashcat and john are both MISSING from the image so no fix is verifiable, and the naive fix is wrong (hashcat exits 1 for "exhausted"). Defect + safe approach recorded in s6 |
| `agent._reject_hostless_step` skips the `urls` list | **OPEN, out of this lane's write scope.** No live producer feeds it after (B) — see s11 |

---

## 5. (B) FIX — the guard now derives its keys from the declaration it drifted from

`agent/planner.py`, three changes:

1. **`addressable_target(v, bare_host_ok=False)`** — one public definition of "this value names
   something that can be requested". `bare_host_ok` is the single real difference between the
   declared keys and is NOT cosmetic: `run_nmap_vuln` gets `juice-shop:3000` and `run_dork_gen` a
   bare domain. It defaults to `False`, so a new call site gets the STRICT reading by not thinking
   about it. An empty string is refused in both modes — `_b("")` returns `""` *specifically* to say
   "there is no base for this host", and letting it flow on as a target is the same falsy-default
   failure the empty string was introduced to stop.
2. **`_addressable` iterates `_TARGET_KEYS` and `_TARGET_LIST_KEYS`** instead of a hand-written
   `("url", "base_url")`. **This is the actual fix.** A second hand-maintained key list is what
   produced the gap, so there is not another one: a fifth target key is guarded by existing, and the
   gate parametrizes over the same constants so it arrives as a test case, never as a blind spot.
   `_BARE_HOST_TARGET_KEYS = ("target",)` is declared beside `_TARGET_KEYS`, not next to the guard,
   because the whole of (B) is that a rule kept away from its declaration drifts away from it.
3. **`js_urls` is filtered with `addressable_target` at the BUILD site** (planner.py:642), not only
   refused at `fresh()`. A list key makes `_addressable` refuse the WHOLE step, and losing nine
   addressable bundles because one was host-less would be a capability loss dressed up as a fix.
   Filtering at the source means the step-level refusal is a backstop that should never fire.

### MEASURED, after

```
$ pytest tests/test_planner_target_addressability.py tests/test_hostless_target_guard.py \
         tests/test_whole_product_reach.py tests/test_liveness_hostless_negative_control.py -q
.........................sssssss.......                                  [100%]
EXIT=0        # was ..FFFF....
```

Q-019's own guard file and both reach guards are unaffected — the fix widens coverage without
touching what they assert. (The `s` skips are network-gated; re-run on `apolaki_default` below.)

### NOT FIXED, and outside this lane's write scope — for the Coordinator

`agent._reject_hostless_step` (the executor ingress) inspects `url`/`base_url`/`target` but **not
the `urls` list**, and it only fires on values containing `"://"` — so `{"target": ""}` and a bare
`/static/app.js` pass it. `agent.py` is not mine to edit. The planner side is now closed, so the
ingress is a backstop with a hole rather than an active leak, but it should be made to reuse
`planner.addressable_target` (now public for exactly this reason).

---

## 6. Brief item 4 — `_run_hash_crack`: the defect is REAL, and the fix is HELD with a reason

`tools.py:2083 _run_hash_crack` has four `_cmd` call sites and **discards the outcome at all four**:

```python
await self._cmd(cmd, timeout=120)                     # the CRACK run -- result thrown away entirely
out, _ = await self._cmd(cmd + ["--show"], timeout=30) # the SHOW  run -- err and exit_code discarded
```

If the crack run fails, `--show` returns nothing and the tool reports
`success=True, "Not cracked with passwords-common (offline dictionary)"`. **"Not cracked" when the
cracker never ran** — the identical false-clean, in the `_cmd` path Q-092 already gave a carrier for.

**WHY I DID NOT SHIP THE OBVIOUS FIX.** MEASURED in the agent image:

```
$ docker run --rm apolaki-agent sh -c '...'
hashcat=MISSING john=MISSING
```

Neither binary exists in this build, so `_run_hash_crack` always takes its
`"Skipped — neither hashcat nor john installed"` branch and **no fix here can be verified in the
real execution path**. Worse, the naive fix is WRONG:

> **hashcat exits 1 for "exhausted" — ran perfectly, cracked nothing.** A plain
> `_cmd_failure(result)` on the crack run would report NOT RUN on every honest failure-to-crack.

That is exactly the shape of the first `_cmd` fix that four guards caught: a rule that looks right
and fires on the wrong population. Shipping it unverifiable, against a binary that is not installed,
on exit-code semantics I cannot test, would be a ceiling set by guesswork.

**RECOMMENDED (for whoever has hashcat in the image):** only the marker-derived reasons from
`_cmd_failure` (`__MISSING__` / `__BUDGET__` / `__EXIT__`) are exit-code-independent and safe to
report as NOT RUN here. `__BUDGET__` is reachable today (`shutil.which` already gates the missing
binary), and it is a genuine false-clean. The exit-code half needs hashcat present and its
0/1/2/-1 semantics pinned in a test before it can be trusted.

**UNVERIFIED, stated as such:** that `__BUDGET__` currently produces a "Not cracked" false-clean is
inferred from reading the control flow, not reproduced — the binaries are absent, so the branch is
unreachable in this build.

---

## 7. The consequence the ticket said made this urgent, MEASURED as fixed

The audit's sharpest complaint was that the unreachable dispatches **were not hiding in an error
table** — `agent.py:840` logs a `ToolResult` carrying an `error` as `tool_error`, everything else as
`tool_result`, and "the 1687 unreachable dispatches sit in `tool_result` wearing a clean-scan
summary."

`run_path_sqli` is the case that cost a real vulnerability: it detects a genuine error-based SQLi on
VAmPI, and the corpus fired it at `https://vampi:5000/...` for **55 of its 58 runs**. Same tool, same
page, the two schemes, through the real `execute` on the snapshot of HEAD:

```
https://vampi:5000/books/v1/1   success=False  error='NO REQUEST COMPLETED: 3 request(s) attempted, 0 completed; ...'
http://vampi:5000/books/v1/1    success=True   error=''
```

and the DURABLE row each one leaves — read straight back out of the sqlite log:

```
etype=tool_error    tool=run_path_sqli  error='NO REQUEST COMPLETED: 3 request(s) attempted, 0 completed;'
etype=tool_result   tool=run_path_sqli  output='0 path-param SQLi finding(s)'
```

**The row type itself now differs.** That is the fix landing where the ticket said the damage was:
the failure is in the error table, not wearing a clean summary. The placement is load-bearing — the
verdict is applied after `_dispatch_engine` and BEFORE `_ledger_outcome`, because `_ledger_outcome`
is what chooses `tool_error` vs `tool_result`.

Root cause (B)'s own shape is visible through the same chokepoint now:

```
_http("https:///.well-known/ai-plugin.json") -> status=0
    err="Request URL is missing an 'http://' or 'https://' protocol."
```

(A) does not stop that URL being built — (B) does — but any that survive are no longer silent.

## 8. SHIP GATE

Baseline to preserve: **3562 passed / 11 skipped / 12 xfailed / 0 failed.**

Full suite with (A) only, working tree, `--network apolaki_default`:

```
FULLSUITE_EXIT=0
passed=3571  skipped=11  xfailed=12  xpassed=0  FAILED=0  ERROR=0   (total 3594)
```

**3571 - 3562 = +9, exactly the 9 tests of `test_http_transport_outcome.py`. Skips and xfails
unchanged. Nothing lost.** Counted off the progress characters, not off the summary line, which does
not survive redirect here; `FAILED` counted with `grep -c '^FAILED'`, never `grep -c F` (the
deprecation prose contains "FastAPI" and "Lifespan Events").

---

## 9. NO ISLANDS — is `_http` the only chokepoint, or one of several?

If engines mostly used a DIFFERENT transport, instrumenting `_http` would be an island. Census in
`tools.py`:

```
self._http(       110 call sites
self._http_send(   34 call sites
```

Both exist, and they are **not** the same defect. MEASURED, same dead URL, on the HEAD snapshot:

```
_http      -> RETURNS a dict, status=0   (the failure arrives as DATA; no exception to catch)
_http_send -> RAISES ConnectError        (the failure arrives as an EXCEPTION; the ledger can see it)
```

`_http_send` has no `try/except` around `c.request` — a transport failure propagates, so a caller
that wraps it reaches `_swallow` and gets the existing `DEGRADED:` line. **`_http` is the one that
converts a failure into a falsy value, and it is the one this ticket is about.** That is also why the
audit measured 2 of 5 wrappers being saved by the ledger and 3 not: the split follows the transport,
not the engine.

So the chokepoint choice is the right one and it is not an island: `ToolRegistry.execute` dispatches
via `getattr(self, "_" + tool_name)` and is the single door for both emitters (`CLAUDE_TOOLS` and
internal `_exec_internal`), the tally is set there, and `_http` books into it from all 110 sites
without any engine being edited. Proven by execution, not by registration: the live A/B in s3 and s7
went through the real `execute`, and the durable `tool_error` row is the observable effect.

---

## 10. MUTATION TEST — four mutants, all killed, each with a DIFFERENT signature

A gate that goes red for every mutation is not discriminating, it is just brittle. Each mutant below
was applied to a throwaway copy of the HEAD snapshot and reddens a *specific* set.

| # | mutant | result | what it proves |
|---|---|---|---|
| 1 | `_http_failure` returns `""` unconditionally (the defect restored) | `FFF.....F` — the 4 dead-transport tests | the gate detects the ORIGINAL defect, and its signature is byte-identical to the pre-fix run |
| 2 | `_http_failure` returns a reason unconditionally ("fail everything") | `FFFFFFFFF` — all 9 | the 5 negative controls are real. Note the 3 dead tests fail here too, on `"WRONG_VERSION_NUMBER" in res.error` — **the gate requires the error to NAME the cause, not merely to be non-empty** |
| 3 | `bare_host_ok` disabled (strict scheme on every key) | `......F...` — only `test_a_bare_host_target_is_still_accepted` | the exemption for `run_nmap_vuln` / `run_dork_gen` is load-bearing and pinned; this is exactly the "delete a whole phase while looking like a fix" mistake |
| 4 | `_addressable` reverted to the hardcoded `("url","base_url")` | `..F.F.....` — the two `target` tests | the key DERIVATION is what closes the `target` half |

Mutant 4 leaves the `urls` tests green because the fix closes that key **twice** — the
`_TARGET_LIST_KEYS` loop in the guard AND the `addressable_target` filter at the `js_urls` build
site. Both halves are independently load-bearing, which is the property I wanted and did not assume.

---

## 11. SCOPE OF THE (B) FIX — the other emitter, checked rather than assumed

`planner.fresh()` is not the only producer of executable steps. `session_kill_target`'s docstring
names the bypass: "steps the graph produces (`_graph_action_steps`) never pass through `fresh()`".
So a fix that only hardened `fresh()` would be an island. Checked:

* `agent.py:3849` — every graph-directed step goes through `_reject_hostless_step` before
  `_run_tool`, so the executor ingress does cover that producer.
* `_graph_action_step` builds its target as `"%s://%s" % (p.scheme, p.netloc)`. An empty netloc
  yields `https://`, which contains `"://"` and has no netloc, so the ingress catches it.
* `_graph_action_step` emits `host`/`port`/`base_url` — **it never emits a `urls` list.**

Therefore the `urls` key, the one both guards skipped, has exactly ONE producer: `planner`'s
`run_js_review` / `run_saml` steps. The (B) fix closes it there twice (build-site filter + derived
guard loop), so the ingress's `urls` gap is now a backstop hole with **no live producer feeding it**
rather than an open path. It should still be closed — `planner.addressable_target` was made public
for exactly that reuse — but it is not currently leaking.

**HONEST LIMIT.** I have not proved the *negative* over the whole product — that no module anywhere
can construct an empty-netloc URL. What is proved: the two producers that feed the executor were
driven with host-less input and, after the fix, emit none; and after (A), any that ever survive stop
being silent. Gate clause 3 is met for the step-building path, which is where all 1495 corpus
dispatches came from.

---

## 12. SHIP GATE — FINAL, both fixes, isolated snapshot

`git archive HEAD apolaki/agent` into a clean directory (never `cp -r` of the working tree), mounted
into a throwaway container on `apolaki_default`. **The shared `apolaki-agent-1` was never touched.**

The mount was verified non-empty BEFORE trusting the result, because a bad `-v` path mounts an empty
volume and pytest then reports success having collected nothing:

```
py files: 178   test files: 301
tests/test_http_transport_outcome.py  tests/test_planner_target_addressability.py
grep -c _ACTIVE_HTTP_TALLY tools.py  -> 4        # (A) present
grep -c addressable_target planner.py -> 5       # (B) present
```

```
SHIP GATE (A+B, git archive HEAD snapshot, --network apolaki_default)
  passed=3581  skipped=11  xfailed=12  xpassed=0  FAILED=0  ERROR=0   total=3604
  FAILED lines: 0
SHIPGATE_EXIT=0
```

| | baseline `2dd1f7a` | ship gate | delta |
|---|---|---|---|
| passed | 3562 | **3581** | **+19 = 9 (A gate) + 10 (B gate), exactly** |
| skipped | 11 | 11 | 0 |
| xfailed | 12 | 12 | 0 — **both strict-xfail markers were deleted by their fixes, not left behind** |
| failed | 0 | **0** | 0 |

**Not a single test lost.** Instrument discipline: exit code captured with `$?` directly off
`docker run`, never off a pipeline; failures counted with `grep -c '^FAILED'`, never `grep -c F`
(the deprecation prose contains "FastAPI" and "Lifespan Events"); pass/skip/xfail counted off the
progress characters, since the summary line does not survive redirect here.

Commits after the snapshot touch `docs/handoff/http_transport_fix.md` only, so HEAD's CODE is
byte-identical to what was gated (`git diff --name-only 86c8dfb..HEAD`).

**One note for the Coordinator:** `e4e2fb0` (Q-095, `docs/QUEUE.md` only, +64 lines) landed at
02:44 in my window, so the "only writer in this repo" assumption did not hold. It was harmless — no
code, and it predates my first commit. This lane's 8 commits touched exactly four files:
`agent/tools.py`, `agent/planner.py`, the two new test files, and this handoff. `docs/QUEUE.md` and
`docs/STATUS.md` were never staged by me; every commit used
`git commit --only -F - -- <explicit paths>` and `git add -A` was never used.

