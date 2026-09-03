# Breaker cycle 20 - adversarial review of Q-158 / Q-155 / Q-163

Role: BREAKER. I am a READER. Nothing in `agent/` was edited by me; the only file I write is this
one. Every claim below is MEASURED (command + real output) or UNVERIFIED.

Targets:

* `agent/rendered_forms.py` + `agent/tests/test_rendered_forms.py`  (Q-158)
* `agent/nosqli_body.py` + `agent/tests/test_nosqli_body.py`        (Q-155)
* `agent/spa_routes.py` + `agent/tests/test_spa_routes.py`          (Q-163)

## B0. Baseline - the suite is green before I touch anything (MEASURED)

```
$ docker run --rm --network apolaki_default -v .../agent:/app -w /app apolaki-agent \
    python -m pytest tests/test_spa_routes.py tests/test_rendered_forms.py \
                     tests/test_nosqli_body.py -p no:cacheprovider -q
........................................................................ [ 61%]
.............................................                            [100%]
117 passed
```

117 passed, 0 skipped, exit 0. Every mutation result below is measured against this baseline, and
every "test X survived" claim is accompanied by proof that the mutant actually APPLIED.

---

# FINDINGS

## F1. HIGH - `nosqli_body`: a single DROPPED request removes a negative control and manufactures a confirmed HIGH on a CLEAN application

Priority-1 class (false positive on a live-shaped target). Two independent instances, both proved
against the ticket's OWN clean-app fixtures - the ones `tests/test_nosqli_body.py` asserts must
stay silent.

### The mechanism

`probe_json_body` (nosqli_body.py:610-621) folds "the request never completed" into the SAME value
that means "the control ran and found nothing":

```python
ctl_r = await _send(probe["control"])
ctl_body = _text(ctl_r) if _ok(ctl_r) else ""            # <- a timeout becomes ""
ctl_error_patterns = {h["pattern"] for h in error_signatures(base_body, ctl_body)}
omit_body = None
if probe["omit"] is not None:
    omit_r = await _send(probe["omit"])
    omit_body = _text(omit_r) if _ok(omit_r) else None   # <- a timeout becomes None
```

`""` is exactly what `analyze_boolean` reads as "the control did not match" (`_matches("")` is
False because `len("") >= len(baseline)` is False), and `None` is exactly what it reads as "no
omit control was supplied" (`if missing_body is not None`). So a dropped request does not degrade
the verdict - it DELETES the control, and the engine then confirms.

This engine sends 10 requests per two-field body (measured, below). `tools.ToolRegistry._http`
returns `{"status": 0, "body": "", "error": ...}` on a timeout, which is precisely the shape
`_ok()` rejects.

### F1a. The OMIT control - a confirmed HIGH on `ignores_objects`

`tests/test_nosqli_body.py::test_an_app_that_discards_objects_is_caught_by_the_omit_request_alone`
states the stake itself: this clean app is separated from a finding by the omit request ALONE, and
the test even asserts `nb.verdict(..., None, ...) is True` when the omit body is absent.

MEASURED. The wrapper fails exactly one request (the omit) the way `_http` reports a timeout:

```
=== request order probe_json_body sends (ignores_objects) ===
   [0] {"id": "YxAfD6AN5Bk3h3Zeo", "product": 1}          baseline
   [1] {"id": "YxAfD6AN5Bk3h3Zeo", "product": 1}          stability sample
   [2] {"id": "YxAfD6AN5Bk3h3Zeo_bbh7f2a", "product": 1}  plain control
   [3] {"product": 1}                                     OMIT control
   [4] {"id": {"$ne": "YxAfD6AN5Bk3h3Zeo_bbh7f2a"}, "product": 1}
   ...

CONTROL: same clean app, nothing dropped -> findings = 0
--- CASE 1  clean app `ignores_objects`, OMIT request timed out (index 3)
    dropped request body : {"product": 1}
    findings             : 1
      title    : NoSQL injection (boolean-blind, JSON body) in 'id'
      severity : high | confidence: confirmed
```

A `high` / `confirmed` finding on an application whose only behaviour is that it DISCARDS a value
it cannot coerce. The finding's own `negative_controls` array lists the plain-value control and
says nothing about the omit control that never ran, so nothing downstream can tell this row from a
row where every control passed.

### F1b. The ERROR negative control - a confirmed HIGH on `driver_error_on_any_miss`

Same mechanism, different control. `ctl_error_patterns` is the set of driver signatures the PLAIN
control also provokes; a signature in that set is suppressed because it is about the VALUE, not the
operator. A failed control request makes that set empty, so nothing is suppressed.

MEASURED, dropping only request [2] (the plain control):

```
CONTROL: same clean app, nothing dropped -> findings = 0
--- CASE 2  clean app `driver_error_on_any_miss`, CONTROL request timed out (index 2)
    dropped request body : {"id": "YxAfD6AN5Bk3h3Zeo_bbh7f2a", "product": 1}
    findings             : 1
      title    : NoSQL injection (error-based, JSON body) in 'id'
      severity : high | confidence: confirmed
      evidence : MongoDB database driver error triggered by the boolean operator payload
                 {"$ne": "YxAfD6AN5Bk3h3Zeo_bbh7f2a"} in JSON body field 'id' -- POST ...
```

`tests/test_nosqli_body.py::test_a_driver_error_the_plain_control_also_provokes_is_not_reported`
exists to make this app silent. One dropped request defeats it.

### The negative control for my own claim

CASE 3 in the same run: the identical clean app with NOTHING dropped returns 0 findings. So the
difference is the dropped request and not a weak fixture. And in F1a the run WITHOUT the drop also
returns 0. Both directions measured.

### REPRODUCTION

```
cp -r apolaki/agent <scratch>/probe
# <scratch>/probe/_breaker_p4_dropped.py  (self-contained; imports the suite's own FakeApp)
MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default \
  -v "<scratch>/probe:/app" -w /app apolaki-agent python _breaker_p4_dropped.py
```

The script wraps `FakeApp.send` with a `DropNth` that returns
`{"status": 0, "body": "", "error": "read timeout"}` for exactly one request index, and takes the
index from a recorded request ORDER rather than guessing it.

### What I am NOT claiming

I did not find a clean-app shape where the dropped PLAIN control alone flips the BOOLEAN oracle:
on every clean fixture in the suite the operator response also fails `_matches(op)`, so the
differential is refused for a second reason. F1b is the error oracle, and F1a is the omit control.
I did not test this against a live target - `nosqli_body` is not yet dispatched from `tools.py`
(section F7), so there is no live path to exercise.

---

## F2. MEDIUM - `spa_routes`: a write DOES leave the browser; the read-only guarantee has an un-gated boot window

The claim under attack, stated as mechanical in two places:

* `spa_routes.py` docstring: "READ-ONLY BY CONSTRUCTION. Two guarantees, both mechanical: ...
  while the drive is running, every non-GET/HEAD request the page attempts is ABORTED at the route
  layer ... a login POST or a comment POST cannot leave the browser."
* `docs/handoff/q163_spa_routes.md`: "READ-ONLY BY MECHANISM."

`discover()` installs the gate AFTER the first navigation has completed AND settled:

```python
out["pages"].append({"url": base, "settle": _goto(page, base, timeout_ms)})
# Registered AFTER the first navigation so the app boots normally; from here on the
# drive is mechanically read-only.
page.route("**/*", _read_only_gate)
```

`_goto` = navigate + `_settle` (load state, then control-count convergence, bounded by
`timeout_ms`, default 15000). Nothing is intercepted for that entire window.

### MEASURED, with the positive control in the same run

A fixture server that LOGS what reached it (same shape as the suite's own `_Fixture`), serving a
page that writes on its own the way a real SPA does:

```
--- what actually reached the APP server ---
     1.00s  GET      /
     1.02s  POST     /beacon-parse       <- left the browser
     1.03s  POST     /beacon-dcl         <- left the browser
     1.21s  GET      /                   <- the module's own restore navigation, gate INSTALLED
```

The 1.21s reload is `_drive_page`'s restore `_goto`. It re-runs the SAME two scripts and produced
NO POSTs. That is the positive control: the gate works, and the two writes escaped only because
they happened before it existed.

### And on a real application

Exactly what `discover()` does before installing the gate, against juice-shop:

```
settle: load+controls-stable in 0.61s
total requests during the ungated window: 36
NON-GET/HEAD requests during that window:
  [('POST', 'http://juice-shop:3000/socket.io/?EIO=4&transport=polling&t=Q1aWGRY&sid=7jI4Hmm...')]
```

One real POST to the target, per `discover()` call. Benign here (a socket.io handshake). The point
is that the count is not zero, on the very application the module was written for.

Severity MEDIUM rather than HIGH: the exposure is ONE page load per `discover()` call, and the
handoff's own limitations paragraph does not mention it, which is the actual defect - a guarantee
stated as mechanical with an undisclosed hole. `tests/test_spa_routes.py::
test_the_drive_never_sends_a_write_and_the_password_field_is_never_driven` cannot see it because
its fixture page issues no writes of its own.

### REPRODUCTION

`<scratch>/probe/_breaker_p2_boot.py` and `_breaker_p3_detail.py`, run the same way as F1.

---

## F3. MEDIUM - `spa_routes`: the read-only gate FAILS OPEN when the request method cannot be read

```python
def _read_only_gate(route):
    try:
        method = (route.request.method or "GET").upper()
    except Exception:
        method = "GET"                      # <- the permissive answer is the default
```

For a guard whose entire job is to refuse writes, the unreadable case resolves to ALLOW.

MEASURED (`_breaker_p1_gate.py`, no target touched):

```
P1a  method property raises      -> ['fallback']      <- the request is ALLOWED
P1b  method is None              -> ['fallback']      <- the request is ALLOWED
P1c  method has trailing newline -> ['abort']
P1d  no fallback attr, GET       -> ['continue_']
P1e  no fallback attr, POST      -> ['abort']
P1f  abort() raises              -> ['abort-attempted'] (exception swallowed, route left unhandled)
```

Reachability: Playwright raises on `route.request` accessors once the page/context is closing, and
`discover()` closes the browser in a `finally` while requests can still be in flight. UNVERIFIED
that I can force that race; the fail-open DIRECTION is MEASURED.

`test_read_only_gate_aborts_every_write` is parametrized over seven well-formed method strings and
so cannot see this. The mutation `SR4` (gate allows every method) IS killed by it, so the test has
teeth - just not on this axis.

---

## F4. LOW/MEDIUM - `spa_routes`: the module's own abort is recorded as a DISCOVERED ROUTE

The module claims: "Both halves of the answer are OBSERVED: the application chooses the route and
the application chooses the parameter name. Nothing is invented."

MEASURED. Driving a plain `<form method="post">` - the read-only gate aborts the submission,
Chromium lands on its error page, and `route_record` reads the resulting `location.href` as a route
the application navigated to:

```
=== attempt detail on the shipped-shape fixture ===
{"before": "http://127.0.0.1:40099/", "after": "http://127.0.0.1:40099/#/lookup?needle=apolakirt7",
 "changed": true, "failure": ""}
     control: {'id': 'needle', 'tag': 'input', 'type': 'text'}
{"before": "http://127.0.0.1:40099/", "after": "chrome-error://chromewebdata/",
 "changed": true, "failure": ""}
     control: {'id': 'note', 'tag': 'input', 'type': 'text'}
routes:
   {"path": "#/lookup", "params": ["needle"], "parameterized": true, ...}
   {"path": "/", "params": [], "parameterized": false,
    "url": "chrome-error://chromewebdata/", "observed_url": "chrome-error://chromewebdata/",
    "before_url": "http://127.0.0.1:40099/"}
```

`"changed": true` and `"source": "typed-control"` on a navigation that FAILED because of our own
gate. The record carries no parameter, so `parameterized_urls` does not hand it to the sweep and no
finding can come of it - that is why this is not HIGH. What it does corrupt is the count the module
reports and the ledger stores: `note: "2 route(s), 1 parameterised, from 2 control attempt(s)"`.
The 2 is wrong, and it will be wrong on every classic POST form the module ever drives.

`tests/test_spa_routes.py::test_finds_routes_on_an_application_that_is_nothing_like_juice_shop`
runs against a fixture containing exactly this form and asserts only that the two REAL routes are
present - it never asserts the absence of junk, so the error-page record has been in the shipped
fixture's output all along.

---

## F5. MEDIUM - `test_module_issues_no_fixed_sleep` does not catch the case its own docstring names

The test's docstring:

> Asserted over the AST, not the text: a substring check would fire on the docstring that explains
> the rule, and (worse) would pass a `getattr(page, "wait_" + "for_timeout")()`. It is the CALL
> that is the race.

The AST walk requires `isinstance(n.func, ast.Attribute)`. A `getattr(...)()` call has
`n.func` = `ast.Call`, and a bare `sleep()` from `from time import sleep` has `n.func` = `ast.Name`.
Neither is an `ast.Attribute`, so the walk passes both - including the exact `getattr` form the
docstring claims it defends against.

### A CORRECTION TO MY OWN MEASUREMENT, recorded rather than edited away

Round 1's `SR2-bare-sleep-call` came back KILLED and I nearly wrote that down. It inserted
`sleep(0.01)` WITHOUT the `from time import sleep` (each mutant is applied to the pristine file
independently), so the module raised `NameError` and a live test failed. That mutant proved nothing
about the sleep test. Re-run correctly - the import and the call together - in
`_breaker_mutate3.py`, and running `test_module_issues_no_fixed_sleep` BY ITSELF as well as the
whole file so the kill cannot be attributed to a different test:

```
SR2b-bare-sleep-import+call          sleep-test:SURVIVED  whole-file:SURVIVED
SR2c-time-module-sleep               sleep-test:KILLED    whole-file:KILLED
                                       FAILED tests/test_spa_routes.py::test_module_issues_no_fixed_sleep
SR3b-getattr-wait-for-timeout-real   sleep-test:SURVIVED  whole-file:SURVIVED
```

So, exactly:

* `time.sleep(0.05)` - an `ast.Attribute` - IS caught. The test works on the form it was aimed at.
* `from time import sleep` + `sleep(0.05)` - an `ast.Name` - is NOT caught, by the test or by
  anything else in the file.
* `getattr(page, "wait_for" + "_timeout")(50)` - an `ast.Call` func - is NOT caught, which is the
  exact construction the docstring names as the reason for preferring the AST over a substring
  check. On this axis the AST walk is not better than the substring check; it is equally blind.

The positive control the test carries (`waits == {"wait_for_function", "wait_for_load_state"}`) is
real and does prove the walk found something - it just proves it about a set the banned check never
consults. Fix direction: also match `ast.Name` funcs, and assert on the module's IMPORTS (a
`spa_routes` that imports `time` or `sleep` at all is already suspect).

---

## F6. MEDIUM - `nosqli_body`: `test_only_declared_wildcards_are_ungrounded` uses the list it claims to pin as its own exemption filter

The module says (nosqli_body.py:118-123):

> these two are the ONLY probe arguments in this module not derived from the observation, and
> `test_only_declared_wildcards_are_ungrounded` pins the list so a third cannot be slipped in.

The test:

```python
for spec in nb.operator_payloads(observed, ctl):
    if spec["payload"] in nb.WILDCARD_PAYLOADS:
        continue                                  # <- the list IS the exemption
    arg = list(spec["payload"].values())[0]
    assert str(observed) in str(arg) or isinstance(arg, (int, float)), spec
assert re.search(nb.WILDCARD_PAYLOADS[0]["$regex"], "anything at all")
assert "" < "a" and nb.WILDCARD_PAYLOADS[1]["$gt"] == ""
```

Growing `WILDCARD_PAYLOADS` grows the set the loop skips. The two trailing asserts are index-based
(`[0]`, `[1]`), so an entry at index 2 is never inspected. The cardinality is never asserted. A
guard that widens when the thing it guards widens is the "guard that checks a declaration" shape.

MEASURED: `NB11-wildcard-list-unpinned` (a third entry `{"$ne": "zzz-invented"}` appended to
`WILDCARD_PAYLOADS`) SURVIVED the full `tests/test_nosqli_body.py`. The decisive version - a third
wildcard that is also EMITTED - is in section F8.

---

## F7. Mutation sweep - the full result

33 mutants, each applied by an exact single-match string replacement with a byte-difference assert,
each run against its own test file, each restored afterwards. Run on a SCRATCH COPY of `agent/`;
the Coordinator's tree was never mutated (md5 of all three modules verified identical to the repo
before the run).

**27 KILLED. 6 survived, of which 2 are equivalent mutants and 4 are real gaps.**

| mutant | result | killed by |
|---|---|---|
| SR2 bare `sleep()` call | KILLED, but INVALID | killed by `NameError` (the import was not in the same mutant) - re-run properly in F5 |
| SR4 gate allows every method | KILLED | `test_read_only_gate_aborts_every_write[POST-abort]` |
| SR5 gate never installed | KILLED | `test_the_drive_never_sends_a_write_...` |
| SR6 `parameterized` asserted | KILLED | `test_route_record_refuses_to_call_a_bare_route_parameterized` |
| SR7 blank every value | KILLED | `test_blank_marked_values_empties_only_the_marker_it_carried` |
| SR8 merge keeps last | KILLED | `test_merge_routes_dedupes_by_page_and_params` |
| SR9 password becomes typeable | KILLED | `test_password_is_not_a_typeable_control` |
| SR10 scope gate ignored on results | KILLED | `test_scope_gate_is_honoured_on_every_discovered_url` |
| NB1 read-only guard always true | KILLED | `test_read_only_guard_rejects_every_mutating_operator` |
| NB2 mutating methods allowed | KILLED | `test_method_gate_refuses_write_methods_with_a_stated_reason` |
| NB3 invented control value | KILLED | `test_nonmatching_string_carries_the_observed_value` |
| NB4 error negative control dropped | KILLED | `test_a_driver_error_the_plain_control_also_provokes_is_not_reported` |
| NB5 omit control dropped | KILLED | `test_an_app_that_discards_objects_is_caught_by_the_omit_request_alone` |
| NB6 stability samples dropped | KILLED | `test_vulnerable_json_body_endpoint_is_confirmed` |
| NB8 booleans are filterable | KILLED | `test_walk_scalars_excludes_booleans_and_nulls` |
| NB9 failed response treated as ok | KILLED | `test_a_dead_endpoint_reports_why_instead_of_reporting_clean` |
| NB10 baseline failure not refused | KILLED | `test_a_dead_endpoint_reports_why_instead_of_reporting_clean` |
| RF1 JSON reflection confirmed | KILLED | `test_reflection_oracle_confirms_only_an_unencoded_breakout...` |
| RF2 escaped-quote control dropped | KILLED | `test_error_oracle_refuses_when_the_escaped_quote_control_errors_too` |
| RF3 infra status judged | KILLED | `test_no_verdict_is_formed_from_a_response_the_edge_produced` |
| RF4 unobserved submission judged | KILLED | `test_no_verdict_is_ever_formed_from_a_submission_that_did_not_happen` |
| RF5 different endpoint judged | KILLED | `test_no_verdict_is_formed_across_two_different_endpoints` |
| RF6 unmapped controls claimed | KILLED | `test_a_control_whose_value_never_reaches_the_wire_is_reported_unmapped...` |
| RF7 encoded reflection confirmed | KILLED | `test_reflection_oracle_confirms_only_an_unencoded_breakout...` |
| RF9 auth bypass on any endpoint | KILLED | `test_auth_bypass_oracle_stays_silent_for_the_hashed_field...` |
| RF10 non-fillable types fillable | KILLED | `test_the_existing_parser_is_blind_to_both_lab_forms` |
| RF11 error oracle ignores baseline | KILLED | `test_error_oracle_refuses_when_the_baseline_ALREADY_carries_the_error` |
| **SR1** bare `sleep` import only | SURVIVED | no-op setup mutant, no behaviour change - not a gap |
| **SR3** `getattr`-built `wait_for_timeout` | **SURVIVED** | F5 |
| **SR11** visibility filter removed | **SURVIVED** | F9 |
| **SR12** `_settle`'s control-count reset removed | **SURVIVED** | F10 |
| **NB7** `Inconclusive` `continue` removed | SURVIVED | EQUIVALENT mutant - see F11 |
| **NB11** third wildcard added to the list | **SURVIVED** | F6 |
| **RF8** "the value does not reflect" refusal removed | SURVIVED | equivalence checked in F8 |

That is a genuinely high kill rate. Every oracle refusal in `rendered_forms` and every stated
control in `nosqli_body` is defended by a test that actually fails when it is removed. The four
real survivors are all guards ABOUT the engines rather than the oracles themselves.

---

## F8. HIGH - `nosqli_body`'s "OBSERVED" body is a body APOLAKI composed, not one the application sent

This is the single most consequential thing I found, and it is a WIRING defect, not a module one.

### The claim

`nosqli_body.py` puts this in a banner, and `tools._run_nosqli_body`'s docstring repeats it:

> THE BODY IS OBSERVED, NEVER INVENTED. Probes are built by mutating a request body this mission
> actually recorded, because a made-up body makes baseline and probe fail identically and the
> engine then reports clean on a vulnerable field - the failure that has bitten three engines here
> already.

### The fact

`_run_nosqli_body` sources that body from `db.get_exchanges(self.mission_id)`. MEASURED - every
producer of a row in that table carrying a `request_body`:

```
$ grep -rn "add_exchange" --include=*.py agent/ | grep -v tests/
agent/db.py:440       def add_exchange(...)
agent/main.py:3796    workbench replay        (an OPERATOR-composed body)
agent/main.py:3842    cURL console            (an OPERATOR-composed body)
agent/tools.py:4281   ToolRegistry._http      (an APOLAKI-composed body)
agent/tools.py:12148  re-files an existing row against a finding id
```

Nothing else. In particular `capture.CaptureStore.add` - the ledger every browser-backed engine
writes to, including `rendered_forms` - takes NO body at all:

```
$ sed -n '40,41p' agent/capture.py
    def add(self, method, url, status, req_headers=None, resp_headers=None, resp_len=0, ms=0.0,
            engine="http", resp_ct=""):
```

So an application-sent request body cannot reach the table `_run_nosqli_body` reads. Worse, the
house convention across the injection engines is `capture=False` on the BENIGN baseline and
`capture=True` on the CONFIRMING payload request (`tools.py:9625` vs `9637/9645`, `9831` vs `9843`,
`10054/10060`, ...), so the rows that ARE there are preferentially INJECTION PAYLOADS.

### MEASURED end to end, on juice-shop, through the real dispatcher

Own DB (`BBH_DB_PATH=/tmp/breaker20.db`), own mission, own container. One request sent exactly the
way `_run_auth_sqli` sends its confirming request, then the real `_run_nosqli_body`:

```
step 1: one auth-bypass style request, captured the way _run_auth_sqli captures it
   sent    : {"email":"' OR 1=1--","password":"x"}
   status  : 200 | body head: {"authentication":{"token":"eyJ0eXAiOiJKV1Qi...

step 2: what the exchange ledger now offers _run_nosqli_body as 'observed'
    POST http://juice-shop:3000/rest/user/login -> {"email":"' OR 1=1--","password":"x"}

step 3: run the real dispatch and see which body it treats as the observation
   ToolResult(tool='nosqli_body', ..., output='2 field(s) probed over 10 request(s)', findings=[])

   the bodies the carrier actually put on the wire:
      POST {"email":"' OR 1=1--","password":"x"}
      POST {"email":"' OR 1=1--","password":"x"}
      POST {"email":"' OR 1=1--_bbh","password":"x"}
      POST {"password":"x"}
      POST {"email":{"$ne":"' OR 1=1--_bbh"},"password":"x"}
      POST {"email":{"$regex":".*"},"password":"x"}
      POST {"email":"' OR 1=1--","password":"x_bbh"}
      POST {"email":"' OR 1=1--"}
      POST {"email":"' OR 1=1--","password":{"$ne":"x_bbh"}}
      POST {"email":"' OR 1=1--","password":{"$regex":".*"}}

   BASELINE (the reference every verdict is measured against):
      {"email":"' OR 1=1--","password":"x"}
     contains an injection payload: True
```

Every one of the ten requests carries another engine's SQL-injection payload. The BASELINE - the
single reference the whole boolean oracle is measured against - is a body that SUCCEEDS as an auth
bypass on juice-shop and comes back 200 with a JWT. That is not the application's behaviour; it is
Apolaki's own previous probe reflected back at it.

The `nonmatching_value` rule is still satisfied on its own terms (`' OR 1=1--_bbh` does carry the
"observed" value as a prefix), which is exactly why no test can see this: the module is correct and
the observation it is handed is not an observation.

0 findings on this run, so I did NOT observe a false positive from it. What I established is that
the discipline the module is built on is not in force on the live path.

### The composition that is missing

`rendered_forms` (Q-158) exists to observe the request an application really sends, including its
body, and proves it does (`wire_form` -> `{"url": ".../rest/user/login", "method": "POST",
"carrier": "json", "params": {...}}`). `nosqli_body` (Q-155) needs exactly that artifact. The two
are in the same repo, landed the same day, and there is no path from one to the other because the
only body-bearing ledger is `db.add_exchange` and `rendered_forms` writes to `capture.add`.

### REPRODUCTION

```
MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default -e BBH_DB_PATH=/tmp/breaker20.db \
  -v "<scratch>/probe:/app" -w /app apolaki-agent python _breaker_p5_observed.py
```

### CORRECTION to my own earlier note

An earlier draft of this file said `nosqli_body` was not dispatched. That was WRONG and I am
recording the correction rather than editing it away: the Coordinator's wiring landed while I was
measuring. It is dispatched from `planner.py:987` (per param endpoint), registered at
`tools.py:544/867`, dispatched at `tools.py:9653`, and auto-stored via `agent.py:97`.

---

## F9. MEDIUM - `nosqli_body` replays an observed POST body up to 10 times, and POST is on the NON-MUTATING list

`NON_MUTATING_METHODS = ("GET", "HEAD", "POST", "SEARCH", "QUERY", "REPORT")`, justified as:

> Methods whose semantics do not mutate the SET a filter selects. A broadened filter here returns
> more rows; it does not touch more rows.

That reasoning is about the FILTER and it is sound. It does not cover the other thing the carrier
does, which is REPLAY THE OBSERVED BODY VERBATIM - as the baseline, then again as the stability
sample, then once per operator with one field changed.

MEASURED in F8: `10 request(s)` for a two-field body, of which the first two are the observed body
sent unchanged. If the observed request was a creation (`POST /api/Feedbacks`, a registration, an
order, a comment), the engine performs that creation ~10 times. `method_verdict` cannot see this,
because it reasons about the operator's blast radius and not about the replay.

The module's own docstring is where the tension is clearest: it refuses `PATCH /rest/products/
reviews` because "a broadened filter selects more documents TO WRITE", under a banner headed
"READ-ONLY PAYLOADS ... Two independent guards, because 'read-only' means two different things
here." There is a third thing it means, and it is not guarded.

I did NOT send a creating POST at a shared lab to demonstrate this, deliberately - the request
count above is the measurement, and the semantics of `POST /api/Feedbacks` are not in dispute.

---

## F10. Islands - all three modules ARE wired (MEASURED)

| module | permission | tool spec | dispatch | planner call site | auto-store |
|---|---|---|---|---|---|
| `rendered_forms` | tools.py:517 | tools.py:878 | tools.py:6142 | planner.py:938 (once per host base) | agent.py:98 |
| `nosqli_body` | tools.py:544 | tools.py:867 | tools.py:9653 | planner.py:987 (per param endpoint) | agent.py:97 |
| `spa_routes` | n/a (not a tool) | n/a | called from `_run_katana`, tools.py:5224 | n/a - feeds `_add_urls` | n/a |

No island. `spa_routes` is correctly NOT a tool: its output joins the crawl surface through
`_add_urls`, and its failures go through `self._swallow` rather than a bare `except`.

One note on the `spa_routes` call site (tools.py:5224-5231): `_spa.discover_async` is called with
`headers=self.session_headers or None`. `session_headers` is the mission's AUTHENTICATED identity,
so the drive types markers into controls while holding a session. That is deliberate and useful,
but it widens F2 and F9's concern: the un-gated boot navigation is made AS THE LOGGED-IN USER.

---

## F11. F6 CONFIRMED WITH TEETH - an INVENTED probe argument ships past the wildcard pin

Round 2 of the mutation sweep ran the decisive version: a third entry appended to
`WILDCARD_PAYLOADS` **and emitted** by `operator_payloads` in place of `$regex`, so an argument
with no relationship whatever to the observed value goes on the wire.

```
NB11b-third-wildcard-EMITTED       SURVIVED  52 passed
```

The payload that shipped: `{"$ne": "zz-invented-sentinel"}`. That is precisely "an invented value
probe wearing a different hat", the thing `test_only_declared_wildcards_are_ungrounded` is named
after, and the whole 52-test suite stays green. F6's mechanism is confirmed: the test uses
`WILDCARD_PAYLOADS` as its own exemption filter, so widening the list widens the exemption. A pin
has to assert the list's CONTENT against a literal, not against itself (memory:
"Self-referential assertion - a bound that tracks the thing it bounds is not a bound").

---

## F12. Round-2 sweep - remaining results

| mutant | result | note |
|---|---|---|
| NB11b third wildcard DECLARED **and EMITTED** | **SURVIVED** | F11 |
| SR11b visibility filter made STRICTER (`width <= 10`) | KILLED by `test_discovers_a_parameterised_spa_route_from_no_hand_supplied_url` | the handoff's M1 claim (juice-shop's only control is 4px wide, so a stricter rule loses it) is DEFENDED. Round 1's SR11 survived only because it loosened the filter, which no test can see. |
| SR13 drive DISABLED / readonly controls | **SURVIVED** | no test pins `el.disabled === true \|\| el.readOnly === true`. Low severity - typing into a disabled control does nothing - but the guard is unmeasured. |
| RF12 canary extraction forced to the whole payload | **SURVIVED** | the `or [payload]` fallback in `judge_probe` has no test. Direction is a FALSE NEGATIVE (the whole breakout string must then reflect verbatim), and I could not find a reachable production path into it: every shape that destroys the marker (`_NUMERIC_TYPES`, the zip/date `_SHAPES` with no `%s`) also destroys it in the BASELINE, so the control is `unmapped` and never planned. Reachability UNVERIFIED; the test gap is real. |
| RF13 `_INFRA_STATUSES` emptied | KILLED by `test_no_verdict_is_formed_from_a_response_the_edge_produced` | the 429/503 refusal is pinned against a literal, not against the imported constant. Correct. |
| NB12 empty/oversized values become candidates | KILLED by `test_candidate_fields_excludes_values_that_cannot_carry_an_observed_probe` | |

---

## F13. F4 downgraded to LOW after measuring the production scope gate

I first recorded the `chrome-error://chromewebdata/` route record (F4) without checking what the
REAL scope gate does with it. It filters it:

```
chrome-error://chromewebdata/            validate -> (False, 'chromewebdata not in scope')
about:blank                              validate -> (False, 'about not in scope')
data:text/html,x                         validate -> (False, 'data not in scope')
http://juice-shop:3000/#/search?q=       validate -> (True, 'In scope via juice-shop:3000')
```

`discover()` applies `_in_scope` BEFORE computing `out["note"]`, and the katana call site passes
`scope_ok=lambda u: self.scope.validate(u)[0]`, so in production neither `routes`, `urls` nor the
note is polluted. What survives the downgrade:

* `out["attempts"]` is NOT filtered, so the evidence still records `"changed": true` for a
  navigation that FAILED because of the module's own abort. An attempt log that says the
  application navigated when it did not is a small claim-vs-fact defect in the evidence trail.
* `test_finds_routes_on_an_application_that_is_nothing_like_juice_shop` uses the DEFAULT
  `scope_ok` (`lambda _u: True`), so the junk record IS in that test's `res["routes"]` today and no
  assertion notices.

MEASURED with the default gate (`_breaker_p3_detail.py`):

```
{"path": "/", "params": [], "parameterized": false,
 "url": "chrome-error://chromewebdata/", "observed_url": "chrome-error://chromewebdata/"}
```

Also measured, for the record: `route_record` accepts `about:blank` (path `"blank"`) and
`data:text/html,x` (path `"text/html,x"`) as routes. All three are scope-filtered in production.

---

## F14. THINGS I TRIED TO BREAK AND COULD NOT

These are results, and they are the reason the sections above should be read as narrow rather than
as a verdict on the work.

### F14a. `rendered_forms` produced ZERO false positives across four applications

MEASURED. `rf.run()` over juice-shop (`#/login`, `#/register`, `#/contact`, `#/forgot-password`),
dvga:5013, vampi:5000, domsource:8080 - 4 forms found, 12 real submissions:

```
counts: {'forms': 4, 'wire_observed': 1, 'probes': 6, 'submissions': 12, 'findings': 2}
  --- route #/login container=form#login-form action=None method_attr=None
      wire: observed=True POST http://juice-shop:3000/rest/user/login carrier=json
            params={'#email': 'email', '#password': 'password'} unmapped=[]
      probe sqli        #email     status=500 verdict=True
      probe auth_bypass #email     status=200 verdict=True
      probe xss         #email     status=500 verdict=False  reflected into a
              application/json; charset=utf-8 response, which a browser does not parse as markup
      probe sqli        #password  status=401 verdict=False  no DBMS error signature appeared
              that the baseline lacked
      probe auth_bypass #password  status=401 verdict=False  no session was issued that the
              benign invalid credential did not also get
      probe xss         #password  status=401 verdict=False  the value does not reflect
  --- route #/register  wire: observed=False unmapped=[4 controls] note='enter on
      #securityAnswerControl did not produce a request carrying our value (Timeout 9000ms)'
  --- route #/contact   wire: observed=False  (CAPTCHA - the stated limitation)
  --- route #/forgot-password container=div wire: observed=False
FINDINGS: 2   (both on #email, both genuinely present in juice-shop)
```

Both findings are real. Three refusals on the SAME form's other real field, each with a different
stated reason. Three forms it could not submit are reported `observed: False` WITH the reason
rather than as clean. dvga / vampi / domsource: 0 forms, 0 findings, no invented ones. This is the
behaviour the false-HIGH memory entries were written to demand, and I could not produce a
counterexample.

### F14b. The `Inconclusive` sentinel cannot be read as a verdict

MEASURED (`_breaker_p7_equiv.py`):

```
analyze_boolean(... samples=[None]) -> Inconclusive("a reference request did not complete, ...")
bool(v): False | `if v:` would fire: False | v == False: True | is_inconclusive(v): True
isinstance(v, int): True  int value: 0
```

Falsy by construction (`class Inconclusive(int)` with value 0), AND explicitly consulted by
`probe_json_body`. Two independent closures. The round-1 mutant NB7 (removing the
`is_inconclusive` `continue`) survived because it is an EQUIVALENT mutant, not because the guard is
missing - the sentinel's falsiness already refuses. Recorded as EQUIVALENT, not SURVIVED.

### F14c. RF8 is an equivalent mutant too

Removing `if canary not in body: return not-confirmed` from `judge_reflection` survived, but
`xt.contexts_of(body, canary)` returns `[]` for an absent canary and the next branch refuses:

```
xt.contexts_of(body_without_canary, 'apolakirfzz') -> []
judge_reflection with an absent canary -> {'confirmed': False, 'oracle': 'reflection',
                                           'reason': 'the value does not reflect'}
```

The early return buys a clearer REASON string, not a guard. Recorded as EQUIVALENT.

### F14d. `judge_error`'s "confirm without the escaped-quote control" branch is unreachable

`judge_error(baseline, probe, control=None)` skips the escaped-quote check entirely and confirms on
the error signature alone. I tried to reach it. `probe_plans` checks its plan cap ONCE PER FIELD,
before appending that field's whole plan group, so a field is either fully planned or fully
skipped and an sqli probe never loses its control:

```
max_fields=1 ->  3 plans, 1 sqli probes, 1 controls, ORPHAN probes: none
max_fields=2 ->  6 plans, 2 sqli probes, 2 controls, ORPHAN probes: none
max_fields=3 ->  9 plans, 3 sqli probes, 3 controls, ORPHAN probes: none
max_fields=4 -> 12 plans, 4 sqli probes, 4 controls, ORPHAN probes: none
max_fields=8 -> 24 plans, 8 sqli probes, 8 controls, ORPHAN probes: none
```

Defensive-only on the current call graph. A control submission that FAILS is a different path and
is handled correctly (`if not control.get("observed"): return not-confirmed`) - this is exactly the
case `nosqli_body` gets wrong in F1, so the two modules disagree about the same question and
`rendered_forms` has the right answer.

### F14e. The scope gate is honoured, and `spa_routes` sent nothing out of scope

MEASURED (`_breaker_p2_boot.py`): the fixture page fetched a second, out-of-scope origin with a
POST at 950ms. Nothing reached that server:

```
--- what actually reached the OUT-OF-SCOPE server ---
(empty)
requests that left the browser off-scope: []
```

That is the read-only gate doing its job on a cross-origin write. (It was blocked as a WRITE, not
as out-of-scope - `_read_only_gate` does not consult scope at all - but the outcome held.)

### F14f. `parameterized` is genuinely computed, and the module carries no route literal

`SR6` (asserting `parameterized: True`) is killed by the named negative control. And
`test_finds_routes_on_an_application_that_is_nothing_like_juice_shop` is a real anti-signature
test: a framework-free fixture with routes `/find` and `#/lookup` and parameters `term` and
`needle`, none of which appear in `spa_routes.py`. I re-ran it with the whole suite and it passes
on its own merits.

---

## F15. Smaller observations, recorded but not argued as defects

1. `rendered_forms.run`'s `max_forms` counter (`seen`) is global across ROUTES, not per route, and
   the inner `break` only leaves the current route's form loop. MEASURED above: with
   `max_forms=4` and five routes, `#/search?q=a` was never reached because the first four routes
   consumed the budget. An earlier route with many forms starves every later one.
2. `spa_routes._settle`'s `window.__apolaki_ctl = null` reset - the Coordinator's repair, commented
   "LOAD-BEARING" - is called from exactly one place (`_goto`, line 319), which always performs a
   navigation, and a navigation gives a fresh `window`. `_STABLE_JS` reads
   `window.__apolaki_ctl || {c:-1,s:0}`, and `undefined` and `null` are both falsy, so the reset is
   a no-op on that path. The round-1 mutant SR12 (removing it) survived every test, consistent with
   that. NOT a defect - the `_swallow` is correct practice regardless - but the "LOAD-BEARING"
   label is stronger than the call graph supports.
3. `_read_only_gate` uses `route.abort()` inside `except Exception: pass`. If the abort itself
   raises (a route already handled, a closing page) the route is left UNHANDLED and the request
   hangs until Playwright's own timeout. MEASURED as behaviour (`P1f`), not as a live failure.
4. `spa_routes` is called from `_run_katana` with `headers=self.session_headers or None` - the
   authenticated identity. Correct for discovery; it means F2's un-gated boot navigation is made as
   the logged-in user.
5. `db.get_exchanges` has no `ORDER BY`, and `_run_nosqli_body` takes `rows[0]`. SQLite returns
   rowid order for this query shape in practice, so the earliest matching exchange wins, but the
   ordering the selection depends on is not stated anywhere.

---

## F16. Summary and suggested order of work

Nothing here should be read as "the three modules are bad". 27 of 33 round-1 mutants and 3 of 6
round-2 mutants died, every oracle refusal in `rendered_forms` is defended by a test that really
fails when it is removed, the live FP hunt across four applications came back clean, and the
`Inconclusive` trap is closed twice over.

Ordered by what I would fix first:

| # | Severity | Where | What |
|---|---|---|---|
| F8 | HIGH | `tools._run_nosqli_body` (wiring) | the "observed" body is one Apolaki composed; on a login endpoint it is literally another engine's `' OR 1=1--` payload, and the baseline it references is an authenticated 200 |
| F1 | HIGH | `nosqli_body.probe_json_body` | a dropped control / omit request DELETES the control instead of degrading the verdict - two confirmed HIGHs on the suite's own CLEAN apps |
| F11/F6 | MEDIUM | `tests/test_nosqli_body.py` | the wildcard pin uses the list it pins as its own exemption; an invented `$ne` argument ships green |
| F2 | MEDIUM | `spa_routes.discover` | the read-only guarantee has an un-gated first-navigation window; 2 POSTs measured on a fixture, 1 on juice-shop |
| F9 | MEDIUM | `nosqli_body` | POST is on `NON_MUTATING_METHODS` and the observed body is REPLAYED ~10x; a creating POST is performed ten times |
| F3 | MEDIUM | `spa_routes._read_only_gate` | fails OPEN when the method cannot be read |
| F5 | MEDIUM | `tests/test_spa_routes.py` | the no-sleep AST walk passes the exact `getattr` form its docstring says it catches, and a bare `sleep()` |
| F12 | LOW | `tests/*` | `SR13` (disabled controls) and `RF12` (canary fallback) are unmeasured |
| F13/F4 | LOW | `spa_routes` | `attempts` records `changed: true` for a navigation the module's own abort broke |
| F15 | note | various | five smaller observations |

## Provenance of every measurement in this file

All runs in a throwaway container (`--rm`, `--network apolaki_default`). The shared
`apolaki-agent-1` was never touched and was never restarted. Mutations were applied ONLY to a
scratch copy of `agent/` (`<scratch>/mut`), verified byte-identical to the repo before the sweep
via `md5sum` on all three modules, and every mutant was restored in a `finally`. The live database
work used `BBH_DB_PATH=/tmp/breaker20.db` inside the container. The only file in the repository
this review wrote is this one.

Probe scripts (in `<scratch>/probe`, none of them in the repo):
`_breaker_p1_gate.py`, `_breaker_p2_boot.py`, `_breaker_p3_detail.py`, `_breaker_p4_dropped.py`,
`_breaker_p5_observed.py`, `_breaker_p6_rf_live.py`, `_breaker_p7_equiv.py`, `_breaker_p8_scope.py`.
Mutation harnesses (in `<scratch>/mut`): `_breaker_mutate.py`, `_breaker_mutate2.py`.

