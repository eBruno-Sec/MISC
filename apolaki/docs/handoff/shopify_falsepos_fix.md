# Shopify false-positive lane — Q-097 / Q-096 / Q-098

**Origin:** a full deterministic assessment against the Shopify HackerOne program on 2026-08-24
produced 18 findings **without ever opening a socket to Shopify**. Three separate defects had to line
up for that to happen. This file is written AS THE WORK HAPPENS; if the lane dies, this is the
contribution.

**Baseline at HEAD `08158c2`:** 3581 passed / 11 skipped / 12 xfailed / 0 failed (Coordinator's
measurement; re-measured here — see §0).

**No traffic was sent to Shopify at any point in this lane.** Every live measurement below is against
the local docker labs on `apolaki_default`.

---

## 0. Baseline re-measurement

Command (backgrounded at the start of the lane):

```
MSYS_NO_PATHCONV=1 docker run --rm --network apolaki_default \
  -v "C:/Users/voice/Desktop/GitHub/MISC/apolaki/agent:/app" -w /app apolaki-agent \
  python -m pytest tests/ -p no:cacheprovider -rfE -q
```

Result: PENDING (running).

---

## 1. Q-097 — `_run_transport_posture` invents header findings from a dead socket

### Reading of the code (MEASURED by reading, before any edit)

`agent/tools.py:3326` `_run_transport_posture`. At `:3347-3359`:

```python
headers, set_cookies = {}, []
try:
    r, _ = await self._http_send("GET", origin + "/", {}, None, True)
    headers = dict(r.headers or {})
    ...
except Exception as _apolaki_swallowed_2960:
    self._swallow(_apolaki_swallowed_2960, 'tools:_run_transport_posture:2960', "")
    pass
```

`headers` stays `{}` when the GET never completes, and `{}` is then handed to
`transport_posture.findings_for(... headers=headers ...)` → `analyze_security_headers(headers or {})`
(`agent/transport_posture.py:275`), which reports **every** protective header absent. The engine then
returns `success=True` with `"ran": true`.

`analyze_cookies` / `analyze_cookie_scope` (empty `set_cookies`) and `analyze_methods` (empty
`allow_header`) are on the same failure path; they happen to be quiet on empty input, so the header
analyser is the one that manufactures findings.

Q-093's chokepoint is in `_http` (`tools.py:4078`, `_http_record`). This path uses `_http_send`
(`tools.py:2282`), which **raises** instead of returning a dict, and the raise is caught locally. So
the Q-093 counter never sees it — confirmed by reading both functions.

The `reachable` signal is already measured and already ignored: `transport_posture.py:502` seeds
`out["reachable"] = False`, `:513` sets it True only after a completed handshake, and the summary
built at `tools.py:3384` copies it into `"tls": {"reachable": ...}` while emitting the findings
anyway.

### The RED gate (committed BEFORE the fix)

`agent/tests/test_transport_posture_dead_socket.py`. Five tests, and the split is the point:

```
$ docker run --rm --network apolaki_default -v ".../agent:/app" -w /app apolaki-agent \
    python -m pytest tests/test_transport_posture_dead_socket.py -p no:cacheprovider -q --tb=no
FF...                                                                    [100%]
```

**2 failed, 3 passed at HEAD.** The 2 failures are the defect; the 3 that ALREADY PASS are the
non-vacuity controls, and their passing before the fix is what proves the file can tell a dead socket
from a bare page rather than merely disliking findings.

MEASURED failure 1 — the 18-finding mechanism, reproduced:

```
AssertionError: header findings were emitted from a request that never completed:
  {'header_missing_x_content_type_options', 'header_missing_csp',
   'header_missing_permissions_policy', 'header_missing_framing_control',
   'header_missing_referrer_policy'}
 + where ... = ToolResult(tool='transport_posture', target='http://juice-shop:3000',
                          success=True, output='DEGRADED: 3 load-bearing c...', error=None)
```

5 rather than 6 only because this fixture is a plaintext origin, so the HSTS rule is correctly
skipped; the field mission was https, which is where the 6th came from. Note `success=True` and the
`DEGRADED:` prefix — the run KNEW three load-bearing calls had failed and emitted the findings anyway.
**Visibility is not enforcement**, in one ToolResult.

MEASURED failure 2 — the pure layer has no way to express "not observed":

```
TypeError: findings_for() got an unexpected keyword argument 'http_observed'
```

The three controls that pass at HEAD:
- a live page that genuinely sends no CSP still reports `header_missing_csp`;
- a live page that sends CSP/XFO/XCTO/Referrer-Policy/Permissions-Policy is accused of none of them;
- the real lab: juice-shop:3000, real sockets. MEASURED 2026-08-24 — it sends
  `x-frame-options: SAMEORIGIN` and `x-content-type-options: nosniff`, and sends neither
  Content-Security-Policy nor Referrer-Policy, so ONE real response proves both directions.

### The fix

Two files, one idea: **an absence can only be observed in something that arrived.**

1. `agent/transport_posture.py:findings_for` gains `http_observed: bool = True`. When it is False the
   cookie, protective-header and method analyses are not run at all. The default preserves every
   existing caller — `headers={}` still means "a response arrived carrying no protective headers" and
   still reports all six. The two states were previously the same VALUE; now they are different
   ARGUMENTS.
2. `agent/tools.py:_run_transport_posture` records `http_ok` / `http_err` in the `except` that
   previously only swallowed, and passes `http_observed=http_ok` down.
   - **Neither channel observed** (HTTP GET failed AND the TLS handshake was not reachable):
     `ran=False`, zero findings, `success=False`, and `error` naming the transport cause. This is the
     Shopify case.
   - **TLS reachable but the GET failed**: the TLS/certificate findings are real evidence and stay;
     the cookie/header/method half is WITHHELD and the summary says so. Silence about the whole origin
     would have thrown away a genuine observation.

`tls_reachable` is now read from the probe into the branch, so the flag that was already measured at
`transport_posture.py:502/513` and printed into `"tls": {"reachable": false}` finally decides
something.

**Stale swallow labels fixed** — the ticket names one, there were three, all in this function:
`:2960 -> :3367`, `:2967 -> :3374`, `:2972 -> :3380` (the true `self._swallow` call-site lines).

**Something the RED gate turned up that the ticket did not have.** The engine's own `res.output` on the
dead path begins:

```
DEGRADED: 3 load-bearing check(s) failed to execute; latest=tools:_run_transport_posture:2972 {"ran": ...
```

The dispatch KNEW all three of its calls had died, said so in its own output string, and emitted five
missing-header findings underneath that sentence with `success=True`. That is the ticket's "visibility
is not enforcement" in a single artifact, and it is now recorded in the test's `_summary()` helper so
the next reader does not have to rediscover it.

### MEASURED after the fix

```
$ docker run --rm --network apolaki_default -v ".../agent:/app" -w /app apolaki-agent \
    python -m pytest tests/test_transport_posture_dead_socket.py tests/test_transport_posture.py \
      tests/test_asvs_transport_config_objective.py tests/test_silent_failure_invariant.py \
      tests/test_deadcode_gate.py tests/test_oracle_properties.py \
      tests/test_ledger_negative_result.py tests/test_arsenal_errored_class.py \
      tests/test_scope_origin_carry.py tests/test_sqli_stability.py -p no:cacheprovider -q
EXIT=0     (176 tests, 1 xfail, 0 failed)
```

The gate file went `FF...` -> `.....`, and the three guards named in the house rules
(`test_deadcode_gate`, `test_silent_failure_invariant`, plus `test_external_tool_liveness` in the full
run) were not edited.

**A note on the first baseline run, so the record is honest.** The lane's opening full-suite baseline
was started against the LIVE working tree and then I edited `tools.py` while it was still running. It
finished `1 failed` on `test_sqli_stability.py::test_every_shipping_boolean_call_supplies_the_reference_sample`
— a source-reading guard that read a half-edited `tools.py`. Re-run against the settled tree: PASSES
(included in the command above). **That failure was my own torn read, not a regression**, and the
lesson is the same one `git archive emits CRLF` taught: a mid-flight snapshot of a shared tree is not
a measurement. Subsequent full-suite runs are started only when the tree is settled.

---

---

## 2. Q-096 — the scope REGEX is used as a hostname

STATUS: not started (Q-097 first, per lane order).

---

## 3. Q-098 — evidence-graded impact text bound to CWE, not to the finding family

STATUS: not started.
