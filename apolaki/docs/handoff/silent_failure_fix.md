# I-5 silent-failure residue: fixing the 15 load-bearing literal-return handlers

Lane opened 2026-08-21 from HEAD `66a7012` (verified green 3519 passed / 11 skipped /
12 xfailed / 0 failed).

## The defect this lane fixes

`_swallowed()` in `agent/tests/test_silent_failure_invariant.py` applies `_constant()`
to its **Assign** branch but not to its **Return** branch. A handler ending `out = []`
is classified; a handler ending `return []` is classified into no category at all and
is therefore constrained by no ceiling. The guard was repaired in a previous lane to
census and CAP those handlers (`_literal_return_swallow`, ceilings at the bottom of the
file). Capping is not fixing. The handlers themselves still swallow.

Fix shape (the one `tools.py` already uses elsewhere): record the swallow, then return
the same empty value. **The return value and the control flow do not change.** The only
change is that the failure becomes visible in the swallow ledger instead of being
indistinguishable from a clean result.

---

## DELIVERABLE 1 - the 15 load-bearing literal-return handlers (MEASURED)

Derived with the guard's own machinery, not a new predicate:
`_partition(predicate=_literal_return_swallow)` with the shipped `_load_call` /
`load_shaped` classification, run against the imported modules inside a throwaway
`apolaki-agent` container.

Command:

    MSYS_NO_PATHCONV=1 docker run --rm -i \
      -v "C:/Users/voice/Desktop/GitHub/MISC/apolaki/agent:/app" -w /app \
      apolaki-agent python - < derive.py

Real output (header line):

    TOTAL 89 {'optional': 61, 'load-bearing': 15, 'control-plane': 13}

which reproduces the shipped ceilings exactly (`optional <= 61`,
`control-plane <= 13`, `load-bearing <= 15`). The 15, as `module:line:function`:

| # | module:line:function |
|---|----------------------|
| 1 | `bie.py:1401:session_fingerprint` |
| 2 | `dns_recon.py:130:doh` |
| 3 | `enip_audit_tool.py:84:_list_identity_tcp` |
| 4 | `tools.py:2457:_fetch` |
| 5 | `tools.py:2874:_get` |
| 6 | `tools.py:3409:_socket_service_probe` |
| 7 | `tools.py:3425:_socket_service_probe` |
| 8 | `tools.py:3608:_send` |
| 9 | `tools.py:4773:_discover_params` |
| 10 | `tools.py:5472:_form_xss_browser_confirm` |
| 11 | `tools.py:5678:_send` |
| 12 | `tools.py:6586:send` |
| 13 | `tools.py:7582:read_state` |
| 14 | `tools.py:7608:worker` |
| 15 | `tools.py:8416:q` |

Ownership check against this lane's write boundary: **none of the 15 live in
`deadcode_gate.py` or `exposure_tool.py`** (both owned by another live lane), so none
has to be deferred as a patch-in-doc. Modules touched: `tools.py` (12), `bie.py` (1),
`dns_recon.py` (1), `enip_audit_tool.py` (1).

Line numbers are as of the working tree at lane open; they shift as fixes land above
them. The `module:function` pair is the stable key - `tools.py` has two distinct
`_send` and the two `_socket_service_probe` rows are two handlers in one function.

---

## Per-site context (MEASURED by AST, same run as the table)

`chain` is innermost-first. `loadcalls` is why `_load_call` classified the protected
block as load-bearing.

| site | chain | protected call that made it load-bearing | discarded value |
|------|-------|------------------------------------------|-----------------|
| `tools.py:2457` | `_fetch < _run_authz_matrix` | `self._http_send` | `(0, "")` |
| `tools.py:2874` | `_get < _run_header_trust` | `self._http_send` | `{"status": 0, "body": ""}` |
| `tools.py:3409` | `_socket_service_probe` | `asyncio.open_connection` | `{"confirmed": False}` |
| `tools.py:3425` | `_socket_service_probe` | `reader.read` | `{"confirmed": False}` |
| `tools.py:3608` | `_send < _test_numeric_abuse` | `self._http_send` | `(0, "")` |
| `tools.py:4773` | `_discover_params` | `self._http` | `[]` |
| `tools.py:5472` | `_form_xss_browser_confirm` | `rate_limited_goto`, `page.fill` | `(False, "")` |
| `tools.py:5678` | `_send < _run_encoded_cookie` | `c.get` | `{"status": 0, "len": 0}` |
| `tools.py:6586` | `send < _run_oauth` | `c.get` | `(0, "")` |
| `tools.py:7582` | `read_state < _run_race` | `c.get` | `{}` |
| `tools.py:7608` | `worker < _run_race` | `c.request` | `{"status": 0, "length": 0}` |
| `tools.py:8416` | `q < _sqli_db_metadata` | `c.get` | `(0, "")` |
| `bie.py:1401` | `session_fingerprint` | `c.get` | `{}` |
| `dns_recon.py:130` | `doh` | `httpx.AsyncClient`, `c.get` | `[]` |
| `enip_audit_tool.py:84` | `_list_identity_tcp` | `socket.create_connection` | `b""` |

In every case the discarded value is ALSO the value the caller reads as a clean negative:
status 0 = "denied/rejected", `{}` = "state did not change", `[]` = "page has no params",
`(False, "")` = "the payload did not execute". That is the whole defect - the failure
is not merely lost, it is converted into evidence of security.

---

## Progress log

### Slice 1 - the 12 ToolRegistry sites (committed)

Each handler now reads `except Exception as _apolaki_exc: self._swallow(_apolaki_exc,
"<owner>", <target>); return <same literal>`. Return values and control flow are
byte-unchanged; the only change is that the failure reaches the ledger.

Owner vocabulary (stable semantic names, not line numbers - the shipped
`'tools:<fn>:<lineno>'` labels in this file go stale on every edit above them):
`authz_matrix.fetch`, `header_trust.get`, `service_pack.socket_connect`,
`service_pack.socket_exchange`, `numeric_abuse.send`, `param_discovery.discover`,
`form_xss.browser_confirm`, `encoded_cookie.send`, `oauth.send`, `race.read_state`,
`race.worker`, `sqli_metadata.query`.

New oracle: `agent/tests/test_silent_failure_residue.py`, 12 tests. Each forces the
protected call to raise and asserts `reg.swallowed` names that owner; the unchanged
return value is asserted only as a control.

**FAIL-BEFORE PROOF (MEASURED).** Snapshot built with `git archive HEAD apolaki/agent`
(NOT `cp -r`), 480 .py files extracted, the new test file copied in, mounted read-only
into a throwaway container:

    docker run --rm -v "<scratch>/pristine/apolaki/agent:/app" -w /app apolaki-agent \
      python -m pytest tests/test_silent_failure_residue.py -p no:cacheprovider -rfE -q

    12 FAILED, EXIT=1

All twelve named in the short summary. Same file against the fixed tree:

    docker run --rm -v ".../apolaki/agent:/app" -w /app apolaki-agent \
      python -m pytest tests/test_silent_failure_residue.py -p no:cacheprovider -rfE -q

    ............  EXIT=0

Census movement, MEASURED before and after with `_partition(predicate=_literal_return_swallow)`:

    before: LITERAL-RETURN 89 {'optional': 61, 'load-bearing': 15, 'control-plane': 13}
    after:  LITERAL-RETURN 77 {'optional': 61, 'load-bearing':  3, 'control-plane': 13}

The default `_swallowed` census is UNCHANGED at `{'optional': 388, 'control-plane': 77,
'load-bearing': 0}`, which is the negative control that this lane did not move handlers
between categories to make a number look better.

Guard edits, both in the tightening direction:
- ceiling `counts["load-bearing"] <= 15` LOWERED to `<= 3`, with the reason in the
  docstring. A ceiling was never raised in this lane.
- `_SWALLOW_RECORDERS` is a FLOOR, not a ceiling. Raised for the 10 owners that gained
  recorders (census total 160 -> 172, owners 77 -> 89) so the 12 new recorders are
  themselves protected against silent deletion. `_recorder_losses` returns `{}`.

Note on the census key: `(module, function)` uses the INNERMOST enclosing function, so
the two distinct nested `_send` closures (`_test_numeric_abuse` and
`_run_encoded_cookie`) collapse into one baseline entry `("tools.py", "_send"): 2`.

