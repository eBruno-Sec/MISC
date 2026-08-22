# I-5 silent-failure residue: fixing the 15 load-bearing literal-return handlers

Lane opened 2026-08-21 from HEAD `66a7012` (verified green 3519 passed / 11 skipped /
12 xfailed / 0 failed).

## STATUS: all 15 fixed, plus the live instance routed in mid-lane

| slice | what | commit |
|-------|------|--------|
| 0 | the 15 derived by AST and written down before any edit | `859e803` |
| 1 | 12 ToolRegistry sites route through `self._swallow` | `5f50857` |
| 2 | 3 module-level helpers + the executor boundary that would have made one an island | `196dfda` |
| 3 | Q-091 dalfox: a live instance of this exact defect class, 171 invocations of evidence | `f9a8815` |
| 4 | no-island check on all 11 recorder owners | `7871871` |

Census movement, MEASURED at each step with the guard's own predicates:

    literal-return load-bearing:  15 -> 3 -> 0
    _swallowed optional:         388 -> 388 -> 387
    swallow recorders:           160 -> 172 -> 176 -> 177   (losses: {} throughout)

Ceilings were LOWERED three times and raised zero times. `_SWALLOW_RECORDERS` is a
FLOOR, and raising it (14 new owners) is tightening, not loosening.

23 new tests in `agent/tests/test_silent_failure_residue.py`, counted by running the
file, not by counting `def`s:

* **19 are kills** - measured RED against a `git archive HEAD` snapshot before the
  matching fix, green after. 12 at slice 1, 4 at slice 2, 3 at slice 3.
* **4 are CONTROLS** that pass on BOTH sides on purpose, and are labelled as such in
  the file: the ContextVar propagation measurement, dalfox's `[{}]` staying a real
  zero, dalfox JSONL still parsing, and the line-by-line mechanism proof. A control
  that only passes after the fix is not a control.

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

### Slice 2 - the 3 module-level helpers (committed)

`bie.session_fingerprint`, `dns_recon.doh` and `enip_audit_tool._list_identity_tcp` have
no ToolRegistry `self`, so `_swallow` was simply not reachable from them. Added
`tools._ACTIVE_REGISTRY` (a ContextVar, set and reset on exactly the span
`_ACTIVE_TOOL_DISPATCH` already covers in `execute`) plus a module-level
`tools._swallow(exc, where, target) -> bool` that forwards to the registry running the
current dispatch. Same ledger, same DEGRADED line, same durable `tool_error` row.

Three constraints shaped this, all of them real:

1. **No new production module.** `test_partition_is_non_vacuous...` asserts
   `len(trees) == 178` as an EQUALITY, so a new `.py` under `agent/` turns it red. The
   recorder therefore lives in `tools.py`, not in a new shared module.
2. **No new broad `except`.** The obvious `try: import tools / except: pass` guard
   around the import would itself be censused as an optional swallow and push
   `counts["optional"]` past its 388 ceiling. The helpers use
   `sys.modules.get("tools")` instead: it cannot raise, cannot trigger an import, and
   does not give a leaf module a hard dependency on the orchestrator.
3. **The recorder is named `_swallow`, deliberately.** `_swallow_recorder_census`
   counts calls whose attribute is literally `_swallow`, so the module-level face is
   covered by the same deletion ratchet as every `self._swallow`.

**THE ISLAND THIS ALMOST SHIPPED (MEASURED).** ContextVars do not cross every thread
boundary, and `enip_audit_tool.probe` is dispatched into one:

    python 3.12.14
    direct            = SET
    run_in_executor   = None      <-- the trap
    asyncio.to_thread = SET

`_run_service_pack`'s enip branch used
`asyncio.get_event_loop().run_in_executor(None, _en.probe, ...)`, which does NOT copy the
context, so `_ACTIVE_REGISTRY.get()` returns its default in the worker thread and the new
recorder would have been registered and never reached - a textbook island, and invisible
to any test that called the helper directly. Changed that ONE call site to
`asyncio.to_thread(_en.probe, host, int(port))`: same default executor, same arguments,
same result, only the context now crosses. `bie` was already on `asyncio.to_thread`
(tools.py:3138) and `dns_recon.doh` is pure async, so neither needed a change.

**Mutant M-EXEC, to prove that change is load-bearing and not decorative.** Snapshot from
`git archive HEAD` with the slice-2 patch applied, then the executor line - and ONLY that
line - reverted. Proof the mutant landed, read back through the IMPORTED module rather
than the file on disk:

    imported module has run_in_executor(None, _en.probe): True
    imported module has to_thread(_en.probe): False

Result: `test_enip_socket_crash_is_not_reported_as_no_ics_device` FAILED with
`AssertionError: []` - the swallow ledger is empty, which is exactly the false clean.
M-EXEC is KILLED. Every recorder was left in place in the mutant, so the failure is
attributable to the boundary and nothing else.

**FAIL-BEFORE PROOF (MEASURED).** Fresh `git archive HEAD` snapshot (481 .py files),
slice-2 production confirmed ABSENT (`_ACTIVE_REGISTRY` count 0, `dns_recon.doh` count 0)
and slice-1 production confirmed PRESENT (`authz_matrix.fetch` count 1):

    5 FAILED, EXIT=1
      test_module_level_swallow_reports_whether_it_actually_recorded
      test_doh_transport_crash_is_not_reported_as_a_domain_with_no_records
      test_enip_socket_crash_is_not_reported_as_no_ics_device
      test_bie_session_fingerprint_crash_is_not_reported_as_two_identical_sessions
      test_every_repaired_owner_is_reachable_from_a_real_execution_path

The 12 slice-1 tests pass there, correctly - HEAD already carries slice 1.
`test_contextvars_do_not_cross_run_in_executor_but_do_cross_to_thread` also passes there:
it measures Python's semantics, not this fix, and it is in the file so the enip call site
cannot be "simplified" back without a test that explains why.

Two of the three are driven END TO END through a real `ToolRegistry.execute(...)`
dispatch - `run_dns` and `run_service_pack` - not by calling the helper directly. The
`run_dns` case is the clearest statement of the whole defect: with every `doh` returning
`[]`, `gather_dns` reports `SPF MISSING, DMARC MISSING, 0 CAA, 0 vendors` and `run_dns`
returns ran=True. A resolver outage was being rendered as an email-authentication
finding. It now carries `DEGRADED: ... latest=dns_recon.doh`.

Census after slice 2:

    LITERAL-RETURN 74 {'optional': 61, 'control-plane': 13}     load-bearing: 0
    SWALLOWED     465 {'optional': 388, 'control-plane': 77}    load-bearing: 0  (unchanged)
    RECORDERS total=176 owners=93                               LOSSES {}

Ceiling LOWERED 3 -> 0 and converted from `<=` to `==`: with the residue cleared, a new
`except: return []` on a load-bearing path is a regression, not a budget item.

Also corrected two now-stale claims in the guard's own comments rather than leaving them
to rot: the header comment said the strong invariant "is FALSE: 15 such handlers exist",
and `_literal_return_swallow`'s docstring justified staying separate from `_swallowed`
by those same 15. Both were true when written and are not now. The predicates stay
separate for the REAL remaining reason: merging moves 61 optional + 13 control-plane rows
into the main census and would need `counts["optional"] <= 388` raised to absorb them.
A ceiling is not raised to make a merge fit.

### Known limitation (stated, not hidden)

`tools._swallow` is a no-op when no dispatch is active, and returns `False` to say so.
Every shipped call site of the three helpers runs inside `ToolRegistry.execute`, which is
why the end-to-end tests above can exist at all. If one is ever called from `planner.py`,
`memory.py` or `retest.py` (today those import only `is_junk_host`, `retest_recipe` and
`retest_verdict`), its failure would be silent again. The `-> bool` return is the hook a
future test uses to detect that, and is asserted in both directions by
`test_module_level_swallow_reports_whether_it_actually_recorded`.

### Slice 3 - Q-091, a live instance of this defect class (committed)

Routed in by the Coordinator mid-lane; `tools.py` was already in this lane's write set.

`_run_dalfox` parsed dalfox `--format json` output line by line under `except: pass`.
dalfox emits a JSON ARRAY. The Coordinator's measurement against the authorized local
Juice Shop lab: a no-result run writes exactly `[\n{}]` - 6 bytes, 2 lines, exit 0, empty
stderr. `json.loads("[")` raises and `json.loads("{}]")` raises, both swallowed. This is
STRUCTURAL: with real results the lines are `[`, `{...},`, `{...}]`, and the array wrapper
plus trailing commas make every line invalid JSON standalone. `len(findings)` was pinned
at 0 for every possible dalfox output. Corpus: 171 invocations, "N XSS signals" histogram
`{0: 171}`, 0 of 1783 findings mentioning dalfox. With `ran=True` that is byte-identical
to a clean scan - this lane's invariant, with 171 invocations of evidence.

`test_dalfox_every_line_of_a_real_array_is_invalid_json_standalone` pins the mechanism
itself, so the reason can never be mistaken for a data quirk.

**Both hazards the Coordinator named are handled, and a third that was one level deeper.**

1. *Empty dicts.* `{}` is dalfox's "nothing found" placeholder. `_dalfox_rows` drops empty
   objects, so the measured `[{}]` stays a real zero. Otherwise the fix converts 171
   silent zeros into 171 empty-dict false positives - worse than the bug.
2. *A gate that proves nothing.* The kill tests feed the REAL bytes and a real multi-entry
   array. MEASURED against a `git archive HEAD` snapshot (ddb4d78, old parser confirmed
   present at tools.py:10810), 3 FAILED:
   `test_dalfox_multi_entry_array_is_actually_parsed`,
   `test_dalfox_findings_are_leads_and_can_never_be_auto_confirmed`,
   `test_dalfox_unparseable_output_is_recorded_not_counted_as_zero`.
   The three controls (`[{}]` stays zero, JSONL still parses, the mechanism test) pass on
   BOTH sides on purpose - a control that only passes after the fix is not a control.
3. *THE DEEPER HAZARD, found by reading the pipeline rather than the ticket.* Fixing only
   the parser would have been worse than the bug. Two measured reasons:
   - `agent._auto_store` (agent.py:1003) skips any finding without `severity`, and raw
     dalfox rows have none. `asvs_model.py:193` had already recorded this as Q-048/GAP-2.
     So a "fixed" parser would still have delivered nothing, while the count now read
     non-zero - a green number over the same dead path.
   - Worse: `run_dalfox` is in `agent._CONFIRMED_BY_TOOL`, and `agent._is_confirmed`
     auto-promotes an UNGRADED row from such a tool straight to CONFIRMED. Parsing the
     array without grading would have turned 171 silent zeros into auto-confirmed XSS
     findings.
   `_dalfox_finding` therefore shapes each row with an explicit `severity` and
   `confidence: "candidate"`, matching the truth-first rule `_run_nuclei` already applies
   to its heavy template set: an external scanner's signal is a LEAD until a native oracle
   confirms it. `test_dalfox_findings_are_leads_and_can_never_be_auto_confirmed` asserts
   through the REAL `BBHAgent._is_confirmed`, not a restatement of it.

Unparseable output is no longer counted as zero: `self._swallow(parse_error,
"dalfox.parse", url)` plus an output that says so and deliberately does NOT contain the
phrase "0 XSS signals", which is the phrase that used to lie.

Field names are read defensively through `.get` and the whole row is preserved under
`raw`: this lane captured dalfox's EMPTY output but never a multi-entry one, so no key
name is asserted as known.

Census after slice 3:

    LITERAL-RETURN 74 {'optional': 61, 'control-plane': 13}   load-bearing: 0
    SWALLOWED     464 {'optional': 387, 'control-plane': 77}  load-bearing: 0
    RECORDERS total=177 owners=94                             LOSSES {}

`counts["optional"]` ceiling LOWERED 388 -> 387, because the deleted `except: pass` is one
fewer censused swallow. Ratcheted rather than left slack, so that seat cannot be quietly
refilled. `_SWALLOW_RECORDERS` floor gains `("tools.py", "_run_dalfox"): 1`.

### No-island check on every recorder added by this lane (MEASURED)

A recorder in an engine nothing dispatches is a declaration, not a fact. `_dispatch_engine`
resolves `getattr(self, "_" + tool_name)`, so a method being absent from `CLAUDE_TOOLS`
proves nothing on its own - the tool-name STRING has several emitters. Each owner was
traced to a real one:

| owner | reached by |
|-------|-----------|
| `_run_authz_matrix` | `agent.py:2502` `_exec_internal("run_authz_matrix", ...)`; `tools.py:441` permission map |
| `_run_header_trust` | `agent.py:2813` `_exec_internal("run_header_trust", ...)`; `tools.py:435` |
| `_run_encoded_cookie` | `agent.py:4065` `_run_tool("run_encoded_cookie", ...)`; `tools.py:336` |
| `_test_numeric_abuse` | `packs.py:51` pack step; `agent.py:103` |
| `_run_oauth` | `planner.py:987` `_step("run_oauth", ...)` |
| `_run_race` | `agent.py:98`; `engine_descriptor.py:355` |
| `_run_dalfox` | `planner.py:914` `_step("run_dalfox", ...)` |
| `_socket_service_probe` | `tools.py:_run_service_pack` |
| `_discover_params` | `tools.py:_run_xss`, `_run_dom_audit`, `_run_dom_trace`; `agent.py:_inject_sweep_surface` |
| `_form_xss_browser_confirm` | `tools.py:_form_xss_emit` |
| `_sqli_db_metadata` | `tools.py:_run_sqli` |

None is inert. Two of the module-level three are additionally proven by END-TO-END tests
through a real `ToolRegistry.execute(...)` dispatch (`run_dns`, `run_service_pack`) rather
than by a call-graph argument.

### Not fixed here, deliberately

`_run_dalfox` findings still carry no `family` key, so they map to no ASVS objective
(Q-048/GAP-2, `asvs_model.py:193`). Adding one would change objective mapping owned by
`asvs_model.py`, which is not in this lane's write set, and the ASVS model does not list
`run_dalfox` for VAL-03 anyway. Flagged, not silently taken.

### Adjacent finding, NOT fixed here (out of scope, no owner assigned)

`tools.py` has 24 remaining `run_in_executor(None, ...)` call sites (dnp3, s7comm, vnc,
rsync, and others). None of them contains one of the 15 handlers, so none is a defect
today. But every one of them is context-blind by the measurement above: any future
module-level recorder placed behind them is a dead island by construction, and the
failure mode is silent. Worth a sweep by whoever owns the beyond-web packs.

