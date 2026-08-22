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
| 5 | Q-092 `_cmd`: exit status on the RETURN edge via `CmdResult`, 18 call sites, one shared predicate | `7a7b90b` |
| 6 | `tools._swallow` wired through a RESOLVED import - it had 3 callers, none visible to static analysis | `9f8293d` |

Between them, slices 5 and 6 clear all 8 of the failures HEAD was carrying:

* the 4 in `tests/test_external_tool_liveness.py`, which another lane wrote to fail by
  design until Q-092 landed - now 7/7 green, file unmodified;
* the 4 in `tests/test_deadcode_gate.py`, confirmed by name:

      4 passed in 12.35s

Neither file was edited, no baseline was raised, and no exemption was added.

## Census: before vs after, and the ceilings (the direct answer)

Both snapshots measured with the SAME predicates, run inside a throwaway container:
`git archive 66a7012` (lane open) versus the working tree.

    ########## BEFORE (66a7012, lane open) ##########
    literal-return : load-bearing=15  optional=61  control-plane=13   total=89
    _swallowed     : load-bearing=0   optional=388 control-plane=77   total=465
    recorders      : total=160 owners=80

    ########## AFTER (HEAD) ##########
    literal-return : load-bearing=0   optional=61  control-plane=13   total=74
    _swallowed     : load-bearing=0   optional=387 control-plane=77   total=464
    recorders      : total=177 owners=94

The real counts moved down. The ceilings moved down WITH them, so no slack was left
behind for the next regression to hide in:

| assertion | before | after | real count now | SLACK |
|-----------|--------|-------|----------------|-------|
| literal-return `load-bearing` | `<= 15` | `== 0` | 0 | **0** |
| literal-return `optional` | `<= 61` | `<= 61` | 61 | **0** |
| literal-return `control-plane` | `<= 13` | `<= 13` | 13 | **0** |
| `_swallowed` `optional` | `<= 388` | `<= 387` | 387 | **0** |
| `_swallowed` `control-plane` | `<= 77` | `<= 77` | 77 | **0** |
| `_swallowed` `load-bearing` | `== 0` | `== 0` | 0 | **0** |

**Every ceiling now sits exactly on the measured count.** The load-bearing one was
additionally converted from `<=` to `==`, so it is no longer a budget at all. Two
ceilings were lowered (15 -> 0, 388 -> 387); the three that did not move were already
touching their real count, because this lane fixed no `optional` or `control-plane`
handler. No ceiling was raised at any point.

`_SWALLOW_RECORDERS` is a FLOOR, not a ceiling. Raising it (80 -> 94 owners, 160 -> 177
recorders) is tightening: it makes each new recorder undeletable without a red test.

31 new tests in `agent/tests/test_silent_failure_residue.py`, counted by running the
file, not by counting `def`s:

* **25 are kills** - measured RED against a `git archive HEAD` snapshot before the
  matching fix, green after. 12 at slice 1, 4 at slice 2, 3 at slice 3, 6 at slice 5.
* **6 are CONTROLS** that pass on BOTH sides on purpose, and are labelled as such in
  the file: the ContextVar propagation measurement, dalfox's `[{}]` staying a real
  zero, dalfox JSONL still parsing, the line-by-line mechanism proof, a non-zero exit
  that still produced output, and exit 0 with no output. A control that only passes
  after the fix is not a control - two of these had to be rewritten when they turned
  out to fail pre-fix on a missing symbol rather than on behaviour.

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

### Q-091 empty-dict filter: VERIFIED PRESENT (re-checked on request)

The filter is in `_dalfox_rows`, on both parse paths, and it is the `and r` / `and row`
truth test that drops `{}`:

    tools.py:117    return [r for r in doc if isinstance(r, dict) and r], None   # array path
    tools.py:129    if isinstance(row, dict) and row:                            # JSONL path

`isinstance(r, dict)` alone would KEEP `{}`, which is why the truth test is the
load-bearing half. Pinned by `test_dalfox_measured_empty_output_stays_a_real_zero`,
which feeds the measured `"[\n{}]"` and asserts `findings == []`, `"0 XSS signals"`, and
an EMPTY swallow ledger (a real zero is not a degradation). That test passes against the
old parser too, on purpose: it is the false-positive control, not the kill.

Without it, the measured `[{}]` would have produced one empty-dict finding per run: 171
silent zeros converted into 171 false positives, and because `run_dalfox` is in
`agent._CONFIRMED_BY_TOOL` they would have been auto-CONFIRMED. Both halves are guarded.

### Slice 4 - Q-092, the `_cmd` chokepoint (committed)

Routed in by the Coordinator. Same defect class as the 15, one level lower: at a
chokepoint 18 call sites share.

`_cmd` captured `proc.returncode` into `_exit` and used it ONLY for the provenance record
in its `finally` block. It never crossed the return edge. A tool that exited non-zero
having produced nothing returned `("", stderr)`, every caller parsed the empty stdout into
zero findings, and the wrapper reported `ran=True`. A crashed external tool and a clean
target were byte-identical rows.

**The carrier is `CmdResult`: the same object callers already unpack.** An AST census of
the 18 `self._cmd(` call sites:

    TOTAL self._cmd call sites: 18
    CHECK a sentinel within 6 lines (12)
    DO NOT check any sentinel (6)

`CmdResult` is a `tuple` subclass of length 2. Every `out, err = await self._cmd(...)`
site keeps working untouched, `result == ("out", "err")` still holds, and the exit status
rides on `result.exit_code`. Two alternatives were rejected on the evidence above: a third
tuple element would break every 2-target unpack in the file AND could be ignored by the 6
sites that already ignore `err`'s content; a `self._last_exit` attribute is exactly the
side channel Q-089 forbids.

**MY FIRST ATTEMPT WAS WRONG, and another lane's guard caught it.** I originally put the
status only in an `__EXIT__` sentinel on `err`, emitted only when the exit was non-zero
AND stdout was empty. That satisfied the Coordinator's wording but FAILED four guards in
`tests/test_external_tool_liveness.py` - a file I hold read-only, whose guards were
written to fail by design until Q-092 landed, and which are the authoritative contract:

* `test_cmd_hands_back_the_exit_status` - the fake binary exits 2 **with a banner on
  stdout**. My rule did not fire, so no status was recoverable at all.
* `test_cmd_reports_a_zero_exit_as_zero` - a CLEAN run must report 0, which a
  failure-only sentinel can never do. Explicitly paired with the above "so the repaired
  `_cmd` cannot satisfy the guard by hard-coding a failure constant".
* `test_wrapper_reports_not_ran_when_the_tool_exits_nonzero` - the measured sqlmap case:
  exit 2, usage error on stderr, ASCII banner on stdout. Stdout was non-empty, so my rule
  let `_run_sqlmap` keep answering `success=True, "No SQLi confirmed"`.

The lesson is the one this whole lane is about: **stdout being non-empty is not the same
as the run having produced a result.** sqlmap's banner is bytes on stdout and is not a
finding. So `_cmd` now reports the status UNCONDITIONALLY and the CALLER decides whether
it salvaged anything.

Changes as shipped:
1. `CmdResult(out, err, exit_code)` returned on all six `_cmd` return paths. `exit_code`
   is `None` when no process exit was observed (binary missing, budget refused, timeout,
   spawn raised) - None means "unknown", never "fine".
2. `_cmd_failure(result, parsed=None) -> str`. One predicate for every failure mode: the
   three `__` sentinels plus `exit_code not in (0, None)`. `parsed` is the caller's own
   answer to "did I get anything out of this run?" - defaulting it to `None` means the
   safe direction (report the failure) is what you get by not thinking about it.
3. The `__EXIT__` sentinel is KEPT on top of that for the unambiguous
   non-zero-and-no-stdout case, because it is what makes the 12 sentinel-reading sites
   fail loudly without each having to reason about exit codes.
4. `_cmd` calls `self._swallow(...)` on that path, so the failure also surfaces through
   `execute()`'s DEGRADED line at all 18 sites and could never sit as an island.
5. All 12 checking sites now bind the whole result (`out, err = _cmd_r = await ...`) and
   call `_cmd_failure(_cmd_r)`. `err.startswith("__MISSING__")` appears ZERO times in
   `tools.py`; a site still hand-rolling it would see `__MISSING__` and keep missing the
   exit code. Existing messages are preserved and katana's and ffuf's hints are kept.

All 7 tests in `tests/test_external_tool_liveness.py` now pass - the 4 that were failing
by design plus their 3 controls. That file was not modified.

MEASURED against `git archive HEAD` (b33edb6, `CmdResult` count 0, `_cmd_failure` count
0, 12 hand-rolled checks present), **6 kills**:

    FAILED test_cmd_failure_predicate_covers_every_sentinel_cmd_can_emit
    FAILED test_cmd_puts_the_exit_status_on_the_return_edge
    FAILED test_cmd_result_is_still_the_pair_every_caller_unpacks
    FAILED test_a_non_zero_exit_the_caller_salvaged_is_not_reported_as_a_failure
    FAILED test_a_crashed_external_tool_is_ran_false_not_a_clean_zero
    FAILED test_every_cmd_caller_now_shares_the_one_failure_predicate

and green after. The end-to-end kill runs through a real `execute("run_nuclei", ...)`
dispatch and asserts `success is False` and that the string `"0 findings"` is absent -
the phrase that used to lie.

**2 both-sides controls, rewritten so they are runnable against the pristine tree.** They
first referenced `tools._cmd_failure`, which does not exist pre-fix, so they failed for a
mechanical reason rather than a behavioural one - a control that cannot run before the fix
is not a control. Re-expressed without that symbol, both now pass on BOTH sides: a
non-zero exit that still produced output keeps its output and is not flagged, and exit 0
with no output stays a clean run.

`test_a_non_zero_exit_the_caller_salvaged_is_not_reported_as_a_failure` is counted as a
KILL rather than a control, honestly: it is the false-positive guard for the `parsed=`
escape hatch, but it exercises a function that does not exist pre-fix, so it cannot run on
the pristine tree and is not a both-sides control.

Regression sweep over every suite that touches an external-tool wrapper
(`test_bbh`, `test_tool_provenance`, `test_dispatch_provenance`,
`test_nmap_service_wiring`, `test_external_tool_liveness`, `test_tool_ledger_status`,
`test_liveness`): **0 failures**, exit 0. This matters because `_cmd`'s return TYPE
changed; the sweep is what proves the 2-tuple compatibility claim empirically rather than
by reading the class.

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

### Slice 6 - `tools._swallow` flagged as dead code, and the part of the report that was wrong

The Coordinator reported `tools._swallow` as an island with **0 callers**, checked with a
grep that excludes `self._swallow(` and `def _swallow(`. Resolution options offered were
WIRE IT, REMOVE IT, or an accounting entry.

**The premise was partly wrong, and I measured it before acting.** The same over-broad
grep, run across ALL production modules instead of `tools.py` alone, finds three callers:

    ./bie.py:1409             _tools._swallow(_apolaki_exc, "bie.session_fingerprint", "")
    ./dns_recon.py:138        _tools._swallow(_apolaki_exc, "dns_recon.doh", ...)
    ./enip_audit_tool.py:91   _tools._swallow(_apolaki_exc, "enip.list_identity_tcp", ...)

They landed in slice 2 (`196dfda`) and each is proven live by an end-to-end test through a
real `ToolRegistry.execute(...)` dispatch. So it was never dead code in the "no caller"
sense, and REMOVE IT would have deleted a mechanism with three live users and broken those
tests.

**But the gate was still right to flag it, for a reason worth keeping.** Reading
`deadcode_gate._module_bindings` (read-only; I hold no write on that file) shows
`scan_qualified` resolves a caller ONLY through a resolved import - `import m as x` then
`x.f`, or an assignment whose right-hand side is already a known module binding. My call
sites did:

    _tools = _sys.modules.get("tools")     # resolves to nothing, by design of the gate
    if _tools is not None:
        _tools._swallow(...)

I chose `sys.modules.get` in slice 2 to avoid an import inside an exception handler. The
cost, which I did not anticipate, is that a dynamically fetched module is invisible to
static analysis, so a genuinely live recorder read as an island. **The gate was measuring
what it says it measures; my wiring was the thing that could not be verified.**

Fix (option 1, WIRE IT - properly this time): the three handlers now use
`import tools as _tools`, a resolved import the gate can follow. Function-level, inside
the handler, so no module-level dependency and no import cycle is created - `tools`
imports `dns_recon` at module scope, and a module-level import back would have been a
cycle. It is safe as a statement in an except handler because every path that can reach
it is already running inside a `ToolRegistry` dispatch, so `tools` is in `sys.modules` and
the statement is a dict lookup. The now-unused `import sys as _sys` was removed from all
three modules so it would not become the next dead entry.

MEASURED after the change, by running the gate itself rather than trusting the tests:

    qualified unused count: 39
    tools._swallow flagged: False
    unaccounted entries: []

No baseline was raised, no exemption added, and `deadcode_gate.py` was not edited. The
count sitting at 39 against a baseline of 37 is not mine: every flagged entry is inside
the gate's own recorded set, and none of the five module-level names this lane added
(`_swallow`, `_cmd_failure`, `CmdResult`, `_dalfox_rows`, `_dalfox_finding`) appears in
the flagged list.

**Lesson worth carrying:** this lane's whole subject is recorders that exist but are not
reached. I added one and wired it in a form no static check could confirm - the island
pattern inside the fix for islands. "I have a test that proves it fires" and "a reader can
verify it is reached" are different properties, and the second is the one a gate enforces.

### The 6 `_cmd` sites that still do NOT check for failure, and why (Q-092)

12 of the 18 sites now share `_cmd_failure`. The other 6 discard the error channel
entirely (`out, _ = await self._cmd(...)`). Each was looked at rather than left unexamined:

| site | disposition |
|------|-------------|
| `_run_metadata:1911` (exiftool) | **Correctly left alone.** A failed exiftool falls through to `upload_tool.extract_metadata`, a real native reader. The check genuinely still runs, so `ran=True` is the honest answer. Covered for visibility by the `_swallow` in `_cmd`. |
| `_run_hash_crack` x4 (hashcat / john) | **Known remaining gap.** A crashed cracker reports "not cracked", which is a false negative of the same shape. Not fixed here because it is an offline convenience feature, not target testing, and widening this commit further was not asked for. Visible via the `_swallow` DEGRADED line but NOT yet `ran=False`. |
| `_run_httpx:4296` | **Fixed.** It used `missing = err.startswith("__MISSING__")`; now `missing = bool(_cmd_failure(_cmd_r))`. |

So the honest count is 13 of 18 sites consuming the failure signal, 1 correct by design,
and 4 (`_run_hash_crack`) still owed. Stated rather than rounded up.

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


---

## FINAL SHIP GATE (MEASURED)

Full suite on an isolated `git archive HEAD` snapshot of `9f8293d` (482 .py files),
run in a throwaway container attached to `apolaki_default` so the lab-dependent tests
actually run instead of skipping (Q-094):

    docker run --rm --network apolaki_default \
      -v "<snapshot>/apolaki/agent:/app" -w /app apolaki-agent \
      python -m pytest tests/ -p no:cacheprovider -rfE -q

    SHIPGATE_EXIT=0
    total tests : 3585
    passed (.)  : 3562
    skipped (s) : 11
    xfailed (x) : 12
    failed (F/E): 0
    FAILED lines: 0    ERROR lines: 0

The counts are read from the progress characters, NOT from pytest's summary line: that
line does not survive redirect in this environment, and the exit code was captured with
`$?` directly off the `docker run` rather than off a pipeline. Reporting a pipeline's
exit as the suite's is how a red run gets called green here.

Against the lane-open baseline of 3519 passed / 11 skipped / 12 xfailed / 0 failed, the
suite has grown by 43 passing tests and lost none.

### Before / after across the whole lane

| gate run | commit | failures |
|----------|--------|----------|
| lane open | `66a7012` | 0 (3519 passed) |
| after slices 1-4 | `7a7b90b` | 4, all `test_deadcode_gate.py` (the 4 liveness ones cleared by slice 5) |
| final | `9f8293d` | **0** (3562 passed) |

### Write-boundary audit

Every file touched by this lane's commits:

    apolaki/agent/bie.py
    apolaki/agent/dns_recon.py
    apolaki/agent/enip_audit_tool.py
    apolaki/agent/tests/test_silent_failure_invariant.py
    apolaki/agent/tests/test_silent_failure_residue.py
    apolaki/agent/tools.py
    apolaki/docs/handoff/silent_failure_fix.md

None of `deadcode_gate.py`, `exposure_tool.py`, `tests/test_deadcode_gate.py`,
`docs/handoff/island_triage.md`, `docs/handoff/tool_liveness_audit.md`,
`tests/test_external_tool_liveness.py`, `docs/QUEUE.md` or `docs/STATUS.md` was modified.
The 8 tests those two guard files own went green by fixing production, not by editing
them.

### Instrument note: a counter that nearly reported 7 failures that do not exist

A convenience waiter loop counted status markers with `tr -cd 'FE'` over the WHOLE gate
output and printed `fail markers in progress: 7`, contradicting the 0 measured from the
progress lines. Resolved by locating each character rather than trusting either number:

    grep -nE '^[.sxXFE]+ *\[ *[0-9]+%\]' shipgate3.txt | grep -E '[FE]'
    -> NONE - no progress line contains an F or E

All 7 are letters inside deprecation-warning prose: "FastAPI", "Lifespan Events",
"AbstractItemEncoder", "TYPE_MAP". The correct extraction restricts to progress lines
(`^[.sxXFE]+ *\[ *N%\]`) before counting, and it agrees with `grep -c '^FAILED'` = 0,
`grep -c '^ERROR'` = 0 and `SHIPGATE_EXIT=0`.

Same family as `grep -c` counting LINES where `ast` counts NODES: a counter pointed at
the wrong substrate produces a confident wrong number in whichever direction it happens
to land. Here it would have been a false RED; the same loop could as easily have hidden a
real one.
