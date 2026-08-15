# Q-012 - ASVS coverage model claims verification capability it does not have

Lane: ASVS BUILDER. Owns `agent/asvs_model.py`, `agent/tests/test_asvs_model.py`, this file.

Every claim below is MEASURED (command + real output) or marked UNVERIFIED.

---

## 1. Baseline reproduced (MEASURED)

Script run in a throwaway container:

```
MSYS_NO_PATHCONV=1 docker run --rm -v "C:/.../apolaki/agent:/app" -w /app apolaki-agent python /scratch/measure.py
```

```
METHODS(_x) = 197  PERMS = 112  SPEC = 77
PERFECT-RUN tally (perms|spec): {'verified': 27, 'attempted': 1, 'failed': 0,
                                 'not_tested': 3, 'not_applicable': 0, 'blocked': 2}
still not_tested: ['AUTHN-04', 'ATHZ-04', 'BUSL-01']
```

Matches the ticket exactly (ticket said PERMS=111; measured 112 - the delta is one key, not
material to the defect). `OBJECTIVES` names 40 distinct engine strings; 6 resolve to nothing
a dispatcher can reach, plus the sentinel `"n/a"` used by the two blocked objectives.

Per-name resolution against the REAL dispatch tables
(`_<name>` method on `ToolRegistry` / `TOOL_PERMISSIONS` / `CLAUDE_TOOLS`):

```
authz_matrix          method=False perms=False spec=False   _run_authz_matrix method=True
bizlogic_graph        method=False perms=False spec=False   _run_bizlogic_graph  =False
dependency_intel      method=False perms=False spec=False   _run_dependency_intel=False
header_analysis       method=False perms=False spec=False   _run_header_analysis =False
run_deser             method=False perms=False spec=False
run_mass_assignment   method=False perms=False spec=False
```

All other 34 names resolve.

---

## 2. THE TICKET'S `authz_matrix` PREMISE IS DISPROVEN (MEASURED)

The ticket states: *"the LEDGER records the bare name while the DISPATCHER uses the `run_` name,
and the model matches against the wrong one"*, and predicts the fix belongs in `tools.py`.

**That is backwards. Measured end-to-end through the real logging and ledger code:**

Both `tool_call` emitters log the REQUESTED tool name, never `ToolResult.tool`:

* `agent/agent.py:551`  - `yield {"type": "tool_call", "tool": tool_name, ...}`   (`_run_tool`, agentic path)
* `agent/agent.py:634`  - `db.add_log(session_id, "tool_call", {"tool": tool_name, ...})` (`_exec_internal`, internal path)

`main.py:413` is the only other `tool_call` writer and uses its own `_SOURCE_REVIEW_TOOL` constant.
There is no code path that writes `ToolResult.tool` into a log row.

Empirical proof (`/scratch/ledger_proof.py`): a real `BBHAgent._exec_internal("run_authz_matrix", ...)`
against a stub registry returning `ToolResult("authz_matrix", ...)` - i.e. exactly what
`tools.py:_run_authz_matrix` returns - then read back through the real
`main._tool_ledger` and `report._engines_from_ledger`:

```
dispatched: ['run_authz_matrix']  ToolResult.tool: authz_matrix
LOG ROWS: [('tool_call', 'run_authz_matrix'), ('tool_result', 'run_authz_matrix')]
_tool_ledger tools: ['run_authz_matrix']
_engines_from_ledger -> ['run_authz_matrix']
'authz_matrix' in ledger names?  False
'run_authz_matrix' in ledger names? True
coverage/asvs 'ran' set -> ['run_authz_matrix']
WITH THE REAL LEDGER NAME, ATHZ-00 status: not_tested | AUTHN-02: not_tested
```

`ToolResult.tool` is a display/label field. It is **not** the ledger key, on either consumer
(`report.coverage_rollup` / `report._asvs_md`, and `main.py:/coverage/asvs`).

**Consequence: there is NO `tools.py` patch to hand over.** The naming-boundary bug is entirely
inside `asvs_model.py`, which this lane owns. `authz_matrix` -> `run_authz_matrix`.

Note the bare-vs-`run_` split is a widespread `ToolResult` labelling convention, not a bug:
`_run_header_trust` -> `ToolResult("header_trust")`, `_run_transport_posture` -> `"transport_posture"`,
`_run_encoded_cookie` -> `"encoded_cookie"`, `_run_fingerprint` -> `"fingerprint"`,
`_run_deserialization` -> `"deserialization"`, `_run_race` -> `"race"`. None of those labels reach a ledger.

---

## 3. Verdict per name

| # | name | objectives | bucket | evidence |
|---|---|---|---|---|
| 1 | `authz_matrix` | AUTHN-02, ATHZ-00 | **(a) mis-named** | `_run_authz_matrix` exists (`tools.py:1894`), `TOOL_PERMISSIONS["run_authz_matrix"]` (`tools.py:179`), dispatched `agent.py:2095`; ledger records `run_authz_matrix` (measured above) |
| 2 | `dependency_intel` | CONF-01 | **(a) module named instead of engine** | `dependency_intel.py` is a module, not a tool. Sole production caller of `vulnerable_component_finding` is `tools.py:5534`, enclosing method `_run_js_review` -> real engine is `run_js_review` |
| 3 | `bizlogic_graph` | BUSL-01 | **(a) module named instead of engine** | `bizlogic.py` exists but is imported only by `codeintel.py:247` (source-review lane) and `main.py:2104` (REST endpoint) - never by `ToolRegistry`. Dispatch-reachable engines emitting family `business_logic`: `test_numeric_abuse` (`tools.py:3062`, in perms+spec) and `run_workflow` (perms+spec) |
| 4 | `header_analysis` | AUTHN-04, SESS-02 | **(b) absent name; SESS-02 has a real substitute, AUTHN-04 does not** | no method/perm/spec. For SESS-02 cookie hardening the real engine is `run_transport_posture` (`transport_posture.py:251` checks HttpOnly/Secure). For AUTHN-04 see below |
| 5 | `run_deser` | VAL-06 | **(b) phantom alias, harmless** | no method/perm/spec. Sibling `run_deserialization` in the same tuple is real (`_run_deserialization` -> `deser_tool.exposure_finding` / `error_finding`, family `deserialization`) |
| 6 | `run_mass_assignment` | ATHZ-04 | **(b) genuinely absent** | no method/perm/spec anywhere; confirms Q-011. Only over-posting code is the lab solver `juiceshop_solvers.py:67` |

### The two objectives that must report NOT IMPLEMENTED

**ATHZ-04 (mass assignment).** No executor exists. Reporting `not_tested` reads as
"we did not get to it"; the truth is the product cannot test it.

**AUTHN-04 (cleartext credential transport).** Two independent defects, both measured:

1. Engine `header_analysis` does not resolve.
2. `"verifiable": False` (`asvs_model.py:47`) with no `blocked_reason` and no `attempt_only`.
   In `assess()` the branch is `elif _engine_ran(obj, ran) and obj.get("verifiable")`, so even if the
   engine name were fixed, AUTHN-04 falls through to `not_tested` **forever**. The name was never
   the only thing keeping it untested.

Deliberately NOT remapped to `run_transport_posture`: that engine checks TLS protocol/cert posture for
an origin, not whether a credential crossed a cleartext channel. Mapping it would manufacture a false
"verified". `"verifiable": False` is the original author's own admission that Apolaki cannot verify it.

---

## 4. Adjacent defects found while measuring - NOT fixed by this lane (MEASURED)

These are real and outside Q-012's scope. Recording, not silently changing.

**(i) Two `violated_by` families have ZERO producers in the entire non-test tree:**
`cleartext_transport` (AUTHN-04) and `cookie_flags` (SESS-02). Measured:

```
grep -rn 'family":\s*"(cookie_flags|cleartext_transport)"' --include=*.py .   # non-test: no hits
```

The only mentions are lookup tables in `remediation.py:247` and `remediation_depth.py:262`.
So **SESS-02 can never fail** - it reads `verified` in a perfect run purely because
`run_encoded_cookie` ran, while nothing in the product can emit the family that would fail it.
Cookie hardening IS actually tested, by `transport_posture.py:251`, but that emits
`security_misconfig` (`transport_posture.py:397`), not `cookie_flags`.

**(ii) CONF-01 names `run_fingerprint`, which cannot emit its violating family.**
`_run_fingerprint` emits family `fingerprint` only; the sole producer of `vulnerable_component`
is `_run_js_review` (`tools.py:5534`). So CONF-01 could read `verified` from an engine structurally
incapable of failing it. Fixing name #2 above (adding `run_js_review`) closes this one as a side effect.

A "verified" backed by an engine that cannot emit the failing family is the same
declaration-vs-fact shape as Q-012, one level down. Suggest a follow-up ticket:
*every objective's `violated_by` families must have at least one real producer reachable from
one of its own engines.*

---

## 5. Status

- [x] Baseline reproduced
- [x] Six names classified with evidence
- [x] `authz_matrix` premise disproven; no `tools.py` patch needed
- [ ] Implementation + tests
- [ ] Full regression
