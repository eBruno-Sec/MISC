"""
Executable investigation workflows (technique packs).

A workflow is a DECLARATIVE, target-agnostic recipe: ordered steps that call the scoped
investigative primitives, extract values from responses into mission variables (safe
JSONPath-lite / regex / header — never eval), substitute {vars} into later steps, assert a
deterministic oracle, and record produced capabilities. Same record is an executable plan
AND a human repro guide. No arbitrary code from the model — only the typed step vocabulary.
"""
from __future__ import annotations

import json
import re

# step "do" -> ToolRegistry transport method
_TOOLMAP = {
    "http_read": "_http_read", "http_request": "_http_request", "http_diff": "_http_diff",
    "confirm_idor": "_confirm_idor", "enumerate_ids": "_run_enumerate_ids",
    "acquire_session": "_acquire_session", "browser_navigate": "_browser_navigate",
    "test_numeric_abuse": "_test_numeric_abuse",
}
_VAR = re.compile(r"\{([a-zA-Z0-9_]+)\}")


def _subst(obj, variables: dict):
    """Recursively replace {var} in strings from `variables` (missing var → left as-is)."""
    if isinstance(obj, str):
        return _VAR.sub(lambda m: str(variables.get(m.group(1), m.group(0))), obj)
    if isinstance(obj, dict):
        return {k: _subst(v, variables) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_subst(v, variables) for v in obj]
    return obj


def _seed_harvest(variables: dict, reg) -> None:
    """Expose harvested Target Intelligence (intel.py) as workflow variables so techniques
    consume TARGET-DERIVED fixtures instead of hardcoded answers:
        harvest_<kind>        -> full candidate list
        harvest_<kind>_first  -> first candidate (for {var} substitution into a URL/param)
    Reserved `harvest_*` namespace, seeded with setdefault so explicit inputs and extracted
    vars win — and so intel harvested by an earlier step becomes available to later steps."""
    store = getattr(reg, "intel", None)
    if store is None:
        return
    try:
        cands = store.to_dict().get("candidates", {})
    except Exception:
        return
    for kind, vals in cands.items():
        if vals:
            variables.setdefault("harvest_" + kind, vals)
            variables.setdefault("harvest_" + kind + "_first", vals[0])


def _jsonpath_lite(data, path: str):
    """Safe traversal for a dotted path like $.data[0].id — dicts/lists only, no eval."""
    cur = data
    for part in re.findall(r"[^.\[\]]+|\[\d+\]", path.lstrip("$.")):
        if part.startswith("[") and part.endswith("]"):
            i = int(part[1:-1])
            if isinstance(cur, list) and -len(cur) <= i < len(cur):
                cur = cur[i]
            else:
                return None
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _extract(step_output: str, resp_headers: dict, spec: dict) -> dict:
    """Return {var: value} from a step result using ONLY whitelisted extractors:
    json (JSONPath-lite over the response body), regex (one capture group), header."""
    out = {}
    try:
        body = json.loads(step_output).get("body", step_output)
    except Exception:
        body = step_output
    parsed = None
    try:
        parsed = json.loads(body) if isinstance(body, str) else body
    except Exception:
        parsed = None
    for var, rule in (spec or {}).items():
        val = None
        if isinstance(rule, str) and rule.startswith("$"):
            val = _jsonpath_lite(parsed if parsed is not None else {}, rule)
        elif isinstance(rule, dict) and rule.get("regex"):
            m = re.search(rule["regex"], body if isinstance(body, str) else json.dumps(body))
            val = (m.group(1) if m and m.groups() else (m.group(0) if m else None))
        elif isinstance(rule, dict) and rule.get("header"):
            val = (resp_headers or {}).get(rule["header"])
        if val is not None:
            out[var] = val
    return out


def _assert_ok(assertion: dict, last_output: str, reg) -> bool:
    """Deterministic oracle check. Supports {capability:X} (state has it) and
    {field:F, equals:V} (F in the last step's JSON output equals V)."""
    if not assertion:
        return True
    if assertion.get("capability"):
        return reg.state.has(assertion["capability"])
    if "field" in assertion:
        try:
            d = json.loads(last_output)
        except Exception:
            d = {}
        return d.get(assertion["field"]) == assertion.get("equals", True)
    return True


def _step_findings(res) -> list:
    """The findings a step's ToolResult carried, faithfully — no coercion, no dropping.

    Q-054. `workflow.run` read `res.output` / `res.success` / `res.error` and NEVER `res.findings`,
    and the dict it returned had no field a finding could travel in. MEASURED against a live Juice
    Shop: `enumerate_ids` over /api/Products/{id} emits a family=idor lead on a direct call and
    NOTHING through `workflow.run`. The same sink swallowed `confirm_idor`'s confirmed CWE-639
    finding, which is the entire point of the flagship `idor_read` pack.

    `getattr` rather than `res.findings`: every real producer is a `ToolResult`, whose `findings`
    field is a dataclass default and therefore always present, so this cannot mask a real engine's
    output. It exists for the duck-typed step stand-ins in tests/test_workflow_headers.py.

    Non-dict entries are forwarded UNCHANGED, matching `ToolResult.__post_init__`: several engines
    put raw URLs/scalars in `findings`, and dropping or coercing them here would be this ticket's
    own defect one layer up. Downstream (`agent._auto_store`) already skips them."""
    return list(getattr(res, "findings", None) or [])


async def run(reg, wf: dict) -> dict:
    """Execute a workflow against a ToolRegistry. Returns
    {ran, log, variables, produced, asserted, findings}. Bounded at 20 steps.

    `findings` is the aggregate of every step's findings in step order, and each log entry carries
    its own step's findings so "which step found it" stays answerable. Both are always present
    (possibly empty) — a caller must never have to distinguish "no key" from "found nothing"."""
    variables = dict(wf.get("inputs") or {})
    variables.update(reg.state.variables)
    log, last_out, findings = [], "{}", []
    # prerequisite capabilities
    for req in wf.get("requires") or []:
        if req.startswith("capability:") and not reg.state.has(req.split(":", 1)[1]):
            return {"ran": False, "error": f"missing prerequisite {req}", "log": log, "findings": []}
    for i, step in enumerate((wf.get("steps") or [])[:20]):
        _seed_harvest(variables, reg)   # target-derived fixtures, refreshed each step
        do = step.get("do")
        meth = _TOOLMAP.get(do)
        if not meth or not hasattr(reg, meth):
            log.append({"step": i, "do": do, "error": "unknown step"})
            continue
        inp = _subst({k: v for k, v in step.items() if k not in ("do", "extract", "as")}, variables)
        if step.get("as"):                      # act as a named session
            inp["session"] = step["as"]
        res = await getattr(reg, meth)(inp)
        last_out = res.output or "{}"
        entry = {"step": i, "do": do, "ok": res.success}
        step_findings = _step_findings(res)
        if step_findings:
            entry["findings"] = step_findings
            findings.extend(step_findings)
        if res.error:
            entry["error"] = res.error
        if step.get("extract"):
            # Response headers live at the top level of the shaped step output (see
            # ToolRegistry._shape_response -> {"headers": ...}); feed them to _extract so a
            # `header` rule can pull a Location/ETag/X-* value. Was hardcoded {} — the header
            # extractor could never fire (registration/redirect flows need this).
            try:
                _rh = json.loads(last_out).get("headers") or {}
            except Exception:
                _rh = {}
            got = _extract(last_out, _rh if isinstance(_rh, dict) else {}, step["extract"])
            for k, v in got.items():
                variables[k] = v
                reg.state.set_var(k, v)
            entry["extracted"] = list(got.keys())
        log.append(entry)
    asserted = _assert_ok(wf.get("assert"), last_out, reg)
    produced = []
    if asserted:
        for cap in wf.get("produces") or []:
            c = cap.split(":", 1)[1] if ":" in cap else cap
            reg.state.add_capability(c, f"workflow {wf.get('id', '?')}")
            produced.append(c)
    return {"ran": True, "asserted": asserted, "log": log,
            "variables": {k: reg.state.variables.get(k) for k in reg.state.variables},
            "produced": produced, "findings": findings}
