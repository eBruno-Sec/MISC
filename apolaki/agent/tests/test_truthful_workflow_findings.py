"""Q-054 — `run_workflow` was a finding sink, TWO SINKS DEEP.

THE DEFECT, MEASURED on 2026-08-16 against the live local Juice Shop lab, same engine and same
target down two paths:

    $ docker run --rm --network apolaki_default -v <HEAD-snapshot>/agent:/app -w /app \
        apolaki-agent python _repro054.py
    DIRECT  success=True findings=1
      DIRECT finding: family=idor confidence=lead title=Enumerable objects by id (8 in 1..8)
    WORKFLOW keys=['asserted', 'log', 'produced', 'ran', 'variables']
    WORKFLOW findings=None
    TOOLRESULT success=True findings=0

`workflow.run` read `res.output` / `res.success` / `res.error` and never `res.findings`, and the
dict it returned had no field a finding could travel in. `tools._run_workflow` then hardcoded `[]`
for its own findings, so repairing either half alone changed nothing observable.

THE FLAGSHIP CASE, also MEASURED live, is worse than a dropped lead. The `idor_read` pack
(packs.py:14) acquires two real Juice Shop identities and proves a cross-user basket read. On
pristine HEAD:

    OUTPUT: {"ran": true, "asserted": true, "log": [... {"step": 2, "do": "confirm_idor", "ok": true}],
             "produced": ["foreign_object_read"]}
    FINDINGS: 0

The pack ran the attack, the oracle confirmed it, the capability was produced -- and the CONFIRMED
CWE-639 finding was discarded. That is the false-clean shape: the mission paid for the requests and
reported nothing.

FIXTURES ARE COPIED FROM REALITY. `REAL_ENUMERATE_IDS_LEAD` is the record `_run_enumerate_ids`
emitted against http://juice-shop:3000/api/Products/{id} (ids 1..8) in the run above.
`REAL_CONFIRM_IDOR_FINDING` is the record `_confirm_idor` emitted for owner=admin@juice-sh.op /
attacker=mc.safesearch@juice-sh.op on http://juice-shop:3000/rest/basket/1 -- both 200, 1310 bytes,
similarity 1.0. Nothing here is invented.

THE THIRD SINK IS NOT IN THIS LANE'S FILES. `agent.py:627` auto-stores a dispatched tool's findings
only when the tool name is in `_AUTO_STORE_TOOLS`, and `run_workflow` is not in that set. See
`docs/handoff/truthful.md` for the one-line patch; `agent.py` belongs to another owner. This file
therefore asserts up to `ToolResult.findings`, which is exactly the boundary `agent._run_tool` reads.
"""
from __future__ import annotations

import asyncio
import json

import tools
import workflow as wf
from scope import ScopeEngine


REAL_ENUMERATE_IDS_LEAD = {
    "title": "Enumerable objects by id (8 in 1..8)",
    "severity": "medium",
    "target": "http://juice-shop:3000/api/Products/{id}",
    "family": "idor",
    "confidence": "lead",
    "engine": "enumerate_ids",
    "tags": ["idor", "enumeration", "bola"],
    "description": ("Sequential object ids return distinct populated records. If these belong to "
                    "other users this is a bulk IDOR - confirm ownership with confirm_idor."),
    "evidence": "accessible ids: [1, 2, 3, 4, 5, 6, 7, 8]",
}

REAL_CONFIRM_IDOR_FINDING = {
    "title": "IDOR / BOLA — cross-user object access confirmed",
    "severity": "high",
    "target": "http://juice-shop:3000/rest/basket/1",
    "family": "idor",
    "cwe": "CWE-639",
    "confidence": "confirmed",
    "engine": "confirm_idor",
    "tags": ["idor", "bola", "access-control"],
    "description": ("An object owned by one user was read by a DIFFERENT authenticated user. The object "
                    "identifier is not authorization-checked, so any user can read another user's records."),
    "impact": "Read other users' data (PII, orders, baskets); bulk exfiltration by walking the id space.",
    "evidence": ("owner GET http://juice-shop:3000/rest/basket/1 -> 200 (1310b)\n"
                 "attacker (different identity) GET http://juice-shop:3000/rest/basket/1 -> 200 (1310b); "
                 "owner/attacker similarity 1.0 (>=0.9 = same object)"),
}


def _reg():
    sc = ScopeEngine()
    sc.load_manual(["juice-shop:3000"], [], "truthful-workflow")
    return tools.ToolRegistry(sc, lab_mode=True)


def _reg_with_stubbed_step(result_findings, method="_run_enumerate_ids", tool="enumerate_ids"):
    """A REAL ToolRegistry with exactly ONE step method replaced, so workflow.run executes the real
    substitution / state / assertion path and only the transport is stubbed."""
    reg = _reg()

    async def _stub(inp):
        return tools.ToolResult(tool, inp.get("url_template") or inp.get("target_url") or "", True,
                                '{"template": "x", "count": 8, "confirmed": true}', list(result_findings))

    setattr(reg, method, _stub)
    return reg


def _enumerate_wf():
    return {"id": "truthful-probe",
            "steps": [{"do": "enumerate_ids",
                       "url_template": "http://juice-shop:3000/api/Products/{id}",
                       "start": 1, "end": 8}]}


def _idor_wf():
    return {"id": "truthful-idor",
            "steps": [{"do": "confirm_idor", "target_url": "http://juice-shop:3000/rest/basket/1",
                       "owner_session": "victim", "attacker_session": "attacker"}]}


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------------------------
# NEGATIVE CONTROL FIRST: assert the input to the experiment before asserting the output.
# ---------------------------------------------------------------------------------------------
def test_the_stubbed_step_really_emits_the_finding():
    reg = _reg_with_stubbed_step([REAL_ENUMERATE_IDS_LEAD])
    res = _run(reg._run_enumerate_ids({"url_template": "http://juice-shop:3000/x/{id}"}))
    assert len(res.findings) == 1 and res.findings[0]["family"] == "idor"


# ---------------------------------------------------------------------------------------------
# SINK 1 — workflow.run
# ---------------------------------------------------------------------------------------------
def test_workflow_run_carries_its_steps_findings_out():
    """FAILS BEFORE THE FIX: `res` had no `findings` key and no log entry carried one."""
    reg = _reg_with_stubbed_step([REAL_ENUMERATE_IDS_LEAD])
    res = _run(wf.run(reg, _enumerate_wf()))
    assert res["ran"] is True
    assert res["findings"], "workflow.run returned no findings although its only step emitted one"
    assert res["findings"][0]["family"] == "idor"


def test_workflow_run_attributes_each_finding_to_its_step():
    """'Which step found it' must stay answerable -- a flat aggregate alone loses that."""
    reg = _reg_with_stubbed_step([REAL_ENUMERATE_IDS_LEAD])
    res = _run(wf.run(reg, _enumerate_wf()))
    steps_with_findings = [e for e in res["log"] if e.get("findings")]
    assert len(steps_with_findings) == 1
    assert steps_with_findings[0]["step"] == 0
    assert steps_with_findings[0]["do"] == "enumerate_ids"
    assert steps_with_findings[0]["findings"][0]["title"] == REAL_ENUMERATE_IDS_LEAD["title"]


def test_workflow_run_carries_the_confirmed_cwe_639_finding():
    """The flagship case: the confirmed finding the `idor_read` pack exists to produce."""
    reg = _reg_with_stubbed_step([REAL_CONFIRM_IDOR_FINDING], "_confirm_idor", "confirm_idor")
    res = _run(wf.run(reg, _idor_wf()))
    assert [f["cwe"] for f in res["findings"]] == ["CWE-639"]
    assert res["findings"][0]["confidence"] == "confirmed"


def test_workflow_run_aggregates_across_steps_in_step_order():
    reg = _reg()

    async def _one(inp):
        return tools.ToolResult("enumerate_ids", "", True, "{}", [dict(REAL_ENUMERATE_IDS_LEAD)])

    async def _two(inp):
        return tools.ToolResult("confirm_idor", "", True, '{"confirmed": true}',
                                [dict(REAL_CONFIRM_IDOR_FINDING)])

    reg._run_enumerate_ids, reg._confirm_idor = _one, _two
    res = _run(wf.run(reg, {"id": "two-step", "steps": _enumerate_wf()["steps"] + _idor_wf()["steps"]}))
    assert [f["confidence"] for f in res["findings"]] == ["lead", "confirmed"]


# --- negative controls: a clean run must stay clean, and the key must always exist -------------
def test_a_step_that_finds_nothing_yields_an_empty_list_not_a_missing_key():
    """`findings` is ALWAYS present. A caller must never have to tell 'no key' from 'found nothing',
    which is the `x or DEFAULT` shape that has bitten this codebase four times."""
    reg = _reg_with_stubbed_step([])
    res = _run(wf.run(reg, _enumerate_wf()))
    assert "findings" in res and res["findings"] == []
    assert all("findings" not in e for e in res["log"])


def test_a_blocked_prerequisite_returns_the_findings_key_too():
    reg = _reg()
    res = _run(wf.run(reg, {"id": "gated", "requires": ["capability:admin_session"],
                            "steps": _enumerate_wf()["steps"]}))
    assert res["ran"] is False
    assert res["findings"] == []


def test_an_unknown_step_invents_no_finding():
    reg = _reg()
    res = _run(wf.run(reg, {"id": "bogus", "steps": [{"do": "not_a_real_step"}]}))
    assert res["findings"] == []
    assert res["log"][0]["error"] == "unknown step"


def test_non_dict_finding_entries_are_forwarded_unchanged_never_coerced():
    """Several engines put raw URLs/scalars in `findings`. Dropping or coercing them here would be
    this ticket's own defect one layer up; `ToolResult.__post_init__` skips them for the same reason.

    MEASURED while writing this: the dict entry arrives carrying `engine: 'enumerate_ids'`, stamped
    by the INNER `ToolResult.__post_init__` before `workflow.run` ever sees it. That is the existing
    provenance contract doing its job, not a mutation this fix introduces -- so the assertion is
    written against what actually crosses the boundary rather than against what looked tidy."""
    reg = _reg_with_stubbed_step(["http://juice-shop:3000/api/Products/1", {"severity": "low"}])
    res = _run(wf.run(reg, _enumerate_wf()))
    assert res["findings"] == ["http://juice-shop:3000/api/Products/1",
                               {"severity": "low", "engine": "enumerate_ids"}]
    assert res["findings"][0] == "http://juice-shop:3000/api/Products/1"   # scalar: untouched


# ---------------------------------------------------------------------------------------------
# SINK 2 — tools._run_workflow (the boundary agent._run_tool actually reads)
# ---------------------------------------------------------------------------------------------
def test_run_workflow_tool_result_carries_them_too():
    """FAILS BEFORE THE FIX: tools.py hardcoded `[]` for this ToolResult's findings."""
    reg = _reg_with_stubbed_step([REAL_ENUMERATE_IDS_LEAD])
    res = _run(reg._run_workflow({"workflow": _enumerate_wf()}))
    assert res.success is True
    assert len(res.findings) == 1
    assert res.findings[0]["family"] == "idor"


def test_run_workflow_preserves_the_inner_engines_provenance():
    """Attribution must name who FOUND it, not who last carried it. `ToolResult.__post_init__`
    stamps `engine` only when unset, so a forwarded finding must still say `confirm_idor`."""
    fresh = {k: v for k, v in REAL_CONFIRM_IDOR_FINDING.items() if k != "engine"}
    reg = _reg_with_stubbed_step([fresh], "_confirm_idor", "confirm_idor")
    res = _run(reg._run_workflow({"workflow": _idor_wf()}))
    assert res.findings[0]["engine"] == "confirm_idor"


def test_run_workflow_output_still_shows_the_step_log_after_forwarding():
    """The fix must not hide the evidence of itself. `output` is truncated at 4000 chars, so the
    full finding dicts travel in `ToolResult.findings` and `output` keeps per-step COUNTS."""
    reg = _reg_with_stubbed_step([REAL_CONFIRM_IDOR_FINDING] * 12, "_confirm_idor", "confirm_idor")
    res = _run(reg._run_workflow({"workflow": _idor_wf()}))
    assert len(res.findings) == 12
    view = json.loads(res.output)                    # not truncated into invalid JSON
    assert view["findings"] == 12
    assert view["log"][0] == {"step": 0, "do": "confirm_idor", "ok": True, "findings": 12}


def test_run_workflow_finding_free_run_reports_no_findings():
    reg = _reg_with_stubbed_step([])
    res = _run(reg._run_workflow({"workflow": _enumerate_wf()}))
    assert res.findings == []
    assert json.loads(res.output)["findings"] == 0


def test_an_unknown_pack_still_returns_no_findings():
    reg = _reg()
    res = _run(reg._run_workflow({"pack": "no-such-pack"}))
    assert res.success is False and res.findings == []
