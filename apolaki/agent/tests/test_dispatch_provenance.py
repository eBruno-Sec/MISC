"""Q-064 -- the two records of one mission must be compared in ONE vocabulary.

`report.ledger_finding_disagreement()` cross-checks what the tool ledger says was DISPATCHED against
what each finding says PRODUCED it. The ledger keys on the dispatch name
(`confirm_browser_persona_bola`); a finding carried the engine's name for itself
(`browser_persona_bola`), bound by `ToolResult.__post_init__`. MEASURED over `TOOL_PERMISSIONS`:
those two strings differ for **95 of 111** engines. So the check accused nearly every engine in the
product of producing findings the ledger never recorded, on missions where they plainly ran -- and
its other half, `productive`, could only ever name the 15 engines whose names happen to coincide.

REPRODUCED on the live records before the fix, real ledger against real findings for mission
57cc3b49 (both fixtures in this directory, both read out of the mission DB):

    productive           : []
    produced_but_unlogged: ['browser_persona_bola', 'xss']
    WARNING RENDERS: True

The fix is NOT normalisation in the checker. That is forbidden here, and it also cannot work: the
map is many-to-one -- `run_sqli`, `run_path_sqli` and `run_sqli_structural` all emit `sqli`, so no
rule recovers a ledger row from a finding. The dispatch name is stamped onto the finding at the
boundary that knows it (`agent._stamp_dispatch`, called from both wrappers), and the checker
compares the ledger's key against the finding's record of that same key.

Nothing here touches the network: only the leaf engine coroutine is replaced, so scope validation,
method resolution, dispatch, the Q-061 ledger writes and the auto-store routing are all the real
thing. The ledger under test is built by `main._tool_ledger` from rows the product wrote.
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile

import agent as agent_mod
import db as dbmod
import main as mainmod
import report
import scope as scope_mod
import tools as tools_mod

BASE = "http://juice-shop:3000"
HERE = os.path.dirname(os.path.abspath(__file__))


def _fresh(mid: str) -> None:
    dbmod.init(os.path.join(tempfile.mkdtemp(), "q064.db"))
    dbmod.create_mission(mid, "Q-064", "active", "o", {"in_scope": ["juice-shop:3000"]}, {})


def _registry(**leaves):
    """A REAL ToolRegistry with only the leaf engine bodies replaced (same construction as
    tests/test_ledger_records_dispatch.py). Stubbing `execute` itself would test nothing."""
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["juice-shop:3000"], [], "q064")
    reg = tools_mod.ToolRegistry(eng, mission_id="q064")
    for name, fn in leaves.items():
        setattr(reg, "_" + name, fn)
    return reg


def _agent(reg, mid=None, mode="active"):
    ag = agent_mod.BBHAgent(reg.scope, reg, asyncio.Event(), strategy="deterministic",
                            mission_id=mid, auto_approve=True)
    ag.mode = mode
    return ag


def _leaf(result_name: str, findings=(), output="ok"):
    """An engine that names ITSELF differently from the dispatch that reaches it -- the shape 95 of
    111 registered engines have. `_confirm_browser_persona_bola` returns
    `ToolResult("browser_persona_bola", ...)`; this is that, verbatim in structure."""
    async def leaf(_inp):
        return tools_mod.ToolResult(result_name, BASE, True, output,
                                    [dict(f) for f in findings], None)
    return leaf


def _bola_finding():
    """Trimmed to the keys the cross-check reads, but the VALUES are the live ones -- taken from
    findings_57cc3b49.json, the verbatim findings table of the mission whose verbatim ledger is
    tool_ledger_57cc3b49.json."""
    real = _live_findings()[0]
    return {k: real[k] for k in ("title", "severity", "confidence", "family", "target")}


def _live_findings() -> list:
    with open(os.path.join(HERE, "findings_57cc3b49.json"), encoding="utf-8") as fh:
        return json.load(fh)["findings"]


def _live_ledger() -> dict:
    with open(os.path.join(HERE, "tool_ledger_57cc3b49.json"), encoding="utf-8") as fh:
        return json.load(fh)


def _ledger(mid: str) -> dict:
    return mainmod._tool_ledger(mid)


def _drive_run_tool(ag, tool: str, inp: dict, mid: str) -> list:
    """Consume `_run_tool` exactly as production does, persisting the events `main` persists."""
    out: list = []

    async def go():
        async for ev in ag._run_tool(tool, inp, mid):
            if "_content" in ev:
                continue
            out.append(ev)
            mainmod._persist_event(mid, ev)
    asyncio.run(go())
    return out


# -- THE DEFECT --------------------------------------------------------------
#
# Both of these FAIL before the fix, with produced_but_unlogged naming an engine that ran.

def test_an_internally_dispatched_engine_is_not_accused_of_being_unlogged():
    """THE measured case. `confirm_browser_persona_bola` is dispatched by `_do_persona_authz`
    through `_exec_internal`, its findings are persisted at agent.py's own store site, and the
    ledger row it leaves is keyed `confirm_browser_persona_bola`. On mission 57cc3b49 that engine
    ran once, produced one finding, and the report called it unlogged."""
    _fresh("q064a")
    reg = _registry(confirm_browser_persona_bola=_leaf("browser_persona_bola", [_bola_finding()]))
    ag = _agent(reg)
    res = asyncio.run(ag._exec_internal("confirm_browser_persona_bola",
                                        {"base_url": BASE, "owner": "user_a", "attacker": "user_b"},
                                        "q064a"))
    dis = report.ledger_finding_disagreement(_ledger("q064a"), list(res.findings))
    assert dis["produced_but_unlogged"] == [], (
        "the engine was DISPATCHED and the ledger has its row; reporting %s as unlogged is the "
        "false alarm" % dis["produced_but_unlogged"])
    assert dis["productive"] == ["confirm_browser_persona_bola"], dis
    assert "Ledger disagreement" not in "\n".join(
        report._arsenal_md(_ledger("q064a"), list(res.findings)))


def test_an_auto_stored_finding_carries_the_dispatch_all_the_way_to_the_report():
    """The other wrapper, end to end: `_run_tool` -> `execute` -> `_auto_store` -> `db.add_finding`.
    Asserted on the finding READ BACK OUT OF THE DB, not on the in-memory dict, because the stamp is
    worth nothing if the write path drops the key."""
    _fresh("q064b")
    xss = {"title": "Reflected XSS (html) in 'sort'", "severity": "high", "confidence": "confirmed",
           "family": "xss", "target": BASE + "/api/Challenges/?sort=%3Cbbhx7h%3E",
           "evidence": "breakout '<bbhx7h>' survived literally"}
    reg = _registry(run_xss=_leaf("xss", [xss], output="1 confirmed"))
    ag = _agent(reg, mid="q064b")
    _drive_run_tool(ag, "run_xss", {"url": BASE + "/api/Challenges/?sort=1"}, "q064b")

    stored = dbmod.get_findings("q064b")
    assert stored, "auto-store landed nothing, so this test proves nothing about provenance"
    assert stored[0].get("engine") == "xss", stored[0]
    assert stored[0].get("dispatch") == "run_xss", (
        "the dispatch name did not survive the write path: %s" % stored[0].get("dispatch"))
    dis = report.ledger_finding_disagreement(_ledger("q064b"), stored)
    assert dis["produced_but_unlogged"] == [], dis
    assert dis["productive"] == ["run_xss"], dis


def test_both_records_of_one_mission_agree_on_a_mixed_run():
    """The whole point of the section, on a run that dispatches four engines through BOTH wrappers.
    A per-engine fix would pass one of these and not the others."""
    _fresh("q064c")
    f = lambda t: {"title": t, "severity": "high", "confidence": "confirmed", "family": "x",
                   "target": BASE + "/a", "evidence": "e"}
    reg = _registry(run_xss=_leaf("xss", [f("x1")]),
                    run_sqli=_leaf("sqli", [f("s1")]),
                    confirm_read_object_idor=_leaf("read_object_idor", [f("i1")]),
                    check_takeover=_leaf("takeover", [f("t1")]))
    ag = _agent(reg, mid="q064c")
    found: list = []
    for tool in ("run_xss", "run_sqli", "check_takeover"):
        for ev in _drive_run_tool(ag, tool, {"url": BASE + "/a"}, "q064c"):
            if ev.get("type") == "finding":
                found.append(ev["finding"])
    res = asyncio.run(ag._exec_internal("confirm_read_object_idor", {"base_url": BASE}, "q064c"))
    found += list(res.findings)

    assert len(found) == 4, [x.get("title") for x in found]
    dis = report.ledger_finding_disagreement(_ledger("q064c"), found)
    assert dis["produced_but_unlogged"] == [], dis
    assert dis["productive"] == ["check_takeover", "confirm_read_object_idor",
                                 "run_sqli", "run_xss"], dis


# -- NEGATIVE CONTROLS: the check must still catch what it exists to catch ----

def test_a_finding_whose_engine_NEVER_APPEARS_in_the_ledger_is_still_reported():
    """MANDATORY. The whole risk of this ticket is fixing the false alarm by killing the alarm.

    A finding naming an engine the ledger has no row for -- no dispatch stamp, nothing to
    corroborate it -- must still be reported. The four engines that DID run in the same call are the
    positive control that the apparatus was looking and simply found them consistent.
    """
    _fresh("q064d")
    reg = _registry(run_xss=_leaf("xss", [{"title": "x", "severity": "high",
                                           "confidence": "confirmed", "family": "xss",
                                           "target": BASE + "/a", "evidence": "e"}]))
    ag = _agent(reg, mid="q064d")
    real = [ev["finding"] for ev in _drive_run_tool(ag, "run_xss", {"url": BASE + "/a"}, "q064d")
            if ev.get("type") == "finding"]
    assert real, "no real finding: the positive control is not in place"
    ghost = {"title": "G", "severity": "high", "family": "open_redirect",
             "confidence": "confirmed", "target": BASE + "/g", "engine": "run_ghost"}
    dis = report.ledger_finding_disagreement(_ledger("q064d"), real + [ghost])
    assert dis["produced_but_unlogged"] == ["run_ghost"], dis
    assert dis["productive"] == ["run_xss"], dis
    md = "\n".join(report._arsenal_md(_ledger("q064d"), real + [ghost]))
    assert "Ledger disagreement" in md and "run_ghost" in md


def test_a_STAMPED_dispatch_the_ledger_never_recorded_is_still_reported():
    """The case the stamp itself creates, and the one a lazy fix would hide.

    A finding stamped with a dispatch name whose ledger row is MISSING is the genuine 'the ledger is
    incomplete' case -- exactly what Q-061 found for real, when ten of twelve `tools.execute` call
    sites left no row at all and a mission that minted two persona sessions reported
    `acquire_session` as never dispatched. The stamp must not become a free pass.
    """
    _fresh("q064e")
    reg = _registry(run_xss=_leaf("xss", [{"title": "x", "severity": "high",
                                           "confidence": "confirmed", "family": "xss",
                                           "target": BASE + "/a", "evidence": "e"}]))
    ag = _agent(reg, mid="q064e")
    real = [ev["finding"] for ev in _drive_run_tool(ag, "run_xss", {"url": BASE + "/a"}, "q064e")
            if ev.get("type") == "finding"]
    led = _ledger("q064e")
    assert "run_xss" in {t["tool"] for t in led["tools"]}, "positive control: the real row exists"

    orphan = {"title": "O", "severity": "high", "family": "idor", "confidence": "confirmed",
              "target": BASE + "/o", "engine": "read_object_idor",
              "dispatch": "confirm_read_object_idor"}
    dis = report.ledger_finding_disagreement(led, real + [orphan])
    assert dis["produced_but_unlogged"] == ["confirm_read_object_idor"], dis
    assert dis["productive"] == ["run_xss"], dis


def test_a_wrong_stamp_is_not_excused_by_a_matching_engine_name():
    """`dispatch` is read INSTEAD OF `engine`, never as a first of two chances.

    If the checker fell back to `engine` whenever `dispatch` missed, a finding stamped with a
    dispatch nobody ran would be laundered clean by an engine name that happens to be in the ledger.
    That is the same 'try harder until it matches' shape as prefix-stripping, one field over.
    """
    led = {"strategy": "deterministic", "mode": "active",
           "tools": [{"tool": "run_sqli", "calls": 4, "findings": 1}]}
    f = {"title": "t", "severity": "high", "family": "sqli", "confidence": "confirmed",
         "target": BASE + "/a", "engine": "run_sqli", "dispatch": "run_never_registered"}
    dis = report.ledger_finding_disagreement(led, [f])
    assert dis["produced_but_unlogged"] == ["run_never_registered"], dis
    assert dis["productive"] == [], dis


def test_a_blank_dispatch_name_stamps_NOTHING():
    """`x or DEFAULT` where empty is a real input. A stamp of `""` would be a finding wearing a
    dispatch key with no dispatch behind it; `str("") or engine` then falls through to `engine`,
    which is the honest outcome -- but only because nothing was written. Asserted on the KEY, not on
    the downstream verdict, so a future reader cannot 'simplify' the guard away."""
    res = tools_mod.ToolResult("xss", BASE, True, "", [{"title": "t", "severity": "high"}])
    agent_mod.BBHAgent._stamp_dispatch("", res)
    assert "dispatch" not in res.findings[0], res.findings[0]
    agent_mod.BBHAgent._stamp_dispatch("   ", res)
    assert "dispatch" not in res.findings[0], res.findings[0]
    agent_mod.BBHAgent._stamp_dispatch(None, res)
    assert "dispatch" not in res.findings[0], res.findings[0]
    agent_mod.BBHAgent._stamp_dispatch("run_xss", res)      # positive control
    assert res.findings[0]["dispatch"] == "run_xss"


def test_a_finding_that_already_names_a_dispatch_KEEPS_it():
    """Mirror of the `engine` rule, pointed the other way. `engine` keeps the INNERMOST producer
    because an aggregating tool re-emits inner results; `dispatch` keeps the FIRST dispatch because
    that is the one the ledger recorded. A later carrier overwriting it would re-attribute a
    finding to whichever engine last touched it."""
    res = tools_mod.ToolResult("web_probes", BASE, True, "",
                               [{"title": "t", "severity": "high", "dispatch": "run_sqli"}])
    agent_mod.BBHAgent._stamp_dispatch("run_web_probes", res)
    assert res.findings[0]["dispatch"] == "run_sqli"


def test_non_dict_findings_are_skipped_not_coerced():
    """Several engines put raw URLs and scalars in `findings`. Raising here would be swallowed
    upstream and become an invisible false negative for the whole engine."""
    res = tools_mod.ToolResult("param_mine", BASE, True, "",
                               [BASE + "/a?id=1", 7, None, {"title": "t", "severity": "low"}])
    agent_mod.BBHAgent._stamp_dispatch("run_param_mine", res)
    assert res.findings[0] == BASE + "/a?id=1"
    assert res.findings[3]["dispatch"] == "run_param_mine"


def test_a_findings_free_result_and_a_None_result_do_not_raise():
    """`_exec_internal` is on the error path of twelve drivers. A stamp that raises would abort a
    driver mid-mission, which is a worse defect than the one being fixed."""
    agent_mod.BBHAgent._stamp_dispatch("run_xss", None)
    res = tools_mod.ToolResult("xss", BASE, False, "", [], "SCOPE BLOCK: nope")
    agent_mod.BBHAgent._stamp_dispatch("run_xss", res)
    assert res.findings == []


# -- the live records, and the honest limit of the fix ------------------------

def test_the_LIVE_pre_stamp_records_still_disagree_and_that_is_correct():
    """The fix stops NEW false alarms; it cannot repair records written before the stamp existed.

    Mission 57cc3b49's findings carry `engine` and no `dispatch`, because they were produced before
    this ticket. For those the only identity available is the engine name, and it genuinely cannot
    be corroborated against the ledger -- so the check still reports them. Pinned deliberately: this
    is the assertion that would fail if someone later 'finished the job' by teaching the checker to
    strip prefixes, which is the forbidden fix.
    """
    dis = report.ledger_finding_disagreement(_live_ledger(), _live_findings())
    assert sorted(dis["produced_but_unlogged"]) == ["browser_persona_bola", "xss"], dis
    logged = {t["tool"] for t in _live_ledger()["tools"]}
    assert {"confirm_browser_persona_bola", "run_xss"} <= logged, (
        "positive control: both dispatch rows ARE in the live ledger, under their dispatch names")


def test_the_same_live_mission_stamped_by_the_product_agrees():
    """The counterpart, and the proof the fix addresses the measured case rather than a lookalike.

    The SAME live findings and the SAME live 46-row ledger, with the dispatch stamped by the
    product's own function rather than typed here by hand -- the leaf returns the real finding under
    the real engine name, `_exec_internal` performs the real dispatch, and `_stamp_dispatch` writes
    whatever it writes. Both engines then reconcile against the untouched live ledger.
    """
    _fresh("q064f")
    live = _live_findings()
    bola = {k: live[0][k] for k in ("title", "severity", "confidence", "family", "target")}
    xss = {k: live[1][k] for k in ("title", "severity", "confidence", "family", "target")}
    reg = _registry(confirm_browser_persona_bola=_leaf("browser_persona_bola", [bola]),
                    run_xss=_leaf("xss", [xss]))
    ag = _agent(reg)

    async def go():
        a = await ag._exec_internal("confirm_browser_persona_bola", {"base_url": BASE}, "q064f")
        b = await ag._exec_internal("run_xss", {"url": BASE + "/a"}, "q064f")
        return list(a.findings) + list(b.findings)
    produced = asyncio.run(go())

    assert [f["engine"] for f in produced] == ["browser_persona_bola", "xss"], (
        "the engine binding must be untouched: it still names the producer, not the dispatch")
    dis = report.ledger_finding_disagreement(_live_ledger(), produced)
    assert dis["produced_but_unlogged"] == [], dis
    assert dis["productive"] == ["confirm_browser_persona_bola", "run_xss"], dis
    assert dis["counts"] == {"confirm_browser_persona_bola": 1, "run_xss": 1}, dis


def test_the_warning_reaches_BOTH_renderers_only_when_it_should():
    """Registration is not invocation, and a check nobody sees is not a check. Both directions on
    both renderers, on the LIVE ledger shape."""
    live = _live_ledger()
    ghost = {"title": "G", "severity": "high", "family": "open_redirect", "confidence": "confirmed",
             "target": BASE + "/g", "dispatch": "run_ghost"}
    clean = {"title": "X", "severity": "high", "family": "xss", "confidence": "confirmed",
             "target": BASE + "/a", "engine": "xss", "dispatch": "run_xss"}
    md = report.generate_report("P", [clean, ghost], {"in_scope": ["juice-shop:3000"]},
                                tool_ledger=live)
    html = report.generate_html_report("P", [clean, ghost], {"in_scope": ["juice-shop:3000"]},
                                       tool_ledger=live)
    assert "Ledger disagreement" in md and "run_ghost" in md
    assert "Ledger disagreement" in html and "run_ghost" in html
    md2 = report.generate_report("P", [clean], {"in_scope": ["juice-shop:3000"]}, tool_ledger=live)
    html2 = report.generate_html_report("P", [clean], {"in_scope": ["juice-shop:3000"]},
                                        tool_ledger=live)
    assert "Ledger disagreement" not in md2 and "Ledger disagreement" not in html2


# -- the ratchet: no consumer of a dispatch's findings may skip the stamp -----
#
# The stamp sits at two wrappers on the argument that every persisted ToolResult comes through one
# of them. That argument was FALSE when it was first written: `_validate_candidates_impl` calls
# `self.tools.execute("run_dom_audit", ...)` directly and promotes those findings, so the ratchet
# below found a third store path the ticket did not name. It is kept because the argument is only
# true while it is true, and the next driver added is the next chance to break it.


def _unstamped_consumers(tree):
    """Functions that bind a `self.tools.execute(...)` result, READ its `.findings`, and never call
    `_stamp_dispatch`. Data flow, not co-occurrence: an earlier line-level version of this check
    flagged `_do_scan_auth` and `_do_persona_authz`, which merely contain an `acquire_session`
    dispatch (no findings) somewhere in the same long method as an unrelated `add_finding`. A
    ratchet that fires on correct code is a ratchet that gets deleted."""
    import ast
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        bound = set()
        for sub in ast.walk(node):
            if not isinstance(sub, ast.Assign):
                continue
            call = sub.value.value if isinstance(sub.value, ast.Await) else sub.value
            if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                    and call.func.attr == "execute"
                    and isinstance(call.func.value, ast.Attribute)
                    and call.func.value.attr == "tools"):
                bound |= {t.id for t in sub.targets if isinstance(t, ast.Name)}
        if not bound:
            continue
        reads = any(isinstance(sub, ast.Attribute) and sub.attr == "findings"
                    and isinstance(sub.value, ast.Name) and sub.value.id in bound
                    for sub in ast.walk(node))
        stamps = any(isinstance(sub, ast.Attribute) and sub.attr == "_stamp_dispatch"
                     for sub in ast.walk(node))
        if reads and not stamps:
            out.append(node.name)
    return out


def test_no_agent_function_consumes_dispatch_findings_without_stamping_them():
    import ast
    import inspect
    offenders = _unstamped_consumers(ast.parse(inspect.getsource(agent_mod)))
    assert offenders == [], (
        "these functions dispatch through tools.execute and consume the result's findings without "
        "binding the dispatch name, so those findings reach the report with only an engine name and "
        "the ledger cross-check cries wolf again: %s" % offenders)


def test_the_ratchet_can_actually_see_the_shape_it_is_looking_for():
    """The paired positive/negative control. A ratchet nobody has watched fire is a ratchet that
    would pass an empty file, which is how a guard that checks a declaration instead of a fact gets
    shipped -- twice, in this codebase."""
    import ast
    bad = ast.parse(
        "class C:\n"
        "    async def _do_thing(self, sid):\n"
        "        res = await self.tools.execute('run_dom_audit', {}, sid)\n"
        "        for f in res.findings:\n"
        "            db.add_finding(self.mission_id, f)\n")
    stamped = ast.parse(
        "class C:\n"
        "    async def _do_thing(self, sid):\n"
        "        res = await self.tools.execute('run_dom_audit', {}, sid)\n"
        "        self._stamp_dispatch('run_dom_audit', res)\n"
        "        for f in res.findings:\n"
        "            db.add_finding(self.mission_id, f)\n")
    no_findings = ast.parse(
        "class C:\n"
        "    async def _do_thing(self, sid):\n"
        "        res = await self.tools.execute('acquire_session', {}, sid)\n"
        "        if res.error:\n"
        "            return\n"
        "        db.add_finding(self.mission_id, {'title': 'authored here'})\n")
    assert _unstamped_consumers(bad) == ["_do_thing"], (
        "the detector cannot see the defect it exists to catch")
    assert _unstamped_consumers(stamped) == [], "the detector fires on the FIX"
    assert _unstamped_consumers(no_findings) == [], (
        "the detector fires on a dispatch whose findings are never consumed -- the false positive "
        "that made the first version of this ratchet flag two correct methods")
