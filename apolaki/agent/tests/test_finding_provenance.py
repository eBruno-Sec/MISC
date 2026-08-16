"""Q-051 -- the ENGINE that produced a finding is known when the finding is built, and was discarded.

`ToolResult` is constructed with the producing tool's own name. Nothing carried that name onto the
findings, so the mission `tool_ledger` knew which engines RAN while no individual finding knew who
produced it. A 400-finding sample carried zero keys naming a tool, engine or source.

This is the fifth appearance of one shape in this project, and the rule is settled: BIND THE VALUE AT
THE POINT IT IS KNOWN; never recover it from prose or infer it later. Q-046 is the cautionary case --
`finding_fp` parsed the tested parameter back out of a rendered title, the split failed, five findings
collapsed into one, and the published baseline understated itself by four true positives.

The binding therefore lives in `ToolResult.__post_init__`, NOT in each producer:
  * 113 methods in tools.py construct a ToolResult, over 312 construction sites. A per-module field is
    312 chances to forget one, and a forgotten one is indistinguishable from an engine that found
    nothing.
  * engines call each other directly (`self._run_xss(...)`) as well as through `execute()`, so a
    binding placed in the dispatcher would miss every internal call.

FAIL-BEFORE-FIX (MEASURED against `git archive HEAD` + only this file; `pytest -q --tb=no -rA`):

    FAILED test_engine_is_bound_on_every_dict_finding            KeyError: 'engine'
    FAILED test_non_dict_findings_are_left_alone                 KeyError: 'engine'
    FAILED test_inner_producer_wins_over_outer_wrapper           KeyError: 'engine'
    FAILED test_empty_engine_string_is_treated_as_absent...      assert '' == 'xss'
    FAILED test_engine_survives_storage_and_retrieval            stored .get('engine') is None
    FAILED test_engine_of_a_real_dispatch_reaches_storage        stored .get('engine') is None
    FAILED test_binding_is_not_opt_in_per_module                 KeyError: 'engine'
    PASSED test_empty_tool_name_does_not_stamp_an_empty_engine   (vacuous pre-fix -- see its docstring)

The one pre-fix PASS is a NEGATIVE CONTROL: it asserts an ABSENCE, which holds trivially while the
feature does not exist. It is named here rather than quietly counted, because a control that could not
have failed is not evidence of anything pre-fix. Its value is entirely POST-fix, where it pins the
specific wrong way this fix could have been written (`x or DEFAULT` over an empty engine name).
"""
import asyncio
import os
import tempfile

import db as dbmod
import dns_recon
import scope as scope_mod
import tools

SCOPE = {"in_scope": ["x.tld"], "bases": ["https://x.tld"], "out_of_scope": []}


def _fresh_db(mid="m"):
    dbmod.DB_PATH = os.path.join(tempfile.mkdtemp(), "t.db")
    dbmod._conn = None
    dbmod.init(dbmod.DB_PATH)
    dbmod.create_mission(mid, "P", "active", "o", SCOPE, {})
    return mid


def _registry():
    sc = scope_mod.ScopeEngine()
    sc.load_manual(["x.tld"], [], "T")
    return tools.ToolRegistry(sc, mission_id="m", lab_mode=True)


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ── the binding itself ───────────────────────────────────────────────────────
def test_engine_is_bound_on_every_dict_finding():
    """The producing engine is stamped at CONSTRUCTION, on every dict, with no producer opt-in."""
    r = tools.ToolResult("sqli", "https://x.tld/a", True, "2 findings",
                         [{"title": "SQLi", "severity": "high"},
                          {"title": "second", "severity": "low"}])
    assert [f["engine"] for f in r.findings] == ["sqli", "sqli"]


def test_empty_tool_name_does_not_stamp_an_empty_engine():
    """NEGATIVE CONTROL for the `x or DEFAULT` trap this codebase has paid for three times (once in
    the benchmark scorer).

    An engine name of "" is a REAL INPUT, not a missing one. Stamping `engine: ""` would make
    "produced by an engine that did not name itself" indistinguishable from "nobody recorded a
    producer" -- the exact ambiguity this ticket exists to remove. Absent is honest; empty is a lie
    that an `engines that produced nothing` report section would then render as a real engine."""
    for name in ("", "   ", None):
        r = tools.ToolResult(name, "https://x.tld/a", True, "", [{"title": "t", "severity": "high"}])
        assert "engine" not in r.findings[0], f"tool={name!r} stamped a meaningless engine"


def test_non_dict_findings_are_left_alone():
    """NEGATIVE CONTROL: several engines return raw scalars/strings in `findings` (katana returns
    URLs). Binding must never raise -- a crash here would be swallowed upstream and become an
    invisible false negative for the whole tool, not just for provenance."""
    r = tools.ToolResult("katana", "https://x.tld", True, "", ["https://x.tld/a", 7, None,
                                                               {"title": "t", "severity": "info"}])
    assert r.findings[:3] == ["https://x.tld/a", 7, None]
    assert r.findings[3]["engine"] == "katana"


def test_inner_producer_wins_over_outer_wrapper():
    """A finding re-wrapped by an aggregating tool keeps its ORIGINAL producer.

    Attribution must name who FOUND it, not who last carried it. Wrappers re-emit inner results
    routinely, and `run_sqli`, `run_sqli_structural` and `run_path_sqli` all emit `tool='sqli'`."""
    inner = tools.ToolResult("ldap", "https://x.tld/a", True, "", [{"title": "LDAPi", "severity": "high"}])
    outer = tools.ToolResult("injection_probes", "https://x.tld/a", True, "", inner.findings)
    assert outer.findings[0]["engine"] == "ldap"


def test_empty_engine_string_is_treated_as_absent_and_gets_filled():
    """The `inner producer wins` rule keys on a real VALUE, not on the presence of a key. A producer
    that set `engine: ""` has recorded nothing, so the boundary must still fill it."""
    r = tools.ToolResult("xss", "https://x.tld/a", True, "",
                         [{"title": "t", "severity": "high", "engine": ""}])
    assert r.findings[0]["engine"] == "xss"


def test_binding_is_not_opt_in_per_module():
    """Guard against this fix being written module-by-module -- the shape the ticket exists to avoid.

    An engine name that appears NOWHERE in tools.py is still bound, which is only possible if the
    binding lives at the ToolResult boundary rather than in a list of known producers."""
    r = tools.ToolResult("an_engine_that_does_not_exist", "https://x.tld", True, "",
                         [{"title": "t", "severity": "info"}])
    assert r.findings[0]["engine"] == "an_engine_that_does_not_exist"


# ── does it SURVIVE STORAGE? (registration is not invocation) ────────────────
def test_engine_survives_storage_and_retrieval():
    """PROVE the field is on a STORED finding -- read back out of SQLite, not asserted on the object
    we just built. `db.add_finding` is the single write chokepoint and `db._gate` normalizes every
    finding on the way in; a normalizer that rebuilt the dict from a field whitelist would drop
    `engine` silently while every unit test above still passed."""
    mid = _fresh_db()
    r = tools.ToolResult("nuclei", "https://x.tld/a", True, "",
                         [{"title": "exposed panel", "severity": "high", "confidence": "confirmed",
                           "target": "https://x.tld/a", "evidence": "200 + panel signature"}])
    fid = dbmod.add_finding(mid, r.findings[0])
    assert fid, "finding was rejected by the gate -- the storage proof would be vacuous"
    stored = [f for f in dbmod.get_findings(mid) if f.get("id") == fid]
    assert stored, "finding did not land in the findings table"
    assert stored[0].get("engine") == "nuclei"


def test_engine_of_a_real_dispatch_reaches_storage():
    """END TO END through the REAL dispatch path, with no hand-built ToolResult anywhere:
    ToolRegistry.execute('check_takeover') -> _check_takeover -> ToolResult -> db.add_finding ->
    db.get_findings. execute() resolves the method by `getattr(self, '_' + tool_name)`, so this also
    pins that the binding is reached through the dispatcher and not only by direct construction."""
    mid = _fresh_db()
    reg = _registry()
    reg.recon["subdomains"] = ["dead.x.tld"]

    async def fake_cname(sub):
        return "dead.x.tld.s3.amazonaws.com"

    async def fake_http(url, **kw):
        return {"status": 404, "body": "NoSuchBucket"}

    dns_recon.resolve_cname, reg._http = fake_cname, fake_http
    res = _run(reg.execute("check_takeover", {}, "m"))
    assert res.findings, "no candidate produced -- the storage assertion below would be vacuous"
    fid = dbmod.add_finding(mid, res.findings[0])
    assert fid, "finding was rejected by the gate -- the storage proof would be vacuous"
    stored = [f for f in dbmod.get_findings(mid) if f.get("id") == fid][0]
    assert stored.get("engine") == "takeover"
