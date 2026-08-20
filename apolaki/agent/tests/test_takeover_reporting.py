"""Q-053 GAP-1, second half: a DETECTED takeover must travel all the way to the RENDERED report.

`fb6f457` landed the producer -- `ToolRegistry._takeover_finding` stamps family "takeover" -- and
`tests/test_finding_provenance.py` pins detection -> family -> store. **Nobody tested `assess()`.**
The existing proofs stop at `map_findings`, which keys on family alone and therefore passed while the
objective row a reader actually sees was still wrong.

MEASURED at 8c7065c, with the producer already live:

    takeover finding + engine ran  -> failed | not_implemented_reason STILL ATTACHED
    CLEAN run, engine RAN          -> not_implemented        <- "verified" unreachable
    engine never ran               -> not_implemented        <- indistinguishable from the row above

`failed` outranks `not_implemented` in `assess`, so the FAIL direction worked BY ACCIDENT and hid the
other two. That is why this file drives the RENDERED markdown rather than the mapping: the defect
lived entirely in the space between "the finding maps" and "the reader is told the truth".

The three lies that shipped, in the order they matter:
  1. a FAILED row still carried a reason saying Apolaki has no engine for this and that its detector
     returns no family. Both clauses were false as of `fb6f457`, and they rendered next to the finding.
  2. a CLEAN run of a capability that EXISTS reported the PRODUCT as lacking it -- the flattering
     direction, which is the one nobody goes looking for.
  3. `not_implemented` stopped discriminating "no engine" from "not run", which is the exact
     distinction `report.coverage_rollup` keeps a separate bucket for, citing Q-012, one layer up.

FIXTURES ARE COPIED FROM REALITY. The CNAME/body pairs below are read out of
`dns_recon.TAKEOVER_FINGERPRINTS` at runtime, never spelled here -- an invented body string would
match nothing, `match_takeover` would return None, and every assertion would pass vacuously on an
empty findings list. `_fingerprint_body` fails loudly if the table stops carrying what it needs.

ENGINE NAME TAKEN FROM THE LEDGER, NOT FROM MEMORY. The ToolResult is built as
`ToolResult("takeover", ...)` while the dispatch name is `check_takeover`; the tool_ledger records the
DISPATCH name. MEASURED over 66,395 real log rows in the named volume: `check_takeover` appears 140
times and `takeover` never does. `test_comm04_engine_name_is_the_dispatch_name` pins that.
"""
from __future__ import annotations

import asyncio
import os
import tempfile

import agent as agentmod
import asvs_model
import db as dbmod
import dns_recon
import report as reportmod
import scope as scopemod
import tools as toolsmod

SCOPE = {"in_scope": ["x.tld"], "bases": ["https://x.tld"], "out_of_scope": []}
_SUB = "dead.x.tld"


def _fresh_db(mid="m-takeover"):
    dbmod.DB_PATH = os.path.join(tempfile.mkdtemp(), "t.db")
    dbmod._conn = None
    dbmod.init(dbmod.DB_PATH)
    dbmod.create_mission(mid, "P", "active", "o", SCOPE, {})
    return mid


def _fingerprint_body(service="Amazon S3"):
    """The REAL cname + unclaimed-resource signature for a provider, read out of the production
    table. Hand-writing these is how a takeover test passes against zero findings."""
    for fp in dns_recon.TAKEOVER_FINGERPRINTS:
        if fp["service"] == service:
            return fp["cname"][0], fp["body"][0]
    raise AssertionError("fingerprint table no longer carries %r -- fixture is stale" % service)


def _agent(mid):
    sc = scopemod.ScopeEngine()
    sc.load_manual(["x.tld"], [], "takeover-e2e")
    reg = toolsmod.ToolRegistry(sc, mission_id=mid, lab_mode=True)
    reg.recon["subdomains"] = [_SUB]
    a = agentmod.BBHAgent(sc, reg, asyncio.Event(), mode="active", auto_approve=True,
                          strategy="deterministic", mission_id=mid)
    return a, reg


def _drive(mid, *, status, body, cname):
    """END TO END through the REAL dispatcher and the REAL auto-store guard site.

    Only the network is stubbed. Everything between -- `_check_takeover`, `dns_recon.match_takeover`,
    `_takeover_finding`, `ToolResult`, the `tool_name in _AUTO_STORE_TOOLS` guard, `_auto_store`,
    `_is_confirmed`, `db.add_finding` -- is production code on its real path."""
    a, reg = _agent(mid)

    async def fake_cname(_sub):
        return cname

    async def fake_http(_url, **_kw):
        return {"status": status, "body": body}

    dns_recon.resolve_cname, reg._http = fake_cname, fake_http

    async def run():
        return [ev async for ev in a._run_tool("check_takeover", {}, mid)]

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(run())
    finally:
        loop.close()


def _ledger(*tools):
    return {"tools": [{"tool": t, "calls": 1, "ok": 1} for t in tools]}


def _comm04(findings, ledger):
    a = asvs_model.assess(findings, attempted_engines=reportmod._engines_from_ledger(ledger))
    return [o for o in a["objectives"] if o["cid"] == "COMM-04"][0]


# -- the fixture apparatus itself, before anything is concluded from it -------
def test_fixture_is_a_real_fingerprint_and_actually_matches():
    """POSITIVE CONTROL for every test below. If `match_takeover` returns None the engine emits no
    candidates and each 'no takeover reported' assertion would hold for the wrong reason."""
    cname, body = _fingerprint_body()
    cand = dns_recon.match_takeover(_SUB, "%s.%s" % (_SUB, cname), 200, body)
    assert cand, "the real fingerprint did not match -- every assertion below would be vacuous"
    assert cand["service"] == "Amazon S3"


# -- GAP-1: detection -> family -> store -> REPORT ----------------------------
def test_confirmed_takeover_travels_from_dispatch_to_stored_finding():
    """The auto-store boundary is the half that gets forgotten. `check_takeover` is in
    `_AUTO_STORE_TOOLS`, and this drives the ONE guard site that reads it rather than asserting
    membership -- a set entry proves registration, not storage."""
    mid = _fresh_db()
    cname, body = _fingerprint_body()
    events = _drive(mid, status=200, body=body, cname="%s.%s" % (_SUB, cname))

    emitted = [e for e in events if e.get("type") == "finding"]
    assert emitted, "no finding event: the auto-store guard never fired for check_takeover"

    stored = dbmod.get_findings(mid)
    assert stored, "finding never reached the findings table"
    assert stored[0]["family"] == "takeover"
    assert stored[0]["confidence"] == "confirmed"


def test_stored_takeover_fails_comm04_in_the_rendered_report():
    """THE WHOLE TICKET, on stored records rather than hand-built dicts: a takeover that was detected
    is a takeover a READER is told about. Asserts on the rendered markdown, which is the artifact the
    client receives."""
    mid = _fresh_db()
    cname, body = _fingerprint_body()
    _drive(mid, status=200, body=body, cname="%s.%s" % (_SUB, cname))
    stored = dbmod.get_findings(mid)
    assert stored, "nothing stored -- the render assertion below would be vacuous"

    md = "\n".join(reportmod._asvs_md(stored, _ledger("check_takeover")))
    assert "COMM-04" in md, "a stored takeover does not reach the ASVS section:\n%s" % md
    assert "Failed objectives" in md

    row = _comm04(stored, _ledger("check_takeover"))
    assert row["status"] == "failed"
    assert row["finding_ids"], "failed with no finding id attached"


def test_failed_comm04_no_longer_carries_a_false_not_implemented_reason():
    """DEFECT 1. The row said 'we found this' and 'we have no engine for this, and our detector
    returns no family' at the same time. Both clauses were false once `fb6f457` shipped."""
    row = _comm04([{"family": "takeover", "id": "F1"}], _ledger("check_takeover"))
    assert row["status"] == "failed"
    assert "not_implemented_reason" not in row, (
        "a FAILED objective still explains why it is unimplemented: %r"
        % row.get("not_implemented_reason"))


def test_a_clean_takeover_run_can_reach_verified():
    """DEFECT 2, and the flattering direction. A capability that EXISTS, RAN, and found nothing must
    not report the PRODUCT as lacking it. `verified` was unreachable while `not_implemented_reason`
    short-circuited the status ladder above `_engine_ran`."""
    mid = _fresh_db()
    _drive(mid, status=200, body="<html>a perfectly ordinary page</html>",
           cname="%s.cdn.example.net" % _SUB)
    assert not dbmod.get_findings(mid), "clean target produced a finding -- NEGATIVE CONTROL FAILED"

    row = _comm04(dbmod.get_findings(mid), _ledger("check_takeover"))
    assert row["status"] == "verified", "a clean run of a real engine still reads %r" % row["status"]


def test_not_run_is_distinguishable_from_not_implemented():
    """DEFECT 3. `report.coverage_rollup` keeps `not_implemented` in its own bucket precisely so a
    reader can tell an ABSENT capability from a SKIPPED one, citing Q-012. COMM-04 collapsed the two:
    both read `not_implemented`, so the bucket lied in the direction of 'we never built it'."""
    assert _comm04([], _ledger("run_xss"))["status"] == "not_tested"
    assert _comm04([], _ledger("check_takeover"))["status"] == "verified"


def test_comm04_engine_name_is_the_dispatch_name_the_ledger_records():
    """NEAR-MISS SPELLING CONTROL, the failure mode that made four of Q-048's six unfailable
    objectives unfailable. `_engines_from_ledger` reads the DISPATCH name; this engine's ToolResult
    carries a DIFFERENT string ('takeover'). Pinning the wrong one loses `verified` silently."""
    obj = [o for o in asvs_model.OBJECTIVES if o["cid"] == "COMM-04"][0]
    assert obj["engine"] == "check_takeover"
    assert obj["engine"] in toolsmod.TOOL_PERMISSIONS, (
        "COMM-04 names an engine that cannot be dispatched")
    assert obj["engine"] in agentmod._AUTO_STORE_TOOLS, (
        "COMM-04's engine is not auto-stored: its findings would be dropped at dispatch")
    # the OTHER string must not accidentally start verifying the objective
    assert _comm04([], _ledger("takeover"))["status"] == "not_tested"


# -- NEGATIVE CONTROLS: nothing to find must still produce nothing ------------
def test_no_dangling_cname_reports_nothing_anywhere():
    """A plumbing fix that makes findings appear where there are none is worse than the silence it
    replaced. Drives the full path against a healthy host and asserts the whole chain stays empty."""
    mid = _fresh_db()
    events = _drive(mid, status=200, body="<html>ok</html>", cname="%s.cdn.example.net" % _SUB)
    assert not [e for e in events if e.get("type") == "finding"]
    assert not dbmod.get_findings(mid)
    md = "\n".join(reportmod._asvs_md(dbmod.get_findings(mid), _ledger("check_takeover")))
    assert "COMM-04" not in md, "COMM-04 rendered as failed with nothing to find:\n%s" % md


def test_unrelated_finding_families_never_fail_comm04():
    """SPURIOUS-FAIL CONTROL. A false FAIL is a defect too -- it is why Q-048 refused to re-point
    AUTHN-02 at `sqli`. COMM-04 must key on `takeover` and nothing else."""
    for fam in ("xss", "sqli", "security_misconfig", "insecure_cookie", "takeover_candidate"):
        row = _comm04([{"family": fam, "id": "F"}], _ledger("check_takeover"))
        assert row["status"] == "verified", "family %r spuriously failed COMM-04" % fam


def test_a_404_only_candidate_is_a_lead_and_does_not_fail_the_objective():
    """The GRADE is load-bearing and must survive this fix. `match_takeover`'s 404 branch yields
    'possible dangling record, verify manually'; `_takeover_finding` grades it `candidate`, so
    `_is_confirmed` routes it to LEADS and it never becomes a stored finding.

    An unverified suspicion must not fail a verification objective -- that is the difference between
    this and the false-positive plumbing the ticket warns against."""
    mid = _fresh_db()
    cname, _ = _fingerprint_body()
    events = _drive(mid, status=404, body="", cname="%s.%s" % (_SUB, cname))

    leads = [e for e in events if e.get("type") == "lead"]
    assert leads, "the 404 branch produced neither a finding nor a lead -- detection was lost"
    assert not dbmod.get_findings(mid), "an unverified 404 candidate was stored as a confirmed finding"
    assert _comm04(dbmod.get_findings(mid), _ledger("check_takeover"))["status"] == "verified"
