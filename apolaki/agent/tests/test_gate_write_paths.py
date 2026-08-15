"""Q-013 — the finding write-gate must have NO bypass, on ANY path that reaches storage.

`findings_gate` states three invariants and `db.add_finding` enforces them. `db.update_finding` did
not, so `PUT /findings/{sid}/{fid}` could write a row that violated all three:

    SCHEMA (#6)  reproduction_steps landed as a raw string    -> SARIF/report/retest index it as a list
    SCOPE  (#8)  a provably out-of-scope target landed        -> an off-scope finding reached the report
    TRUTH  (#7)  a `lead` confidence sat in the findings table -> a lead masquerading as a confirmation

These tests are written as ABSENCE-OF-BYPASS, not presence-of-check. `test_no_ungated_sql_writer`
enumerates every SQL statement in the package that writes the findings table, and
`test_every_finding_write_route_is_gated` DISCOVERS the HTTP write routes from `app.routes` and drives
each one with a violating payload. A test that asserted "update_finding calls the gate" would pass the
moment someone adds a fourth writer; these fail.

FAIL-BEFORE-FIX (measured on the pre-fix tree, and these are NOT import errors — every symbol used
already existed):
  * schema  : reproduction_steps == '1) do a 2) do b'  (str)          -> assert isinstance(..., list) FAILED
  * scope   : stored target == 'http://evil.example.com/p'            -> assert not off_scope FAILED
  * truth   : confidence == 'lead' still in get_findings()            -> assert not is_lead FAILED
  * route   : PUT /findings/{sid}/{fid} landed all three violations   -> violations == [] FAILED
  * sql     : update_finding executed `UPDATE findings ...` without calling the gate -> FAILED
"""
import os
import re
import tempfile

import db as dbmod
import findings_gate as fg

SCOPE = {"in_scope": ["app"], "bases": ["http://app:3000"], "out_of_scope": []}


def _fresh_db():
    dbmod.DB_PATH = os.path.join(tempfile.mkdtemp(), "t.db")
    dbmod._conn = None
    dbmod.init(dbmod.DB_PATH)


def _seed(mid="m"):
    _fresh_db()
    dbmod.create_mission(mid, "P", "active", "o", SCOPE, {})
    return dbmod.add_finding(mid, {"title": "legit", "confidence": "confirmed",
                                   "target": "http://app:3000/x",
                                   "evidence": "GET /x -> 200, owner-created object"})


def gate_violations(mid: str) -> list:
    """Every findings_gate invariant broken by a row that is IN STORAGE right now.

    This is the predicate the bypass controls assert is empty. It reads the CONFIRMED-findings table
    and re-applies the three invariants to what actually landed, so it does not care which code path
    put the row there — which is the whole point."""
    scope = (dbmod.get_mission(mid) or {}).get("scope") or {}
    bad = []
    for f in dbmod.get_findings(mid):
        if not isinstance(f.get("reproduction_steps"), list):
            bad.append(("SCHEMA", f.get("id"), repr(f.get("reproduction_steps"))))
        if fg.off_scope(f, scope):
            bad.append(("SCOPE", f.get("id"), f.get("target") or f.get("url")))
        if fg.is_lead(f):
            bad.append(("TRUTH", f.get("id"), f.get("confidence")))
    return bad


# ── the three invariants, on the update path ─────────────────────
def test_update_finding_enforces_schema_invariant():
    """#6: a producer that PUTs a numbered string still lands a list in storage."""
    mid, fid = "m", _seed()
    assert dbmod.update_finding(mid, fid, {"title": "legit", "confidence": "confirmed",
                                           "target": "http://app:3000/x",
                                           "reproduction_steps": "1) do a 2) do b"}) is True
    row = dbmod.get_finding(mid, fid)
    assert isinstance(row["reproduction_steps"], list) and len(row["reproduction_steps"]) == 2
    assert gate_violations(mid) == []


def test_update_finding_refuses_offscope_target():
    """#8: an update that moves a finding out of scope is REFUSED — the row keeps its in-scope target."""
    mid, fid = "m", _seed()
    assert dbmod.update_finding(mid, fid, {"title": "off", "confidence": "confirmed",
                                           "target": "http://evil.example.com/p"}) is False
    row = dbmod.get_finding(mid, fid)
    assert row["target"] == "http://app:3000/x"                 # unchanged, not overwritten
    assert gate_violations(mid) == []


def test_update_finding_cannot_park_a_lead_in_the_confirmed_table():
    """#7: demoting a row to a lead through the update path REROUTES it to the leads list — it does
    not leave a lead-confidence row sitting in the confirmed-findings table."""
    mid, fid = "m", _seed()
    assert dbmod.update_finding(mid, fid, {"title": "maybe", "confidence": "lead",
                                           "target": "http://app:3000/x"}) is True
    assert [f for f in dbmod.get_findings(mid) if f.get("id") == fid] == []
    leads = (dbmod.get_mission(mid).get("context") or {}).get("leads") or []
    assert any(l.get("title") == "maybe" for l in leads)
    assert gate_violations(mid) == []


def test_update_finding_keeps_tenant_isolation_and_legitimate_merges():
    """The gate must not break the two legitimate callers: a cross-mission write still fails, and an
    in-mission merge (main.capture_finding_poc attaching a screenshot, agent._triage annotating a
    finding) still succeeds."""
    _fresh_db()
    dbmod.create_mission("m1", "P", "active", "o", SCOPE, {})
    dbmod.create_mission("m2", "P", "active", "o", SCOPE, {})
    fid = dbmod.add_finding("m1", {"title": "f1", "confidence": "confirmed",
                                   "target": "http://app:3000/x"})
    assert dbmod.update_finding("m2", fid, {"title": "hacked"}) is False      # tenant isolation (#10)
    assert dbmod.get_findings("m1")[0]["title"] == "f1"
    merged = dict(dbmod.get_finding("m1", fid))
    merged["poc_screenshot"] = "iVBOR..."                                    # capture_finding_poc shape
    merged["analyst_notes"] = "triage: CWE-639"                              # _triage shape
    assert dbmod.update_finding("m1", fid, merged) is True
    row = dbmod.get_finding("m1", fid)
    assert row["poc_screenshot"] == "iVBOR..." and row["analyst_notes"] == "triage: CWE-639"


# ── absence-of-bypass: no ungated SQL writer anywhere in the package ──
#: Functions in the package that are ALLOWED to execute a write against the `findings` table. Each is
#: a gate chokepoint or a delete (which removes rows, so no invariant can be violated by it). A new
#: entry here has to be argued: it means a fourth way to reach the findings table exists.
_ALLOWED_SQL_WRITERS = {
    "db.py:add_finding": "gate chokepoint — normalize / off_scope / is_lead before INSERT",
    "db.py:update_finding": "gate chokepoint — normalize / off_scope / is_lead before UPDATE",
    "db.py:delete_finding": "removes a row; cannot violate an invariant",
    "db.py:delete_mission": "removes every row for a mission; cannot violate an invariant",
}

_SQL_WRITE = re.compile(r"(INSERT\s+(?:OR\s+\w+\s+)?INTO|UPDATE|DELETE\s+FROM)\s+findings\b", re.I)

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _sql_writers():
    """(file:function) for every source line in the package that executes SQL writing `findings`."""
    import ast
    found = {}
    for fname in sorted(os.listdir(AGENT_DIR)):
        if not fname.endswith(".py"):
            continue
        src = open(os.path.join(AGENT_DIR, fname), encoding="utf8").read()
        if not _SQL_WRITE.search(src):
            continue
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            body = "\n".join(l for l in src.splitlines()[node.lineno - 1:
                                                        (node.end_lineno or node.lineno)])
            if _SQL_WRITE.search(body):
                found["%s:%s" % (fname, node.name)] = True
    return set(found)


def test_no_ungated_sql_writer_reaches_the_findings_table():
    """ABSENCE of a bypass: the set of functions that write the findings table in SQL is exactly the
    known chokepoints. A new writer anywhere in the package fails this, whether or not it happens to
    call the gate — because the next one won't."""
    writers = _sql_writers()
    unexpected = writers - set(_ALLOWED_SQL_WRITERS)
    assert not unexpected, ("ungated writer(s) reaching the findings table: %s — route them through "
                            "db.add_finding/db.update_finding or justify them in _ALLOWED_SQL_WRITERS"
                            % sorted(unexpected))
    # and the two writers that INSERT/UPDATE must both route through the ONE gate evaluator, which
    # must itself evaluate all three named invariants. Checking the writers for the invariant NAMES
    # would be a guard on a declaration: `update_finding` could name `off_scope` in a comment and
    # still not act on it. Checking that the single evaluator exists and that both writers call it is
    # the fact — and the behavioural tests above are what prove the evaluator is obeyed.
    src = open(os.path.join(AGENT_DIR, "db.py"), encoding="utf8").read()
    import ast
    tree = ast.parse(src)

    def _body(name):
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
        return "\n".join(src.splitlines()[node.lineno - 1:(node.end_lineno or node.lineno)])

    for inv in ("normalize", "off_scope", "is_lead"):
        assert inv in _body("_gate"), "db._gate does not evaluate the %s invariant" % inv
    for fn in ("add_finding", "update_finding"):
        assert "_gate(" in _body(fn), "db.%s does not route through the gate evaluator" % fn


# ── absence-of-bypass: every HTTP route that can write a finding is gated ──
#: HTTP write routes under /findings, DISCOVERED from app.routes rather than hardcoded. Pinned so a
#: new body-bearing route forces a decision instead of silently inheriting a bypass.
_KNOWN_FINDING_WRITE_ROUTES = {
    ("POST", "/findings/{session_id}"),
    ("PUT", "/findings/{session_id}/{fid}"),
    ("POST", "/findings/{session_id}/{fid}/poc"),
}


def _finding_write_routes(app):
    out = set()
    for r in app.routes:
        path = getattr(r, "path", "")
        if not path.startswith("/findings"):
            continue
        for m in (getattr(r, "methods", None) or set()):
            if m in ("POST", "PUT", "PATCH"):
                out.add((m, path))
    return out


def test_every_finding_write_route_is_gated():
    """Drive EVERY discovered HTTP write route with each invariant-violating payload and assert that
    nothing violating reached storage. Path-agnostic on purpose: this is the control that fails if a
    bypass comes back through a route nobody remembered to gate."""
    import pytest
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    import main as mainmod

    routes = _finding_write_routes(mainmod.app)
    assert routes == _KNOWN_FINDING_WRITE_ROUTES, (
        "the set of /findings write routes changed: %s — drive the new one below and pin it"
        % sorted(routes ^ _KNOWN_FINDING_WRITE_ROUTES))

    dbmod.DB_PATH = os.path.join(tempfile.mkdtemp(), "t.db")
    dbmod._conn = None
    with TestClient(mainmod.app) as c:
        mid = "gatewrite"
        dbmod.create_mission(mid, "P", "active", "o", SCOPE, {})
        fid = dbmod.add_finding(mid, {"title": "legit", "confidence": "confirmed",
                                      "target": "http://app:3000/x",
                                      "evidence": "GET /x -> 200, owner-created object"})
        violating = [
            {"title": "s", "confidence": "confirmed", "target": "http://app:3000/x",
             "reproduction_steps": "1) do a 2) do b"},                     # SCHEMA
            {"title": "o", "confidence": "confirmed", "target": "http://evil.example.com/p"},  # SCOPE
            {"title": "t", "confidence": "lead", "target": "http://app:3000/x"},               # TRUTH
        ]
        for method, path in sorted(routes):
            url = path.replace("{session_id}", mid).replace("{fid}", fid)
            for payload in violating:
                c.request(method, url, json=payload)
                assert gate_violations(mid) == [], (
                    "%s %s let a gate violation reach storage: %s"
                    % (method, path, gate_violations(mid)))


# ── absence-of-bypass, second pass: no HTTP body can AUTHOR proof ──
#: Evidence prose an ENGINE would emit for a confirmed IDOR — it satisfies every signal group
#: `proof_schema.validate_confirmed` checks. Sent as a request body it must never produce a
#: confirmation, because `confirmed` names WHO observed the proof, not which words appear in a string.
_FABRICATED = {
    "title": "IDOR", "confidence": "confirmed", "confirmed": True, "family": "idor",
    "cwe": "CWE-639", "target": "http://app:3000/api/orders/2", "url": "http://app:3000/api/orders/2",
    "impact": "Any user can read any other user's order.",
    "evidence": ("GET /api/orders/2 as user A -> 200 with user B's owner record (identical body to "
                 "B's own read); the same request anon -> 403 denied. Cross-user object read."),
    "reproduction_steps": ["GET /api/orders/2"],
}


def test_no_http_write_route_can_mint_an_oracle_confirmation():
    """The property, stated where it cannot be sidestepped: starting from a mission with NO engine
    findings, driving EVERY discovered /findings write route with a fully-fabricated proof payload
    must leave zero rows that `get_findings_gated` reports as confirmed.

    Field-level rules are an implementation detail and each of them is individually defeatable — a
    PUT-only fix falls to DELETE + POST, a blacklist falls to the next field proof_schema learns to
    read. This asserts the outcome for every route at once, which is the shape that catches the
    bypass coming back through a path nobody remembered to gate.

    FAIL-BEFORE-FIX (measured): PUT with this payload moved a gate-demoted row from `lead` to
    `confirmed` — `is_confirmed` True with no engine having issued a request — and POST minted one
    outright from the same body.
    """
    import pytest
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    import main as mainmod
    import proof_schema as ps

    dbmod.DB_PATH = os.path.join(tempfile.mkdtemp(), "t.db")
    dbmod._conn = None
    with TestClient(mainmod.app) as c:
        mid = "mintcheck"
        dbmod.create_mission(mid, "P", "active", "o", SCOPE, {})
        routes = _finding_write_routes(mainmod.app)

        def confirmed_rows():
            return [f for f in dbmod.get_findings_gated(mid) if ps.is_confirmed(f)]

        # (1) every discovered write route, driven with the fabricated proof, in both the
        #     "no such finding yet" and "a finding exists to overwrite" states.
        seed = dbmod.add_finding(mid, {"title": "IDOR", "confidence": "confirmed", "family": "idor",
                                       "cwe": "CWE-639", "target": "http://app:3000/api/orders/2",
                                       "evidence": "the id parameter is sequential, looks guessable",
                                       "reproduction_steps": ["GET /api/orders/2"]})
        assert not confirmed_rows(), "the seed finding should be demoted by the proof gate"
        for method, path in sorted(routes):
            url = path.replace("{session_id}", mid).replace("{fid}", seed)
            c.request(method, url, json=_FABRICATED)
            assert not confirmed_rows(), (
                "%s %s minted an oracle confirmation from a request body: %s"
                % (method, path, [f.get("title") for f in confirmed_rows()]))

        # (2) the DELETE + POST route around a PUT-only fix
        c.delete("/findings/%s/%s" % (mid, seed))
        c.post("/findings/%s" % mid, json=dict(_FABRICATED, operator="e.bruno", rationale="I saw it"))
        assert not confirmed_rows(), "DELETE + POST minted an oracle confirmation"

        # (3) and the operator's claim is not discarded either — it is recorded as an attestation
        leads = (dbmod.get_mission(mid).get("context") or {}).get("leads") or []
        att = [l for l in leads if l.get("operator_attestation")]
        assert att and att[0]["operator_attestation"]["operator"] == "e.bruno"
        assert att[0]["operator_attestation"]["machine_proof"] is False


def test_put_refuses_a_proof_bearing_edit_with_a_reason_and_still_allows_annotation():
    """The two halves of the PUT rule, asserted separately because they are REDUNDANT and the
    outcome-level control above therefore cannot tell them apart: with either half alone a fabricated
    payload still fails to mint, so a mutant that removes one survives that test. Measured — mutants
    M9 (refusal removed) and M10 (whitelist merge removed) both survived
    `test_no_http_write_route_can_mint_an_oracle_confirmation` and are killed here.

    Half one: an attempt to author proof is REFUSED, visibly, naming the fields, and changes nothing.
    Half two: an annotation edit still lands — the route is narrowed, not disabled."""
    import pytest
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    import main as mainmod

    dbmod.DB_PATH = os.path.join(tempfile.mkdtemp(), "t.db")
    dbmod._conn = None
    with TestClient(mainmod.app) as c:
        mid = "putrule"
        dbmod.create_mission(mid, "P", "active", "o", SCOPE, {})
        fid = dbmod.add_finding(mid, {"title": "IDOR", "confidence": "confirmed", "family": "idor",
                                      "cwe": "CWE-639", "target": "http://app:3000/api/orders/2",
                                      "evidence": "the id parameter is sequential, looks guessable",
                                      "reproduction_steps": ["GET /api/orders/2"]})
        # half one — refused, with the offending field named, and nothing written
        r = c.put("/findings/%s/%s" % (mid, fid), json={"evidence": _FABRICATED["evidence"]})
        assert r.status_code == 400, r.text
        assert "evidence" in r.json()["detail"] and "Nothing was changed" in r.json()["detail"]
        assert dbmod.get_finding(mid, fid)["evidence"].startswith("the id parameter")

        # half two — an annotation edit still lands, and a full read-modify-write round trip that
        # changes ONLY an annotation is accepted even though it resends every proof field unchanged
        assert c.put("/findings/%s/%s" % (mid, fid), json={"title": "IDOR (triaged)"}).status_code == 200
        assert dbmod.get_finding(mid, fid)["title"] == "IDOR (triaged)"
        rmw = dict(dbmod.get_finding(mid, fid))
        rmw["analyst_notes"] = "reviewed"
        assert c.put("/findings/%s/%s" % (mid, fid), json=rmw).status_code == 200
        assert dbmod.get_finding(mid, fid)["analyst_notes"] == "reviewed"


def test_editable_key_whitelist_contains_nothing_the_proof_gate_reads():
    """A drift guard on the whitelist itself. `_EDITABLE_FINDING_KEYS` is what an HTTP body may
    change; if a key the proof gate READS ever lands in it, the route can author proof again. The
    forbidden set is derived from proof_schema rather than retyped, so a new proof field is covered
    the day it is added."""
    import main as mainmod
    import proof_schema as ps

    proof_read = set(ps.CONTROL_KEYS) | {ps.ORACLE_KEY, "oracle", "counter_example"}
    proof_read |= {k for k, _v in ps._SOURCE_MARKERS}                 # proof_kind's markers
    proof_read |= {"confidence", "confirmed", "evidence", "impact",   # validate_confirmed's inputs
                   "reproduction_steps", "family", "cwe",
                   "target", "url",                                   # scope + what is claimed
                   "operator_attestation", "authored_by", "id"}
    overlap = mainmod._EDITABLE_FINDING_KEYS & proof_read
    assert not overlap, ("these keys carry proof and must not be editable through an HTTP body: %s"
                         % sorted(overlap))
