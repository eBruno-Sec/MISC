"""Q-089: what `db.add_finding` RETURNS could not tell a store from a reroute, and a caller counted it.

THE DEFECT, measured 2026-08-18 against the running agent. `db.add_finding` is the write chokepoint
for the three finding invariants, and it has three genuinely different outcomes:

    SCHEMA/admit  -> a row is INSERTed into the findings table
    TRUTH  (#7)   -> a lead-confidence item is REROUTED to the mission's leads list; NO row
    SCOPE  (#8)   -> a provably off-scope item is REFUSED; nothing is written anywhere

It reported them with a single `str`: the finding id, the LEAD id, or "". The refusal is
distinguishable (falsy); **the reroute is not** -- it returns a truthy id exactly like a store. So

    stored = sum(1 for f in findings if db.add_finding(session_id, f))     # main.py:459

counted a reroute as a store, and `/engage` plus the mission context told the operator:

    status=complete   stored_findings=1   rejected_findings=0
    findings table:   0 rows          leads list: 1

WHY INVARIANT I-2 MISSED IT. I-2 ("every finding-producing path reaches exactly ONE persistence
owner") measured 0 unowned paths, and that measurement was CORRECT: this path has an owner. The
ambiguity is not in the ownership, it is in the OUTCOME the owner reports back across the boundary --
which an ownership census cannot see, because it counts edges and this defect lives in a return type.

THE FIX IS THE RETURN TYPE, NOT THE COUNTER. `add_finding` returns a `db.FindingWriteId`: a real `str`
(so every one of the 21 production call sites that uses it as an id is untouched, and it still
serialises, binds to sqlite and compares as the string it always was) carrying `.verdict` and
`.stored`. Counting the counter's own opinion is replaced by asking the writer what it did.

WHAT EACH HALF BELOW GUARDS

1. VERDICT UNIT TESTS -- all three outcomes, each asserted against the TABLE and the LEADS LIST, not
   against the return value alone. A return that claims `stored` while the table is empty is the
   whole ticket, so no assertion here is allowed to trust the verdict by itself.

2. BACK-COMPAT CONTROL -- the id contract every existing caller reads is byte-identical. If this
   fails, the fix broke 21 call sites this lane is not allowed to edit.

3. END-TO-END -- a REAL mission through the production `/engage` endpoint. `stored_findings` must
   equal `len(db.get_findings(sid))` for a rerouted lead (the defect) AND for a genuine store (the
   negative control, which proves the fix did not simply stop counting).

4. BYPASS GUARD -- an AST census proving NO production call site reads the write id as a store
   confirmation. Its own non-vacuity control (the census must find the known call sites) and its own
   semantic mutant (a planted truthiness read must be flagged) are below it, because a census that
   silently found nothing would pass this file forever.
"""
from __future__ import annotations

import ast
import asyncio
import os
import tempfile

import pytest
from fastapi.testclient import TestClient

import codeintel
import db as dbmod
import main as mainmod

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SCOPE = {"in_scope": ["app"], "bases": ["http://app:3000"], "out_of_scope": []}

#: The exact shape `codereview._source_finding` emits, so what a test changes is the ONE field under
#: examination (confidence / target) and nothing else.
CANONICAL = {
    "title": "Broken hash function: MD5", "severity": "medium", "target": "src/Weak.java",
    "confidence": "confirmed", "family": "weak_hash", "cwe": "CWE-328", "line": 8,
    "provenance": "source-derived", "lane": "code-assisted", "analysis": "static-call-site",
    "description": "MessageDigest.getInstance at src/Weak.java line 8", "impact": "no integrity",
    "evidence": "src/Weak.java:8  MessageDigest.getInstance(MD5)",
    "oracle": "the source selects the digest 'MD5' at a MessageDigest.getInstance call site",
    "remediation": "Use SHA-256.", "reproduction_steps": ["Open src/Weak.java at line 8"],
    "tags": ["sast", "code-assisted", "crypto", "hash"],
}


def _fresh_db(mid: str) -> None:
    """A private DB per test. The real corpus lives in a named docker volume and is never touched."""
    dbmod.DB_PATH = os.path.join(tempfile.mkdtemp(), "t.db")
    dbmod._conn = None
    dbmod.init(dbmod.DB_PATH)
    dbmod.create_mission(mid, "Q-089 write verdict", "active", "o", SCOPE, {})


def _leads(mid: str) -> list:
    return ((dbmod.get_mission(mid) or {}).get("context") or {}).get("leads") or []


# ══════════════════════════════════════════════════════════════════════════════════════
# 1. THE THREE VERDICTS -- each checked against the table and the leads list, never the return alone
# ══════════════════════════════════════════════════════════════════════════════════════

def test_an_admitted_finding_reports_stored_and_leaves_a_row():
    _fresh_db("q089ok")
    write = dbmod.add_finding("q089ok", dict(CANONICAL, target="http://app:3000/x"))

    assert write.verdict == dbmod.STORED
    assert write.stored is True
    rows = dbmod.get_findings("q089ok")
    assert len(rows) == 1 and rows[0]["id"] == str(write)
    assert _leads("q089ok") == []


def test_a_rerouted_lead_reports_rerouted_and_leaves_no_row():
    """The defect. The return is TRUTHY -- it is the lead id -- and the table is empty."""
    _fresh_db("q089lead")
    write = dbmod.add_finding("q089lead", dict(CANONICAL, confidence="lead",
                                               target="http://app:3000/x"))

    assert str(write), "precondition: the reroute still returns the lead id (truthy)"
    assert write.verdict == dbmod.REROUTED
    assert write.stored is False, "a reroute reported itself as a store"
    assert dbmod.get_findings("q089lead") == []
    leads = _leads("q089lead")
    assert len(leads) == 1 and leads[0]["id"] == str(write)


def test_an_off_scope_finding_reports_refused_and_writes_nothing_anywhere():
    _fresh_db("q089off")
    write = dbmod.add_finding("q089off", dict(CANONICAL, target="http://evil.example.com/p"))

    assert write.verdict == dbmod.REFUSED
    assert write.stored is False
    assert str(write) == ""
    assert dbmod.get_findings("q089off") == [] and _leads("q089off") == []


def test_the_three_verdicts_are_distinct_values():
    """A vocabulary whose members collide cannot distinguish anything."""
    assert len({dbmod.STORED, dbmod.REROUTED, dbmod.REFUSED}) == 3


# ══════════════════════════════════════════════════════════════════════════════════════
# 2. BACK-COMPAT -- the id contract 21 production call sites already read is unchanged
# ══════════════════════════════════════════════════════════════════════════════════════

def test_the_write_id_is_still_an_ordinary_string_for_every_existing_caller():
    """`f["id"] = db.add_finding(...)` is the dominant idiom and it must keep working verbatim:
    the value has to BE a str -- json-serialisable, sqlite-bindable, comparable and hashable as the
    id it always was. A wrapper object would have broken every one of those silently."""
    import json

    _fresh_db("q089compat")
    f = dict(CANONICAL, target="http://app:3000/x")
    f["id"] = dbmod.add_finding("q089compat", f)

    assert isinstance(f["id"], str)
    assert json.loads(json.dumps(f))["id"] == f["id"]
    assert dbmod.get_finding("q089compat", f["id"]) is not None
    assert {f["id"]: 1}[str(f["id"])] == 1, "the id no longer hashes as its own string"


def test_the_write_id_survives_copy_and_pickle_with_its_verdict():
    """FOUND BY THIS CONTROL, not by review. `copy` reconstructs a `str` subclass by calling
    `cls.__new__(cls, <the string>)`, so the first version of `FindingWriteId` made

        copy.deepcopy({"id": db.add_finding(...)})

    raise `TypeError: __new__() missing 1 required positional argument`. Nothing in production
    deepcopies a finding today, which is precisely why this needed a test rather than a reader: the
    break was invisible to every findings test and to the full suite, and the caller who hit it would
    have been someone else, later, with no reason to suspect the id."""
    import copy
    import pickle

    _fresh_db("q089copy")
    write = dbmod.add_finding("q089copy", dict(CANONICAL, target="http://app:3000/x"))

    for clone in (copy.copy(write), copy.deepcopy(write), pickle.loads(pickle.dumps(write)),
                  copy.deepcopy({"id": write})["id"]):
        assert clone == str(write)
        assert clone.verdict == dbmod.STORED, "a copy lost the verdict"
        assert clone.stored is True


def test_a_refused_write_is_still_falsy_and_a_reroute_is_still_truthy():
    """Deliberately pinned: this fix does NOT change truthiness. `tests/test_findings_gate.py:62`
    asserts a rerouted lead id is truthy, so making the reroute falsy would have been a silent
    behaviour change dressed up as a bug fix. The reroute is distinguished by `.stored`, and the
    census below is what proves no production caller still asks the truthiness question."""
    _fresh_db("q089truth")
    refused = dbmod.add_finding("q089truth", dict(CANONICAL, target="http://evil.example.com/p"))
    rerouted = dbmod.add_finding("q089truth", dict(CANONICAL, confidence="lead",
                                                   target="http://app:3000/x"))
    assert not refused
    assert rerouted


# ══════════════════════════════════════════════════════════════════════════════════════
# 3. END TO END -- a real mission through the production /engage endpoint
# ══════════════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.delenv("APOLAKI_API_TOKEN", raising=False)
    dbmod.init(str(tmp_path / "apolaki.db"))
    mainmod.sessions.clear()
    client = TestClient(mainmod.app)
    try:
        yield client
    finally:
        client.close()
        mainmod.sessions.clear()


def _engage(client, source_root):
    r = client.post("/engage", json={"program_name": "Q-089 write verdict",
                                     "in_scope": ["fixture.invalid"], "mode": "passive",
                                     "strategy": "deterministic", "source_root": str(source_root)})
    assert r.status_code == 200, r.text
    return r.json()


def _stub_analyzer(monkeypatch, findings):
    def _review(root, **_kw):
        return {"lane": "code-assisted", "provenance": "source-derived", "root": root, "error": "",
                "files_scanned": 1, "files": ["src/Weak.java"], "properties_resolved": 0,
                "findings": [dict(f) for f in findings], "by_cwe": {}, "by_file": {}}
    monkeypatch.setattr(codeintel, "review_source_tree", _review)


def test_engage_never_reports_more_stored_findings_than_the_table_holds(api, tmp_path, monkeypatch):
    """The measured defect, end to end on the surface the operator actually reads."""
    root = tmp_path / "src"
    root.mkdir()
    _stub_analyzer(monkeypatch, [dict(CANONICAL, confidence="lead")])

    engaged = _engage(api, root)
    sid = engaged["session_id"]
    state = engaged["source_review"]

    # non-vacuity: the analyzer DID run and the TRUTH invariant DID reroute -- otherwise a
    # stored_findings of 0 would be explained by nothing having happened at all.
    assert state["findings"] == 1, "the analyzer did not produce the finding under test"
    leads = api.get("/missions/%s" % sid).json()["leads"]
    assert len(leads) == 1, "precondition: the finding was rerouted to the leads list"

    rows = api.get("/findings/%s" % sid).json()["findings"]
    assert state["stored_findings"] == len(rows) == 0, (
        "stored_findings=%s but the findings table holds %s row(s)"
        % (state["stored_findings"], len(rows)))
    assert state["stored_findings"] == len(dbmod.get_findings(sid))
    assert "lead" in state["error"], (
        "the operator is told a count without being told the reroute that explains it: %r"
        % state["error"])

    # the archived copy the report reads must carry the same number, not the optimistic one
    assert api.get("/missions/%s" % sid).json()["source_review"]["stored_findings"] == 0


def test_a_genuine_source_store_still_counts_end_to_end(api, tmp_path, monkeypatch):
    """NEGATIVE CONTROL. A fix that made `stored_findings` honest by making it always 0 would pass
    the test above. Two real stores must still be counted as two."""
    root = tmp_path / "src"
    root.mkdir()
    _stub_analyzer(monkeypatch, [dict(CANONICAL),
                                 dict(CANONICAL, title="Weak cipher: DES", cwe="CWE-327",
                                      family="weak_crypto", line=12)])

    engaged = _engage(api, root)
    sid = engaged["session_id"]
    state = engaged["source_review"]

    assert state["status"] == "complete", state.get("error")
    assert state["stored_findings"] == 2
    assert state["stored_findings"] == len(dbmod.get_findings(sid))
    assert state["rejected_findings"] == 0 and state["error"] == ""
    assert api.get("/missions/%s" % sid).json()["leads"] == []


def test_the_source_lane_reports_a_reroute_without_calling_it_a_rejection(monkeypatch):
    """A reroute is CORRECT behaviour, so the lane may not report it as a persistence failure with
    no further explanation. The count must be honest AND the reason must name what happened."""
    _fresh_db("q089say")

    def _review(root, **_kw):
        return {"lane": "code-assisted", "provenance": "source-derived", "root": root, "error": "",
                "files_scanned": 1, "files": ["src/Weak.java"], "properties_resolved": 0,
                "findings": [dict(CANONICAL, confidence="lead")], "by_cwe": {}, "by_file": {}}
    monkeypatch.setattr(codeintel, "review_source_tree", _review)

    state = asyncio.run(mainmod._run_source_review("q089say", "/does/not/matter"))
    assert state["stored_findings"] == 0 == len(dbmod.get_findings("q089say"))
    assert len(_leads("q089say")) == 1
    assert "rerouted" in state["error"] and "lead" in state["error"], state["error"]


# ══════════════════════════════════════════════════════════════════════════════════════
# 4. BYPASS GUARD -- no production call site reads the write id as a store confirmation
# ══════════════════════════════════════════════════════════════════════════════════════

def _production_sources():
    """Every production module in the package. `tests/` is excluded ON PURPOSE: a test may legitimately
    assert the truthiness of a lead id (test_findings_gate.py:62 does), and that is the pin, not a
    violation."""
    out = []
    for dirpath, dirnames, filenames in os.walk(AGENT_DIR):
        dirnames[:] = [d for d in dirnames if d not in ("tests", "__pycache__", ".git")]
        for fn in sorted(filenames):
            if fn.endswith(".py"):
                p = os.path.join(dirpath, fn)
                out.append((os.path.relpath(p, AGENT_DIR),
                            open(p, encoding="utf-8", errors="replace").read()))
    return out


def _write_id_uses(path, src):
    """(call sites, boolean-context uses) for `db.add_finding` in one module.

    Resolves the module under EVERY binding form -- `import db`, `import db as X`,
    `from db import add_finding`, `from db import add_finding as af` -- because a `db.add_finding(`
    text scan missed aliased and from-imported sites in this package two days ago and produced a
    confidently wrong zero. Boolean context is either DIRECT (the call is the test of an if / while /
    ternary / assert, a comprehension condition, an operand of and/or/not, or an argument to
    bool()/any()/all()) or ONE HOP through a local name assigned from the call, which is how the
    same question gets asked two lines later.
    """
    tree = ast.parse(src)
    parents = {c: n for n in ast.walk(tree) for c in ast.iter_child_nodes(n)}
    mods, direct = set(), {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.name == "db" or a.name.endswith(".db"):
                    mods.add(a.asname or a.name.split(".")[0])
        elif isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[-1] == "db":
            for a in n.names:
                if a.name == "add_finding":
                    direct[a.asname or a.name] = a.name

    def _is_call(node):
        if not isinstance(node, ast.Call):
            return False
        fn = node.func
        if isinstance(fn, ast.Attribute) and fn.attr == "add_finding":
            return isinstance(fn.value, ast.Name) and fn.value.id in mods
        return isinstance(fn, ast.Name) and fn.id in direct

    def _bool_ctx(node):
        p = parents.get(node)
        while isinstance(p, ast.UnaryOp):
            node, p = p, parents.get(p)
        if isinstance(p, ast.BoolOp):
            return "and/or"
        if isinstance(p, (ast.If, ast.While, ast.IfExp)) and p.test is node:
            return type(p).__name__.lower() + " test"
        if isinstance(p, ast.Assert) and p.test is node:
            return "assert"
        if isinstance(p, ast.comprehension) and any(i is node for i in p.ifs):
            return "comprehension condition"
        if isinstance(p, ast.Call) and isinstance(p.func, ast.Name) and p.func.id in (
                "bool", "any", "all"):
            return "%s()" % p.func.id
        return ""

    spans = [(n.lineno, n.end_lineno or n.lineno) for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]

    def scope(line):
        best = 0
        for a, b in spans:
            if a <= line <= b and a > best:
                best = a
        return best

    calls, bad, tainted = [], [], {}
    for n in ast.walk(tree):
        if not _is_call(n):
            continue
        calls.append("%s:%d" % (path, n.lineno))
        ctx = _bool_ctx(n)
        if ctx:
            bad.append("%s:%d used directly as a %s" % (path, n.lineno, ctx))
        p = parents.get(n)
        if isinstance(p, ast.Assign) and len(p.targets) == 1 and isinstance(p.targets[0], ast.Name):
            tainted[(scope(n.lineno), p.targets[0].id)] = n.lineno
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)):
            continue
        src_line = tainted.get((scope(n.lineno), n.id))
        ctx = _bool_ctx(n) if src_line else ""
        if ctx:
            bad.append("%s:%d `%s` (from line %d) used as a %s" % (path, n.lineno, n.id, src_line, ctx))
    return calls, bad


def test_no_production_call_site_reads_the_write_id_as_a_store_confirmation():
    """ABSENCE, repository-wide. The Q-089 shape is `if db.add_finding(...)` in any spelling: the id
    is truthy for a REROUTE, so truthiness answers "did something happen", never "was it stored".
    A caller that needs the answer must read `.stored`."""
    offenders = []
    for path, src in _production_sources():
        offenders += _write_id_uses(path, src)[1]
    assert not offenders, (
        "production code reads db.add_finding's return as a store confirmation: %s -- a rerouted "
        "lead returns a TRUTHY id and no row. Read `.stored` (db.FindingWriteId)." % offenders)


def test_the_census_is_non_vacuous():
    """A census that found nothing would pass the guard above forever. Measured 2026-08-20:
    21 production call sites (agent.py 15, main.py 5, tools.py 1)."""
    calls = []
    for path, src in _production_sources():
        calls += _write_id_uses(path, src)[0]
    assert len(calls) >= 18, (
        "the add_finding census found only %d call site(s); it was 21 when this guard was written, "
        "so the resolver is broken rather than the tree being clean: %s" % (len(calls), calls))
    assert any(c.startswith("agent.py:") for c in calls)
    assert any(c.startswith("main.py:") for c in calls)


@pytest.mark.parametrize("planted", [
    "import db\ndef f(m, x):\n    if db.add_finding(m, x):\n        return 1\n",
    "import db as _d\ndef f(m, xs):\n    return sum(1 for x in xs if _d.add_finding(m, x))\n",
    "from db import add_finding\ndef f(m, x):\n    return bool(add_finding(m, x))\n",
    "from db import add_finding as af\ndef f(m, x):\n    fid = af(m, x)\n    if fid:\n        return 1\n",
    "import db\ndef f(m, x):\n    return db.add_finding(m, x) and 2\n",
])
def test_the_bypass_guard_flags_a_planted_truthiness_read(planted):
    """SEMANTIC MUTANT for the guard itself, one per binding form the resolver claims to handle --
    including the aliased and from-imported spellings a text scan misses. If any of these is not
    flagged, the clean result above is a property of the scanner, not of the tree."""
    _, bad = _write_id_uses("planted.py", planted)
    assert bad, "the census did not flag a planted truthiness read:\n%s" % planted


def test_the_bypass_guard_does_not_flag_an_ordinary_id_use():
    """The other half of the mutant: a guard that flagged everything would also be vacuous."""
    ok = ("import db\n"
          "def f(m, x):\n"
          "    x['id'] = db.add_finding(m, x)\n"
          "    fid = db.add_finding(m, x)\n"
          "    return {'id': fid}\n")
    calls, bad = _write_id_uses("ok.py", ok)
    assert len(calls) == 2 and bad == []
