"""Q-044 source-proof lane: the code-assisted lane's PERSISTENCE half, which nothing tested.

Q-044 was filed because the code-assisted (SAST) lane was an island. The wiring was fixed by another
lane, but the ticket's own definition of done -- *a real mission produces a stored source-derived
finding* -- stayed unproven, and measured against the live corpus (1057 findings / 113 missions) the
count of `provenance=source-derived` rows was **0**. The path existed and had never carried a finding.

It carries one now: mission `2fb87a3a` stored **716** source-derived findings from the OWASP Benchmark
Java tree through the production `/engage` endpoint (see `docs/handoff/source_proof.md`). These tests
are the regression guard for that result, because there was none -- `agent/tests/` covered
`codereview.review_source` and `codeintel.review_source_tree` thoroughly and covered
`main._run_source_review`, `main._canonical_source_finding` and the write into `db.findings` not at all.
An engine proven to PRODUCE a finding is not an engine proven to STORE one; that gap is the whole
ticket.

Every fixture below was measured against the running agent before the test was written.

WHAT EACH HALF GUARDS

1. The POSITIVE CONTROL is the mission proof in miniature: a real Java tree through the real
   `_run_source_review` must leave rows in `db.findings` carrying all three canonical markers. If the
   lane silently stops persisting, this goes red.

2. The MUTANTS are the negative control the positive control needs. `_canonical_source_finding` is
   supposed to FAIL CLOSED, and a contract that never rejects anything is indistinguishable from no
   contract at all. Each mutant removes exactly one required marker and asserts that NOTHING is
   written -- so a passing positive control cannot be explained by a gate that admits everything.

3. The STRICT XFAIL pins a MEASURED latent defect (below). It is not a wish; it is executable
   evidence, so a fix makes the suite go red and the marker has to be removed deliberately.
"""
from __future__ import annotations

import asyncio
import os
import tempfile

import pytest

import codeintel
import db as dbmod
import main as mainmod

SCOPE = {"in_scope": ["app"], "bases": ["http://app:3000"], "out_of_scope": []}

# Measured: `codeintel.review_source_tree` on this one file returns exactly three findings --
# weak_crypto/CWE-327 line 12, weak_hash/CWE-328 line 8, weak_random/CWE-330 line 15 -- each carrying
# provenance=source-derived, lane=code-assisted, analysis=static-call-site, confidence=confirmed.
JAVA = """package com.example;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import java.util.Random;

public class Weak {
    public byte[] digest(byte[] b) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(b);
    }
    public Cipher cipher() throws Exception {
        return Cipher.getInstance("DES/ECB/PKCS5Padding");
    }
    public int token() {
        Random r = new Random();
        return r.nextInt();
    }
}
"""

# One canonical source finding in the exact shape `codereview._source_finding` emits. Used by the
# mutants, so what they remove is a marker and nothing else.
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
    dbmod.create_mission(mid, "Q-044 persistence", "active", "o", SCOPE, {})


def _java_tree() -> str:
    root = tempfile.mkdtemp()
    os.makedirs(os.path.join(root, "src"), exist_ok=True)
    with open(os.path.join(root, "src", "Weak.java"), "w", encoding="utf-8") as fh:
        fh.write(JAVA)
    return root


def _stub_tree(monkeypatch, findings: list) -> None:
    """Return `findings` from the analyzer without changing anything else about the envelope."""
    def _review(root, **_kw):
        return {"lane": "code-assisted", "provenance": "source-derived", "root": root, "error": "",
                "files_scanned": 1, "files": ["src/Weak.java"], "properties_resolved": 0,
                "findings": [dict(f) for f in findings], "by_cwe": {}, "by_file": {}}
    monkeypatch.setattr(codeintel, "review_source_tree", _review)


# ══════════════════════════════════════════════════════════════════════════════════════
# 1. POSITIVE CONTROL -- the Q-044 proof in miniature, on the real analyzer
# ══════════════════════════════════════════════════════════════════════════════════════

def test_a_real_source_tree_lands_canonical_findings_in_the_findings_table():
    """The whole ticket: `_run_source_review` must leave ROWS IN THE DB, not merely return a count.

    The assertion that matters is the second one. `stored_findings` is a number the function computes
    about itself; `db.get_findings` is the table. Q-044's zero was measured on the table, so the proof
    has to be measured there too.
    """
    _fresh_db("q044pos")
    state = asyncio.run(mainmod._run_source_review("q044pos", _java_tree()))

    assert state["status"] == "complete", state.get("error")
    assert state["findings"] == 3 and state["rejected_findings"] == 0

    rows = dbmod.get_findings("q044pos")
    assert len(rows) == 3, "the lane reported findings that never reached the findings table"
    assert state["stored_findings"] == len(rows), (
        "stored_findings disagrees with the table -- see the strict xfail below")

    for row in rows:
        assert row["provenance"] == "source-derived"
        assert row["lane"] == "code-assisted"
        assert row["analysis"] == "static-call-site"
    assert {r["cwe"] for r in rows} == {"CWE-327", "CWE-328", "CWE-330"}


def test_the_stored_rows_are_findable_by_the_query_that_reported_zero():
    """The Q-044 baseline query itself, run against a mission that used the lane.

    `SELECT ... WHERE provenance='source-derived'` returned 0 across 1057 rows. A guard on the count
    is worth nothing unless the guard uses the same predicate the measurement did.
    """
    _fresh_db("q044qry")
    asyncio.run(mainmod._run_source_review("q044qry", _java_tree()))
    source_derived = [f for f in dbmod.get_findings("q044qry")
                      if f.get("provenance") == "source-derived"]
    assert len(source_derived) == 3


def test_the_lane_records_itself_on_the_mission_context():
    """The report reads the mission context, so a stored finding with no lane record is unattributable."""
    _fresh_db("q044ctx")
    asyncio.run(mainmod._run_source_review("q044ctx", _java_tree()))
    review = ((dbmod.get_mission("q044ctx") or {}).get("context") or {}).get("source_review") or {}
    assert review.get("lane") == "code-assisted"
    assert review.get("provenance") == "source-derived"
    assert review.get("status") == "complete"
    assert review.get("stored_findings") == 3


# ══════════════════════════════════════════════════════════════════════════════════════
# 2. MUTANTS -- `_canonical_source_finding` must FAIL CLOSED, or the positive control is vacuous
# ══════════════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("marker", ["provenance", "lane", "analysis"])
def test_a_finding_missing_one_marker_is_rejected_and_nothing_is_stored(monkeypatch, marker):
    """Remove exactly ONE required marker; the whole batch must be refused.

    This is the guard against the shape this project keeps producing: a contract that is declared and
    never enforced. If any of these three mutants stores a row, the evidence contract is decoration
    and the positive control above proves nothing about it.
    """
    mutant = dict(CANONICAL)
    mutant.pop(marker)
    _fresh_db("q044mut")
    _stub_tree(monkeypatch, [mutant])

    state = asyncio.run(mainmod._run_source_review("q044mut", "/does/not/matter"))

    assert state["status"] == "error", "a finding missing %r was accepted" % marker
    assert state["rejected_findings"] == 1
    assert state["stored_findings"] == 0
    assert dbmod.get_findings("q044mut") == [], (
        "a non-canonical source finding reached the findings table under DAST semantics")


def test_one_bad_finding_rejects_the_whole_batch(monkeypatch):
    """`valid_findings` is an `all(...)`, and that is deliberate -- pin it.

    A partial store would put SOME rows in under DAST semantics while reporting an error, which is the
    worst of both: a wrong number and a wrong provenance, with a red status to explain neither.
    """
    bad = dict(CANONICAL, provenance="dast")
    _fresh_db("q044mix")
    _stub_tree(monkeypatch, [dict(CANONICAL), bad])

    state = asyncio.run(mainmod._run_source_review("q044mix", "/does/not/matter"))

    assert state["status"] == "error"
    assert state["rejected_findings"] == 2
    assert dbmod.get_findings("q044mix") == []


def test_an_absent_source_root_stores_nothing_and_is_not_an_error(monkeypatch):
    """The default path. A mission without `source_root` must be indistinguishable from today's."""
    _fresh_db("q044none")
    called = []
    monkeypatch.setattr(codeintel, "review_source_tree",
                        lambda *a, **k: called.append(a) or {"findings": []})
    state = asyncio.run(mainmod._run_source_review("q044none", None))
    assert called == [], "the analyzer ran with no source provided"
    assert state["stored_findings"] == 0
    assert state["error"] == "no source provided"
    assert dbmod.get_findings("q044none") == []


# ══════════════════════════════════════════════════════════════════════════════════════
# 3. MEASURED LATENT DEFECT -- `stored_findings` can count a finding that is NOT stored
# ══════════════════════════════════════════════════════════════════════════════════════

# Q-082 CLOSED 2026-08-19 -- the strict xfail this test carried has been removed BY DESIGN, which is
# what the pin was for (see this module's docstring, point 3: "a fix makes the suite go red and the
# marker has to be removed deliberately"). The measured defect was worse than the pin recorded:
# 716 of 716 markdown findings, and 4 of 4 HTML cards, carried the fabricated request. The fix lives
# in `report.finding_curl` (a `proof_schema.proof_kind` check) plus a `Where in the code` block in
# BOTH renderers -- the pin's note that "the fix is local and needs no renderer change" was right
# about the false claim and wrong about what replaces it. Full evidence: docs/handoff/reproduction.md.
def test_a_source_derived_finding_gets_no_curl_reproduction():
    import report
    assert report.finding_curl(dict(CANONICAL)) == "", (
        "a static call-site finding was given an HTTP reproduction command")


@pytest.mark.xfail(strict=True, reason=(
    "MEASURED 2026-08-18 against the running agent. `db.add_finding` returns a TRUTHY id from "
    "`add_lead` when the TRUTH invariant reroutes a lead-confidence finding to the mission's leads "
    "list, and `_run_source_review` counts `sum(1 for f in findings if db.add_finding(...))`. A "
    "canonical source finding carrying confidence='lead' therefore yields status=complete, "
    "stored_findings=1, rejected_findings=0 -- while the findings table holds 0 rows and the leads "
    "list holds 1. The /engage response and the mission context both tell the operator a "
    "source-derived finding was stored when none was. LATENT today because "
    "`codereview._source_finding` hard-codes confidence='confirmed', so no production producer can "
    "emit this shape; `_canonical_source_finding` does not constrain confidence, so any future one "
    "can. Patch proposed in docs/handoff/source_proof.md -- count what the table accepted, and "
    "report rerouted leads under their own key rather than as stored findings."))
def test_stored_findings_must_never_count_a_finding_the_table_did_not_accept(monkeypatch):
    _fresh_db("q044lead")
    _stub_tree(monkeypatch, [dict(CANONICAL, confidence="lead")])

    state = asyncio.run(mainmod._run_source_review("q044lead", "/does/not/matter"))

    rows = dbmod.get_findings("q044lead")
    leads = ((dbmod.get_mission("q044lead") or {}).get("context") or {}).get("leads") or []
    assert len(leads) == 1, "precondition: the TRUTH invariant did reroute it to leads"
    assert state["stored_findings"] == len(rows), (
        "stored_findings=%s but the findings table holds %s row(s)"
        % (state["stored_findings"], len(rows)))
