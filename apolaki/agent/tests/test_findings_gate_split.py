"""Q-017 -- `db.get_findings` (RAW) vs `db.get_findings_gated`, and the rule that decides which.

`main.py` split 13 raw call sites against 7 gated ones with the rule written down NOWHERE, so which
side a call site sat on was maintained by guesswork. Measured before changing anything (whole stored
corpus, 1057 findings / 113 missions): the gate is LENGTH-PRESERVING (1057 rows in, 1057 out, zero
missions differ) and rewrites exactly four fields -- confidence, proof_gap, tags, success_oracle --
on 107 rows across 63 missions, 64 of them confirmed -> lead.

That makes the rule decidable instead of aesthetic:

  * GATED when whole rows reach a human, a model, a report or a SCORE. Since the gate never drops a
    row, this can only ever ANNOTATE a finding, never hide one.
  * RAW is REQUIRED -- not merely tolerated -- on any path that WRITES rows back
    (`db.update_finding`, `db.add_finding`) or exports for round-trip restore, because the gate
    rewrites in place and a gated read on a write path PERSISTS a presentation-time demotion.
  * RAW is CORRECT for a count, a dedupe key, or a field the gate does not touch -- but that is a
    claim about the CONSUMER, and every such site was measured, not assumed (0/63 each, with an
    all-rows-demoted positive control proving those consumers are blind to `confidence`).

Ten of the thirteen raw sites were already correct and three of those ten would BREAK if converted.
Three were wrong. These tests pin BOTH halves, because a lane that mass-converts is as wrong as the
drift that put the benchmark scorer on the raw side.

FAIL-BEFORE-FIX, measured on the pre-fix tree -- no import errors, every symbol already existed:
  * /findings/{sid}      -> confidence == 'confirmed', proof_gap absent   -> assert FAILED
  * /missions/{sid}      -> confidence == 'confirmed'                     -> assert FAILED
  * /benchmark/clientauthz?session= -> confirmed_coverage_pct == 100.0    -> assert FAILED
                                       (the honest value is 0.0)
The three raw-by-design controls (/backup, the round trip, the census) PASSED before the fix and
must keep passing: they are what stops the next lane from "fixing" the other ten.
"""
from __future__ import annotations

import ast
import json
import os
import tempfile

import db as dbmod
import main as mainmod
from fastapi.testclient import TestClient

SCOPE = {"in_scope": ["app"], "bases": ["http://app:3000"], "out_of_scope": []}

# family `idor` is in proof_schema._DEFAULT_ENFORCE and this evidence carries no ownership/denial
# signal, so the gate demotes it. It is still a legitimate stored row: `db.add_finding`'s write gate
# accepts it (its TRUTH invariant only rejects a `lead` confidence), which is exactly how the 64
# demotable rows in the real corpus got there.
UNPROVEN = {"title": "IDOR on /api/orders/2", "family": "idor", "severity": "high",
            "cwe": "CWE-639", "target": "http://app:3000/api/orders/2",
            "confidence": "confirmed", "impact": "read another user's order",
            "description": "sequential object id", "reproduction_steps": ["GET /api/orders/2"],
            "evidence": "GET /api/orders/2 -> 200 returned an order"}

# NEGATIVE CONTROL row: same family, but the evidence carries the ownership + denial signals the
# gate demands. It must survive every gated surface as `confirmed`.
PROVEN = {"title": "IDOR on /api/orders/9", "family": "idor", "severity": "high",
          "cwe": "CWE-639", "target": "http://app:3000/api/orders/9",
          "confidence": "confirmed", "impact": "read another user's order",
          "description": "sequential object id",
          "reproduction_steps": ["GET /api/orders/9 as user B"],
          "evidence": ("GET /api/orders/9 as user B -> 200; the object's owner is user A "
                       "(owner field = userA), and the same request without the session is denied "
                       "with 401")}


def _seed(mid: str, rows=(UNPROVEN,)) -> None:
    dbmod.DB_PATH = os.path.join(tempfile.mkdtemp(), "t.db")
    dbmod._conn = None
    dbmod.init(dbmod.DB_PATH)
    dbmod.create_mission(mid, "P", "active", "o", SCOPE, {})
    for r in rows:
        assert dbmod.add_finding(mid, dict(r)), "fixture row was rejected by the WRITE gate"


def _by_title(findings):
    return {f.get("title"): f for f in findings}


# ── the three sites the rule condemns: readers must be gated ─────────────────────────────────────

def test_findings_api_is_gated_and_hides_nothing():
    _seed("gsplit1", rows=(UNPROVEN, PROVEN))
    with TestClient(mainmod.app) as c:
        body = c.get("/findings/gsplit1").json()["findings"]
    # NOTHING IS HIDDEN. The gate is non-destructive, so gating a reader must not shrink the set.
    assert len(body) == len(dbmod.get_findings("gsplit1")) == 2
    got = _by_title(body)
    weak = got["IDOR on /api/orders/2"]
    assert weak["confidence"] == "lead", "an unproven confirmation reached the findings API as confirmed"
    assert weak.get("proof_gap"), "the demotion must say WHY, or the reader cannot act on it"
    assert "needs-confirmation" in (weak.get("tags") or [])
    # NEGATIVE CONTROL: the gate must not flatten everything into leads.
    assert got["IDOR on /api/orders/9"]["confidence"] == "confirmed"


def test_mission_detail_is_gated_and_hides_nothing():
    _seed("gsplit2", rows=(UNPROVEN, PROVEN))
    with TestClient(mainmod.app) as c:
        body = c.get("/missions/gsplit2").json()["findings"]
    assert len(body) == 2
    got = _by_title(body)
    assert got["IDOR on /api/orders/2"]["confidence"] == "lead"
    assert got["IDOR on /api/orders/2"].get("proof_gap")
    assert got["IDOR on /api/orders/9"]["confidence"] == "confirmed"


def test_benchmark_score_counts_only_confirmations_the_gate_allowed():
    """The measured wrong number: three stored missions published confirmed_coverage_pct 100.0 on
    `clientauthz` where every one of those confirmations had already been demoted."""
    _seed("gsplit3")
    with TestClient(mainmod.app) as c:
        m = c.get("/benchmark/clientauthz?session=gsplit3").json()["metrics"]
    assert m["confirmed_coverage_pct"] == 0.0, "a demoted row scored as a confirmation"
    assert m["confirmed_classes"] == 0
    # ...and DISCOVERY is untouched. Gating the scorer must not manufacture a false negative:
    # `benchmark.evaluate` builds `discovered` from every row regardless of confidence.
    assert m["class_coverage_pct"] == 100.0
    assert m["discovered_classes"] == 1 and m["false_negatives"] == 0
    assert m["findings_total"] == 1


def test_benchmark_score_still_credits_a_proven_confirmation():
    """NEGATIVE CONTROL for the test above: if gating the scorer zeroed every confirmation, the
    previous assertion would pass for the wrong reason."""
    _seed("gsplit4", rows=(PROVEN,))
    with TestClient(mainmod.app) as c:
        m = c.get("/benchmark/clientauthz?session=gsplit4").json()["metrics"]
    assert m["confirmed_coverage_pct"] == 100.0
    assert m["confirmed_classes"] == 1


# ── the raw-by-design half: converting these would be the bug ────────────────────────────────────

def test_backup_stays_raw_because_restore_writes_it_back():
    """`/backup` is a round trip of STORED state, not a presentation of it. `POST /restore` feeds
    these rows straight into `db.add_finding`, so gating the export would bake a presentation-time
    demotion into the restored mission permanently."""
    _seed("gsplit5")
    with TestClient(mainmod.app) as c:
        dump = json.loads(c.get("/backup/gsplit5").text)
        assert dump["findings"][0]["confidence"] == "confirmed", "backup must export STORED state"
        assert "proof_gap" not in dump["findings"][0]
        new_id = c.post("/restore", json=dump).json()["session_id"]
        # the round trip preserved the stored verdict...
        assert dbmod.get_findings(new_id)[0]["confidence"] == "confirmed"
        # ...while the restored mission's READER surface still tells the truth about it.
        assert c.get("/findings/%s" % new_id).json()["findings"][0]["confidence"] == "lead"


def test_poc_capture_does_not_persist_a_demotion(monkeypatch):
    """`POST /findings/{sid}/{fid}/poc` is a read-modify-`db.update_finding`. A gated read here
    would write `lead` + `proof_gap` back into storage, so attaching a screenshot would silently
    demote the finding it was meant to strengthen."""
    import browser_engine
    _seed("gsplit6")
    fid = dbmod.get_findings("gsplit6")[0]["id"]
    monkeypatch.setattr(browser_engine, "screenshot",
                        lambda url: {"browser": True, "png_b64": "iVBOR", "bytes": 5})
    with TestClient(mainmod.app) as c:
        assert c.post("/findings/gsplit6/%s/poc" % fid).json()["ok"] is True
    stored = dbmod.get_findings("gsplit6")[0]
    assert stored["confidence"] == "confirmed", "attaching a PoC demoted the finding in STORAGE"
    assert "proof_gap" not in stored
    assert stored.get("poc_screenshot")


def test_status_count_is_identical_either_way():
    """The count endpoint is raw, and that is safe only because the gate never drops a row. This
    test is what makes that claim falsifiable rather than an assumption in a comment."""
    _seed("gsplit7", rows=(UNPROVEN, PROVEN))
    assert len(dbmod.get_findings("gsplit7")) == len(dbmod.get_findings_gated("gsplit7"))
    with TestClient(mainmod.app) as c:
        assert c.get("/status/gsplit7").json()["findings_count"] == 2


# ── drift guard: every call site is on a DECLARED side ───────────────────────────────────────────

# Enclosing function -> why raw is correct there. Adding a raw read without adding a line here is a
# test failure, which is the whole point: the drift that put the benchmark scorer on the raw side
# happened silently.
RAW_BY_DESIGN = {
    "get_status": "count only; the gate is length-preserving",
    "_report_bundle": "gated inline on the next lines via proof_schema.demote_unproven",
    "_tool_ledger": "reads family/cwe, which the gate never rewrites",
    "asvs_coverage": "asvs_model.assess maps by family/cwe and never reads confidence",
    "blind_benchmark_run": "SEALING; match keys are (path, family, proof)",
    "technique_plan": "observations are family/cwe/target; TP never reads confidence",
    "attack_graph_view": "same observation layer as technique_plan",
    "cloud_posture_ingest": "dedupe key set over (title, target, provenance, account)",
    "capture_finding_poc": "read-modify-WRITE; a gated read would persist the demotion",
    "backup": "round-trip export; /restore writes these rows back via db.add_finding",
}

# Presentation surfaces that must never regress to a raw read.
MUST_BE_GATED = {"mission_detail", "get_findings", "benchmark_fixture", "_coverage",
                 "get_report_poc", "_graph_inputs", "_record_memory", "retest_findings",
                 "poc_bundle_export", "sarif_export"}


def _census():
    """(raw, gated) -> {enclosing function name: [line, ...]}, resolved with ast so a decorator can
    never be mis-assigned. A grep-based census mis-attributed a call to a handler 294 lines away."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "main.py")
    tree = ast.parse(open(path, encoding="utf-8").read())
    spans = [(n.lineno, n.end_lineno, n.name) for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]

    def owner(line):
        best = None
        for a, b, name in spans:
            if a <= line <= b and (best is None or a > best[0]):
                best = (a, name)
        return best[1] if best else "<module>"

    raw, gated = {}, {}
    for n in ast.walk(tree):
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and isinstance(n.func.value, ast.Name) and n.func.value.id == "db"
                and n.func.attr in ("get_findings", "get_findings_gated")):
            bucket = gated if n.func.attr == "get_findings_gated" else raw
            bucket.setdefault(owner(n.lineno), []).append(n.lineno)
    return raw, gated


def test_every_raw_findings_read_declares_why():
    raw, _ = _census()
    undeclared = {fn: lines for fn, lines in raw.items() if fn not in RAW_BY_DESIGN}
    assert not undeclared, (
        "raw db.get_findings() with no declared reason: %s. Read the Q-017 rule above "
        "main.py's get_status, decide which clause this site claims, and add it to "
        "RAW_BY_DESIGN -- or use db.get_findings_gated()." % undeclared)


def test_presentation_surfaces_never_regress_to_raw():
    raw, gated = _census()
    regressed = sorted(MUST_BE_GATED & set(raw))
    assert not regressed, "presentation surface reverted to a raw findings read: %s" % regressed
    missing = sorted(MUST_BE_GATED - set(gated))
    assert not missing, "declared-gated surface no longer reads findings at all: %s" % missing


def test_census_apparatus_actually_sees_both_kinds():
    """POSITIVE CONTROL for the two guards above. If `_census` silently returned empty dicts -- a
    renamed accessor, a moved file -- both would pass while checking nothing."""
    raw, gated = _census()
    assert len(raw) >= 10 and len(gated) >= 10, (len(raw), len(gated))
    assert "backup" in raw and "get_findings" in gated
