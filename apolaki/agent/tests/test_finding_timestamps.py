"""Q-102 — a finding is a claim about a MOMENT, and the moment was being thrown away.

Operator-reported from a live Shopify run: the report carried exactly one time, its own render clock.
Every finding and every ledger row was undated, so a running assessment could not be told apart from
a wedged one, and `Retest / closure` could not say which moment was being retested.

The data existed the whole time. `db.get_findings` ran

    SELECT data FROM findings WHERE mission_id=? ORDER BY created_at

which SORTS by the timestamp and never SELECTS it. Used and discarded inside one statement, the same
shape as `_cmd` dropping `proc.returncode` (Q-092) and `_key_bits` dropping the key algorithm (Q-101).

THE LOAD-BEARING TEST HERE IS `test_rendering_twice_does_not_move_the_timestamps`. A report that
stamps itself at render time would pass every other assertion in this file while telling the reader
nothing about the evidence -- and it would look authoritative doing it, which makes it worse than
printing no time at all.
"""
import os
import tempfile

import pytest

import db
import report


@pytest.fixture()
def mission(tmp_path):
    db.init(str(tmp_path / "ts.db"))
    mid = db.create_mission("ts-program", {"in_scope": ["example.test"]})
    return mid


def _finding(fid, title):
    return {"id": fid, "title": title, "severity": "medium", "target": "https://example.test/",
            "description": "d", "engine": "transport_posture", "family": "security_misconfig"}


# ── the accessor must hand back the instant it already sorts on ───────────────

def test_get_findings_attaches_the_rows_own_time(mission):
    db.add_finding(mission, _finding("f1", "one"))
    got = db.get_findings(mission)
    assert len(got) == 1
    assert got[0].get("observed_at"), "the row's created_at must reach the caller"


def test_a_finding_that_already_carries_a_time_keeps_its_own(mission):
    """A replayed or re-imported finding knows when it was actually seen. The moment this database
    happened to store it is a worse answer, so the stored value must not be overwritten."""
    f = _finding("f2", "two")
    f["observed_at"] = "1999-01-01T00:00:00Z"
    db.add_finding(mission, f)
    got = [x for x in db.get_findings(mission) if x["id"] == "f2"][0]
    assert got["observed_at"] == "1999-01-01T00:00:00Z"


# ── the report must surface it, and must not invent it ────────────────────────

def test_the_report_prints_when_a_finding_was_observed():
    f = _finding("f3", "three")
    f["observed_at"] = "2026-08-27T22:10:00Z"
    md = report.generate_report("p", [f], {"in_scope": ["example.test"]})
    assert "**Observed:** 2026-08-27T22:10:00Z" in md


def test_a_finding_with_no_stored_time_says_nothing_rather_than_guessing():
    """Silence is the honest answer for a row stored before this landed. Printing the render clock
    would be a claim about evidence this report cannot make."""
    md = report.generate_report("p", [_finding("f4", "four")], {"in_scope": ["example.test"]})
    assert "**Observed:**" not in md


def test_the_header_reports_the_span_of_the_evidence():
    """On a RUNNING report this is the only way to tell progress from a wedge."""
    a, b = _finding("f5", "five"), _finding("f6", "six")
    a["observed_at"] = "2026-08-27T20:00:00Z"
    b["observed_at"] = "2026-08-27T22:30:00Z"
    md = report.generate_report("p", [a, b], {"in_scope": ["example.test"]})
    assert "**First evidence:** 2026-08-27T20:00:00Z" in md
    assert "**Latest evidence:** 2026-08-27T22:30:00Z" in md


def test_the_span_is_silent_when_nothing_carries_a_time():
    md = report.generate_report("p", [_finding("f7", "seven")], {"in_scope": ["example.test"]})
    assert "First evidence" not in md and "Latest evidence" not in md


# ── THE CONTROL THAT MATTERS ──────────────────────────────────────────────────

def test_rendering_twice_does_not_move_the_timestamps():
    """The whole point. If these move between renders, the report is timestamping ITSELF rather than
    the evidence -- which passes every other test above while being worse than no timestamp, because
    a moving number still looks authoritative.

    `Report generated` is EXPECTED to differ between renders; it is a fact about the file. Everything
    describing the evidence must be byte-identical."""
    f = _finding("f8", "eight")
    f["observed_at"] = "2026-08-27T21:00:00Z"
    scope = {"in_scope": ["example.test"]}
    first = report.generate_report("p", [dict(f)], scope)
    second = report.generate_report("p", [dict(f)], scope)

    def evidence_lines(md):
        return [ln for ln in md.splitlines()
                if ln.startswith(("**Observed:**", "**First evidence:**", "**Latest evidence:**"))]

    assert evidence_lines(first) == evidence_lines(second), "evidence times must not track the clock"
    assert evidence_lines(first), "non-vacuity: there must BE evidence lines to compare"


def test_report_generated_is_still_present_and_is_about_the_file():
    """The render clock is still useful and still printed -- just no longer the only time in the
    document, and no longer standing in for when anything was seen."""
    md = report.generate_report("p", [_finding("f9", "nine")], {"in_scope": ["example.test"]})
    assert "**Report generated:**" in md
