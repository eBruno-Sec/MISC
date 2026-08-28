"""Q-107 — a running mission had no heartbeat, so three signals all read flat while it worked.

Reported by the operator mid-run. He could not tell a working mission from a wedged one, and ended
up using `docker stats` to check whether his own tool was alive. Measured over 85 minutes of a live
Shopify mission:

    Latest evidence   moved 2 minutes   derived from FINDINGS (Q-102) -- and a healthy scan may
                                        legitimately produce none for hours
    Tools Invoked     573 -> 570        the ledger was a window (Q-105), so it went BACKWARDS
    Surface Urls      flat              grows during crawl, correctly flat during probe
    Report generated  advanced          a fact about the RENDERER; advances for a hung run too

Q-102 is mine and was half a fix: I built `Latest evidence` to answer this exact question and bound
it to findings, the one thing a working scan may produce none of.

THE GATE THAT MATTERS IS `test_activity_with_zero_findings_still_advances_the_heartbeat` -- the case
all three existing signals fail. Its negative control matters just as much: a mission with no
activity must NOT advance, or the field is just another clock wearing a useful name.
"""
import db as dbmod
import pytest

import report


@pytest.fixture()
def mission(tmp_path):
    dbmod.init(str(tmp_path / "hb.db"))
    mid = "q107"
    dbmod.create_mission(mid, "P", "active", "o", {"in_scope": ["example.test"]}, {})
    return mid


# ── the case every existing signal fails ──────────────────────────────────────

def test_activity_with_zero_findings_still_advances_the_heartbeat(mission):
    """A scan probing 465 endpoints and confirming nothing is WORKING. Findings-based signals call
    that indistinguishable from a wedge; this must not."""
    before = dbmod.mission_heartbeat(mission)
    for _ in range(5):
        dbmod.add_log(mission, "tool_call", {"tool": "run_sqli"})
    after = dbmod.mission_heartbeat(mission)

    assert after["dispatches"] > before["dispatches"], (before, after)
    assert after["last_dispatch"] >= before["last_dispatch"]
    assert dbmod.get_findings(mission) == [], "the point is that there are NO findings"


def test_a_mission_with_no_activity_does_not_advance(mission):
    """The negative control, and the one that keeps this from being another clock. If it ticked
    without work it would be `Report generated` again under a better name."""
    first = dbmod.mission_heartbeat(mission)
    dbmod.add_log(mission, "finding", {"title": "t"})        # not a dispatch
    dbmod.add_log(mission, "info", {"content": "x"})         # not a dispatch
    second = dbmod.mission_heartbeat(mission)
    assert second == first, (first, second)


def test_dispatches_only_ever_rises(mission):
    """Q-105's lesson applied here before it can repeat: a heartbeat that can go BACKWARDS is worse
    than none, because it still looks authoritative."""
    seen = []
    for _ in range(6):
        for _ in range(300):
            dbmod.add_log(mission, "tool_call", {"tool": "t"})
        seen.append(dbmod.mission_heartbeat(mission)["dispatches"])
    assert seen == sorted(seen) and len(set(seen)) == len(seen), seen


def test_an_empty_mission_reports_zero_rather_than_failing(mission):
    hb = dbmod.mission_heartbeat(mission)
    assert hb == {"dispatches": 0, "last_dispatch": ""}


# ── it has to reach the operator ──────────────────────────────────────────────

def test_the_report_prints_the_heartbeat():
    finding = {"id": "h1", "title": "t", "severity": "low", "target": "https://example.test/",
               "description": "d", "engine": "e", "family": "security_misconfig"}
    md = report.generate_report("p", [finding], {"in_scope": ["example.test"]},
                                heartbeat={"last_dispatch": "2026-08-28T06:44:00Z", "dispatches": 812})
    assert "**Last activity:** 2026-08-28T06:44:00Z (812 tool dispatches)" in md


def test_the_report_is_silent_when_no_heartbeat_was_supplied():
    """A zero would read as 'nothing has run', which is a claim. Silence is the honest answer for a
    caller that did not pass one."""
    md = report.generate_report("p", [], {"in_scope": ["example.test"]})
    assert "Last activity" not in md


def test_the_heartbeat_appears_on_the_ZERO_FINDINGS_report_too():
    """The case the feature exists for. `generate_report` has a separate short path for a mission
    with no confirmed findings, and that is precisely the report an operator stares at while
    waiting. My first version added the heartbeat only to the full report, so it would have been
    missing from the one document the waiting case ever renders."""
    md = report.generate_report("p", [], {"in_scope": ["example.test"]},
                                heartbeat={"last_dispatch": "2026-08-28T06:44:00Z", "dispatches": 812})
    assert "No confirmed vulnerabilities" in md, "this must be the short path"
    assert "**Last activity:** 2026-08-28T06:44:00Z (812 tool dispatches)" in md
