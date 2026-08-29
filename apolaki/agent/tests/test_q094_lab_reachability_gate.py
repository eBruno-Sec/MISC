"""Q-094 -- the documented test command omits `--network`, and 10 tests answer by SKIPPING.

MEASURED by the I-11 lane, same tree, same commit, only the docker flag differs:

    without --network apolaki_default:   2 failed, 3526 passed, 19 skipped
    with    --network apolaki_default:   0 failed, 3536 passed, 11 skipped

A networkless run does not merely fail more, it TESTS LESS -- ten real assertions silently convert
to skips, and the SKIPPED total prints as a number nobody diffs. `conftest.py`'s
`_q094_lab_reachability_gate` session fixture turns that specific skip shape into a hard failure.

This file tests the PURE predicate directly (`conftest._report_is_lab_unreachable`), not the session
fixture itself: mutating the real, shared `_lab_unreachable_nodeids` list from inside a test would
poison this very session's own end-of-run gate. The predicate is the part that can regress silently
(a wording change in the skip message, or the gate widening to catch a skip it should not), so it is
the part with a positive AND a negative control.
"""
from __future__ import annotations

import conftest as CT


class _FakeReport:
    def __init__(self, skipped: bool, longrepr):
        self.skipped = skipped
        self.longrepr = longrepr


def test_a_dns_connection_failure_skip_trips_the_gate():
    """POSITIVE CONTROL: the exact wording all three real call sites use."""
    r = _FakeReport(True, ("tests/test_truthful_metadata.py", 56,
                            "Skipped: juice-shop lab unreachable "
                            "([Errno -2] Name or service not known); no measurement, not a pass"))
    assert CT._report_is_lab_unreachable(r) is True


def test_a_content_gap_skip_does_not_trip_the_gate():
    """NEGATIVE CONTROL, the one that matters most: the lab ANSWERED, this fixture just is not
    there. Tripping on this shape too is the guard-that-cannot-fail trap -- it would fire on every
    run, networked or not, and the operator would learn to ignore it exactly like the skip count
    itself was being ignored before this ticket."""
    r = _FakeReport(True, ("tests/test_truthful_metadata.py", 58,
                            "Skipped: juice-shop served HTTP 404 for /assets/x.jpg; no measurement"))
    assert CT._report_is_lab_unreachable(r) is False


def test_an_unrelated_skip_does_not_trip_the_gate():
    """NEGATIVE CONTROL: a skip for a missing local tool (exiftool, Chromium) is legitimate on any
    machine, network or not, and must never be conflated with the lab being unreachable."""
    r = _FakeReport(True, ("tests/test_css_injection.py", 121,
                            "Skipped: Chromium is required for the real CSSOM fixture"))
    assert CT._report_is_lab_unreachable(r) is False


def test_a_passing_report_never_trips_the_gate_even_if_the_text_would_match():
    """NEGATIVE CONTROL on the guard itself: `skipped` must be checked, not just the text -- a
    report that is not a skip (a pass, a fail with 'lab unreachable' in an unrelated assertion
    message) must never be counted."""
    r = _FakeReport(False, "lab unreachable (this is not actually a skip report)")
    assert CT._report_is_lab_unreachable(r) is False


def test_a_report_with_no_longrepr_does_not_crash():
    """Some skip reports carry longrepr=None or an object with no meaningful str(); the predicate
    must degrade to False, never raise."""
    r = _FakeReport(True, None)
    assert CT._report_is_lab_unreachable(r) is False
