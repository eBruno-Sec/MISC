"""The capability matrix is machine-readable, self-validating, and never merges its six states —
so 'green unit tests' can never be reported as 'live-proven through the real product path'."""
from __future__ import annotations

import capability_matrix as cm


def test_matrix_validates_clean():
    assert cm.validate() == []


def test_every_capability_has_exactly_one_valid_state_and_evidence():
    for c in cm.CAPABILITIES:
        assert c["state"] in cm.STATES, c["name"]
        assert str(c.get("evidence") or "").strip(), c["name"]


def test_states_are_never_merged():
    # the six states are distinct buckets; every capability lands in exactly one
    m = cm.matrix()
    assert set(m["by_state"]) == set(cm.STATES)
    assert sum(m["counts"].values()) == m["total"] == len(cm.CAPABILITIES)


def test_live_proven_requires_a_named_lab():
    for c in cm.CAPABILITIES:
        if c["state"] == "live_proven":
            assert c["labs"], c["name"]


def test_unfinished_and_blocked_are_reported_not_hidden():
    m = cm.matrix()
    # honesty: the matrix must still surface work that is NOT done (never silently 'complete')
    assert m["counts"]["unfinished"] >= 1
    assert m["counts"]["blocked"] >= 1
