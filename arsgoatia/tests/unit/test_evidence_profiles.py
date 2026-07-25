"""Evidence-profile completeness (§16/§17). Deterministic; no AI."""

from __future__ import annotations

import pytest

from evidence.profiles import check_profile, required_components


def test_authorization_differential_components():
    req = required_components("authorization_differential")
    assert req == {"baseline_own", "differential", "positive_control", "negative_control"}


def test_incomplete_profile_reports_missing():
    check = check_profile("authorization_differential", {"baseline_own", "differential"})
    assert check.complete is False
    assert set(check.missing) == {"positive_control", "negative_control"}


def test_complete_profile():
    check = check_profile(
        "authorization_differential",
        {"baseline_own", "differential", "positive_control", "negative_control"},
    )
    assert check.complete is True
    assert check.missing == []


def test_unknown_profile_raises():
    with pytest.raises(KeyError):
        required_components("does_not_exist")
