from __future__ import annotations

from packages.domain.findings import (
    EVIDENCE_PROFILES,
    FINDING_TRANSITIONS,
    FindingState,
    can_confirm,
    can_transition,
    check_evidence_profile,
)


def test_valid_transitions():
    assert can_transition(FindingState.CANDIDATE, FindingState.CONFIRMED)
    assert can_transition(FindingState.CONFIRMED, FindingState.REMEDIATION_PLANNED)
    assert can_transition(FindingState.REMEDIATED, FindingState.RETEST_PENDING)


def test_invalid_transitions():
    assert not can_transition(FindingState.CANDIDATE, FindingState.CLOSED)
    assert not can_transition(FindingState.CLOSED, FindingState.CANDIDATE)


def test_bola_evidence_profile_exists():
    assert "web.authz.bola.differential" in EVIDENCE_PROFILES


def test_evidence_profile_check_empty():
    result = check_evidence_profile("web.authz.bola.differential", set(), set())
    assert not result.satisfied
    assert len(result.missing_exchanges) > 0


def test_evidence_profile_check_satisfied():
    profile = EVIDENCE_PROFILES["web.authz.bola.differential"]
    exchanges = set(profile["required_exchanges"])
    fields = set(profile["required_fields"])
    result = check_evidence_profile("web.authz.bola.differential", exchanges, fields)
    assert result.satisfied


def test_can_confirm_from_candidate():
    assert can_confirm(
        FindingState.CANDIDATE, evidence_profile_satisfied=True, validator_passed=True
    )


def test_cannot_confirm_without_evidence():
    assert not can_confirm(
        FindingState.CANDIDATE, evidence_profile_satisfied=False, validator_passed=True
    )


def test_cannot_confirm_from_wrong_state():
    assert not can_confirm(
        FindingState.CONFIRMED, evidence_profile_satisfied=True, validator_passed=True
    )


def test_all_transitions_map_valid_states():
    for src, dests in FINDING_TRANSITIONS.items():
        assert isinstance(src, FindingState)
        for d in dests:
            assert isinstance(d, FindingState)


def test_unknown_profile():
    result = check_evidence_profile("nonexistent.profile", set(), set())
    assert not result.satisfied
