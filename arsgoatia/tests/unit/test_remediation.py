from __future__ import annotations

from packages.domain.remediation import (
    REMEDIATION_TRANSITIONS,
    RemediationState,
    can_transition,
    validate_no_force_push,
)

# ---------------------------------------------------------------------------
# Valid state transitions
# ---------------------------------------------------------------------------


def test_proposed_to_diff_ready_is_valid():
    assert can_transition(RemediationState.PROPOSED, RemediationState.DIFF_READY)


def test_diff_ready_to_diff_approved_is_valid():
    assert can_transition(RemediationState.DIFF_READY, RemediationState.DIFF_APPROVED)


def test_testing_to_tests_passed_is_valid():
    assert can_transition(RemediationState.TESTING, RemediationState.TESTS_PASSED)


def test_tests_failed_can_loop_back_to_diff_ready():
    assert can_transition(RemediationState.TESTS_FAILED, RemediationState.DIFF_READY)


def test_committed_to_pr_created_is_valid():
    assert can_transition(RemediationState.COMMITTED, RemediationState.PR_CREATED)


def test_full_happy_path_is_walkable():
    path = [
        RemediationState.PROPOSED,
        RemediationState.DIFF_READY,
        RemediationState.DIFF_APPROVED,
        RemediationState.TESTING,
        RemediationState.TESTS_PASSED,
        RemediationState.COMMIT_APPROVED,
        RemediationState.COMMITTED,
        RemediationState.PR_CREATED,
    ]
    for current, target in zip(path, path[1:]):
        assert can_transition(current, target), f"{current} -> {target} should be valid"


# ---------------------------------------------------------------------------
# Invalid state transitions
# ---------------------------------------------------------------------------


def test_proposed_cannot_skip_straight_to_committed():
    assert not can_transition(RemediationState.PROPOSED, RemediationState.COMMITTED)


def test_pr_created_is_terminal():
    for target in RemediationState:
        assert not can_transition(RemediationState.PR_CREATED, target)


def test_rejected_is_terminal():
    for target in RemediationState:
        assert not can_transition(RemediationState.REJECTED, target)


def test_expired_is_terminal():
    for target in RemediationState:
        assert not can_transition(RemediationState.EXPIRED, target)


def test_cannot_transition_backwards_from_tests_passed_to_testing():
    assert not can_transition(RemediationState.TESTS_PASSED, RemediationState.TESTING)


def test_all_transition_targets_reference_valid_states():
    for src, dests in REMEDIATION_TRANSITIONS.items():
        assert isinstance(src, RemediationState)
        for dest in dests:
            assert isinstance(dest, RemediationState)


# ---------------------------------------------------------------------------
# validate_no_force_push
# ---------------------------------------------------------------------------


def test_force_push_to_protected_branch_rejected():
    protected = {"main", "master"}
    assert validate_no_force_push("main", protected) is False
    assert validate_no_force_push("master", protected) is False


def test_force_push_to_unprotected_branch_allowed():
    protected = {"main", "master"}
    assert validate_no_force_push("feature/fix-remediation", protected) is True


def test_force_push_protected_set_empty_allows_any_branch():
    assert validate_no_force_push("main", set()) is True
