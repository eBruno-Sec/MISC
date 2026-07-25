"""Assessment lifecycle state machine (§8)."""

from __future__ import annotations

import pytest

from domain.lifecycle import (
    MAIN_SEQUENCE,
    AssessmentLifecycle,
    LifecycleError,
    LifecycleState,
)


def test_full_forward_progression():
    life = AssessmentLifecycle()
    assert life.state is LifecycleState.DRAFT
    for expected in MAIN_SEQUENCE[1:]:
        assert life.advance() is expected
    assert life.state is LifecycleState.ARCHIVED
    with pytest.raises(LifecycleError):
        life.advance()


def test_target_interaction_and_execution_guards():
    # No target interaction before authorization is verified (§8.3).
    assert AssessmentLifecycle(LifecycleState.DRAFT).can_interact_with_target() is False
    assert AssessmentLifecycle(LifecycleState.AUTHORIZATION_PENDING).can_interact_with_target() is False
    assert AssessmentLifecycle(LifecycleState.AUTHORIZATION_VALIDATED).can_interact_with_target() is True
    # No execution before scope compilation (§8.3).
    assert AssessmentLifecycle(LifecycleState.AUTHORIZATION_VALIDATED).can_execute() is False
    assert AssessmentLifecycle(LifecycleState.SCOPE_COMPILED).can_execute() is True


def test_pause_resume_returns_to_prior_state():
    life = AssessmentLifecycle(LifecycleState.RECON_RUNNING)
    life.request_pause()
    assert life.state is LifecycleState.PAUSE_REQUESTED
    life.confirm_paused()
    assert life.state is LifecycleState.PAUSED
    assert life.resume() is LifecycleState.RECON_RUNNING


def test_cannot_pause_from_draft():
    with pytest.raises(LifecycleError):
        AssessmentLifecycle(LifecycleState.DRAFT).request_pause()


def test_emergency_stop_is_terminal():
    life = AssessmentLifecycle(LifecycleState.VALIDATION_RUNNING)
    life.request_emergency_stop()
    assert life.state is LifecycleState.EMERGENCY_STOP_REQUESTED
    life.confirm_emergency_stopped()
    assert life.state is LifecycleState.EMERGENCY_STOPPED
    assert life.is_terminal() is True


def test_approval_gate_round_trip():
    life = AssessmentLifecycle(LifecycleState.VALIDATION_RUNNING)
    life.require_approval()
    assert life.state is LifecycleState.APPROVAL_REQUIRED
    assert life.clear_approval() is LifecycleState.VALIDATION_RUNNING


def test_non_adjacent_transition_rejected():
    life = AssessmentLifecycle(LifecycleState.DRAFT)
    with pytest.raises(LifecycleError):
        life.transition_to(LifecycleState.SCOPE_COMPILED)
