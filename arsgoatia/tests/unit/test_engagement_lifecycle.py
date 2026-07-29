from __future__ import annotations

import pytest

from packages.domain.governance import (
    LIFECYCLE_TRANSITIONS,
    TERMINAL_STATES,
    EngagementLifecycle,
    LifecycleState,
)


def test_initial_state():
    lc = EngagementLifecycle()
    assert lc.state == LifecycleState.DRAFT


def test_valid_transition_draft_to_auth_pending():
    lc = EngagementLifecycle()
    lc.transition(LifecycleState.AUTHORIZATION_PENDING)
    assert lc.state == LifecycleState.AUTHORIZATION_PENDING


def test_invalid_transition_raises():
    lc = EngagementLifecycle()
    with pytest.raises(ValueError, match="invalid transition"):
        lc.transition(LifecycleState.RUNNING)


def test_terminal_states_cannot_transition():
    for state in TERMINAL_STATES:
        lc = EngagementLifecycle(state=state)
        with pytest.raises(ValueError):
            lc.transition(LifecycleState.DRAFT)


def test_advance_happy_path():
    lc = EngagementLifecycle()
    lc.advance()
    assert lc.state == LifecycleState.AUTHORIZATION_PENDING
    lc.advance()
    assert lc.state == LifecycleState.SCOPE_COMPILED


def test_pause_and_resume():
    lc = EngagementLifecycle(state=LifecycleState.RUNNING)
    lc.pause()
    assert lc.state == LifecycleState.PAUSED
    lc.resume()
    assert lc.state == LifecycleState.RUNNING


def test_emergency_stop_from_running():
    lc = EngagementLifecycle(state=LifecycleState.RUNNING)
    lc.emergency_stop()
    assert lc.state == LifecycleState.STOPPING


def test_emergency_stop_from_non_active():
    lc = EngagementLifecycle(state=LifecycleState.SCOPE_COMPILED)
    lc.emergency_stop()
    assert lc.state == LifecycleState.REVOCATION_REQUESTED


def test_all_transitions_are_documented():
    for src, dests in LIFECYCLE_TRANSITIONS.items():
        for dest in dests:
            assert isinstance(dest, LifecycleState)
            lc = EngagementLifecycle(state=src)
            lc.transition(dest)
            assert lc.state == dest


def test_request_revocation():
    lc = EngagementLifecycle(state=LifecycleState.RUNNING)
    lc.request_revocation()
    assert lc.state == LifecycleState.REVOCATION_REQUESTED


def test_is_active():
    assert EngagementLifecycle(state=LifecycleState.RUNNING).is_active
    assert EngagementLifecycle(state=LifecycleState.PAUSED).is_active
    assert not EngagementLifecycle(state=LifecycleState.DRAFT).is_active


def test_is_terminal():
    assert EngagementLifecycle(state=LifecycleState.COMPLETED).is_terminal
    assert EngagementLifecycle(state=LifecycleState.REVOKED).is_terminal
    assert not EngagementLifecycle(state=LifecycleState.RUNNING).is_terminal
