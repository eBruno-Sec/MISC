from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from packages.domain.execution import (
    ACTION_TRANSITIONS,
    ActionState,
    RunnerLease,
    ToolOutcome,
    can_transition_action,
    is_lease_valid,
    requires_cleanup,
)


def test_proposed_to_dispatched():
    assert can_transition_action(ActionState.PROPOSED, ActionState.DISPATCHED)


def test_proposed_to_rejected():
    assert can_transition_action(ActionState.PROPOSED, ActionState.REJECTED)


def test_running_terminal_states():
    for target in (ActionState.SUCCEEDED, ActionState.FAILED, ActionState.TIMED_OUT, ActionState.CANCELLED):
        assert can_transition_action(ActionState.RUNNING, target)


def test_terminal_states_stuck():
    assert not can_transition_action(ActionState.REJECTED, ActionState.PROPOSED)
    assert not can_transition_action(ActionState.CLEANUP_VERIFIED, ActionState.RUNNING)


def test_all_transitions_valid():
    for src, dests in ACTION_TRANSITIONS.items():
        for dest in dests:
            assert isinstance(dest, ActionState)
            assert can_transition_action(src, dest)


def test_lease_valid():
    now = datetime.now(timezone.utc)
    lease = RunnerLease(
        lease_id=uuid4(),
        runner_id="runner-1",
        action_id=uuid4(),
        pool_id="web-active",
        claimed_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    assert is_lease_valid(lease, now)


def test_lease_expired():
    now = datetime.now(timezone.utc)
    lease = RunnerLease(
        lease_id=uuid4(),
        runner_id="runner-1",
        action_id=uuid4(),
        pool_id="web-active",
        claimed_at=now - timedelta(minutes=10),
        expires_at=now - timedelta(minutes=5),
    )
    assert not is_lease_valid(lease, now)


def test_lease_revoked():
    now = datetime.now(timezone.utc)
    lease = RunnerLease(
        lease_id=uuid4(),
        runner_id="runner-1",
        action_id=uuid4(),
        pool_id="web-active",
        claimed_at=now,
        expires_at=now + timedelta(minutes=5),
        revoked=True,
    )
    assert not is_lease_valid(lease, now)


def test_requires_cleanup_mutation():
    assert requires_cleanup(ActionState.SUCCEEDED, "reversible")
    assert requires_cleanup(ActionState.FAILED, "state_changing")


def test_no_cleanup_for_none_mutation():
    assert not requires_cleanup(ActionState.SUCCEEDED, "none")
    assert not requires_cleanup(ActionState.RUNNING, "none")


def test_tool_outcome_values():
    assert ToolOutcome.SUCCEEDED.value == "succeeded"
    assert ToolOutcome.BLOCKED_BY_POLICY.value == "blocked_by_policy"
