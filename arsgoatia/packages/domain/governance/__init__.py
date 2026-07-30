from __future__ import annotations

import enum


class LifecycleState(enum.Enum):
    DRAFT = "draft"
    AUTHORIZATION_PENDING = "authorization_pending"
    SCOPE_COMPILED = "scope_compiled"
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    CLEANUP_PENDING = "cleanup_pending"
    REPORTING = "reporting"
    COMPLETED = "completed"
    REVOCATION_REQUESTED = "revocation_requested"
    REVOKED = "revoked"
    FAILED = "failed"


MAIN_SEQUENCE: list[LifecycleState] = [
    LifecycleState.DRAFT,
    LifecycleState.AUTHORIZATION_PENDING,
    LifecycleState.SCOPE_COMPILED,
    LifecycleState.READY,
    LifecycleState.RUNNING,
]

ACTIVE_STATES: frozenset[LifecycleState] = frozenset(
    {
        LifecycleState.RUNNING,
        LifecycleState.PAUSED,
        LifecycleState.STOPPING,
    }
)

TERMINAL_STATES: frozenset[LifecycleState] = frozenset(
    {
        LifecycleState.COMPLETED,
        LifecycleState.REVOKED,
    }
)

NONTERMINAL_STATES: frozenset[LifecycleState] = frozenset(set(LifecycleState) - TERMINAL_STATES)

LIFECYCLE_TRANSITIONS: dict[LifecycleState, frozenset[LifecycleState]] = {
    LifecycleState.DRAFT: frozenset({LifecycleState.AUTHORIZATION_PENDING}),
    LifecycleState.AUTHORIZATION_PENDING: frozenset({LifecycleState.SCOPE_COMPILED}),
    LifecycleState.SCOPE_COMPILED: frozenset({LifecycleState.READY}),
    LifecycleState.READY: frozenset({LifecycleState.RUNNING}),
    LifecycleState.RUNNING: frozenset(
        {
            LifecycleState.PAUSED,
            LifecycleState.STOPPING,
            LifecycleState.REVOCATION_REQUESTED,
            LifecycleState.FAILED,
        }
    ),
    LifecycleState.PAUSED: frozenset(
        {
            LifecycleState.RUNNING,
            LifecycleState.STOPPING,
            LifecycleState.REVOCATION_REQUESTED,
            LifecycleState.FAILED,
        }
    ),
    LifecycleState.STOPPING: frozenset({LifecycleState.CLEANUP_PENDING}),
    LifecycleState.CLEANUP_PENDING: frozenset(
        {
            LifecycleState.REPORTING,
            LifecycleState.REVOKED,
            LifecycleState.COMPLETED,
        }
    ),
    LifecycleState.REPORTING: frozenset({LifecycleState.COMPLETED}),
    LifecycleState.COMPLETED: frozenset(),
    LifecycleState.REVOCATION_REQUESTED: frozenset({LifecycleState.CLEANUP_PENDING}),
    LifecycleState.REVOKED: frozenset(),
    LifecycleState.FAILED: frozenset({LifecycleState.CLEANUP_PENDING}),
}


class EngagementLifecycle:
    def __init__(self, state: LifecycleState = LifecycleState.DRAFT) -> None:
        self._state = state

    @property
    def state(self) -> LifecycleState:
        return self._state

    @property
    def is_active(self) -> bool:
        return self._state in ACTIVE_STATES

    @property
    def is_terminal(self) -> bool:
        return self._state in TERMINAL_STATES

    def can_transition(self, target: LifecycleState) -> bool:
        return target in LIFECYCLE_TRANSITIONS.get(self._state, frozenset())

    def transition(self, target: LifecycleState) -> None:
        if not self.can_transition(target):
            raise ValueError(f"invalid transition: {self._state.value} -> {target.value}")
        self._state = target

    def advance(self) -> None:
        if self._state in MAIN_SEQUENCE:
            idx = MAIN_SEQUENCE.index(self._state)
            if idx + 1 < len(MAIN_SEQUENCE):
                self._state = MAIN_SEQUENCE[idx + 1]
                return
        raise ValueError(f"cannot advance from {self._state.value}")

    def pause(self) -> None:
        if self._state != LifecycleState.RUNNING:
            raise ValueError(f"can only pause from RUNNING, not {self._state.value}")
        self._state = LifecycleState.PAUSED

    def resume(self) -> None:
        if self._state != LifecycleState.PAUSED:
            raise ValueError(f"can only resume from PAUSED, not {self._state.value}")
        self._state = LifecycleState.RUNNING

    def emergency_stop(self) -> None:
        if self._state in TERMINAL_STATES:
            raise ValueError(f"cannot emergency stop from terminal state {self._state.value}")
        if self._state in {LifecycleState.RUNNING, LifecycleState.PAUSED}:
            self._state = LifecycleState.STOPPING
        else:
            self._state = LifecycleState.REVOCATION_REQUESTED

    def request_revocation(self) -> None:
        if self._state in TERMINAL_STATES:
            raise ValueError("cannot revoke from terminal state")
        self._state = LifecycleState.REVOCATION_REQUESTED
