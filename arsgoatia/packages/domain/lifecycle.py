"""Assessment lifecycle state machine (§8).

Pure, dependency-free logic so it is exhaustively unit-testable and safe to call
from deterministic Temporal workflow code. The AssessmentWorkflow holds an
instance and drives it; the state rules (§8.3) are enforced here, not scattered
across activities.
"""

from __future__ import annotations

import enum


class LifecycleState(str, enum.Enum):
    # Main lifecycle (§8.1), in order.
    DRAFT = "DRAFT"
    AUTHORIZATION_PENDING = "AUTHORIZATION_PENDING"
    AUTHORIZATION_VALIDATED = "AUTHORIZATION_VALIDATED"
    SCOPE_COMPILED = "SCOPE_COMPILED"
    READY = "READY"
    PRE_RECON_RUNNING = "PRE_RECON_RUNNING"
    RECON_RUNNING = "RECON_RUNNING"
    ATTACK_SURFACE_READY = "ATTACK_SURFACE_READY"
    ANALYSIS_RUNNING = "ANALYSIS_RUNNING"
    VALIDATION_RUNNING = "VALIDATION_RUNNING"
    CHAIN_EXPANSION = "CHAIN_EXPANSION"
    IMPACT_VALIDATION = "IMPACT_VALIDATION"
    REPORTING = "REPORTING"
    REVIEW = "REVIEW"
    COMPLETED = "COMPLETED"
    ARCHIVED = "ARCHIVED"
    # Exceptional states (§8.2).
    PAUSE_REQUESTED = "PAUSE_REQUESTED"
    PAUSED = "PAUSED"
    RESUME_REQUESTED = "RESUME_REQUESTED"
    CANCEL_REQUESTED = "CANCEL_REQUESTED"
    CANCELLING = "CANCELLING"
    CANCELLED = "CANCELLED"
    EMERGENCY_STOP_REQUESTED = "EMERGENCY_STOP_REQUESTED"
    EMERGENCY_STOPPED = "EMERGENCY_STOPPED"
    SCOPE_REVIEW_REQUIRED = "SCOPE_REVIEW_REQUIRED"
    POLICY_REVIEW_REQUIRED = "POLICY_REVIEW_REQUIRED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    FAILED_RECOVERABLE = "FAILED_RECOVERABLE"
    FAILED_TERMINAL = "FAILED_TERMINAL"


# The linear main-lifecycle order; index gives a rank for the §8.3 guards.
MAIN_SEQUENCE: list[LifecycleState] = [
    LifecycleState.DRAFT,
    LifecycleState.AUTHORIZATION_PENDING,
    LifecycleState.AUTHORIZATION_VALIDATED,
    LifecycleState.SCOPE_COMPILED,
    LifecycleState.READY,
    LifecycleState.PRE_RECON_RUNNING,
    LifecycleState.RECON_RUNNING,
    LifecycleState.ATTACK_SURFACE_READY,
    LifecycleState.ANALYSIS_RUNNING,
    LifecycleState.VALIDATION_RUNNING,
    LifecycleState.CHAIN_EXPANSION,
    LifecycleState.IMPACT_VALIDATION,
    LifecycleState.REPORTING,
    LifecycleState.REVIEW,
    LifecycleState.COMPLETED,
    LifecycleState.ARCHIVED,
]

_RANK = {s: i for i, s in enumerate(MAIN_SEQUENCE)}
# States from which a pause / emergency-stop may be requested (anything active).
_PAUSABLE = set(MAIN_SEQUENCE[MAIN_SEQUENCE.index(LifecycleState.READY) : -2])


class LifecycleError(RuntimeError):
    """Raised on an illegal transition or a rule violation (§8.3)."""


class AssessmentLifecycle:
    def __init__(self, state: LifecycleState = LifecycleState.DRAFT) -> None:
        self.state = state
        self._resume_to: LifecycleState | None = None

    # -- guards (§8.3) --------------------------------------------------- #
    def can_interact_with_target(self) -> bool:
        """No active target interaction before authorization is verified."""
        return self.state in _RANK and _RANK[self.state] >= _RANK[LifecycleState.AUTHORIZATION_VALIDATED]

    def can_execute(self) -> bool:
        """No execution before scope compilation."""
        return self.state in _RANK and _RANK[self.state] >= _RANK[LifecycleState.SCOPE_COMPILED]

    def is_terminal(self) -> bool:
        return self.state in {
            LifecycleState.ARCHIVED,
            LifecycleState.CANCELLED,
            LifecycleState.EMERGENCY_STOPPED,
            LifecycleState.FAILED_TERMINAL,
        }

    # -- main progression ------------------------------------------------ #
    def advance(self) -> LifecycleState:
        """Move one step along the main sequence."""
        if self.state not in _RANK:
            raise LifecycleError(f"cannot advance from exceptional state {self.state.value}")
        idx = _RANK[self.state]
        if idx >= len(MAIN_SEQUENCE) - 1:
            raise LifecycleError("already at end of lifecycle")
        self.state = MAIN_SEQUENCE[idx + 1]
        return self.state

    def transition_to(self, target: LifecycleState) -> LifecycleState:
        """Explicit forward transition to a main-sequence state (no skipping)."""
        if self.state not in _RANK or target not in _RANK:
            raise LifecycleError(f"illegal transition {self.state.value} -> {target.value}")
        if _RANK[target] != _RANK[self.state] + 1:
            raise LifecycleError(
                f"non-adjacent transition {self.state.value} -> {target.value}"
            )
        self.state = target
        return self.state

    # -- exceptional overlays -------------------------------------------- #
    def request_pause(self) -> None:
        if self.state not in _PAUSABLE:
            raise LifecycleError(f"cannot pause from {self.state.value}")
        self._resume_to = self.state
        self.state = LifecycleState.PAUSE_REQUESTED

    def confirm_paused(self) -> None:
        if self.state is not LifecycleState.PAUSE_REQUESTED:
            raise LifecycleError("pause was not requested")
        self.state = LifecycleState.PAUSED

    def resume(self) -> LifecycleState:
        if self.state not in {LifecycleState.PAUSED, LifecycleState.PAUSE_REQUESTED}:
            raise LifecycleError(f"cannot resume from {self.state.value}")
        if self._resume_to is None:
            raise LifecycleError("no state to resume to")
        self.state = self._resume_to
        self._resume_to = None
        return self.state

    def request_emergency_stop(self) -> None:
        self._resume_to = None
        self.state = LifecycleState.EMERGENCY_STOP_REQUESTED

    def confirm_emergency_stopped(self) -> None:
        if self.state is not LifecycleState.EMERGENCY_STOP_REQUESTED:
            raise LifecycleError("emergency stop was not requested")
        self.state = LifecycleState.EMERGENCY_STOPPED

    def require_approval(self) -> None:
        """High-risk actions require action-bound approval (§8.3)."""
        self._resume_to = self.state if self.state in _RANK else self._resume_to
        self.state = LifecycleState.APPROVAL_REQUIRED

    def clear_approval(self) -> LifecycleState:
        if self.state is not LifecycleState.APPROVAL_REQUIRED:
            raise LifecycleError("no approval pending")
        if self._resume_to is None:
            raise LifecycleError("no state to return to after approval")
        self.state = self._resume_to
        self._resume_to = None
        return self.state
