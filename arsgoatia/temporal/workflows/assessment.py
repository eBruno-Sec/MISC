"""Root AssessmentWorkflow (§10.3).

Durable orchestrator for one assessment. Holds only compact state (lifecycle,
flags, pending approvals) — never raw artifacts or secrets — so history stays
small and deterministic. All IO/AI/tool work happens in activities (added in
M2+). This M1 skeleton wires the lifecycle, the pause/resume gate, the
action-bound approval gate, and emergency stop.

Determinism note: signal handlers only mutate flags/dicts; every lifecycle
transition happens in run(), and every branch is on recorded state.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from domain.lifecycle import AssessmentLifecycle, LifecycleState

# Phases the slice drives, in order. Each is gated by pause/emergency; M2+ wires
# the child workflow / activity that does the real work behind each phase.
_SLICE_PHASES: list[LifecycleState] = [
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
]


@workflow.defn
class AssessmentWorkflow:
    def __init__(self) -> None:
        self._life = AssessmentLifecycle()
        self._paused = False
        self._emergency = False
        self._cancelled = False
        self._approvals: dict[str, bool] = {}
        self._pending_approval: str | None = None
        self._recon_summary: dict[str, Any] | None = None
        self._identities: dict[str, Any] | None = None
        self._validation_summary: dict[str, Any] | None = None

    @workflow.run
    async def run(self, params: dict[str, Any]) -> dict[str, Any]:
        require_approval = bool(params.get("require_validation_approval", True))
        run_recon = bool(params.get("run_recon", True))
        run_validation = bool(params.get("run_validation", True))
        assessment_id = params.get("assessment_id")
        tenant_id = params.get("tenant_id")
        action_id = str(params.get("validation_action_id", "idor-validation"))

        for phase in _SLICE_PHASES:
            await self._gate()
            if self._cancelled or self._emergency:
                break

            # Safe HTTP recon (R1) on the target-egress worker — never in the workflow.
            if phase is LifecycleState.RECON_RUNNING and run_recon:
                self._recon_summary = await workflow.execute_activity(
                    "safe_http_recon",
                    {"assessment_id": assessment_id, "tenant_id": tenant_id},
                    task_queue="safe-recon",
                    start_to_close_timeout=timedelta(seconds=180),
                    retry_policy=RetryPolicy(maximum_attempts=2),
                )

            # Establish the two standard-user identities the IDOR module requires.
            if phase is LifecycleState.ANALYSIS_RUNNING and run_validation:
                base_url = (self._recon_summary or {}).get("base_url") or params.get("base_url")
                self._identities = await workflow.execute_activity(
                    "establish_identities",
                    {
                        "assessment_id": assessment_id,
                        "tenant_id": tenant_id,
                        "base_url": base_url,
                        "target_asset_id": params.get("target_asset_id"),
                    },
                    task_queue="api-testing",
                    start_to_close_timeout=timedelta(seconds=120),
                    retry_policy=RetryPolicy(maximum_attempts=2),
                )

            # The validation phase runs the R2 differential behind an action-bound
            # approval (policy returns require_approval under lab-safe).
            if phase is LifecycleState.VALIDATION_RUNNING and run_validation:
                granted = True
                if require_approval:
                    granted = await self._await_approval(action_id)
                    if not granted:
                        self._life.state = LifecycleState.FAILED_RECOVERABLE
                        break
                idents = (self._identities or {}).get("identities", [])
                base_url = (self._recon_summary or {}).get("base_url") or params.get("base_url")
                self._validation_summary = await workflow.execute_activity(
                    "run_idor_validation",
                    {
                        "assessment_id": assessment_id,
                        "tenant_id": tenant_id,
                        "base_url": base_url,
                        "target_asset_id": params.get("target_asset_id"),
                        "identities": idents,
                        "assessment_revision": params.get("assessment_revision", 1),
                        "policy_revision": params.get("policy_revision", 1),
                        "action_id": action_id,
                        "approval_granted": granted,
                    },
                    task_queue="high-risk-validation",
                    start_to_close_timeout=timedelta(seconds=180),
                    retry_policy=RetryPolicy(maximum_attempts=1),
                )

            self._life.transition_to(phase)

        if self._emergency:
            self._life.confirm_emergency_stopped()
        elif self._cancelled:
            self._life.state = LifecycleState.CANCELLED

        return {
            "assessment_id": assessment_id,
            "final_state": self._life.state.value,
            "recon": self._recon_summary,
            "validation": self._validation_summary,
        }

    # -- gates ----------------------------------------------------------- #
    async def _gate(self) -> None:
        """Block while paused; the §8.3 pause primitive. Emergency/cancel break
        the wait so run() can unwind."""
        await workflow.wait_condition(
            lambda: (not self._paused) or self._emergency or self._cancelled
        )
        if self._paused and not (self._emergency or self._cancelled):
            # Reflect PAUSED in queryable state while blocked.
            pass

    async def _await_approval(self, action_id: str) -> bool:
        """Action-bound HITL gate (§13.6). Idempotent: first ProvideApproval wins."""
        self._pending_approval = action_id
        self._life.require_approval()
        await workflow.wait_condition(
            lambda: action_id in self._approvals or self._emergency or self._cancelled
        )
        self._pending_approval = None
        if action_id in self._approvals:
            self._life.clear_approval()
        return self._approvals.get(action_id, False)

    # -- signals (§10.7) ------------------------------------------------- #
    @workflow.signal
    def pause(self) -> None:
        self._paused = True

    @workflow.signal
    def resume(self) -> None:
        self._paused = False

    @workflow.signal
    def emergency_stop(self) -> None:
        self._emergency = True

    @workflow.signal
    def cancel(self) -> None:
        self._cancelled = True

    @workflow.signal
    def provide_approval(self, action_id: str, granted: bool) -> None:
        # First decision wins; duplicate signals (which arrive as their own
        # events on replay) are ignored.
        if action_id not in self._approvals:
            self._approvals[action_id] = granted

    # -- queries --------------------------------------------------------- #
    @workflow.query
    def get_state(self) -> dict[str, Any]:
        display = self._life.state.value
        if self._paused and not self._life.is_terminal():
            display = LifecycleState.PAUSED.value
        return {
            "lifecycle_state": display,
            "paused": self._paused,
            "emergency": self._emergency,
            "pending_approval": self._pending_approval,
        }
