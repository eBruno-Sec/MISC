from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from services.worker.activities.validation import (
        AccessContextParam,
        ActionEnvelopeParam,
        BOLAParams,
        run_bola_validation,
    )


@dataclass
class ValidationWorkflowInput:
    target_endpoint: str
    access_contexts: list[AccessContextParam]
    engagement_id: str
    tenant_id: str
    action_id: str
    envelope: ActionEnvelopeParam
    requires_approval: bool = False


@dataclass
class ValidationWorkflowResult:
    finding_status: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    capability_produced: bool = False
    approved: bool = False


@workflow.defn
class ValidationWorkflow:
    def __init__(self) -> None:
        self._approval_granted: bool = False
        self._approval_ref: str = ""

    @workflow.signal
    async def provide_approval(self, action_id: str, approval_ref: str) -> None:
        self._approval_granted = True
        self._approval_ref = approval_ref

    @workflow.run
    async def run(self, input: ValidationWorkflowInput) -> ValidationWorkflowResult:
        if input.requires_approval:
            await workflow.wait_condition(lambda: self._approval_granted)

        result = await workflow.execute_activity(
            run_bola_validation,
            BOLAParams(
                target_endpoint=input.target_endpoint,
                access_contexts=input.access_contexts,
                engagement_id=input.engagement_id,
                tenant_id=input.tenant_id,
                action_id=input.action_id,
                envelope=input.envelope,
            ),
            start_to_close_timeout=timedelta(minutes=10),
            heartbeat_timeout=timedelta(seconds=60),
            retry_policy=workflow.RetryPolicy(
                initial_interval=timedelta(seconds=2),
                maximum_interval=timedelta(seconds=60),
                maximum_attempts=3,
                non_retryable_error_types=[
                    "ScopeViolationError",
                    "ApprovalRequiredError",
                ],
            ),
        )

        return ValidationWorkflowResult(
            finding_status=result.finding_status,
            evidence_refs=result.evidence_refs,
            capability_produced=result.capability_produced,
            approved=self._approval_granted,
        )
