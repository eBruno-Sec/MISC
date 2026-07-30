from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from services.worker.activities.chain import ChainParams, create_chain_step
    from services.worker.activities.cleanup import (
        CleanupObligation,
        CleanupParams,
        CleanupResult,
        run_cleanup,
    )
    from services.worker.activities.identity import (
        IdentityParams,
        establish_identities,
    )
    from services.worker.activities.recon import (
        ScopeRuleParam,
    )
    from services.worker.activities.reporting import (
        FindingParam,
        ReportParams,
        generate_reports,
    )
    from services.worker.activities.validation import (
        AccessContextParam,
        ActionEnvelopeParam,
    )
    from services.worker.workflows.recon import ReconWorkflow, ReconWorkflowInput
    from services.worker.workflows.validation import (
        ValidationWorkflow,
        ValidationWorkflowInput,
        ValidationWorkflowResult,
    )

ACTIVITY_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    maximum_interval=timedelta(seconds=30),
    maximum_attempts=3,
)


@dataclass
class EngagementInput:
    engagement_id: str
    tenant_id: str
    target_url: str
    scope_rules: list[ScopeRuleParam]
    identity_count: int = 2
    approval_required_tiers: list[str] = field(default_factory=lambda: ["R2", "R3", "R4", "R5"])
    cleanup_obligations: list[CleanupObligation] = field(default_factory=list)


@dataclass
class EngagementState:
    lifecycle: str = "DRAFT"
    phase: str = ""
    progress_pct: int = 0
    findings_count: int = 0
    evidence_count: int = 0
    error: str = ""


@dataclass
class EngagementResult:
    final_state: str = ""
    findings_count: int = 0
    report_ids: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    cleanup_verified: bool = False


@workflow.defn
class EngagementWorkflow:
    def __init__(self) -> None:
        self._state = EngagementState()
        self._paused: bool = False
        self._emergency_stop: bool = False
        self._cancelled: bool = False
        self._pending_approvals: dict[str, str] = {}
        self._child_handles: list[workflow.ChildWorkflowHandle] = []
        self._findings: list[FindingParam] = []
        self._all_evidence_refs: list[str] = []
        self._cleanup_needed: bool = False

    # -- Signals --

    @workflow.signal
    async def pause_engagement(self) -> None:
        self._paused = True
        self._state.lifecycle = "PAUSED"

    @workflow.signal
    async def resume_engagement(self) -> None:
        self._paused = False
        if self._state.lifecycle == "PAUSED":
            self._state.lifecycle = "RUNNING"

    @workflow.signal
    async def emergency_stop(self) -> None:
        self._emergency_stop = True
        self._state.lifecycle = "STOPPING"
        for handle in self._child_handles:
            handle.cancel()
        self._cleanup_needed = True

    @workflow.signal
    async def cancel_engagement(self) -> None:
        self._cancelled = True
        self._state.lifecycle = "STOPPING"
        for handle in self._child_handles:
            handle.cancel()

    @workflow.signal
    async def provide_approval(self, action_id: str, approval_ref: str) -> None:
        self._pending_approvals[action_id] = approval_ref

    # -- Queries --

    @workflow.query
    def get_state(self) -> EngagementState:
        return self._state

    # -- Helpers --

    async def _gate(self) -> None:
        await workflow.wait_condition(lambda: not self._paused and not self._emergency_stop)

    async def _await_approval(self, action_id: str) -> str:
        await workflow.wait_condition(lambda: action_id in self._pending_approvals)
        return self._pending_approvals[action_id]

    def _update(
        self,
        lifecycle: str | None = None,
        phase: str | None = None,
        progress: int | None = None,
    ) -> None:
        if lifecycle:
            self._state.lifecycle = lifecycle
        if phase is not None:
            self._state.phase = phase
        if progress is not None:
            self._state.progress_pct = progress

    def _check_stop(self) -> bool:
        return self._emergency_stop or self._cancelled

    # -- Main orchestration --

    @workflow.run
    async def run(self, input: EngagementInput) -> EngagementResult:
        wf_id_suffix = workflow.uuid4()

        try:
            return await self._execute(input, str(wf_id_suffix))
        except Exception as exc:
            self._state.lifecycle = "FAILED"
            self._state.error = str(exc)
            if self._cleanup_needed:
                await self._run_cleanup_phase(input)
            raise

    async def _execute(self, input: EngagementInput, wf_id_suffix: str) -> EngagementResult:
        # Phase 1: Authorization
        self._update(lifecycle="AUTHORIZATION_PENDING", phase="authorization", progress=5)
        await self._gate()
        if self._check_stop():
            return await self._finalize(input, aborted=True)

        # Phase 2: Compile scope
        self._update(lifecycle="SCOPE_COMPILED", phase="scope_compilation", progress=10)
        await self._gate()
        if self._check_stop():
            return await self._finalize(input, aborted=True)

        # Phase 3: Ready
        self._update(lifecycle="READY", phase="ready", progress=15)
        await self._gate()
        if self._check_stop():
            return await self._finalize(input, aborted=True)

        # Phase 4: Running - Recon
        self._update(lifecycle="RUNNING", phase="recon", progress=20)
        await self._gate()
        if self._check_stop():
            return await self._finalize(input, aborted=True)

        recon_handle = await workflow.start_child_workflow(
            ReconWorkflow.run,
            ReconWorkflowInput(
                target_url=input.target_url,
                scope_rules=input.scope_rules,
                engagement_id=input.engagement_id,
                tenant_id=input.tenant_id,
            ),
            id=f"recon-{input.engagement_id}-{wf_id_suffix}",
            task_queue="arsgoatia-execution",
        )
        self._child_handles.append(recon_handle)

        try:
            recon_result = await recon_handle
        except workflow.ChildWorkflowError:
            if self._check_stop():
                return await self._finalize(input, aborted=True)
            raise

        self._all_evidence_refs.extend(recon_result.evidence_refs)
        self._state.evidence_count = len(self._all_evidence_refs)
        self._update(progress=35)

        # Phase 5: Establish identities
        self._update(phase="identity_establishment", progress=40)
        await self._gate()
        if self._check_stop():
            return await self._finalize(input, aborted=True)

        identity_result = await workflow.execute_activity(
            establish_identities,
            IdentityParams(
                target_url=input.target_url,
                engagement_id=input.engagement_id,
                tenant_id=input.tenant_id,
                identity_count=input.identity_count,
            ),
            start_to_close_timeout=timedelta(minutes=5),
            heartbeat_timeout=timedelta(seconds=30),
            retry_policy=ACTIVITY_RETRY,
            task_queue="arsgoatia-execution",
        )
        self._cleanup_needed = True
        self._update(progress=50)

        # Phase 6: Validation (with approval gate for R2+)
        self._update(phase="validation", progress=55)
        await self._gate()
        if self._check_stop():
            return await self._finalize(input, aborted=True)

        action_id = str(workflow.uuid4())
        requires_approval = any(tier in input.approval_required_tiers for tier in ["R2"])

        if requires_approval:
            # Block on the action-bound approval gate (HITL). The signal's
            # arrival is the gate; the ref itself is bound into the envelope
            # by the executor, not here.
            await self._await_approval(action_id)

        access_ctxs = [
            AccessContextParam(
                persona=ctx.persona,
                credential_ref=ctx.credential_ref,
            )
            for ctx in identity_result.access_contexts
        ]

        if recon_result.discovered_endpoints:
            for ep in recon_result.discovered_endpoints:
                if self._check_stop():
                    break

                validation_handle = await workflow.start_child_workflow(
                    ValidationWorkflow.run,
                    ValidationWorkflowInput(
                        target_endpoint=ep.url,
                        access_contexts=access_ctxs,
                        engagement_id=input.engagement_id,
                        tenant_id=input.tenant_id,
                        action_id=action_id,
                        envelope=ActionEnvelopeParam(
                            action_id=action_id,
                            action_digest="",
                            technique="bola-differential",
                            effective_risk_tier="R2",
                            idempotency_key=f"bola-{input.engagement_id}-{ep.url}",
                        ),
                        requires_approval=False,
                    ),
                    id=f"validation-{input.engagement_id}-{str(workflow.uuid4())[:8]}",
                    task_queue="arsgoatia-execution",
                )
                self._child_handles.append(validation_handle)

                try:
                    val_result: ValidationWorkflowResult = await validation_handle
                except workflow.ChildWorkflowError:
                    if self._check_stop():
                        break
                    continue

                self._all_evidence_refs.extend(val_result.evidence_refs)
                self._state.evidence_count = len(self._all_evidence_refs)

                if val_result.finding_status == "CONFIRMED":
                    finding_id = str(workflow.uuid4())
                    self._findings.append(
                        FindingParam(
                            finding_id=finding_id,
                            weakness="BOLA",
                            affected_object=ep.url,
                            status="CONFIRMED",
                            confidence=1.0,
                            severity=7.5,
                            evidence_refs=val_result.evidence_refs,
                        )
                    )
                    self._state.findings_count = len(self._findings)

        self._update(progress=70)

        # Phase 7: Create chain / capabilities
        if self._findings and not self._check_stop():
            self._update(phase="chain_construction", progress=75)
            await self._gate()

            for finding in self._findings:
                capability_id = str(workflow.uuid4())
                await workflow.execute_activity(
                    create_chain_step,
                    ChainParams(
                        engagement_id=input.engagement_id,
                        tenant_id=input.tenant_id,
                        finding_id=finding.finding_id,
                        capability_id=capability_id,
                        technique="bola-differential",
                        preconditions=["authenticated_user"],
                        postconditions=["unauthorized_data_access"],
                        evidence_refs=finding.evidence_refs,
                    ),
                    start_to_close_timeout=timedelta(minutes=2),
                    retry_policy=ACTIVITY_RETRY,
                    task_queue="arsgoatia-execution",
                )

        self._update(progress=80)

        # Phase 8: Reporting
        self._update(lifecycle="REPORTING", phase="reporting", progress=85)
        await self._gate()
        if self._check_stop():
            return await self._finalize(input, aborted=True)

        report_result = await workflow.execute_activity(
            generate_reports,
            ReportParams(
                engagement_id=input.engagement_id,
                tenant_id=input.tenant_id,
                findings=self._findings,
                evidence_refs=self._all_evidence_refs,
            ),
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=ACTIVITY_RETRY,
            task_queue="arsgoatia-execution",
        )
        self._update(progress=90)

        # Phase 9: Cleanup
        cleanup_result = await self._run_cleanup_phase(input)
        self._update(progress=95)

        # Done
        self._update(lifecycle="COMPLETED", phase="completed", progress=100)
        return EngagementResult(
            final_state="COMPLETED",
            findings_count=len(self._findings),
            report_ids=[
                report_result.html_report_id,
                report_result.json_report_id,
                report_result.sarif_report_id,
            ],
            evidence_refs=self._all_evidence_refs,
            cleanup_verified=cleanup_result.all_verified if cleanup_result else True,
        )

    async def _run_cleanup_phase(self, input: EngagementInput) -> CleanupResult | None:
        if not self._cleanup_needed:
            return None

        self._update(
            lifecycle="CLEANUP_PENDING", phase="cleanup", progress=self._state.progress_pct
        )

        obligations = input.cleanup_obligations or []
        if not obligations:
            return CleanupResult(outcomes=[], all_verified=True)

        return await workflow.execute_activity(
            run_cleanup,
            CleanupParams(
                engagement_id=input.engagement_id,
                tenant_id=input.tenant_id,
                obligations=obligations,
            ),
            start_to_close_timeout=timedelta(minutes=10),
            heartbeat_timeout=timedelta(seconds=60),
            retry_policy=ACTIVITY_RETRY,
            task_queue="arsgoatia-execution",
        )

    async def _finalize(self, input: EngagementInput, *, aborted: bool = False) -> EngagementResult:
        cleanup_result: CleanupResult | None = None
        if self._cleanup_needed:
            cleanup_result = await self._run_cleanup_phase(input)

        final = "COMPLETED" if not aborted else "FAILED"
        if self._emergency_stop:
            final = "FAILED"
        self._update(lifecycle=final, phase="finalized", progress=100)

        return EngagementResult(
            final_state=final,
            findings_count=len(self._findings),
            report_ids=[],
            evidence_refs=self._all_evidence_refs,
            cleanup_verified=cleanup_result.all_verified if cleanup_result else True,
        )
