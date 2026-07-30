from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from services.worker.activities.broad_web_audit import (
        BroadWebAuditParams,
        run_broad_web_audit,
    )
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
    from services.worker.activities.juice_shop import (
        JuiceShopBOLAParams,
        run_juice_shop_basket_idor,
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
    from services.worker.queues import CONTROL_QUEUE, WEB_QUEUE
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


def _severity_num(sev: str) -> float:
    return {
        "critical": 9.5,
        "high": 7.5,
        "medium": 5.0,
        "low": 3.0,
        "info": 1.0,
    }.get(sev.lower(), 0.0)


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
    report_contract_version: int = 0


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
            task_queue=CONTROL_QUEUE,
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
        self._update(progress=30)

        # Phase 4b: Broad web audit — passive headers + active SQLi/XSS/LFI
        # against every discovered parameterised endpoint. Results are
        # deterministic; one CONFIRMED finding per pack per (endpoint, param).
        if recon_result.discovered_endpoints and not self._check_stop():
            self._update(phase="broad_web_audit", progress=32)
            await self._gate()
            audit_result = await workflow.execute_activity(
                run_broad_web_audit,
                BroadWebAuditParams(
                    engagement_id=input.engagement_id,
                    tenant_id=input.tenant_id,
                    action_id=str(workflow.uuid4()),
                    endpoints=[
                        {"url": ep.url, "content_type": ep.content_type}
                        for ep in recon_result.discovered_endpoints
                    ],
                    token="",
                ),
                start_to_close_timeout=timedelta(minutes=8),
                retry_policy=ACTIVITY_RETRY,
                task_queue=WEB_QUEUE,
            )
            self._all_evidence_refs.extend(audit_result.evidence_refs)
            self._state.evidence_count = len(self._all_evidence_refs)
            for f in audit_result.findings:
                finding_id = str(workflow.uuid4())
                self._findings.append(
                    FindingParam(
                        finding_id=finding_id,
                        weakness=f.weakness,
                        affected_object=f.target,
                        status=f.status,
                        confidence=1.0,
                        severity=_severity_num(f.severity),
                        evidence_refs=f.evidence_refs,
                    )
                )
            self._state.findings_count = len(self._findings)

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
            task_queue=CONTROL_QUEUE,
        )
        self._cleanup_needed = True
        self._update(progress=50)

        # Phase 5b: Juice Shop-specific technique pack (best-effort; only meaningful
        # when the target actually is Juice Shop). Produces a CONFIRMED finding if
        # cross-user basket read succeeds.
        if "juice-shop" in input.target_url and len(identity_result.access_contexts) >= 2:
            self._update(phase="juice_shop_probe", progress=52)
            await self._gate()
            if not self._check_stop():
                ida = identity_result.access_contexts[0]
                idb = identity_result.access_contexts[1]
                # credential_ref may be a real token or a "secret://..." fallback;
                # the pack degrades to INCONCLUSIVE if tokens are missing.
                token_a = "" if ida.credential_ref.startswith("secret://") else ida.credential_ref
                token_b = "" if idb.credential_ref.startswith("secret://") else idb.credential_ref
                id_a = getattr(ida, "object_id", None)
                id_b = getattr(idb, "object_id", None)
                js_result = await workflow.execute_activity(
                    run_juice_shop_basket_idor,
                    JuiceShopBOLAParams(
                        engagement_id=input.engagement_id,
                        tenant_id=input.tenant_id,
                        action_id=str(workflow.uuid4()),
                        target_url=input.target_url,
                        identity_a={
                            "persona": ida.persona,
                            "token": token_a,
                            "object_id": id_a,
                        },
                        identity_b={
                            "persona": idb.persona,
                            "token": token_b,
                            "object_id": id_b,
                        },
                    ),
                    start_to_close_timeout=timedelta(minutes=3),
                    retry_policy=ACTIVITY_RETRY,
                    task_queue=WEB_QUEUE,
                )
                self._all_evidence_refs.extend(js_result.evidence_refs)
                self._state.evidence_count = len(self._all_evidence_refs)
                if js_result.finding_status == "CONFIRMED":
                    finding_id = str(workflow.uuid4())
                    self._findings.append(
                        FindingParam(
                            finding_id=finding_id,
                            weakness="BOLA (Juice Shop basket IDOR)",
                            affected_object=f"{input.target_url}/rest/basket/{{id}}",
                            status="CONFIRMED",
                            confidence=1.0,
                            severity=8.5,
                            evidence_refs=js_result.evidence_refs,
                        )
                    )
                    self._state.findings_count = len(self._findings)

        # Phase 6: Validation (with approval gate for R2+)
        self._update(phase="validation", progress=55)
        await self._gate()
        if self._check_stop():
            return await self._finalize(input, aborted=True)

        action_id = str(workflow.uuid4())
        requires_approval = any(tier in input.approval_required_tiers for tier in ["R2"])

        if requires_approval:
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
                    task_queue=CONTROL_QUEUE,
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
                    task_queue=CONTROL_QUEUE,
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
            task_queue=WEB_QUEUE,
        )
        self._update(progress=90)

        # Safe workflow evolution (§14.5): the reporting contract gained
        # additional fields after the initial cut. workflow.patched() records
        # the patch decision in history so replays of pre-evolution histories
        # deterministically resolve to version 0, while new runs resolve to 1.
        report_contract_version = (
            1 if workflow.patched("reporting-contract-version") else 0
        )

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
            report_contract_version=report_contract_version,
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
            task_queue=CONTROL_QUEUE,
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
