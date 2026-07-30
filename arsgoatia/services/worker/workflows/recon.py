from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from services.worker.activities.recon import (
        DiscoveredEndpoint,
        ReconParams,
        ScopeRuleParam,
        safe_http_recon,
    )
    from services.worker.queues import WEB_QUEUE


@dataclass
class ReconWorkflowInput:
    target_url: str
    scope_rules: list[ScopeRuleParam]
    engagement_id: str
    tenant_id: str


@dataclass
class ReconWorkflowResult:
    discovered_endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    assets: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)


@workflow.defn
class ReconWorkflow:
    @workflow.run
    async def run(self, input: ReconWorkflowInput) -> ReconWorkflowResult:
        result = await workflow.execute_activity(
            safe_http_recon,
            ReconParams(
                target_url=input.target_url,
                scope_rules=input.scope_rules,
                engagement_id=input.engagement_id,
                tenant_id=input.tenant_id,
            ),
            start_to_close_timeout=timedelta(minutes=5),
            heartbeat_timeout=timedelta(seconds=30),
            retry_policy=workflow.RetryPolicy(
                initial_interval=timedelta(seconds=1),
                maximum_interval=timedelta(seconds=30),
                maximum_attempts=3,
                non_retryable_error_types=["ScopeViolationError"],
            ),
            task_queue=WEB_QUEUE,
        )

        return ReconWorkflowResult(
            discovered_endpoints=result.discovered_endpoints,
            assets=result.assets,
            evidence_refs=result.evidence_refs,
        )
