"""Temporal client factory + workflow-launch helpers for the API."""
from __future__ import annotations

import os
from dataclasses import asdict
from typing import Any

from temporalio.client import Client

_client: Client | None = None


def _address() -> str:
    return (
        os.environ.get("ARSGOATIA_TEMPORAL_ADDRESS")
        or os.environ.get("TEMPORAL_ADDRESS")
        or os.environ.get("TEMPORAL_HOST")
        or "temporal:7233"
    )


def _namespace() -> str:
    return os.environ.get("ARSGOATIA_TEMPORAL_NAMESPACE", "default")


async def get_client() -> Client:
    global _client
    if _client is None:
        _client = await Client.connect(_address(), namespace=_namespace())
    return _client


CONTROL_QUEUE = "arsgoatia-control"


async def start_engagement_workflow(
    *,
    engagement_id: str,
    tenant_id: str,
    target_url: str,
    scope_rules: list[dict[str, str]],
    identity_count: int = 2,
) -> tuple[str, str]:
    """Kick the EngagementWorkflow. Returns (workflow_id, run_id)."""
    from services.worker.activities.recon import ScopeRuleParam  # noqa: PLC0415
    from services.worker.workflows.engagement import (  # noqa: PLC0415
        EngagementInput,
        EngagementWorkflow,
    )

    client = await get_client()
    workflow_id = f"eng-{engagement_id}"
    handle = await client.start_workflow(
        EngagementWorkflow.run,
        EngagementInput(
            engagement_id=engagement_id,
            tenant_id=tenant_id,
            target_url=target_url,
            scope_rules=[ScopeRuleParam(**r) for r in scope_rules],
            identity_count=identity_count,
            approval_required_tiers=[],  # UI-driven approval only kicks in for R3+ in this MVP
            cleanup_obligations=[],
        ),
        id=workflow_id,
        task_queue=CONTROL_QUEUE,
    )
    return workflow_id, handle.first_execution_run_id or ""


async def signal_engagement(engagement_id: str, signal_name: str, *args: Any) -> None:
    client = await get_client()
    handle = client.get_workflow_handle(f"eng-{engagement_id}")
    await handle.signal(signal_name, *args)


async def query_engagement_state(engagement_id: str) -> dict[str, Any] | None:
    client = await get_client()
    handle = client.get_workflow_handle(f"eng-{engagement_id}")
    try:
        state = await handle.query("get_state")
    except Exception:
        return None
    if hasattr(state, "__dataclass_fields__"):
        return asdict(state)
    return dict(state) if isinstance(state, dict) else None
