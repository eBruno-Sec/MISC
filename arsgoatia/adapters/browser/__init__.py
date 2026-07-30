"""ArsGoatia browser adapter — headless Chromium for JS-heavy targets.

Uses Playwright under the hood. Validates envelope + scope before every navigation.
Not part of the first vertical slice (HTTP adapter covers it), but the contract
is defined so future packs can declare browser dependencies.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from adapters import (
    AdapterContract,
    AdapterMetadata,
    AdapterResult,
    EvidenceSink,
    ExecutionPlan,
    HeartbeatReport,
)


class BrowserAdapter(AdapterContract):
    def describe(self) -> AdapterMetadata:
        return AdapterMetadata(
            adapter_id="browser",
            version="0.1.0",
            description="Headless Chromium adapter for JS-rendered targets",
            supported_techniques=["web.xss.reflected", "web.xss.stored", "web.authz.ui_bypass"],
            parameter_schema={
                "type": "object",
                "properties": {
                    "headless": {"type": "boolean", "default": True},
                    "viewport_width": {"type": "integer", "default": 1280},
                    "viewport_height": {"type": "integer", "default": 720},
                    "timeout_ms": {"type": "integer", "default": 30000},
                },
            },
        )

    def preflight(self, envelope: Any, secret_leases: dict[str, str]) -> ExecutionPlan:
        raise NotImplementedError("browser adapter not yet implemented")

    def execute(
        self, plan: ExecutionPlan, cancellation: Any, evidence_sink: EvidenceSink
    ) -> AdapterResult:
        raise NotImplementedError("browser adapter not yet implemented")

    def heartbeat(
        self, progress: float, resource_use: dict[str, Any], budget_counters: dict[str, Any]
    ) -> HeartbeatReport:
        return HeartbeatReport(
            progress_pct=progress,
            requests_made=0,
            bytes_received=0,
            budget_remaining=budget_counters,
        )

    def cancel(self, grace_period: float) -> AdapterResult:
        return AdapterResult(outcome="cancelled")

    def cleanup(self, obligations: list[UUID]) -> dict[str, Any]:
        return {"cleaned": True, "obligations_resolved": len(obligations)}

    def normalize(
        self, raw_references: list[Any]
    ) -> tuple[list[dict[str, Any]], list[str], list[str]]:
        return [], [], ["browser adapter not yet implemented"]
