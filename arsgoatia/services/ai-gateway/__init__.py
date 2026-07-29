"""ArsGoatia AI gateway service wrapper.

Provides a unified interface for AI model interactions with budget
tracking, rate limiting, and model routing.  All AI calls from the
platform flow through this gateway so spend is centrally controlled.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

logger = logging.getLogger("arsgoatia.services.ai_gateway")


class GatewayStatus(Enum):
    READY = "ready"
    BUDGET_EXHAUSTED = "budget_exhausted"
    RATE_LIMITED = "rate_limited"
    DISABLED = "disabled"
    ERROR = "error"


@dataclass
class UsageRecord:
    """Tracks token usage for a single completion call."""

    record_id: UUID
    engagement_id: UUID
    model: str
    prompt_tokens: int
    completion_tokens: int
    estimated_cost_usd: float
    timestamp: datetime


@dataclass
class AIGatewayService:
    """AI gateway -- unified model access with budget enforcement.

    Wraps the configured AI provider (Anthropic, OpenAI, etc.) and
    enforces per-engagement spend budgets.  The real implementation
    will use httpx to call provider APIs; this stub tracks state only.
    """

    model: str = ""
    api_key: str = ""
    enabled: bool = False

    _total_spend_usd: float = field(default=0.0, init=False, repr=False)
    _usage_records: list[UsageRecord] = field(
        default_factory=list, init=False, repr=False
    )
    _budget_limit_usd: float = field(default=100.0, init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.model:
            self.model = os.environ.get("AI_MODEL", "anthropic/claude-sonnet-4-20250514")
        if not self.api_key:
            self.api_key = os.environ.get("AI_API_KEY", "")
        self.enabled = os.environ.get("AI_ENABLED", "false").lower() == "true"

    def complete(
        self,
        *,
        engagement_id: UUID,
        messages: list[dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> dict[str, Any]:
        """Send a completion request through the gateway.

        Parameters
        ----------
        engagement_id:
            The engagement this request is charged against.
        messages:
            Chat messages in ``[{"role": ..., "content": ...}]`` format.
        max_tokens:
            Maximum tokens for the completion.
        temperature:
            Sampling temperature.

        Returns
        -------
        dict
            A response dict containing ``content``, ``model``,
            ``usage``, and ``record_id``.

        Raises
        ------
        RuntimeError
            If the gateway is disabled or the budget is exhausted.
        """
        status = self.get_status()
        if status == GatewayStatus.DISABLED:
            raise RuntimeError("AI gateway is disabled")
        if status == GatewayStatus.BUDGET_EXHAUSTED:
            raise RuntimeError("AI budget exhausted for this engagement")

        # TODO: call actual AI provider via httpx
        logger.info(
            "AI completion request (model=%s, messages=%d, max_tokens=%d)",
            self.model,
            len(messages),
            max_tokens,
        )

        # Stub: record simulated usage
        record = UsageRecord(
            record_id=uuid4(),
            engagement_id=engagement_id,
            model=self.model,
            prompt_tokens=0,
            completion_tokens=0,
            estimated_cost_usd=0.0,
            timestamp=datetime.now(timezone.utc),
        )
        self._usage_records.append(record)

        return {
            "content": "",
            "model": self.model,
            "usage": {
                "prompt_tokens": record.prompt_tokens,
                "completion_tokens": record.completion_tokens,
            },
            "record_id": str(record.record_id),
        }

    def check_budget(self, engagement_id: UUID) -> dict[str, Any]:
        """Check remaining AI budget for an engagement.

        Returns a dict with ``remaining_usd``, ``total_spent_usd``,
        ``limit_usd``, and ``within_budget``.
        """
        engagement_spend = sum(
            r.estimated_cost_usd
            for r in self._usage_records
            if r.engagement_id == engagement_id
        )
        remaining = max(0.0, self._budget_limit_usd - engagement_spend)

        return {
            "engagement_id": str(engagement_id),
            "total_spent_usd": engagement_spend,
            "limit_usd": self._budget_limit_usd,
            "remaining_usd": remaining,
            "within_budget": remaining > 0,
        }

    def get_status(self) -> GatewayStatus:
        """Return the current gateway status."""
        if not self.enabled:
            return GatewayStatus.DISABLED
        if not self.api_key:
            return GatewayStatus.ERROR
        if self._total_spend_usd >= self._budget_limit_usd:
            return GatewayStatus.BUDGET_EXHAUSTED
        return GatewayStatus.READY

    def set_budget_limit(self, limit_usd: float) -> None:
        """Set the global AI budget limit."""
        self._budget_limit_usd = limit_usd
        logger.info("AI budget limit set to $%.2f", limit_usd)


__all__ = ["AIGatewayService", "GatewayStatus", "UsageRecord"]
