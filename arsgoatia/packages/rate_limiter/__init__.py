"""ArsGoatia rate limiter — token bucket + budget ledger for execution pacing.

Per spec §9.6:
  - Each engagement has a request budget, cost budget (USD), and concurrency limit.
  - Actions consume tokens from the bucket; over-budget actions are denied.
  - The bucket refills at a configured rate (requests/second).
  - Burst capacity is capped at `capacity` tokens.
  - Emergency stop zeroes out all remaining budget immediately.
  - All state is append-only: consumption records form the audit trail.
"""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4


class BudgetDenialReason(enum.Enum):
    REQUESTS_EXCEEDED = "requests_exceeded"
    COST_EXCEEDED = "cost_exceeded"
    CONCURRENCY_EXCEEDED = "concurrency_exceeded"
    EMERGENCY_STOP = "emergency_stop"
    RATE_EXCEEDED = "rate_exceeded"


@dataclass(frozen=True)
class BudgetSpec:
    max_requests: int = 50_000
    max_cost_usd: float = 25.0
    max_concurrent: int = 10
    requests_per_second: float = 10.0
    burst_capacity: int = 50


@dataclass(frozen=True)
class ConsumptionRecord:
    record_id: UUID
    tenant_id: UUID
    engagement_id: UUID
    action_id: UUID
    requests_consumed: int
    cost_usd: float
    recorded_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class BudgetCheckResult:
    allowed: bool
    denial_reason: BudgetDenialReason | None = None
    remaining_requests: int = 0
    remaining_cost_usd: float = 0.0
    remaining_concurrent: int = 0


class TokenBucket:
    """Thread-safe leaky token bucket for request-rate enforcement."""

    def __init__(self, capacity: int, refill_rate: float) -> None:
        self._capacity = capacity
        self._refill_rate = refill_rate
        self._tokens: float = float(capacity)
        self._last_refill: float = time.monotonic()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        self._tokens = min(
            self._capacity,
            self._tokens + elapsed * self._refill_rate,
        )
        self._last_refill = now

    def consume(self, count: int = 1) -> bool:
        self._refill()
        if self._tokens >= count:
            self._tokens -= count
            return True
        return False

    @property
    def available(self) -> float:
        self._refill()
        return self._tokens

    def drain(self) -> None:
        self._tokens = 0.0


class BudgetLedger:
    """Per-engagement budget ledger with append-only consumption records."""

    def __init__(self) -> None:
        self._specs: dict[tuple[UUID, UUID], BudgetSpec] = {}
        self._consumed_requests: dict[tuple[UUID, UUID], int] = {}
        self._consumed_cost: dict[tuple[UUID, UUID], float] = {}
        self._active_count: dict[tuple[UUID, UUID], int] = {}
        self._records: list[ConsumptionRecord] = []
        self._emergency_stopped: set[tuple[UUID, UUID]] = set()
        self._buckets: dict[tuple[UUID, UUID], TokenBucket] = {}

    def register(self, tenant_id: UUID, engagement_id: UUID, spec: BudgetSpec) -> None:
        key = (tenant_id, engagement_id)
        self._specs[key] = spec
        self._consumed_requests.setdefault(key, 0)
        self._consumed_cost.setdefault(key, 0.0)
        self._active_count.setdefault(key, 0)
        self._buckets[key] = TokenBucket(
            capacity=spec.burst_capacity,
            refill_rate=spec.requests_per_second,
        )

    def check(
        self,
        tenant_id: UUID,
        engagement_id: UUID,
        requests_needed: int,
        cost_usd: float = 0.0,
    ) -> BudgetCheckResult:
        key = (tenant_id, engagement_id)

        if key in self._emergency_stopped:
            return BudgetCheckResult(
                allowed=False,
                denial_reason=BudgetDenialReason.EMERGENCY_STOP,
            )

        spec = self._specs.get(key, BudgetSpec())
        consumed_req = self._consumed_requests.get(key, 0)
        consumed_cost = self._consumed_cost.get(key, 0.0)
        active = self._active_count.get(key, 0)

        remaining_req = spec.max_requests - consumed_req
        remaining_cost = spec.max_cost_usd - consumed_cost
        remaining_concurrent = spec.max_concurrent - active

        if consumed_req + requests_needed > spec.max_requests:
            return BudgetCheckResult(
                allowed=False,
                denial_reason=BudgetDenialReason.REQUESTS_EXCEEDED,
                remaining_requests=max(0, remaining_req),
                remaining_cost_usd=max(0.0, remaining_cost),
                remaining_concurrent=max(0, remaining_concurrent),
            )

        if consumed_cost + cost_usd > spec.max_cost_usd:
            return BudgetCheckResult(
                allowed=False,
                denial_reason=BudgetDenialReason.COST_EXCEEDED,
                remaining_requests=max(0, remaining_req),
                remaining_cost_usd=max(0.0, remaining_cost),
                remaining_concurrent=max(0, remaining_concurrent),
            )

        if active >= spec.max_concurrent:
            return BudgetCheckResult(
                allowed=False,
                denial_reason=BudgetDenialReason.CONCURRENCY_EXCEEDED,
                remaining_requests=max(0, remaining_req),
                remaining_cost_usd=max(0.0, remaining_cost),
                remaining_concurrent=0,
            )

        bucket = self._buckets.get(key)
        if bucket and not bucket.consume(min(requests_needed, spec.burst_capacity)):
            return BudgetCheckResult(
                allowed=False,
                denial_reason=BudgetDenialReason.RATE_EXCEEDED,
                remaining_requests=max(0, remaining_req),
                remaining_cost_usd=max(0.0, remaining_cost),
                remaining_concurrent=max(0, remaining_concurrent),
            )

        return BudgetCheckResult(
            allowed=True,
            remaining_requests=max(0, remaining_req - requests_needed),
            remaining_cost_usd=max(0.0, remaining_cost - cost_usd),
            remaining_concurrent=max(0, remaining_concurrent),
        )

    def consume(
        self,
        tenant_id: UUID,
        engagement_id: UUID,
        action_id: UUID,
        requests_consumed: int,
        cost_usd: float = 0.0,
    ) -> ConsumptionRecord:
        key = (tenant_id, engagement_id)
        self._consumed_requests[key] = self._consumed_requests.get(key, 0) + requests_consumed
        self._consumed_cost[key] = self._consumed_cost.get(key, 0.0) + cost_usd
        self._active_count[key] = self._active_count.get(key, 0) + 1
        record = ConsumptionRecord(
            record_id=uuid4(),
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            action_id=action_id,
            requests_consumed=requests_consumed,
            cost_usd=cost_usd,
        )
        self._records.append(record)
        return record

    def release(self, tenant_id: UUID, engagement_id: UUID) -> None:
        """Decrement active count when an action completes."""
        key = (tenant_id, engagement_id)
        current = self._active_count.get(key, 0)
        self._active_count[key] = max(0, current - 1)

    def emergency_stop(self, tenant_id: UUID, engagement_id: UUID) -> None:
        key = (tenant_id, engagement_id)
        self._emergency_stopped.add(key)
        bucket = self._buckets.get(key)
        if bucket:
            bucket.drain()

    def is_emergency_stopped(self, tenant_id: UUID, engagement_id: UUID) -> bool:
        return (tenant_id, engagement_id) in self._emergency_stopped

    def consumed_requests(self, tenant_id: UUID, engagement_id: UUID) -> int:
        return self._consumed_requests.get((tenant_id, engagement_id), 0)

    def consumed_cost_usd(self, tenant_id: UUID, engagement_id: UUID) -> float:
        return self._consumed_cost.get((tenant_id, engagement_id), 0.0)

    def active_count(self, tenant_id: UUID, engagement_id: UUID) -> int:
        return self._active_count.get((tenant_id, engagement_id), 0)

    def records_for_engagement(
        self, tenant_id: UUID, engagement_id: UUID
    ) -> list[ConsumptionRecord]:
        return [
            r
            for r in self._records
            if r.tenant_id == tenant_id and r.engagement_id == engagement_id
        ]

    def snapshot(self, tenant_id: UUID, engagement_id: UUID) -> dict[str, Any]:
        key = (tenant_id, engagement_id)
        spec = self._specs.get(key, BudgetSpec())
        return {
            "max_requests": spec.max_requests,
            "consumed_requests": self._consumed_requests.get(key, 0),
            "remaining_requests": spec.max_requests - self._consumed_requests.get(key, 0),
            "max_cost_usd": spec.max_cost_usd,
            "consumed_cost_usd": self._consumed_cost.get(key, 0.0),
            "remaining_cost_usd": spec.max_cost_usd - self._consumed_cost.get(key, 0.0),
            "max_concurrent": spec.max_concurrent,
            "active_count": self._active_count.get(key, 0),
            "emergency_stopped": key in self._emergency_stopped,
        }
