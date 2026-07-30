"""ArsGoatia observability — structured logging, metrics, and trace context.

Per §13.2: propagate trace_id, tenant-safe hashed tenant ID, engagement revision,
workflow/run/action IDs. Never place secrets, raw bodies, command payloads, prompts,
or source snippets in labels/logs.
"""

from __future__ import annotations

import hashlib
import logging
import time
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Generator
from uuid import UUID, uuid4

# ---------------------------------------------------------------------------
# Trace context (W3C-style)
# ---------------------------------------------------------------------------


@dataclass
class TraceContext:
    trace_id: str = ""
    span_id: str = ""
    parent_span_id: str = ""
    trace_flags: int = 0

    def __post_init__(self) -> None:
        if not self.trace_id:
            self.trace_id = uuid4().hex
        if not self.span_id:
            self.span_id = uuid4().hex[:16]

    def child(self) -> TraceContext:
        return TraceContext(
            trace_id=self.trace_id,
            span_id=uuid4().hex[:16],
            parent_span_id=self.span_id,
            trace_flags=self.trace_flags,
        )

    def to_header(self) -> str:
        return f"00-{self.trace_id}-{self.span_id}-{self.trace_flags:02x}"

    @classmethod
    def from_header(cls, header: str) -> TraceContext:
        parts = header.split("-")
        if len(parts) != 4:
            return cls()
        return cls(
            trace_id=parts[1],
            span_id=parts[2],
            trace_flags=int(parts[3], 16),
        )


# ---------------------------------------------------------------------------
# Tenant-safe hashing (never log raw tenant IDs in metrics)
# ---------------------------------------------------------------------------


def hash_tenant_id(tenant_id: UUID) -> str:
    return hashlib.sha256(str(tenant_id).encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Structured log context
# ---------------------------------------------------------------------------


_FORBIDDEN_FIELDS = frozenset(
    {
        "password",
        "secret",
        "token",
        "bearer",
        "authorization",
        "cookie",
        "api_key",
        "apikey",
        "private_key",
        "credential",
        "prompt",
        "raw_body",
        "command_payload",
        "source_snippet",
    }
)


def _is_safe_field(key: str) -> bool:
    lower = key.lower()
    return not any(forbidden in lower for forbidden in _FORBIDDEN_FIELDS)


def sanitize_log_fields(fields: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in fields.items() if _is_safe_field(k)}


@dataclass
class LogContext:
    trace_id: str = ""
    tenant_hash: str = ""
    engagement_id: str = ""
    workflow_id: str = ""
    run_id: str = ""
    action_id: str = ""
    adapter: str = ""
    runner_pool: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def for_engagement(
        cls, tenant_id: UUID, engagement_id: UUID, trace: TraceContext | None = None
    ) -> LogContext:
        return cls(
            trace_id=trace.trace_id if trace else "",
            tenant_hash=hash_tenant_id(tenant_id),
            engagement_id=str(engagement_id),
        )

    def with_action(self, action_id: UUID) -> LogContext:
        return LogContext(
            trace_id=self.trace_id,
            tenant_hash=self.tenant_hash,
            engagement_id=self.engagement_id,
            workflow_id=self.workflow_id,
            run_id=self.run_id,
            action_id=str(action_id),
            adapter=self.adapter,
            runner_pool=self.runner_pool,
            extra=dict(self.extra),
        )

    def as_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        for k in (
            "trace_id",
            "tenant_hash",
            "engagement_id",
            "workflow_id",
            "run_id",
            "action_id",
            "adapter",
            "runner_pool",
        ):
            v = getattr(self, k)
            if v:
                d[k] = v
        if self.extra:
            d.update(sanitize_log_fields(self.extra))
        return d


# ---------------------------------------------------------------------------
# Structured logger
# ---------------------------------------------------------------------------


class StructuredLogger:
    def __init__(self, name: str, context: LogContext | None = None) -> None:
        self._logger = logging.getLogger(f"arsgoatia.{name}")
        self._context = context or LogContext()

    def _log(self, level: int, msg: str, **kwargs: Any) -> None:
        safe = sanitize_log_fields(kwargs)
        extra = {**self._context.as_dict(), **safe}
        self._logger.log(level, msg, extra={"structured": extra})

    def info(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.INFO, msg, **kwargs)

    def warning(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.WARNING, msg, **kwargs)

    def error(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.ERROR, msg, **kwargs)

    def debug(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.DEBUG, msg, **kwargs)

    def with_context(self, context: LogContext) -> StructuredLogger:
        return StructuredLogger(self._logger.name.removeprefix("arsgoatia."), context)


# ---------------------------------------------------------------------------
# Metrics (in-memory counters/gauges/histograms for dev; production uses Prometheus)
# ---------------------------------------------------------------------------


class MetricsRegistry:
    def __init__(self) -> None:
        self._counters: dict[str, dict[tuple[str, ...], float]] = defaultdict(
            lambda: defaultdict(float)
        )
        self._gauges: dict[str, dict[tuple[str, ...], float]] = defaultdict(
            lambda: defaultdict(float)
        )
        self._histograms: dict[str, list[tuple[tuple[str, ...], float]]] = defaultdict(list)

    def _label_key(self, labels: dict[str, str]) -> tuple[str, ...]:
        safe = sanitize_log_fields(labels)
        return tuple(sorted(safe.items()))  # type: ignore[arg-type]

    def increment(
        self, name: str, value: float = 1.0, labels: dict[str, str] | None = None
    ) -> None:
        key = self._label_key(labels or {})
        self._counters[name][key] += value

    def gauge_set(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        key = self._label_key(labels or {})
        self._gauges[name][key] = value

    def observe(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        key = self._label_key(labels or {})
        self._histograms[name].append((key, value))

    def get_counter(self, name: str, labels: dict[str, str] | None = None) -> float:
        key = self._label_key(labels or {})
        return self._counters.get(name, {}).get(key, 0.0)

    def get_gauge(self, name: str, labels: dict[str, str] | None = None) -> float:
        key = self._label_key(labels or {})
        return self._gauges.get(name, {}).get(key, 0.0)

    def get_histogram_count(self, name: str) -> int:
        return len(self._histograms.get(name, []))

    @contextmanager
    def timer(self, name: str, labels: dict[str, str] | None = None) -> Generator[None, None, None]:
        start = time.monotonic()
        try:
            yield
        finally:
            self.observe(name, time.monotonic() - start, labels)

    def snapshot(self) -> dict[str, Any]:
        return {
            "counters": {
                name: {str(k): v for k, v in buckets.items()}
                for name, buckets in self._counters.items()
            },
            "gauges": {
                name: {str(k): v for k, v in buckets.items()}
                for name, buckets in self._gauges.items()
            },
            "histograms": {name: len(samples) for name, samples in self._histograms.items()},
        }


# ---------------------------------------------------------------------------
# Standard metric names (§13.2)
# ---------------------------------------------------------------------------

API_REQUEST_DURATION = "arsgoatia_api_request_duration_seconds"
API_REQUEST_TOTAL = "arsgoatia_api_request_total"
API_ERROR_TOTAL = "arsgoatia_api_error_total"
WORKFLOW_BACKLOG = "arsgoatia_workflow_backlog"
PROPOSAL_DECISION_TOTAL = "arsgoatia_proposal_decision_total"
APPROVAL_AGE_SECONDS = "arsgoatia_approval_age_seconds"
EVIDENCE_UPLOAD_TOTAL = "arsgoatia_evidence_upload_total"
EVIDENCE_QUARANTINE_TOTAL = "arsgoatia_evidence_quarantine_total"
OUTBOX_LAG_SECONDS = "arsgoatia_outbox_lag_seconds"
BUDGET_BURN_RATIO = "arsgoatia_budget_burn_ratio"
FINDING_VALIDATOR_TOTAL = "arsgoatia_finding_validator_total"
CLEANUP_AGE_SECONDS = "arsgoatia_cleanup_age_seconds"
AI_COST_USD = "arsgoatia_ai_cost_usd"
RUNNER_AVAILABLE = "arsgoatia_runner_available"
RUNNER_REJECTED_TOTAL = "arsgoatia_runner_rejected_total"


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditEvent:
    event_id: UUID
    tenant_id: UUID
    event_type: str
    actor: str
    occurred_at: datetime
    resource_type: str
    resource_id: UUID
    details: dict[str, Any] = field(default_factory=dict)
    trace_id: str = ""
    classification: str = "internal"

    @classmethod
    def create(
        cls,
        tenant_id: UUID,
        event_type: str,
        actor: str,
        resource_type: str,
        resource_id: UUID,
        details: dict[str, Any] | None = None,
        trace: TraceContext | None = None,
    ) -> AuditEvent:
        safe_details = sanitize_log_fields(details or {})
        return cls(
            event_id=uuid4(),
            tenant_id=tenant_id,
            event_type=event_type,
            actor=actor,
            occurred_at=datetime.now(timezone.utc),
            resource_type=resource_type,
            resource_id=resource_id,
            details=safe_details,
            trace_id=trace.trace_id if trace else "",
        )
