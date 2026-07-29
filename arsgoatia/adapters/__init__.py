"""ArsGoatia adapter contract -- abstract base and shared types for all adapters.

Every adapter (HTTP, browser, nuclei, etc.) implements AdapterContract
so the execution engine can drive them uniformly through preflight,
execute, heartbeat, cancel, and cleanup phases per spec section 7.5.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable
from uuid import UUID


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AdapterError(Exception):
    """Raised when an adapter encounters an unrecoverable internal error."""


# ---------------------------------------------------------------------------
# Evidence sink protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class EvidenceSink(Protocol):
    """Protocol for storing evidence artifacts produced during execution."""

    def store(self, data: bytes, media_type: str, metadata: dict[str, Any]) -> str:
        """Persist *data* and return its content-addressable digest."""
        ...


# ---------------------------------------------------------------------------
# Shared dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AdapterMetadata:
    """Immutable descriptor returned by ``AdapterContract.describe()``."""

    adapter_id: str
    version: str
    description: str
    supported_techniques: list[str]
    parameter_schema: dict[str, Any]


@dataclass(frozen=True)
class ExecutionPlan:
    """Resolved, validated plan produced by ``AdapterContract.preflight()``."""

    envelope_digest: str
    resolved_target: str
    resolved_addresses: list[str]
    parameters: dict[str, Any]
    budget: dict[str, Any]
    timeout_seconds: float


@dataclass
class AdapterResult:
    """Outcome bundle returned by ``AdapterContract.execute()``."""

    outcome: str  # value from ToolOutcome
    observations: list[dict[str, Any]] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)
    resource_usage: dict[str, Any] = field(default_factory=dict)


@dataclass
class HeartbeatReport:
    """Progress snapshot emitted by ``AdapterContract.heartbeat()``."""

    progress_pct: float
    requests_made: int
    bytes_received: int
    budget_remaining: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Abstract adapter contract
# ---------------------------------------------------------------------------


class AdapterContract(abc.ABC):
    """Base class every ArsGoatia adapter must implement (spec section 7.5)."""

    @abc.abstractmethod
    def describe(self) -> AdapterMetadata:
        """Return metadata, schemas, capabilities, and image digest."""

    @abc.abstractmethod
    def preflight(
        self,
        envelope: Any,
        secret_leases: dict[str, str],
    ) -> ExecutionPlan:
        """Validate the envelope, resolve the target, and return an execution plan."""

    @abc.abstractmethod
    def execute(
        self,
        plan: ExecutionPlan,
        cancellation: Any,
        evidence_sink: EvidenceSink,
    ) -> AdapterResult:
        """Carry out the plan, storing evidence and returning normalised observations."""

    @abc.abstractmethod
    def heartbeat(
        self,
        progress: float,
        resource_use: dict[str, Any],
        budget_counters: dict[str, Any],
    ) -> HeartbeatReport:
        """Produce a progress snapshot for the execution engine."""

    @abc.abstractmethod
    def cancel(self, grace_period: float) -> AdapterResult:
        """Signal cancellation; return a termination result after grace period."""

    @abc.abstractmethod
    def cleanup(self, obligations: list[UUID]) -> dict[str, Any]:
        """Honour cleanup obligations and return cleanup evidence."""

    @abc.abstractmethod
    def normalize(
        self,
        raw_references: list[Any],
    ) -> tuple[list[dict[str, Any]], list[str], list[str]]:
        """Normalise raw data into (observations, coverage, diagnostics)."""
