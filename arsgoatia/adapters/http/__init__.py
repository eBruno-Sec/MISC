"""ArsGoatia HTTP adapter -- probes web targets over HTTP/HTTPS.

Implements the full AdapterContract lifecycle for HTTP-based techniques
such as BOLA differential probing, HTTP reconnaissance, and header
analysis per spec sections 7.5 and 9.6.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

from adapters import (
    AdapterContract,
    AdapterError,
    AdapterMetadata,
    AdapterResult,
    EvidenceSink,
    ExecutionPlan,
    HeartbeatReport,
)
from packages.scope import ScopeVerdict, check_target

# Re-export ScopeVerdict so callers can inspect it if needed.
__all__ = ["HttpAdapter", "BudgetTracker", "HttpRawResponse"]


# ---------------------------------------------------------------------------
# Budget tracking
# ---------------------------------------------------------------------------


@dataclass
class BudgetTracker:
    """Tracks request count, byte count, and elapsed time against limits."""

    max_requests: int = 0
    max_bytes: int = 0
    max_seconds: float = 0.0
    requests_made: int = 0
    bytes_received: int = 0
    _start_time: float = field(default=0.0, repr=False)

    def start(self) -> None:
        self._start_time = time.monotonic()

    @property
    def elapsed_seconds(self) -> float:
        if self._start_time == 0.0:
            return 0.0
        return time.monotonic() - self._start_time

    def record_request(self, response_bytes: int) -> None:
        self.requests_made += 1
        self.bytes_received += response_bytes

    def check(self) -> str | None:
        """Return a reason string if any budget is exceeded, else ``None``."""
        if self.max_requests > 0 and self.requests_made >= self.max_requests:
            return f"request budget exhausted ({self.requests_made}/{self.max_requests})"
        if self.max_bytes > 0 and self.bytes_received >= self.max_bytes:
            return f"byte budget exhausted ({self.bytes_received}/{self.max_bytes})"
        if self.max_seconds > 0.0 and self.elapsed_seconds >= self.max_seconds:
            return f"time budget exhausted ({self.elapsed_seconds:.1f}s/{self.max_seconds:.1f}s)"
        return None

    def remaining(self) -> dict[str, Any]:
        return {
            "requests_remaining": max(0, self.max_requests - self.requests_made)
            if self.max_requests > 0
            else None,
            "bytes_remaining": max(0, self.max_bytes - self.bytes_received)
            if self.max_bytes > 0
            else None,
            "seconds_remaining": max(0.0, self.max_seconds - self.elapsed_seconds)
            if self.max_seconds > 0.0
            else None,
        }


# ---------------------------------------------------------------------------
# Raw HTTP response capture
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HttpRawResponse:
    """Lightweight snapshot of an HTTP response for normalisation."""

    status_code: int
    headers: dict[str, str]
    body: bytes
    redirect_chain: list[str] = field(default_factory=list)
    elapsed_ms: float = 0.0


# ---------------------------------------------------------------------------
# Supported technique catalogue
# ---------------------------------------------------------------------------

_SUPPORTED_TECHNIQUES: list[str] = [
    "web.authz.bola.differential",
    "web.recon.http",
    "web.recon.headers",
    "web.recon.methods",
    "web.recon.tls",
]

_PARAMETER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "method": {"type": "string", "default": "GET"},
        "headers": {"type": "object", "additionalProperties": {"type": "string"}},
        "body": {"type": "string", "default": ""},
        "follow_redirects": {"type": "boolean", "default": False},
    },
}


# ---------------------------------------------------------------------------
# HTTP adapter
# ---------------------------------------------------------------------------


class HttpAdapter(AdapterContract):
    """Concrete HTTP adapter implementing the full AdapterContract lifecycle."""

    _ADAPTER_ID = "arsgoatia.adapter.http"
    _VERSION = "0.1.0"

    def __init__(
        self,
        scope: Any | None = None,
        *,
        http_client: Any | None = None,
    ) -> None:
        self._scope = scope
        self._http_client = http_client
        self._cancellation_event: threading.Event = threading.Event()
        self._budget = BudgetTracker()

    # -- describe -----------------------------------------------------------

    def describe(self) -> AdapterMetadata:
        return AdapterMetadata(
            adapter_id=self._ADAPTER_ID,
            version=self._VERSION,
            description="HTTP/HTTPS probe adapter for web security validation",
            supported_techniques=list(_SUPPORTED_TECHNIQUES),
            parameter_schema=dict(_PARAMETER_SCHEMA),
        )

    # -- preflight ----------------------------------------------------------

    def preflight(
        self,
        envelope: Any,
        secret_leases: dict[str, str],
    ) -> ExecutionPlan:
        # Extract target locator from envelope
        if hasattr(envelope, "target"):
            target = envelope.target
            locator = target.locator if hasattr(target, "locator") else str(target)
            expected_addresses = (
                list(target.expected_addresses)
                if hasattr(target, "expected_addresses")
                else []
            )
        elif isinstance(envelope, dict):
            target_dict = envelope.get("target", {})
            locator = target_dict.get("locator", "")
            expected_addresses = target_dict.get("expected_addresses", [])
        else:
            raise AdapterError("envelope must have a 'target' attribute or key")

        if not locator:
            raise AdapterError("target locator is empty")

        # Validate URL scheme
        parsed = urlparse(locator)
        if parsed.scheme not in ("http", "https"):
            raise AdapterError(
                f"unsupported URL scheme '{parsed.scheme}'; expected http or https"
            )

        # Scope check
        if self._scope is not None:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            verdict: ScopeVerdict = check_target(self._scope, locator, port=port)
            if not verdict.allowed:
                raise AdapterError(f"target out of scope: {verdict.reason}")

        # Extract budget from envelope
        budget_raw: dict[str, Any] = {}
        if hasattr(envelope, "budget"):
            budget_raw = dict(envelope.budget) if envelope.budget else {}
        elif isinstance(envelope, dict):
            budget_raw = dict(envelope.get("budget", {}))

        timeout = float(budget_raw.get("timeout_seconds", 30.0))

        # Extract envelope digest
        envelope_digest: str = ""
        if hasattr(envelope, "action_digest"):
            envelope_digest = envelope.action_digest
        elif isinstance(envelope, dict):
            envelope_digest = envelope.get("action_digest", "")

        # Extract parameters
        parameters: dict[str, Any] = {}
        if hasattr(envelope, "parameters"):
            parameters = dict(envelope.parameters) if envelope.parameters else {}
        elif isinstance(envelope, dict):
            parameters = dict(envelope.get("parameters", {}))

        return ExecutionPlan(
            envelope_digest=envelope_digest,
            resolved_target=locator,
            resolved_addresses=expected_addresses,
            parameters=parameters,
            budget=budget_raw,
            timeout_seconds=timeout,
        )

    # -- execute ------------------------------------------------------------

    def execute(
        self,
        plan: ExecutionPlan,
        cancellation: Any,
        evidence_sink: EvidenceSink,
    ) -> AdapterResult:
        if isinstance(cancellation, threading.Event):
            self._cancellation_event = cancellation

        # Initialise budget from plan
        self._budget = BudgetTracker(
            max_requests=int(plan.budget.get("max_requests", 0)),
            max_bytes=int(plan.budget.get("max_bytes", 0)),
            max_seconds=plan.timeout_seconds,
        )
        self._budget.start()

        # Pre-execution budget check
        budget_violation = self._budget.check()
        if budget_violation:
            return AdapterResult(
                outcome="resource_exhausted",
                diagnostics=[budget_violation],
                resource_usage=self._resource_usage(),
            )

        # Cancellation check
        if self._cancellation_event.is_set():
            return AdapterResult(
                outcome="cancelled",
                diagnostics=["cancelled before request"],
                resource_usage=self._resource_usage(),
            )

        # Perform HTTP request
        method = plan.parameters.get("method", "GET")
        headers = plan.parameters.get("headers", {})
        body = plan.parameters.get("body", "")
        follow_redirects = plan.parameters.get("follow_redirects", False)

        try:
            raw_response = self._do_request(
                url=plan.resolved_target,
                method=method,
                headers=headers,
                body=body,
                follow_redirects=follow_redirects,
                timeout=plan.timeout_seconds,
            )
        except TimeoutError:
            return AdapterResult(
                outcome="timed_out",
                diagnostics=["HTTP request timed out"],
                resource_usage=self._resource_usage(),
            )
        except AdapterError:
            raise
        except Exception as exc:
            return AdapterResult(
                outcome="adapter_error",
                diagnostics=[f"HTTP request failed: {exc}"],
                resource_usage=self._resource_usage(),
            )

        # Record budget usage
        self._budget.record_request(len(raw_response.body))

        # Store evidence
        evidence_data = json.dumps(
            {
                "url": plan.resolved_target,
                "method": method,
                "status_code": raw_response.status_code,
                "headers": raw_response.headers,
                "body_sha256": hashlib.sha256(raw_response.body).hexdigest(),
                "body_size": len(raw_response.body),
                "redirect_chain": raw_response.redirect_chain,
                "elapsed_ms": raw_response.elapsed_ms,
            },
            indent=2,
        ).encode()

        evidence_ref = evidence_sink.store(
            data=evidence_data,
            media_type="application/json",
            metadata={
                "adapter": self._ADAPTER_ID,
                "target": plan.resolved_target,
            },
        )

        # Normalise observations
        observations, coverage, diagnostics = self.normalize([raw_response])

        return AdapterResult(
            outcome="succeeded",
            observations=observations,
            evidence_refs=[evidence_ref],
            diagnostics=diagnostics,
            resource_usage=self._resource_usage(),
        )

    # -- heartbeat ----------------------------------------------------------

    def heartbeat(
        self,
        progress: float,
        resource_use: dict[str, Any],
        budget_counters: dict[str, Any],
    ) -> HeartbeatReport:
        return HeartbeatReport(
            progress_pct=progress,
            requests_made=self._budget.requests_made,
            bytes_received=self._budget.bytes_received,
            budget_remaining=self._budget.remaining(),
        )

    # -- cancel -------------------------------------------------------------

    def cancel(self, grace_period: float) -> AdapterResult:
        self._cancellation_event.set()
        return AdapterResult(
            outcome="cancelled",
            diagnostics=[f"cancellation signalled with {grace_period:.1f}s grace"],
            resource_usage=self._resource_usage(),
        )

    # -- cleanup ------------------------------------------------------------

    def cleanup(self, obligations: list[UUID]) -> dict[str, Any]:
        # HTTP adapter is stateless -- no mutations to undo.
        return {
            "cleaned": True,
            "obligations_handled": [str(o) for o in obligations],
            "notes": "HTTP adapter is stateless; no cleanup required",
        }

    # -- normalize ----------------------------------------------------------

    def normalize(
        self,
        raw_references: list[Any],
    ) -> tuple[list[dict[str, Any]], list[str], list[str]]:
        """Extract status codes, headers, body hashes, and redirect chains."""
        observations: list[dict[str, Any]] = []
        coverage: list[str] = []
        diagnostics: list[str] = []

        for raw in raw_references:
            if not isinstance(raw, HttpRawResponse):
                diagnostics.append(f"skipped non-HttpRawResponse: {type(raw).__name__}")
                continue

            body_hash = hashlib.sha256(raw.body).hexdigest()
            obs: dict[str, Any] = {
                "status_code": raw.status_code,
                "headers": dict(raw.headers),
                "body_sha256": body_hash,
                "body_size": len(raw.body),
                "redirect_chain": list(raw.redirect_chain),
                "elapsed_ms": raw.elapsed_ms,
            }
            observations.append(obs)

            # Coverage markers
            coverage.append(f"http_status_{raw.status_code}")
            if raw.headers:
                coverage.append("http_headers_captured")
            if raw.redirect_chain:
                coverage.append("redirect_chain_captured")

        return observations, coverage, diagnostics

    # -- internal helpers ---------------------------------------------------

    def _do_request(
        self,
        *,
        url: str,
        method: str,
        headers: dict[str, str],
        body: str,
        follow_redirects: bool,
        timeout: float,
    ) -> HttpRawResponse:
        """Dispatch the HTTP request via the configured client.

        If no ``http_client`` was injected at construction, raises
        ``AdapterError`` so tests can verify the lifecycle without
        making real network calls.
        """
        if self._http_client is None:
            raise AdapterError(
                "no HTTP client configured; inject one via http_client parameter"
            )

        # The injected client must be a callable matching:
        #   client(url, method, headers, body, follow_redirects, timeout) -> HttpRawResponse
        return self._http_client(
            url=url,
            method=method,
            headers=headers,
            body=body,
            follow_redirects=follow_redirects,
            timeout=timeout,
        )

    def _resource_usage(self) -> dict[str, Any]:
        return {
            "requests_made": self._budget.requests_made,
            "bytes_received": self._budget.bytes_received,
            "elapsed_seconds": round(self._budget.elapsed_seconds, 3),
        }
