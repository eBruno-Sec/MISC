"""Unit tests for the adapter framework and HTTP adapter.

Covers the AdapterContract ABC, shared dataclasses, EvidenceSink protocol,
budget tracking, cancellation, and the full HttpAdapter lifecycle.
"""

from __future__ import annotations

import hashlib
import threading
from typing import Any
from uuid import uuid4

import pytest

from adapters import (
    AdapterContract,
    AdapterError,
    AdapterMetadata,
    AdapterResult,
    EvidenceSink,
    ExecutionPlan,
    HeartbeatReport,
)
from adapters.http import BudgetTracker, HttpAdapter, HttpRawResponse
from packages.contracts.schemas.engagement import ScopeRule, ScopeSpec

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scope(include=None, exclude=None):
    return ScopeSpec(
        include=include or [],
        exclude=exclude or [],
    )


def _rule(type_: str, value: str):
    return ScopeRule(type=type_, value=value)


class FakeEvidenceSink:
    """In-memory evidence sink for testing."""

    def __init__(self) -> None:
        self.stored: list[tuple[bytes, str, dict[str, Any]]] = []

    def store(self, data: bytes, media_type: str, metadata: dict[str, Any]) -> str:
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        self.stored.append((data, media_type, metadata))
        return digest


def _fake_http_client(
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
    body: bytes = b"OK",
    redirect_chain: list[str] | None = None,
) -> Any:
    """Return a callable that mimics an HTTP client for injection."""

    def _client(**kwargs: Any) -> HttpRawResponse:
        return HttpRawResponse(
            status_code=status,
            headers=headers or {"content-type": "text/plain"},
            body=body,
            redirect_chain=redirect_chain or [],
            elapsed_ms=42.0,
        )

    return _client


def _valid_envelope() -> dict[str, Any]:
    return {
        "action_digest": "sha256:abc123",
        "target": {
            "locator": "https://api.example.test/users/1",
            "expected_addresses": ["93.184.216.34"],
        },
        "parameters": {
            "method": "GET",
            "headers": {"Authorization": "Bearer token"},
        },
        "budget": {
            "max_requests": 10,
            "max_bytes": 1_000_000,
            "timeout_seconds": 30.0,
        },
    }


# ---------------------------------------------------------------------------
# 1. AdapterMetadata construction
# ---------------------------------------------------------------------------


def test_adapter_metadata_construction():
    meta = AdapterMetadata(
        adapter_id="test.adapter",
        version="1.0.0",
        description="A test adapter",
        supported_techniques=["web.recon.http"],
        parameter_schema={"type": "object"},
    )
    assert meta.adapter_id == "test.adapter"
    assert meta.version == "1.0.0"
    assert meta.supported_techniques == ["web.recon.http"]


def test_adapter_metadata_frozen():
    meta = AdapterMetadata(
        adapter_id="test.adapter",
        version="1.0.0",
        description="A test adapter",
        supported_techniques=[],
        parameter_schema={},
    )
    with pytest.raises(AttributeError):
        meta.adapter_id = "mutated"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 2. ExecutionPlan construction and frozen
# ---------------------------------------------------------------------------


def test_execution_plan_construction():
    plan = ExecutionPlan(
        envelope_digest="sha256:abc",
        resolved_target="https://example.test",
        resolved_addresses=["1.2.3.4"],
        parameters={"method": "GET"},
        budget={"max_requests": 5},
        timeout_seconds=30.0,
    )
    assert plan.resolved_target == "https://example.test"
    assert plan.timeout_seconds == 30.0


def test_execution_plan_frozen():
    plan = ExecutionPlan(
        envelope_digest="sha256:abc",
        resolved_target="https://example.test",
        resolved_addresses=[],
        parameters={},
        budget={},
        timeout_seconds=10.0,
    )
    with pytest.raises(AttributeError):
        plan.resolved_target = "https://other.test"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 3. HttpAdapter.describe() returns correct metadata
# ---------------------------------------------------------------------------


def test_http_adapter_describe():
    adapter = HttpAdapter()
    meta = adapter.describe()
    assert meta.adapter_id == "arsgoatia.adapter.http"
    assert meta.version == "0.1.0"
    assert "web.authz.bola.differential" in meta.supported_techniques
    assert "web.recon.http" in meta.supported_techniques
    assert isinstance(meta.parameter_schema, dict)


# ---------------------------------------------------------------------------
# 4. HttpAdapter.preflight() with valid envelope
# ---------------------------------------------------------------------------


def test_http_adapter_preflight_valid():
    scope = _scope(include=[_rule("dns_suffix", "*.example.test")])
    adapter = HttpAdapter(scope=scope)
    envelope = _valid_envelope()
    plan = adapter.preflight(envelope, secret_leases={})

    assert plan.resolved_target == "https://api.example.test/users/1"
    assert plan.resolved_addresses == ["93.184.216.34"]
    assert plan.envelope_digest == "sha256:abc123"
    assert plan.timeout_seconds == 30.0
    assert plan.parameters["method"] == "GET"


def test_http_adapter_preflight_no_scope():
    """Preflight succeeds when no scope is configured (scope=None)."""
    adapter = HttpAdapter()
    envelope = _valid_envelope()
    plan = adapter.preflight(envelope, secret_leases={})
    assert plan.resolved_target == "https://api.example.test/users/1"


# ---------------------------------------------------------------------------
# 5. HttpAdapter.preflight() rejects out-of-scope target
# ---------------------------------------------------------------------------


def test_http_adapter_preflight_out_of_scope():
    scope = _scope(include=[_rule("exact_host", "allowed.test")])
    adapter = HttpAdapter(scope=scope)
    envelope = _valid_envelope()  # target is api.example.test

    with pytest.raises(AdapterError, match="target out of scope"):
        adapter.preflight(envelope, secret_leases={})


def test_http_adapter_preflight_empty_scope_denies():
    scope = _scope(include=[])  # empty scope => fail closed
    adapter = HttpAdapter(scope=scope)
    envelope = _valid_envelope()

    with pytest.raises(AdapterError, match="target out of scope"):
        adapter.preflight(envelope, secret_leases={})


# ---------------------------------------------------------------------------
# 6. HttpAdapter.normalize() extracts status/headers/body hash
# ---------------------------------------------------------------------------


def test_http_adapter_normalize_basic():
    adapter = HttpAdapter()
    body = b"Hello, world!"
    raw = HttpRawResponse(
        status_code=200,
        headers={"content-type": "text/plain", "x-custom": "value"},
        body=body,
        redirect_chain=[],
        elapsed_ms=15.0,
    )
    observations, coverage, diagnostics = adapter.normalize([raw])

    assert len(observations) == 1
    obs = observations[0]
    assert obs["status_code"] == 200
    assert obs["body_sha256"] == hashlib.sha256(body).hexdigest()
    assert obs["body_size"] == len(body)
    assert obs["headers"]["content-type"] == "text/plain"
    assert "http_status_200" in coverage
    assert "http_headers_captured" in coverage
    assert diagnostics == []


def test_http_adapter_normalize_redirect_chain():
    adapter = HttpAdapter()
    raw = HttpRawResponse(
        status_code=301,
        headers={"location": "https://new.example.test"},
        body=b"",
        redirect_chain=["https://old.example.test", "https://new.example.test"],
        elapsed_ms=5.0,
    )
    observations, coverage, diagnostics = adapter.normalize([raw])

    assert observations[0]["redirect_chain"] == [
        "https://old.example.test",
        "https://new.example.test",
    ]
    assert "redirect_chain_captured" in coverage


def test_http_adapter_normalize_skips_non_response():
    adapter = HttpAdapter()
    observations, coverage, diagnostics = adapter.normalize(["not-a-response"])
    assert observations == []
    assert len(diagnostics) == 1
    assert "skipped" in diagnostics[0]


# ---------------------------------------------------------------------------
# 7. Budget tracking
# ---------------------------------------------------------------------------


def test_budget_tracker_request_limit():
    bt = BudgetTracker(max_requests=2)
    bt.start()
    bt.record_request(100)
    assert bt.check() is None
    bt.record_request(200)
    reason = bt.check()
    assert reason is not None
    assert "request budget exhausted" in reason


def test_budget_tracker_byte_limit():
    bt = BudgetTracker(max_bytes=500)
    bt.start()
    bt.record_request(300)
    assert bt.check() is None
    bt.record_request(300)
    reason = bt.check()
    assert reason is not None
    assert "byte budget exhausted" in reason


def test_budget_tracker_remaining():
    bt = BudgetTracker(max_requests=10, max_bytes=1000)
    bt.start()
    bt.record_request(100)
    remaining = bt.remaining()
    assert remaining["requests_remaining"] == 9
    assert remaining["bytes_remaining"] == 900


# ---------------------------------------------------------------------------
# 8. Cancel sets event
# ---------------------------------------------------------------------------


def test_cancel_sets_event():
    adapter = HttpAdapter()
    result = adapter.cancel(grace_period=5.0)
    assert result.outcome == "cancelled"
    assert adapter._cancellation_event.is_set()


def test_execute_respects_cancellation():
    adapter = HttpAdapter(http_client=_fake_http_client())
    scope = _scope(include=[_rule("dns_suffix", "*.example.test")])
    adapter._scope = scope
    envelope = _valid_envelope()
    plan = adapter.preflight(envelope, secret_leases={})

    cancel_event = threading.Event()
    cancel_event.set()  # pre-cancelled

    result = adapter.execute(plan, cancel_event, FakeEvidenceSink())
    assert result.outcome == "cancelled"


# ---------------------------------------------------------------------------
# 9. AdapterResult construction
# ---------------------------------------------------------------------------


def test_adapter_result_construction():
    result = AdapterResult(
        outcome="succeeded",
        observations=[{"status_code": 200}],
        evidence_refs=["sha256:abc"],
        diagnostics=[],
        resource_usage={"requests_made": 1},
    )
    assert result.outcome == "succeeded"
    assert result.observations[0]["status_code"] == 200
    assert result.evidence_refs == ["sha256:abc"]


def test_adapter_result_defaults():
    result = AdapterResult(outcome="failed")
    assert result.observations == []
    assert result.evidence_refs == []
    assert result.diagnostics == []
    assert result.resource_usage == {}


# ---------------------------------------------------------------------------
# 10. HeartbeatReport construction
# ---------------------------------------------------------------------------


def test_heartbeat_report_construction():
    report = HeartbeatReport(
        progress_pct=0.75,
        requests_made=15,
        bytes_received=4096,
        budget_remaining={"requests_remaining": 5},
    )
    assert report.progress_pct == 0.75
    assert report.requests_made == 15
    assert report.bytes_received == 4096
    assert report.budget_remaining["requests_remaining"] == 5


# ---------------------------------------------------------------------------
# 11. EvidenceSink protocol conformance
# ---------------------------------------------------------------------------


def test_evidence_sink_protocol():
    sink = FakeEvidenceSink()
    assert isinstance(sink, EvidenceSink)
    digest = sink.store(b"test", "text/plain", {"key": "val"})
    assert digest.startswith("sha256:")
    assert len(sink.stored) == 1


# ---------------------------------------------------------------------------
# 12. Full execute lifecycle with mock client
# ---------------------------------------------------------------------------


def test_execute_full_lifecycle():
    scope = _scope(include=[_rule("dns_suffix", "*.example.test")])
    client = _fake_http_client(
        status=200,
        headers={"content-type": "application/json"},
        body=b'{"id": 1}',
    )
    adapter = HttpAdapter(scope=scope, http_client=client)

    envelope = _valid_envelope()
    plan = adapter.preflight(envelope, secret_leases={})
    sink = FakeEvidenceSink()
    cancel_event = threading.Event()

    result = adapter.execute(plan, cancel_event, sink)

    assert result.outcome == "succeeded"
    assert len(result.observations) == 1
    assert result.observations[0]["status_code"] == 200
    assert len(result.evidence_refs) == 1
    assert result.evidence_refs[0].startswith("sha256:")
    assert result.resource_usage["requests_made"] == 1
    assert len(sink.stored) == 1


# ---------------------------------------------------------------------------
# 13. Execute without HTTP client raises AdapterError
# ---------------------------------------------------------------------------


def test_execute_no_client_raises():
    adapter = HttpAdapter()
    plan = ExecutionPlan(
        envelope_digest="sha256:abc",
        resolved_target="https://api.example.test/test",
        resolved_addresses=[],
        parameters={"method": "GET"},
        budget={},
        timeout_seconds=10.0,
    )
    sink = FakeEvidenceSink()
    cancel_event = threading.Event()

    with pytest.raises(AdapterError, match="no HTTP client configured"):
        adapter.execute(plan, cancel_event, sink)


# ---------------------------------------------------------------------------
# 14. Preflight rejects non-HTTP schemes
# ---------------------------------------------------------------------------


def test_preflight_rejects_ftp_scheme():
    adapter = HttpAdapter()
    envelope = {
        "target": {"locator": "ftp://files.example.test/data"},
        "parameters": {},
        "budget": {},
    }
    with pytest.raises(AdapterError, match="unsupported URL scheme"):
        adapter.preflight(envelope, secret_leases={})


# ---------------------------------------------------------------------------
# 15. Cleanup returns evidence
# ---------------------------------------------------------------------------


def test_cleanup_returns_evidence():
    adapter = HttpAdapter()
    obligation_id = uuid4()
    result = adapter.cleanup([obligation_id])
    assert result["cleaned"] is True
    assert str(obligation_id) in result["obligations_handled"]


# ---------------------------------------------------------------------------
# 16. Heartbeat uses budget state
# ---------------------------------------------------------------------------


def test_heartbeat_reflects_budget():
    adapter = HttpAdapter()
    adapter._budget = BudgetTracker(max_requests=10, max_bytes=5000)
    adapter._budget.start()
    adapter._budget.record_request(1024)
    adapter._budget.record_request(512)

    report = adapter.heartbeat(
        progress=0.5,
        resource_use={},
        budget_counters={},
    )
    assert report.progress_pct == 0.5
    assert report.requests_made == 2
    assert report.bytes_received == 1536
    assert report.budget_remaining["requests_remaining"] == 8


# ---------------------------------------------------------------------------
# 17. AdapterContract is abstract
# ---------------------------------------------------------------------------


def test_adapter_contract_is_abstract():
    with pytest.raises(TypeError):
        AdapterContract()  # type: ignore[abstract]
