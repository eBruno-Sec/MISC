from __future__ import annotations

from uuid import uuid4

from packages.observability import (
    API_REQUEST_DURATION,
    API_REQUEST_TOTAL,
    AuditEvent,
    LogContext,
    MetricsRegistry,
    StructuredLogger,
    TraceContext,
    hash_tenant_id,
    sanitize_log_fields,
)


def test_trace_context_create():
    tc = TraceContext()
    assert len(tc.trace_id) == 32
    assert len(tc.span_id) == 16


def test_trace_context_child():
    parent = TraceContext()
    child = parent.child()
    assert child.trace_id == parent.trace_id
    assert child.parent_span_id == parent.span_id
    assert child.span_id != parent.span_id


def test_trace_context_header_roundtrip():
    tc = TraceContext(trace_id="a" * 32, span_id="b" * 16, trace_flags=1)
    header = tc.to_header()
    assert header == f"00-{'a' * 32}-{'b' * 16}-01"
    parsed = TraceContext.from_header(header)
    assert parsed.trace_id == tc.trace_id
    assert parsed.span_id == tc.span_id
    assert parsed.trace_flags == 1


def test_trace_context_from_invalid_header():
    tc = TraceContext.from_header("garbage")
    assert len(tc.trace_id) == 32


def test_hash_tenant_id_deterministic():
    tid = uuid4()
    h1 = hash_tenant_id(tid)
    h2 = hash_tenant_id(tid)
    assert h1 == h2
    assert len(h1) == 16


def test_hash_tenant_id_different_for_different_tenants():
    assert hash_tenant_id(uuid4()) != hash_tenant_id(uuid4())


def test_sanitize_removes_secrets():
    fields = {
        "user": "alice",
        "password": "secret123",
        "authorization": "Bearer xyz",
        "request_count": 5,
    }
    safe = sanitize_log_fields(fields)
    assert "user" in safe
    assert "request_count" in safe
    assert "password" not in safe
    assert "authorization" not in safe


def test_sanitize_removes_nested_secret_keys():
    fields = {
        "api_key_id": "key-123",
        "normal_field": "value",
    }
    safe = sanitize_log_fields(fields)
    assert "api_key_id" not in safe
    assert "normal_field" in safe


def test_log_context_for_engagement():
    tid = uuid4()
    eid = uuid4()
    trace = TraceContext()
    ctx = LogContext.for_engagement(tid, eid, trace)
    assert ctx.trace_id == trace.trace_id
    assert ctx.tenant_hash == hash_tenant_id(tid)
    assert ctx.engagement_id == str(eid)


def test_log_context_with_action():
    ctx = LogContext(tenant_hash="abc", engagement_id="eng-1")
    aid = uuid4()
    child = ctx.with_action(aid)
    assert child.action_id == str(aid)
    assert child.tenant_hash == "abc"
    assert child.engagement_id == "eng-1"


def test_log_context_as_dict_filters_empty():
    ctx = LogContext(tenant_hash="hash123")
    d = ctx.as_dict()
    assert d == {"tenant_hash": "hash123"}
    assert "trace_id" not in d
    assert "engagement_id" not in d


def test_log_context_extra_sanitized():
    ctx = LogContext(extra={"user": "alice", "secret_key": "hidden"})
    d = ctx.as_dict()
    assert "user" in d
    assert "secret_key" not in d


def test_metrics_counter():
    m = MetricsRegistry()
    m.increment(API_REQUEST_TOTAL, labels={"method": "GET"})
    m.increment(API_REQUEST_TOTAL, labels={"method": "GET"})
    m.increment(API_REQUEST_TOTAL, labels={"method": "POST"})
    assert m.get_counter(API_REQUEST_TOTAL, {"method": "GET"}) == 2.0
    assert m.get_counter(API_REQUEST_TOTAL, {"method": "POST"}) == 1.0


def test_metrics_gauge():
    m = MetricsRegistry()
    m.gauge_set("runners", 5.0, {"pool": "web"})
    assert m.get_gauge("runners", {"pool": "web"}) == 5.0
    m.gauge_set("runners", 3.0, {"pool": "web"})
    assert m.get_gauge("runners", {"pool": "web"}) == 3.0


def test_metrics_histogram():
    m = MetricsRegistry()
    m.observe(API_REQUEST_DURATION, 0.5)
    m.observe(API_REQUEST_DURATION, 1.2)
    assert m.get_histogram_count(API_REQUEST_DURATION) == 2


def test_metrics_timer():
    m = MetricsRegistry()
    with m.timer("test_timer"):
        pass
    assert m.get_histogram_count("test_timer") == 1


def test_metrics_snapshot():
    m = MetricsRegistry()
    m.increment("req_total")
    m.gauge_set("active", 3.0)
    m.observe("latency", 0.1)
    snap = m.snapshot()
    assert "counters" in snap
    assert "gauges" in snap
    assert "histograms" in snap


def test_metrics_labels_sanitized():
    m = MetricsRegistry()
    m.increment("x", labels={"method": "GET", "secret_token": "bad"})
    assert m.get_counter("x", {"method": "GET"}) == 1.0


def test_audit_event_create():
    tid = uuid4()
    rid = uuid4()
    trace = TraceContext()
    event = AuditEvent.create(
        tenant_id=tid,
        event_type="action.approved",
        actor="approver@test",
        resource_type="action",
        resource_id=rid,
        details={"reason": "safe"},
        trace=trace,
    )
    assert event.tenant_id == tid
    assert event.event_type == "action.approved"
    assert event.trace_id == trace.trace_id
    assert event.details == {"reason": "safe"}


def test_audit_event_sanitizes_details():
    event = AuditEvent.create(
        tenant_id=uuid4(),
        event_type="test",
        actor="op",
        resource_type="engagement",
        resource_id=uuid4(),
        details={"action": "start", "password": "hunter2"},
    )
    assert "action" in event.details
    assert "password" not in event.details


def test_structured_logger_creates():
    logger = StructuredLogger("test")
    logger.info("hello", count=5)


def test_structured_logger_with_context():
    ctx = LogContext(tenant_hash="abc")
    logger = StructuredLogger("test", ctx)
    child = logger.with_context(ctx.with_action(uuid4()))
    assert child is not None
