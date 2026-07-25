"""Outbox and audit row builders (pure, no database)."""

from __future__ import annotations

from uuid import uuid4

from audit.audit import build_audit_row
from events.outbox import build_outbox_row
from schemas.events import EventEnvelope, EventType


def _envelope() -> EventEnvelope:
    aid = uuid4()
    return EventEnvelope(
        event_type=EventType.SCOPE_COMPILED,
        tenant_id=uuid4(),
        assessment_id=aid,
        assessment_revision=1,
        policy_revision=1,
        aggregate_type="assessment",
        aggregate_id=aid,
        producer="api",
        correlation_id=uuid4(),
        payload={"targets": ["juice-shop:3000"]},
    ).finalized()


def test_outbox_row_carries_event_and_envelope():
    env = _envelope()
    row = build_outbox_row(env)
    assert row.event_id == str(env.event_id)
    assert row.event_type == "ScopeCompiled"
    assert row.tenant_id == str(env.tenant_id)
    assert row.envelope["payload_hash"] == env.payload_hash
    assert row.dispatched_at is None


def test_outbox_row_finalizes_unhashed_envelope():
    # An envelope passed without a hash is finalized during row build.
    env = _envelope().model_copy(update={"payload_hash": ""})
    row = build_outbox_row(env)
    assert row.envelope["payload_hash"] != ""


def test_audit_row_maps_envelope():
    env = _envelope()
    row = build_audit_row(env)
    assert row.event_type == "ScopeCompiled"
    assert row.aggregate_type == "assessment"
    assert row.payload_hash == env.payload_hash
    assert row.payload == {"targets": ["juice-shop:3000"]}
