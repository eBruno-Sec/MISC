from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import pytest

from packages.testing import (
    UUIDFactory,
    assert_audit_recorded,
    assert_event_emitted,
    assert_no_secrets_in_dict,
    build_action,
    build_engagement,
    build_envelope,
    build_evidence_data,
    build_finding,
    build_hypothesis,
    build_scope_rule,
    fresh_uuid,
    hours_ago,
    hours_from_now,
    minutes_from_now,
    sequential_uuid,
    utcnow,
)


def test_uuid_factory_sequential():
    f = UUIDFactory(start=100)
    a = f.next()
    b = f.next()
    assert a != b
    assert a.int == 100
    assert b.int == 101


def test_fresh_uuid():
    a = fresh_uuid()
    b = fresh_uuid()
    assert isinstance(a, UUID)
    assert a != b


def test_sequential_uuid_explicit():
    u = sequential_uuid(42)
    assert u.int == 42


def test_utcnow():
    now = utcnow()
    assert now.tzinfo is not None
    assert now.tzinfo == timezone.utc


def test_hours_ago():
    past = hours_ago(2)
    now = utcnow()
    assert past < now


def test_hours_from_now():
    future = hours_from_now(2)
    now = utcnow()
    assert future > now


def test_minutes_from_now():
    future = minutes_from_now(30)
    now = utcnow()
    assert future > now


def test_build_engagement_defaults():
    e = build_engagement()
    assert e["state"] == "draft"
    assert isinstance(e["id"], UUID)
    assert e["name"] == "test-engagement"
    assert "sha256:" in e["authorization_artifact_digest"]


def test_build_engagement_overrides():
    e = build_engagement(name="custom", state="running")
    assert e["name"] == "custom"
    assert e["state"] == "running"


def test_build_action_defaults():
    a = build_action()
    assert a["state"] == "proposed"
    assert a["risk_tier"] == "R2"
    assert a["technique_id"] == "web.authz.bola.differential"


def test_build_scope_rule():
    r = build_scope_rule(rule_type="cidr", value="10.0.0.0/24")
    assert r["type"] == "cidr"
    assert r["value"] == "10.0.0.0/24"
    assert r["action"] == "allow"


def test_build_envelope():
    env = build_envelope(effectiveRiskTier="R3")
    assert env["effectiveRiskTier"] == "R3"
    assert "actionId" in env
    assert "expiresAt" in env


def test_build_evidence_data():
    data, mt = build_evidence_data("test content", "text/plain")
    assert data == b"test content"
    assert mt == "text/plain"


def test_build_hypothesis():
    h = build_hypothesis(state="TESTABLE")
    assert h["state"] == "TESTABLE"
    assert h["category"] == "authorization.object_level"


def test_build_finding():
    f = build_finding(severity="critical")
    assert f["severity"] == "critical"
    assert f["cwe"] == "CWE-639"


class _FakeEvent:
    def __init__(self, event_type, **kwargs):
        self.event_type = event_type
        self.payload = kwargs


def test_assert_event_emitted_success():
    events = [_FakeEvent("action.proposed", technique="bola")]
    assert_event_emitted(events, "action.proposed")


def test_assert_event_emitted_with_payload_check():
    events = [_FakeEvent("action.proposed", technique="bola")]
    assert_event_emitted(events, "action.proposed", technique="bola")


def test_assert_event_emitted_fails():
    events = [_FakeEvent("other")]
    with pytest.raises(AssertionError):
        assert_event_emitted(events, "action.proposed")


class _FakeAudit:
    def __init__(self, action, resource_type):
        self.action = action
        self.resource_type = resource_type


def test_assert_audit_recorded():
    entries = [_FakeAudit("create_engagement", "engagement")]
    assert_audit_recorded(entries, "create_engagement", "engagement")


def test_assert_no_secrets_clean():
    assert_no_secrets_in_dict({"user": "alice", "count": 5})


def test_assert_no_secrets_catches_jwt():
    with pytest.raises(AssertionError, match="possible secret"):
        assert_no_secrets_in_dict({"token_value": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"})


def test_assert_no_secrets_nested():
    with pytest.raises(AssertionError, match="possible secret"):
        assert_no_secrets_in_dict({"outer": {"auth": "Bearer eyJhbGciOiJIUzI1NiJ9.x.y"}})


def test_assert_no_secrets_in_list():
    with pytest.raises(AssertionError, match="possible secret"):
        assert_no_secrets_in_dict({"items": ["Bearer eyJhbGciOiJIUzI1NiJ9.x.y"]})
