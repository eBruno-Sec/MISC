"""Contract-model unit tests (M0 acceptance).

These lock the invariants the rest of the platform relies on: risk ordering,
policy restrictiveness ordering, deterministic event hashing, envelope expiry,
and round-trip fidelity of the domain value objects.
"""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

from schemas.action_envelope import (
    ActionBudget,
    ActionEnvelope,
    Actor,
    ActorKind,
    EnvelopeTarget,
)
from schemas.common import Decision, RiskClass, utcnow
from schemas.domain import Capability, CapabilityType, Finding
from schemas.events import EventEnvelope, EventType, payload_hash
from schemas.policy import PolicyDecision


def test_risk_class_rank_is_ordered():
    order = [RiskClass.R0, RiskClass.R1, RiskClass.R2, RiskClass.R3, RiskClass.R4, RiskClass.R5]
    assert [r.rank for r in order] == [0, 1, 2, 3, 4, 5]
    assert RiskClass.R2.rank < RiskClass.R3.rank


def test_decision_restrictiveness_is_ordered():
    assert Decision.ALLOW.restrictiveness < Decision.ALLOW_WITH_LIMITS.restrictiveness
    assert Decision.ALLOW_WITH_LIMITS.restrictiveness < Decision.REQUIRE_APPROVAL.restrictiveness
    assert Decision.REQUIRE_APPROVAL.restrictiveness < Decision.DENY.restrictiveness
    # Most restrictive across a layer set wins.
    layers = [Decision.ALLOW, Decision.REQUIRE_APPROVAL, Decision.ALLOW_WITH_LIMITS]
    assert max(layers, key=lambda d: d.restrictiveness) is Decision.REQUIRE_APPROVAL


def test_policy_decision_defaults_closed():
    # A bare PolicyDecision denies; the fail-closed default.
    assert PolicyDecision().decision is Decision.DENY
    denied = PolicyDecision.denied("no_authorization", "scope_ambiguous")
    assert denied.decision is Decision.DENY
    assert denied.reason_codes == ["no_authorization", "scope_ambiguous"]


def test_payload_hash_is_deterministic_and_key_order_independent():
    a = {"b": 2, "a": 1, "nested": {"y": 2, "x": 1}}
    b = {"a": 1, "nested": {"x": 1, "y": 2}, "b": 2}
    assert payload_hash(a) == payload_hash(b)


def test_event_envelope_finalized_sets_hash():
    tid, aid = uuid4(), uuid4()
    ev = EventEnvelope(
        event_type=EventType.SCOPE_COMPILED,
        tenant_id=tid,
        assessment_id=aid,
        assessment_revision=1,
        policy_revision=1,
        aggregate_type="assessment",
        aggregate_id=aid,
        producer="control-plane",
        correlation_id=uuid4(),
        payload={"targets": ["juice-shop:3000"]},
    )
    assert ev.payload_hash == ""
    final = ev.finalized()
    assert final.payload_hash == payload_hash({"targets": ["juice-shop:3000"]})
    # Frozen model: finalizing returns a copy, original is unchanged.
    assert ev.payload_hash == ""


def _envelope(expires_delta_seconds: int) -> ActionEnvelope:
    aid = uuid4()
    return ActionEnvelope(
        tenant_id=uuid4(),
        assessment_id=aid,
        assessment_revision=1,
        policy_revision=1,
        module_id="web.authorization.idor",
        module_version="1.0.0",
        actor=Actor(kind=ActorKind.AGENT, id="planner"),
        origin_context_id=uuid4(),
        targets=[EnvelopeTarget(asset_id=uuid4(), resolved_destination="juice-shop:3000")],
        requested_effect="differential_read",
        risk_class=RiskClass.R2,
        budget=ActionBudget(max_requests=8, max_rps=2.0, timeout_seconds=30, max_bytes=1_048_576),
        idempotency_key="idor-1",
        expires_at=utcnow() + timedelta(seconds=expires_delta_seconds),
    )


def test_action_envelope_expiry():
    assert _envelope(-5).is_expired() is True
    assert _envelope(60).is_expired() is False


def test_finding_and_capability_roundtrip():
    aid = uuid4()
    finding = Finding(assessment_id=aid, internal_class="authorization.object_level")
    dumped = finding.model_dump()
    assert Finding.model_validate(dumped).internal_class == "authorization.object_level"

    cap = Capability(
        assessment_id=aid,
        capability_type=CapabilityType.READ_OBJECT,
        access_context_id=uuid4(),
        label="read_foreign_object",
    )
    assert cap.capability_type is CapabilityType.READ_OBJECT
    assert cap.label == "read_foreign_object"
