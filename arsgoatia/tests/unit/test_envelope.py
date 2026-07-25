"""Signed action envelope + approval binding (§13.5-13.6)."""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest

from policy.envelope import (
    approval_matches_envelope,
    build_binding,
    compute_signature,
    sign,
    verify,
)
from schemas.action_envelope import ActionBudget, ActionEnvelope, Actor, ActorKind, EnvelopeTarget
from schemas.common import RiskClass, utcnow
from schemas.policy import EnforcedLimits

KEY = "dev-signing-key"


def _envelope(**over) -> ActionEnvelope:
    aid = uuid4()
    base = dict(
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
        approval_ref=uuid4(),
        budget=ActionBudget(max_requests=8, max_rps=2.0, timeout_seconds=30, max_bytes=1_048_576),
        idempotency_key="idor-1",
        expires_at=utcnow() + timedelta(minutes=5),
    )
    base.update(over)
    return ActionEnvelope(**base)


def test_sign_then_verify_ok():
    env = sign(_envelope(), KEY)
    ok, reason = verify(env, KEY)
    assert ok is True and reason == "ok"


def test_tamper_any_field_fails():
    env = sign(_envelope(), KEY)
    # Mutate the resolved destination after signing.
    tampered = env.model_copy(
        update={
            "targets": [
                EnvelopeTarget(asset_id=env.targets[0].asset_id, resolved_destination="evil:80")
            ]
        }
    )
    ok, reason = verify(tampered, KEY)
    assert ok is False and reason == "bad_signature"


def test_wrong_key_fails():
    env = sign(_envelope(), KEY)
    ok, reason = verify(env, "other-key")
    assert ok is False and reason == "bad_signature"


def test_expired_fails():
    env = sign(_envelope(expires_at=utcnow() - timedelta(seconds=1)), KEY)
    ok, reason = verify(env, KEY)
    assert ok is False and reason == "expired"


def test_revision_drift_rejected():
    env = sign(_envelope(assessment_revision=1), KEY)
    ok, reason = verify(env, KEY, expected_revision=2)
    assert ok is False and reason == "revision_drift"


def test_approval_binding_matches_only_its_action():
    env = sign(_envelope(), KEY)
    limits = EnforcedLimits(max_requests=8, allowed_methods=["GET"])
    binding = build_binding(
        env,
        action_class="authorization.object_level",
        enforced_limits=limits,
        expires_at=utcnow() + timedelta(minutes=5),
    )
    binding.granted = True
    ok, reason = approval_matches_envelope(binding, env)
    assert ok is True and reason == "ok"

    # A different action (new approval_ref/targets) must not match.
    other = sign(_envelope(), KEY)
    ok2, reason2 = approval_matches_envelope(binding, other)
    assert ok2 is False


def test_ungranted_approval_never_matches():
    env = sign(_envelope(), KEY)
    limits = EnforcedLimits()
    binding = build_binding(
        env,
        action_class="x",
        enforced_limits=limits,
        expires_at=utcnow() + timedelta(minutes=5),
    )
    # granted defaults to None -> not a positive approval.
    ok, reason = approval_matches_envelope(binding, env)
    assert ok is False and reason == "approval_not_granted"


def test_signature_is_deterministic():
    env = _envelope()
    assert compute_signature(env, KEY) == compute_signature(env, KEY)
