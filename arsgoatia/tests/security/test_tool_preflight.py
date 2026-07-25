"""Tool SDK preflight gate (§21, §10.11): the executor re-verifies the envelope
and re-runs the scope firewall — queue routing is not authorization."""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

from policy.envelope import sign
from policy.scope_firewall import ScopeFirewall
from schemas.action_envelope import ActionBudget, ActionEnvelope, Actor, ActorKind, EnvelopeTarget
from schemas.common import RiskClass, utcnow
from schemas.tool_io import ToolRequest
from tool_sdk.http_client import preflight_verify

KEY = "dev-key"


def _request(destination="juice-shop:3000", expires_delta=300, key=KEY):
    env = ActionEnvelope(
        tenant_id=uuid4(),
        assessment_id=uuid4(),
        assessment_revision=1,
        policy_revision=1,
        module_id="web.authorization.idor",
        module_version="1.0.0",
        actor=Actor(kind=ActorKind.SYSTEM, id="validation"),
        origin_context_id=uuid4(),
        targets=[EnvelopeTarget(asset_id=uuid4(), resolved_destination=destination)],
        requested_effect="differential_read",
        risk_class=RiskClass.R2,
        approval_ref=uuid4(),
        budget=ActionBudget(max_requests=1, max_rps=2.0, timeout_seconds=20, max_bytes=1024),
        idempotency_key="k",
        expires_at=utcnow() + timedelta(seconds=expires_delta),
    )
    signed = sign(env, key)
    return ToolRequest(tool_id="http_differential", tool_version="1.0.0", action_envelope=signed)


def _fw():
    return ScopeFirewall.from_targets([{"value": "juice-shop:3000", "disposition": "include"}])


def test_valid_envelope_in_scope_passes():
    ok, reason = preflight_verify(_request(), signing_key=KEY, firewall=_fw())
    assert ok is True and reason == "ok"


def test_wrong_signing_key_denied():
    req = _request(key="attacker-key")
    ok, reason = preflight_verify(req, signing_key=KEY, firewall=_fw())
    assert ok is False and reason.startswith("envelope:")


def test_out_of_scope_destination_denied():
    req = _request(destination="evil.example.com:443")
    ok, reason = preflight_verify(req, signing_key=KEY, firewall=_fw())
    assert ok is False and reason.startswith("scope:")


def test_expired_envelope_denied():
    req = _request(expires_delta=-1)
    ok, reason = preflight_verify(req, signing_key=KEY, firewall=_fw())
    assert ok is False and reason == "envelope:expired"


def test_revision_drift_denied():
    ok, reason = preflight_verify(
        _request(), signing_key=KEY, firewall=_fw(), expected_revision=99
    )
    assert ok is False and reason == "envelope:revision_drift"
