from __future__ import annotations

from datetime import datetime, timedelta, timezone

from packages.envelope import (
    bind_approval,
    check_nonce_replay,
    check_revocation_epoch,
    sign_action_envelope,
    validate_envelope_fields,
    verify_action_envelope,
)


def _envelope(**overrides):
    base = {
        "actionId": "action-001",
        "tenantId": "tenant-001",
        "engagementRevisionId": "rev-001",
        "technique": {"id": "web.authz.bola.differential", "version": "1.0.0"},
        "target": {"locator": "https://api.test/basket/1"},
        "effectiveRiskTier": "R2",
        "nonce": "unique-nonce-123",
        "expiresAt": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
    }
    base.update(overrides)
    return base


def test_sign_and_verify():
    env = _envelope()
    key = b"test-signing-key"
    sig = sign_action_envelope(env, key)
    assert verify_action_envelope(env, sig, key)


def test_tampered_envelope_fails():
    env = _envelope()
    key = b"test-signing-key"
    sig = sign_action_envelope(env, key)
    env["actionId"] = "tampered-action"
    assert not verify_action_envelope(env, sig, key)


def test_different_key_fails():
    env = _envelope()
    sig = sign_action_envelope(env, b"key-one")
    assert not verify_action_envelope(env, sig, b"key-two")


def test_validate_valid_envelope():
    env = _envelope()
    errors = validate_envelope_fields(env)
    assert errors == []


def test_validate_missing_fields():
    errors = validate_envelope_fields({})
    assert len(errors) > 0
    field_names = " ".join(errors)
    assert "actionId" in field_names
    assert "tenantId" in field_names


def test_validate_expired_envelope():
    env = _envelope(expiresAt=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat())
    errors = validate_envelope_fields(env)
    assert any("expir" in e.lower() for e in errors)


def test_nonce_replay():
    store: set[str] = set()
    assert not check_nonce_replay("nonce-1", store)
    assert check_nonce_replay("nonce-1", store)


def test_revocation_epoch_valid():
    assert check_revocation_epoch(42, 42)
    assert check_revocation_epoch(43, 42)


def test_revocation_epoch_invalid():
    assert not check_revocation_epoch(41, 42)


def test_bind_approval_deterministic():
    env = _envelope()
    env["actionDigest"] = "sha256:abc123"
    d1 = bind_approval(env, ["decision-a", "decision-b"])
    d2 = bind_approval(env, ["decision-b", "decision-a"])
    assert d1 == d2


def test_signature_excludes_signature_field():
    env = _envelope()
    key = b"test-key"
    sig1 = sign_action_envelope(env, key)
    env["signature"] = {"alg": "HMAC", "value": "old-sig"}
    sig2 = sign_action_envelope(env, key)
    assert sig1 == sig2
