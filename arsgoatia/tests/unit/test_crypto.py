from __future__ import annotations

from packages.crypto import (
    NonceStore,
    canonical_json,
    compute_digest,
    request_spec_digest,
    sign_envelope,
    verify_envelope,
)


def test_sign_and_verify_envelope():
    payload = {"action": "test", "target": "example.test"}
    key = b"test-signing-key"
    sig = sign_envelope(payload, key)
    assert verify_envelope(payload, sig, key)


def test_tampered_envelope_fails_verification():
    payload = {"action": "test", "target": "example.test"}
    key = b"test-signing-key"
    sig = sign_envelope(payload, key)
    tampered = {"action": "test", "target": "evil.test"}
    assert not verify_envelope(tampered, sig, key)


def test_canonical_json_deterministic():
    a = canonical_json({"z": 1, "a": 2, "m": {"y": 3, "b": 4}})
    b = canonical_json({"m": {"b": 4, "y": 3}, "a": 2, "z": 1})
    assert a == b


def test_compute_digest_sha256():
    d = compute_digest(b"hello")
    assert d.startswith("sha256:")
    assert len(d) == 71


def test_nonce_replay_detection():
    store = NonceStore()
    nonce = store.generate()
    assert not store.check_and_record(nonce)
    fresh = "new-nonce-value"
    assert store.check_and_record(fresh)
    assert not store.check_and_record(fresh)


def test_request_spec_digest_deterministic():
    spec = {"method": "GET", "url": "https://example.test/api"}
    d1 = request_spec_digest(spec)
    d2 = request_spec_digest(spec)
    assert d1 == d2
    assert d1.startswith("sha256:")


def test_different_key_fails_verification():
    payload = {"action": "test"}
    key1 = b"key-one"
    key2 = b"key-two"
    sig = sign_envelope(payload, key1)
    assert not verify_envelope(payload, sig, key2)
