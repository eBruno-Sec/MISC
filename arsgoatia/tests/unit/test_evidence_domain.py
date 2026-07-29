from __future__ import annotations

from uuid import uuid4

from packages.domain.evidence import (
    compute_digest,
    contains_secret_marker,
    redact_headers,
    storage_key,
    to_curl,
    verify_digest,
)


def test_compute_and_verify_digest():
    data = b"test evidence payload"
    digest = compute_digest(data)
    assert digest.startswith("sha256:")
    assert verify_digest(data, digest)


def test_verify_digest_rejects_tampered():
    data = b"original"
    digest = compute_digest(data)
    assert not verify_digest(b"tampered", digest)


def test_storage_key_format():
    tid = uuid4()
    digest = "sha256:deadbeef0123456789abcdef"
    key = storage_key(tid, digest)
    assert str(tid) in key
    assert "sha256" in key
    assert "de" in key


def test_redact_headers():
    headers = {
        "Authorization": "Bearer secret-token-123",
        "Content-Type": "application/json",
        "Cookie": "session=abc123",
        "X-Custom": "safe-value",
    }
    redacted = redact_headers(headers)
    assert redacted["Authorization"] == "[REDACTED]"
    assert redacted["Cookie"] == "[REDACTED]"
    assert redacted["Content-Type"] == "application/json"
    assert redacted["X-Custom"] == "safe-value"


def test_contains_secret_marker():
    assert contains_secret_marker("Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig")
    assert contains_secret_marker("Basic dXNlcjpwYXNz")
    assert not contains_secret_marker("application/json")


def test_to_curl_basic():
    cmd = to_curl(
        method="GET",
        url="https://api.example.test/v1/users",
        headers={"Accept": "application/json"},
    )
    assert "curl" in cmd
    assert "https://api.example.test/v1/users" in cmd
    assert "-X GET" in cmd


def test_to_curl_redacts_sensitive():
    cmd = to_curl(
        method="POST",
        url="https://api.example.test",
        headers={"Authorization": "Bearer secret", "Content-Type": "application/json"},
        body='{"key": "value"}',
    )
    assert "[REDACTED]" in cmd
    assert "secret" not in cmd
