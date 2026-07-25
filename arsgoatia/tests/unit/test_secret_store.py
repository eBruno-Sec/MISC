"""Secret store helpers + encryption round-trip (§10 secret handling, ADR 0003)."""

from __future__ import annotations

import pytest

from secrets_store.store import decrypt, encrypt, fingerprint, make_uri, parse_uri


def test_fingerprint_is_sha256_and_stable():
    fp = fingerprint("Bearer abc.def.ghi")
    assert len(fp) == 64
    assert fp == fingerprint("Bearer abc.def.ghi")
    assert fp != fingerprint("other")


def test_uri_round_trip():
    uri = make_uri("abc-123")
    assert uri == "secret://abc-123"
    assert parse_uri(uri) == "abc-123"


def test_parse_uri_rejects_non_secret():
    with pytest.raises(ValueError):
        parse_uri("http://not-a-secret")


def test_encrypt_decrypt_round_trip_and_hides_plaintext():
    token = "eyJhbGciOi.SECRETJWT.sig"
    ct = encrypt(token)
    assert token not in ct  # ciphertext (or base64) does not contain the raw token
    assert decrypt(ct) == token
