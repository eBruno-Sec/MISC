"""PoC rendering + redaction (ported olympus poc.py)."""

from __future__ import annotations

from evidence.poc import redact_headers, to_curl, to_raw_http

_EX = {
    "method": "GET",
    "url": "http://juice-shop:3000/rest/basket/2",
    "request_headers": {
        "Authorization": "Bearer eyJhbGci.secret.token",
        "Cookie": "token=abc",
        "User-Agent": "arsgoatia",
    },
}


def test_redact_masks_sensitive_headers_only():
    red = redact_headers(_EX["request_headers"])
    assert red["Authorization"] == "<redacted>"
    assert red["Cookie"] == "<redacted>"
    assert red["User-Agent"] == "arsgoatia"


def test_curl_and_raw_never_leak_token():
    curl = to_curl(_EX)
    raw = to_raw_http(_EX)
    assert "secret.token" not in curl
    assert "secret.token" not in raw
    assert "<redacted>" in curl
    assert "/rest/basket/2" in raw
