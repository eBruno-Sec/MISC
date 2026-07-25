"""Proof-of-concept rendering and header redaction.

Ported from olympus/backend/core/poc.py. Pure functions over plain dicts: no DB,
no network. Sensitive headers are masked so a reproduction shows that auth is
required without leaking the session/token — the redaction guarantee behind
"AI never sees raw secrets" and "evidence is redacted by default".
"""

from __future__ import annotations

from shlex import quote
from urllib.parse import urlparse

SENSITIVE_HEADERS = {
    "cookie",
    "authorization",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
    "x-csrf-token",
}
REDACTED = "<redacted>"

# httpx adds these; curl / the raw request set them itself.
_SKIP_CURL_HEADERS = {"host", "content-length"}


def redact_headers(headers: dict) -> dict:
    """Mask credential-bearing header values while keeping the header names."""
    out = {}
    for k, v in (headers or {}).items():
        out[k] = REDACTED if str(k).lower() in SENSITIVE_HEADERS else v
    return out


def to_curl(ex: dict, redact: bool = True) -> str:
    """Render a captured exchange as a copy-pasteable curl command."""
    method = (ex.get("method") or "GET").upper()
    url = ex.get("url") or ""
    headers = ex.get("request_headers") or {}
    if redact:
        headers = redact_headers(headers)
    parts = ["curl -i -sk"]
    if method != "GET":
        parts.append("-X " + method)
    for k, v in headers.items():
        if str(k).lower() in _SKIP_CURL_HEADERS:
            continue
        parts.append("-H " + quote(f"{k}: {v}"))
    body = ex.get("request_body")
    if body:
        parts.append("--data " + quote(body))
    parts.append(quote(url))
    return " ".join(parts)


def to_raw_http(ex: dict, redact: bool = True) -> str:
    """Render a captured exchange as a raw HTTP/1.1 request block."""
    method = (ex.get("method") or "GET").upper()
    url = ex.get("url") or ""
    p = urlparse(url)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    headers = ex.get("request_headers") or {}
    if redact:
        headers = redact_headers(headers)
    lines = [f"{method} {path} HTTP/1.1"]
    if p.netloc:
        lines.append(f"Host: {p.netloc}")
    for k, v in headers.items():
        if str(k).lower() == "host":
            continue
        lines.append(f"{k}: {v}")
    body = ex.get("request_body") or ""
    return ("\n".join(lines) + "\n\n" + body).rstrip()
