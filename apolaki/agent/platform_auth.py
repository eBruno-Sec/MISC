"""
Platform authentication gate.

Apolaki is LOCAL-ONLY by default: no platform token is required and nothing changes. To prepare for
more than one local user or an explicit external bind, set APOLAKI_API_TOKEN — every request then
needs a matching `X-Apolaki-Token` header (or `Authorization: Bearer <token>`), except a small
allowlist (health check, API docs, the UI shell). Comparison is constant-time.

Pure gate logic (unit-tested); main.py wires it as a thin middleware.
"""
from __future__ import annotations

import hmac
import os

# paths always reachable without the token: liveness, API schema/docs, the UI shell + its assets.
_ALLOWLIST = {"/health", "/", "/openapi.json", "/docs", "/redoc", "/favicon.ico"}
_ALLOW_PREFIXES = ("/ui", "/static", "/assets")


def required() -> bool:
    """True only when an operator has set a platform token (opt-in hardening)."""
    return bool(os.environ.get("APOLAKI_API_TOKEN"))


def is_exempt(path: str) -> bool:
    p = (path or "").rstrip("/") or "/"
    return p in _ALLOWLIST or path in _ALLOWLIST or any(path.startswith(x) for x in _ALLOW_PREFIXES)


def check(provided: str) -> bool:
    """Constant-time token check. When no token is configured, always allow (local-only default)."""
    expected = os.environ.get("APOLAKI_API_TOKEN")
    if not expected:
        return True
    return hmac.compare_digest(str(provided or ""), str(expected))


def token_from_headers(headers) -> str:
    """Extract the presented token from X-Apolaki-Token or an Authorization: Bearer header."""
    try:
        t = headers.get("x-apolaki-token")
        if t:
            return t
        auth = headers.get("authorization") or ""
        if auth.lower().startswith("bearer "):
            return auth[7:]
    except Exception:
        pass
    return ""


def authorize(path: str, headers, query_token: str = None) -> bool:
    """The whole decision for one request: allowed if the platform is open, the path is exempt, or a
    valid token was presented (via header, or a `token` query param for EventSource which cannot set
    headers)."""
    if not required() or is_exempt(path):
        return True
    return check(token_from_headers(headers) or (query_token or ""))
