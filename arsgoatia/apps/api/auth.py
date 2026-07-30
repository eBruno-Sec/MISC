"""JWT + optional TOTP MFA for the API.

Dev-friendly: a JWT is optional; when neither an ``Authorization: Bearer``
header nor a legacy ``X-Auth-User`` header is set, the API still falls
back to a ``dev-operator/admin`` context. This keeps local Compose usable
without a login step while giving deployed instances a real token flow.

MFA is optional per user (a TOTP secret is bootstrapped from the env
``ARSGOATIA_OPERATOR_TOTP_SECRET``); if configured, operations that
require MFA (R3+ approvals) must present a fresh ``X-MFA-Code`` header
that verifies against the current TOTP window. If no TOTP secret is
configured, MFA is skipped — that mode is intentional for dev.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import time
from typing import Any


class AuthError(Exception):
    pass


# ---------------------------------------------------------------------------
# JWT (HS256, deliberately minimal — no external deps)
# ---------------------------------------------------------------------------


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _signing_key() -> bytes:
    key = os.environ.get(
        "ARSGOATIA_JWT_SECRET",
        os.environ.get("ARSGOATIA_SIGNING_KEY", "dev-signing-key-change-in-production"),
    )
    return key.encode()


def issue_token(*, user: str, role: str, tenant_id: str, ttl_seconds: int = 3600) -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user,
        "role": role,
        "tenant_id": tenant_id,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    header_seg = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_seg = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_seg}.{payload_seg}".encode()
    sig = hmac.new(_signing_key(), signing_input, hashlib.sha256).digest()
    sig_seg = _b64url_encode(sig)
    return f"{header_seg}.{payload_seg}.{sig_seg}"


def verify_token(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthError("malformed token")
    header_seg, payload_seg, sig_seg = parts
    try:
        header = json.loads(_b64url_decode(header_seg))
    except Exception as exc:
        raise AuthError("bad header") from exc
    if header.get("alg") != "HS256":
        raise AuthError(f"unsupported alg {header.get('alg')!r}")
    signing_input = f"{header_seg}.{payload_seg}".encode()
    expected = hmac.new(_signing_key(), signing_input, hashlib.sha256).digest()
    try:
        got = _b64url_decode(sig_seg)
    except Exception as exc:
        raise AuthError("bad signature encoding") from exc
    if not hmac.compare_digest(expected, got):
        raise AuthError("signature mismatch")
    try:
        payload = json.loads(_b64url_decode(payload_seg))
    except Exception as exc:
        raise AuthError("bad payload") from exc
    if int(payload.get("exp", 0)) < int(time.time()):
        raise AuthError("token expired")
    return payload


# ---------------------------------------------------------------------------
# TOTP (RFC 6238, 30-second window, SHA-1, 6 digits)
# ---------------------------------------------------------------------------


def _totp_at(secret: str, timestamp: float) -> str:
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    counter = int(timestamp // 30)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (
        (digest[offset] & 0x7F) << 24
        | (digest[offset + 1] & 0xFF) << 16
        | (digest[offset + 2] & 0xFF) << 8
        | (digest[offset + 3] & 0xFF)
    ) % 1_000_000
    return f"{code:06d}"


def verify_totp(code: str, *, secret: str, window: int = 1) -> bool:
    now = time.time()
    for step in range(-window, window + 1):
        if hmac.compare_digest(code, _totp_at(secret, now + step * 30)):
            return True
    return False


def operator_totp_secret() -> str | None:
    return os.environ.get("ARSGOATIA_OPERATOR_TOTP_SECRET") or None


def require_mfa_for(role: str, risk_tier: str) -> bool:
    """Return True if the given (role, tier) combination requires MFA."""
    if risk_tier in ("R3", "R4", "R5"):
        return True
    return False
