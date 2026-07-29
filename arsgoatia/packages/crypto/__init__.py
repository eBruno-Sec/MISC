"""ArsGoatia cryptographic primitives.

Provides envelope signing/verification, canonical JSON serialisation,
content-addressed digests, and nonce replay detection.

All functions are deterministic and side-effect-free (except the
nonce store, which is an in-memory set for fast replay checks).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from collections import OrderedDict
from typing import Any


# ---------------------------------------------------------------------------
# Canonical JSON
# ---------------------------------------------------------------------------


def canonical_json(obj: Any) -> bytes:
    """Produce a deterministic JSON byte-string.

    Keys are sorted recursively, no whitespace, unicode escaped.
    """
    return json.dumps(
        _sort_keys_recursive(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _sort_keys_recursive(obj: Any) -> Any:
    if isinstance(obj, dict):
        return OrderedDict(
            sorted((k, _sort_keys_recursive(v)) for k, v in obj.items())
        )
    if isinstance(obj, (list, tuple)):
        return [_sort_keys_recursive(item) for item in obj]
    return obj


# ---------------------------------------------------------------------------
# Digests
# ---------------------------------------------------------------------------


def compute_digest(data: bytes, algorithm: str = "sha256") -> str:
    """Return ``algorithm:hex_digest`` for *data*."""
    if algorithm != "sha256":
        raise ValueError(f"unsupported algorithm: {algorithm}")
    digest = hashlib.sha256(data).hexdigest()
    return f"sha256:{digest}"


def request_spec_digest(spec: dict[str, Any]) -> str:
    """Content-addressed digest of a request specification."""
    return compute_digest(canonical_json(spec))


# ---------------------------------------------------------------------------
# HMAC-based envelope signing / verification
# ---------------------------------------------------------------------------


def sign_envelope(payload: dict[str, Any], key: bytes) -> str:
    """Sign *payload* with HMAC-SHA256 using *key*.

    Returns the hex-encoded signature.
    """
    canon = canonical_json(payload)
    return hmac.new(key, canon, hashlib.sha256).hexdigest()


def verify_envelope(payload: dict[str, Any], signature: str, key: bytes) -> bool:
    """Verify the HMAC-SHA256 signature of *payload*."""
    expected = sign_envelope(payload, key)
    return hmac.compare_digest(expected, signature)


# ---------------------------------------------------------------------------
# Nonce replay detection
# ---------------------------------------------------------------------------


class NonceStore:
    """Simple in-memory nonce store for replay detection.

    Production deployments should back this with Redis or a database
    with TTL-based eviction.
    """

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def check_and_record(self, nonce: str) -> bool:
        """Return True if the nonce is fresh (not seen before).

        Returns False if the nonce was already recorded (replay).
        """
        if nonce in self._seen:
            return False
        self._seen.add(nonce)
        return True

    def generate(self) -> str:
        """Generate a cryptographically random nonce and record it."""
        nonce = secrets.token_hex(16)
        self._seen.add(nonce)
        return nonce
