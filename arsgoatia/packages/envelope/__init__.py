"""ArsGoatia signed action envelope system.

Every target-facing action carries a signed envelope binding the action,
its target, the engagement revision it was authorized against, and its
expiry.  This module implements the envelope-level contract:

- Deterministic signing / verification (HMAC-SHA256 over canonical JSON).
- Structural field validation (fail-closed: missing/invalid fields are
  reported, never silently accepted).
- Nonce replay detection.
- Revocation-epoch fencing (an envelope minted before a revocation event
  must be rejected).
- Approval binding: cryptographically tying an envelope to the specific
  approval decisions that authorized it.

All checks here are deterministic and side-effect-free except
``check_nonce_replay``, which mutates the caller-supplied nonce store.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from packages.crypto import canonical_json, compute_digest, sign_envelope, verify_envelope

__all__ = [
    "sign_action_envelope",
    "verify_action_envelope",
    "validate_envelope_fields",
    "check_nonce_replay",
    "check_revocation_epoch",
    "bind_approval",
]


# ---------------------------------------------------------------------------
# Signing / verification
# ---------------------------------------------------------------------------


def _signable_payload(envelope_data: dict[str, Any]) -> dict[str, Any]:
    """Return *envelope_data* with the ``signature`` field excluded.

    The signature can never be part of what it signs -- canonicalisation
    happens over everything else in the envelope.
    """
    return {k: v for k, v in envelope_data.items() if k != "signature"}


def sign_action_envelope(envelope_data: dict[str, Any], signing_key: bytes) -> str:
    """Canonicalise *envelope_data* (excluding ``signature``) and sign it.

    Returns the hex-encoded HMAC-SHA256 signature.
    """
    payload = _signable_payload(envelope_data)
    return sign_envelope(payload, signing_key)


def verify_action_envelope(
    envelope_data: dict[str, Any], signature: str, signing_key: bytes
) -> bool:
    """Verify that *signature* matches *envelope_data* under *signing_key*.

    ``signature`` is compared against a freshly computed HMAC over the
    envelope with any ``signature`` field excluded, so this is safe to
    call with the raw envelope dict (signature field included or not).
    """
    payload = _signable_payload(envelope_data)
    return verify_envelope(payload, signature, signing_key)


# ---------------------------------------------------------------------------
# Structural field validation
# ---------------------------------------------------------------------------

_REQUIRED_PRESENCE_FIELDS = (
    "actionId",
    "tenantId",
    "engagementRevisionId",
    "technique",
    "target",
    "nonce",
    "effectiveRiskTier",
)


def _parse_timestamp(value: Any) -> datetime | None:
    """Best-effort parse of a timestamp field into an aware ``datetime``.

    Accepts ``datetime`` instances, ISO-8601 strings (with or without a
    trailing ``Z``), and numeric (epoch-seconds) values.  Returns ``None``
    if the value cannot be parsed.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    return None


def validate_envelope_fields(envelope: dict[str, Any]) -> list[str]:
    """Return a list of validation errors for *envelope* (empty = valid).

    Fail-closed: absence or malformation of any required field is an
    error, never a silently-accepted default.
    """
    errors: list[str] = []

    for field in _REQUIRED_PRESENCE_FIELDS:
        if envelope.get(field) in (None, ""):
            errors.append(f"missing required field: {field}")

    if "expiresAt" in envelope and envelope.get("expiresAt") not in (None, ""):
        expires_at = _parse_timestamp(envelope["expiresAt"])
        if expires_at is None:
            errors.append("expiresAt is not a valid timestamp")
        elif expires_at <= datetime.now(timezone.utc):
            errors.append("expiresAt is not in the future")

    return errors


# ---------------------------------------------------------------------------
# Nonce replay detection
# ---------------------------------------------------------------------------


def check_nonce_replay(nonce: str, store: set) -> bool:
    """Return True if *nonce* has already been seen (a replay).

    Always records *nonce* into *store* -- fresh nonces are added so a
    subsequent call with the same value correctly reports a replay.
    """
    if nonce in store:
        return True
    store.add(nonce)
    return False


# ---------------------------------------------------------------------------
# Revocation epoch fencing
# ---------------------------------------------------------------------------


def check_revocation_epoch(envelope_epoch: int, current_epoch: int) -> bool:
    """Return True if *envelope_epoch* is still valid.

    An envelope is valid only if it was minted at or after the current
    revocation epoch.  A revocation event bumps the current epoch, which
    fences out every envelope signed before it.
    """
    return envelope_epoch >= current_epoch


# ---------------------------------------------------------------------------
# Approval binding
# ---------------------------------------------------------------------------


def bind_approval(envelope: dict[str, Any], approval_decision_ids: list[str]) -> str:
    """Cryptographically bind *envelope* to the approval decisions.

    Computes a content-addressed sha256 digest over the envelope's
    action digest plus the sorted approval decision IDs, so the binding
    is stable regardless of decision-ID ordering.
    """
    action_digest = envelope.get("actionDigest", "")
    binding = {
        "actionDigest": action_digest,
        "decisionIds": sorted(approval_decision_ids),
    }
    return compute_digest(canonical_json(binding))
