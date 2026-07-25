"""Signed action envelope (§13.5) and approval binding (§13.6).

Dev signing is HMAC-SHA256 over the canonical JSON of every field except the
signature, keyed from SESSION_SECRET (ADR 0003 notes the prod swap to KMS /
asymmetric — the shape and verify path are identical). The executor calls
verify() before any target-facing action; a tamper of any field, an expired
envelope, or an approval-binding mismatch fails closed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime
from uuid import UUID

from schemas.action_envelope import ActionEnvelope, ApprovalBinding
from schemas.common import utcnow
from schemas.policy import EnforcedLimits


def _canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _signing_payload(envelope: ActionEnvelope) -> dict:
    data = envelope.model_dump(mode="json")
    data.pop("signature", None)
    return data


def compute_signature(envelope: ActionEnvelope, key: str) -> str:
    return hmac.new(
        key.encode("utf-8"), _canonical_bytes(_signing_payload(envelope)), hashlib.sha256
    ).hexdigest()


def sign(envelope: ActionEnvelope, key: str) -> ActionEnvelope:
    """Return a copy of the envelope with a valid signature."""
    return envelope.model_copy(update={"signature": compute_signature(envelope, key)})


def verify(
    envelope: ActionEnvelope,
    key: str,
    *,
    now: datetime | None = None,
    expected_revision: int | None = None,
    expected_policy_revision: int | None = None,
) -> tuple[bool, str]:
    """Fail-closed verification. Returns (ok, reason)."""
    if not envelope.signature:
        return False, "missing_signature"
    expected = compute_signature(envelope, key)
    if not hmac.compare_digest(expected, envelope.signature):
        return False, "bad_signature"
    if envelope.is_expired(now):
        return False, "expired"
    if expected_revision is not None and envelope.assessment_revision != expected_revision:
        return False, "revision_drift"
    if (
        expected_policy_revision is not None
        and envelope.policy_revision != expected_policy_revision
    ):
        return False, "policy_revision_drift"
    return True, "ok"


def limits_hash(limits: EnforcedLimits) -> str:
    """Stable hash of enforced limits, used to bind an approval to exact limits."""
    return hashlib.sha256(_canonical_bytes(limits.model_dump(mode="json"))).hexdigest()


def approval_matches_envelope(binding: ApprovalBinding, envelope: ActionEnvelope) -> tuple[bool, str]:
    """Verify an approval binds to THIS action (§13.6): exact targets, context,
    revisions, and limits. A generic approval never matches."""
    if binding.granted is not True:
        return False, "approval_not_granted"
    if binding.approval_ref != envelope.approval_ref:
        return False, "approval_ref_mismatch"
    if binding.context_id != envelope.origin_context_id:
        return False, "context_mismatch"
    if binding.assessment_revision != envelope.assessment_revision:
        return False, "revision_mismatch"
    if binding.policy_revision != envelope.policy_revision:
        return False, "policy_revision_mismatch"
    env_target_ids = {t.asset_id for t in envelope.targets}
    if set(binding.target_ids) != env_target_ids:
        return False, "target_mismatch"
    if binding.expires_at is not None and utcnow() >= binding.expires_at:
        return False, "approval_expired"
    return True, "ok"


def build_binding(
    envelope: ActionEnvelope,
    *,
    action_class: str,
    enforced_limits: EnforcedLimits,
    expires_at: datetime,
    mutation_allowance: int = 0,
    cleanup_required: bool = False,
) -> ApprovalBinding:
    """Create the approval binding an operator must grant for this exact action."""
    assert envelope.approval_ref is not None, "envelope needs an approval_ref"
    return ApprovalBinding(
        approval_ref=envelope.approval_ref,
        action_class=action_class,
        target_ids=[t.asset_id for t in envelope.targets],
        context_id=envelope.origin_context_id,
        assessment_revision=envelope.assessment_revision,
        policy_revision=envelope.policy_revision,
        enforced_limits_hash=limits_hash(enforced_limits),
        mutation_allowance=mutation_allowance,
        cleanup_required=cleanup_required,
        expires_at=expires_at,
    )
