"""Capability engine (§18).

Two capabilities are equivalent only when type, context, subject, target,
privilege, scope revision, and policy constraints all match. Capabilities expire
when their session/credential is revoked, the target leaves scope, the
environment changes, the finding is disproven, or a revision invalidates the
context. Module eligibility is checked against proven capabilities + contexts.

Pure functions — no I/O — so equivalence and eligibility are unit-testable.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CapabilityKey:
    capability_type: str
    context_id: str
    subject_identity_id: str | None
    target_asset_id: str | None
    privilege: str | None
    scope_revision: int
    policy_revision: int


def capability_key(cap: dict) -> CapabilityKey:
    return CapabilityKey(
        capability_type=cap.get("capability_type", ""),
        context_id=cap.get("access_context_id", ""),
        subject_identity_id=cap.get("subject_identity_id"),
        target_asset_id=cap.get("target_asset_id"),
        privilege=cap.get("privilege"),
        scope_revision=int(cap.get("scope_revision", 0)),
        policy_revision=int(cap.get("policy_revision", 0)),
    )


def capabilities_equivalent(a: dict, b: dict) -> bool:
    """§18 equivalence — a stricter equality than object identity."""
    return capability_key(a) == capability_key(b)


def is_expired(cap: dict, *, session_active: bool, target_in_scope: bool, finding_disproven: bool,
               revision_invalidated: bool) -> bool:
    """§18 expiry conditions."""
    if not session_active:
        return True
    if not target_in_scope:
        return True
    if finding_disproven:
        return True
    if revision_invalidated:
        return True
    return cap.get("validation_state") in {"expired", "revoked", "disproven"}


@dataclass
class EligibilityRule:
    module_id: str
    required_capabilities: list[str] = field(default_factory=list)
    required_context_state: str = "active"


def module_eligible(
    rule: EligibilityRule, proven_capabilities: list[dict], context_state: str
) -> tuple[bool, str]:
    """A module is eligible when its required capabilities are all present as
    proven capabilities and the context is in the required state (§18)."""
    if context_state != rule.required_context_state:
        return False, f"context_state={context_state}"
    have = {
        c.get("label") or c.get("capability_type")
        for c in proven_capabilities
        if c.get("validation_state") == "proven"
    }
    missing = [r for r in rule.required_capabilities if r not in have]
    if missing:
        return False, f"missing_capabilities={missing}"
    return True, "eligible"
