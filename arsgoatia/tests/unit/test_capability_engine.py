"""Capability equivalence + eligibility (§18)."""

from __future__ import annotations

from module_sdk.capability import (
    EligibilityRule,
    capabilities_equivalent,
    is_expired,
    module_eligible,
)


def _cap(**over):
    base = dict(
        capability_type="read_object",
        access_context_id="ctx-1",
        subject_identity_id="A",
        target_asset_id="asset-1",
        privilege="standard_user",
        scope_revision=1,
        policy_revision=1,
        validation_state="proven",
        label="read_foreign_object",
    )
    base.update(over)
    return base


def test_equivalence_requires_all_dimensions():
    assert capabilities_equivalent(_cap(), _cap()) is True
    assert capabilities_equivalent(_cap(), _cap(target_asset_id="asset-2")) is False
    assert capabilities_equivalent(_cap(), _cap(scope_revision=2)) is False
    assert capabilities_equivalent(_cap(), _cap(policy_revision=2)) is False


def test_expiry_conditions():
    cap = _cap()
    assert is_expired(cap, session_active=True, target_in_scope=True, finding_disproven=False, revision_invalidated=False) is False
    assert is_expired(cap, session_active=False, target_in_scope=True, finding_disproven=False, revision_invalidated=False) is True
    assert is_expired(cap, session_active=True, target_in_scope=False, finding_disproven=False, revision_invalidated=False) is True
    assert is_expired(cap, session_active=True, target_in_scope=True, finding_disproven=True, revision_invalidated=False) is True


def test_module_eligibility_by_capability():
    rule = EligibilityRule(module_id="next.module", required_capabilities=["read_foreign_object"])
    ok, _ = module_eligible(rule, [_cap()], context_state="active")
    assert ok is True
    # Missing capability -> ineligible.
    no, reason = module_eligible(rule, [], context_state="active")
    assert no is False and "missing_capabilities" in reason
    # Wrong context state -> ineligible.
    no2, reason2 = module_eligible(rule, [_cap()], context_state="expired")
    assert no2 is False and "context_state" in reason2
