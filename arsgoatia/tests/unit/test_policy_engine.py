"""Layered policy engine (§13). Fail-closed + most-restrictive-wins."""

from __future__ import annotations

from domain.repositories import default_lab_safe_rules
from policy.engine import ActionRequest, RevisionContext, evaluate
from schemas.common import Decision, RiskClass


def _ctx(**over) -> RevisionContext:
    base = dict(
        authorization_verified=True,
        authorization_expired=False,
        scope_ok=True,
        policy_rules=default_lab_safe_rules(),
        environment="lab",
    )
    base.update(over)
    return RevisionContext(**base)


def _action(risk: RiskClass, mutation: bool = False) -> ActionRequest:
    return ActionRequest(risk_class=risk, module_id="web.authorization.idor", mutation=mutation)


def test_r1_recon_allowed_with_limits():
    d = evaluate(_action(RiskClass.R1), _ctx())
    assert d.decision is Decision.ALLOW_WITH_LIMITS
    assert d.enforced_limits.max_requests == 500


def test_r2_idor_requires_approval():
    d = evaluate(_action(RiskClass.R2), _ctx())
    assert d.decision is Decision.REQUIRE_APPROVAL
    assert d.required_approval_class == "normal"


def test_r4_and_r5_denied():
    assert evaluate(_action(RiskClass.R4), _ctx()).decision is Decision.DENY
    assert evaluate(_action(RiskClass.R5), _ctx()).decision is Decision.DENY


def test_fail_closed_without_authorization():
    d = evaluate(_action(RiskClass.R1), _ctx(authorization_verified=False))
    assert d.decision is Decision.DENY
    assert "authorization_not_verified" in d.reason_codes


def test_fail_closed_out_of_scope_and_expired():
    assert evaluate(_action(RiskClass.R1), _ctx(scope_ok=False)).decision is Decision.DENY
    assert (
        evaluate(_action(RiskClass.R1), _ctx(authorization_expired=True)).decision is Decision.DENY
    )


def test_fail_closed_without_rules():
    assert evaluate(_action(RiskClass.R1), _ctx(policy_rules={})).decision is Decision.DENY


def test_production_mutation_denied_even_if_matrix_would_allow():
    # A matrix that would allow R2, but production + mutation + deny-mutation wins.
    rules = default_lab_safe_rules()
    rules["risk_class_decisions"]["R2"] = "allow_with_limits"
    d = evaluate(
        _action(RiskClass.R2, mutation=True),
        _ctx(policy_rules=rules, environment="production", production_default_deny_mutation=True),
    )
    assert d.decision is Decision.DENY
