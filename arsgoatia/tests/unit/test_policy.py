from __future__ import annotations

from datetime import datetime, timezone, timedelta

from packages.contracts.schemas.common import DecisionOutcome, MutationClass, RiskTier
from packages.contracts.schemas.engagement import AuthorizationSpec, BudgetSpec, RulesSpec
from packages.contracts.schemas.policy import ActionRequest
from packages.policy import PolicyContext, evaluate


def _now():
    return datetime.now(timezone.utc)


def _auth(hours_valid=2):
    now = _now()
    return AuthorizationSpec(
        artifact_digest="sha256:abc",
        issuer="test@example.test",
        valid_from=now - timedelta(hours=1),
        valid_until=now + timedelta(hours=hours_valid),
    )


def _rules(approval_mapping=None):
    return RulesSpec(
        mode="active",
        allowed_risk_tiers=[RiskTier.R0, RiskTier.R1, RiskTier.R2, RiskTier.R3],
        approval_mapping=approval_mapping or {},
    )


def _budget(requests=1000, ai_cost=10.0):
    return BudgetSpec(requests=requests, ai_cost_usd=ai_cost)


def _request(risk_tier=RiskTier.R2):
    return ActionRequest(
        technique="web.authz.bola.differential",
        target="https://api.example.test/orders/1",
        risk_tier=risk_tier,
        mutation=MutationClass.none,
    )


def test_r5_always_denied():
    ctx = PolicyContext(authorization=_auth(), rules=_rules(), is_in_scope=True)
    result = evaluate(_request(RiskTier.R5), ctx)
    assert result.outcome == DecisionOutcome.deny
    assert "R5" in result.reason


def test_r4_denied_by_default():
    ctx = PolicyContext(authorization=_auth(), rules=_rules(), is_in_scope=True)
    result = evaluate(_request(RiskTier.R4), ctx)
    assert result.outcome == DecisionOutcome.deny


def test_expired_authorization_denied():
    auth = AuthorizationSpec(
        artifact_digest="sha256:abc",
        issuer="test@example.test",
        valid_from=_now() - timedelta(hours=48),
        valid_until=_now() - timedelta(hours=24),
    )
    ctx = PolicyContext(authorization=auth, rules=_rules(), is_in_scope=True)
    result = evaluate(_request(RiskTier.R0), ctx)
    assert result.outcome == DecisionOutcome.deny
    assert "expired" in result.reason


def test_out_of_scope_denied():
    ctx = PolicyContext(authorization=_auth(), rules=_rules(), is_in_scope=False)
    result = evaluate(_request(RiskTier.R0), ctx)
    assert result.outcome == DecisionOutcome.deny
    assert "scope" in result.reason.lower()


def test_outside_time_window_denied():
    auth = AuthorizationSpec(
        artifact_digest="sha256:abc",
        issuer="test@example.test",
        valid_from=_now() + timedelta(hours=24),
        valid_until=_now() + timedelta(hours=48),
    )
    ctx = PolicyContext(authorization=auth, rules=_rules(), is_in_scope=True)
    result = evaluate(_request(RiskTier.R0), ctx)
    assert result.outcome == DecisionOutcome.deny


def test_budget_exceeded_denied():
    ctx = PolicyContext(
        authorization=_auth(),
        rules=_rules(),
        budget=_budget(requests=100),
        budget_consumed_requests=100,
        is_in_scope=True,
    )
    result = evaluate(_request(RiskTier.R0), ctx)
    assert result.outcome == DecisionOutcome.deny
    assert "budget" in result.reason.lower()


def test_r2_requires_approval_per_rules():
    rules = _rules(approval_mapping={RiskTier.R2: DecisionOutcome.require_approval})
    ctx = PolicyContext(authorization=_auth(), rules=rules, is_in_scope=True)
    result = evaluate(_request(RiskTier.R2), ctx)
    assert result.outcome == DecisionOutcome.require_approval


def test_r0_r1_auto_allowed():
    ctx = PolicyContext(authorization=_auth(), rules=_rules(), is_in_scope=True)
    for tier in [RiskTier.R0, RiskTier.R1]:
        result = evaluate(_request(tier), ctx)
        assert result.outcome == DecisionOutcome.allow, f"{tier} should auto-allow"


def test_most_restrictive_wins():
    rules = _rules(approval_mapping={RiskTier.R2: DecisionOutcome.require_approval})
    ctx = PolicyContext(authorization=_auth(), rules=rules, is_in_scope=True)
    result = evaluate(_request(RiskTier.R2), ctx)
    assert result.outcome == DecisionOutcome.require_approval


def test_fail_closed_on_missing_data():
    ctx = PolicyContext()
    result = evaluate(_request(RiskTier.R0), ctx)
    assert result.outcome == DecisionOutcome.deny
    assert "fail closed" in result.reason.lower()


def test_r3_requires_one_person_approval():
    ctx = PolicyContext(authorization=_auth(), rules=_rules(), is_in_scope=True)
    result = evaluate(_request(RiskTier.R3), ctx)
    assert result.outcome == DecisionOutcome.require_approval
    assert "R3" in result.reason
