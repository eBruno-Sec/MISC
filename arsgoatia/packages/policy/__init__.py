"""ArsGoatia deterministic policy engine.

Every action request is evaluated against the engagement's rules,
authorization, scope, time window, and budget.  The engine is fully
deterministic -- AI never participates in policy decisions.

Principles:
- Fail closed: missing data => DENY.
- Most restrictive wins across layers.
- R5 always denied.  R4 denied by default.
- R3 requires at least one human approval.
- R0/R1 auto-allowed when all other checks pass.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from packages.contracts.schemas.common import DecisionOutcome, RiskTier
from packages.contracts.schemas.engagement import (
    AuthorizationSpec,
    BudgetSpec,
    RulesSpec,
    ScopeSpec,
)
from packages.contracts.schemas.policy import ActionRequest

# ---------------------------------------------------------------------------
# Policy context -- everything the engine needs to decide
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyContext:
    """Immutable snapshot of everything the engine needs to decide."""

    authorization: AuthorizationSpec | None = None
    scope: ScopeSpec | None = None
    rules: RulesSpec | None = None
    budget: BudgetSpec | None = None
    current_time: datetime | None = None
    budget_consumed_requests: int = 0
    budget_consumed_usd: float = 0.0
    is_in_scope: bool | None = None  # pre-computed by scope engine


# ---------------------------------------------------------------------------
# Decision result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyResult:
    outcome: DecisionOutcome
    reason: str
    layers_evaluated: list[str]
    most_restrictive_layer: str | None = None


# ---------------------------------------------------------------------------
# Individual evaluation layers
# ---------------------------------------------------------------------------


def _evaluate_risk_tier(request: ActionRequest) -> tuple[DecisionOutcome | None, str]:
    """R5 always deny, R4 deny by default."""
    if request.risk_tier == RiskTier.R5:
        return DecisionOutcome.deny, "R5 actions are unconditionally denied"
    if request.risk_tier == RiskTier.R4:
        return DecisionOutcome.deny, "R4 actions denied by default"
    return None, ""


def _evaluate_authorization(ctx: PolicyContext) -> tuple[DecisionOutcome | None, str]:
    """Authorization must be present and not expired."""
    if ctx.authorization is None:
        return DecisionOutcome.deny, "missing authorization data -- fail closed"
    now = ctx.current_time or datetime.now(timezone.utc)
    if now > ctx.authorization.valid_until:
        return DecisionOutcome.deny, "authorization has expired"
    if now < ctx.authorization.valid_from:
        return DecisionOutcome.deny, "authorization not yet valid"
    return None, ""


def _evaluate_scope(ctx: PolicyContext) -> tuple[DecisionOutcome | None, str]:
    """Target must be in scope."""
    if ctx.is_in_scope is None:
        return DecisionOutcome.deny, "scope check result missing -- fail closed"
    if not ctx.is_in_scope:
        return DecisionOutcome.deny, "target is out of scope"
    return None, ""


def _evaluate_time_window(ctx: PolicyContext) -> tuple[DecisionOutcome | None, str]:
    """If authorization has a time window, current_time must be in it."""
    if ctx.authorization is None:
        return DecisionOutcome.deny, "missing authorization for time window check"
    now = ctx.current_time or datetime.now(timezone.utc)
    if now < ctx.authorization.valid_from or now > ctx.authorization.valid_until:
        return DecisionOutcome.deny, "outside authorized time window"
    return None, ""


def _evaluate_budget(ctx: PolicyContext) -> tuple[DecisionOutcome | None, str]:
    """Budget must not be exceeded."""
    if ctx.budget is None:
        return None, ""  # no budget constraint
    if ctx.budget.requests is not None and ctx.budget_consumed_requests >= ctx.budget.requests:
        return DecisionOutcome.deny, "request budget exceeded"
    if ctx.budget.ai_cost_usd is not None and ctx.budget_consumed_usd >= ctx.budget.ai_cost_usd:
        return DecisionOutcome.deny, "AI cost budget exceeded"
    return None, ""


def _evaluate_approval_requirements(
    request: ActionRequest, ctx: PolicyContext
) -> tuple[DecisionOutcome | None, str]:
    """Determine if approval is needed based on risk tier and rules."""
    if ctx.rules is None:
        return DecisionOutcome.deny, "missing rules -- fail closed"

    # Check the approval mapping from the rules
    if request.risk_tier in ctx.rules.approval_mapping:
        mapped_decision = ctx.rules.approval_mapping[request.risk_tier]
        if mapped_decision == DecisionOutcome.require_approval:
            return DecisionOutcome.require_approval, (
                f"R{request.risk_tier.value} requires approval per rules"
            )
        if mapped_decision == DecisionOutcome.deny:
            return DecisionOutcome.deny, f"R{request.risk_tier.value} denied by rules"
        return None, ""

    # Default approval requirements by risk tier
    if request.risk_tier == RiskTier.R3:
        return (
            DecisionOutcome.require_approval,
            "R3 requires at least one human approval",
        )
    if request.risk_tier in (RiskTier.R0, RiskTier.R1):
        return DecisionOutcome.allow, "R0/R1 auto-allowed"
    return None, ""


# ---------------------------------------------------------------------------
# Main evaluation
# ---------------------------------------------------------------------------

_LAYERS = [
    ("risk_tier", lambda req, ctx: _evaluate_risk_tier(req)),
    ("authorization", lambda req, ctx: _evaluate_authorization(ctx)),
    ("scope", lambda req, ctx: _evaluate_scope(ctx)),
    ("time_window", lambda req, ctx: _evaluate_time_window(ctx)),
    ("budget", lambda req, ctx: _evaluate_budget(ctx)),
    ("approval", lambda req, ctx: _evaluate_approval_requirements(req, ctx)),
]


def evaluate(request: ActionRequest, ctx: PolicyContext) -> PolicyResult:
    """Evaluate *request* against all policy layers.

    Most-restrictive-wins: any DENY stops evaluation.  REQUIRE_APPROVAL
    is more restrictive than ALLOW.  If no layer yields a decision,
    the engine fails closed with DENY.
    """
    # Fail closed on missing critical data
    if ctx.authorization is None and ctx.rules is None:
        return PolicyResult(
            outcome=DecisionOutcome.deny,
            reason="missing critical policy data -- fail closed",
            layers_evaluated=["fail_closed"],
            most_restrictive_layer="fail_closed",
        )

    layers_evaluated: list[str] = []
    most_restrictive: DecisionOutcome = DecisionOutcome.allow
    most_restrictive_layer: str | None = None
    most_restrictive_reason: str = ""

    for layer_name, evaluator in _LAYERS:
        decision, reason = evaluator(request, ctx)
        layers_evaluated.append(layer_name)

        if decision is None:
            continue

        # DENY is most restrictive -- short-circuit
        if decision == DecisionOutcome.deny:
            return PolicyResult(
                outcome=DecisionOutcome.deny,
                reason=reason,
                layers_evaluated=layers_evaluated,
                most_restrictive_layer=layer_name,
            )

        # Track most restrictive non-deny decision
        if _restrictiveness(decision) > _restrictiveness(most_restrictive) or (
            most_restrictive_layer is None and decision is not None
        ):
            most_restrictive = decision
            most_restrictive_layer = layer_name
            most_restrictive_reason = reason

    # If we got through all layers with no explicit decision, fail closed
    if most_restrictive_layer is None:
        return PolicyResult(
            outcome=DecisionOutcome.deny,
            reason="no layer yielded an explicit allow -- fail closed",
            layers_evaluated=layers_evaluated,
            most_restrictive_layer="default",
        )

    return PolicyResult(
        outcome=most_restrictive,
        reason=most_restrictive_reason,
        layers_evaluated=layers_evaluated,
        most_restrictive_layer=most_restrictive_layer,
    )


def _restrictiveness(outcome: DecisionOutcome) -> int:
    """Higher = more restrictive."""
    return {
        DecisionOutcome.allow: 0,
        DecisionOutcome.allow_with_limits: 1,
        DecisionOutcome.require_approval: 2,
        DecisionOutcome.deny: 3,
    }.get(outcome, 0)
