"""Layered policy engine (§13.1-13.3).

evaluate() runs the policy layers and returns the MOST RESTRICTIVE decision
(deny > require_approval > allow_with_limits > allow). It is fail-closed: any
missing/unverified/expired authorization, out-of-scope target, missing policy
rules, or evaluation error yields DENY. AI never touches this path.

Pure: takes an ActionRequest and a RevisionContext (both plain data) and returns
a PolicyDecision, so the full decision matrix is unit-testable without a DB.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from schemas.common import Decision, RiskClass
from schemas.policy import EnforcedLimits, PolicyDecision


@dataclass
class ActionRequest:
    risk_class: RiskClass
    module_id: str
    mutation: bool = False
    target_destinations: list[str] = field(default_factory=list)


@dataclass
class RevisionContext:
    authorization_verified: bool
    authorization_expired: bool
    scope_ok: bool
    policy_rules: dict
    environment: str = "lab"
    production_default_deny_mutation: bool = True


def _most_restrictive(decisions: list[Decision]) -> Decision:
    return max(decisions, key=lambda d: d.restrictiveness)


def evaluate(action: ActionRequest, ctx: RevisionContext) -> PolicyDecision:
    # --- Fail-closed hard gates (§13.4, §8.3) ------------------------------
    if not ctx.authorization_verified:
        return PolicyDecision.denied("authorization_not_verified")
    if ctx.authorization_expired:
        return PolicyDecision.denied("authorization_expired")
    if not ctx.scope_ok:
        return PolicyDecision.denied("out_of_scope")
    rules = ctx.policy_rules or {}
    matrix = rules.get("risk_class_decisions")
    if not matrix:
        return PolicyDecision.denied("no_policy_rules")

    # --- Layer: risk-class base decision (assessment/module policy) --------
    base_raw = matrix.get(action.risk_class.value)
    if base_raw is None:
        return PolicyDecision.denied("risk_class_not_permitted")
    try:
        base = Decision(base_raw)
    except ValueError:
        return PolicyDecision.denied("invalid_policy_decision")

    layer_decisions = [base]

    # --- Layer: environment policy ----------------------------------------
    if action.mutation and ctx.environment == "production" and ctx.production_default_deny_mutation:
        layer_decisions.append(Decision.DENY)

    # R5 is prohibited by default regardless of matrix (defense in depth).
    if action.risk_class is RiskClass.R5:
        layer_decisions.append(Decision.DENY)

    decision = _most_restrictive(layer_decisions)

    # --- Assemble limits + approval class ---------------------------------
    limits_raw = rules.get("limits", {})
    enforced = EnforcedLimits(
        max_requests=int(limits_raw.get("max_requests", 0)),
        max_rps=float(limits_raw.get("max_rps", 0)),
        max_concurrency=int(limits_raw.get("max_concurrency", 1)),
        max_runtime_seconds=int(limits_raw.get("max_runtime_seconds", 0)),
        max_mutations=int(limits_raw.get("max_mutations", 0)),
        allowed_destinations=list(action.target_destinations),
        allowed_methods=list(limits_raw.get("allowed_methods", [])),
    )
    approval_class = None
    if decision is Decision.REQUIRE_APPROVAL:
        approval_class = (rules.get("required_approval_class", {}) or {}).get(
            action.risk_class.value, "normal"
        )

    reason_codes = [f"risk:{action.risk_class.value}", f"decision:{decision.value}"]
    return PolicyDecision(
        decision=decision,
        reason_codes=reason_codes,
        applied_policy_refs=[rules.get("profile", "lab-safe")],
        required_approval_class=approval_class,
        enforced_limits=enforced,
        cleanup_required=bool(rules.get("cleanup_required", False)),
    )
