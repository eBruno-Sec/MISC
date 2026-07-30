"""Deterministic constraint solver (spec §1.3, §8.4, §11.3, §18).

Rejects any candidate action that violates scope, testing window, rate limits,
data-handling rules, mutation/safety restrictions, required approval, or risk
class. Fail-closed: any violation, missing input, or ambiguity rejects the
action. No LLM is involved; every decision is a pure function of the candidate
and the engagement constraints, so it is fully replayable and auditable.

This is the standalone "eliminate invalid plans" stage the planner (packages/
planner) feeds through before utility ranking.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from scope.firewall import ScopeFirewall

_SENSITIVITY_RANK = {"public": 0, "internal": 1, "confidential": 2, "regulated": 3, "secret": 4}
_RISK_RANK = {"R0": 0, "R1": 1, "R2": 2, "R3": 3, "R4": 4, "R5": 5}


@dataclass
class ActionCandidate:
    action_class: str
    destination: str  # host or host:port the action would hit
    risk_class: str = "R1"
    mutation: bool = False
    estimated_requests: int = 1
    estimated_rps: float = 1.0
    data_sensitivity: str = "internal"
    requires_approval: bool = False
    approval_present: bool = False
    at_time: datetime | None = None


@dataclass
class ConstraintContext:
    firewall: ScopeFirewall
    window_start: datetime | None = None
    window_end: datetime | None = None
    max_rps: float = 2.0
    max_requests_remaining: int = 500
    allow_mutation: bool = False
    max_data_sensitivity: str = "confidential"
    max_risk_class: str = "R4"  # R5 is prohibited by default regardless
    now: datetime | None = None


@dataclass
class ConstraintResult:
    satisfied: bool
    violations: list[str] = field(default_factory=list)


class ConstraintSolver:
    """Runs every constraint and rejects on ANY violation (fail-closed)."""

    def check(self, candidate: ActionCandidate, ctx: ConstraintContext) -> ConstraintResult:
        v: list[str] = []

        # Scope (deny-overrides-allow, arg-injection guard live in the firewall).
        if not ctx.firewall.preflight(candidate.destination, []).allowed:
            v.append("scope")

        # Risk class: R5 prohibited by default; otherwise must not exceed the cap.
        cr = _RISK_RANK.get(candidate.risk_class)
        cap = _RISK_RANK.get(ctx.max_risk_class, 4)
        if cr is None:
            v.append("risk_class_unknown")
        elif candidate.risk_class == "R5" or cr > cap:
            v.append("risk_class")

        # Testing window.
        if ctx.window_start is not None and ctx.window_end is not None:
            t = candidate.at_time or ctx.now
            if t is None:
                v.append("time_window_unknown")  # fail closed when a window is set
            elif not (ctx.window_start <= t <= ctx.window_end):
                v.append("time_window")

        # Rate + request budget.
        if candidate.estimated_rps > ctx.max_rps:
            v.append("rate_limit")
        if candidate.estimated_requests > ctx.max_requests_remaining:
            v.append("request_budget")

        # Mutation / destructive restriction.
        if candidate.mutation and not ctx.allow_mutation:
            v.append("mutation_not_allowed")

        # Data-handling limit.
        ds = _SENSITIVITY_RANK.get(candidate.data_sensitivity)
        maxds = _SENSITIVITY_RANK.get(ctx.max_data_sensitivity, 2)
        if ds is None:
            v.append("data_sensitivity_unknown")
        elif ds > maxds:
            v.append("data_sensitivity")

        # Required approval must be present and bound.
        if candidate.requires_approval and not candidate.approval_present:
            v.append("approval_required")

        return ConstraintResult(satisfied=not v, violations=v)

    def filter(
        self, candidates: list[ActionCandidate], ctx: ConstraintContext
    ) -> tuple[list[ActionCandidate], list[tuple[ActionCandidate, list[str]]]]:
        """Partition candidates into (allowed, rejected-with-reasons)."""
        allowed: list[ActionCandidate] = []
        rejected: list[tuple[ActionCandidate, list[str]]] = []
        for c in candidates:
            result = self.check(c, ctx)
            if result.satisfied:
                allowed.append(c)
            else:
                rejected.append((c, result.violations))
        return allowed, rejected
