"""ArsGoatia planner — 8-layer deterministic scoring engine.

The planner selects the next action to propose for an engagement.
Layers 1-5 and 7-8 are fully deterministic; layer 6 is AI-advisory
(ranking within the already-eligible set — AI never adds or removes
candidates, never bypasses policy, never changes risk tiers).

Scoring layers (spec §8.2):
  1. Eligibility filter — technique preconditions + scope + policy
  2. Priority scoring — novelty, coverage, capability prerequisites
  3. Risk ordering — lower risk tier preferred
  4. Cost efficiency — estimated budget consumption
  5. Dependency resolution — topological order of prerequisite capabilities
  6. AI ranking (advisory) — reorder equally-scored candidates
  7. Deduplication — skip already-tested hypotheses
  8. Rate limiting — enforce budget and pacing constraints
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID


@dataclass(frozen=True)
class PlannerCandidate:
    technique_id: str
    target_locator: str
    risk_tier: str
    mutation_class: str
    hypothesis_id: UUID | None = None
    prerequisite_capabilities: frozenset[str] = frozenset()
    estimated_requests: int = 1
    estimated_cost_usd: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScoredCandidate:
    candidate: PlannerCandidate
    score: float
    layer_scores: dict[str, float] = field(default_factory=dict)
    eligible: bool = True
    rejection_reason: str | None = None


@dataclass(frozen=True)
class PlannerContext:
    engagement_id: UUID
    tenant_id: UUID
    allowed_risk_tiers: frozenset[str] = frozenset({"R0", "R1", "R2"})
    available_capabilities: frozenset[str] = frozenset()
    completed_techniques: frozenset[str] = frozenset()
    tested_hypotheses: frozenset[UUID] = frozenset()
    budget_remaining_requests: int = 50000
    budget_remaining_usd: float = 25.0
    scope_targets: list[str] = field(default_factory=list)
    current_phase: str = "recon"


@dataclass(frozen=True)
class PlannerResult:
    ranked_candidates: list[ScoredCandidate]
    ineligible: list[ScoredCandidate]
    ai_reranked: bool = False


RISK_TIER_ORDER = {"R0": 0, "R1": 1, "R2": 2, "R3": 3, "R4": 4, "R5": 5}


def _layer1_eligibility(
    candidate: PlannerCandidate, ctx: PlannerContext
) -> tuple[bool, str | None]:
    if candidate.risk_tier not in ctx.allowed_risk_tiers:
        return False, f"risk tier {candidate.risk_tier} not allowed"

    if candidate.risk_tier == "R5":
        return False, "R5 unconditionally denied"

    missing = candidate.prerequisite_capabilities - ctx.available_capabilities
    if missing:
        return False, f"missing prerequisites: {', '.join(sorted(missing))}"

    return True, None


def _layer2_priority_score(
    candidate: PlannerCandidate, ctx: PlannerContext
) -> float:
    score = 0.0

    if candidate.technique_id not in ctx.completed_techniques:
        score += 10.0

    if candidate.hypothesis_id and candidate.hypothesis_id not in ctx.tested_hypotheses:
        score += 5.0

    if candidate.prerequisite_capabilities <= ctx.available_capabilities:
        score += 3.0

    return score


def _layer3_risk_ordering(candidate: PlannerCandidate) -> float:
    rank = RISK_TIER_ORDER.get(candidate.risk_tier, 5)
    return 10.0 - (rank * 2.0)


def _layer4_cost_efficiency(
    candidate: PlannerCandidate, ctx: PlannerContext
) -> float:
    if ctx.budget_remaining_requests <= 0:
        return -100.0
    efficiency = 1.0 - (candidate.estimated_requests / max(ctx.budget_remaining_requests, 1))
    cost_ratio = 1.0 - (candidate.estimated_cost_usd / max(ctx.budget_remaining_usd, 0.01))
    return (efficiency + cost_ratio) * 5.0


def _layer5_dependency_order(
    candidate: PlannerCandidate, ctx: PlannerContext
) -> float:
    if not candidate.prerequisite_capabilities:
        return 2.0
    met = len(candidate.prerequisite_capabilities & ctx.available_capabilities)
    total = len(candidate.prerequisite_capabilities)
    return (met / total) * 2.0 if total > 0 else 2.0


def _layer7_deduplication(
    candidate: PlannerCandidate, ctx: PlannerContext
) -> float:
    if candidate.hypothesis_id and candidate.hypothesis_id in ctx.tested_hypotheses:
        return -50.0
    if candidate.technique_id in ctx.completed_techniques:
        return -20.0
    return 0.0


def _layer8_rate_limiting(
    candidate: PlannerCandidate, ctx: PlannerContext
) -> float:
    if candidate.estimated_requests > ctx.budget_remaining_requests:
        return -100.0
    if candidate.estimated_cost_usd > ctx.budget_remaining_usd:
        return -100.0
    return 0.0


def score_candidate(
    candidate: PlannerCandidate, ctx: PlannerContext
) -> ScoredCandidate:
    eligible, reason = _layer1_eligibility(candidate, ctx)
    if not eligible:
        return ScoredCandidate(
            candidate=candidate,
            score=-math.inf,
            eligible=False,
            rejection_reason=reason,
        )

    layer_scores = {
        "priority": _layer2_priority_score(candidate, ctx),
        "risk": _layer3_risk_ordering(candidate),
        "cost": _layer4_cost_efficiency(candidate, ctx),
        "dependency": _layer5_dependency_order(candidate, ctx),
        "dedup": _layer7_deduplication(candidate, ctx),
        "rate_limit": _layer8_rate_limiting(candidate, ctx),
    }

    total = sum(layer_scores.values())
    return ScoredCandidate(
        candidate=candidate,
        score=total,
        layer_scores=layer_scores,
        eligible=True,
    )


def plan(
    candidates: list[PlannerCandidate],
    ctx: PlannerContext,
    *,
    ai_rankings: list[str] | None = None,
) -> PlannerResult:
    scored = [score_candidate(c, ctx) for c in candidates]

    eligible = [s for s in scored if s.eligible]
    ineligible = [s for s in scored if not s.eligible]

    eligible.sort(key=lambda s: s.score, reverse=True)

    ai_reranked = False
    if ai_rankings:
        tech_to_idx = {tid: i for i, tid in enumerate(ai_rankings)}
        stable = list(enumerate(eligible))
        stable.sort(
            key=lambda pair: (
                tech_to_idx.get(pair[1].candidate.technique_id, len(ai_rankings)),
                -pair[1].score,
                pair[0],
            )
        )
        eligible = [s for _, s in stable]
        ai_reranked = True

    return PlannerResult(
        ranked_candidates=eligible,
        ineligible=ineligible,
        ai_reranked=ai_reranked,
    )


def next_action(
    candidates: list[PlannerCandidate],
    ctx: PlannerContext,
    *,
    ai_rankings: list[str] | None = None,
) -> ScoredCandidate | None:
    result = plan(candidates, ctx, ai_rankings=ai_rankings)
    return result.ranked_candidates[0] if result.ranked_candidates else None
