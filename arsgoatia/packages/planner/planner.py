"""Deterministic planner (§11.4 layers 1-5, 7, 8) with an optional advisory AI
ranking (layer 6). The safety-relevant filtering is deterministic; AI can only
reorder the already-eligible set (§11.5)."""

from __future__ import annotations

from typing import Callable

from planner.scoring import SCORING_VERSION, priority
from schemas.common import RiskClass
from schemas.planner import ActionProposal, PlannerDecision

# A ranker takes the ordered ids and may return a reordering of the SAME id set.
AIRanker = Callable[[list[str]], list[str] | None]


def _dedupe_key(p: ActionProposal) -> tuple:
    return (p.module_id, p.context_id, tuple(sorted(p.target_ids)))


def _features(p: ActionProposal) -> dict[str, float]:
    # Deterministic feature derivation from the proposal. Expected gains raise
    # information/impact; cost lowers priority; higher risk adds mutation risk.
    return {
        "information_gain": float(len(p.expected_gains)),
        "impact_gain": 1.0 if p.estimated_risk_class.rank >= RiskClass.R2.rank else 0.0,
        "chain_unlock_value": 1.0 if "capability" in " ".join(p.expected_gains).lower() else 0.0,
        "execution_cost": float(p.estimated_cost_requests) / 100.0,
        "mutation_risk": float(max(0, p.estimated_risk_class.rank - RiskClass.R2.rank)),
    }


def plan(
    proposals: list[ActionProposal],
    *,
    budget_remaining_requests: int,
    ai_ranker: AIRanker | None = None,
) -> PlannerDecision:
    dropped: list[str] = []

    # Layer 1-2: eligibility + scope/policy — prohibited-by-default (R5) removed.
    eligible = []
    for p in proposals:
        if p.estimated_risk_class is RiskClass.R5:
            dropped.append(f"{p.module_id}:prohibited_r5")
            continue
        eligible.append(p)

    # Layer 3: budget filter.
    within_budget = []
    for p in eligible:
        if p.estimated_cost_requests > budget_remaining_requests:
            dropped.append(f"{p.module_id}:over_budget")
            continue
        within_budget.append(p)

    # Layer 4: dedupe.
    seen: set[tuple] = set()
    deduped: list[ActionProposal] = []
    for p in within_budget:
        k = _dedupe_key(p)
        if k in seen:
            dropped.append(f"{p.module_id}:duplicate")
            continue
        seen.add(k)
        deduped.append(p)

    # Layer 5: priority scoring (deterministic, versioned).
    for p in deduped:
        p.score = priority(_features(p))
    ranked = sorted(deduped, key=lambda p: p.score, reverse=True)
    ranking_source = "deterministic"

    # Layer 6: optional AI ranking — may only reorder the SAME set.
    if ai_ranker is not None and ranked:
        ids = [p.module_id for p in ranked]
        proposed = ai_ranker(ids)
        if proposed and set(proposed) == set(ids):
            order = {mid: i for i, mid in enumerate(proposed)}
            ranked = sorted(ranked, key=lambda p: order[p.module_id])
            ranking_source = "ai_advisory"

    # Layer 7-8: safety re-validation (no R5 survived) + scheduling order.
    assert all(p.estimated_risk_class is not RiskClass.R5 for p in ranked)

    return PlannerDecision(
        ranked_proposals=ranked,
        dropped=dropped,
        ranking_source=ranking_source,
        rationale=f"scoring={SCORING_VERSION}",
    )
