"""Deterministic planner (§11.4) + advisory AI ranking (§11.5)."""

from __future__ import annotations

from planner.planner import plan
from schemas.common import RiskClass
from schemas.planner import ActionProposal


def _p(module_id, risk=RiskClass.R2, cost=10, gains=None, ctx="ctx-1", targets=None):
    return ActionProposal(
        module_id=module_id,
        module_version="1.0.0",
        context_id=ctx,
        target_ids=targets or ["t1"],
        estimated_risk_class=risk,
        estimated_cost_requests=cost,
        expected_gains=gains or [],
    )


def test_drops_prohibited_r5_and_over_budget():
    proposals = [
        _p("mod.ok", cost=5),
        _p("mod.r5", risk=RiskClass.R5, cost=1),
        _p("mod.expensive", cost=1000),
    ]
    decision = plan(proposals, budget_remaining_requests=100)
    ids = [p.module_id for p in decision.ranked_proposals]
    assert "mod.ok" in ids
    assert "mod.r5" not in ids
    assert "mod.expensive" not in ids
    assert any("prohibited_r5" in d for d in decision.dropped)
    assert any("over_budget" in d for d in decision.dropped)


def test_deduplicates_same_action():
    proposals = [_p("mod.a"), _p("mod.a")]  # same module+context+targets
    decision = plan(proposals, budget_remaining_requests=100)
    assert len(decision.ranked_proposals) == 1
    assert any("duplicate" in d for d in decision.dropped)


def test_scoring_is_deterministic_and_orders_by_value():
    high = _p("mod.high", gains=["capability read_foreign_object", "info"], cost=1)
    low = _p("mod.low", gains=[], cost=50)
    d1 = plan([low, high], budget_remaining_requests=100)
    d2 = plan([high, low], budget_remaining_requests=100)
    assert [p.module_id for p in d1.ranked_proposals] == [p.module_id for p in d2.ranked_proposals]
    assert d1.ranked_proposals[0].module_id == "mod.high"
    assert d1.ranking_source == "deterministic"


def test_ai_ranker_may_reorder_same_set_only():
    a, b = _p("mod.a", ctx="c1", targets=["x"]), _p("mod.b", ctx="c2", targets=["y"])
    # Valid reorder -> applied.
    d = plan([a, b], budget_remaining_requests=100, ai_ranker=lambda ids: list(reversed(ids)))
    assert d.ranking_source == "ai_advisory"
    # Invalid set (adds an id) -> ignored, stays deterministic.
    d2 = plan([a, b], budget_remaining_requests=100, ai_ranker=lambda ids: ids + ["mod.injected"])
    assert d2.ranking_source == "deterministic"
