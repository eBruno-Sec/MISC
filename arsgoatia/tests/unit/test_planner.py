"""Unit tests for the planner scoring engine."""

from __future__ import annotations

from uuid import uuid4

from packages.planner import (
    PlannerCandidate,
    PlannerContext,
    next_action,
    plan,
    score_candidate,
)


def _ctx(**kwargs) -> PlannerContext:
    defaults = dict(
        engagement_id=uuid4(),
        tenant_id=uuid4(),
    )
    defaults.update(kwargs)
    return PlannerContext(**defaults)


def _candidate(**kwargs) -> PlannerCandidate:
    defaults = dict(
        technique_id="web.authz.bola.differential",
        target_locator="https://api.test/basket/1",
        risk_tier="R2",
        mutation_class="none",
    )
    defaults.update(kwargs)
    return PlannerCandidate(**defaults)


class TestEligibilityFilter:
    def test_r5_always_ineligible(self):
        c = _candidate(risk_tier="R5")
        ctx = _ctx(allowed_risk_tiers=frozenset({"R0", "R1", "R2", "R3", "R4", "R5"}))
        result = score_candidate(c, ctx)
        assert not result.eligible
        assert "R5" in result.rejection_reason

    def test_disallowed_risk_tier(self):
        c = _candidate(risk_tier="R3")
        ctx = _ctx(allowed_risk_tiers=frozenset({"R0", "R1", "R2"}))
        result = score_candidate(c, ctx)
        assert not result.eligible

    def test_allowed_risk_tier(self):
        c = _candidate(risk_tier="R2")
        ctx = _ctx(allowed_risk_tiers=frozenset({"R0", "R1", "R2"}))
        result = score_candidate(c, ctx)
        assert result.eligible

    def test_missing_prerequisites(self):
        c = _candidate(
            prerequisite_capabilities=frozenset({"read_foreign_object", "session_hijack"})
        )
        ctx = _ctx(available_capabilities=frozenset({"read_foreign_object"}))
        result = score_candidate(c, ctx)
        assert not result.eligible
        assert "session_hijack" in result.rejection_reason

    def test_all_prerequisites_met(self):
        c = _candidate(prerequisite_capabilities=frozenset({"read_foreign_object"}))
        ctx = _ctx(available_capabilities=frozenset({"read_foreign_object"}))
        result = score_candidate(c, ctx)
        assert result.eligible


class TestPriorityScoring:
    def test_novel_technique_scores_higher(self):
        c_novel = _candidate(technique_id="novel")
        c_done = _candidate(technique_id="done")
        ctx = _ctx(completed_techniques=frozenset({"done"}))
        s_novel = score_candidate(c_novel, ctx)
        s_done = score_candidate(c_done, ctx)
        assert s_novel.score > s_done.score

    def test_untested_hypothesis_bonus(self):
        hid = uuid4()
        c_new = _candidate(hypothesis_id=hid)
        c_tested = _candidate(hypothesis_id=uuid4())
        ctx = _ctx(tested_hypotheses=frozenset({c_tested.hypothesis_id}))
        s_new = score_candidate(c_new, ctx)
        s_tested = score_candidate(c_tested, ctx)
        assert s_new.score > s_tested.score


class TestRiskOrdering:
    def test_lower_risk_preferred(self):
        c_r0 = _candidate(risk_tier="R0")
        c_r2 = _candidate(risk_tier="R2")
        ctx = _ctx(allowed_risk_tiers=frozenset({"R0", "R1", "R2"}))
        s_r0 = score_candidate(c_r0, ctx)
        s_r2 = score_candidate(c_r2, ctx)
        assert s_r0.layer_scores["risk"] > s_r2.layer_scores["risk"]


class TestCostEfficiency:
    def test_cheaper_action_scores_higher(self):
        c_cheap = _candidate(estimated_requests=10, estimated_cost_usd=0.01)
        c_expensive = _candidate(
            technique_id="expensive",
            estimated_requests=10000,
            estimated_cost_usd=10.0,
        )
        ctx = _ctx()
        s_cheap = score_candidate(c_cheap, ctx)
        s_exp = score_candidate(c_expensive, ctx)
        assert s_cheap.layer_scores["cost"] > s_exp.layer_scores["cost"]

    def test_over_budget_penalty(self):
        c = _candidate(estimated_requests=100)
        ctx = _ctx(budget_remaining_requests=50)
        result = score_candidate(c, ctx)
        assert result.layer_scores["rate_limit"] < 0


class TestDeduplication:
    def test_already_tested_hypothesis_penalty(self):
        hid = uuid4()
        c = _candidate(hypothesis_id=hid)
        ctx = _ctx(tested_hypotheses=frozenset({hid}))
        result = score_candidate(c, ctx)
        assert result.layer_scores["dedup"] < 0

    def test_completed_technique_penalty(self):
        c = _candidate(technique_id="done")
        ctx = _ctx(completed_techniques=frozenset({"done"}))
        result = score_candidate(c, ctx)
        assert result.layer_scores["dedup"] < 0


class TestPlanFunction:
    def test_plan_sorts_by_score(self):
        candidates = [
            _candidate(technique_id="low", risk_tier="R2", estimated_requests=5000),
            _candidate(technique_id="high", risk_tier="R0", estimated_requests=10),
        ]
        ctx = _ctx(allowed_risk_tiers=frozenset({"R0", "R1", "R2"}))
        result = plan(candidates, ctx)
        assert len(result.ranked_candidates) == 2
        assert result.ranked_candidates[0].candidate.technique_id == "high"

    def test_plan_separates_ineligible(self):
        candidates = [
            _candidate(technique_id="ok", risk_tier="R1"),
            _candidate(technique_id="bad", risk_tier="R5"),
        ]
        ctx = _ctx()
        result = plan(candidates, ctx)
        assert len(result.ranked_candidates) == 1
        assert len(result.ineligible) == 1
        assert result.ineligible[0].candidate.technique_id == "bad"

    def test_ai_rankings_reorder(self):
        candidates = [
            _candidate(technique_id="a", risk_tier="R0"),
            _candidate(technique_id="b", risk_tier="R0"),
        ]
        ctx = _ctx(allowed_risk_tiers=frozenset({"R0", "R1", "R2"}))
        result = plan(candidates, ctx, ai_rankings=["b", "a"])
        assert result.ai_reranked
        assert result.ranked_candidates[0].candidate.technique_id == "b"

    def test_empty_candidates(self):
        result = plan([], _ctx())
        assert len(result.ranked_candidates) == 0
        assert len(result.ineligible) == 0


class TestNextAction:
    def test_returns_best_candidate(self):
        candidates = [
            _candidate(technique_id="slow", risk_tier="R2"),
            _candidate(technique_id="fast", risk_tier="R0"),
        ]
        ctx = _ctx(allowed_risk_tiers=frozenset({"R0", "R1", "R2"}))
        best = next_action(candidates, ctx)
        assert best is not None
        assert best.candidate.technique_id == "fast"

    def test_returns_none_when_all_ineligible(self):
        candidates = [_candidate(risk_tier="R5")]
        result = next_action(candidates, _ctx())
        assert result is None

    def test_returns_none_when_empty(self):
        result = next_action([], _ctx())
        assert result is None
