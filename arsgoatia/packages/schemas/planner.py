"""Planner I/O (§11).

The planner selects and ranks the next actions. Layers 1-5 and 7-8 are
deterministic (eligibility, safety, budget, dedupe); layer 6 is optional AI
ranking that can only reorder within the already-eligible set — it can never add
an action or bypass a safety gate.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from schemas.common import RiskClass


class ActionProposal(BaseModel):
    module_id: str
    module_version: str
    context_id: str
    target_ids: list[str] = Field(default_factory=list)
    rationale: str = ""
    expected_gains: list[str] = Field(default_factory=list)
    estimated_risk_class: RiskClass = RiskClass.R1
    estimated_cost_requests: int = 0
    score: float = 0.0


class PlannerInput(BaseModel):
    assessment_id: str
    eligible_proposals: list[ActionProposal] = Field(default_factory=list)
    budget_remaining_requests: int = 0
    context: dict[str, Any] = Field(default_factory=dict)


class PlannerDecision(BaseModel):
    ranked_proposals: list[ActionProposal] = Field(default_factory=list)
    dropped: list[str] = Field(default_factory=list)
    ranking_source: str = "deterministic"  # deterministic | ai_advisory
    rationale: str = ""
