from __future__ import annotations

from pydantic import Field

from .common import (
    BaseContract,
    DecisionOutcome,
    MutationClass,
    RiskTier,
    UUIDv7,
)


class ActionRequest(BaseContract):
    technique: str
    target: str
    risk_tier: RiskTier
    mutation: MutationClass
    access_contexts: list[UUIDv7] = Field(default_factory=list)
    parameters_digest: str | None = None


class PolicyRule(BaseContract):
    rule_id: str
    risk_tier: RiskTier
    action: str
    decision: DecisionOutcome
    conditions: dict[str, object] = Field(default_factory=dict)


class PolicyDecision(BaseContract):
    decision_id: UUIDv7
    decision: DecisionOutcome
    risk_tier: RiskTier
    reason: str
    layers_evaluated: list[str] = Field(default_factory=list)
    most_restrictive_layer: str | None = None
    version: str
