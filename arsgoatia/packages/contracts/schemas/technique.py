from __future__ import annotations

from pydantic import Field

from .common import (
    BaseContract,
    MutationClass,
    RiskTier,
)


class ActionBudget(BaseContract):
    max_requests: int | None = Field(default=None, ge=1)
    max_duration_seconds: float | None = Field(default=None, gt=0)
    max_bytes: int | None = Field(default=None, ge=0)


class SafetyConstraints(BaseContract):
    redirects: str = Field(default="reject")
    require_pinned_dns: bool = True
    disallow_network_classes: list[str] = Field(default_factory=list)


class PromotionRequirements(BaseContract):
    min_runs: int = Field(default=10, ge=1)
    min_success_rate: float = Field(default=0.95, ge=0, le=1)
    required_reviewers: int = Field(default=1, ge=0)
    required_environments: list[str] = Field(default_factory=list)


class TechniqueManifest(BaseContract):
    id: str
    version: str
    pack: str
    description: str
    target_types: list[str] = Field(default_factory=list)
    required_capabilities: list[str] = Field(default_factory=list)
    risk_tier: RiskTier
    mutation: MutationClass
    preconditions: list[str] = Field(default_factory=list)
    parameters_schema: dict[str, object] = Field(
        default_factory=dict,
        description="JSON Schema for technique parameters",
    )
    action_budget: ActionBudget = Field(default_factory=ActionBudget)
    evidence_profile: dict[str, object] = Field(default_factory=dict)
    validator: str | None = None
    cleanup: str | None = None
    safety: SafetyConstraints = Field(default_factory=SafetyConstraints)
    promotion: PromotionRequirements = Field(default_factory=PromotionRequirements)
