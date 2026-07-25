"""Policy decision contract (§13.3).

Produced by the policy engine (packages/policy). enforced_limits are re-applied
by the executor; the decision is fail-closed by construction (default DENY).
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from schemas.common import Decision


class EnforcedLimits(BaseModel):
    max_requests: int = 0
    max_rps: float = 0.0
    max_concurrency: int = 1
    max_runtime_seconds: int = 0
    max_mutations: int = 0
    allowed_destinations: list[str] = Field(default_factory=list)
    allowed_methods: list[str] = Field(default_factory=list)


class PolicyDecision(BaseModel):
    decision: Decision = Decision.DENY
    reason_codes: list[str] = Field(default_factory=list)
    applied_policy_refs: list[str] = Field(default_factory=list)
    required_approval_class: str | None = None
    enforced_limits: EnforcedLimits = Field(default_factory=EnforcedLimits)
    cleanup_required: bool = False

    @classmethod
    def denied(cls, *reason_codes: str) -> "PolicyDecision":
        """Fail-closed helper: a hard DENY with reasons and no limits."""
        return cls(decision=Decision.DENY, reason_codes=list(reason_codes))
