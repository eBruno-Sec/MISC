"""ArsGoatia policy packs -- risk-tier decision profiles.

A policy profile maps risk tiers to decisions and encodes approval
requirements, data-residency constraints, and persistence behaviour
that the policy engine enforces at action-proposal time.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PolicyProfile:
    profile_id: str
    version: str
    description: str
    risk_tier_decisions: dict[str, str] = field(default_factory=dict)
    approval_requirements: dict[str, Any] = field(default_factory=dict)
    data_residency: str = "local"
    persistence_policy: str = "until_engagement_close"


# ---------------------------------------------------------------------------
# Built-in profiles
# ---------------------------------------------------------------------------

LAB_SAFE_PROFILE = PolicyProfile(
    profile_id="lab_safe",
    version="1.0.0",
    description="Permissive profile for lab/training environments",
    risk_tier_decisions={
        "R0": "allow",
        "R1": "allow",
        "R2": "require_approval",
        "R3": "require_approval",
        "R4": "deny",
        "R5": "deny",
    },
    approval_requirements={
        "R2": {"approver_role": "operator"},
        "R3": {"approver_role": "operator"},
    },
    data_residency="local",
    persistence_policy="until_engagement_close",
)

PRODUCTION_STRICT_PROFILE = PolicyProfile(
    profile_id="production_strict",
    version="1.0.0",
    description="Conservative profile for production assessments",
    risk_tier_decisions={
        "R0": "allow",
        "R1": "allow_with_limits",
        "R2": "require_approval",
        "R3": "require_approval",
        "R4": "deny",
        "R5": "deny",
    },
    approval_requirements={
        "R1": {"approver_role": "operator", "max_concurrent": 2},
        "R2": {"approver_role": "lead"},
        "R3": {"approver_role": "lead", "requires_justification": True},
    },
    data_residency="local",
    persistence_policy="until_engagement_close",
)
