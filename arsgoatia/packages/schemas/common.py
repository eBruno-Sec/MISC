"""Shared enums and primitives used across the contract models.

Spec: risk classes (§13.2), lifecycle assertion states (§6.13-6.21).
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Annotated

from pydantic import Field

# Confidence is a normalized score in [0, 1] (spec calls it `decimal`).
Confidence = Annotated[float, Field(ge=0.0, le=1.0)]

# Event/contract schema version. Bumped when a payload shape changes
# incompatibly; consumers assert compatibility (§9, §33 schema evolution).
SchemaVersion = Annotated[int, Field(ge=1)]


def utcnow() -> datetime:
    """Timezone-aware UTC now. All contract timestamps are UTC."""
    return datetime.now(timezone.utc)


class RiskClass(str, enum.Enum):
    """Risk classes (§13.2). Ordered least-to-most impactful."""

    R0 = "R0"  # Passive analysis
    R1 = "R1"  # Safe read-only interaction
    R2 = "R2"  # Bounded state-neutral active testing
    R3 = "R3"  # Controlled state mutation
    R4 = "R4"  # High-impact or sensitive validation
    R5 = "R5"  # Prohibited by default

    @property
    def rank(self) -> int:
        return int(self.value[1:])


class Decision(str, enum.Enum):
    """Policy decision outcomes (§13.3). Ordered most-to-least permissive so
    the engine can pick the most restrictive across layers."""

    ALLOW = "allow"
    ALLOW_WITH_LIMITS = "allow_with_limits"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"

    @property
    def restrictiveness(self) -> int:
        return {
            "allow": 0,
            "allow_with_limits": 1,
            "require_approval": 2,
            "deny": 3,
        }[self.value]


class AssertionState(str, enum.Enum):
    """Observation lifecycle (§6.13)."""

    OBSERVED = "observed"
    INFERRED = "inferred"
    CANDIDATE = "candidate"
    VALIDATED = "validated"
    DISPROVEN = "disproven"
    EXPIRED = "expired"


class HypothesisState(str, enum.Enum):
    """Hypothesis lifecycle (§6.14)."""

    PROPOSED = "proposed"
    PLANNED = "planned"
    VALIDATING = "validating"
    PROVEN = "proven"
    DISPROVEN = "disproven"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"
    EXPIRED = "expired"


class FindingValidationState(str, enum.Enum):
    """Finding lifecycle (§6.15, §17)."""

    CANDIDATE = "candidate"
    VALIDATED = "validated"
    CONFIRMED = "confirmed"
    DISPROVEN = "disproven"
    INCONCLUSIVE = "inconclusive"
    ACCEPTED_RISK = "accepted_risk"
    REMEDIATED = "remediated"


class SeverityLabel(str, enum.Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CapabilityState(str, enum.Enum):
    """Capability validation lifecycle (§6.16)."""

    CANDIDATE = "candidate"
    PROVEN = "proven"
    DISPROVEN = "disproven"
    EXPIRED = "expired"
    REVOKED = "revoked"


class Sensitivity(str, enum.Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"


class RedactionState(str, enum.Enum):
    RAW = "raw"
    REDACTED = "redacted"
    SANITIZED = "sanitized"
