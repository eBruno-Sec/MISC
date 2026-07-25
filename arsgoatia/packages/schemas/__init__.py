"""ArsGoatia shared contracts.

Single source of truth for every cross-boundary payload: events, policy
decisions, signed action envelopes, module and tool I/O, and the domain value
objects. These are versioned pydantic v2 models; the persistence layer
(packages/domain) and every worker validates against them.

Spec references are noted per module (section numbers from the handoff).
"""

from schemas.common import (
    AssertionState,
    Confidence,
    Decision,
    RiskClass,
    SchemaVersion,
    utcnow,
)

__all__ = [
    "AssertionState",
    "Confidence",
    "Decision",
    "RiskClass",
    "SchemaVersion",
    "utcnow",
]
