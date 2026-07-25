"""Versioned priority model (§11.4).

priority = information_gain + impact_gain + chain_unlock_value
         + coverage_gap_value + evidence_completion_value
         - execution_cost - mutation_risk - target_stability_risk
         - redundancy_penalty - uncertainty_penalty

The formula and weights are versioned so historical rankings are reproducible.
"""

from __future__ import annotations

SCORING_VERSION = "1.0.0"

_POSITIVE = (
    "information_gain",
    "impact_gain",
    "chain_unlock_value",
    "coverage_gap_value",
    "evidence_completion_value",
)
_NEGATIVE = (
    "execution_cost",
    "mutation_risk",
    "target_stability_risk",
    "redundancy_penalty",
    "uncertainty_penalty",
)

# Weights (all 1.0 in v1; kept explicit so tuning bumps SCORING_VERSION).
WEIGHTS: dict[str, float] = {**{k: 1.0 for k in _POSITIVE}, **{k: 1.0 for k in _NEGATIVE}}


def priority(features: dict[str, float]) -> float:
    score = 0.0
    for k in _POSITIVE:
        score += WEIGHTS[k] * float(features.get(k, 0.0))
    for k in _NEGATIVE:
        score -= WEIGHTS[k] * float(features.get(k, 0.0))
    return score
