"""Deterministic reasoning layer.

Structured reasoning decides; automation only collects and executes; LLMs are
never in this control path. This package holds the pure, deterministic engines
that turn evidence + capabilities into constrained, ranked plans:

  constraints.py   — fail-closed constraint solver (scope/time/rate/data/approval)
  attack_graph.py  — attack graph + precondition/effect pathfinding (GOAP-style)

Everything here is dependency-light and unit-tested, so a decision can be
replayed and audited without any model in the loop.
"""

from reasoning.attack_graph import AttackEdge, AttackGraph, PathResult
from reasoning.constraints import (
    ActionCandidate,
    ConstraintContext,
    ConstraintSolver,
    ConstraintResult,
)

__all__ = [
    "ActionCandidate",
    "ConstraintContext",
    "ConstraintSolver",
    "ConstraintResult",
    "AttackEdge",
    "AttackGraph",
    "PathResult",
]
