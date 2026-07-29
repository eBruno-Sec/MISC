"""Deterministic attack graph + pathfinding (spec §7, §8, §11, §18).

Edges are techniques with preconditions (capabilities required) and effects
(capabilities produced) plus weight attributes (success probability, confidence,
cost, noise, risk). Planning is a GOAP/STRIPS-style best-first search over
capability states: from a starting set of capabilities, find the best sequence of
techniques that yields a goal capability, ranked by a chosen strategy.

Pure and deterministic (ties broken by edge id), so a chosen attack path can be
replayed and audited with no model in the loop. This generalizes ArsGoatia's
single confirmed chain step into a searchable graph.
"""

from __future__ import annotations

import heapq
import math
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AttackEdge:
    id: str
    technique: str
    requires: frozenset[str] = frozenset()
    provides: frozenset[str] = frozenset()
    success_probability: float = 1.0
    confidence: float = 1.0
    cost: float = 1.0
    noise: float = 0.0
    risk: float = 0.0
    finding_id: str | None = None
    evidence_refs: tuple[str, ...] = ()
    src: str | None = None
    dst: str | None = None


# Strategy -> non-negative per-edge weight (Dijkstra minimizes the sum).
_STRATEGIES = {
    "shortest": lambda e: 1.0,
    "lowest_cost": lambda e: max(0.0, e.cost),
    "lowest_noise": lambda e: max(0.0, e.noise),
    "least_privilege": lambda e: max(0.0, e.risk),
    # Maximize the product of confidence == minimize sum of -log(confidence).
    "highest_confidence": lambda e: -math.log(max(e.confidence, 1e-9)),
}


@dataclass
class PathResult:
    found: bool
    strategy: str
    edges: list[AttackEdge] = field(default_factory=list)
    hops: int = 0
    total_weight: float = 0.0
    product_confidence: float = 1.0
    total_noise: float = 0.0
    total_risk: float = 0.0
    total_cost: float = 0.0

    @property
    def technique_sequence(self) -> list[str]:
        return [e.technique for e in self.edges]


class AttackGraph:
    def __init__(self) -> None:
        self._edges: list[AttackEdge] = []

    def add_edge(self, edge: AttackEdge) -> None:
        self._edges.append(edge)

    def add_edges(self, edges: list[AttackEdge]) -> None:
        self._edges.extend(edges)

    def find_path(
        self,
        start_capabilities: set[str],
        goal_capability: str,
        strategy: str = "shortest",
        *,
        max_states: int = 100_000,
    ) -> PathResult:
        """Best path (by strategy) from the starting capabilities to a state that
        includes goal_capability. Returns PathResult(found=False) if unreachable."""
        if strategy not in _STRATEGIES:
            raise ValueError(f"unknown strategy: {strategy}")
        weight_of = _STRATEGIES[strategy]

        start = frozenset(start_capabilities)

        # Dijkstra over capability-set states. The goal is returned when its state
        # is POPPED (lowest accumulated weight), which guarantees the chosen path
        # is optimal for the strategy — not merely the first path that reaches it.
        counter = 0
        pq: list[tuple[float, int, frozenset[str], tuple[str, ...]]] = [(0.0, 0, start, ())]
        best_cost: dict[frozenset[str], float] = {start: 0.0}
        by_id = {e.id: e for e in self._edges}
        visited = 0

        while pq:
            acc, _, state, path_ids = heapq.heappop(pq)
            if acc > best_cost.get(state, math.inf):
                continue
            if goal_capability in state:
                return self._build_result(strategy, [by_id[i] for i in path_ids])
            visited += 1
            if visited > max_states:
                break

            # Deterministic expansion order: applicable edges sorted by id. Skip
            # edges that add nothing new (provides already satisfied) to avoid cycles.
            for edge in sorted(
                (e for e in self._edges if e.requires <= state and not e.provides <= state),
                key=lambda e: e.id,
            ):
                new_state = state | edge.provides
                new_cost = acc + weight_of(edge)
                if new_cost < best_cost.get(new_state, math.inf):
                    best_cost[new_state] = new_cost
                    counter += 1
                    heapq.heappush(pq, (new_cost, counter, new_state, path_ids + (edge.id,)))

        return PathResult(found=False, strategy=strategy)

    def _build_result(self, strategy: str, edges: list[AttackEdge]) -> PathResult:
        weight_of = _STRATEGIES[strategy]
        conf = 1.0
        for e in edges:
            conf *= e.confidence
        return PathResult(
            found=True,
            strategy=strategy,
            edges=edges,
            hops=len(edges),
            total_weight=sum(weight_of(e) for e in edges),
            product_confidence=conf,
            total_noise=sum(e.noise for e in edges),
            total_risk=sum(e.risk for e in edges),
            total_cost=sum(e.cost for e in edges),
        )
