"""ArsGoatia attack graph module -- repository contract and in-memory implementation.

Provides the graph abstraction for attack-path analysis per section 8.3 of the spec.
Neo4j initially, behind a graph repository contract; PostgreSQL remains canonical.

The API accepts named, versioned query templates with typed inputs, cost limits,
tenant injection, and read-only transactions.  User- or model-generated Cypher
is never executed directly.

Graph nodes: Asset, Service, Endpoint, Identity, Capability, Finding,
             AttackStep, Hypothesis, Observation
Graph edges: EXPOSES, RUNS_ON, HAS_ENDPOINT, PROVED_BY, LEADS_TO,
             GAINED_BY, SUPPORTS, REFUTES
"""

from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable
from uuid import UUID

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class NodeLabel(enum.Enum):
    ASSET = "Asset"
    SERVICE = "Service"
    ENDPOINT = "Endpoint"
    IDENTITY = "Identity"
    CAPABILITY = "Capability"
    FINDING = "Finding"
    ATTACK_STEP = "AttackStep"
    HYPOTHESIS = "Hypothesis"
    OBSERVATION = "Observation"


class EdgeLabel(enum.Enum):
    EXPOSES = "EXPOSES"
    RUNS_ON = "RUNS_ON"
    HAS_ENDPOINT = "HAS_ENDPOINT"
    PROVED_BY = "PROVED_BY"
    LEADS_TO = "LEADS_TO"
    GAINED_BY = "GAINED_BY"
    SUPPORTS = "SUPPORTS"
    REFUTES = "REFUTES"


# ---------------------------------------------------------------------------
# Core dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GraphNode:
    id: UUID
    tenant_id: UUID
    label: NodeLabel
    properties: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class GraphEdge:
    id: UUID
    tenant_id: UUID
    label: EdgeLabel
    source_id: UUID
    target_id: UUID
    properties: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class StoredQuery:
    name: str
    version: str
    description: str
    parameter_schema: dict[str, Any] = field(default_factory=dict)
    cost_limit: int = 1000


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class GraphError(Exception):
    """Base error for graph operations."""


class TenantViolationError(GraphError):
    """Raised when an operation crosses tenant boundaries."""


class QueryNotFoundError(GraphError):
    """Raised when a named stored query does not exist."""


class CostLimitExceededError(GraphError):
    """Raised when a query exceeds its cost budget."""


class NodeNotFoundError(GraphError):
    """Raised when a referenced node does not exist in the tenant's graph."""


# ---------------------------------------------------------------------------
# Repository contract (ABC)
# ---------------------------------------------------------------------------


class GraphRepository(ABC):
    """Abstract graph repository -- all implementations must satisfy this contract."""

    @abstractmethod
    def project_node(self, node: GraphNode) -> None:
        """Upsert a node into the graph.  Tenant is taken from the node."""

    @abstractmethod
    def project_edge(self, edge: GraphEdge) -> None:
        """Upsert an edge into the graph.  Tenant is taken from the edge."""

    @abstractmethod
    def execute_query(
        self,
        tenant_id: UUID,
        query_name: str,
        params: dict[str, Any],
        *,
        cost_limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """Execute a named stored query within a tenant boundary."""

    @abstractmethod
    def remove_node(self, tenant_id: UUID, node_id: UUID) -> bool:
        """Remove a node.  Returns True if it existed."""

    @abstractmethod
    def remove_edge(self, tenant_id: UUID, edge_id: UUID) -> bool:
        """Remove an edge.  Returns True if it existed."""

    @abstractmethod
    def clear_tenant(self, tenant_id: UUID) -> int:
        """Remove all nodes and edges for a tenant.  Returns count removed."""


# ---------------------------------------------------------------------------
# Stored-query registry
# ---------------------------------------------------------------------------

# A query function receives (repo, tenant_id, params, cost_limit) and returns results.
QueryFunc = Callable[["InMemoryGraphRepository", UUID, dict[str, Any], int], list[dict[str, Any]]]

_STORED_QUERIES: dict[str, StoredQuery] = {}
_QUERY_FUNCS: dict[str, QueryFunc] = {}


def _register_query(
    name: str,
    version: str,
    description: str,
    parameter_schema: dict[str, Any],
    cost_limit: int = 1000,
) -> Callable[[QueryFunc], QueryFunc]:
    """Decorator that registers a named stored query."""

    def decorator(fn: QueryFunc) -> QueryFunc:
        _STORED_QUERIES[name] = StoredQuery(
            name=name,
            version=version,
            description=description,
            parameter_schema=parameter_schema,
            cost_limit=cost_limit,
        )
        _QUERY_FUNCS[name] = fn
        return fn

    return decorator


# ---------------------------------------------------------------------------
# Named stored queries
# ---------------------------------------------------------------------------


@_register_query(
    name="shortest_path",
    version="1.0.0",
    description="BFS shortest confirmed path between two nodes (crown-jewel targeting).",
    parameter_schema={"source_id": "UUID", "target_id": "UUID"},
    cost_limit=5000,
)
def _shortest_path(
    repo: InMemoryGraphRepository,
    tenant_id: UUID,
    params: dict[str, Any],
    cost_limit: int,
) -> list[dict[str, Any]]:
    source_id = params["source_id"]
    target_id = params["target_id"]

    if source_id not in repo._nodes_by_tenant.get(tenant_id, {}):
        return []
    if target_id not in repo._nodes_by_tenant.get(tenant_id, {}):
        return []
    if source_id == target_id:
        node = repo._nodes_by_tenant[tenant_id][source_id]
        return [{"path": [_node_to_dict(node)], "length": 0}]

    # Build adjacency from tenant edges
    adjacency: dict[UUID, list[tuple[UUID, GraphEdge]]] = {}
    for edge in repo._edges_by_tenant.get(tenant_id, {}).values():
        adjacency.setdefault(edge.source_id, []).append((edge.target_id, edge))
        # Treat graph as undirected for path-finding
        adjacency.setdefault(edge.target_id, []).append((edge.source_id, edge))

    visited: set[UUID] = set()
    queue: deque[tuple[UUID, list[UUID], list[GraphEdge]]] = deque()
    queue.append((source_id, [source_id], []))
    visited.add(source_id)
    nodes_visited = 0

    while queue:
        current, path_nodes, path_edges = queue.popleft()
        nodes_visited += 1
        if nodes_visited > cost_limit:
            raise CostLimitExceededError(
                f"shortest_path exceeded cost limit of {cost_limit} (visited {nodes_visited} nodes)"
            )

        for neighbor_id, edge in adjacency.get(current, []):
            if neighbor_id in visited:
                continue
            new_path_nodes = path_nodes + [neighbor_id]
            new_path_edges = path_edges + [edge]
            if neighbor_id == target_id:
                tenant_nodes = repo._nodes_by_tenant[tenant_id]
                return [
                    {
                        "path": [_node_to_dict(tenant_nodes[nid]) for nid in new_path_nodes],
                        "edges": [_edge_to_dict(e) for e in new_path_edges],
                        "length": len(new_path_edges),
                    }
                ]
            visited.add(neighbor_id)
            queue.append((neighbor_id, new_path_nodes, new_path_edges))

    return []


@_register_query(
    name="capabilities_by_identity",
    version="1.0.0",
    description="All capabilities reachable from an identity via GAINED_BY edges.",
    parameter_schema={"identity_id": "UUID"},
    cost_limit=2000,
)
def _capabilities_by_identity(
    repo: InMemoryGraphRepository,
    tenant_id: UUID,
    params: dict[str, Any],
    cost_limit: int,
) -> list[dict[str, Any]]:
    identity_id = params["identity_id"]
    tenant_nodes = repo._nodes_by_tenant.get(tenant_id, {})

    if identity_id not in tenant_nodes:
        return []

    # Build adjacency (directed) from GAINED_BY edges within the tenant.
    # GAINED_BY: Capability --GAINED_BY--> Identity means
    # "capability gained by identity", so from the identity we follow
    # edges where identity is the target.
    adjacency: dict[UUID, list[UUID]] = {}
    for edge in repo._edges_by_tenant.get(tenant_id, {}).values():
        if edge.label == EdgeLabel.GAINED_BY:
            # capability -> identity; we want identity -> capability
            adjacency.setdefault(edge.target_id, []).append(edge.source_id)
        elif edge.label == EdgeLabel.LEADS_TO:
            adjacency.setdefault(edge.source_id, []).append(edge.target_id)

    visited: set[UUID] = set()
    queue: deque[UUID] = deque([identity_id])
    visited.add(identity_id)
    capabilities: list[dict[str, Any]] = []
    nodes_visited = 0

    while queue:
        current = queue.popleft()
        nodes_visited += 1
        if nodes_visited > cost_limit:
            raise CostLimitExceededError(
                f"capabilities_by_identity exceeded cost limit of {cost_limit}"
            )
        node = tenant_nodes.get(current)
        if node is not None and node.label == NodeLabel.CAPABILITY:
            capabilities.append(_node_to_dict(node))

        for neighbor_id in adjacency.get(current, []):
            if neighbor_id not in visited:
                visited.add(neighbor_id)
                queue.append(neighbor_id)

    return capabilities


@_register_query(
    name="attack_surface",
    version="1.0.0",
    description="All externally-reachable assets and endpoints (exposed via EXPOSES/HAS_ENDPOINT).",
    parameter_schema={"tenant_id": "UUID"},
    cost_limit=3000,
)
def _attack_surface(
    repo: InMemoryGraphRepository,
    tenant_id: UUID,
    params: dict[str, Any],
    cost_limit: int,
) -> list[dict[str, Any]]:
    tenant_nodes = repo._nodes_by_tenant.get(tenant_id, {})
    tenant_edges = repo._edges_by_tenant.get(tenant_id, {})

    # Collect all nodes that participate in EXPOSES or HAS_ENDPOINT edges
    exposed_ids: set[UUID] = set()
    nodes_visited = 0

    for edge in tenant_edges.values():
        nodes_visited += 1
        if nodes_visited > cost_limit:
            raise CostLimitExceededError(f"attack_surface exceeded cost limit of {cost_limit}")
        if edge.label in (EdgeLabel.EXPOSES, EdgeLabel.HAS_ENDPOINT):
            exposed_ids.add(edge.source_id)
            exposed_ids.add(edge.target_id)

    results: list[dict[str, Any]] = []
    for nid in exposed_ids:
        node = tenant_nodes.get(nid)
        if node is not None and node.label in (
            NodeLabel.ASSET,
            NodeLabel.ENDPOINT,
            NodeLabel.SERVICE,
        ):
            results.append(_node_to_dict(node))

    return results


@_register_query(
    name="evidence_for_step",
    version="1.0.0",
    description="Evidence artifacts linked to an attack step via PROVED_BY/SUPPORTS.",
    parameter_schema={"step_id": "UUID"},
    cost_limit=1000,
)
def _evidence_for_step(
    repo: InMemoryGraphRepository,
    tenant_id: UUID,
    params: dict[str, Any],
    cost_limit: int,
) -> list[dict[str, Any]]:
    step_id = params["step_id"]
    tenant_nodes = repo._nodes_by_tenant.get(tenant_id, {})
    tenant_edges = repo._edges_by_tenant.get(tenant_id, {})

    if step_id not in tenant_nodes:
        return []

    evidence_ids: set[UUID] = set()
    nodes_visited = 0

    for edge in tenant_edges.values():
        nodes_visited += 1
        if nodes_visited > cost_limit:
            raise CostLimitExceededError(f"evidence_for_step exceeded cost limit of {cost_limit}")
        if edge.label in (EdgeLabel.PROVED_BY, EdgeLabel.SUPPORTS):
            if edge.source_id == step_id:
                evidence_ids.add(edge.target_id)
            elif edge.target_id == step_id:
                evidence_ids.add(edge.source_id)

    results: list[dict[str, Any]] = []
    for eid in evidence_ids:
        node = tenant_nodes.get(eid)
        if node is not None:
            results.append(_node_to_dict(node))

    return results


@_register_query(
    name="invalidated_findings",
    version="1.0.0",
    description="Findings that depended on a retracted observation via SUPPORTS/REFUTES.",
    parameter_schema={"retracted_fact_id": "UUID"},
    cost_limit=2000,
)
def _invalidated_findings(
    repo: InMemoryGraphRepository,
    tenant_id: UUID,
    params: dict[str, Any],
    cost_limit: int,
) -> list[dict[str, Any]]:
    retracted_fact_id = params["retracted_fact_id"]
    tenant_nodes = repo._nodes_by_tenant.get(tenant_id, {})
    tenant_edges = repo._edges_by_tenant.get(tenant_id, {})

    if retracted_fact_id not in tenant_nodes:
        return []

    # Find all findings reachable from the retracted observation
    # via SUPPORTS edges (observation supports finding).
    affected_ids: set[UUID] = set()
    queue: deque[UUID] = deque([retracted_fact_id])
    visited: set[UUID] = {retracted_fact_id}
    nodes_visited = 0

    while queue:
        current = queue.popleft()
        nodes_visited += 1
        if nodes_visited > cost_limit:
            raise CostLimitExceededError(
                f"invalidated_findings exceeded cost limit of {cost_limit}"
            )

        for edge in tenant_edges.values():
            if edge.label == EdgeLabel.SUPPORTS and edge.source_id == current:
                target = tenant_nodes.get(edge.target_id)
                if target is not None and target.label == NodeLabel.FINDING:
                    affected_ids.add(edge.target_id)
                if edge.target_id not in visited:
                    visited.add(edge.target_id)
                    queue.append(edge.target_id)

    results: list[dict[str, Any]] = []
    for fid in affected_ids:
        node = tenant_nodes.get(fid)
        if node is not None:
            results.append(_node_to_dict(node))

    return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _node_to_dict(node: GraphNode) -> dict[str, Any]:
    return {
        "id": node.id,
        "tenant_id": node.tenant_id,
        "label": node.label.value,
        "properties": dict(node.properties),
    }


def _edge_to_dict(edge: GraphEdge) -> dict[str, Any]:
    return {
        "id": edge.id,
        "tenant_id": edge.tenant_id,
        "label": edge.label.value,
        "source_id": edge.source_id,
        "target_id": edge.target_id,
        "properties": dict(edge.properties),
    }


# ---------------------------------------------------------------------------
# In-memory implementation
# ---------------------------------------------------------------------------


class InMemoryGraphRepository(GraphRepository):
    """Pure-Python in-memory graph satisfying the repository contract.

    Stores nodes and edges in dicts keyed by (tenant_id, node/edge id).
    Enforces tenant isolation on every operation -- wrong tenant yields
    empty results or raises TenantViolationError.
    """

    def __init__(self) -> None:
        # tenant_id -> {node_id -> GraphNode}
        self._nodes_by_tenant: dict[UUID, dict[UUID, GraphNode]] = {}
        # tenant_id -> {edge_id -> GraphEdge}
        self._edges_by_tenant: dict[UUID, dict[UUID, GraphEdge]] = {}

    # -- Node operations ---------------------------------------------------

    def project_node(self, node: GraphNode) -> None:
        tenant_nodes = self._nodes_by_tenant.setdefault(node.tenant_id, {})
        tenant_nodes[node.id] = node

    def remove_node(self, tenant_id: UUID, node_id: UUID) -> bool:
        tenant_nodes = self._nodes_by_tenant.get(tenant_id, {})
        if node_id not in tenant_nodes:
            return False
        del tenant_nodes[node_id]
        # Remove edges that reference this node
        tenant_edges = self._edges_by_tenant.get(tenant_id, {})
        to_remove = [
            eid
            for eid, edge in tenant_edges.items()
            if edge.source_id == node_id or edge.target_id == node_id
        ]
        for eid in to_remove:
            del tenant_edges[eid]
        return True

    # -- Edge operations ---------------------------------------------------

    def project_edge(self, edge: GraphEdge) -> None:
        # Validate that both endpoints exist within the same tenant
        tenant_nodes = self._nodes_by_tenant.get(edge.tenant_id, {})
        if edge.source_id not in tenant_nodes:
            raise NodeNotFoundError(
                f"Source node {edge.source_id} not found in tenant {edge.tenant_id}"
            )
        if edge.target_id not in tenant_nodes:
            raise NodeNotFoundError(
                f"Target node {edge.target_id} not found in tenant {edge.tenant_id}"
            )
        tenant_edges = self._edges_by_tenant.setdefault(edge.tenant_id, {})
        tenant_edges[edge.id] = edge

    def remove_edge(self, tenant_id: UUID, edge_id: UUID) -> bool:
        tenant_edges = self._edges_by_tenant.get(tenant_id, {})
        if edge_id not in tenant_edges:
            return False
        del tenant_edges[edge_id]
        return True

    # -- Tenant operations -------------------------------------------------

    def clear_tenant(self, tenant_id: UUID) -> int:
        node_count = len(self._nodes_by_tenant.pop(tenant_id, {}))
        edge_count = len(self._edges_by_tenant.pop(tenant_id, {}))
        return node_count + edge_count

    # -- Query execution ---------------------------------------------------

    def execute_query(
        self,
        tenant_id: UUID,
        query_name: str,
        params: dict[str, Any],
        *,
        cost_limit: int = 1000,
    ) -> list[dict[str, Any]]:
        if query_name not in _QUERY_FUNCS:
            raise QueryNotFoundError(f"No stored query named '{query_name}'")

        stored = _STORED_QUERIES[query_name]
        # Enforce the lower of caller limit and query definition limit
        effective_limit = min(cost_limit, stored.cost_limit)

        return _QUERY_FUNCS[query_name](self, tenant_id, params, effective_limit)

    # -- Introspection -----------------------------------------------------

    def get_node(self, tenant_id: UUID, node_id: UUID) -> GraphNode | None:
        """Return a node only if it belongs to the given tenant."""
        return self._nodes_by_tenant.get(tenant_id, {}).get(node_id)

    def get_edge(self, tenant_id: UUID, edge_id: UUID) -> GraphEdge | None:
        """Return an edge only if it belongs to the given tenant."""
        return self._edges_by_tenant.get(tenant_id, {}).get(edge_id)

    def node_count(self, tenant_id: UUID) -> int:
        return len(self._nodes_by_tenant.get(tenant_id, {}))

    def edge_count(self, tenant_id: UUID) -> int:
        return len(self._edges_by_tenant.get(tenant_id, {}))

    @staticmethod
    def list_stored_queries() -> list[StoredQuery]:
        return list(_STORED_QUERIES.values())
