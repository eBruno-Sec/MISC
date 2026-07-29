from __future__ import annotations

from uuid import uuid4

import pytest

from packages.graph import (
    CostLimitExceededError,
    EdgeLabel,
    GraphEdge,
    GraphNode,
    InMemoryGraphRepository,
    NodeLabel,
    NodeNotFoundError,
    QueryNotFoundError,
    TenantViolationError,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tenant_a() -> "uuid4":
    return uuid4()


@pytest.fixture
def tenant_b() -> "uuid4":
    return uuid4()


@pytest.fixture
def repo() -> InMemoryGraphRepository:
    return InMemoryGraphRepository()


def _node(tenant_id, label=NodeLabel.ASSET, **props) -> GraphNode:
    return GraphNode(id=uuid4(), tenant_id=tenant_id, label=label, properties=props)


def _edge(tenant_id, label, source_id, target_id, **props) -> GraphEdge:
    return GraphEdge(
        id=uuid4(),
        tenant_id=tenant_id,
        label=label,
        source_id=source_id,
        target_id=target_id,
        properties=props,
    )


# ---------------------------------------------------------------------------
# Node CRUD
# ---------------------------------------------------------------------------

def test_project_and_get_node(repo, tenant_a):
    node = _node(tenant_a, NodeLabel.ASSET, hostname="web01")
    repo.project_node(node)
    assert repo.get_node(tenant_a, node.id) is node
    assert repo.node_count(tenant_a) == 1


def test_remove_node(repo, tenant_a):
    node = _node(tenant_a)
    repo.project_node(node)
    assert repo.remove_node(tenant_a, node.id) is True
    assert repo.get_node(tenant_a, node.id) is None
    assert repo.node_count(tenant_a) == 0


def test_remove_nonexistent_node(repo, tenant_a):
    assert repo.remove_node(tenant_a, uuid4()) is False


# ---------------------------------------------------------------------------
# Edge CRUD
# ---------------------------------------------------------------------------

def test_project_and_get_edge(repo, tenant_a):
    n1 = _node(tenant_a, NodeLabel.SERVICE)
    n2 = _node(tenant_a, NodeLabel.ENDPOINT)
    repo.project_node(n1)
    repo.project_node(n2)
    edge = _edge(tenant_a, EdgeLabel.HAS_ENDPOINT, n1.id, n2.id)
    repo.project_edge(edge)
    assert repo.get_edge(tenant_a, edge.id) is edge
    assert repo.edge_count(tenant_a) == 1


def test_remove_edge(repo, tenant_a):
    n1 = _node(tenant_a)
    n2 = _node(tenant_a)
    repo.project_node(n1)
    repo.project_node(n2)
    edge = _edge(tenant_a, EdgeLabel.LEADS_TO, n1.id, n2.id)
    repo.project_edge(edge)
    assert repo.remove_edge(tenant_a, edge.id) is True
    assert repo.get_edge(tenant_a, edge.id) is None


def test_remove_node_cascades_edges(repo, tenant_a):
    n1 = _node(tenant_a)
    n2 = _node(tenant_a)
    repo.project_node(n1)
    repo.project_node(n2)
    edge = _edge(tenant_a, EdgeLabel.RUNS_ON, n1.id, n2.id)
    repo.project_edge(edge)
    repo.remove_node(tenant_a, n1.id)
    assert repo.edge_count(tenant_a) == 0


def test_project_edge_missing_source_raises(repo, tenant_a):
    n2 = _node(tenant_a)
    repo.project_node(n2)
    edge = _edge(tenant_a, EdgeLabel.LEADS_TO, uuid4(), n2.id)
    with pytest.raises(NodeNotFoundError):
        repo.project_edge(edge)


def test_project_edge_missing_target_raises(repo, tenant_a):
    n1 = _node(tenant_a)
    repo.project_node(n1)
    edge = _edge(tenant_a, EdgeLabel.LEADS_TO, n1.id, uuid4())
    with pytest.raises(NodeNotFoundError):
        repo.project_edge(edge)


# ---------------------------------------------------------------------------
# Tenant isolation
# ---------------------------------------------------------------------------

def test_cross_tenant_node_invisible(repo, tenant_a, tenant_b):
    node = _node(tenant_a, NodeLabel.IDENTITY, username="admin")
    repo.project_node(node)
    assert repo.get_node(tenant_b, node.id) is None


def test_cross_tenant_edge_invisible(repo, tenant_a, tenant_b):
    n1 = _node(tenant_a)
    n2 = _node(tenant_a)
    repo.project_node(n1)
    repo.project_node(n2)
    edge = _edge(tenant_a, EdgeLabel.EXPOSES, n1.id, n2.id)
    repo.project_edge(edge)
    assert repo.get_edge(tenant_b, edge.id) is None


def test_cross_tenant_remove_denied(repo, tenant_a, tenant_b):
    node = _node(tenant_a)
    repo.project_node(node)
    assert repo.remove_node(tenant_b, node.id) is False
    # Node still exists in its own tenant
    assert repo.get_node(tenant_a, node.id) is not None


def test_clear_tenant(repo, tenant_a, tenant_b):
    for _ in range(5):
        repo.project_node(_node(tenant_a))
    for _ in range(3):
        repo.project_node(_node(tenant_b))
    removed = repo.clear_tenant(tenant_a)
    assert removed == 5
    assert repo.node_count(tenant_a) == 0
    assert repo.node_count(tenant_b) == 3


# ---------------------------------------------------------------------------
# Stored query: shortest_path
# ---------------------------------------------------------------------------

def test_shortest_path_direct(repo, tenant_a):
    n1 = _node(tenant_a, NodeLabel.ASSET)
    n2 = _node(tenant_a, NodeLabel.ASSET)
    repo.project_node(n1)
    repo.project_node(n2)
    repo.project_edge(_edge(tenant_a, EdgeLabel.LEADS_TO, n1.id, n2.id))

    results = repo.execute_query(
        tenant_a, "shortest_path",
        {"source_id": n1.id, "target_id": n2.id},
    )
    assert len(results) == 1
    assert results[0]["length"] == 1
    assert len(results[0]["path"]) == 2


def test_shortest_path_same_node(repo, tenant_a):
    node = _node(tenant_a)
    repo.project_node(node)
    results = repo.execute_query(
        tenant_a, "shortest_path",
        {"source_id": node.id, "target_id": node.id},
    )
    assert len(results) == 1
    assert results[0]["length"] == 0


def test_shortest_path_no_connection(repo, tenant_a):
    n1 = _node(tenant_a)
    n2 = _node(tenant_a)
    repo.project_node(n1)
    repo.project_node(n2)
    results = repo.execute_query(
        tenant_a, "shortest_path",
        {"source_id": n1.id, "target_id": n2.id},
    )
    assert results == []


def test_shortest_path_cross_tenant_returns_empty(repo, tenant_a, tenant_b):
    n1 = _node(tenant_a)
    n2 = _node(tenant_b)
    repo.project_node(n1)
    repo.project_node(n2)
    results = repo.execute_query(
        tenant_a, "shortest_path",
        {"source_id": n1.id, "target_id": n2.id},
    )
    assert results == []


# ---------------------------------------------------------------------------
# Stored query: capabilities_by_identity
# ---------------------------------------------------------------------------

def test_capabilities_by_identity(repo, tenant_a):
    identity = _node(tenant_a, NodeLabel.IDENTITY, name="svc-account")
    cap1 = _node(tenant_a, NodeLabel.CAPABILITY, name="read-secrets")
    cap2 = _node(tenant_a, NodeLabel.CAPABILITY, name="write-s3")
    unrelated = _node(tenant_a, NodeLabel.CAPABILITY, name="admin")

    repo.project_node(identity)
    repo.project_node(cap1)
    repo.project_node(cap2)
    repo.project_node(unrelated)

    # cap1 gained by identity, cap2 gained by identity
    repo.project_edge(_edge(tenant_a, EdgeLabel.GAINED_BY, cap1.id, identity.id))
    repo.project_edge(_edge(tenant_a, EdgeLabel.GAINED_BY, cap2.id, identity.id))

    results = repo.execute_query(
        tenant_a, "capabilities_by_identity",
        {"identity_id": identity.id},
    )
    result_ids = {r["id"] for r in results}
    assert cap1.id in result_ids
    assert cap2.id in result_ids
    assert unrelated.id not in result_ids


# ---------------------------------------------------------------------------
# Stored query: attack_surface
# ---------------------------------------------------------------------------

def test_attack_surface(repo, tenant_a):
    asset = _node(tenant_a, NodeLabel.ASSET, hostname="web01")
    service = _node(tenant_a, NodeLabel.SERVICE, name="nginx")
    endpoint = _node(tenant_a, NodeLabel.ENDPOINT, path="/api")
    internal = _node(tenant_a, NodeLabel.ASSET, hostname="db01")

    repo.project_node(asset)
    repo.project_node(service)
    repo.project_node(endpoint)
    repo.project_node(internal)

    repo.project_edge(_edge(tenant_a, EdgeLabel.EXPOSES, asset.id, service.id))
    repo.project_edge(_edge(tenant_a, EdgeLabel.HAS_ENDPOINT, service.id, endpoint.id))

    results = repo.execute_query(
        tenant_a, "attack_surface", {"tenant_id": tenant_a},
    )
    result_ids = {r["id"] for r in results}
    assert asset.id in result_ids
    assert service.id in result_ids
    assert endpoint.id in result_ids
    assert internal.id not in result_ids


# ---------------------------------------------------------------------------
# Stored query: evidence_for_step
# ---------------------------------------------------------------------------

def test_evidence_for_step(repo, tenant_a):
    step = _node(tenant_a, NodeLabel.ATTACK_STEP, description="exploit CVE-2024-1234")
    obs1 = _node(tenant_a, NodeLabel.OBSERVATION, detail="port 443 open")
    obs2 = _node(tenant_a, NodeLabel.OBSERVATION, detail="version banner")

    repo.project_node(step)
    repo.project_node(obs1)
    repo.project_node(obs2)

    repo.project_edge(_edge(tenant_a, EdgeLabel.PROVED_BY, step.id, obs1.id))
    repo.project_edge(_edge(tenant_a, EdgeLabel.SUPPORTS, step.id, obs2.id))

    results = repo.execute_query(
        tenant_a, "evidence_for_step", {"step_id": step.id},
    )
    result_ids = {r["id"] for r in results}
    assert obs1.id in result_ids
    assert obs2.id in result_ids


# ---------------------------------------------------------------------------
# Stored query: invalidated_findings
# ---------------------------------------------------------------------------

def test_invalidated_findings(repo, tenant_a):
    obs = _node(tenant_a, NodeLabel.OBSERVATION, detail="open port 22")
    finding = _node(tenant_a, NodeLabel.FINDING, title="SSH exposed")
    unrelated_finding = _node(tenant_a, NodeLabel.FINDING, title="XSS in /login")

    repo.project_node(obs)
    repo.project_node(finding)
    repo.project_node(unrelated_finding)

    repo.project_edge(_edge(tenant_a, EdgeLabel.SUPPORTS, obs.id, finding.id))

    results = repo.execute_query(
        tenant_a, "invalidated_findings",
        {"retracted_fact_id": obs.id},
    )
    result_ids = {r["id"] for r in results}
    assert finding.id in result_ids
    assert unrelated_finding.id not in result_ids


# ---------------------------------------------------------------------------
# Cost limit enforcement
# ---------------------------------------------------------------------------

def test_cost_limit_exceeded(repo, tenant_a):
    # Build a chain of nodes long enough to exceed a tiny cost limit
    nodes = [_node(tenant_a) for _ in range(20)]
    for n in nodes:
        repo.project_node(n)
    for i in range(len(nodes) - 1):
        repo.project_edge(
            _edge(tenant_a, EdgeLabel.LEADS_TO, nodes[i].id, nodes[i + 1].id)
        )

    with pytest.raises(CostLimitExceededError):
        repo.execute_query(
            tenant_a, "shortest_path",
            {"source_id": nodes[0].id, "target_id": nodes[-1].id},
            cost_limit=3,
        )


# ---------------------------------------------------------------------------
# Query registry
# ---------------------------------------------------------------------------

def test_unknown_query_raises(repo, tenant_a):
    with pytest.raises(QueryNotFoundError):
        repo.execute_query(tenant_a, "nonexistent_query", {})


def test_list_stored_queries():
    queries = InMemoryGraphRepository.list_stored_queries()
    names = {q.name for q in queries}
    assert "shortest_path" in names
    assert "capabilities_by_identity" in names
    assert "attack_surface" in names
    assert "evidence_for_step" in names
    assert "invalidated_findings" in names


# ---------------------------------------------------------------------------
# Empty graph edge cases
# ---------------------------------------------------------------------------

def test_empty_graph_shortest_path(repo, tenant_a):
    results = repo.execute_query(
        tenant_a, "shortest_path",
        {"source_id": uuid4(), "target_id": uuid4()},
    )
    assert results == []


def test_empty_graph_capabilities(repo, tenant_a):
    results = repo.execute_query(
        tenant_a, "capabilities_by_identity",
        {"identity_id": uuid4()},
    )
    assert results == []


def test_empty_graph_attack_surface(repo, tenant_a):
    results = repo.execute_query(
        tenant_a, "attack_surface", {"tenant_id": tenant_a},
    )
    assert results == []


def test_empty_graph_evidence(repo, tenant_a):
    results = repo.execute_query(
        tenant_a, "evidence_for_step", {"step_id": uuid4()},
    )
    assert results == []


def test_frozen_node():
    node = _node(uuid4())
    with pytest.raises(AttributeError):
        node.label = NodeLabel.SERVICE  # type: ignore[misc]


def test_frozen_edge(repo, tenant_a):
    n1 = _node(tenant_a)
    n2 = _node(tenant_a)
    repo.project_node(n1)
    repo.project_node(n2)
    edge = _edge(tenant_a, EdgeLabel.LEADS_TO, n1.id, n2.id)
    with pytest.raises(AttributeError):
        edge.label = EdgeLabel.EXPOSES  # type: ignore[misc]
