"""Tenant isolation stress tests.

These tests verify that every data-access path enforces tenant boundaries.
A leak between tenants is a zero-tolerance invariant per spec section 3.
"""

from __future__ import annotations

from uuid import uuid4

from packages.application import (
    CommandStatus,
    InMemoryActionRepo,
    InMemoryAuditLog,
    InMemoryEngagementRepo,
    InMemoryEventBus,
    InMemoryEvidenceStore,
)


def _make_repos():
    return (
        InMemoryEngagementRepo(),
        InMemoryActionRepo(),
        InMemoryEvidenceStore(),
        InMemoryEventBus(),
        InMemoryAuditLog(),
    )


class TestEngagementTenantIsolation:
    def test_create_and_get_same_tenant(self):
        repo = InMemoryEngagementRepo()
        tid = uuid4()
        eid = uuid4()
        repo.create(tid, {"id": eid, "state": "draft"})
        assert repo.get(tid, eid) is not None
        assert repo.get(tid, eid)["id"] == eid

    def test_get_wrong_tenant_returns_none(self):
        repo = InMemoryEngagementRepo()
        tid_a, tid_b = uuid4(), uuid4()
        eid = uuid4()
        repo.create(tid_a, {"id": eid, "state": "draft"})
        assert repo.get(tid_b, eid) is None

    def test_many_tenants_isolated(self):
        repo = InMemoryEngagementRepo()
        tenants = [uuid4() for _ in range(20)]
        eids = [uuid4() for _ in range(20)]

        for tid, eid in zip(tenants, eids):
            repo.create(tid, {"id": eid, "state": "running"})

        for i, (tid, eid) in enumerate(zip(tenants, eids)):
            assert repo.get(tid, eid) is not None
            for j, other_tid in enumerate(tenants):
                if i != j:
                    assert repo.get(other_tid, eid) is None

    def test_update_state_wrong_tenant_fails(self):
        repo = InMemoryEngagementRepo()
        tid_a, tid_b = uuid4(), uuid4()
        eid = uuid4()
        repo.create(tid_a, {"id": eid, "state": "draft"})
        repo.update_state(tid_b, eid, "running")
        assert repo.get(tid_a, eid)["state"] == "draft"


class TestActionTenantIsolation:
    def test_action_wrong_tenant_returns_none(self):
        repo = InMemoryActionRepo()
        tid_a, tid_b = uuid4(), uuid4()
        aid = uuid4()
        repo.create(tid_a, {"id": aid, "state": "proposed"})
        assert repo.get(tid_a, aid) is not None
        assert repo.get(tid_b, aid) is None

    def test_action_update_wrong_tenant(self):
        repo = InMemoryActionRepo()
        tid_a, tid_b = uuid4(), uuid4()
        aid = uuid4()
        repo.create(tid_a, {"id": aid, "state": "proposed"})
        repo.update_state(tid_b, aid, "approved")
        assert repo.get(tid_a, aid)["state"] == "proposed"


class TestEvidenceTenantIsolation:
    def test_evidence_wrong_tenant_returns_none(self):
        store = InMemoryEvidenceStore()
        tid_a, tid_b = uuid4(), uuid4()
        digest = store.store(tid_a, b"sensitive-finding", "text/plain", {})
        assert store.get_artifact(tid_a, digest) is not None
        assert store.get_artifact(tid_b, digest) is None

    def test_evidence_metadata_wrong_tenant(self):
        store = InMemoryEvidenceStore()
        tid_a, tid_b = uuid4(), uuid4()
        digest = store.store(tid_a, b"data", "application/json", {"key": "val"})
        assert store.get_metadata(tid_a, digest) is not None
        assert store.get_metadata(tid_b, digest) is None

    def test_same_content_different_tenants(self):
        store = InMemoryEvidenceStore()
        tid_a, tid_b = uuid4(), uuid4()
        content = b"identical-content"
        digest_a = store.store(tid_a, content, "text/plain", {})
        digest_b = store.store(tid_b, content, "text/plain", {})
        assert digest_a == digest_b
        assert store.get_artifact(tid_a, digest_a) is not None
        assert store.get_artifact(tid_b, digest_a) is not None
        assert store.get_artifact(tid_a, digest_b) is not None


class TestGraphTenantIsolation:
    def test_graph_node_wrong_tenant(self):
        from packages.graph import GraphNode, InMemoryGraphRepository, NodeLabel

        graph = InMemoryGraphRepository()
        tid_a, tid_b = uuid4(), uuid4()
        nid = uuid4()
        graph.project_node(
            GraphNode(id=nid, tenant_id=tid_a, label=NodeLabel.ASSET, properties={"name": "target"})
        )
        assert graph.get_node(tid_a, nid) is not None
        assert graph.get_node(tid_b, nid) is None

    def test_graph_clear_one_tenant_preserves_other(self):
        from packages.graph import GraphNode, InMemoryGraphRepository, NodeLabel

        graph = InMemoryGraphRepository()
        tid_a, tid_b = uuid4(), uuid4()
        nid_a, nid_b = uuid4(), uuid4()
        graph.project_node(
            GraphNode(id=nid_a, tenant_id=tid_a, label=NodeLabel.FINDING, properties={})
        )
        graph.project_node(
            GraphNode(id=nid_b, tenant_id=tid_b, label=NodeLabel.FINDING, properties={})
        )
        graph.clear_tenant(tid_a)
        assert graph.get_node(tid_a, nid_a) is None
        assert graph.get_node(tid_b, nid_b) is not None

    def test_graph_query_wrong_tenant(self):
        from packages.graph import (
            EdgeLabel,
            GraphEdge,
            GraphNode,
            InMemoryGraphRepository,
            NodeLabel,
        )

        graph = InMemoryGraphRepository()
        tid_a, tid_b = uuid4(), uuid4()
        nid1, nid2 = uuid4(), uuid4()
        graph.project_node(
            GraphNode(id=nid1, tenant_id=tid_a, label=NodeLabel.IDENTITY, properties={})
        )
        graph.project_node(
            GraphNode(id=nid2, tenant_id=tid_a, label=NodeLabel.CAPABILITY, properties={})
        )
        graph.project_edge(
            GraphEdge(
                id=uuid4(),
                tenant_id=tid_a,
                label=EdgeLabel.GAINED_BY,
                source_id=nid2,
                target_id=nid1,
            )
        )
        results_a = graph.execute_query(tid_a, "capabilities_by_identity", {"identity_id": nid1})
        assert len(results_a) == 1
        results_b = graph.execute_query(tid_b, "capabilities_by_identity", {"identity_id": nid1})
        assert len(results_b) == 0


class TestCrossServiceTenantIsolation:
    def test_approve_action_wrong_tenant(self):
        from packages.application import (
            ApproveActionCommand,
            handle_approve_action,
        )

        repo = InMemoryActionRepo()
        tid_a, tid_b = uuid4(), uuid4()
        aid = uuid4()
        repo.create(tid_a, {"id": aid, "state": "approval_required"})

        result = handle_approve_action(
            ApproveActionCommand(
                tenant_id=tid_b,
                action_id=aid,
                approver="attacker@evil.test",
                decision_digest="sha256:bad",
            ),
            repo,
        )
        assert result.status == CommandStatus.NOT_FOUND
        assert repo.get(tid_a, aid)["state"] == "approval_required"

    def test_emergency_stop_wrong_tenant(self):
        from packages.application import (
            EmergencyStopCommand,
            handle_emergency_stop,
        )

        repo = InMemoryEngagementRepo()
        tid_a, tid_b = uuid4(), uuid4()
        eid = uuid4()
        repo.create(tid_a, {"id": eid, "state": "running"})

        result = handle_emergency_stop(
            EmergencyStopCommand(
                tenant_id=tid_b,
                engagement_id=eid,
                actor="attacker",
                reason="trying to stop someone else's engagement",
            ),
            repo,
        )
        assert result.status == CommandStatus.NOT_FOUND
        assert repo.get(tid_a, eid)["state"] == "running"


class TestNonceTenantIsolation:
    def test_nonce_stores_are_separate(self):
        from packages.crypto import NonceStore

        ns_a = NonceStore()
        ns_b = NonceStore()
        assert ns_a.check_and_record("nonce-1")
        assert ns_b.check_and_record("nonce-1")
        assert not ns_a.check_and_record("nonce-1")
        assert not ns_b.check_and_record("nonce-1")
