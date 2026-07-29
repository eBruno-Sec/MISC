"""Performance baseline tests — verify critical paths meet latency budgets.

These tests establish that the in-memory fast paths (policy evaluation,
scope checking, envelope signing/verification, evidence hashing) can
sustain the throughput needed for real assessments.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest


class TestPolicyEvalThroughput:
    def test_policy_eval_under_1ms(self):
        from packages.contracts.schemas.common import MutationClass, RiskTier
        from packages.contracts.schemas.policy import ActionRequest
        from packages.policy import PolicyContext, evaluate

        ctx = PolicyContext(current_time=datetime.now(timezone.utc))
        request = ActionRequest(
            technique="web.authz.bola", target="https://api.test",
            risk_tier=RiskTier.R2, mutation=MutationClass.none,
        )

        start = time.perf_counter()
        for _ in range(1000):
            evaluate(request, ctx)
        elapsed = time.perf_counter() - start

        avg_us = (elapsed / 1000) * 1_000_000
        assert avg_us < 1000, f"policy eval took {avg_us:.0f}us avg, budget is 1000us"


class TestScopeCheckThroughput:
    def test_scope_check_under_500us(self):
        from packages.contracts.schemas.engagement import ScopeRule, ScopeSpec
        from packages.scope import check_target

        scope = ScopeSpec(
            include=[
                ScopeRule(type="dns_suffix", value="apps.example.test", action="allow"),
                ScopeRule(type="dns_suffix", value="api.example.test", action="allow"),
            ],
            exclude=[
                ScopeRule(type="url_prefix", value="https://admin.apps.example.test/", action="deny"),
            ],
        )

        start = time.perf_counter()
        for _ in range(1000):
            check_target(scope, "https://target.apps.example.test/api/v1/users")
        elapsed = time.perf_counter() - start

        avg_us = (elapsed / 1000) * 1_000_000
        assert avg_us < 500, f"scope check took {avg_us:.0f}us avg, budget is 500us"


class TestEnvelopeCryptoThroughput:
    def test_sign_verify_under_2ms(self):
        from packages.envelope import sign_action_envelope, verify_action_envelope

        env = {
            "actionId": str(uuid4()),
            "tenantId": str(uuid4()),
            "engagementRevisionId": str(uuid4()),
            "technique": {"id": "bola", "version": "1.0.0"},
            "target": {"locator": "https://api.test/basket/1"},
            "effectiveRiskTier": "R2",
            "nonce": "perf-nonce",
            "expiresAt": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(),
        }
        key = b"perf-test-key"

        start = time.perf_counter()
        for _ in range(1000):
            sig = sign_action_envelope(env, key)
            verify_action_envelope(env, sig, key)
        elapsed = time.perf_counter() - start

        avg_us = (elapsed / 1000) * 1_000_000
        assert avg_us < 2000, f"sign+verify took {avg_us:.0f}us avg, budget is 2000us"


class TestEvidenceHashThroughput:
    def test_hash_1kb_under_100us(self):
        from packages.domain.evidence import compute_digest

        data = b"x" * 1024

        start = time.perf_counter()
        for _ in range(1000):
            compute_digest(data)
        elapsed = time.perf_counter() - start

        avg_us = (elapsed / 1000) * 1_000_000
        assert avg_us < 100, f"1KB hash took {avg_us:.0f}us avg, budget is 100us"

    def test_hash_1mb_under_5ms(self):
        from packages.domain.evidence import compute_digest

        data = b"x" * (1024 * 1024)

        start = time.perf_counter()
        for _ in range(100):
            compute_digest(data)
        elapsed = time.perf_counter() - start

        avg_us = (elapsed / 100) * 1_000_000
        assert avg_us < 5000, f"1MB hash took {avg_us:.0f}us avg, budget is 5000us"


class TestGraphQueryThroughput:
    def test_bfs_100_nodes_under_10ms(self):
        from packages.graph import (
            GraphNode, GraphEdge, EdgeLabel,
            InMemoryGraphRepository, NodeLabel,
        )

        graph = InMemoryGraphRepository()
        tid = uuid4()
        nodes = [uuid4() for _ in range(100)]

        for nid in nodes:
            graph.project_node(
                GraphNode(id=nid, tenant_id=tid, label=NodeLabel.ASSET, properties={})
            )
        for i in range(99):
            graph.project_edge(
                GraphEdge(
                    id=uuid4(), tenant_id=tid, label=EdgeLabel.LEADS_TO,
                    source_id=nodes[i], target_id=nodes[i + 1],
                )
            )

        start = time.perf_counter()
        for _ in range(10):
            graph.execute_query(
                tid, "shortest_path",
                {"source_id": nodes[0], "target_id": nodes[99]},
            )
        elapsed = time.perf_counter() - start

        avg_ms = (elapsed / 10) * 1000
        assert avg_ms < 10, f"BFS 100 nodes took {avg_ms:.1f}ms avg, budget is 10ms"


class TestSecretRedactionThroughput:
    def test_redact_secrets_under_500us(self):
        from packages.ai_gateway import redact_secrets_from_text

        text = (
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig\n"
            "Cookie: session=abc123; token=xyz789\n"
            "X-API-Key: sk-proj-1234567890\n"
        ) * 10

        start = time.perf_counter()
        for _ in range(1000):
            redact_secrets_from_text(text)
        elapsed = time.perf_counter() - start

        avg_us = (elapsed / 1000) * 1_000_000
        assert avg_us < 500, f"redaction took {avg_us:.0f}us avg, budget is 500us"
