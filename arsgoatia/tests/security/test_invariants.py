"""Security invariant tests — verifying the 30 system invariants from §3.

These tests ensure the non-negotiable invariants are enforced across
the codebase. Each test maps to one or more spec invariants.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest


class TestInvariant_NoTargetWithoutAuthorization:
    """§3 Invariant 1: No target interaction without verified authorization."""

    def test_scope_denies_when_empty(self):
        from packages.contracts.schemas.engagement import ScopeSpec
        from packages.scope import check_target

        scope = ScopeSpec(include=[], exclude=[])
        result = check_target(scope, "https://target.test/api")
        assert not result.allowed

    def test_scope_denies_out_of_scope_target(self):
        from packages.contracts.schemas.engagement import ScopeRule, ScopeSpec
        from packages.scope import check_target

        scope = ScopeSpec(
            include=[ScopeRule(type="dns_suffix", value="allowed.test", action="allow")],
            exclude=[],
        )
        result = check_target(scope, "https://evil.test/api")
        assert not result.allowed

    def test_firewall_denies_metadata_address(self):
        from packages.contracts.schemas.engagement import ScopeRule, ScopeSpec
        from packages.scope.firewall import ScopeFirewall

        scope = ScopeSpec(
            include=[ScopeRule(type="dns_suffix", value="169.254.169.254", action="allow")],
            exclude=[],
        )
        fw = ScopeFirewall(scope)
        result = fw.preflight(
            "http://169.254.169.254/latest/meta-data/",
            resolved_addresses=["169.254.169.254"],
        )
        assert not result.allowed


class TestInvariant_ImmutableRevisions:
    """§3 Invariant 2: Immutable revisions — frozen contracts cannot be mutated."""

    def test_action_envelope_frozen(self):
        from packages.contracts.schemas.action_envelope import (
            ActionEnvelope,
            EnvelopeSignature,
            RevisionDigests,
            TargetSpec,
        )
        from packages.contracts.schemas.common import MutationClass, RiskTier

        env = ActionEnvelope(
            action_id=uuid4(),
            action_digest="sha256:test",
            tenant_id=uuid4(),
            engagement_revision_id=uuid4(),
            proposal_id=uuid4(),
            actor="test",
            revisions=RevisionDigests(
                auth_digest="sha256:a", scope_digest="sha256:b", policy_digest="sha256:c"
            ),
            technique="web.authz.bola.differential",
            adapter="http-probe",
            runner="runner-1",
            target=TargetSpec(asset_id=uuid4(), locator="https://api.test/basket/1"),
            request_spec_digest="sha256:req",
            effective_risk_tier=RiskTier.R2,
            mutation_class=MutationClass.none,
            idempotency_key="sha256:idem",
            nonce="test-nonce",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            signature=EnvelopeSignature(alg="HMAC-SHA256", kid="dev", value="sig"),
        )
        with pytest.raises(Exception):
            env.action_id = uuid4()

    def test_evidence_envelope_frozen(self):
        from packages.contracts.schemas.common import Sensitivity
        from packages.contracts.schemas.evidence import (
            ArtifactRef,
            CaptureMetadata,
            EvidenceEnvelope,
        )

        ev = EvidenceEnvelope(
            evidence_id=uuid4(),
            tenant_id=uuid4(),
            engagement_revision_id=uuid4(),
            action_id=uuid4(),
            kind="http_exchange",
            artifact=ArtifactRef(
                digest="sha256:abc",
                size=100,
                media_type="application/json",
                storage_uri="evidence://test",
            ),
            capture=CaptureMetadata(
                tool="http-probe",
                tool_version="1.0.0",
                captured_at=datetime.now(timezone.utc),
            ),
            sensitivity=Sensitivity.restricted,
            signature="sig-value",
        )
        with pytest.raises(Exception):
            ev.evidence_id = uuid4()


class TestInvariant_DenyOverridesAllow:
    """§3 Invariant 3: Deny overrides allow in scope evaluation."""

    def test_deny_overrides_allow_in_scope(self):
        from packages.contracts.schemas.engagement import ScopeRule, ScopeSpec
        from packages.scope import check_target

        scope = ScopeSpec(
            include=[
                ScopeRule(type="dns_suffix", value="apps.example.test", action="allow"),
            ],
            exclude=[
                ScopeRule(
                    type="url_prefix",
                    value="https://billing.apps.example.test/",
                    action="deny",
                ),
            ],
        )
        result = check_target(scope, "https://billing.apps.example.test/api")
        assert not result.allowed


class TestInvariant_SignedEnvelopes:
    """§3 Invariant 4: Signed action envelopes — tamper detection."""

    def test_envelope_tamper_detected(self):
        from packages.envelope import sign_action_envelope, verify_action_envelope

        env = {
            "actionId": str(uuid4()),
            "tenantId": str(uuid4()),
            "engagementRevisionId": str(uuid4()),
            "technique": {"id": "bola", "version": "1.0.0"},
            "target": {"locator": "https://api.test/basket/1"},
            "effectiveRiskTier": "R2",
            "nonce": "unique-nonce",
            "expiresAt": (
                datetime.now(timezone.utc) + timedelta(minutes=5)
            ).isoformat(),
        }
        key = b"signing-key"
        sig = sign_action_envelope(env, key)
        assert verify_action_envelope(env, sig, key)

        env["actionId"] = "tampered"
        assert not verify_action_envelope(env, sig, key)

    def test_different_key_rejects(self):
        from packages.envelope import sign_action_envelope, verify_action_envelope

        env = {
            "actionId": str(uuid4()),
            "tenantId": str(uuid4()),
            "engagementRevisionId": str(uuid4()),
            "technique": {"id": "bola", "version": "1.0.0"},
            "target": {"locator": "https://api.test"},
            "effectiveRiskTier": "R2",
            "nonce": "nonce",
            "expiresAt": (
                datetime.now(timezone.utc) + timedelta(minutes=5)
            ).isoformat(),
        }
        sig = sign_action_envelope(env, b"key-a")
        assert not verify_action_envelope(env, sig, b"key-b")


class TestInvariant_MostRestrictiveWins:
    """§3 Invariant 5: Most restrictive policy decision wins."""

    def test_r5_always_denied(self):
        from packages.contracts.schemas.common import MutationClass, RiskTier
        from packages.contracts.schemas.policy import ActionRequest
        from packages.policy import PolicyContext, evaluate

        ctx = PolicyContext(
            current_time=datetime.now(timezone.utc),
        )
        request = ActionRequest(
            technique="destructive",
            target="https://api.test",
            risk_tier=RiskTier.R5,
            mutation=MutationClass.destructive,
        )

        result = evaluate(request, ctx)
        assert result.outcome.value == "deny"


class TestInvariant_R5Unsupported:
    """§3 Invariant: R5 has no exception path in the product."""

    def test_r5_in_proposal_denied(self):
        from packages.application import (
            CommandStatus,
            InMemoryActionRepo,
            InMemoryEngagementRepo,
            ProposeActionCommand,
            handle_propose_action,
        )

        eng_repo = InMemoryEngagementRepo()
        tid = uuid4()
        eid = uuid4()
        eng_repo.create(tid, {"id": eid, "state": "running"})

        result = handle_propose_action(
            ProposeActionCommand(
                tenant_id=tid,
                engagement_id=eid,
                technique_id="destructive",
                target_locator="https://api.test",
                risk_tier="R5",
                mutation_class="destructive",
                actor="planner",
            ),
            eng_repo,
            InMemoryActionRepo(),
        )
        assert result.status == CommandStatus.POLICY_DENIED


class TestInvariant_NonceReplay:
    """§3 Invariant: Nonce replay prevention."""

    def test_nonce_replay_detected(self):
        from packages.envelope import check_nonce_replay

        store: set[str] = set()
        assert not check_nonce_replay("nonce-1", store)
        assert check_nonce_replay("nonce-1", store)

    def test_crypto_nonce_store_replay(self):
        from packages.crypto import NonceStore

        ns = NonceStore()
        assert ns.check_and_record("nonce-a")
        assert not ns.check_and_record("nonce-a")


class TestInvariant_SecretsRedaction:
    """§3 Invariant: Secrets never in logs, evidence, prompts, or history."""

    def test_ai_gateway_redacts_bearer(self):
        from packages.ai_gateway import redact_secrets_from_text

        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"
        redacted, labels = redact_secrets_from_text(text)
        assert "eyJ" not in redacted
        assert len(labels) > 0

    def test_ai_gateway_redacts_basic_auth(self):
        from packages.ai_gateway import redact_secrets_from_text

        text = "Authorization: Basic dXNlcjpwYXNzd29yZA=="
        redacted, labels = redact_secrets_from_text(text)
        assert "dXNlcjpwYXNz" not in redacted

    def test_evidence_domain_redacts_headers(self):
        from packages.domain.evidence import redact_headers

        headers = {
            "content-type": "application/json",
            "authorization": "Bearer secret-token",
            "cookie": "session=abc123",
            "x-request-id": "req-123",
        }
        redacted = redact_headers(headers)
        assert redacted["content-type"] == "application/json"
        assert redacted["x-request-id"] == "req-123"
        assert "secret-token" not in redacted["authorization"]
        assert "abc123" not in redacted["cookie"]

    def test_observability_sanitizes_secret_fields(self):
        from packages.observability import sanitize_log_fields

        fields = {
            "user": "alice",
            "password": "hunter2",
            "api_key": "sk-123",
            "count": 42,
        }
        safe = sanitize_log_fields(fields)
        assert "user" in safe
        assert "count" in safe
        assert "password" not in safe
        assert "api_key" not in safe

    def test_testing_helper_catches_jwt(self):
        from packages.testing import assert_no_secrets_in_dict

        with pytest.raises(AssertionError):
            assert_no_secrets_in_dict(
                {"data": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"}
            )


class TestInvariant_TenantIsolation:
    """§3 Invariant: Zero tolerated cross-tenant disclosure."""

    def test_evidence_store_tenant_boundary(self):
        from packages.application import InMemoryEvidenceStore

        store = InMemoryEvidenceStore()
        tid_a = uuid4()
        tid_b = uuid4()
        digest = store.store(tid_a, b"sensitive", "text/plain", {})
        assert store.get_artifact(tid_b, digest) is None

    def test_engagement_repo_tenant_boundary(self):
        from packages.application import InMemoryEngagementRepo

        repo = InMemoryEngagementRepo()
        tid_a = uuid4()
        tid_b = uuid4()
        eid = uuid4()
        repo.create(tid_a, {"id": eid, "state": "running"})
        assert repo.get(tid_b, eid) is None

    def test_graph_tenant_boundary(self):
        from packages.graph import GraphNode, InMemoryGraphRepository, NodeLabel

        graph = InMemoryGraphRepository()
        tid_a = uuid4()
        tid_b = uuid4()
        nid = uuid4()
        graph.project_node(
            GraphNode(id=nid, tenant_id=tid_a, label=NodeLabel.ASSET, properties={"name": "target"})
        )
        node = graph.get_node(tid_a, nid)
        assert node is not None
        node_b = graph.get_node(tid_b, nid)
        assert node_b is None


class TestInvariant_DangerousAddressBlocked:
    """§3 Invariant: SSRF protection — metadata/loopback/link-local blocked."""

    @pytest.mark.parametrize(
        "url,resolved_ip",
        [
            ("http://169.254.169.254/latest/meta-data/", "169.254.169.254"),
            ("http://127.0.0.1:8080/admin", "127.0.0.1"),
            ("http://[::1]:8080/admin", "::1"),
            ("http://0.0.0.0:8080", "0.0.0.0"),
        ],
    )
    def test_dangerous_addresses_blocked(self, url, resolved_ip):
        from packages.contracts.schemas.engagement import ScopeRule, ScopeSpec
        from packages.scope.firewall import ScopeFirewall

        scope = ScopeSpec(
            include=[ScopeRule(type="dns_suffix", value="*", action="allow")],
            exclude=[],
        )
        fw = ScopeFirewall(scope)
        result = fw.preflight(url, resolved_addresses=[resolved_ip])
        assert not result.allowed, f"{url} should be blocked"


class TestInvariant_CleanupRequired:
    """§3 Invariant: Mutation actions require cleanup verification."""

    def test_mutation_requires_cleanup(self):
        from packages.domain.execution import ActionState, requires_cleanup

        assert requires_cleanup(ActionState.SUCCEEDED, "reversible")
        assert requires_cleanup(ActionState.FAILED, "state_changing")

    def test_no_mutation_no_cleanup(self):
        from packages.domain.execution import ActionState, requires_cleanup

        assert not requires_cleanup(ActionState.SUCCEEDED, "none")
        assert not requires_cleanup(ActionState.RUNNING, "none")


class TestInvariant_DeterministicConfirmation:
    """§3 Invariant: Finding confirmation is deterministic, never AI."""

    def test_bola_confirmation_deterministic(self):
        from packs.techniques.web_authz.bola_differential import (
            ExchangeResult,
            confirm_bola,
        )

        baseline = ExchangeResult(
            label="baseline",
            status_code=200,
            body_contains_object=True,
            object_id="basket-1",
            evidence_digest="sha256:a",
        )
        differential = ExchangeResult(
            label="differential",
            status_code=200,
            body_contains_object=True,
            object_id="basket-1",
            evidence_digest="sha256:b",
        )
        positive_control = ExchangeResult(
            label="positive_control",
            status_code=200,
            body_contains_object=True,
            object_id="basket-2",
            evidence_digest="sha256:c",
        )
        negative_control = ExchangeResult(
            label="negative_control",
            status_code=401,
            body_contains_object=False,
            object_id="basket-1",
            evidence_digest="sha256:d",
        )
        result = confirm_bola(baseline, differential, positive_control, negative_control)
        assert result.confirmed

    def test_bola_rejects_without_proper_negative_control(self):
        from packs.techniques.web_authz.bola_differential import (
            ExchangeResult,
            confirm_bola,
        )

        baseline = ExchangeResult(
            label="baseline", status_code=200, body_contains_object=True,
            object_id="1", evidence_digest="sha256:a",
        )
        differential = ExchangeResult(
            label="differential", status_code=200, body_contains_object=True,
            object_id="1", evidence_digest="sha256:b",
        )
        positive_control = ExchangeResult(
            label="positive_control", status_code=200, body_contains_object=True,
            object_id="2", evidence_digest="sha256:c",
        )
        negative_control = ExchangeResult(
            label="negative_control", status_code=200, body_contains_object=True,
            object_id="1", evidence_digest="sha256:d",
        )
        result = confirm_bola(baseline, differential, positive_control, negative_control)
        assert not result.confirmed


class TestInvariant_IAMApprovalRequiresMFA:
    """§3 Invariant: High-risk approval requires MFA."""

    def test_high_risk_approval_requires_mfa(self):
        from packages.domain.iam import (
            AuthContext,
            PlatformRole,
            Principal,
            PrincipalType,
            can_approve_high_risk,
        )

        principal = Principal(
            id=uuid4(),
            tenant_id=uuid4(),
            principal_type=PrincipalType.USER,
            name="op",
            roles=frozenset({PlatformRole.APPROVER}),
            teams=frozenset(),
        )
        ctx_no_mfa = AuthContext(
            principal=principal,
            tenant_id=principal.tenant_id,
            session_id=uuid4(),
            authenticated_at=datetime.now(timezone.utc),
            mfa_verified=False,
        )
        assert not can_approve_high_risk(ctx_no_mfa)

        ctx_with_mfa = AuthContext(
            principal=principal,
            tenant_id=principal.tenant_id,
            session_id=uuid4(),
            authenticated_at=datetime.now(timezone.utc),
            mfa_verified=True,
        )
        assert can_approve_high_risk(ctx_with_mfa)


class TestInvariant_TwoPersonRule:
    """§3 / §13.8: Two-person rule — R4 actions require a different approver."""

    def test_requestor_cannot_approve_own_r4_request(self):
        from packages.approval import ApprovalRegistry, TwoPersonRuleError

        reg = ApprovalRegistry()
        tid = uuid4()
        eid = uuid4()
        aid = uuid4()
        reg.create_request(
            tenant_id=tid, engagement_id=eid, action_id=aid,
            envelope_digest="sha256:abc", risk_tier="R4",
            requestor_id="alice", requires_two_person=True,
        )
        with pytest.raises(TwoPersonRuleError):
            reg.grant(tid, aid, "alice")

    def test_different_approver_satisfies_two_person_rule(self):
        from packages.approval import ApprovalRegistry, ApprovalState

        reg = ApprovalRegistry()
        tid = uuid4()
        eid = uuid4()
        aid = uuid4()
        reg.create_request(
            tenant_id=tid, engagement_id=eid, action_id=aid,
            envelope_digest="sha256:abc", risk_tier="R4",
            requestor_id="alice", requires_two_person=True,
        )
        decision = reg.grant(tid, aid, "bob")
        assert decision.state == ApprovalState.GRANTED

    def test_approval_is_action_bound_no_reuse(self):
        """A granted approval for action_id=X cannot satisfy a different action_id=Y."""
        from packages.approval import ApprovalRegistry

        reg = ApprovalRegistry()
        tid = uuid4()
        eid = uuid4()
        aid_x = uuid4()
        aid_y = uuid4()
        reg.create_request(
            tenant_id=tid, engagement_id=eid, action_id=aid_x,
            envelope_digest="sha256:x", risk_tier="R2", requestor_id="alice",
        )
        reg.grant(tid, aid_x, "bob")
        # Y has no request at all → is_approved must return False
        assert not reg.is_approved(tid, aid_y)

    def test_generic_approved_flag_rejected(self):
        """Approval must be bound to an exact action; generic bool is rejected."""
        from packages.approval import ApprovalRegistry

        reg = ApprovalRegistry()
        tid = uuid4()
        # Without a matching request, is_approved is always False
        assert not reg.is_approved(tid, uuid4())


class TestInvariant_ApprovalBinding:
    """§13.8: Binding digest links approval to exact envelope content."""

    def test_tampered_envelope_invalidates_binding(self):
        from packages.approval import ApprovalRegistry

        reg = ApprovalRegistry()
        tid = uuid4()
        eid = uuid4()
        aid = uuid4()
        reg.create_request(
            tenant_id=tid, engagement_id=eid, action_id=aid,
            envelope_digest="sha256:original", risk_tier="R2", requestor_id="alice",
        )
        decision = reg.grant(tid, aid, "bob")
        # Tamper: different envelope_digest
        assert not reg.verify_binding(tid, aid, "sha256:tampered", decision.binding_digest)

    def test_correct_envelope_validates_binding(self):
        from packages.approval import ApprovalRegistry

        reg = ApprovalRegistry()
        tid = uuid4()
        eid = uuid4()
        aid = uuid4()
        reg.create_request(
            tenant_id=tid, engagement_id=eid, action_id=aid,
            envelope_digest="sha256:original", risk_tier="R2", requestor_id="alice",
        )
        decision = reg.grant(tid, aid, "bob")
        assert reg.verify_binding(tid, aid, "sha256:original", decision.binding_digest)

    def test_expired_approval_not_valid(self):
        from packages.approval import ApprovalRegistry, ApprovalRequest

        reg = ApprovalRegistry()
        tid = uuid4()
        eid = uuid4()
        aid = uuid4()
        reg.create_request(
            tenant_id=tid, engagement_id=eid, action_id=aid,
            envelope_digest="sha256:abc", risk_tier="R2", requestor_id="alice",
            expires_in=timedelta(hours=1),
        )
        reg.grant(tid, aid, "bob")
        # Manually expire the request
        req = reg.get_request_for_action(tid, aid)
        expired_req = ApprovalRequest(
            request_id=req.request_id,
            tenant_id=req.tenant_id,
            engagement_id=req.engagement_id,
            action_id=req.action_id,
            envelope_digest=req.envelope_digest,
            risk_tier=req.risk_tier,
            requestor_id=req.requestor_id,
            requires_two_person=req.requires_two_person,
            metadata=req.metadata,
            created_at=req.created_at,
            expires_at=req.created_at - timedelta(seconds=1),
        )
        reg._requests[(tid, req.request_id)] = expired_req
        assert not reg.is_approved(tid, aid)


class TestInvariant_BudgetEmergencyStop:
    """§9.6: Emergency stop zeroes budget immediately and is irreversible."""

    def test_emergency_stop_denies_all_subsequent_requests(self):
        from packages.rate_limiter import BudgetLedger, BudgetDenialReason, BudgetSpec

        ledger = BudgetLedger()
        tid, eid = uuid4(), uuid4()
        ledger.register(tid, eid, BudgetSpec(requests_per_second=1000.0, burst_capacity=1000))
        # Before stop: allowed
        assert ledger.check(tid, eid, requests_needed=1).allowed
        # Emergency stop
        ledger.emergency_stop(tid, eid)
        result = ledger.check(tid, eid, requests_needed=1)
        assert not result.allowed
        assert result.denial_reason == BudgetDenialReason.EMERGENCY_STOP

    def test_emergency_stop_is_irreversible(self):
        from packages.rate_limiter import BudgetLedger, BudgetSpec

        ledger = BudgetLedger()
        tid, eid = uuid4(), uuid4()
        ledger.register(tid, eid, BudgetSpec(requests_per_second=1000.0, burst_capacity=1000))
        ledger.emergency_stop(tid, eid)
        # No method to reverse it — still stopped
        assert ledger.is_emergency_stopped(tid, eid)

    def test_emergency_stop_does_not_affect_other_engagements(self):
        from packages.rate_limiter import BudgetLedger, BudgetSpec

        ledger = BudgetLedger()
        tid, eid_a, eid_b = uuid4(), uuid4(), uuid4()
        spec = BudgetSpec(requests_per_second=1000.0, burst_capacity=1000)
        ledger.register(tid, eid_a, spec)
        ledger.register(tid, eid_b, spec)
        ledger.emergency_stop(tid, eid_a)
        assert not ledger.check(tid, eid_a, requests_needed=1).allowed
        assert ledger.check(tid, eid_b, requests_needed=1).allowed


class TestInvariant_TruthMaintenance:
    """PRX-019: Retracting an observation cascades STALE to dependent hypotheses."""

    def test_retraction_cascades_stale(self):
        from packages.hypothesis import HypothesisRegistry, HypothesisState

        reg = HypothesisRegistry()
        tid, eid = uuid4(), uuid4()
        h = reg.create(tid, eid, "authz may be absent", "differential pattern observed")
        obs = reg.record_observation(tid, eid, "http_response", {"status": 200}, "tool")
        reg.link_observation(tid, h.hypothesis_id, obs.observation_id)
        reg.retract_observation(tid, obs.observation_id, "contradicted")
        assert reg.get(tid, h.hypothesis_id).state == HypothesisState.STALE

    def test_stale_hypothesis_can_be_reopened_with_new_evidence(self):
        from packages.hypothesis import HypothesisRegistry, HypothesisState

        reg = HypothesisRegistry()
        tid, eid = uuid4(), uuid4()
        h = reg.create(tid, eid, "authz may be absent", "differential pattern observed")
        obs = reg.record_observation(tid, eid, "http_response", {"status": 200}, "tool")
        reg.link_observation(tid, h.hypothesis_id, obs.observation_id)
        reg.retract_observation(tid, obs.observation_id)
        reg.transition(tid, h.hypothesis_id, HypothesisState.OPEN, "re-investigating")
        assert reg.get(tid, h.hypothesis_id).state == HypothesisState.OPEN
