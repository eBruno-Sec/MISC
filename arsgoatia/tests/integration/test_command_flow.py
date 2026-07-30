"""Integration tests: full command flows across application + domain layers.

These tests exercise the command handlers with in-memory infrastructure,
verifying that the application layer correctly orchestrates domain logic,
event emission, and audit recording end-to-end.
"""

from __future__ import annotations

from uuid import uuid4

from packages.application import (
    ApproveActionCommand,
    CommandStatus,
    CreateEngagementCommand,
    EmergencyStopCommand,
    InMemoryActionRepo,
    InMemoryAuditLog,
    InMemoryEngagementRepo,
    InMemoryEventBus,
    InMemoryEvidenceStore,
    PauseEngagementCommand,
    ProposeActionCommand,
    RecordEvidenceCommand,
    RejectActionCommand,
    ResumeEngagementCommand,
    StartEngagementCommand,
    handle_approve_action,
    handle_create_engagement,
    handle_emergency_stop,
    handle_pause_engagement,
    handle_propose_action,
    handle_record_evidence,
    handle_reject_action,
    handle_resume_engagement,
    handle_start_engagement,
)
from packages.approval import ApprovalRegistry
from packages.rate_limiter import BudgetLedger, BudgetSpec
from packages.testing import (
    assert_audit_recorded,
    hours_from_now,
    utcnow,
)


class TestFullEngagementLifecycle:
    """Test the entire engagement lifecycle from creation through emergency stop."""

    def setup_method(self):
        self.eng_repo = InMemoryEngagementRepo()
        self.action_repo = InMemoryActionRepo()
        self.evidence_store = InMemoryEvidenceStore()
        self.bus = InMemoryEventBus()
        self.audit = InMemoryAuditLog()
        self.tenant_id = uuid4()
        self.actor = "operator@test.com"

    def _create_engagement(self):
        cmd = CreateEngagementCommand(
            tenant_id=self.tenant_id,
            name="acme-q3-web",
            actor=self.actor,
            authorization_artifact_digest="sha256:auth123",
            valid_from=utcnow(),
            valid_until=hours_from_now(168),
            scope_rules=[{"type": "dns_suffix", "value": "apps.example.test", "action": "allow"}],
            allowed_risk_tiers=["R0", "R1", "R2"],
            budget={"requests": 50000, "ai_cost_usd": 25},
        )
        result = handle_create_engagement(cmd, self.eng_repo, self.bus, self.audit)
        assert result.status == CommandStatus.SUCCESS
        return result.resource_id

    def _advance_to_ready(self, engagement_id):
        self.eng_repo.update_state(self.tenant_id, engagement_id, "ready")

    def test_create_start_pause_resume_stop(self):
        eid = self._create_engagement()
        self._advance_to_ready(eid)

        result = handle_start_engagement(
            StartEngagementCommand(tenant_id=self.tenant_id, engagement_id=eid, actor=self.actor),
            self.eng_repo,
            self.bus,
            self.audit,
        )
        assert result.status == CommandStatus.SUCCESS
        assert self.eng_repo.get(self.tenant_id, eid)["state"] == "running"

        result = handle_pause_engagement(
            PauseEngagementCommand(
                tenant_id=self.tenant_id,
                engagement_id=eid,
                actor=self.actor,
                reason="lunch break",
            ),
            self.eng_repo,
            self.bus,
        )
        assert result.status == CommandStatus.SUCCESS

        result = handle_resume_engagement(
            ResumeEngagementCommand(tenant_id=self.tenant_id, engagement_id=eid, actor=self.actor),
            self.eng_repo,
            self.bus,
        )
        assert result.status == CommandStatus.SUCCESS
        assert self.eng_repo.get(self.tenant_id, eid)["state"] == "running"

        result = handle_emergency_stop(
            EmergencyStopCommand(
                tenant_id=self.tenant_id,
                engagement_id=eid,
                actor=self.actor,
                reason="threat detected",
            ),
            self.eng_repo,
            self.bus,
            self.audit,
        )
        assert result.status == CommandStatus.SUCCESS
        assert self.eng_repo.get(self.tenant_id, eid)["state"] == "stopping"

    def test_events_emitted_for_full_lifecycle(self):
        eid = self._create_engagement()
        self._advance_to_ready(eid)

        handle_start_engagement(
            StartEngagementCommand(tenant_id=self.tenant_id, engagement_id=eid, actor=self.actor),
            self.eng_repo,
            self.bus,
        )
        handle_pause_engagement(
            PauseEngagementCommand(tenant_id=self.tenant_id, engagement_id=eid, actor=self.actor),
            self.eng_repo,
            self.bus,
        )
        handle_resume_engagement(
            ResumeEngagementCommand(tenant_id=self.tenant_id, engagement_id=eid, actor=self.actor),
            self.eng_repo,
            self.bus,
        )

        event_types = [e.event_type for e in self.bus.events]
        assert "engagement.created" in event_types
        assert "engagement.started" in event_types
        assert "engagement.paused" in event_types
        assert "engagement.resumed" in event_types

    def test_audit_trail_for_lifecycle(self):
        eid = self._create_engagement()
        self._advance_to_ready(eid)

        handle_start_engagement(
            StartEngagementCommand(tenant_id=self.tenant_id, engagement_id=eid, actor=self.actor),
            self.eng_repo,
            self.bus,
            self.audit,
        )

        assert_audit_recorded(self.audit.entries, "create_engagement", "engagement")
        assert_audit_recorded(self.audit.entries, "start_engagement", "engagement")


class TestActionProposalApprovalFlow:
    """Test the propose -> approve -> execute -> evidence flow."""

    def setup_method(self):
        self.eng_repo = InMemoryEngagementRepo()
        self.action_repo = InMemoryActionRepo()
        self.evidence_store = InMemoryEvidenceStore()
        self.bus = InMemoryEventBus()
        self.audit = InMemoryAuditLog()
        self.tenant_id = uuid4()

        eid = uuid4()
        self.engagement_id = eid
        self.eng_repo.create(
            self.tenant_id,
            {
                "id": eid,
                "tenant_id": self.tenant_id,
                "name": "test",
                "state": "running",
            },
        )

    def test_propose_approve_record_evidence(self):
        propose_result = handle_propose_action(
            ProposeActionCommand(
                tenant_id=self.tenant_id,
                engagement_id=self.engagement_id,
                technique_id="web.authz.bola.differential",
                target_locator="https://api.test/basket/1",
                risk_tier="R2",
                mutation_class="none",
                actor="planner",
            ),
            self.eng_repo,
            self.action_repo,
            self.bus,
        )
        assert propose_result.status == CommandStatus.SUCCESS
        action_id = propose_result.resource_id

        self.action_repo.update_state(self.tenant_id, action_id, "approval_required")

        approve_result = handle_approve_action(
            ApproveActionCommand(
                tenant_id=self.tenant_id,
                action_id=action_id,
                approver="approver@test",
                decision_digest="sha256:decision123",
            ),
            self.action_repo,
            self.bus,
            self.audit,
        )
        assert approve_result.status == CommandStatus.SUCCESS
        assert self.action_repo.get(self.tenant_id, action_id)["state"] == "approved"

        evidence_result = handle_record_evidence(
            RecordEvidenceCommand(
                tenant_id=self.tenant_id,
                action_id=action_id,
                data=b'{"status": 200, "body": {"id": 1, "products": []}}',
                media_type="application/json",
                actor="runner-1",
            ),
            self.evidence_store,
            self.bus,
        )
        assert evidence_result.status == CommandStatus.SUCCESS
        digest = evidence_result.data["digest"]
        assert digest.startswith("sha256:")

        stored = self.evidence_store.get_artifact(self.tenant_id, digest)
        assert stored is not None
        assert b"status" in stored

    def test_full_event_chain(self):
        propose_result = handle_propose_action(
            ProposeActionCommand(
                tenant_id=self.tenant_id,
                engagement_id=self.engagement_id,
                technique_id="web.authz.bola.differential",
                target_locator="https://api.test/basket/1",
                risk_tier="R2",
                mutation_class="none",
                actor="planner",
            ),
            self.eng_repo,
            self.action_repo,
            self.bus,
        )
        action_id = propose_result.resource_id
        self.action_repo.update_state(self.tenant_id, action_id, "approval_required")

        handle_approve_action(
            ApproveActionCommand(
                tenant_id=self.tenant_id,
                action_id=action_id,
                approver="approver@test",
                decision_digest="sha256:d",
            ),
            self.action_repo,
            self.bus,
        )

        handle_record_evidence(
            RecordEvidenceCommand(
                tenant_id=self.tenant_id,
                action_id=action_id,
                data=b"evidence bytes",
                media_type="application/octet-stream",
                actor="runner-1",
            ),
            self.evidence_store,
            self.bus,
        )

        event_types = [e.event_type for e in self.bus.events]
        assert "action.proposed" in event_types
        assert "action.approved" in event_types
        assert "evidence.captured" in event_types

    def test_r5_denied_in_proposal_flow(self):
        result = handle_propose_action(
            ProposeActionCommand(
                tenant_id=self.tenant_id,
                engagement_id=self.engagement_id,
                technique_id="destructive.rm_rf",
                target_locator="https://api.test",
                risk_tier="R5",
                mutation_class="destructive",
                actor="planner",
            ),
            self.eng_repo,
            self.action_repo,
            self.bus,
        )
        assert result.status == CommandStatus.POLICY_DENIED
        assert len(self.bus.events) == 0


class TestTenantIsolation:
    """Verify that tenant boundaries are enforced across all operations."""

    def test_tenant_a_cannot_see_tenant_b_engagement(self):
        repo = InMemoryEngagementRepo()
        tid_a = uuid4()
        tid_b = uuid4()
        eid = uuid4()
        repo.create(tid_a, {"id": eid, "state": "running"})
        assert repo.get(tid_a, eid) is not None
        assert repo.get(tid_b, eid) is None

    def test_tenant_a_cannot_see_tenant_b_evidence(self):
        store = InMemoryEvidenceStore()
        tid_a = uuid4()
        tid_b = uuid4()
        digest = store.store(tid_a, b"sensitive finding", "text/plain", {})
        assert store.get_artifact(tid_a, digest) is not None
        assert store.get_artifact(tid_b, digest) is None

    def test_tenant_a_cannot_approve_tenant_b_action(self):
        repo = InMemoryActionRepo()
        tid_a = uuid4()
        tid_b = uuid4()
        aid = uuid4()
        repo.create(tid_a, {"id": aid, "state": "approval_required"})

        result = handle_approve_action(
            ApproveActionCommand(
                tenant_id=tid_b,
                action_id=aid,
                approver="attacker",
                decision_digest="sha256:bad",
            ),
            repo,
        )
        assert result.status == CommandStatus.NOT_FOUND

    def test_tenant_a_cannot_start_tenant_b_engagement(self):
        repo = InMemoryEngagementRepo()
        tid_a = uuid4()
        tid_b = uuid4()
        eid = uuid4()
        repo.create(tid_a, {"id": eid, "state": "ready"})

        result = handle_start_engagement(
            StartEngagementCommand(tenant_id=tid_b, engagement_id=eid, actor="op"),
            repo,
        )
        assert result.status == CommandStatus.NOT_FOUND

    def test_evidence_tenant_isolation_on_metadata(self):
        store = InMemoryEvidenceStore()
        tid_a = uuid4()
        tid_b = uuid4()
        digest = store.store(tid_a, b"data", "text/plain", {"secret": "value"})
        assert store.get_metadata(tid_a, digest) is not None
        assert store.get_metadata(tid_b, digest) is None


class TestOutboxEventRelay:
    """Test the outbox -> relay -> subscriber pipeline."""

    def test_outbox_relay_dispatches_to_subscribers(self):
        from packages.events import (
            EventSubscription,
            InMemoryOutbox,
            OutboxRelay,
            create_outbox_entry,
        )

        outbox = InMemoryOutbox()
        subs = EventSubscription()
        received = []
        subs.subscribe("finding.confirmed", lambda e: received.append(e))

        entry = create_outbox_entry(
            "finding.confirmed",
            uuid4(),
            "finding",
            uuid4(),
            {"severity": "high", "cwe": "CWE-639"},
        )
        outbox.write(entry)

        relay = OutboxRelay(outbox, subs)
        dispatched = relay.poll_and_dispatch()
        assert dispatched == 1
        assert len(received) == 1
        assert received[0].payload["cwe"] == "CWE-639"

    def test_outbox_relay_multiple_event_types(self):
        from packages.events import (
            EventSubscription,
            InMemoryOutbox,
            OutboxRelay,
            create_outbox_entry,
        )

        outbox = InMemoryOutbox()
        subs = EventSubscription()
        actions = []
        findings = []
        subs.subscribe("action.proposed", lambda e: actions.append(e))
        subs.subscribe("finding.confirmed", lambda e: findings.append(e))

        outbox.write(create_outbox_entry("action.proposed", uuid4(), "action", uuid4()))
        outbox.write(create_outbox_entry("finding.confirmed", uuid4(), "finding", uuid4()))
        outbox.write(create_outbox_entry("action.proposed", uuid4(), "action", uuid4()))

        relay = OutboxRelay(outbox, subs)
        relay.poll_and_dispatch()
        assert len(actions) == 2
        assert len(findings) == 1


class TestApprovalGateFlow:
    """Full approval-gate-pause-resume flow per §37 steps 7-14."""

    def setup_method(self):
        self.eng_repo = InMemoryEngagementRepo()
        self.action_repo = InMemoryActionRepo()
        self.evidence_store = InMemoryEvidenceStore()
        self.bus = InMemoryEventBus()
        self.audit = InMemoryAuditLog()
        self.approval_reg = ApprovalRegistry()
        self.budget_ledger = BudgetLedger()
        self.tenant_id = uuid4()
        self.engagement_id = uuid4()
        spec = BudgetSpec(
            max_requests=100,
            max_cost_usd=5.0,
            max_concurrent=5,
            requests_per_second=100.0,
            burst_capacity=100,
        )
        self.budget_ledger.register(self.tenant_id, self.engagement_id, spec)
        self.eng_repo.create(
            self.tenant_id,
            {
                "id": self.engagement_id,
                "state": "running",
                "started_at": utcnow().isoformat(),
            },
        )

    def test_full_approve_gate_flow(self):
        """propose→pause→request_approval→grant→resume→execute."""
        # 1. Propose R2 action (with approval registry: creates request)
        propose_result = handle_propose_action(
            ProposeActionCommand(
                tenant_id=self.tenant_id,
                engagement_id=self.engagement_id,
                technique_id="web.authz.bola.differential",
                target_locator="http://juice-shop:3000/rest/basket/1",
                risk_tier="R2",
                mutation_class="none",
                actor="planner",
            ),
            self.eng_repo,
            self.action_repo,
            self.bus,
            budget_ledger=self.budget_ledger,
            approval_registry=self.approval_reg,
        )
        assert propose_result.status == CommandStatus.SUCCESS
        assert propose_result.data.get("requires_approval") is True
        action_id = propose_result.resource_id

        # 2. Pause engagement (waiting for approval)
        pause_result = handle_pause_engagement(
            PauseEngagementCommand(
                tenant_id=self.tenant_id,
                engagement_id=self.engagement_id,
                actor="orchestrator",
                reason="awaiting R2 approval",
            ),
            self.eng_repo,
            self.bus,
        )
        assert pause_result.status == CommandStatus.SUCCESS
        assert self.eng_repo.get(self.tenant_id, self.engagement_id)["state"] == "paused"

        # 3. Approval request already created by propose handler
        req = self.approval_reg.get_request_for_action(self.tenant_id, action_id)
        assert req is not None
        assert req.requestor_id == "planner"
        assert req.risk_tier == "R2"
        assert not self.approval_reg.is_approved(self.tenant_id, action_id)

        # 4. Grant approval from a different actor
        approve_result = handle_approve_action(
            ApproveActionCommand(
                tenant_id=self.tenant_id,
                action_id=action_id,
                approver="security-lead",
                reason="approved for Juice Shop",
            ),
            self.action_repo,
            self.bus,
            self.audit,
            approval_registry=self.approval_reg,
        )
        assert approve_result.status == CommandStatus.SUCCESS
        binding = approve_result.data.get("binding_digest", "")
        assert binding.startswith("sha256:")
        assert self.approval_reg.is_approved(self.tenant_id, action_id)

        # 5. Verify binding matches
        assert self.approval_reg.verify_binding(
            self.tenant_id, action_id, req.envelope_digest, binding
        )

        # 6. Resume engagement
        resume_result = handle_resume_engagement(
            ResumeEngagementCommand(
                tenant_id=self.tenant_id,
                engagement_id=self.engagement_id,
                actor="orchestrator",
            ),
            self.eng_repo,
            self.bus,
        )
        assert resume_result.status == CommandStatus.SUCCESS
        assert self.eng_repo.get(self.tenant_id, self.engagement_id)["state"] == "running"

        # 7. Check events emitted
        event_types = [e.event_type for e in self.bus.events]
        assert "action.proposed" in event_types
        assert "engagement.paused" in event_types
        assert "action.approved" in event_types
        assert "engagement.resumed" in event_types

    def test_rejected_action_flow(self):
        """propose→reject: action goes to rejected, no execution possible."""
        propose_result = handle_propose_action(
            ProposeActionCommand(
                tenant_id=self.tenant_id,
                engagement_id=self.engagement_id,
                technique_id="web.authz.bola.write",
                target_locator="http://juice-shop:3000/api/users",
                risk_tier="R2",
                mutation_class="write",
                actor="planner",
            ),
            self.eng_repo,
            self.action_repo,
            self.bus,
            approval_registry=self.approval_reg,
        )
        action_id = propose_result.resource_id

        reject_result = handle_reject_action(
            RejectActionCommand(
                tenant_id=self.tenant_id,
                action_id=action_id,
                approver="security-lead",
                reason="out of scope for this engagement",
            ),
            self.action_repo,
            self.bus,
            self.audit,
            approval_registry=self.approval_reg,
        )
        assert reject_result.status == CommandStatus.SUCCESS
        assert self.action_repo.get(self.tenant_id, action_id)["state"] == "rejected"
        assert not self.approval_reg.is_approved(self.tenant_id, action_id)
        event_types = [e.event_type for e in self.bus.events]
        assert "action.rejected" in event_types

    def test_budget_exhausted_blocks_proposals(self):
        """Once budget is exhausted, propose returns POLICY_DENIED."""
        exhausted_ledger = BudgetLedger()
        exhausted_spec = BudgetSpec(
            max_requests=1,
            max_cost_usd=0.0,
            requests_per_second=100.0,
            burst_capacity=1,
        )
        exhausted_ledger.register(self.tenant_id, self.engagement_id, exhausted_spec)
        # Use the 1 allowed request
        exhausted_ledger.consume(self.tenant_id, self.engagement_id, uuid4(), 1)
        # Now propose should be denied
        result = handle_propose_action(
            ProposeActionCommand(
                tenant_id=self.tenant_id,
                engagement_id=self.engagement_id,
                technique_id="web.recon",
                target_locator="http://juice-shop:3000",
                risk_tier="R1",
                mutation_class="none",
                actor="planner",
            ),
            self.eng_repo,
            self.action_repo,
            budget_ledger=exhausted_ledger,
        )
        assert result.status == CommandStatus.POLICY_DENIED

    def test_emergency_stop_integration(self):
        """Emergency stop blocks budget and marks engagement stopping."""
        handle_emergency_stop(
            EmergencyStopCommand(
                tenant_id=self.tenant_id,
                engagement_id=self.engagement_id,
                actor="security-lead",
                reason="threat detected",
            ),
            self.eng_repo,
            self.bus,
            self.audit,
        )
        self.budget_ledger.emergency_stop(self.tenant_id, self.engagement_id)
        assert self.budget_ledger.is_emergency_stopped(self.tenant_id, self.engagement_id)
        assert self.eng_repo.get(self.tenant_id, self.engagement_id)["state"] == "stopping"
        # Budget check after emergency stop
        assert not self.budget_ledger.check(
            self.tenant_id, self.engagement_id, requests_needed=1
        ).allowed


class TestCrossModuleEvidence:
    """Test evidence flow: store -> retrieve -> verify digest."""

    def test_evidence_digest_is_content_addressed(self):
        store = InMemoryEvidenceStore()
        tid = uuid4()
        data = b'{"status": 200, "body": "test"}'
        digest1 = store.store(tid, data, "application/json", {"label": "first"})
        digest2 = store.store(tid, data, "application/json", {"label": "second"})
        assert digest1 == digest2

    def test_different_content_different_digest(self):
        store = InMemoryEvidenceStore()
        tid = uuid4()
        d1 = store.store(tid, b"content-a", "text/plain", {})
        d2 = store.store(tid, b"content-b", "text/plain", {})
        assert d1 != d2

    def test_evidence_metadata_includes_media_type(self):
        store = InMemoryEvidenceStore()
        tid = uuid4()
        digest = store.store(tid, b"data", "application/json", {"kind": "http_exchange"})
        meta = store.get_metadata(tid, digest)
        assert meta["media_type"] == "application/json"
        assert meta["kind"] == "http_exchange"
