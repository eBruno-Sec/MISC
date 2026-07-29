"""Full §37 vertical slice integration test — in-memory, no Docker required.

Exercises the complete IDOR slice chain using only in-memory registries:
  engagement lifecycle → observation → hypothesis → policy → approval gate
  → differential evidence → finding confirmation → capability proof → chain step.

This mirrors every mandatory event in tests/histories/idor_slice.json
but validates the live Python code, not just the fixture JSON.
"""
from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from uuid import uuid4

import pytest

from packages.application import (
    ApproveActionCommand,
    CommandStatus,
    CreateEngagementCommand,
    EmergencyStopCommand,
    InMemoryActionRepo,
    InMemoryAuditLog,
    InMemoryEngagementRepo,
    InMemoryEvidenceStore,
    InMemoryEventBus,
    PauseEngagementCommand,
    ProposeActionCommand,
    RecordEvidenceCommand,
    ResumeEngagementCommand,
    StartEngagementCommand,
    handle_approve_action,
    handle_create_engagement,
    handle_emergency_stop,
    handle_pause_engagement,
    handle_propose_action,
    handle_record_evidence,
    handle_resume_engagement,
    handle_start_engagement,
)
from packages.approval import ApprovalRegistry
from packages.capability import CapabilityRegistry, FindingNotConfirmedError
from packages.hypothesis import (
    HypothesisRegistry,
    HypothesisState,
)
from packages.rate_limiter import BudgetLedger, BudgetSpec
from packages.testing import hours_from_now, utcnow
from packs.techniques.web_authz.bola_differential import (
    BOLAConfirmation,
    ExchangeResult,
    build_capability,
    confirm_bola,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _evidence_bytes(exchanges: list[dict]) -> bytes:
    return json.dumps(exchanges, sort_keys=True).encode()


# ---------------------------------------------------------------------------
# Main slice fixture
# ---------------------------------------------------------------------------

class TestVerticalSliceIDOR:
    """Walk through every mandatory §37 step in one coherent test chain."""

    def setup_method(self):
        self.tenant_id = uuid4()
        self.engagement_id = uuid4()
        self.actor = "pentest-operator"

        # Registries
        self.eng_repo = InMemoryEngagementRepo()
        self.action_repo = InMemoryActionRepo()
        self.evidence_store = InMemoryEvidenceStore()
        self.bus = InMemoryEventBus()
        self.audit = InMemoryAuditLog()
        self.approval_registry = ApprovalRegistry()
        self.hypothesis_registry = HypothesisRegistry()
        self.capability_registry = CapabilityRegistry()
        # Unregistered engagements use default BudgetSpec (50K requests) — fine for tests
        self.budget_ledger = BudgetLedger()

    # ── Step 1 — engagement.created ─────────────────────────────────────

    def test_step01_create_engagement(self):
        result = handle_create_engagement(
            CreateEngagementCommand(
                tenant_id=self.tenant_id,
                name="juice-shop-idor-slice",
                actor=self.actor,
                authorization_artifact_digest="sha256:auth-artifact-idor",
                valid_from=utcnow(),
                valid_until=hours_from_now(72),
                scope_rules=[
                    {"type": "exact_host", "value": "juice-shop", "action": "allow"},
                    {"type": "port_pin", "value": "3000", "action": "allow"},
                ],
                allowed_risk_tiers=["R0", "R1", "R2"],
                budget={"requests": 500, "ai_cost_usd": 5.0},
            ),
            self.eng_repo,
            self.bus,
            self.audit,
        )
        assert result.status == CommandStatus.SUCCESS
        eng = self.eng_repo.get(self.tenant_id, result.resource_id)
        assert eng is not None
        assert eng["state"] == "draft"

        emitted = [e.event_type for e in self.bus.events]
        assert "engagement.created" in emitted

    # ── Step 2 — engagement.started ─────────────────────────────────────

    def test_step02_start_engagement(self):
        result = handle_create_engagement(
            CreateEngagementCommand(
                tenant_id=self.tenant_id,
                name="juice-shop-idor-slice",
                actor=self.actor,
                authorization_artifact_digest="sha256:auth-artifact-idor",
                valid_from=utcnow(),
                valid_until=hours_from_now(72),
                scope_rules=[],
                allowed_risk_tiers=["R0", "R1", "R2"],
            ),
            self.eng_repo,
            self.bus,
            self.audit,
        )
        eid = result.resource_id
        self.eng_repo.update_state(self.tenant_id, eid, "ready")

        started = handle_start_engagement(
            StartEngagementCommand(
                tenant_id=self.tenant_id, engagement_id=eid, actor=self.actor
            ),
            self.eng_repo,
            self.bus,
            self.audit,
        )
        assert started.status == CommandStatus.SUCCESS
        assert self.eng_repo.get(self.tenant_id, eid)["state"] == "running"

        emitted = [e.event_type for e in self.bus.events]
        assert "engagement.started" in emitted

    # ── Steps 3-4 — recon + observation ─────────────────────────────────

    def test_step03_observation_recorded(self):
        tid, eid = self.tenant_id, uuid4()
        obs = self.hypothesis_registry.record_observation(
            tid, eid,
            observation_type="http_response",
            value={
                "endpoint": "/rest/basket/{id}",
                "own_status": 200,
                "cross_status_observed": "unknown",
            },
            provenance="recon.passive",
            confidence=0.6,
        )
        assert obs.observation_type == "http_response"
        assert obs.confidence == 0.6
        assert obs.retracted is False

    # ── Step 5 — hypothesis.created ─────────────────────────────────────

    def test_step04_hypothesis_created_open(self):
        tid, eid = self.tenant_id, uuid4()
        h = self.hypothesis_registry.create(
            tenant_id=tid,
            engagement_id=eid,
            claim="object-level authorization absent on /rest/basket/{id}",
            rationale="basket endpoint uses sequential IDs with no authz check",
            confidence=0.6,
            missing_evidence=["differential_request", "negative_control"],
        )
        assert h.state == HypothesisState.OPEN
        assert h.confidence == 0.6

    # ── Step 6 — hypothesis.transitioned TESTABLE ───────────────────────

    def test_step05_hypothesis_testable_after_observation_link(self):
        tid, eid = self.tenant_id, uuid4()
        h = self.hypothesis_registry.create(
            tenant_id=tid,
            engagement_id=eid,
            claim="IDOR on basket",
            rationale="sequential IDs",
            confidence=0.6,
        )
        obs = self.hypothesis_registry.record_observation(
            tid, eid, "http_response", {"endpoint": "/rest/basket/{id}"}, "recon"
        )
        self.hypothesis_registry.link_observation(tid, h.hypothesis_id, obs.observation_id)
        updated = self.hypothesis_registry.transition(
            tid, h.hypothesis_id, HypothesisState.TESTABLE,
            reason="prerequisites met: two identities, recon completed"
        )
        assert updated.state == HypothesisState.TESTABLE
        # Verify transition history recorded
        transitions = self.hypothesis_registry.transitions_for(h.hypothesis_id)
        assert any(t.from_state == HypothesisState.OPEN for t in transitions)

    # ── Steps 7-8 — policy decision + action proposed ────────────────────

    def test_step06_r2_action_requires_approval(self):
        tid, eid = self.tenant_id, uuid4()
        self.eng_repo.create(tid, {"id": eid, "tenant_id": tid, "name": "t", "state": "running"})

        result = handle_propose_action(
            ProposeActionCommand(
                tenant_id=tid,
                engagement_id=eid,
                technique_id="web.authz.bola.differential",
                target_locator="http://juice-shop:3000/rest/basket/2",
                risk_tier="R2",
                mutation_class="none",
                actor="planner",
            ),
            self.eng_repo,
            self.action_repo,
            self.bus,
            budget_ledger=self.budget_ledger,
            approval_registry=self.approval_registry,
        )
        assert result.status == CommandStatus.SUCCESS
        action = self.action_repo.get(tid, result.resource_id)
        assert action["state"] == "approval_required"
        assert action["risk_tier"] == "R2"

        emitted = [e.event_type for e in self.bus.events]
        assert "action.proposed" in emitted

    # ── Steps 9-12 — pause + approval gate ──────────────────────────────

    def test_step07_pause_approve_resume(self):
        tid, eid = self.tenant_id, uuid4()
        self.eng_repo.create(tid, {"id": eid, "tenant_id": tid, "name": "t", "state": "running"})

        # Propose R2 action
        propose_result = handle_propose_action(
            ProposeActionCommand(
                tenant_id=tid,
                engagement_id=eid,
                technique_id="web.authz.bola.differential",
                target_locator="http://juice-shop:3000/rest/basket/2",
                risk_tier="R2",
                mutation_class="none",
                actor="planner",
            ),
            self.eng_repo,
            self.action_repo,
            self.bus,
            budget_ledger=self.budget_ledger,
            approval_registry=self.approval_registry,
        )
        action_id = propose_result.resource_id

        # Pause
        pause_result = handle_pause_engagement(
            PauseEngagementCommand(
                tenant_id=tid,
                engagement_id=eid,
                actor=self.actor,
                reason="awaiting approval for R2 IDOR action",
            ),
            self.eng_repo,
            self.bus,
        )
        assert pause_result.status == CommandStatus.SUCCESS
        assert self.eng_repo.get(tid, eid)["state"] == "paused"

        emitted = [e.event_type for e in self.bus.events]
        assert "engagement.paused" in emitted

        # Approve
        self.action_repo.update_state(tid, action_id, "approval_required")
        approve_result = handle_approve_action(
            ApproveActionCommand(
                tenant_id=tid,
                action_id=action_id,
                approver="security-lead",
                decision_digest="sha256:approval-binding-idor",
            ),
            self.action_repo,
            self.bus,
            self.audit,
            approval_registry=self.approval_registry,
        )
        assert approve_result.status == CommandStatus.SUCCESS

        # Resume
        resume_result = handle_resume_engagement(
            ResumeEngagementCommand(
                tenant_id=tid, engagement_id=eid, actor=self.actor
            ),
            self.eng_repo,
            self.bus,
        )
        assert resume_result.status == CommandStatus.SUCCESS
        assert self.eng_repo.get(tid, eid)["state"] == "running"

        emitted = [e.event_type for e in self.bus.events]
        assert "engagement.resumed" in emitted

    # ── Step 13 — differential execution + evidence ──────────────────────

    def test_step08_differential_exchanges_and_evidence(self):
        tid, eid = self.tenant_id, uuid4()
        self.eng_repo.create(tid, {"id": eid, "tenant_id": tid, "name": "t", "state": "running"})

        # Simulate the 4 differential exchanges
        exchanges = [
            {"label": "baseline_own",      "status": 200, "token": "alice", "path": "/rest/basket/1"},
            {"label": "differential_cross", "status": 200, "token": "alice", "path": "/rest/basket/2"},
            {"label": "positive_control",   "status": 200, "token": "bob",   "path": "/rest/basket/2"},
            {"label": "negative_control",   "status": 401, "token": None,    "path": "/rest/basket/2"},
        ]
        evidence_bytes = _evidence_bytes(exchanges)

        result = handle_record_evidence(
            RecordEvidenceCommand(
                tenant_id=tid,
                action_id=uuid4(),
                data=evidence_bytes,
                media_type="application/json",
                actor="runner-agent",
            ),
            self.evidence_store,
            self.bus,
        )
        assert result.status == CommandStatus.SUCCESS

        digest = result.data.get("digest")
        assert digest is not None
        assert digest.startswith("sha256:")

        emitted = [e.event_type for e in self.bus.events]
        assert "evidence.captured" in emitted

    # ── Step 14 — BOLA confirmation (deterministic) ──────────────────────

    def test_step09_bola_confirmed_deterministically(self):
        baseline = ExchangeResult(
            label="baseline_own", status_code=200,
            body_contains_object=True, object_id="basket-1",
        )
        differential = ExchangeResult(
            label="differential_cross", status_code=200,
            body_contains_object=True, object_id="basket-2",
        )
        positive_control = ExchangeResult(
            label="positive_control", status_code=200,
            body_contains_object=True, object_id="basket-2",
        )
        negative_control = ExchangeResult(
            label="negative_control", status_code=401,
            body_contains_object=False,
        )

        result: BOLAConfirmation = confirm_bola(
            baseline, differential, positive_control, negative_control
        )
        assert result.confirmed is True
        assert result.rule_version == "1.0.0"
        assert len(result.exchanges) == 4

    # ── Step 15 — finding confirmed → capability emitted ─────────────────

    def test_step10_capability_only_after_confirmed_finding(self):
        tid, eid = self.tenant_id, uuid4()
        finding_id = uuid4()

        # Must fail with unconfirmed finding
        with pytest.raises(FindingNotConfirmedError):
            self.capability_registry.emit(
                tenant_id=tid,
                engagement_id=eid,
                name="read_foreign_object",
                description="Alice can read Bob's basket via IDOR",
                finding_id=finding_id,
                evidence_digests=frozenset(["sha256:abc123"]),
                technique_id="web.authz.bola.differential",
                target_locator="http://juice-shop:3000/rest/basket/2",
                finding_state="open",
            )

        # Succeeds when finding is confirmed
        cap = self.capability_registry.emit(
            tenant_id=tid,
            engagement_id=eid,
            name="read_foreign_object",
            description="Alice can read Bob's basket via IDOR",
            finding_id=finding_id,
            evidence_digests=frozenset(["sha256:evidence-digest-idor"]),
            technique_id="web.authz.bola.differential",
            target_locator="http://juice-shop:3000/rest/basket/2",
            finding_state="confirmed",
        )
        assert cap.name == "read_foreign_object"
        assert cap.state.value == "proven"
        assert "sha256:evidence-digest-idor" in cap.evidence_digests
        assert self.capability_registry.has_capability(tid, eid, "read_foreign_object")

    # ── Step 16 — full chain: from engagement to capability ──────────────

    def test_step11_full_chain_engagement_to_capability(self):
        """Walk the complete slice as one coherent chain."""
        tid = self.tenant_id
        finding_id = uuid4()
        eid = uuid4()

        # 1. Create + start engagement
        self.eng_repo.create(tid, {
            "id": eid, "tenant_id": tid,
            "name": "full-slice", "state": "running",
        })

        # 2. Record observation
        obs = self.hypothesis_registry.record_observation(
            tid, eid,
            "http_response_differential",
            {"endpoint": "/rest/basket/{id}", "cross_status": "unknown"},
            "recon.passive",
            confidence=0.6,
        )

        # 3. Create hypothesis
        h = self.hypothesis_registry.create(
            tenant_id=tid,
            engagement_id=eid,
            claim="IDOR on basket",
            rationale="sequential IDs, no authz",
            confidence=0.6,
            missing_evidence=["differential_request"],
        )
        self.hypothesis_registry.link_observation(tid, h.hypothesis_id, obs.observation_id)

        # 4. Transition to TESTABLE
        h = self.hypothesis_registry.transition(
            tid, h.hypothesis_id, HypothesisState.TESTABLE, reason="identities ready"
        )
        assert h.state == HypothesisState.TESTABLE

        # 5. Propose R2 action
        propose = handle_propose_action(
            ProposeActionCommand(
                tenant_id=tid,
                engagement_id=eid,
                technique_id="web.authz.bola.differential",
                target_locator="http://juice-shop:3000/rest/basket/2",
                risk_tier="R2",
                mutation_class="none",
                actor="planner",
            ),
            self.eng_repo,
            self.action_repo,
            self.bus,
            budget_ledger=self.budget_ledger,
            approval_registry=self.approval_registry,
        )
        action_id = propose.resource_id
        assert self.action_repo.get(tid, action_id)["state"] == "approval_required"

        # 6. Pause + approve + resume
        handle_pause_engagement(
            PauseEngagementCommand(tenant_id=tid, engagement_id=eid, actor=self.actor),
            self.eng_repo, self.bus,
        )
        assert self.eng_repo.get(tid, eid)["state"] == "paused"

        handle_approve_action(
            ApproveActionCommand(
                tenant_id=tid,
                action_id=action_id,
                approver="security-lead",
                decision_digest="sha256:binding-idor",
            ),
            self.action_repo, self.bus, self.audit,
            approval_registry=self.approval_registry,
        )

        handle_resume_engagement(
            ResumeEngagementCommand(tenant_id=tid, engagement_id=eid, actor=self.actor),
            self.eng_repo, self.bus,
        )
        assert self.eng_repo.get(tid, eid)["state"] == "running"

        # 7. Transition hypothesis to TESTING
        h = self.hypothesis_registry.transition(
            tid, h.hypothesis_id, HypothesisState.TESTING, reason="action approved and running"
        )

        # 8. Record evidence (4 exchanges)
        exchanges = [
            {"label": "baseline_own", "status": 200, "token": "alice", "path": "/rest/basket/1"},
            {"label": "differential_cross", "status": 200, "token": "alice", "path": "/rest/basket/2"},
            {"label": "positive_control", "status": 200, "token": "bob", "path": "/rest/basket/2"},
            {"label": "negative_control", "status": 401, "token": None, "path": "/rest/basket/2"},
        ]
        evidence_bytes = _evidence_bytes(exchanges)
        evidence_result = handle_record_evidence(
            RecordEvidenceCommand(
                tenant_id=tid,
                action_id=action_id,
                data=evidence_bytes,
                media_type="application/json",
                actor="runner-agent",
            ),
            self.evidence_store, self.bus,
        )
        evidence_digest = evidence_result.data["digest"]
        assert evidence_digest.startswith("sha256:")

        # 9. BOLA confirmation
        bola_result = confirm_bola(
            ExchangeResult("baseline_own", 200, True, "basket-1"),
            ExchangeResult("differential_cross", 200, True, "basket-2"),
            ExchangeResult("positive_control", 200, True, "basket-2"),
            ExchangeResult("negative_control", 401, False),
        )
        assert bola_result.confirmed is True

        # 10. Transition hypothesis to SUPPORTED
        h = self.hypothesis_registry.transition(
            tid, h.hypothesis_id, HypothesisState.SUPPORTED, reason="BOLA confirmed"
        )
        assert h.state == HypothesisState.SUPPORTED

        # 11. Emit capability (only after finding confirmed)
        cap = self.capability_registry.emit(
            tenant_id=tid,
            engagement_id=eid,
            name="read_foreign_object",
            description="Alice can read Bob's basket via IDOR (CWE-639)",
            finding_id=finding_id,
            evidence_digests=frozenset([evidence_digest]),
            technique_id="web.authz.bola.differential",
            target_locator="http://juice-shop:3000/rest/basket/2",
            finding_state="confirmed",
        )
        assert cap.state.value == "proven"
        assert cap.name == "read_foreign_object"
        assert evidence_digest in cap.evidence_digests

        # 12. Verify event trail covers §37 mandatory events
        emitted = {e.event_type for e in self.bus.events}
        assert "engagement.paused" in emitted
        assert "engagement.resumed" in emitted
        assert "action.proposed" in emitted
        assert "action.approved" in emitted
        assert "evidence.captured" in emitted

    # ── Step 17 — build_capability output structure ───────────────────────

    def test_step12_capability_output_structure(self):
        cap_dict = build_capability(
            actor_id="alice",
            access_context_id="ctx-001",
            target_object="basket-2",
            evidence_refs=["sha256:evidence-digest-idor"],
        )
        assert cap_dict["type"] == "read_foreign_object"
        assert cap_dict["operation"] == "read"
        assert cap_dict["object"] == "basket-2"
        assert cap_dict["technique_id"] == "web.authz.bola.differential"
        assert cap_dict["evidence_refs"] == ["sha256:evidence-digest-idor"]

    # ── Step 18 — emergency stop aborts the slice ────────────────────────

    def test_step13_emergency_stop_aborts(self):
        tid, eid = self.tenant_id, uuid4()
        self.eng_repo.create(tid, {"id": eid, "tenant_id": tid, "name": "t", "state": "running"})

        result = handle_emergency_stop(
            EmergencyStopCommand(
                tenant_id=tid,
                engagement_id=eid,
                actor=self.actor,
                reason="unexpected scope violation detected",
            ),
            self.eng_repo,
            self.bus,
            self.audit,
        )
        assert result.status == CommandStatus.SUCCESS
        assert self.eng_repo.get(tid, eid)["state"] == "stopping"

        # Budget is stopped for this engagement
        self.budget_ledger.emergency_stop(tid, eid)
        budget_result = self.budget_ledger.check(tid, eid, requests_needed=1)
        allowed = budget_result.allowed
        assert allowed is False

        emitted = [e.event_type for e in self.bus.events]
        assert "engagement.emergency_stop" in emitted

    # ── Truth maintenance — retraction cascades ──────────────────────────

    def test_step14_truth_maintenance_cascades_stale(self):
        tid, eid = self.tenant_id, uuid4()

        # Hypothesis supported by one observation
        h = self.hypothesis_registry.create(
            tenant_id=tid, engagement_id=eid,
            claim="IDOR on basket", rationale="sequential IDs",
        )
        obs = self.hypothesis_registry.record_observation(
            tid, eid, "http_response", {"endpoint": "/rest/basket/{id}"}, "recon"
        )
        self.hypothesis_registry.link_observation(tid, h.hypothesis_id, obs.observation_id)
        h = self.hypothesis_registry.transition(
            tid, h.hypothesis_id, HypothesisState.TESTABLE, reason="obs linked"
        )

        # Retract the observation — hypothesis should cascade to STALE
        self.hypothesis_registry.retract_observation(tid, obs.observation_id, reason="scan error")
        h_after = self.hypothesis_registry.get(tid, h.hypothesis_id)
        assert h_after.state == HypothesisState.STALE

    # ── Capability immutability ───────────────────────────────────────────

    def test_step15_capability_immutable_no_delete(self):
        tid, eid = self.tenant_id, uuid4()
        finding_id = uuid4()

        cap = self.capability_registry.emit(
            tenant_id=tid,
            engagement_id=eid,
            name="read_foreign_object",
            description="BOLA capability",
            finding_id=finding_id,
            evidence_digests=frozenset(["sha256:immut-test"]),
            technique_id="web.authz.bola.differential",
            target_locator="http://juice-shop:3000/rest/basket/2",
            finding_state="confirmed",
        )

        # Verify capability is retrievable and marked proven
        retrieved = self.capability_registry.get(tid, cap.capability_id)
        assert retrieved is not None
        assert retrieved.state.value == "proven"

        # CapabilityRegistry has no delete or update method — only transition
        assert not hasattr(self.capability_registry, "delete")
        assert not hasattr(self.capability_registry, "update")

        # List shows it
        caps = self.capability_registry.list_for_engagement(tid, eid)
        assert any(c.capability_id == cap.capability_id for c in caps)
