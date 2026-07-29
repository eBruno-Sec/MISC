from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from packages.application import (
    ApproveActionCommand,
    CommandResult,
    CommandStatus,
    CreateEngagementCommand,
    DomainEvent,
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


def _now():
    return datetime.now(timezone.utc)


def _make_repo_with_engagement(state="draft"):
    repo = InMemoryEngagementRepo()
    tid = uuid4()
    eid = uuid4()
    engagement = {
        "id": eid,
        "tenant_id": tid,
        "name": "test",
        "state": state,
        "created_at": _now(),
    }
    repo.create(tid, engagement)
    return repo, tid, eid


# --- CreateEngagement ---


def test_create_engagement_success():
    repo = InMemoryEngagementRepo()
    bus = InMemoryEventBus()
    audit = InMemoryAuditLog()
    cmd = CreateEngagementCommand(
        tenant_id=uuid4(),
        name="acme-q3",
        actor="operator@test",
        authorization_artifact_digest="sha256:abc",
        valid_from=_now(),
        valid_until=_now() + timedelta(days=7),
    )
    result = handle_create_engagement(cmd, repo, bus, audit)
    assert result.status == CommandStatus.SUCCESS
    assert result.resource_id is not None
    assert len(bus.events) == 1
    assert bus.events[0].event_type == "engagement.created"
    assert len(audit.entries) == 1


def test_create_engagement_empty_name_rejected():
    repo = InMemoryEngagementRepo()
    cmd = CreateEngagementCommand(
        tenant_id=uuid4(),
        name="",
        actor="op",
        authorization_artifact_digest="sha256:abc",
        valid_from=_now(),
        valid_until=_now() + timedelta(days=1),
    )
    result = handle_create_engagement(cmd, repo)
    assert result.status == CommandStatus.REJECTED


def test_create_engagement_invalid_dates_rejected():
    repo = InMemoryEngagementRepo()
    now = _now()
    cmd = CreateEngagementCommand(
        tenant_id=uuid4(),
        name="test",
        actor="op",
        authorization_artifact_digest="sha256:abc",
        valid_from=now + timedelta(days=7),
        valid_until=now,
    )
    result = handle_create_engagement(cmd, repo)
    assert result.status == CommandStatus.REJECTED


# --- StartEngagement ---


def test_start_engagement_from_ready():
    repo, tid, eid = _make_repo_with_engagement("ready")
    bus = InMemoryEventBus()
    cmd = StartEngagementCommand(tenant_id=tid, engagement_id=eid, actor="op")
    result = handle_start_engagement(cmd, repo, bus)
    assert result.status == CommandStatus.SUCCESS
    assert repo.get(tid, eid)["state"] == "running"
    assert bus.events[0].event_type == "engagement.started"


def test_start_engagement_from_draft_fails():
    repo, tid, eid = _make_repo_with_engagement("draft")
    result = handle_start_engagement(
        StartEngagementCommand(tenant_id=tid, engagement_id=eid, actor="op"), repo
    )
    assert result.status == CommandStatus.CONFLICT


def test_start_engagement_not_found():
    repo = InMemoryEngagementRepo()
    result = handle_start_engagement(
        StartEngagementCommand(tenant_id=uuid4(), engagement_id=uuid4(), actor="op"),
        repo,
    )
    assert result.status == CommandStatus.NOT_FOUND


# --- PauseEngagement ---


def test_pause_engagement():
    repo, tid, eid = _make_repo_with_engagement("running")
    bus = InMemoryEventBus()
    result = handle_pause_engagement(
        PauseEngagementCommand(tenant_id=tid, engagement_id=eid, actor="op", reason="lunch"),
        repo,
        bus,
    )
    assert result.status == CommandStatus.SUCCESS
    assert repo.get(tid, eid)["state"] == "paused"
    assert bus.events[0].event_type == "engagement.paused"


def test_pause_from_non_running_fails():
    repo, tid, eid = _make_repo_with_engagement("draft")
    result = handle_pause_engagement(
        PauseEngagementCommand(tenant_id=tid, engagement_id=eid, actor="op"), repo
    )
    assert result.status == CommandStatus.CONFLICT


# --- ResumeEngagement ---


def test_resume_engagement():
    repo, tid, eid = _make_repo_with_engagement("paused")
    bus = InMemoryEventBus()
    result = handle_resume_engagement(
        ResumeEngagementCommand(tenant_id=tid, engagement_id=eid, actor="op"),
        repo,
        bus,
    )
    assert result.status == CommandStatus.SUCCESS
    assert repo.get(tid, eid)["state"] == "running"


def test_resume_from_non_paused_fails():
    repo, tid, eid = _make_repo_with_engagement("running")
    result = handle_resume_engagement(
        ResumeEngagementCommand(tenant_id=tid, engagement_id=eid, actor="op"), repo
    )
    assert result.status == CommandStatus.CONFLICT


# --- EmergencyStop ---


def test_emergency_stop():
    repo, tid, eid = _make_repo_with_engagement("running")
    bus = InMemoryEventBus()
    audit = InMemoryAuditLog()
    result = handle_emergency_stop(
        EmergencyStopCommand(
            tenant_id=tid, engagement_id=eid, actor="op", reason="threat detected"
        ),
        repo,
        bus,
        audit,
    )
    assert result.status == CommandStatus.SUCCESS
    assert repo.get(tid, eid)["state"] == "stopping"
    assert bus.events[0].event_type == "engagement.emergency_stop"
    assert audit.entries[0].action == "emergency_stop"


def test_emergency_stop_terminal_fails():
    repo, tid, eid = _make_repo_with_engagement("completed")
    result = handle_emergency_stop(
        EmergencyStopCommand(
            tenant_id=tid, engagement_id=eid, actor="op", reason="late"
        ),
        repo,
    )
    assert result.status == CommandStatus.CONFLICT


# --- ProposeAction ---


def test_propose_action():
    repo, tid, eid = _make_repo_with_engagement("running")
    action_repo = InMemoryActionRepo()
    bus = InMemoryEventBus()
    cmd = ProposeActionCommand(
        tenant_id=tid,
        engagement_id=eid,
        technique_id="web.authz.bola.differential",
        target_locator="https://api.test/basket/1",
        risk_tier="R2",
        mutation_class="none",
        actor="planner",
    )
    result = handle_propose_action(cmd, repo, action_repo, bus)
    assert result.status == CommandStatus.SUCCESS
    assert len(bus.events) == 1
    assert bus.events[0].event_type == "action.proposed"


def test_propose_action_r5_denied():
    repo, tid, eid = _make_repo_with_engagement("running")
    action_repo = InMemoryActionRepo()
    cmd = ProposeActionCommand(
        tenant_id=tid,
        engagement_id=eid,
        technique_id="destructive.rm_rf",
        target_locator="https://api.test",
        risk_tier="R5",
        mutation_class="destructive",
        actor="planner",
    )
    result = handle_propose_action(cmd, repo, action_repo)
    assert result.status == CommandStatus.POLICY_DENIED


def test_propose_action_non_running_engagement():
    repo, tid, eid = _make_repo_with_engagement("paused")
    action_repo = InMemoryActionRepo()
    cmd = ProposeActionCommand(
        tenant_id=tid,
        engagement_id=eid,
        technique_id="web.recon",
        target_locator="https://api.test",
        risk_tier="R1",
        mutation_class="none",
        actor="planner",
    )
    result = handle_propose_action(cmd, repo, action_repo)
    assert result.status == CommandStatus.CONFLICT


# --- ApproveAction ---


def test_approve_action():
    action_repo = InMemoryActionRepo()
    tid = uuid4()
    aid = uuid4()
    action_repo.create(
        tid,
        {"id": aid, "state": "approval_required", "tenant_id": tid},
    )
    bus = InMemoryEventBus()
    audit = InMemoryAuditLog()
    result = handle_approve_action(
        ApproveActionCommand(
            tenant_id=tid,
            action_id=aid,
            approver="approver@test",
            decision_digest="sha256:decision",
        ),
        action_repo,
        bus,
        audit,
    )
    assert result.status == CommandStatus.SUCCESS
    assert action_repo.get(tid, aid)["state"] == "approved"


def test_approve_already_approved_fails():
    action_repo = InMemoryActionRepo()
    tid = uuid4()
    aid = uuid4()
    action_repo.create(tid, {"id": aid, "state": "approved", "tenant_id": tid})
    result = handle_approve_action(
        ApproveActionCommand(
            tenant_id=tid,
            action_id=aid,
            approver="a",
            decision_digest="sha256:x",
        ),
        action_repo,
    )
    assert result.status == CommandStatus.CONFLICT


# --- RecordEvidence ---


def test_record_evidence():
    store = InMemoryEvidenceStore()
    bus = InMemoryEventBus()
    tid = uuid4()
    result = handle_record_evidence(
        RecordEvidenceCommand(
            tenant_id=tid,
            action_id=uuid4(),
            data=b'{"status": 200}',
            media_type="application/json",
            actor="runner-1",
        ),
        store,
        bus,
    )
    assert result.status == CommandStatus.SUCCESS
    assert "digest" in result.data
    assert result.data["digest"].startswith("sha256:")
    assert len(bus.events) == 1


def test_record_evidence_empty_data_rejected():
    store = InMemoryEvidenceStore()
    result = handle_record_evidence(
        RecordEvidenceCommand(
            tenant_id=uuid4(),
            action_id=uuid4(),
            data=b"",
            media_type="application/json",
            actor="runner-1",
        ),
        store,
    )
    assert result.status == CommandStatus.REJECTED


# --- In-memory repos ---


def test_engagement_repo_tenant_isolation():
    repo = InMemoryEngagementRepo()
    tid1 = uuid4()
    tid2 = uuid4()
    eid = uuid4()
    repo.create(tid1, {"id": eid, "state": "draft"})
    assert repo.get(tid1, eid) is not None
    assert repo.get(tid2, eid) is None


def test_evidence_store_tenant_isolation():
    store = InMemoryEvidenceStore()
    tid1 = uuid4()
    tid2 = uuid4()
    digest = store.store(tid1, b"secret data", "text/plain", {})
    assert store.get_artifact(tid1, digest) == b"secret data"
    assert store.get_artifact(tid2, digest) is None


def test_action_repo_list_by_engagement():
    repo = InMemoryActionRepo()
    tid = uuid4()
    eid = uuid4()
    repo.create(tid, {"id": uuid4(), "engagement_id": eid, "state": "proposed"})
    repo.create(tid, {"id": uuid4(), "engagement_id": eid, "state": "approved"})
    repo.create(tid, {"id": uuid4(), "engagement_id": uuid4(), "state": "proposed"})
    actions = repo.list_by_engagement(tid, eid)
    assert len(actions) == 2
