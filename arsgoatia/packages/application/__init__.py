"""ArsGoatia application layer — commands, queries, and ports.

The single authoritative domain-write path. All mutations flow through
commands; reads flow through queries. Infrastructure implements ports.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol, runtime_checkable
from uuid import UUID, uuid4

from packages.approval import (
    ApprovalRegistry,
    ApprovalRegistryError,
    DuplicateApprovalError,
    TwoPersonRuleError,
)
from packages.rate_limiter import BudgetDenialReason, BudgetLedger


# ---------------------------------------------------------------------------
# Ports — interfaces that infrastructure must implement
# ---------------------------------------------------------------------------


@runtime_checkable
class EngagementRepository(Protocol):
    """Persistence port for engagements."""

    def get(self, tenant_id: UUID, engagement_id: UUID) -> dict[str, Any] | None: ...

    def create(self, tenant_id: UUID, engagement: dict[str, Any]) -> UUID: ...

    def update_state(
        self, tenant_id: UUID, engagement_id: UUID, state: str
    ) -> None: ...

    def create_revision(
        self, tenant_id: UUID, engagement_id: UUID, revision: dict[str, Any]
    ) -> UUID: ...

    def get_current_revision(
        self, tenant_id: UUID, engagement_id: UUID
    ) -> dict[str, Any] | None: ...


@runtime_checkable
class ActionRepository(Protocol):
    """Persistence port for action proposals and execution."""

    def create(self, tenant_id: UUID, action: dict[str, Any]) -> UUID: ...

    def get(self, tenant_id: UUID, action_id: UUID) -> dict[str, Any] | None: ...

    def update_state(
        self, tenant_id: UUID, action_id: UUID, state: str
    ) -> None: ...

    def list_by_engagement(
        self, tenant_id: UUID, engagement_id: UUID
    ) -> list[dict[str, Any]]: ...


@runtime_checkable
class EvidenceStore(Protocol):
    """Persistence port for immutable evidence artifacts."""

    def store(
        self, tenant_id: UUID, data: bytes, media_type: str, metadata: dict[str, Any]
    ) -> str: ...

    def get_metadata(self, tenant_id: UUID, digest: str) -> dict[str, Any] | None: ...

    def get_artifact(self, tenant_id: UUID, digest: str) -> bytes | None: ...


@runtime_checkable
class EventBus(Protocol):
    """Port for publishing domain events to the outbox."""

    def publish(self, event: DomainEvent) -> None: ...


@runtime_checkable
class AuditLog(Protocol):
    """Port for immutable audit entries."""

    def record(self, entry: AuditEntry) -> None: ...


# ---------------------------------------------------------------------------
# Domain events
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DomainEvent:
    event_id: UUID
    event_type: str
    tenant_id: UUID
    aggregate_type: str
    aggregate_id: UUID
    occurred_at: datetime
    actor: str
    payload: dict[str, Any] = field(default_factory=dict)
    causation_id: UUID | None = None
    correlation_id: UUID | None = None


@dataclass(frozen=True)
class AuditEntry:
    entry_id: UUID
    tenant_id: UUID
    actor: str
    action: str
    resource_type: str
    resource_id: UUID
    occurred_at: datetime
    details: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Command results
# ---------------------------------------------------------------------------


class CommandStatus(enum.Enum):
    SUCCESS = "success"
    REJECTED = "rejected"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    POLICY_DENIED = "policy_denied"


@dataclass(frozen=True)
class CommandResult:
    status: CommandStatus
    resource_id: UUID | None = None
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CreateEngagementCommand:
    tenant_id: UUID
    name: str
    actor: str
    authorization_artifact_digest: str
    valid_from: datetime
    valid_until: datetime
    scope_rules: list[dict[str, Any]] = field(default_factory=list)
    allowed_risk_tiers: list[str] = field(default_factory=list)
    budget: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CompileScopeCommand:
    tenant_id: UUID
    engagement_id: UUID
    actor: str


@dataclass(frozen=True)
class StartEngagementCommand:
    tenant_id: UUID
    engagement_id: UUID
    actor: str


@dataclass(frozen=True)
class PauseEngagementCommand:
    tenant_id: UUID
    engagement_id: UUID
    actor: str
    reason: str = ""


@dataclass(frozen=True)
class ResumeEngagementCommand:
    tenant_id: UUID
    engagement_id: UUID
    actor: str


@dataclass(frozen=True)
class EmergencyStopCommand:
    tenant_id: UUID
    engagement_id: UUID
    actor: str
    reason: str


@dataclass(frozen=True)
class ProposeActionCommand:
    tenant_id: UUID
    engagement_id: UUID
    technique_id: str
    target_locator: str
    risk_tier: str
    mutation_class: str
    actor: str
    parameters: dict[str, Any] = field(default_factory=dict)
    access_context_ids: list[UUID] = field(default_factory=list)


@dataclass(frozen=True)
class ApproveActionCommand:
    tenant_id: UUID
    action_id: UUID
    approver: str
    decision_digest: str = ""
    reason: str = ""


@dataclass(frozen=True)
class RejectActionCommand:
    tenant_id: UUID
    action_id: UUID
    approver: str
    reason: str


@dataclass(frozen=True)
class RecordEvidenceCommand:
    tenant_id: UUID
    action_id: UUID
    data: bytes
    media_type: str
    actor: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ConfirmFindingCommand:
    tenant_id: UUID
    finding_id: UUID
    actor: str
    evidence_digests: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GetEngagementQuery:
    tenant_id: UUID
    engagement_id: UUID


@dataclass(frozen=True)
class ListActionsQuery:
    tenant_id: UUID
    engagement_id: UUID
    state_filter: str | None = None


@dataclass(frozen=True)
class GetEvidenceQuery:
    tenant_id: UUID
    digest: str


@dataclass(frozen=True)
class GetAuditTrailQuery:
    tenant_id: UUID
    resource_type: str
    resource_id: UUID
    limit: int = 100


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _emit(bus: EventBus | None, event: DomainEvent) -> None:
    if bus is not None:
        bus.publish(event)


def _audit(log: AuditLog | None, entry: AuditEntry) -> None:
    if log is not None:
        log.record(entry)


def handle_create_engagement(
    cmd: CreateEngagementCommand,
    repo: EngagementRepository,
    bus: EventBus | None = None,
    audit: AuditLog | None = None,
) -> CommandResult:
    if not cmd.name:
        return CommandResult(status=CommandStatus.REJECTED, message="name is required")

    if cmd.valid_until <= cmd.valid_from:
        return CommandResult(
            status=CommandStatus.REJECTED,
            message="valid_until must be after valid_from",
        )

    engagement_id = uuid4()
    now = _now()
    engagement = {
        "id": engagement_id,
        "tenant_id": cmd.tenant_id,
        "name": cmd.name,
        "state": "draft",
        "authorization_artifact_digest": cmd.authorization_artifact_digest,
        "valid_from": cmd.valid_from,
        "valid_until": cmd.valid_until,
        "scope_rules": cmd.scope_rules,
        "allowed_risk_tiers": cmd.allowed_risk_tiers,
        "budget": cmd.budget,
        "created_at": now,
        "created_by": cmd.actor,
    }

    repo.create(cmd.tenant_id, engagement)

    _emit(
        bus,
        DomainEvent(
            event_id=uuid4(),
            event_type="engagement.created",
            tenant_id=cmd.tenant_id,
            aggregate_type="engagement",
            aggregate_id=engagement_id,
            occurred_at=now,
            actor=cmd.actor,
        ),
    )

    _audit(
        audit,
        AuditEntry(
            entry_id=uuid4(),
            tenant_id=cmd.tenant_id,
            actor=cmd.actor,
            action="create_engagement",
            resource_type="engagement",
            resource_id=engagement_id,
            occurred_at=now,
        ),
    )

    return CommandResult(
        status=CommandStatus.SUCCESS,
        resource_id=engagement_id,
    )


def handle_start_engagement(
    cmd: StartEngagementCommand,
    repo: EngagementRepository,
    bus: EventBus | None = None,
    audit: AuditLog | None = None,
) -> CommandResult:
    engagement = repo.get(cmd.tenant_id, cmd.engagement_id)
    if engagement is None:
        return CommandResult(
            status=CommandStatus.NOT_FOUND,
            message="engagement not found",
        )

    if engagement["state"] != "ready":
        return CommandResult(
            status=CommandStatus.CONFLICT,
            message=f"cannot start from state {engagement['state']}",
        )

    now = _now()
    repo.update_state(cmd.tenant_id, cmd.engagement_id, "running")

    _emit(
        bus,
        DomainEvent(
            event_id=uuid4(),
            event_type="engagement.started",
            tenant_id=cmd.tenant_id,
            aggregate_type="engagement",
            aggregate_id=cmd.engagement_id,
            occurred_at=now,
            actor=cmd.actor,
        ),
    )

    _audit(
        audit,
        AuditEntry(
            entry_id=uuid4(),
            tenant_id=cmd.tenant_id,
            actor=cmd.actor,
            action="start_engagement",
            resource_type="engagement",
            resource_id=cmd.engagement_id,
            occurred_at=now,
        ),
    )

    return CommandResult(status=CommandStatus.SUCCESS, resource_id=cmd.engagement_id)


def handle_pause_engagement(
    cmd: PauseEngagementCommand,
    repo: EngagementRepository,
    bus: EventBus | None = None,
) -> CommandResult:
    engagement = repo.get(cmd.tenant_id, cmd.engagement_id)
    if engagement is None:
        return CommandResult(
            status=CommandStatus.NOT_FOUND, message="engagement not found"
        )

    if engagement["state"] != "running":
        return CommandResult(
            status=CommandStatus.CONFLICT,
            message=f"cannot pause from state {engagement['state']}",
        )

    repo.update_state(cmd.tenant_id, cmd.engagement_id, "paused")
    _emit(
        bus,
        DomainEvent(
            event_id=uuid4(),
            event_type="engagement.paused",
            tenant_id=cmd.tenant_id,
            aggregate_type="engagement",
            aggregate_id=cmd.engagement_id,
            occurred_at=_now(),
            actor=cmd.actor,
            payload={"reason": cmd.reason},
        ),
    )

    return CommandResult(status=CommandStatus.SUCCESS, resource_id=cmd.engagement_id)


def handle_resume_engagement(
    cmd: ResumeEngagementCommand,
    repo: EngagementRepository,
    bus: EventBus | None = None,
) -> CommandResult:
    engagement = repo.get(cmd.tenant_id, cmd.engagement_id)
    if engagement is None:
        return CommandResult(
            status=CommandStatus.NOT_FOUND, message="engagement not found"
        )

    if engagement["state"] != "paused":
        return CommandResult(
            status=CommandStatus.CONFLICT,
            message=f"cannot resume from state {engagement['state']}",
        )

    repo.update_state(cmd.tenant_id, cmd.engagement_id, "running")
    _emit(
        bus,
        DomainEvent(
            event_id=uuid4(),
            event_type="engagement.resumed",
            tenant_id=cmd.tenant_id,
            aggregate_type="engagement",
            aggregate_id=cmd.engagement_id,
            occurred_at=_now(),
            actor=cmd.actor,
        ),
    )

    return CommandResult(status=CommandStatus.SUCCESS, resource_id=cmd.engagement_id)


def handle_emergency_stop(
    cmd: EmergencyStopCommand,
    repo: EngagementRepository,
    bus: EventBus | None = None,
    audit: AuditLog | None = None,
) -> CommandResult:
    engagement = repo.get(cmd.tenant_id, cmd.engagement_id)
    if engagement is None:
        return CommandResult(
            status=CommandStatus.NOT_FOUND, message="engagement not found"
        )

    terminal = {"completed", "revoked"}
    if engagement["state"] in terminal:
        return CommandResult(
            status=CommandStatus.CONFLICT,
            message=f"cannot emergency stop from terminal state {engagement['state']}",
        )

    now = _now()
    repo.update_state(cmd.tenant_id, cmd.engagement_id, "stopping")

    _emit(
        bus,
        DomainEvent(
            event_id=uuid4(),
            event_type="engagement.emergency_stop",
            tenant_id=cmd.tenant_id,
            aggregate_type="engagement",
            aggregate_id=cmd.engagement_id,
            occurred_at=now,
            actor=cmd.actor,
            payload={"reason": cmd.reason},
        ),
    )

    _audit(
        audit,
        AuditEntry(
            entry_id=uuid4(),
            tenant_id=cmd.tenant_id,
            actor=cmd.actor,
            action="emergency_stop",
            resource_type="engagement",
            resource_id=cmd.engagement_id,
            occurred_at=now,
            details={"reason": cmd.reason},
        ),
    )

    return CommandResult(status=CommandStatus.SUCCESS, resource_id=cmd.engagement_id)


def handle_propose_action(
    cmd: ProposeActionCommand,
    engagement_repo: EngagementRepository,
    action_repo: ActionRepository,
    bus: EventBus | None = None,
    budget_ledger: BudgetLedger | None = None,
    approval_registry: ApprovalRegistry | None = None,
) -> CommandResult:
    engagement = engagement_repo.get(cmd.tenant_id, cmd.engagement_id)
    if engagement is None:
        return CommandResult(
            status=CommandStatus.NOT_FOUND, message="engagement not found"
        )

    active_states = {"running"}
    if engagement["state"] not in active_states:
        return CommandResult(
            status=CommandStatus.CONFLICT,
            message=f"engagement state {engagement['state']} does not allow proposals",
        )

    if cmd.risk_tier == "R5":
        return CommandResult(
            status=CommandStatus.POLICY_DENIED,
            message="R5 actions are unsupported; no exception path exists",
        )

    if budget_ledger is not None:
        budget_result = budget_ledger.check(
            cmd.tenant_id, cmd.engagement_id, requests_needed=1
        )
        if not budget_result.allowed:
            reason = (
                budget_result.denial_reason.value
                if budget_result.denial_reason
                else "budget_denied"
            )
            return CommandResult(
                status=CommandStatus.POLICY_DENIED,
                message=f"budget check denied: {reason}",
                data={"denial_reason": reason},
            )

    action_id = uuid4()
    now = _now()

    # R2+ actions require an approval request before execution
    requires_approval = cmd.risk_tier in {"R2", "R3", "R4"}
    requires_two_person = cmd.risk_tier == "R4"
    initial_state = "approval_required" if requires_approval else "proposed"

    action = {
        "id": action_id,
        "tenant_id": cmd.tenant_id,
        "engagement_id": cmd.engagement_id,
        "technique_id": cmd.technique_id,
        "target_locator": cmd.target_locator,
        "risk_tier": cmd.risk_tier,
        "mutation_class": cmd.mutation_class,
        "state": initial_state,
        "parameters": cmd.parameters,
        "access_context_ids": [str(u) for u in cmd.access_context_ids],
        "created_at": now,
        "created_by": cmd.actor,
    }

    action_repo.create(cmd.tenant_id, action)

    if approval_registry is not None and requires_approval:
        import hashlib, json
        envelope_digest = "sha256:" + hashlib.sha256(
            json.dumps(
                {
                    "action_id": str(action_id),
                    "technique_id": cmd.technique_id,
                    "target_locator": cmd.target_locator,
                    "risk_tier": cmd.risk_tier,
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()
        try:
            approval_registry.create_request(
                tenant_id=cmd.tenant_id,
                engagement_id=cmd.engagement_id,
                action_id=action_id,
                envelope_digest=envelope_digest,
                risk_tier=cmd.risk_tier,
                requestor_id=cmd.actor,
                requires_two_person=requires_two_person,
                expires_in=timedelta(hours=4),
            )
        except DuplicateApprovalError:
            pass  # idempotent — approval request already exists

    _emit(
        bus,
        DomainEvent(
            event_id=uuid4(),
            event_type="action.proposed",
            tenant_id=cmd.tenant_id,
            aggregate_type="action",
            aggregate_id=action_id,
            occurred_at=now,
            actor=cmd.actor,
            payload={
                "technique_id": cmd.technique_id,
                "target": cmd.target_locator,
                "risk_tier": cmd.risk_tier,
                "requires_approval": requires_approval,
            },
        ),
    )

    return CommandResult(
        status=CommandStatus.SUCCESS,
        resource_id=action_id,
        data={"requires_approval": requires_approval},
    )


def handle_approve_action(
    cmd: ApproveActionCommand,
    action_repo: ActionRepository,
    bus: EventBus | None = None,
    audit: AuditLog | None = None,
    approval_registry: ApprovalRegistry | None = None,
) -> CommandResult:
    action = action_repo.get(cmd.tenant_id, cmd.action_id)
    if action is None:
        return CommandResult(
            status=CommandStatus.NOT_FOUND, message="action not found"
        )

    approvable = {"proposed", "approval_required"}
    if action["state"] not in approvable:
        return CommandResult(
            status=CommandStatus.CONFLICT,
            message=f"cannot approve action in state {action['state']}",
        )

    now = _now()
    binding_digest = cmd.decision_digest

    if approval_registry is not None:
        try:
            decision = approval_registry.grant(
                cmd.tenant_id, cmd.action_id, cmd.approver, reason=cmd.reason
            )
            binding_digest = decision.binding_digest
        except TwoPersonRuleError as exc:
            return CommandResult(
                status=CommandStatus.POLICY_DENIED,
                message=str(exc),
            )
        except ApprovalRegistryError as exc:
            return CommandResult(
                status=CommandStatus.REJECTED,
                message=str(exc),
            )

    action_repo.update_state(cmd.tenant_id, cmd.action_id, "approved")

    _emit(
        bus,
        DomainEvent(
            event_id=uuid4(),
            event_type="action.approved",
            tenant_id=cmd.tenant_id,
            aggregate_type="action",
            aggregate_id=cmd.action_id,
            occurred_at=now,
            actor=cmd.approver,
            payload={"decision_digest": binding_digest},
        ),
    )

    _audit(
        audit,
        AuditEntry(
            entry_id=uuid4(),
            tenant_id=cmd.tenant_id,
            actor=cmd.approver,
            action="approve_action",
            resource_type="action",
            resource_id=cmd.action_id,
            occurred_at=now,
        ),
    )

    return CommandResult(
        status=CommandStatus.SUCCESS,
        resource_id=cmd.action_id,
        data={"binding_digest": binding_digest},
    )


def handle_reject_action(
    cmd: RejectActionCommand,
    action_repo: ActionRepository,
    bus: EventBus | None = None,
    audit: AuditLog | None = None,
    approval_registry: ApprovalRegistry | None = None,
) -> CommandResult:
    action = action_repo.get(cmd.tenant_id, cmd.action_id)
    if action is None:
        return CommandResult(
            status=CommandStatus.NOT_FOUND, message="action not found"
        )

    rejectable = {"proposed", "approval_required"}
    if action["state"] not in rejectable:
        return CommandResult(
            status=CommandStatus.CONFLICT,
            message=f"cannot reject action in state {action['state']}",
        )

    if approval_registry is not None:
        try:
            approval_registry.deny(
                cmd.tenant_id, cmd.action_id, cmd.approver, reason=cmd.reason
            )
        except ApprovalRegistryError as exc:
            return CommandResult(status=CommandStatus.REJECTED, message=str(exc))

    now = _now()
    action_repo.update_state(cmd.tenant_id, cmd.action_id, "rejected")

    _emit(
        bus,
        DomainEvent(
            event_id=uuid4(),
            event_type="action.rejected",
            tenant_id=cmd.tenant_id,
            aggregate_type="action",
            aggregate_id=cmd.action_id,
            occurred_at=now,
            actor=cmd.approver,
            payload={"reason": cmd.reason},
        ),
    )

    _audit(
        audit,
        AuditEntry(
            entry_id=uuid4(),
            tenant_id=cmd.tenant_id,
            actor=cmd.approver,
            action="reject_action",
            resource_type="action",
            resource_id=cmd.action_id,
            occurred_at=now,
            details={"reason": cmd.reason},
        ),
    )

    return CommandResult(status=CommandStatus.SUCCESS, resource_id=cmd.action_id)


def handle_record_evidence(
    cmd: RecordEvidenceCommand,
    evidence_store: EvidenceStore,
    bus: EventBus | None = None,
) -> CommandResult:
    if not cmd.data:
        return CommandResult(
            status=CommandStatus.REJECTED, message="evidence data is empty"
        )

    metadata = {
        **cmd.metadata,
        "action_id": str(cmd.action_id),
        "recorded_by": cmd.actor,
    }
    digest = evidence_store.store(cmd.tenant_id, cmd.data, cmd.media_type, metadata)

    _emit(
        bus,
        DomainEvent(
            event_id=uuid4(),
            event_type="evidence.captured",
            tenant_id=cmd.tenant_id,
            aggregate_type="evidence",
            aggregate_id=cmd.action_id,
            occurred_at=_now(),
            actor=cmd.actor,
            payload={"digest": digest, "media_type": cmd.media_type},
        ),
    )

    return CommandResult(
        status=CommandStatus.SUCCESS,
        data={"digest": digest},
    )


# ---------------------------------------------------------------------------
# In-memory implementations (for testing / dev)
# ---------------------------------------------------------------------------


class InMemoryEngagementRepo:
    def __init__(self) -> None:
        self._store: dict[tuple[UUID, UUID], dict[str, Any]] = {}
        self._revisions: dict[tuple[UUID, UUID], list[dict[str, Any]]] = {}

    def get(self, tenant_id: UUID, engagement_id: UUID) -> dict[str, Any] | None:
        return self._store.get((tenant_id, engagement_id))

    def create(self, tenant_id: UUID, engagement: dict[str, Any]) -> UUID:
        eid = engagement["id"]
        self._store[(tenant_id, eid)] = engagement
        return eid

    def update_state(
        self, tenant_id: UUID, engagement_id: UUID, state: str
    ) -> None:
        key = (tenant_id, engagement_id)
        if key in self._store:
            self._store[key]["state"] = state

    def create_revision(
        self, tenant_id: UUID, engagement_id: UUID, revision: dict[str, Any]
    ) -> UUID:
        key = (tenant_id, engagement_id)
        self._revisions.setdefault(key, []).append(revision)
        return revision.get("id", uuid4())

    def get_current_revision(
        self, tenant_id: UUID, engagement_id: UUID
    ) -> dict[str, Any] | None:
        key = (tenant_id, engagement_id)
        revs = self._revisions.get(key, [])
        return revs[-1] if revs else None


class InMemoryActionRepo:
    def __init__(self) -> None:
        self._store: dict[tuple[UUID, UUID], dict[str, Any]] = {}

    def get(self, tenant_id: UUID, action_id: UUID) -> dict[str, Any] | None:
        return self._store.get((tenant_id, action_id))

    def create(self, tenant_id: UUID, action: dict[str, Any]) -> UUID:
        aid = action["id"]
        self._store[(tenant_id, aid)] = action
        return aid

    def update_state(
        self, tenant_id: UUID, action_id: UUID, state: str
    ) -> None:
        key = (tenant_id, action_id)
        if key in self._store:
            self._store[key]["state"] = state

    def list_by_engagement(
        self, tenant_id: UUID, engagement_id: UUID
    ) -> list[dict[str, Any]]:
        return [
            a
            for (tid, _), a in self._store.items()
            if tid == tenant_id and a.get("engagement_id") == engagement_id
        ]


class InMemoryEvidenceStore:
    def __init__(self) -> None:
        self._store: dict[tuple[UUID, str], tuple[bytes, str, dict[str, Any]]] = {}

    def store(
        self, tenant_id: UUID, data: bytes, media_type: str, metadata: dict[str, Any]
    ) -> str:
        import hashlib

        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        self._store[(tenant_id, digest)] = (data, media_type, metadata)
        return digest

    def get_metadata(self, tenant_id: UUID, digest: str) -> dict[str, Any] | None:
        entry = self._store.get((tenant_id, digest))
        if entry is None:
            return None
        _, media_type, metadata = entry
        return {**metadata, "media_type": media_type, "digest": digest}

    def get_artifact(self, tenant_id: UUID, digest: str) -> bytes | None:
        entry = self._store.get((tenant_id, digest))
        return entry[0] if entry else None


class InMemoryEventBus:
    def __init__(self) -> None:
        self.events: list[DomainEvent] = []

    def publish(self, event: DomainEvent) -> None:
        self.events.append(event)


class InMemoryAuditLog:
    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def record(self, entry: AuditEntry) -> None:
        self.entries.append(entry)
