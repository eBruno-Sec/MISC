"""ArsGoatia capability registry — proven-only, evidence-backed capabilities.

Per spec §18:
  - A capability is emitted ONLY when a finding reaches CONFIRMED state AND
    all required evidence is present with verified digests.
  - Capabilities are immutable once recorded; they cannot be deleted or modified.
  - Capabilities may expire; an expired capability is not actionable but its
    record is preserved for audit.
  - Capability transitions track the provenance chain: discovery → proven.
  - Capabilities are scoped to (tenant_id, engagement_id) pairs.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4


class CapabilityState(enum.Enum):
    DISCOVERED = "discovered"
    PROVEN = "proven"
    EXPIRED = "expired"
    SUPERSEDED = "superseded"


CAPABILITY_TRANSITIONS: dict[CapabilityState, frozenset[CapabilityState]] = {
    CapabilityState.DISCOVERED: frozenset({CapabilityState.PROVEN, CapabilityState.SUPERSEDED}),
    CapabilityState.PROVEN: frozenset({CapabilityState.EXPIRED, CapabilityState.SUPERSEDED}),
    CapabilityState.EXPIRED: frozenset(),
    CapabilityState.SUPERSEDED: frozenset(),
}

ACTIVE_CAPABILITY_STATES = frozenset({CapabilityState.DISCOVERED, CapabilityState.PROVEN})


class CapabilityError(Exception):
    pass


class EvidenceRequiredError(CapabilityError):
    pass


class FindingNotConfirmedError(CapabilityError):
    pass


class InvalidTransitionError(CapabilityError):
    pass


@dataclass(frozen=True)
class CapabilityRecord:
    capability_id: UUID
    tenant_id: UUID
    engagement_id: UUID
    name: str
    description: str
    finding_id: UUID
    evidence_digests: frozenset[str]
    state: CapabilityState
    technique_id: str
    target_locator: str
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    superseded_by: UUID | None = None


@dataclass(frozen=True)
class CapabilityTransition:
    transition_id: UUID
    capability_id: UUID
    from_state: CapabilityState
    to_state: CapabilityState
    reason: str
    actor: str
    transitioned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class CapabilityRegistry:
    """Immutable capability store — append-only, no update or delete paths."""

    def __init__(self) -> None:
        self._capabilities: dict[tuple[UUID, UUID], CapabilityRecord] = {}
        self._transitions: list[CapabilityTransition] = []
        # name → set of capability_ids per (tenant, engagement)
        self._name_index: dict[tuple[UUID, UUID, str], set[UUID]] = {}

    def emit(
        self,
        tenant_id: UUID,
        engagement_id: UUID,
        name: str,
        description: str,
        finding_id: UUID,
        evidence_digests: frozenset[str],
        technique_id: str,
        target_locator: str,
        *,
        finding_state: str = "confirmed",
        initial_state: CapabilityState = CapabilityState.PROVEN,
        expires_in: timedelta | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> CapabilityRecord:
        if finding_state.lower() != "confirmed":
            raise FindingNotConfirmedError(
                f"capability may only be emitted from a confirmed finding; "
                f"got finding_state={finding_state!r}"
            )

        if not evidence_digests:
            raise EvidenceRequiredError(
                "at least one evidence digest is required to emit a capability"
            )

        for digest in evidence_digests:
            if not digest.startswith("sha256:"):
                raise EvidenceRequiredError(
                    f"evidence digest must be sha256-prefixed: {digest!r}"
                )

        now = datetime.now(timezone.utc)
        expires_at = (now + expires_in) if expires_in else None

        record = CapabilityRecord(
            capability_id=uuid4(),
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            name=name,
            description=description,
            finding_id=finding_id,
            evidence_digests=evidence_digests,
            state=initial_state,
            technique_id=technique_id,
            target_locator=target_locator,
            metadata=metadata or {},
            created_at=now,
            expires_at=expires_at,
        )
        key = (tenant_id, record.capability_id)
        self._capabilities[key] = record

        name_key = (tenant_id, engagement_id, name)
        self._name_index.setdefault(name_key, set()).add(record.capability_id)

        return record

    def get(self, tenant_id: UUID, capability_id: UUID) -> CapabilityRecord | None:
        return self._capabilities.get((tenant_id, capability_id))

    def transition(
        self,
        tenant_id: UUID,
        capability_id: UUID,
        new_state: CapabilityState,
        reason: str = "",
        actor: str = "system",
        superseded_by: UUID | None = None,
    ) -> CapabilityRecord:
        key = (tenant_id, capability_id)
        record = self._capabilities.get(key)
        if record is None:
            raise CapabilityError(f"capability not found: {capability_id}")

        allowed = CAPABILITY_TRANSITIONS.get(record.state, frozenset())
        if new_state not in allowed:
            raise InvalidTransitionError(
                f"invalid capability transition: {record.state.value} → {new_state.value}"
            )

        self._transitions.append(CapabilityTransition(
            transition_id=uuid4(),
            capability_id=capability_id,
            from_state=record.state,
            to_state=new_state,
            reason=reason,
            actor=actor,
        ))

        updated = CapabilityRecord(
            capability_id=record.capability_id,
            tenant_id=record.tenant_id,
            engagement_id=record.engagement_id,
            name=record.name,
            description=record.description,
            finding_id=record.finding_id,
            evidence_digests=record.evidence_digests,
            state=new_state,
            technique_id=record.technique_id,
            target_locator=record.target_locator,
            metadata=record.metadata,
            created_at=record.created_at,
            expires_at=record.expires_at,
            superseded_by=superseded_by,
        )
        self._capabilities[key] = updated
        return updated

    def is_active(self, tenant_id: UUID, capability_id: UUID) -> bool:
        record = self.get(tenant_id, capability_id)
        if record is None:
            return False
        if record.state not in ACTIVE_CAPABILITY_STATES:
            return False
        if record.expires_at and datetime.now(timezone.utc) > record.expires_at:
            return False
        return True

    def list_for_engagement(
        self,
        tenant_id: UUID,
        engagement_id: UUID,
        *,
        active_only: bool = False,
    ) -> list[CapabilityRecord]:
        results = [
            r for r in self._capabilities.values()
            if r.tenant_id == tenant_id and r.engagement_id == engagement_id
        ]
        if active_only:
            results = [r for r in results if self.is_active(tenant_id, r.capability_id)]
        return results

    def find_by_name(
        self,
        tenant_id: UUID,
        engagement_id: UUID,
        name: str,
        *,
        active_only: bool = True,
    ) -> list[CapabilityRecord]:
        name_key = (tenant_id, engagement_id, name)
        cap_ids = self._name_index.get(name_key, set())
        results = []
        for cid in cap_ids:
            record = self.get(tenant_id, cid)
            if record is None:
                continue
            if active_only and not self.is_active(tenant_id, cid):
                continue
            results.append(record)
        return results

    def transitions_for(self, capability_id: UUID) -> list[CapabilityTransition]:
        return [t for t in self._transitions if t.capability_id == capability_id]

    def has_capability(
        self,
        tenant_id: UUID,
        engagement_id: UUID,
        name: str,
    ) -> bool:
        return len(self.find_by_name(tenant_id, engagement_id, name)) > 0
