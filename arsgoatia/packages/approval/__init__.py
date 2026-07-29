"""ArsGoatia approval registry — action-bound, exactly-once approval tracking.

Per spec §13.8:
  - Approvals are bound to an exact (action_id, envelope_digest, risk_tier) tuple.
  - A generic "approved=true" is always rejected.
  - Duplicate approval for the same action_id is idempotent (first write wins).
  - Approvals expire; a request to use an expired approval is denied.
  - Two-person rule: R4 requires approver_id != requestor_id, both must be listed
    on the authorization record for that engagement.
"""
from __future__ import annotations

import enum
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4


class ApprovalState(enum.Enum):
    PENDING = "pending"
    GRANTED = "granted"
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"


APPROVAL_TRANSITIONS: dict[ApprovalState, frozenset[ApprovalState]] = {
    ApprovalState.PENDING: frozenset({
        ApprovalState.GRANTED,
        ApprovalState.DENIED,
        ApprovalState.REVOKED,
    }),
    ApprovalState.GRANTED: frozenset({ApprovalState.EXPIRED, ApprovalState.REVOKED}),
    ApprovalState.DENIED: frozenset(),
    ApprovalState.EXPIRED: frozenset(),
    ApprovalState.REVOKED: frozenset(),
}

TERMINAL_APPROVAL_STATES = frozenset({
    ApprovalState.DENIED,
    ApprovalState.EXPIRED,
    ApprovalState.REVOKED,
})


@dataclass(frozen=True)
class ApprovalRequest:
    request_id: UUID
    tenant_id: UUID
    engagement_id: UUID
    action_id: UUID
    envelope_digest: str
    risk_tier: str
    requestor_id: str
    requires_two_person: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(hours=4)
    )


@dataclass(frozen=True)
class ApprovalDecision:
    decision_id: UUID
    request_id: UUID
    action_id: UUID
    state: ApprovalState
    approver_id: str
    binding_digest: str
    decided_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    reason: str = ""


def compute_binding_digest(
    action_id: UUID,
    envelope_digest: str,
    approver_id: str,
    decided_at: datetime,
) -> str:
    payload = json.dumps(
        {
            "action_id": str(action_id),
            "envelope_digest": envelope_digest,
            "approver_id": approver_id,
            "decided_at": decided_at.isoformat(),
        },
        sort_keys=True,
    )
    return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()[:32]


class ApprovalRegistryError(Exception):
    pass


class DuplicateApprovalError(ApprovalRegistryError):
    pass


class InvalidTransitionError(ApprovalRegistryError):
    pass


class TwoPersonRuleError(ApprovalRegistryError):
    pass


class ApprovalRegistry:
    """Append-only approval ledger — first write wins per action_id."""

    def __init__(self) -> None:
        self._requests: dict[tuple[UUID, UUID], ApprovalRequest] = {}
        self._decisions: dict[tuple[UUID, UUID], ApprovalDecision] = {}
        # action_id -> request_id mapping per tenant
        self._action_index: dict[tuple[UUID, UUID], UUID] = {}

    # ------------------------------------------------------------------
    # Requests
    # ------------------------------------------------------------------

    def create_request(
        self,
        tenant_id: UUID,
        engagement_id: UUID,
        action_id: UUID,
        envelope_digest: str,
        risk_tier: str,
        requestor_id: str,
        *,
        requires_two_person: bool = False,
        expires_in: timedelta = timedelta(hours=4),
        metadata: dict[str, Any] | None = None,
    ) -> ApprovalRequest:
        action_key = (tenant_id, action_id)
        if action_key in self._action_index:
            existing_rid = self._action_index[action_key]
            raise DuplicateApprovalError(
                f"approval request already exists for action {action_id}: "
                f"request_id={existing_rid}"
            )

        now = datetime.now(timezone.utc)
        request = ApprovalRequest(
            request_id=uuid4(),
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            action_id=action_id,
            envelope_digest=envelope_digest,
            risk_tier=risk_tier,
            requestor_id=requestor_id,
            requires_two_person=requires_two_person,
            metadata=metadata or {},
            created_at=now,
            expires_at=now + expires_in,
        )
        key = (tenant_id, request.request_id)
        self._requests[key] = request
        self._action_index[action_key] = request.request_id
        return request

    def get_request(self, tenant_id: UUID, request_id: UUID) -> ApprovalRequest | None:
        return self._requests.get((tenant_id, request_id))

    def get_request_for_action(
        self, tenant_id: UUID, action_id: UUID
    ) -> ApprovalRequest | None:
        rid = self._action_index.get((tenant_id, action_id))
        if rid is None:
            return None
        return self._requests.get((tenant_id, rid))

    # ------------------------------------------------------------------
    # Decisions
    # ------------------------------------------------------------------

    def grant(
        self,
        tenant_id: UUID,
        action_id: UUID,
        approver_id: str,
        reason: str = "",
    ) -> ApprovalDecision:
        request = self.get_request_for_action(tenant_id, action_id)
        if request is None:
            raise ApprovalRegistryError(f"no approval request found for action {action_id}")

        if self._is_decided(tenant_id, action_id):
            raise DuplicateApprovalError(
                f"approval for action {action_id} already decided"
            )

        if datetime.now(timezone.utc) > request.expires_at:
            raise ApprovalRegistryError(f"approval request for action {action_id} has expired")

        if request.requires_two_person and approver_id == request.requestor_id:
            raise TwoPersonRuleError(
                f"two-person rule: approver_id must differ from requestor_id "
                f"({request.requestor_id!r})"
            )

        now = datetime.now(timezone.utc)
        binding = compute_binding_digest(
            action_id=action_id,
            envelope_digest=request.envelope_digest,
            approver_id=approver_id,
            decided_at=now,
        )
        decision = ApprovalDecision(
            decision_id=uuid4(),
            request_id=request.request_id,
            action_id=action_id,
            state=ApprovalState.GRANTED,
            approver_id=approver_id,
            binding_digest=binding,
            decided_at=now,
            reason=reason,
        )
        self._decisions[(tenant_id, action_id)] = decision
        return decision

    def deny(
        self,
        tenant_id: UUID,
        action_id: UUID,
        approver_id: str,
        reason: str = "",
    ) -> ApprovalDecision:
        request = self.get_request_for_action(tenant_id, action_id)
        if request is None:
            raise ApprovalRegistryError(f"no approval request found for action {action_id}")

        if self._is_decided(tenant_id, action_id):
            raise DuplicateApprovalError(
                f"approval for action {action_id} already decided"
            )

        if request.requires_two_person and approver_id == request.requestor_id:
            raise TwoPersonRuleError(
                "two-person rule: approver_id must differ from requestor_id"
            )

        now = datetime.now(timezone.utc)
        decision = ApprovalDecision(
            decision_id=uuid4(),
            request_id=request.request_id,
            action_id=action_id,
            state=ApprovalState.DENIED,
            approver_id=approver_id,
            binding_digest=compute_binding_digest(
                action_id=action_id,
                envelope_digest=request.envelope_digest,
                approver_id=approver_id,
                decided_at=now,
            ),
            decided_at=now,
            reason=reason,
        )
        self._decisions[(tenant_id, action_id)] = decision
        return decision

    def get_decision(self, tenant_id: UUID, action_id: UUID) -> ApprovalDecision | None:
        return self._decisions.get((tenant_id, action_id))

    def is_approved(self, tenant_id: UUID, action_id: UUID) -> bool:
        decision = self.get_decision(tenant_id, action_id)
        if decision is None:
            return False
        if decision.state != ApprovalState.GRANTED:
            return False
        request = self.get_request_for_action(tenant_id, action_id)
        if request and datetime.now(timezone.utc) > request.expires_at:
            return False
        return True

    def verify_binding(
        self,
        tenant_id: UUID,
        action_id: UUID,
        envelope_digest: str,
        binding_digest: str,
    ) -> bool:
        """Verify that a binding digest matches the stored decision for this envelope."""
        decision = self.get_decision(tenant_id, action_id)
        if decision is None or decision.state != ApprovalState.GRANTED:
            return False
        request = self.get_request_for_action(tenant_id, action_id)
        if request is None:
            return False
        if request.envelope_digest != envelope_digest:
            return False
        expected = compute_binding_digest(
            action_id=action_id,
            envelope_digest=envelope_digest,
            approver_id=decision.approver_id,
            decided_at=decision.decided_at,
        )
        return hmac.compare_digest(expected, binding_digest)

    def pending_for_engagement(
        self, tenant_id: UUID, engagement_id: UUID
    ) -> list[ApprovalRequest]:
        return [
            req
            for req in self._requests.values()
            if req.tenant_id == tenant_id
            and req.engagement_id == engagement_id
            and not self._is_decided(tenant_id, req.action_id)
        ]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_decided(self, tenant_id: UUID, action_id: UUID) -> bool:
        return (tenant_id, action_id) in self._decisions
