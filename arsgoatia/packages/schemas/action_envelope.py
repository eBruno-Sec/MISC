"""Signed action envelope (§13.5) and approval binding (§13.6).

The control plane signs an envelope only after a policy decision and, when
required, a matching approval. The executor re-verifies signature, expiry,
revision currency, and approval binding before any target-facing action.
"""

from __future__ import annotations

import enum
from datetime import datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from schemas.common import RiskClass, utcnow


class ActorKind(str, enum.Enum):
    AGENT = "agent"
    ANALYST = "analyst"
    SYSTEM = "system"


class Actor(BaseModel):
    kind: ActorKind
    id: str


class EnvelopeTarget(BaseModel):
    asset_id: UUID
    endpoint_id: UUID | None = None
    resolved_destination: str


class ActionBudget(BaseModel):
    max_requests: int
    max_rps: float
    timeout_seconds: int
    max_bytes: int


class ActionEnvelope(BaseModel):
    """Canonical, signable action envelope. `signature` is set by the signer
    (packages/policy/envelope.py) over the canonical form of every other field."""

    model_config = ConfigDict(frozen=True)

    action_id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    assessment_id: UUID
    assessment_revision: int
    policy_revision: int
    module_id: str
    module_version: str
    actor: Actor
    origin_context_id: UUID
    targets: list[EnvelopeTarget]
    requested_effect: str
    risk_class: RiskClass
    approval_ref: UUID | None = None
    budget: ActionBudget
    idempotency_key: str
    expires_at: datetime
    signature: str = ""

    def is_expired(self, now: datetime | None = None) -> bool:
        return (now or utcnow()) >= self.expires_at


class ApprovalBinding(BaseModel):
    """§13.6 — approval binds to an exact action, never a generic boolean."""

    approval_ref: UUID = Field(default_factory=uuid4)
    action_class: str
    target_ids: list[UUID]
    context_id: UUID
    assessment_revision: int
    policy_revision: int
    enforced_limits_hash: str
    mutation_allowance: int = 0
    cleanup_required: bool = False
    expires_at: datetime
    resolved_by: str | None = None
    resolved_at: datetime | None = None
    granted: bool | None = None
