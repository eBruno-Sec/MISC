"""ArsGoatia identity bootstrap — test identity management for assessments.

Handles creation and management of test identities used during assessments.
Per spec: identities are registered against the target, JWTs stored as
secret references (never logged), and access contexts track which identity
has which level of access.

For the first vertical slice (Juice Shop IDOR):
  - Register 2 test users via target's registration endpoint
  - Log in each to get JWT tokens → secret store (ref only)
  - Create access contexts mapping identity → capabilities
  - Track session validity and credential fingerprints
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID, uuid4


@dataclass(frozen=True)
class TestIdentity:
    identity_id: UUID
    tenant_id: UUID
    engagement_id: UUID
    label: str
    email: str
    credential_fingerprint: str
    secret_ref_id: UUID | None = None
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class AccessContext:
    context_id: UUID
    identity: TestIdentity
    session_token_fingerprint: str
    secret_ref_id: UUID
    capabilities: frozenset[str] = frozenset()
    is_valid: bool = True


@dataclass(frozen=True)
class IdentityBootstrapPlan:
    engagement_id: UUID
    target_base_url: str
    registration_path: str
    login_path: str
    identities_to_create: int = 2


@dataclass(frozen=True)
class BootstrapResult:
    success: bool
    identities: list[TestIdentity]
    access_contexts: list[AccessContext]
    errors: list[str] = field(default_factory=list)
    evidence_digests: list[str] = field(default_factory=list)


class IdentityRegistry:
    def __init__(self) -> None:
        self._identities: dict[tuple[UUID, UUID], TestIdentity] = {}
        self._contexts: dict[tuple[UUID, UUID], AccessContext] = {}

    def register(self, identity: TestIdentity) -> None:
        key = (identity.tenant_id, identity.identity_id)
        self._identities[key] = identity

    def get(self, tenant_id: UUID, identity_id: UUID) -> TestIdentity | None:
        return self._identities.get((tenant_id, identity_id))

    def list_for_engagement(
        self, tenant_id: UUID, engagement_id: UUID
    ) -> list[TestIdentity]:
        return [
            ident for ident in self._identities.values()
            if ident.tenant_id == tenant_id and ident.engagement_id == engagement_id
        ]

    def add_context(self, context: AccessContext) -> None:
        key = (context.identity.tenant_id, context.context_id)
        self._contexts[key] = context

    def get_context(self, tenant_id: UUID, context_id: UUID) -> AccessContext | None:
        return self._contexts.get((tenant_id, context_id))

    def contexts_for_identity(
        self, tenant_id: UUID, identity_id: UUID
    ) -> list[AccessContext]:
        return [
            ctx for ctx in self._contexts.values()
            if ctx.identity.tenant_id == tenant_id
            and ctx.identity.identity_id == identity_id
        ]

    def invalidate_all(self, tenant_id: UUID, engagement_id: UUID) -> int:
        count = 0
        to_update = []
        for key, ctx in self._contexts.items():
            if (ctx.identity.tenant_id == tenant_id
                    and ctx.identity.engagement_id == engagement_id
                    and ctx.is_valid):
                to_update.append(key)

        for key in to_update:
            old = self._contexts[key]
            self._contexts[key] = AccessContext(
                context_id=old.context_id,
                identity=old.identity,
                session_token_fingerprint=old.session_token_fingerprint,
                secret_ref_id=old.secret_ref_id,
                capabilities=old.capabilities,
                is_valid=False,
            )
            count += 1
        return count


def fingerprint_credential(raw_value: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw_value).hexdigest()[:32]


def create_test_identity(
    tenant_id: UUID,
    engagement_id: UUID,
    label: str,
    email: str,
    credential_value: bytes,
    secret_ref_id: UUID | None = None,
) -> TestIdentity:
    return TestIdentity(
        identity_id=uuid4(),
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        label=label,
        email=email,
        credential_fingerprint=fingerprint_credential(credential_value),
        secret_ref_id=secret_ref_id,
    )
