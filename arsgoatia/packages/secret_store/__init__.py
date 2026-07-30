"""ArsGoatia secret store — secrets as references only.

Per spec §3 invariant: secrets are never stored in logs, evidence, prompts,
or conversation history. This module provides:
- A SecretProvider protocol for pluggable backends (env-file for dev, Vault for prod)
- SecretRef: an opaque reference with fingerprint but no raw value
- Lease-based access: callers get time-bounded leases, not persistent handles
- Revocation: emergency stop can revoke all leases instantly
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable
from uuid import UUID, uuid4


@dataclass(frozen=True)
class SecretRef:
    ref_id: UUID
    fingerprint: str
    provider: str
    created_at: float
    metadata: dict[str, str] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"SecretRef(ref_id={self.ref_id}, fingerprint={self.fingerprint[:16]}...)"


@dataclass(frozen=True)
class SecretLease:
    lease_id: UUID
    ref: SecretRef
    expires_at: float
    tenant_id: UUID
    purpose: str

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at


@runtime_checkable
class SecretProvider(Protocol):
    def store(self, tenant_id: UUID, value: bytes, metadata: dict[str, str]) -> SecretRef: ...

    def retrieve(self, tenant_id: UUID, ref: SecretRef) -> bytes | None: ...

    def revoke(self, tenant_id: UUID, ref: SecretRef) -> bool: ...


def compute_fingerprint(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()[:32]


class InMemorySecretStore:
    def __init__(self) -> None:
        self._secrets: dict[tuple[UUID, UUID], bytes] = {}
        self._refs: dict[tuple[UUID, UUID], SecretRef] = {}
        self._leases: dict[UUID, SecretLease] = {}
        self._revoked: set[UUID] = set()

    def store(
        self, tenant_id: UUID, value: bytes, metadata: dict[str, str] | None = None
    ) -> SecretRef:
        ref = SecretRef(
            ref_id=uuid4(),
            fingerprint=compute_fingerprint(value),
            provider="in-memory",
            created_at=time.time(),
            metadata=metadata or {},
        )
        key = (tenant_id, ref.ref_id)
        self._secrets[key] = value
        self._refs[key] = ref
        return ref

    def retrieve(self, tenant_id: UUID, ref: SecretRef) -> bytes | None:
        if ref.ref_id in self._revoked:
            return None
        return self._secrets.get((tenant_id, ref.ref_id))

    def revoke(self, tenant_id: UUID, ref: SecretRef) -> bool:
        key = (tenant_id, ref.ref_id)
        if key in self._secrets:
            del self._secrets[key]
            self._revoked.add(ref.ref_id)
            return True
        return False

    def create_lease(
        self,
        tenant_id: UUID,
        ref: SecretRef,
        duration_seconds: float,
        purpose: str,
    ) -> SecretLease | None:
        if ref.ref_id in self._revoked:
            return None
        if (tenant_id, ref.ref_id) not in self._secrets:
            return None

        lease = SecretLease(
            lease_id=uuid4(),
            ref=ref,
            expires_at=time.time() + duration_seconds,
            tenant_id=tenant_id,
            purpose=purpose,
        )
        self._leases[lease.lease_id] = lease
        return lease

    def retrieve_with_lease(self, tenant_id: UUID, lease: SecretLease) -> bytes | None:
        if lease.is_expired:
            return None
        if lease.lease_id not in self._leases:
            return None
        if lease.ref.ref_id in self._revoked:
            return None
        return self._secrets.get((tenant_id, lease.ref.ref_id))

    def revoke_all_leases(self, tenant_id: UUID) -> int:
        revoked = 0
        to_remove = [lid for lid, lease in self._leases.items() if lease.tenant_id == tenant_id]
        for lid in to_remove:
            del self._leases[lid]
            revoked += 1
        return revoked

    def revoke_all_secrets(self, tenant_id: UUID) -> int:
        revoked = 0
        to_remove = [key for key in self._secrets if key[0] == tenant_id]
        for key in to_remove:
            self._revoked.add(key[1])
            del self._secrets[key]
            revoked += 1
        return revoked

    def count(self, tenant_id: UUID) -> int:
        return sum(1 for k in self._secrets if k[0] == tenant_id)
