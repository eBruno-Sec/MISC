"""Unit tests for the secret store."""
from __future__ import annotations

import time
from uuid import uuid4

import pytest

from packages.secret_store import InMemorySecretStore, SecretRef, compute_fingerprint


class TestComputeFingerprint:
    def test_deterministic(self):
        v = b"my-secret"
        assert compute_fingerprint(v) == compute_fingerprint(v)

    def test_different_values_different_fingerprints(self):
        assert compute_fingerprint(b"a") != compute_fingerprint(b"b")

    def test_format(self):
        fp = compute_fingerprint(b"test")
        assert fp.startswith("sha256:")
        assert len(fp) == 7 + 32


class TestInMemorySecretStore:
    def test_store_and_retrieve(self):
        store = InMemorySecretStore()
        tid = uuid4()
        ref = store.store(tid, b"secret-value")
        assert ref.fingerprint.startswith("sha256:")
        assert ref.provider == "in-memory"
        retrieved = store.retrieve(tid, ref)
        assert retrieved == b"secret-value"

    def test_retrieve_wrong_tenant(self):
        store = InMemorySecretStore()
        tid_a, tid_b = uuid4(), uuid4()
        ref = store.store(tid_a, b"secret")
        assert store.retrieve(tid_b, ref) is None

    def test_revoke(self):
        store = InMemorySecretStore()
        tid = uuid4()
        ref = store.store(tid, b"secret")
        assert store.retrieve(tid, ref) == b"secret"
        assert store.revoke(tid, ref)
        assert store.retrieve(tid, ref) is None

    def test_revoke_wrong_tenant(self):
        store = InMemorySecretStore()
        tid_a, tid_b = uuid4(), uuid4()
        ref = store.store(tid_a, b"secret")
        assert not store.revoke(tid_b, ref)
        assert store.retrieve(tid_a, ref) == b"secret"

    def test_secret_ref_repr_does_not_leak(self):
        store = InMemorySecretStore()
        ref = store.store(uuid4(), b"top-secret-password")
        repr_str = repr(ref)
        assert "top-secret-password" not in repr_str
        assert "SecretRef" in repr_str

    def test_metadata_on_ref(self):
        store = InMemorySecretStore()
        ref = store.store(uuid4(), b"v", {"role": "admin"})
        assert ref.metadata["role"] == "admin"

    def test_count(self):
        store = InMemorySecretStore()
        tid = uuid4()
        store.store(tid, b"a")
        store.store(tid, b"b")
        store.store(uuid4(), b"c")
        assert store.count(tid) == 2


class TestLeaseBasedAccess:
    def test_create_and_use_lease(self):
        store = InMemorySecretStore()
        tid = uuid4()
        ref = store.store(tid, b"secret")
        lease = store.create_lease(tid, ref, duration_seconds=3600, purpose="test")
        assert lease is not None
        assert not lease.is_expired
        assert store.retrieve_with_lease(tid, lease) == b"secret"

    def test_expired_lease_denied(self):
        store = InMemorySecretStore()
        tid = uuid4()
        ref = store.store(tid, b"secret")
        lease = store.create_lease(tid, ref, duration_seconds=-1, purpose="test")
        assert lease is not None
        assert lease.is_expired
        assert store.retrieve_with_lease(tid, lease) is None

    def test_lease_on_revoked_secret_denied(self):
        store = InMemorySecretStore()
        tid = uuid4()
        ref = store.store(tid, b"secret")
        lease = store.create_lease(tid, ref, duration_seconds=3600, purpose="test")
        store.revoke(tid, ref)
        assert store.retrieve_with_lease(tid, lease) is None

    def test_cannot_lease_revoked_secret(self):
        store = InMemorySecretStore()
        tid = uuid4()
        ref = store.store(tid, b"secret")
        store.revoke(tid, ref)
        assert store.create_lease(tid, ref, 3600, "test") is None


class TestBulkRevocation:
    def test_revoke_all_leases(self):
        store = InMemorySecretStore()
        tid = uuid4()
        ref1 = store.store(tid, b"a")
        ref2 = store.store(tid, b"b")
        l1 = store.create_lease(tid, ref1, 3600, "test1")
        l2 = store.create_lease(tid, ref2, 3600, "test2")
        assert store.revoke_all_leases(tid) == 2
        assert store.retrieve_with_lease(tid, l1) is None
        assert store.retrieve_with_lease(tid, l2) is None
        assert store.retrieve(tid, ref1) == b"a"

    def test_revoke_all_secrets(self):
        store = InMemorySecretStore()
        tid = uuid4()
        ref1 = store.store(tid, b"a")
        ref2 = store.store(tid, b"b")
        other_tid = uuid4()
        ref3 = store.store(other_tid, b"c")
        assert store.revoke_all_secrets(tid) == 2
        assert store.retrieve(tid, ref1) is None
        assert store.retrieve(tid, ref2) is None
        assert store.retrieve(other_tid, ref3) == b"c"
