"""Unit tests for the identity bootstrap package."""

from __future__ import annotations

from uuid import uuid4

import pytest

from packages.identity import (
    AccessContext,
    BootstrapResult,
    IdentityBootstrapPlan,
    IdentityRegistry,
    create_test_identity,
    fingerprint_credential,
)


class TestFingerprintCredential:
    def test_deterministic(self):
        cred = b"my-password"
        assert fingerprint_credential(cred) == fingerprint_credential(cred)

    def test_different_values_differ(self):
        assert fingerprint_credential(b"a") != fingerprint_credential(b"b")

    def test_format(self):
        fp = fingerprint_credential(b"test")
        assert fp.startswith("sha256:")
        assert len(fp) == 7 + 32

    def test_empty_bytes(self):
        fp = fingerprint_credential(b"")
        assert fp.startswith("sha256:")


class TestCreateTestIdentity:
    def test_creates_identity(self):
        tid = uuid4()
        eid = uuid4()
        identity = create_test_identity(
            tenant_id=tid,
            engagement_id=eid,
            label="alice",
            email="alice@example.com",
            credential_value=b"password123",
        )
        assert identity.tenant_id == tid
        assert identity.engagement_id == eid
        assert identity.label == "alice"
        assert identity.email == "alice@example.com"
        assert identity.credential_fingerprint.startswith("sha256:")

    def test_secret_ref_id_optional(self):
        identity = create_test_identity(
            tenant_id=uuid4(),
            engagement_id=uuid4(),
            label="anon",
            email="anon@example.com",
            credential_value=b"pass",
        )
        assert identity.secret_ref_id is None

    def test_secret_ref_id_set(self):
        ref_id = uuid4()
        identity = create_test_identity(
            tenant_id=uuid4(),
            engagement_id=uuid4(),
            label="admin",
            email="admin@example.com",
            credential_value=b"pass",
            secret_ref_id=ref_id,
        )
        assert identity.secret_ref_id == ref_id

    def test_unique_ids(self):
        tid, eid = uuid4(), uuid4()
        i1 = create_test_identity(tid, eid, "a", "a@x.com", b"p")
        i2 = create_test_identity(tid, eid, "b", "b@x.com", b"p")
        assert i1.identity_id != i2.identity_id

    def test_frozen(self):
        identity = create_test_identity(uuid4(), uuid4(), "x", "x@x.com", b"p")
        with pytest.raises((AttributeError, TypeError)):
            identity.label = "modified"  # type: ignore[misc]


class TestIdentityRegistry:
    def test_register_and_get(self):
        reg = IdentityRegistry()
        tid = uuid4()
        identity = create_test_identity(tid, uuid4(), "user1", "u1@x.com", b"pass")
        reg.register(identity)
        found = reg.get(tid, identity.identity_id)
        assert found == identity

    def test_get_wrong_tenant_returns_none(self):
        reg = IdentityRegistry()
        tid_a, tid_b = uuid4(), uuid4()
        identity = create_test_identity(tid_a, uuid4(), "user", "u@x.com", b"pass")
        reg.register(identity)
        assert reg.get(tid_b, identity.identity_id) is None

    def test_get_unknown_id_returns_none(self):
        reg = IdentityRegistry()
        assert reg.get(uuid4(), uuid4()) is None

    def test_list_for_engagement(self):
        reg = IdentityRegistry()
        tid = uuid4()
        eid = uuid4()
        other_eid = uuid4()
        i1 = create_test_identity(tid, eid, "a", "a@x.com", b"p1")
        i2 = create_test_identity(tid, eid, "b", "b@x.com", b"p2")
        i3 = create_test_identity(tid, other_eid, "c", "c@x.com", b"p3")
        reg.register(i1)
        reg.register(i2)
        reg.register(i3)
        result = reg.list_for_engagement(tid, eid)
        assert len(result) == 2
        ids = {i.identity_id for i in result}
        assert i1.identity_id in ids
        assert i2.identity_id in ids
        assert i3.identity_id not in ids

    def test_list_for_engagement_wrong_tenant(self):
        reg = IdentityRegistry()
        tid_a, tid_b = uuid4(), uuid4()
        eid = uuid4()
        identity = create_test_identity(tid_a, eid, "u", "u@x.com", b"p")
        reg.register(identity)
        assert reg.list_for_engagement(tid_b, eid) == []

    def test_add_and_get_context(self):
        reg = IdentityRegistry()
        tid = uuid4()
        identity = create_test_identity(tid, uuid4(), "user", "u@x.com", b"pass")
        reg.register(identity)
        ctx = AccessContext(
            context_id=uuid4(),
            identity=identity,
            session_token_fingerprint="sha256:abc",
            secret_ref_id=uuid4(),
            capabilities=frozenset({"read_basket"}),
        )
        reg.add_context(ctx)
        found = reg.get_context(tid, ctx.context_id)
        assert found == ctx

    def test_get_context_wrong_tenant(self):
        reg = IdentityRegistry()
        tid_a, tid_b = uuid4(), uuid4()
        identity = create_test_identity(tid_a, uuid4(), "u", "u@x.com", b"p")
        ctx = AccessContext(
            context_id=uuid4(),
            identity=identity,
            session_token_fingerprint="sha256:abc",
            secret_ref_id=uuid4(),
        )
        reg.add_context(ctx)
        assert reg.get_context(tid_b, ctx.context_id) is None

    def test_contexts_for_identity(self):
        reg = IdentityRegistry()
        tid = uuid4()
        identity = create_test_identity(tid, uuid4(), "u", "u@x.com", b"p")
        reg.register(identity)
        ctx1 = AccessContext(
            context_id=uuid4(),
            identity=identity,
            session_token_fingerprint="sha256:aaa",
            secret_ref_id=uuid4(),
        )
        ctx2 = AccessContext(
            context_id=uuid4(),
            identity=identity,
            session_token_fingerprint="sha256:bbb",
            secret_ref_id=uuid4(),
        )
        reg.add_context(ctx1)
        reg.add_context(ctx2)
        result = reg.contexts_for_identity(tid, identity.identity_id)
        assert len(result) == 2

    def test_invalidate_all(self):
        reg = IdentityRegistry()
        tid = uuid4()
        eid = uuid4()
        i1 = create_test_identity(tid, eid, "a", "a@x.com", b"pa")
        i2 = create_test_identity(tid, eid, "b", "b@x.com", b"pb")
        reg.register(i1)
        reg.register(i2)
        ctx1 = AccessContext(
            context_id=uuid4(),
            identity=i1,
            session_token_fingerprint="sha256:aaa",
            secret_ref_id=uuid4(),
            is_valid=True,
        )
        ctx2 = AccessContext(
            context_id=uuid4(),
            identity=i2,
            session_token_fingerprint="sha256:bbb",
            secret_ref_id=uuid4(),
            is_valid=True,
        )
        reg.add_context(ctx1)
        reg.add_context(ctx2)
        count = reg.invalidate_all(tid, eid)
        assert count == 2
        assert not reg.get_context(tid, ctx1.context_id).is_valid
        assert not reg.get_context(tid, ctx2.context_id).is_valid

    def test_invalidate_all_different_engagement(self):
        reg = IdentityRegistry()
        tid = uuid4()
        eid_a, eid_b = uuid4(), uuid4()
        i_a = create_test_identity(tid, eid_a, "a", "a@x.com", b"pa")
        i_b = create_test_identity(tid, eid_b, "b", "b@x.com", b"pb")
        reg.register(i_a)
        reg.register(i_b)
        ctx_a = AccessContext(
            context_id=uuid4(),
            identity=i_a,
            session_token_fingerprint="sha256:aaa",
            secret_ref_id=uuid4(),
        )
        ctx_b = AccessContext(
            context_id=uuid4(),
            identity=i_b,
            session_token_fingerprint="sha256:bbb",
            secret_ref_id=uuid4(),
        )
        reg.add_context(ctx_a)
        reg.add_context(ctx_b)
        count = reg.invalidate_all(tid, eid_a)
        assert count == 1
        assert reg.get_context(tid, ctx_b.context_id).is_valid

    def test_invalidate_all_returns_zero_for_empty(self):
        reg = IdentityRegistry()
        assert reg.invalidate_all(uuid4(), uuid4()) == 0

    def test_already_invalid_not_counted(self):
        reg = IdentityRegistry()
        tid = uuid4()
        eid = uuid4()
        identity = create_test_identity(tid, eid, "u", "u@x.com", b"p")
        reg.register(identity)
        ctx = AccessContext(
            context_id=uuid4(),
            identity=identity,
            session_token_fingerprint="sha256:aaa",
            secret_ref_id=uuid4(),
            is_valid=False,
        )
        reg.add_context(ctx)
        count = reg.invalidate_all(tid, eid)
        assert count == 0


class TestAccessContext:
    def test_default_valid(self):
        tid = uuid4()
        identity = create_test_identity(tid, uuid4(), "u", "u@x.com", b"p")
        ctx = AccessContext(
            context_id=uuid4(),
            identity=identity,
            session_token_fingerprint="sha256:abc",
            secret_ref_id=uuid4(),
        )
        assert ctx.is_valid is True

    def test_capabilities_default_empty(self):
        tid = uuid4()
        identity = create_test_identity(tid, uuid4(), "u", "u@x.com", b"p")
        ctx = AccessContext(
            context_id=uuid4(),
            identity=identity,
            session_token_fingerprint="sha256:abc",
            secret_ref_id=uuid4(),
        )
        assert ctx.capabilities == frozenset()

    def test_frozen(self):
        tid = uuid4()
        identity = create_test_identity(tid, uuid4(), "u", "u@x.com", b"p")
        ctx = AccessContext(
            context_id=uuid4(),
            identity=identity,
            session_token_fingerprint="sha256:abc",
            secret_ref_id=uuid4(),
        )
        with pytest.raises((AttributeError, TypeError)):
            ctx.is_valid = False  # type: ignore[misc]


class TestIdentityBootstrapPlan:
    def test_creation(self):
        eid = uuid4()
        plan = IdentityBootstrapPlan(
            engagement_id=eid,
            target_base_url="http://juice-shop:3000",
            registration_path="/api/Users",
            login_path="/rest/user/login",
        )
        assert plan.identities_to_create == 2
        assert plan.engagement_id == eid

    def test_custom_count(self):
        plan = IdentityBootstrapPlan(
            engagement_id=uuid4(),
            target_base_url="http://target",
            registration_path="/register",
            login_path="/login",
            identities_to_create=3,
        )
        assert plan.identities_to_create == 3


class TestBootstrapResult:
    def test_success_result(self):
        tid = uuid4()
        eid = uuid4()
        i1 = create_test_identity(tid, eid, "a", "a@x.com", b"p1")
        i2 = create_test_identity(tid, eid, "b", "b@x.com", b"p2")
        ctx1 = AccessContext(
            context_id=uuid4(),
            identity=i1,
            session_token_fingerprint="sha256:aaa",
            secret_ref_id=uuid4(),
        )
        ctx2 = AccessContext(
            context_id=uuid4(),
            identity=i2,
            session_token_fingerprint="sha256:bbb",
            secret_ref_id=uuid4(),
        )
        result = BootstrapResult(
            success=True,
            identities=[i1, i2],
            access_contexts=[ctx1, ctx2],
            evidence_digests=["sha256:digest1"],
        )
        assert result.success
        assert len(result.identities) == 2
        assert len(result.access_contexts) == 2
        assert result.errors == []

    def test_failure_result(self):
        result = BootstrapResult(
            success=False,
            identities=[],
            access_contexts=[],
            errors=["registration failed: 500"],
        )
        assert not result.success
        assert len(result.errors) == 1
