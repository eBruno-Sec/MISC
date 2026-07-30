"""Unit tests for the approval registry package."""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest

from packages.approval import (
    ApprovalRegistry,
    ApprovalRegistryError,
    ApprovalRequest,
    ApprovalState,
    DuplicateApprovalError,
    TwoPersonRuleError,
    compute_binding_digest,
)


def _registry() -> ApprovalRegistry:
    return ApprovalRegistry()


def _request(
    registry: ApprovalRegistry,
    tenant_id=None,
    engagement_id=None,
    action_id=None,
    requestor_id="alice",
    risk_tier="R2",
    requires_two_person=False,
    expires_in=timedelta(hours=4),
) -> ApprovalRequest:
    tid = tenant_id or uuid4()
    eid = engagement_id or uuid4()
    aid = action_id or uuid4()
    return registry.create_request(
        tenant_id=tid,
        engagement_id=eid,
        action_id=aid,
        envelope_digest="sha256:abc123",
        risk_tier=risk_tier,
        requestor_id=requestor_id,
        requires_two_person=requires_two_person,
        expires_in=expires_in,
    )


class TestComputeBindingDigest:
    def test_deterministic(self):
        from datetime import datetime, timezone

        aid = uuid4()
        now = datetime(2024, 1, 1, tzinfo=timezone.utc)
        d1 = compute_binding_digest(aid, "sha256:abc", "alice", now)
        d2 = compute_binding_digest(aid, "sha256:abc", "alice", now)
        assert d1 == d2

    def test_different_approvers_differ(self):
        from datetime import datetime, timezone

        aid = uuid4()
        now = datetime(2024, 1, 1, tzinfo=timezone.utc)
        d1 = compute_binding_digest(aid, "sha256:abc", "alice", now)
        d2 = compute_binding_digest(aid, "sha256:abc", "bob", now)
        assert d1 != d2

    def test_different_envelope_differ(self):
        from datetime import datetime, timezone

        aid = uuid4()
        now = datetime(2024, 1, 1, tzinfo=timezone.utc)
        d1 = compute_binding_digest(aid, "sha256:abc", "alice", now)
        d2 = compute_binding_digest(aid, "sha256:xyz", "alice", now)
        assert d1 != d2

    def test_format(self):
        from datetime import datetime, timezone

        d = compute_binding_digest(uuid4(), "sha256:abc", "alice", datetime.now(timezone.utc))
        assert d.startswith("sha256:")


class TestCreateRequest:
    def test_creates_request(self):
        reg = _registry()
        tid = uuid4()
        eid = uuid4()
        aid = uuid4()
        req = reg.create_request(
            tenant_id=tid,
            engagement_id=eid,
            action_id=aid,
            envelope_digest="sha256:abc",
            risk_tier="R2",
            requestor_id="alice",
        )
        assert req.action_id == aid
        assert req.tenant_id == tid
        assert req.risk_tier == "R2"
        assert req.requestor_id == "alice"

    def test_duplicate_action_id_raises(self):
        reg = _registry()
        tid = uuid4()
        aid = uuid4()
        reg.create_request(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=aid,
            envelope_digest="sha256:abc",
            risk_tier="R2",
            requestor_id="alice",
        )
        with pytest.raises(DuplicateApprovalError):
            reg.create_request(
                tenant_id=tid,
                engagement_id=uuid4(),
                action_id=aid,
                envelope_digest="sha256:xyz",
                risk_tier="R2",
                requestor_id="alice",
            )

    def test_same_action_different_tenant_ok(self):
        reg = _registry()
        tid_a, tid_b = uuid4(), uuid4()
        aid = uuid4()
        reg.create_request(
            tenant_id=tid_a,
            engagement_id=uuid4(),
            action_id=aid,
            envelope_digest="sha256:abc",
            risk_tier="R2",
            requestor_id="alice",
        )
        req = reg.create_request(
            tenant_id=tid_b,
            engagement_id=uuid4(),
            action_id=aid,
            envelope_digest="sha256:abc",
            risk_tier="R2",
            requestor_id="bob",
        )
        assert req is not None

    def test_get_request(self):
        reg = _registry()
        tid = uuid4()
        aid = uuid4()
        req = reg.create_request(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=aid,
            envelope_digest="sha256:abc",
            risk_tier="R2",
            requestor_id="alice",
        )
        found = reg.get_request(tid, req.request_id)
        assert found == req

    def test_get_request_wrong_tenant_returns_none(self):
        reg = _registry()
        tid_a, tid_b = uuid4(), uuid4()
        req = reg.create_request(
            tenant_id=tid_a,
            engagement_id=uuid4(),
            action_id=uuid4(),
            envelope_digest="sha256:abc",
            risk_tier="R2",
            requestor_id="alice",
        )
        assert reg.get_request(tid_b, req.request_id) is None

    def test_get_request_for_action(self):
        reg = _registry()
        tid = uuid4()
        aid = uuid4()
        req = reg.create_request(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=aid,
            envelope_digest="sha256:abc",
            risk_tier="R2",
            requestor_id="alice",
        )
        found = reg.get_request_for_action(tid, aid)
        assert found == req

    def test_get_request_for_unknown_action_returns_none(self):
        reg = _registry()
        assert reg.get_request_for_action(uuid4(), uuid4()) is None


class TestGrant:
    def test_grant_creates_decision(self):
        reg = _registry()
        tid = uuid4()
        aid = uuid4()
        reg.create_request(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=aid,
            envelope_digest="sha256:abc",
            risk_tier="R2",
            requestor_id="alice",
        )
        decision = reg.grant(tid, aid, "bob", reason="approved by security lead")
        assert decision.state == ApprovalState.GRANTED
        assert decision.approver_id == "bob"
        assert decision.binding_digest.startswith("sha256:")
        assert decision.reason == "approved by security lead"

    def test_grant_no_request_raises(self):
        reg = _registry()
        with pytest.raises(ApprovalRegistryError):
            reg.grant(uuid4(), uuid4(), "bob")

    def test_duplicate_grant_raises(self):
        reg = _registry()
        tid = uuid4()
        aid = uuid4()
        reg.create_request(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=aid,
            envelope_digest="sha256:abc",
            risk_tier="R2",
            requestor_id="alice",
        )
        reg.grant(tid, aid, "bob")
        with pytest.raises(DuplicateApprovalError):
            reg.grant(tid, aid, "charlie")

    def test_expired_request_cannot_be_granted(self):
        reg = _registry()
        tid = uuid4()
        aid = uuid4()
        reg.create_request(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=aid,
            envelope_digest="sha256:abc",
            risk_tier="R2",
            requestor_id="alice",
            expires_in=timedelta(seconds=-1),
        )
        with pytest.raises(ApprovalRegistryError, match="expired"):
            reg.grant(tid, aid, "bob")

    def test_two_person_rule_enforced(self):
        reg = _registry()
        tid = uuid4()
        aid = uuid4()
        reg.create_request(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=aid,
            envelope_digest="sha256:abc",
            risk_tier="R4",
            requestor_id="alice",
            requires_two_person=True,
        )
        with pytest.raises(TwoPersonRuleError):
            reg.grant(tid, aid, "alice")

    def test_two_person_rule_different_approver_ok(self):
        reg = _registry()
        tid = uuid4()
        aid = uuid4()
        reg.create_request(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=aid,
            envelope_digest="sha256:abc",
            risk_tier="R4",
            requestor_id="alice",
            requires_two_person=True,
        )
        decision = reg.grant(tid, aid, "bob")
        assert decision.state == ApprovalState.GRANTED


class TestDeny:
    def test_deny_creates_decision(self):
        reg = _registry()
        tid = uuid4()
        aid = uuid4()
        reg.create_request(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=aid,
            envelope_digest="sha256:abc",
            risk_tier="R2",
            requestor_id="alice",
        )
        decision = reg.deny(tid, aid, "bob", reason="too risky")
        assert decision.state == ApprovalState.DENIED
        assert decision.reason == "too risky"

    def test_deny_no_request_raises(self):
        reg = _registry()
        with pytest.raises(ApprovalRegistryError):
            reg.deny(uuid4(), uuid4(), "bob")

    def test_duplicate_deny_raises(self):
        reg = _registry()
        tid = uuid4()
        aid = uuid4()
        reg.create_request(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=aid,
            envelope_digest="sha256:abc",
            risk_tier="R2",
            requestor_id="alice",
        )
        reg.deny(tid, aid, "bob")
        with pytest.raises(DuplicateApprovalError):
            reg.deny(tid, aid, "charlie")


class TestIsApproved:
    def test_approved(self):
        reg = _registry()
        tid = uuid4()
        aid = uuid4()
        reg.create_request(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=aid,
            envelope_digest="sha256:abc",
            risk_tier="R2",
            requestor_id="alice",
        )
        reg.grant(tid, aid, "bob")
        assert reg.is_approved(tid, aid) is True

    def test_denied_not_approved(self):
        reg = _registry()
        tid = uuid4()
        aid = uuid4()
        reg.create_request(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=aid,
            envelope_digest="sha256:abc",
            risk_tier="R2",
            requestor_id="alice",
        )
        reg.deny(tid, aid, "bob")
        assert reg.is_approved(tid, aid) is False

    def test_no_decision_not_approved(self):
        reg = _registry()
        tid = uuid4()
        aid = uuid4()
        reg.create_request(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=aid,
            envelope_digest="sha256:abc",
            risk_tier="R2",
            requestor_id="alice",
        )
        assert reg.is_approved(tid, aid) is False

    def test_expired_grant_not_approved(self):
        reg = _registry()
        tid = uuid4()
        aid = uuid4()
        reg.create_request(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=aid,
            envelope_digest="sha256:abc",
            risk_tier="R2",
            requestor_id="alice",
            expires_in=timedelta(hours=4),
        )
        reg.grant(tid, aid, "bob")
        # manually expire the request by patching the expires_at
        request = reg.get_request_for_action(tid, aid)
        key = (tid, request.request_id)

        expired_req = ApprovalRequest(
            request_id=request.request_id,
            tenant_id=request.tenant_id,
            engagement_id=request.engagement_id,
            action_id=request.action_id,
            envelope_digest=request.envelope_digest,
            risk_tier=request.risk_tier,
            requestor_id=request.requestor_id,
            requires_two_person=request.requires_two_person,
            metadata=request.metadata,
            created_at=request.created_at,
            expires_at=request.created_at - timedelta(seconds=1),
        )
        reg._requests[key] = expired_req
        assert reg.is_approved(tid, aid) is False


class TestVerifyBinding:
    def test_valid_binding(self):
        reg = _registry()
        tid = uuid4()
        aid = uuid4()
        reg.create_request(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=aid,
            envelope_digest="sha256:abc",
            risk_tier="R2",
            requestor_id="alice",
        )
        decision = reg.grant(tid, aid, "bob")
        assert reg.verify_binding(tid, aid, "sha256:abc", decision.binding_digest) is True

    def test_wrong_envelope_rejected(self):
        reg = _registry()
        tid = uuid4()
        aid = uuid4()
        reg.create_request(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=aid,
            envelope_digest="sha256:abc",
            risk_tier="R2",
            requestor_id="alice",
        )
        decision = reg.grant(tid, aid, "bob")
        assert reg.verify_binding(tid, aid, "sha256:xyz", decision.binding_digest) is False

    def test_tampered_digest_rejected(self):
        reg = _registry()
        tid = uuid4()
        aid = uuid4()
        reg.create_request(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=aid,
            envelope_digest="sha256:abc",
            risk_tier="R2",
            requestor_id="alice",
        )
        reg.grant(tid, aid, "bob")
        assert reg.verify_binding(tid, aid, "sha256:abc", "sha256:tampered") is False

    def test_no_decision_rejected(self):
        reg = _registry()
        tid = uuid4()
        aid = uuid4()
        reg.create_request(
            tenant_id=tid,
            engagement_id=uuid4(),
            action_id=aid,
            envelope_digest="sha256:abc",
            risk_tier="R2",
            requestor_id="alice",
        )
        assert reg.verify_binding(tid, aid, "sha256:abc", "sha256:fake") is False


class TestPendingForEngagement:
    def test_returns_undecided(self):
        reg = _registry()
        tid = uuid4()
        eid = uuid4()
        aid1, aid2 = uuid4(), uuid4()
        reg.create_request(tid, eid, aid1, "sha256:1", "R2", "alice")
        reg.create_request(tid, eid, aid2, "sha256:2", "R2", "alice")
        reg.grant(tid, aid1, "bob")
        pending = reg.pending_for_engagement(tid, eid)
        ids = {r.action_id for r in pending}
        assert aid1 not in ids
        assert aid2 in ids

    def test_empty_when_all_decided(self):
        reg = _registry()
        tid = uuid4()
        eid = uuid4()
        aid = uuid4()
        reg.create_request(tid, eid, aid, "sha256:1", "R2", "alice")
        reg.grant(tid, aid, "bob")
        assert reg.pending_for_engagement(tid, eid) == []

    def test_different_engagement_not_included(self):
        reg = _registry()
        tid = uuid4()
        eid_a, eid_b = uuid4(), uuid4()
        aid_a, aid_b = uuid4(), uuid4()
        reg.create_request(tid, eid_a, aid_a, "sha256:a", "R2", "alice")
        reg.create_request(tid, eid_b, aid_b, "sha256:b", "R2", "alice")
        pending = reg.pending_for_engagement(tid, eid_a)
        ids = {r.action_id for r in pending}
        assert aid_a in ids
        assert aid_b not in ids
