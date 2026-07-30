"""Unit tests for the capability registry."""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest

from packages.capability import (
    CAPABILITY_TRANSITIONS,
    CapabilityError,
    CapabilityRecord,
    CapabilityRegistry,
    CapabilityState,
    EvidenceRequiredError,
    FindingNotConfirmedError,
    InvalidTransitionError,
)

_GOOD_DIGESTS = frozenset({"sha256:abc123", "sha256:def456"})


def _emit(
    registry: CapabilityRegistry,
    tenant_id=None,
    engagement_id=None,
    name="read_foreign_object",
    finding_state="confirmed",
    evidence_digests=None,
) -> CapabilityRecord:
    tid = tenant_id or uuid4()
    eid = engagement_id or uuid4()
    return registry.emit(
        tenant_id=tid,
        engagement_id=eid,
        name=name,
        description="Can read objects owned by other users",
        finding_id=uuid4(),
        evidence_digests=_GOOD_DIGESTS if evidence_digests is None else evidence_digests,
        technique_id="web.authz.bola.differential",
        target_locator="http://juice-shop:3000/rest/basket/1",
        finding_state=finding_state,
    )


class TestCapabilityTransitions:
    def test_discovered_to_proven(self):
        assert CapabilityState.PROVEN in CAPABILITY_TRANSITIONS[CapabilityState.DISCOVERED]

    def test_proven_to_expired(self):
        assert CapabilityState.EXPIRED in CAPABILITY_TRANSITIONS[CapabilityState.PROVEN]

    def test_terminal_states_empty(self):
        assert len(CAPABILITY_TRANSITIONS[CapabilityState.EXPIRED]) == 0
        assert len(CAPABILITY_TRANSITIONS[CapabilityState.SUPERSEDED]) == 0


class TestEmit:
    def test_emits_proven_capability(self):
        reg = CapabilityRegistry()
        cap = _emit(reg)
        assert cap.state == CapabilityState.PROVEN
        assert cap.name == "read_foreign_object"
        assert cap.evidence_digests == _GOOD_DIGESTS

    def test_unconfirmed_finding_raises(self):
        reg = CapabilityRegistry()
        with pytest.raises(FindingNotConfirmedError):
            _emit(reg, finding_state="pending")

    def test_open_finding_raises(self):
        reg = CapabilityRegistry()
        with pytest.raises(FindingNotConfirmedError):
            _emit(reg, finding_state="open")

    def test_empty_evidence_raises(self):
        reg = CapabilityRegistry()
        with pytest.raises(EvidenceRequiredError):
            _emit(reg, evidence_digests=frozenset())

    def test_non_sha256_digest_raises(self):
        reg = CapabilityRegistry()
        with pytest.raises(EvidenceRequiredError, match="sha256"):
            _emit(reg, evidence_digests=frozenset({"md5:abc123"}))

    def test_capability_frozen(self):
        reg = CapabilityRegistry()
        cap = _emit(reg)
        with pytest.raises((AttributeError, TypeError)):
            cap.name = "modified"  # type: ignore[misc]

    def test_unique_ids_per_emit(self):
        reg = CapabilityRegistry()
        tid = uuid4()
        eid = uuid4()
        c1 = _emit(reg, tenant_id=tid, engagement_id=eid)
        c2 = _emit(reg, tenant_id=tid, engagement_id=eid)
        assert c1.capability_id != c2.capability_id

    def test_expires_at_set(self):
        reg = CapabilityRegistry()
        cap = reg.emit(
            tenant_id=uuid4(),
            engagement_id=uuid4(),
            name="cap",
            description="d",
            finding_id=uuid4(),
            evidence_digests=_GOOD_DIGESTS,
            technique_id="t",
            target_locator="http://x",
            finding_state="confirmed",
            expires_in=timedelta(days=90),
        )
        assert cap.expires_at is not None

    def test_no_expiry_by_default(self):
        reg = CapabilityRegistry()
        cap = _emit(reg)
        assert cap.expires_at is None


class TestGet:
    def test_get_by_id(self):
        reg = CapabilityRegistry()
        tid = uuid4()
        cap = _emit(reg, tenant_id=tid)
        found = reg.get(tid, cap.capability_id)
        assert found == cap

    def test_get_wrong_tenant_returns_none(self):
        reg = CapabilityRegistry()
        tid_a, tid_b = uuid4(), uuid4()
        cap = _emit(reg, tenant_id=tid_a)
        assert reg.get(tid_b, cap.capability_id) is None

    def test_get_unknown_returns_none(self):
        reg = CapabilityRegistry()
        assert reg.get(uuid4(), uuid4()) is None


class TestTransition:
    def test_proven_to_expired(self):
        reg = CapabilityRegistry()
        tid = uuid4()
        cap = _emit(reg, tenant_id=tid)
        updated = reg.transition(tid, cap.capability_id, CapabilityState.EXPIRED, "TTL reached")
        assert updated.state == CapabilityState.EXPIRED

    def test_proven_to_superseded(self):
        reg = CapabilityRegistry()
        tid = uuid4()
        cap = _emit(reg, tenant_id=tid)
        new_cap = _emit(reg, tenant_id=tid)
        updated = reg.transition(
            tid,
            cap.capability_id,
            CapabilityState.SUPERSEDED,
            superseded_by=new_cap.capability_id,
        )
        assert updated.state == CapabilityState.SUPERSEDED
        assert updated.superseded_by == new_cap.capability_id

    def test_invalid_transition_raises(self):
        reg = CapabilityRegistry()
        tid = uuid4()
        cap = _emit(reg, tenant_id=tid)
        reg.transition(tid, cap.capability_id, CapabilityState.EXPIRED)
        with pytest.raises(InvalidTransitionError):
            reg.transition(tid, cap.capability_id, CapabilityState.PROVEN)

    def test_unknown_capability_raises(self):
        reg = CapabilityRegistry()
        with pytest.raises(CapabilityError):
            reg.transition(uuid4(), uuid4(), CapabilityState.EXPIRED)

    def test_transition_records_history(self):
        reg = CapabilityRegistry()
        tid = uuid4()
        cap = _emit(reg, tenant_id=tid)
        reg.transition(tid, cap.capability_id, CapabilityState.EXPIRED, reason="TTL")
        history = reg.transitions_for(cap.capability_id)
        assert len(history) == 1
        assert history[0].reason == "TTL"
        assert history[0].from_state == CapabilityState.PROVEN
        assert history[0].to_state == CapabilityState.EXPIRED

    def test_multiple_transitions_recorded(self):
        reg = CapabilityRegistry()
        tid = uuid4()
        cap = reg.emit(
            tenant_id=tid,
            engagement_id=uuid4(),
            name="cap",
            description="d",
            finding_id=uuid4(),
            evidence_digests=_GOOD_DIGESTS,
            technique_id="t",
            target_locator="http://x",
            finding_state="confirmed",
            initial_state=CapabilityState.DISCOVERED,
        )
        reg.transition(tid, cap.capability_id, CapabilityState.PROVEN, "verified")
        reg.transition(tid, cap.capability_id, CapabilityState.EXPIRED, "TTL")
        history = reg.transitions_for(cap.capability_id)
        assert len(history) == 2


class TestIsActive:
    def test_proven_is_active(self):
        reg = CapabilityRegistry()
        tid = uuid4()
        cap = _emit(reg, tenant_id=tid)
        assert reg.is_active(tid, cap.capability_id) is True

    def test_expired_not_active(self):
        reg = CapabilityRegistry()
        tid = uuid4()
        cap = _emit(reg, tenant_id=tid)
        reg.transition(tid, cap.capability_id, CapabilityState.EXPIRED)
        assert reg.is_active(tid, cap.capability_id) is False

    def test_superseded_not_active(self):
        reg = CapabilityRegistry()
        tid = uuid4()
        cap = _emit(reg, tenant_id=tid)
        reg.transition(tid, cap.capability_id, CapabilityState.SUPERSEDED)
        assert reg.is_active(tid, cap.capability_id) is False

    def test_unknown_not_active(self):
        reg = CapabilityRegistry()
        assert reg.is_active(uuid4(), uuid4()) is False

    def test_past_expires_at_not_active(self):
        reg = CapabilityRegistry()
        tid = uuid4()
        cap = reg.emit(
            tenant_id=tid,
            engagement_id=uuid4(),
            name="cap",
            description="d",
            finding_id=uuid4(),
            evidence_digests=_GOOD_DIGESTS,
            technique_id="t",
            target_locator="http://x",
            finding_state="confirmed",
            expires_in=timedelta(seconds=-1),
        )
        assert reg.is_active(tid, cap.capability_id) is False


class TestListForEngagement:
    def test_returns_all_for_engagement(self):
        reg = CapabilityRegistry()
        tid = uuid4()
        eid = uuid4()
        c1 = _emit(reg, tenant_id=tid, engagement_id=eid)
        c2 = _emit(reg, tenant_id=tid, engagement_id=eid, name="write_object")
        c3 = _emit(reg, tenant_id=tid)  # different engagement
        result = reg.list_for_engagement(tid, eid)
        ids = {r.capability_id for r in result}
        assert c1.capability_id in ids
        assert c2.capability_id in ids
        assert c3.capability_id not in ids

    def test_active_only_filter(self):
        reg = CapabilityRegistry()
        tid = uuid4()
        eid = uuid4()
        c1 = _emit(reg, tenant_id=tid, engagement_id=eid)
        c2 = _emit(reg, tenant_id=tid, engagement_id=eid, name="write_object")
        reg.transition(tid, c2.capability_id, CapabilityState.EXPIRED)
        active = reg.list_for_engagement(tid, eid, active_only=True)
        ids = {r.capability_id for r in active}
        assert c1.capability_id in ids
        assert c2.capability_id not in ids

    def test_wrong_tenant_excluded(self):
        reg = CapabilityRegistry()
        tid_a, tid_b = uuid4(), uuid4()
        eid = uuid4()
        _emit(reg, tenant_id=tid_a, engagement_id=eid)
        assert reg.list_for_engagement(tid_b, eid) == []


class TestFindByName:
    def test_finds_active(self):
        reg = CapabilityRegistry()
        tid = uuid4()
        eid = uuid4()
        cap = _emit(reg, tenant_id=tid, engagement_id=eid, name="read_foreign_object")
        results = reg.find_by_name(tid, eid, "read_foreign_object")
        assert any(r.capability_id == cap.capability_id for r in results)

    def test_does_not_find_expired_when_active_only(self):
        reg = CapabilityRegistry()
        tid = uuid4()
        eid = uuid4()
        cap = _emit(reg, tenant_id=tid, engagement_id=eid)
        reg.transition(tid, cap.capability_id, CapabilityState.EXPIRED)
        assert reg.find_by_name(tid, eid, "read_foreign_object") == []

    def test_finds_expired_when_not_active_only(self):
        reg = CapabilityRegistry()
        tid = uuid4()
        eid = uuid4()
        cap = _emit(reg, tenant_id=tid, engagement_id=eid)
        reg.transition(tid, cap.capability_id, CapabilityState.EXPIRED)
        results = reg.find_by_name(tid, eid, "read_foreign_object", active_only=False)
        assert any(r.capability_id == cap.capability_id for r in results)

    def test_empty_for_unknown_name(self):
        reg = CapabilityRegistry()
        tid = uuid4()
        eid = uuid4()
        _emit(reg, tenant_id=tid, engagement_id=eid)
        assert reg.find_by_name(tid, eid, "unknown_cap") == []


class TestHasCapability:
    def test_true_when_active_exists(self):
        reg = CapabilityRegistry()
        tid = uuid4()
        eid = uuid4()
        _emit(reg, tenant_id=tid, engagement_id=eid, name="read_foreign_object")
        assert reg.has_capability(tid, eid, "read_foreign_object") is True

    def test_false_when_none(self):
        reg = CapabilityRegistry()
        tid = uuid4()
        eid = uuid4()
        assert reg.has_capability(tid, eid, "read_foreign_object") is False

    def test_false_after_expiry(self):
        reg = CapabilityRegistry()
        tid = uuid4()
        eid = uuid4()
        cap = _emit(reg, tenant_id=tid, engagement_id=eid)
        reg.transition(tid, cap.capability_id, CapabilityState.EXPIRED)
        assert reg.has_capability(tid, eid, "read_foreign_object") is False
