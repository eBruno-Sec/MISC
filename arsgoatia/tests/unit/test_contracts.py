from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from packages.contracts.schemas.action_envelope import (
    ActionEnvelope,
    EnvelopeSignature,
    RevisionDigests,
    TargetSpec,
)
from packages.contracts.schemas.common import (
    ActionState,
    DecisionOutcome,
    MutationClass,
    RiskTier,
    Sensitivity,
)
from packages.contracts.schemas.evidence import ArtifactRef, CaptureMetadata, EvidenceEnvelope
from packages.crypto import canonical_json

# ---------------------------------------------------------------------------
# Enum value checks
# ---------------------------------------------------------------------------


def test_risk_tier_values():
    assert {t.value for t in RiskTier} == {"R0", "R1", "R2", "R3", "R4", "R5"}


def test_mutation_class_values():
    assert {m.value for m in MutationClass} == {
        "none",
        "reversible",
        "state_changing",
        "destructive",
    }


def test_decision_outcome_values():
    assert {d.value for d in DecisionOutcome} == {
        "allow",
        "allow_with_limits",
        "require_approval",
        "deny",
    }


def test_sensitivity_values():
    assert {s.value for s in Sensitivity} == {
        "public",
        "internal",
        "restricted",
        "confidential",
    }


def test_action_state_includes_terminal_and_evidence_states():
    values = {s.value for s in ActionState}
    for expected in ("PROPOSED", "SUCCEEDED", "FAILED", "EVIDENCE_ACCEPTED", "EVIDENCE_REJECTED"):
        assert expected in values


# ---------------------------------------------------------------------------
# ActionEnvelope required fields
# ---------------------------------------------------------------------------


def _action_envelope_kwargs(**overrides):
    kwargs = dict(
        action_id=uuid4(),
        action_digest="sha256:" + "a" * 64,
        tenant_id=uuid4(),
        engagement_revision_id=uuid4(),
        proposal_id=uuid4(),
        actor="agent:planner",
        revisions=RevisionDigests(
            auth_digest="sha256:" + "b" * 64,
            scope_digest="sha256:" + "c" * 64,
            policy_digest="sha256:" + "d" * 64,
        ),
        technique="web.recon.port_scan",
        adapter="nmap",
        runner="runner-1",
        target=TargetSpec(asset_id=uuid4(), locator="target.test"),
        request_spec_digest="sha256:" + "e" * 64,
        effective_risk_tier=RiskTier.R1,
        mutation_class=MutationClass.none,
        expires_at=datetime.now(timezone.utc),
        nonce="abc123",
        idempotency_key="idem-1",
        signature=EnvelopeSignature(alg="hmac-sha256", kid="key-1", value="deadbeef"),
    )
    kwargs.update(overrides)
    return kwargs


def test_action_envelope_valid_construction():
    env = ActionEnvelope(**_action_envelope_kwargs())
    assert env.effective_risk_tier == RiskTier.R1
    assert env.mutation_class == MutationClass.none


@pytest.mark.parametrize(
    "missing_field",
    [
        "action_id",
        "action_digest",
        "tenant_id",
        "engagement_revision_id",
        "proposal_id",
        "actor",
        "revisions",
        "technique",
        "adapter",
        "runner",
        "target",
        "request_spec_digest",
        "effective_risk_tier",
        "mutation_class",
        "expires_at",
        "nonce",
        "idempotency_key",
        "signature",
    ],
)
def test_action_envelope_missing_required_field_raises(missing_field):
    kwargs = _action_envelope_kwargs()
    del kwargs[missing_field]
    with pytest.raises(ValidationError):
        ActionEnvelope(**kwargs)


# ---------------------------------------------------------------------------
# EvidenceEnvelope required fields
# ---------------------------------------------------------------------------


def _evidence_envelope_kwargs(**overrides):
    kwargs = dict(
        evidence_id=uuid4(),
        tenant_id=uuid4(),
        engagement_revision_id=uuid4(),
        action_id=uuid4(),
        kind="http_transaction",
        artifact=ArtifactRef(
            digest="sha256:" + "a" * 64,
            size=128,
            media_type="application/json",
            storage_uri="s3://bucket/key",
        ),
        capture=CaptureMetadata(
            tool="curl",
            tool_version="8.0",
            captured_at=datetime.now(timezone.utc),
        ),
        signature="deadbeef",
    )
    kwargs.update(overrides)
    return kwargs


def test_evidence_envelope_valid_construction():
    ev = EvidenceEnvelope(**_evidence_envelope_kwargs())
    assert ev.sensitivity == Sensitivity.restricted  # default applies


@pytest.mark.parametrize(
    "missing_field",
    [
        "evidence_id",
        "tenant_id",
        "engagement_revision_id",
        "action_id",
        "kind",
        "artifact",
        "capture",
        "signature",
    ],
)
def test_evidence_envelope_missing_required_field_raises(missing_field):
    kwargs = _evidence_envelope_kwargs()
    del kwargs[missing_field]
    with pytest.raises(ValidationError):
        EvidenceEnvelope(**kwargs)


# ---------------------------------------------------------------------------
# Frozen / immutable contracts
# ---------------------------------------------------------------------------


def test_action_envelope_is_frozen():
    env = ActionEnvelope(**_action_envelope_kwargs())
    with pytest.raises(ValidationError):
        env.action_id = uuid4()


def test_evidence_envelope_is_frozen():
    ev = EvidenceEnvelope(**_evidence_envelope_kwargs())
    with pytest.raises(ValidationError):
        ev.kind = "other"


def test_nested_contract_is_frozen():
    sig = EnvelopeSignature(alg="hmac-sha256", kid="key-1", value="deadbeef")
    with pytest.raises(ValidationError):
        sig.value = "tampered"


# ---------------------------------------------------------------------------
# canonical_json determinism edge cases
# ---------------------------------------------------------------------------


def test_canonical_json_empty_dict_and_list():
    assert canonical_json({}) == b"{}"
    assert canonical_json([]) == b"[]"


def test_canonical_json_unicode_is_ascii_escaped_and_deterministic():
    payload = {"name": "héllo wörld 日本語"}
    a = canonical_json(payload)
    b = canonical_json(dict(payload))
    assert a == b
    # ensure_ascii=True means the raw multi-byte characters never appear
    assert "é".encode() not in a
    assert b"\\u00e9" in a


def test_canonical_json_nested_structures_sorted_regardless_of_input_order():
    a = canonical_json({"z": 1, "a": {"y": [3, 2, 1], "b": 4}})
    b = canonical_json({"a": {"b": 4, "y": [3, 2, 1]}, "z": 1})
    assert a == b


def test_canonical_json_key_order_independent_at_all_levels():
    first = {"outer": {"inner_b": 2, "inner_a": 1}, "top_z": True}
    second = {"top_z": True, "outer": {"inner_a": 1, "inner_b": 2}}
    assert canonical_json(first) == canonical_json(second)


def test_canonical_json_scalars():
    assert canonical_json(None) == b"null"
    assert canonical_json(True) == b"true"
    assert canonical_json(123) == b"123"
    assert canonical_json("plain") == b'"plain"'


def test_canonical_json_no_whitespace():
    out = canonical_json({"a": 1, "b": [1, 2, 3]})
    assert b" " not in out
