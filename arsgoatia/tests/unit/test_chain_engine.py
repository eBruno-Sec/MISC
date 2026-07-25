"""Attack-chain construction + versioned (non-CVSS) severity (§19, ADR 0005)."""

from __future__ import annotations

from chain.engine import (
    CHAIN_SEVERITY_VERSION,
    build_capability_transition,
    build_chain_step,
    chain_severity,
)


def test_chain_severity_is_versioned_and_not_cvss():
    label, rationale = chain_severity(
        validated_step_count=1,
        capabilities_gained=["read_foreign_object"],
        crosses_identity_boundary=True,
        reaches_sensitive_data=True,
    )
    assert label in {"medium", "high", "critical"}
    assert rationale["not_cvss"] is True
    assert rationale["method_version"] == CHAIN_SEVERITY_VERSION


def test_chain_severity_scales_with_impact():
    low, _ = chain_severity(
        validated_step_count=0,
        capabilities_gained=[],
        crosses_identity_boundary=False,
        reaches_sensitive_data=False,
    )
    high, _ = chain_severity(
        validated_step_count=3,
        capabilities_gained=["a", "b"],
        crosses_identity_boundary=True,
        reaches_sensitive_data=True,
    )
    assert low == "informational"
    assert high == "critical"


def test_build_chain_step_and_transition_shape():
    step = build_chain_step(
        attack_chain_id="chain-1",
        sequence_number=1,
        prerequisite_capability_ids=[],
        source_context_id="ctx-1",
        action_execution_id=None,
        finding_id="f-1",
        resulting_capability_ids=["cap-1"],
        evidence_refs=["e1"],
    )
    assert step["sequence_number"] == 1
    assert step["resulting_capability_ids"] == ["cap-1"]
    assert step["validation_state"] == "validated"

    tr = build_capability_transition(
        source_context_id="ctx-1",
        prerequisite_capability_ids=[],
        action_execution_id=None,
        finding_id="f-1",
        resulting_capability_ids=["cap-1"],
        resulting_context_ids=["ctx-1"],
        evidence_refs=["e1"],
    )
    assert tr["resulting_capability_ids"] == ["cap-1"]
    assert tr["validation_state"] == "validated"
