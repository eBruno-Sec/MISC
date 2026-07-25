"""Attack-chain construction + severity (§19).

Each chain step declares prerequisite capabilities, source context, action,
finding, resulting capabilities/contexts, evidence, and validation state. Chain
severity is a versioned ArsGoatia method — deliberately NOT CVSS — combining
blast radius, capability escalation, and validated-step count.

Pure functions so construction and scoring are reproducible and unit-testable.
"""

from __future__ import annotations

CHAIN_SEVERITY_VERSION = "1.0.0"

_SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]


def build_capability_transition(
    *,
    source_context_id: str,
    prerequisite_capability_ids: list[str],
    action_execution_id: str | None,
    finding_id: str | None,
    resulting_capability_ids: list[str],
    resulting_context_ids: list[str] | None = None,
    evidence_refs: list[str] | None = None,
) -> dict:
    return {
        "source_context_id": source_context_id,
        "prerequisite_capability_ids": prerequisite_capability_ids,
        "action_execution_id": action_execution_id,
        "finding_id": finding_id,
        "resulting_capability_ids": resulting_capability_ids,
        "resulting_context_ids": resulting_context_ids or [],
        "validation_state": "validated",
        "evidence_refs": evidence_refs or [],
    }


def build_chain_step(
    *,
    attack_chain_id: str,
    sequence_number: int,
    prerequisite_capability_ids: list[str],
    source_context_id: str,
    action_execution_id: str | None,
    finding_id: str | None,
    resulting_capability_ids: list[str],
    resulting_context_ids: list[str] | None = None,
    evidence_refs: list[str] | None = None,
) -> dict:
    return {
        "attack_chain_id": attack_chain_id,
        "sequence_number": sequence_number,
        "prerequisite_capability_ids": prerequisite_capability_ids,
        "source_context_id": source_context_id,
        "action_execution_id": action_execution_id,
        "finding_id": finding_id,
        "resulting_capability_ids": resulting_capability_ids,
        "resulting_context_ids": resulting_context_ids or [],
        "evidence_refs": evidence_refs or [],
        "validation_state": "validated",
    }


def chain_severity(
    *,
    validated_step_count: int,
    capabilities_gained: list[str],
    crosses_identity_boundary: bool,
    reaches_sensitive_data: bool,
) -> tuple[str, dict]:
    """Versioned, non-CVSS chain severity (ADR 0005). Returns (label, rationale)."""
    blast_radius = (2 if reaches_sensitive_data else 0) + (2 if crosses_identity_boundary else 0)
    escalation = len({c for c in capabilities_gained})
    steps = max(0, validated_step_count)
    raw = blast_radius + escalation + steps

    if raw >= 6:
        label = "critical"
    elif raw >= 4:
        label = "high"
    elif raw >= 2:
        label = "medium"
    elif raw >= 1:
        label = "low"
    else:
        label = "informational"

    rationale = {
        "method_version": CHAIN_SEVERITY_VERSION,
        "not_cvss": True,
        "blast_radius": blast_radius,
        "capability_escalation": escalation,
        "validated_steps": steps,
        "raw_score": raw,
    }
    return label, rationale
