"""Unit tests for the reversible-preference-update fixture technique (§14.2).

This technique exercises the state-changing / cleanup-verification path that
the BOLA module (mutation: none) does not. Confirmation is deterministic and
requires that the mutation took effect AND the original value was restored.
"""

from __future__ import annotations

import dataclasses
from uuid import uuid4

import pytest

from modules.web.workflow_preference import (
    TECHNIQUE_ID,
    ReversiblePreferenceUpdateModule,
)
from modules.web.workflow_preference import (
    module as pref_module,
)
from packages.module_sdk import (
    ConfirmationDecision,
    EligibilityDecision,
    ModuleContext,
    ModuleRunResult,
)

# ── Helpers ────────────────────────────────────────────────────────────────


def _ctx(
    *,
    identities: list[str] | None = None,
    endpoints: list[str] | None = None,
    target: str = "http://juice-shop:3000",
) -> ModuleContext:
    return ModuleContext(
        engagement_id=uuid4(),
        tenant_id=uuid4(),
        target_locator=target,
        metadata={
            "identities": identities or [],
            "endpoints": endpoints or [],
        },
    )


def _evidence(
    *,
    baseline_status: int = 200,
    baseline_value: str = "en",
    mutate_status: int = 200,
    verify_mutation_status: int = 200,
    mutated_value: str = "de",
    restore_status: int = 200,
    verify_restore_status: int = 200,
    restored_value: str = "en",
    evidence_digest: str = "sha256:" + "b" * 64,
    drop: str | None = None,
) -> dict:
    exchanges = [
        {"label": "read_baseline", "actual_status": baseline_status, "value": baseline_value},
        {"label": "mutate", "actual_status": mutate_status},
        {
            "label": "verify_mutation",
            "actual_status": verify_mutation_status,
            "value": mutated_value,
        },
        {"label": "restore", "actual_status": restore_status},
        {
            "label": "verify_restore",
            "actual_status": verify_restore_status,
            "value": restored_value,
        },
    ]
    if drop is not None:
        exchanges = [ex for ex in exchanges if ex["label"] != drop]
    return {"evidence_digest": evidence_digest, "exchanges": exchanges}


# ── Identity ─────────────────────────────────────────────────────────────────


class TestIdentity:
    def test_module_id(self):
        assert pref_module.MODULE_ID == "web.workflow.reversible_preference_update"

    def test_technique_id(self):
        assert pref_module.TECHNIQUE_ID == "web.workflow.reversible-preference-update"

    def test_risk_tier_r3(self):
        assert pref_module.RISK_TIER == "R3"

    def test_mutation_class_reversible(self):
        assert pref_module.MUTATION_CLASS == "reversible"

    def test_singleton_is_module_instance(self):
        assert isinstance(pref_module, ReversiblePreferenceUpdateModule)


# ── Eligibility ──────────────────────────────────────────────────────────────


class TestEligibility:
    def test_eligible_with_identity_and_preference_endpoint(self):
        ctx = _ctx(identities=["alice"], endpoints=["/rest/user/preferences"])
        result = pref_module.eligibility(ctx)
        assert result.decision == EligibilityDecision.ELIGIBLE

    def test_not_eligible_without_identity(self):
        ctx = _ctx(identities=[], endpoints=["/rest/user/preferences"])
        result = pref_module.eligibility(ctx)
        assert result.decision == EligibilityDecision.PREREQUISITE_MISSING
        assert "min_1_identity" in result.missing_prerequisites

    def test_not_eligible_without_preference_endpoint(self):
        ctx = _ctx(identities=["alice"], endpoints=["/rest/basket/{id}"])
        result = pref_module.eligibility(ctx)
        assert result.decision == EligibilityDecision.PREREQUISITE_MISSING
        assert "writable_preference_endpoint" in result.missing_prerequisites

    def test_eligible_with_settings_path(self):
        ctx = _ctx(identities=["alice"], endpoints=["/api/account/settings"])
        assert pref_module.eligibility(ctx).decision == EligibilityDecision.ELIGIBLE


# ── Proposals ─────────────────────────────────────────────────────────────────


class TestProposals:
    def test_one_proposal_per_endpoint(self):
        ctx = _ctx(identities=["alice"], endpoints=["/settings", "/profile"])
        proposals = pref_module.build_proposals(ctx)
        assert len(proposals) == 2

    def test_proposal_is_reversible_r3(self):
        ctx = _ctx(identities=["alice"], endpoints=["/settings"])
        p = pref_module.build_proposals(ctx)[0]
        assert p.risk_tier == "R3"
        assert p.mutation_class == "reversible"
        assert p.parameters["requires_cleanup"] is True

    def test_proposal_technique_id(self):
        ctx = _ctx(identities=["alice"], endpoints=["/settings"])
        assert pref_module.build_proposals(ctx)[0].technique_id == TECHNIQUE_ID

    def test_no_proposals_without_identity(self):
        ctx = _ctx(identities=[], endpoints=["/settings"])
        assert pref_module.build_proposals(ctx) == []

    def test_proposals_frozen(self):
        ctx = _ctx(identities=["alice"], endpoints=["/settings"])
        p = pref_module.build_proposals(ctx)[0]
        with pytest.raises(dataclasses.FrozenInstanceError):
            p.risk_tier = "R0"  # type: ignore[misc]


# ── Confirmation ──────────────────────────────────────────────────────────────


class TestConfirmation:
    def test_confirmed_full_reversible_cycle(self):
        result = pref_module.confirm(_evidence(), _ctx())
        assert result.is_confirmed
        assert result.decision == ConfirmationDecision.CONFIRMED
        assert result.capability_name == "reversible_state_write"
        assert result.metadata["cleanup_verified"] is True

    def test_confirmed_preserves_evidence_digest(self):
        result = pref_module.confirm(_evidence(evidence_digest="sha256:" + "c" * 64), _ctx())
        assert result.evidence_digest == "sha256:" + "c" * 64

    def test_refuted_when_cleanup_not_restored(self):
        # verify_restore returns a value that does NOT equal baseline → cleanup failed
        result = pref_module.confirm(_evidence(restored_value="de"), _ctx())
        assert result.decision == ConfirmationDecision.REFUTED
        assert "cleanup failed" in result.reason
        assert result.metadata["cleanup_verified"] is False
        assert result.capability_name is None

    def test_refuted_when_restore_write_fails(self):
        result = pref_module.confirm(_evidence(restore_status=500), _ctx())
        assert result.decision == ConfirmationDecision.REFUTED
        assert "restore failed" in result.reason
        assert result.metadata["cleanup_verified"] is False

    def test_refuted_when_baseline_read_fails(self):
        result = pref_module.confirm(_evidence(baseline_status=404), _ctx())
        assert result.decision == ConfirmationDecision.REFUTED
        assert "read_baseline failed" in result.reason

    def test_refuted_when_mutate_fails(self):
        result = pref_module.confirm(_evidence(mutate_status=403), _ctx())
        assert result.decision == ConfirmationDecision.REFUTED
        assert "mutate failed" in result.reason

    def test_inconclusive_when_mutation_had_no_effect(self):
        # mutated value equals baseline → write did not take effect
        result = pref_module.confirm(_evidence(mutated_value="en"), _ctx())
        assert result.decision == ConfirmationDecision.INCONCLUSIVE
        assert "did not take effect" in result.reason

    def test_inconclusive_when_exchange_missing(self):
        result = pref_module.confirm(_evidence(drop="restore"), _ctx())
        assert result.decision == ConfirmationDecision.INCONCLUSIVE
        assert "missing required exchanges" in result.reason

    def test_rule_version(self):
        result = pref_module.confirm(_evidence(), _ctx())
        assert result.rule_version == "1.0.0"


# ── Advisory run ──────────────────────────────────────────────────────────────


class TestRun:
    def test_run_finds_candidates(self):
        ctx = _ctx(
            identities=["alice"],
            endpoints=["/settings", "/rest/basket/{id}", "/profile"],
        )
        result = pref_module.run(ctx)
        assert isinstance(result, ModuleRunResult)
        assert result.metadata["candidates_found"] == 2

    def test_run_no_candidates(self):
        ctx = _ctx(identities=["alice"], endpoints=["/rest/basket/{id}"])
        result = pref_module.run(ctx)
        assert result.metadata["candidates_found"] == 0
        assert result.observations == []
