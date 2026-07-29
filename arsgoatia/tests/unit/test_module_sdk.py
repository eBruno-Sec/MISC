"""Unit tests for the module SDK base class and IDOR differential module."""
from __future__ import annotations

import dataclasses
from uuid import uuid4

import pytest

from packages.module_sdk import (
    ActionProposal,
    ConfirmationDecision,
    ConfirmationResult,
    EligibilityDecision,
    EligibilityResult,
    ModuleBase,
    ModuleContext,
    ModuleOutputError,
    ModuleRunResult,
)
from modules.web.authorization_idor import (
    IDORDifferentialModule,
    MODULE_ID,
    TECHNIQUE_ID,
    module as idor_module,
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
    baseline_status: int = 200,
    diff_status: int = 200,
    diff_body_object: bool = True,
    positive_status: int = 200,
    negative_status: int = 401,
    evidence_digest: str = "sha256:test-evidence",
) -> dict:
    return {
        "evidence_digest": evidence_digest,
        "exchanges": [
            {"label": "baseline_own",      "actual_status": baseline_status},
            {"label": "differential_cross", "actual_status": diff_status, "body_contains_object": diff_body_object},
            {"label": "positive_control",   "actual_status": positive_status},
            {"label": "negative_control",   "actual_status": negative_status},
        ],
    }


# ── Module SDK base ────────────────────────────────────────────────────────

class TestModuleSDKBase:
    def test_action_proposal_frozen(self):
        p = ActionProposal(technique_id="t", target_locator="http://test/")
        with pytest.raises(dataclasses.FrozenInstanceError):
            p.technique_id = "tampered"  # type: ignore[misc]

    def test_eligibility_result_frozen(self):
        r = EligibilityResult(decision=EligibilityDecision.ELIGIBLE)
        with pytest.raises(dataclasses.FrozenInstanceError):
            r.decision = EligibilityDecision.NOT_ELIGIBLE  # type: ignore[misc]

    def test_confirmation_result_frozen(self):
        r = ConfirmationResult(
            decision=ConfirmationDecision.CONFIRMED,
            reason="test",
            rule_version="1.0.0",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            r.decision = ConfirmationDecision.REFUTED  # type: ignore[misc]

    def test_module_context_frozen(self):
        ctx = _ctx()
        with pytest.raises(dataclasses.FrozenInstanceError):
            ctx.target_locator = "http://evil/"  # type: ignore[misc]

    def test_confirmation_result_is_confirmed_property(self):
        confirmed = ConfirmationResult(
            decision=ConfirmationDecision.CONFIRMED, reason="ok", rule_version="1.0.0"
        )
        assert confirmed.is_confirmed is True

        refuted = ConfirmationResult(
            decision=ConfirmationDecision.REFUTED, reason="no", rule_version="1.0.0"
        )
        assert refuted.is_confirmed is False

    def test_abstract_methods_required(self):
        class IncompleteModule(ModuleBase):
            MODULE_ID = "test"

        with pytest.raises(TypeError):
            IncompleteModule()  # type: ignore[abstract]

    def test_default_run_returns_empty_result(self):
        class MinimalModule(ModuleBase):
            MODULE_ID = "minimal"
            TECHNIQUE_ID = "test"

            def eligibility(self, ctx):
                return EligibilityResult(decision=EligibilityDecision.ELIGIBLE)

            def build_proposals(self, ctx):
                return []

            def confirm(self, evidence, ctx):
                return ConfirmationResult(
                    decision=ConfirmationDecision.CONFIRMED,
                    reason="ok",
                    rule_version="1.0.0",
                )

        m = MinimalModule()
        ctx = _ctx()
        result = m.run(ctx)
        assert isinstance(result, ModuleRunResult)
        assert result.observations == []

    def test_validate_output_catches_missing_keys(self):
        class MinimalModule(ModuleBase):
            MODULE_ID = "m"
            TECHNIQUE_ID = "t"

            def eligibility(self, ctx): ...
            def build_proposals(self, ctx): ...
            def confirm(self, evidence, ctx): ...

        m = MinimalModule()
        errors = m.validate_output({"module_id": "m"})
        assert any("technique_id" in e for e in errors)

    def test_validate_output_passes_complete(self):
        class MinimalModule(ModuleBase):
            MODULE_ID = "m"
            TECHNIQUE_ID = "t"

            def eligibility(self, ctx): ...
            def build_proposals(self, ctx): ...
            def confirm(self, evidence, ctx): ...

        m = MinimalModule()
        errors = m.validate_output({
            "module_id": "m", "technique_id": "t",
            "version": "1.0.0", "decision": "confirmed",
        })
        assert errors == []


# ── IDOR module identity ────────────────────────────────────────────────────

class TestIDORModuleIdentity:
    def test_module_id(self):
        assert idor_module.MODULE_ID == "web.authorization.idor.differential"

    def test_technique_id(self):
        assert idor_module.TECHNIQUE_ID == "web.authz.bola.differential"

    def test_risk_tier_r2(self):
        assert idor_module.RISK_TIER == "R2"

    def test_mutation_class_none(self):
        assert idor_module.MUTATION_CLASS == "none"

    def test_confirmation_rule_version(self):
        assert idor_module.CONFIRMATION_RULE_VERSION == "1.0.0"

    def test_singleton_is_module_instance(self):
        from modules.web.authorization_idor import module
        assert isinstance(module, IDORDifferentialModule)


# ── IDOR eligibility ────────────────────────────────────────────────────────

class TestIDOREligibility:
    def test_eligible_with_two_identities_and_basket(self):
        ctx = _ctx(
            identities=["alice", "bob"],
            endpoints=["/rest/user/login", "/rest/basket/{id}"],
        )
        result = idor_module.eligibility(ctx)
        assert result.decision == EligibilityDecision.ELIGIBLE

    def test_not_eligible_one_identity(self):
        ctx = _ctx(
            identities=["alice"],
            endpoints=["/rest/basket/{id}"],
        )
        result = idor_module.eligibility(ctx)
        assert result.decision == EligibilityDecision.PREREQUISITE_MISSING
        assert "min_2_identities" in result.missing_prerequisites

    def test_not_eligible_no_object_endpoint(self):
        ctx = _ctx(
            identities=["alice", "bob"],
            endpoints=["/rest/user/login", "/health"],
        )
        result = idor_module.eligibility(ctx)
        assert result.decision == EligibilityDecision.PREREQUISITE_MISSING
        assert "object_level_endpoint" in result.missing_prerequisites

    def test_not_eligible_empty_context(self):
        ctx = _ctx()
        result = idor_module.eligibility(ctx)
        assert result.decision != EligibilityDecision.ELIGIBLE

    def test_eligible_with_uuid_path(self):
        ctx = _ctx(
            identities=["alice", "bob"],
            endpoints=["/api/documents/{uuid}"],
        )
        result = idor_module.eligibility(ctx)
        assert result.decision == EligibilityDecision.ELIGIBLE

    def test_eligible_with_numeric_id(self):
        ctx = _ctx(
            identities=["alice", "bob"],
            endpoints=["/api/orders/42"],
        )
        result = idor_module.eligibility(ctx)
        assert result.decision == EligibilityDecision.ELIGIBLE

    def test_eligible_multiple_candidates_increases_confidence(self):
        ctx_one = _ctx(
            identities=["alice", "bob"],
            endpoints=["/rest/basket/{id}"],
        )
        ctx_many = _ctx(
            identities=["alice", "bob"],
            endpoints=["/rest/basket/{id}", "/rest/orders/{id}", "/api/files/{id}"],
        )
        r1 = idor_module.eligibility(ctx_one)
        r2 = idor_module.eligibility(ctx_many)
        assert r2.confidence >= r1.confidence


# ── IDOR proposals ──────────────────────────────────────────────────────────

class TestIDORProposals:
    def test_builds_one_proposal_per_endpoint(self):
        ctx = _ctx(
            identities=["alice", "bob"],
            endpoints=["/rest/basket/{id}", "/rest/orders/{id}"],
        )
        proposals = idor_module.build_proposals(ctx)
        assert len(proposals) == 2

    def test_proposal_technique_id(self):
        ctx = _ctx(
            identities=["alice", "bob"],
            endpoints=["/rest/basket/{id}"],
        )
        proposals = idor_module.build_proposals(ctx)
        assert proposals[0].technique_id == TECHNIQUE_ID

    def test_proposal_risk_tier_r2(self):
        ctx = _ctx(
            identities=["alice", "bob"],
            endpoints=["/rest/basket/{id}"],
        )
        proposals = idor_module.build_proposals(ctx)
        assert proposals[0].risk_tier == "R2"

    def test_proposal_mutation_class_none(self):
        ctx = _ctx(
            identities=["alice", "bob"],
            endpoints=["/rest/basket/{id}"],
        )
        proposals = idor_module.build_proposals(ctx)
        assert proposals[0].mutation_class == "none"

    def test_empty_proposals_without_identities(self):
        ctx = _ctx(identities=[], endpoints=["/rest/basket/{id}"])
        assert idor_module.build_proposals(ctx) == []

    def test_empty_proposals_without_object_endpoint(self):
        ctx = _ctx(identities=["alice", "bob"], endpoints=["/health"])
        assert idor_module.build_proposals(ctx) == []

    def test_proposal_target_includes_base_url(self):
        ctx = _ctx(
            identities=["alice", "bob"],
            endpoints=["/rest/basket/{id}"],
            target="http://juice-shop:3000",
        )
        proposals = idor_module.build_proposals(ctx)
        assert proposals[0].target_locator.startswith("http://juice-shop:3000")

    def test_proposals_are_frozen(self):
        ctx = _ctx(
            identities=["alice", "bob"],
            endpoints=["/rest/basket/{id}"],
        )
        proposals = idor_module.build_proposals(ctx)
        with pytest.raises(dataclasses.FrozenInstanceError):
            proposals[0].risk_tier = "R5"  # type: ignore[misc]


# ── IDOR confirmation ───────────────────────────────────────────────────────

class TestIDORConfirmation:
    def test_confirmed_bola_all_green(self):
        ctx = _ctx(identities=["alice", "bob"], endpoints=["/rest/basket/{id}"])
        result = idor_module.confirm(_evidence(), ctx)
        assert result.is_confirmed
        assert result.decision == ConfirmationDecision.CONFIRMED
        assert result.capability_name == "read_foreign_object"
        assert "CWE-639" in result.metadata.get("cwe", "")

    def test_refuted_when_differential_denies(self):
        ctx = _ctx(identities=["alice", "bob"], endpoints=["/rest/basket/{id}"])
        result = idor_module.confirm(_evidence(diff_status=403), ctx)
        assert result.decision == ConfirmationDecision.REFUTED
        assert "403" in result.reason

    def test_refuted_when_baseline_fails(self):
        ctx = _ctx(identities=["alice", "bob"], endpoints=["/rest/basket/{id}"])
        result = idor_module.confirm(_evidence(baseline_status=404), ctx)
        assert result.decision == ConfirmationDecision.REFUTED
        assert "baseline" in result.reason

    def test_refuted_when_positive_control_fails(self):
        ctx = _ctx(identities=["alice", "bob"], endpoints=["/rest/basket/{id}"])
        result = idor_module.confirm(_evidence(positive_status=401), ctx)
        assert result.decision == ConfirmationDecision.REFUTED
        assert "positive_control" in result.reason

    def test_refuted_when_negative_control_not_denied(self):
        ctx = _ctx(identities=["alice", "bob"], endpoints=["/rest/basket/{id}"])
        result = idor_module.confirm(_evidence(negative_status=200), ctx)
        assert result.decision == ConfirmationDecision.REFUTED
        assert "negative_control" in result.reason

    def test_inconclusive_when_differential_has_no_object(self):
        ctx = _ctx(identities=["alice", "bob"], endpoints=["/rest/basket/{id}"])
        result = idor_module.confirm(
            _evidence(diff_status=200, diff_body_object=False), ctx
        )
        assert result.decision == ConfirmationDecision.INCONCLUSIVE
        assert "owner-discriminating" in result.reason

    def test_inconclusive_missing_exchange(self):
        ctx = _ctx(identities=["alice", "bob"], endpoints=["/rest/basket/{id}"])
        incomplete = {"exchanges": [{"label": "baseline_own", "actual_status": 200}]}
        result = idor_module.confirm(incomplete, ctx)
        assert result.decision == ConfirmationDecision.INCONCLUSIVE
        assert "missing required exchanges" in result.reason

    def test_confirmation_preserves_evidence_digest(self):
        ctx = _ctx(identities=["alice", "bob"], endpoints=["/rest/basket/{id}"])
        result = idor_module.confirm(
            _evidence(evidence_digest="sha256:abc123"), ctx
        )
        assert result.is_confirmed
        assert result.evidence_digest == "sha256:abc123"

    def test_confirmation_rule_version_is_1_0_0(self):
        ctx = _ctx(identities=["alice", "bob"], endpoints=["/rest/basket/{id}"])
        result = idor_module.confirm(_evidence(), ctx)
        assert result.rule_version == "1.0.0"

    def test_confirmation_metadata_includes_technique(self):
        ctx = _ctx(identities=["alice", "bob"], endpoints=["/rest/basket/{id}"])
        result = idor_module.confirm(_evidence(), ctx)
        assert result.metadata["technique_id"] == TECHNIQUE_ID

    def test_confirmation_metadata_includes_owasp(self):
        ctx = _ctx(identities=["alice", "bob"], endpoints=["/rest/basket/{id}"])
        result = idor_module.confirm(_evidence(), ctx)
        assert result.metadata["owasp"] == "API1:2023"

    def test_403_negative_control_also_accepted(self):
        ctx = _ctx(identities=["alice", "bob"], endpoints=["/rest/basket/{id}"])
        result = idor_module.confirm(_evidence(negative_status=403), ctx)
        assert result.is_confirmed


# ── IDOR advisory run ───────────────────────────────────────────────────────

class TestIDORRun:
    def test_run_finds_candidates(self):
        ctx = _ctx(
            identities=["alice", "bob"],
            endpoints=["/rest/basket/{id}", "/rest/user/login", "/rest/orders/{id}"],
        )
        result = idor_module.run(ctx)
        assert isinstance(result, ModuleRunResult)
        assert result.metadata["candidates_found"] == 2
        labels = {o["type"] for o in result.observations}
        assert "candidate_object_endpoint" in labels

    def test_run_no_candidates(self):
        ctx = _ctx(
            identities=["alice", "bob"],
            endpoints=["/rest/user/login", "/health"],
        )
        result = idor_module.run(ctx)
        assert result.metadata["candidates_found"] == 0
        assert result.observations == []

    def test_run_module_id(self):
        ctx = _ctx()
        result = idor_module.run(ctx)
        assert result.module_id == MODULE_ID
