"""Contract tests for Pydantic v2 schemas.

Validates forwards-compatibility, spec-compliance, immutability,
strict-mode enforcement, and JSON round-trip fidelity for every
major contract in packages.contracts.schemas.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from packages.contracts.schemas.action_envelope import (
    ActionEnvelope,
    AttemptPolicy,
    EnvelopeSignature,
    RevisionDigests,
    TargetSpec,
)
from packages.contracts.schemas.common import (
    ActionState,
    BaseContract,
    CleanupState,
    DecisionOutcome,
    FindingState,
    HypothesisState,
    LifecycleState,
    MutationClass,
    ProvenanceClass,
    RiskTier,
    Sensitivity,
    ToolOutcome,
)
from packages.contracts.schemas.domain import (
    CleanupObligation,
    CostVector,
    Finding,
    Hypothesis,
    Observation,
)
from packages.contracts.schemas.engagement import (
    AuthorizationSpec,
    BudgetSpec,
    EngagementRevision,
    EngagementSpec,
    RulesSpec,
    ScopeRule,
    ScopeSpec,
)
from packages.contracts.schemas.events import (
    EventEnvelope,
    EventType,
)
from packages.contracts.schemas.evidence import (
    ArtifactRef,
    CaptureMetadata,
    EvidenceEnvelope,
    RedactionInfo,
)
from packages.contracts.schemas.policy import (
    PolicyDecision,
)
from packages.contracts.schemas.technique import (
    TechniqueManifest,
)

# ---------------------------------------------------------------------------
# Helpers -- reusable factory kwargs for constructing valid instances
# ---------------------------------------------------------------------------

_TS = datetime.now(timezone.utc)
_UUID = uuid4()


def _uuid():
    return uuid4()


def _sig():
    return EnvelopeSignature(alg="hmac-sha256", kid="key-1", value="deadbeef")


def _revisions():
    return RevisionDigests(
        auth_digest="sha256:" + "a" * 64,
        scope_digest="sha256:" + "b" * 64,
        policy_digest="sha256:" + "c" * 64,
    )


def _target():
    return TargetSpec(asset_id=_uuid(), locator="target.example.com")


def _action_envelope_kwargs(**overrides):
    kwargs = dict(
        action_id=_uuid(),
        action_digest="sha256:" + "d" * 64,
        tenant_id=_uuid(),
        engagement_revision_id=_uuid(),
        proposal_id=_uuid(),
        actor="agent:planner",
        revisions=_revisions(),
        technique="web.recon.port_scan",
        adapter="nmap",
        runner="runner-1",
        target=_target(),
        request_spec_digest="sha256:" + "e" * 64,
        effective_risk_tier=RiskTier.R1,
        mutation_class=MutationClass.none,
        expires_at=_TS,
        nonce="nonce-abc",
        idempotency_key="idem-1",
        signature=_sig(),
    )
    kwargs.update(overrides)
    return kwargs


def _artifact_ref():
    return ArtifactRef(
        digest="sha256:" + "f" * 64,
        size=1024,
        media_type="application/json",
        storage_uri="s3://bucket/key",
    )


def _capture_meta():
    return CaptureMetadata(
        tool="curl",
        tool_version="8.0",
        captured_at=_TS,
    )


def _evidence_envelope_kwargs(**overrides):
    kwargs = dict(
        evidence_id=_uuid(),
        tenant_id=_uuid(),
        engagement_revision_id=_uuid(),
        action_id=_uuid(),
        kind="http_transaction",
        artifact=_artifact_ref(),
        capture=_capture_meta(),
        signature="deadbeef",
    )
    kwargs.update(overrides)
    return kwargs


def _auth_spec():
    return AuthorizationSpec(
        artifact_digest="sha256:" + "a" * 64,
        issuer="ars:issuer",
        valid_from=_TS,
        valid_until=_TS,
    )


def _engagement_spec_kwargs(**overrides):
    kwargs = dict(
        authorization=_auth_spec(),
        scope=ScopeSpec(),
        rules=RulesSpec(),
        budgets=BudgetSpec(),
    )
    kwargs.update(overrides)
    return kwargs


def _event_envelope_kwargs(**overrides):
    kwargs = dict(
        event_id=_uuid(),
        event_type=EventType.ACTION_PROPOSED,
        tenant_id=_uuid(),
        aggregate_type="action",
        aggregate_id=_uuid(),
        aggregate_version=1,
        actor="agent:planner",
        occurred_at=_TS,
    )
    kwargs.update(overrides)
    return kwargs


def _policy_decision_kwargs(**overrides):
    kwargs = dict(
        decision_id=_uuid(),
        decision=DecisionOutcome.allow,
        risk_tier=RiskTier.R0,
        reason="low risk",
        version="1.0",
    )
    kwargs.update(overrides)
    return kwargs


def _technique_manifest_kwargs(**overrides):
    kwargs = dict(
        id="web.recon.port_scan",
        version="1.0.0",
        pack="recon",
        description="TCP port scan via nmap",
        risk_tier=RiskTier.R1,
        mutation=MutationClass.none,
    )
    kwargs.update(overrides)
    return kwargs


# ===================================================================
# 1. Frozen / immutability tests
# ===================================================================


class TestFrozenImmutability:
    """All BaseContract subclasses must reject field assignment."""

    def test_action_envelope_frozen(self):
        env = ActionEnvelope(**_action_envelope_kwargs())
        with pytest.raises(ValidationError):
            env.actor = "tampered"

    def test_evidence_envelope_frozen(self):
        ev = EvidenceEnvelope(**_evidence_envelope_kwargs())
        with pytest.raises(ValidationError):
            ev.kind = "tampered"

    def test_envelope_signature_frozen(self):
        sig = _sig()
        with pytest.raises(ValidationError):
            sig.value = "tampered"

    def test_scope_rule_frozen(self):
        rule = ScopeRule(type="cidr", value="10.0.0.0/8")
        with pytest.raises(ValidationError):
            rule.value = "tampered"

    def test_event_envelope_frozen(self):
        ev = EventEnvelope(**_event_envelope_kwargs())
        with pytest.raises(ValidationError):
            ev.actor = "tampered"

    def test_policy_decision_frozen(self):
        pd = PolicyDecision(**_policy_decision_kwargs())
        with pytest.raises(ValidationError):
            pd.reason = "tampered"

    def test_observation_frozen(self):
        obs = Observation(
            observation_id=_uuid(),
            typed_value={"port": 80},
            provenance=ProvenanceClass.OBSERVED,
            valid_time=_TS,
            observed_time=_TS,
            confidence=0.9,
        )
        with pytest.raises(ValidationError):
            obs.confidence = 0.1

    def test_technique_manifest_frozen(self):
        tm = TechniqueManifest(**_technique_manifest_kwargs())
        with pytest.raises(ValidationError):
            tm.version = "tampered"


# ===================================================================
# 2. Required field enforcement
# ===================================================================


class TestRequiredFields:
    """Major contracts must reject construction when required fields are missing."""

    @pytest.mark.parametrize(
        "field",
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
    def test_action_envelope_missing_required(self, field):
        kwargs = _action_envelope_kwargs()
        del kwargs[field]
        with pytest.raises(ValidationError):
            ActionEnvelope(**kwargs)

    @pytest.mark.parametrize(
        "field",
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
    def test_evidence_envelope_missing_required(self, field):
        kwargs = _evidence_envelope_kwargs()
        del kwargs[field]
        with pytest.raises(ValidationError):
            EvidenceEnvelope(**kwargs)

    @pytest.mark.parametrize(
        "field",
        [
            "event_id",
            "event_type",
            "tenant_id",
            "aggregate_type",
            "aggregate_id",
            "aggregate_version",
            "actor",
            "occurred_at",
        ],
    )
    def test_event_envelope_missing_required(self, field):
        kwargs = _event_envelope_kwargs()
        del kwargs[field]
        with pytest.raises(ValidationError):
            EventEnvelope(**kwargs)

    def test_authorization_spec_missing_issuer(self):
        with pytest.raises(ValidationError):
            AuthorizationSpec(
                artifact_digest="sha256:abc",
                valid_from=_TS,
                valid_until=_TS,
            )

    def test_policy_decision_missing_reason(self):
        kwargs = _policy_decision_kwargs()
        del kwargs["reason"]
        with pytest.raises(ValidationError):
            PolicyDecision(**kwargs)

    def test_technique_manifest_missing_id(self):
        kwargs = _technique_manifest_kwargs()
        del kwargs["id"]
        with pytest.raises(ValidationError):
            TechniqueManifest(**kwargs)


# ===================================================================
# 3. Enum strict-mode validation
# ===================================================================


class TestEnumStrictMode:
    """Strict mode must reject raw strings where an enum is expected."""

    def test_risk_tier_rejects_string(self):
        kwargs = _action_envelope_kwargs(effective_risk_tier="R1")
        with pytest.raises(ValidationError):
            ActionEnvelope(**kwargs)

    def test_mutation_class_rejects_string(self):
        kwargs = _action_envelope_kwargs(mutation_class="none")
        with pytest.raises(ValidationError):
            ActionEnvelope(**kwargs)

    def test_event_type_rejects_string(self):
        kwargs = _event_envelope_kwargs(event_type="action.proposed")
        with pytest.raises(ValidationError):
            EventEnvelope(**kwargs)

    def test_decision_outcome_rejects_string(self):
        kwargs = _policy_decision_kwargs(decision="allow")
        with pytest.raises(ValidationError):
            PolicyDecision(**kwargs)

    def test_sensitivity_rejects_string(self):
        kwargs = _evidence_envelope_kwargs(sensitivity="restricted")
        with pytest.raises(ValidationError):
            EvidenceEnvelope(**kwargs)

    def test_provenance_rejects_string(self):
        with pytest.raises(ValidationError):
            Observation(
                observation_id=_uuid(),
                typed_value={},
                provenance="OBSERVED",
                valid_time=_TS,
                observed_time=_TS,
                confidence=0.5,
            )

    def test_finding_state_rejects_string(self):
        with pytest.raises(ValidationError):
            Finding(
                finding_id=_uuid(),
                weakness="xss",
                affected_object="param",
                status="CANDIDATE",
                confidence=0.8,
                severity=5.0,
            )

    def test_hypothesis_state_rejects_string(self):
        with pytest.raises(ValidationError):
            Hypothesis(
                hypothesis_id=_uuid(),
                claim="test",
                rationale="test",
                confidence=0.5,
                status="OPEN",
            )


# ===================================================================
# 4. Type coercion rejection (strict mode)
# ===================================================================


class TestTypeCoercionRejection:
    """Strict mode must reject wrong types without coercing."""

    def test_int_where_str_expected(self):
        """actor field expects str; int must be rejected."""
        kwargs = _action_envelope_kwargs(actor=12345)
        with pytest.raises(ValidationError):
            ActionEnvelope(**kwargs)

    def test_str_where_int_expected(self):
        """aggregate_version expects int; str must be rejected."""
        kwargs = _event_envelope_kwargs(aggregate_version="1")
        with pytest.raises(ValidationError):
            EventEnvelope(**kwargs)

    def test_str_where_float_expected(self):
        """confidence expects float; str must be rejected."""
        with pytest.raises(ValidationError):
            Observation(
                observation_id=_uuid(),
                typed_value={},
                provenance=ProvenanceClass.OBSERVED,
                valid_time=_TS,
                observed_time=_TS,
                confidence="0.5",
            )

    def test_int_where_uuid_expected(self):
        """action_id expects UUID; int must be rejected."""
        kwargs = _action_envelope_kwargs(action_id=42)
        with pytest.raises(ValidationError):
            ActionEnvelope(**kwargs)

    def test_str_where_datetime_expected(self):
        """expires_at expects datetime; plain str must be rejected."""
        kwargs = _action_envelope_kwargs(expires_at="2025-01-01T00:00:00Z")
        with pytest.raises(ValidationError):
            ActionEnvelope(**kwargs)

    def test_float_where_int_expected_on_artifact_size(self):
        """ArtifactRef.size expects int; float must be rejected."""
        with pytest.raises(ValidationError):
            ArtifactRef(
                digest="sha256:abc",
                size=1024.5,
                media_type="application/json",
                storage_uri="s3://bucket/key",
            )

    def test_bool_where_str_expected(self):
        """technique field expects str; bool must be rejected."""
        kwargs = _action_envelope_kwargs(technique=True)
        with pytest.raises(ValidationError):
            ActionEnvelope(**kwargs)


# ===================================================================
# 5. JSON round-trip fidelity
# ===================================================================


class TestJsonRoundTrip:
    """model_dump_json() -> model_validate_json() must preserve all fields.

    Because BaseContract uses strict=True, the round-trip must go through
    the JSON serializer/deserializer path (not mode='json' dicts, which
    would produce plain strings that strict Python validation rejects).
    """

    def test_action_envelope_round_trip(self):
        original = ActionEnvelope(**_action_envelope_kwargs())
        json_str = original.model_dump_json()
        restored = ActionEnvelope.model_validate_json(json_str)
        assert restored == original

    def test_evidence_envelope_round_trip(self):
        original = EvidenceEnvelope(**_evidence_envelope_kwargs())
        json_str = original.model_dump_json()
        restored = EvidenceEnvelope.model_validate_json(json_str)
        assert restored == original

    def test_event_envelope_round_trip(self):
        original = EventEnvelope(**_event_envelope_kwargs())
        json_str = original.model_dump_json()
        restored = EventEnvelope.model_validate_json(json_str)
        assert restored == original

    def test_engagement_spec_round_trip(self):
        original = EngagementSpec(**_engagement_spec_kwargs())
        json_str = original.model_dump_json()
        restored = EngagementSpec.model_validate_json(json_str)
        assert restored == original

    def test_policy_decision_round_trip(self):
        original = PolicyDecision(**_policy_decision_kwargs())
        json_str = original.model_dump_json()
        restored = PolicyDecision.model_validate_json(json_str)
        assert restored == original

    def test_technique_manifest_round_trip(self):
        original = TechniqueManifest(**_technique_manifest_kwargs())
        json_str = original.model_dump_json()
        restored = TechniqueManifest.model_validate_json(json_str)
        assert restored == original

    def test_observation_round_trip(self):
        original = Observation(
            observation_id=_uuid(),
            typed_value={"port": 80, "state": "open"},
            provenance=ProvenanceClass.OBSERVED,
            valid_time=_TS,
            observed_time=_TS,
            confidence=0.95,
        )
        json_str = original.model_dump_json()
        restored = Observation.model_validate_json(json_str)
        assert restored == original

    def test_finding_round_trip(self):
        original = Finding(
            finding_id=_uuid(),
            weakness="SQL Injection",
            affected_object="/api/login",
            confidence=0.85,
            severity=9.1,
        )
        json_str = original.model_dump_json()
        restored = Finding.model_validate_json(json_str)
        assert restored == original

    def test_engagement_revision_round_trip(self):
        original = EngagementRevision(
            revision_id=_uuid(),
            engagement_id=_uuid(),
            revision_number=1,
            content_digest="sha256:" + "a" * 64,
            spec=EngagementSpec(**_engagement_spec_kwargs()),
            created_at=_TS,
            created_by="operator:admin",
        )
        json_str = original.model_dump_json()
        restored = EngagementRevision.model_validate_json(json_str)
        assert restored == original

    def test_cleanup_obligation_round_trip(self):
        original = CleanupObligation(
            obligation_id=_uuid(),
            inverse_action="remove_file",
            trigger="action_complete",
            deadline=_TS,
        )
        json_str = original.model_dump_json()
        restored = CleanupObligation.model_validate_json(json_str)
        assert restored == original


# ===================================================================
# 6. Schema version stability (deterministic JSON Schema)
# ===================================================================


class TestSchemaStability:
    """model_json_schema() output must be deterministic across calls."""

    @pytest.mark.parametrize(
        "model",
        [
            ActionEnvelope,
            EvidenceEnvelope,
            EventEnvelope,
            EngagementSpec,
            PolicyDecision,
            TechniqueManifest,
            Finding,
            Observation,
        ],
    )
    def test_json_schema_deterministic(self, model):
        schema_a = json.dumps(model.model_json_schema(), sort_keys=True)
        schema_b = json.dumps(model.model_json_schema(), sort_keys=True)
        assert schema_a == schema_b

    def test_json_schema_round_trip_via_json(self):
        """Serialize schema to JSON string, parse back, compare."""
        schema = ActionEnvelope.model_json_schema()
        serialized = json.dumps(schema, sort_keys=True)
        deserialized = json.loads(serialized)
        assert deserialized == schema


# ===================================================================
# 7. EventType enum completeness
# ===================================================================


class TestEventTypeCompleteness:
    """EventType must contain exactly 40 unique members."""

    def test_event_type_has_40_members(self):
        assert len(EventType) == 40

    def test_event_type_values_are_unique(self):
        values = [e.value for e in EventType]
        assert len(values) == len(set(values))

    def test_event_type_names_are_unique(self):
        names = [e.name for e in EventType]
        assert len(names) == len(set(names))

    def test_event_type_expected_categories(self):
        """Every expected domain category is represented."""
        values = {e.value for e in EventType}
        expected_prefixes = [
            "engagement.",
            "execution.",
            "action.",
            "evidence.",
            "finding.",
            "hypothesis.",
            "cleanup.",
            "policy.",
            "scope.",
            "budget.",
            "revocation.",
        ]
        for prefix in expected_prefixes:
            matching = [v for v in values if v.startswith(prefix)]
            assert len(matching) >= 1, f"No EventType with prefix '{prefix}'"


# ===================================================================
# 8. RiskTier ordering
# ===================================================================


class TestRiskTierOrdering:
    """RiskTier enum values must be lexicographically ordered R0 < R1 < ... < R5."""

    def test_risk_tier_value_ordering(self):
        tiers = list(RiskTier)
        for i in range(len(tiers) - 1):
            assert tiers[i].value < tiers[i + 1].value

    def test_risk_tier_has_six_levels(self):
        assert len(RiskTier) == 6

    def test_risk_tier_r0_is_lowest(self):
        assert RiskTier.R0.value == "R0"
        assert all(RiskTier.R0.value <= t.value for t in RiskTier)

    def test_risk_tier_r5_is_highest(self):
        assert RiskTier.R5.value == "R5"
        assert all(RiskTier.R5.value >= t.value for t in RiskTier)


# ===================================================================
# 9. State machine enum completeness
# ===================================================================


class TestStateEnumCompleteness:
    """Verify all state-machine enums have the expected number of members."""

    def test_action_state_has_16_values(self):
        assert len(ActionState) == 16

    def test_finding_state_has_10_values(self):
        assert len(FindingState) == 10

    def test_hypothesis_state_has_7_values(self):
        assert len(HypothesisState) == 7

    def test_cleanup_state_has_7_values(self):
        assert len(CleanupState) == 7

    def test_lifecycle_state_has_13_values(self):
        assert len(LifecycleState) == 13

    def test_mutation_class_has_4_values(self):
        assert len(MutationClass) == 4

    def test_decision_outcome_has_4_values(self):
        assert len(DecisionOutcome) == 4

    def test_sensitivity_has_4_values(self):
        assert len(Sensitivity) == 4

    def test_tool_outcome_has_11_values(self):
        assert len(ToolOutcome) == 11

    def test_provenance_class_has_4_values(self):
        assert len(ProvenanceClass) == 4

    def test_action_state_values_are_unique(self):
        values = [s.value for s in ActionState]
        assert len(values) == len(set(values))

    def test_finding_state_values_are_unique(self):
        values = [s.value for s in FindingState]
        assert len(values) == len(set(values))

    def test_action_state_expected_members(self):
        """Verify key terminal and intermediate states exist."""
        names = {s.name for s in ActionState}
        for expected in [
            "PROPOSED",
            "REJECTED",
            "APPROVAL_REQUIRED",
            "APPROVED",
            "DISPATCHED",
            "LEASED",
            "RUNNING",
            "SUCCEEDED",
            "FAILED",
            "TIMED_OUT",
            "CANCELLED",
            "UNKNOWN_REQUIRES_REVIEW",
            "EVIDENCE_ACCEPTED",
            "EVIDENCE_REJECTED",
            "CLEANUP_PENDING",
            "CLEANUP_VERIFIED",
        ]:
            assert expected in names, f"ActionState missing '{expected}'"


# ===================================================================
# Additional contract-level tests
# ===================================================================


class TestBaseContractConfig:
    """Verify BaseContract enforces strict + frozen via ConfigDict."""

    def test_strict_mode_enabled(self):
        assert BaseContract.model_config.get("strict") is True

    def test_frozen_mode_enabled(self):
        assert BaseContract.model_config.get("frozen") is True


class TestFieldConstraints:
    """Verify ge/le/gt Field constraints are enforced."""

    def test_artifact_ref_negative_size_rejected(self):
        with pytest.raises(ValidationError):
            ArtifactRef(
                digest="sha256:abc",
                size=-1,
                media_type="text/plain",
                storage_uri="s3://b/k",
            )

    def test_confidence_above_one_rejected(self):
        with pytest.raises(ValidationError):
            Finding(
                finding_id=_uuid(),
                weakness="xss",
                affected_object="param",
                confidence=1.5,
                severity=5.0,
            )

    def test_severity_above_ten_rejected(self):
        with pytest.raises(ValidationError):
            Finding(
                finding_id=_uuid(),
                weakness="xss",
                affected_object="param",
                confidence=0.5,
                severity=10.1,
            )

    def test_revision_number_zero_rejected(self):
        with pytest.raises(ValidationError):
            EngagementRevision(
                revision_id=_uuid(),
                engagement_id=_uuid(),
                revision_number=0,
                content_digest="sha256:abc",
                spec=EngagementSpec(**_engagement_spec_kwargs()),
                created_at=_TS,
                created_by="op",
            )

    def test_attempt_policy_max_attempts_zero_rejected(self):
        with pytest.raises(ValidationError):
            AttemptPolicy(max_attempts=0)

    def test_detection_risk_above_one_rejected(self):
        with pytest.raises(ValidationError):
            CostVector(detection_risk=1.5)


class TestDefaultValues:
    """Verify that optional fields with defaults resolve correctly."""

    def test_scope_spec_defaults(self):
        s = ScopeSpec()
        assert s.include == []
        assert s.exclude == []
        assert s.ports == []
        assert s.redirect_policy == "reject"

    def test_rules_spec_defaults(self):
        r = RulesSpec()
        assert r.mode == "autonomous"
        assert r.allowed_risk_tiers == []
        assert r.persistence == "ephemeral"

    def test_redaction_info_defaults(self):
        r = RedactionInfo()
        assert r.applied is False
        assert r.strategy is None
        assert r.fields_redacted == []

    def test_cost_vector_defaults(self):
        c = CostVector()
        assert c.time_seconds == 0
        assert c.complexity == 0
        assert c.privilege_required == "none"
        assert c.detection_risk == 0

    def test_evidence_envelope_default_sensitivity(self):
        ev = EvidenceEnvelope(**_evidence_envelope_kwargs())
        assert ev.sensitivity == Sensitivity.restricted

    def test_event_envelope_default_schema_version(self):
        ev = EventEnvelope(**_event_envelope_kwargs())
        assert ev.schema_version == "1.0"

    def test_engagement_revision_default_sensitivity(self):
        rev = EngagementRevision(
            revision_id=_uuid(),
            engagement_id=_uuid(),
            revision_number=1,
            content_digest="sha256:abc",
            spec=EngagementSpec(**_engagement_spec_kwargs()),
            created_at=_TS,
            created_by="op",
        )
        assert rev.sensitivity == Sensitivity.internal
