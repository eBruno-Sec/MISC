from __future__ import annotations

from packages.contracts.schemas.common import MutationClass, RiskTier
from packages.techniques import (
    BOLA_DIFFERENTIAL,
    ActionBudget,
    SafetyConstraints,
    TargetType,
    TechniqueManifest,
    check_eligibility,
    get_technique,
    list_techniques,
    register_technique,
)


def test_bola_technique_registered():
    t = get_technique("web.authz.bola.differential")
    assert t is not None
    assert t.risk_tier == RiskTier.R2
    assert t.mutation == MutationClass.none


def test_list_techniques():
    techniques = list_techniques()
    ids = {t.id for t in techniques}
    assert "web.authz.bola.differential" in ids


def test_eligibility_all_met():
    eligible, reasons = check_eligibility(
        BOLA_DIFFERENTIAL,
        available_capabilities={"http.request", "identity.session.two"},
        precondition_state={
            "endpoint.has_object_identifier": "true",
            "access_context_count": "2",
        },
    )
    assert eligible
    assert reasons == []


def test_eligibility_missing_capability():
    eligible, reasons = check_eligibility(
        BOLA_DIFFERENTIAL,
        available_capabilities={"http.request"},
        precondition_state={
            "endpoint.has_object_identifier": "true",
            "access_context_count": "2",
        },
    )
    assert not eligible
    assert any("identity.session.two" in r for r in reasons)


def test_eligibility_precondition_failed():
    eligible, reasons = check_eligibility(
        BOLA_DIFFERENTIAL,
        available_capabilities={"http.request", "identity.session.two"},
        precondition_state={
            "endpoint.has_object_identifier": "false",
            "access_context_count": "2",
        },
    )
    assert not eligible


def test_custom_technique_registration():
    custom = TechniqueManifest(
        id="web.injection.sql.blind",
        version="1.0.0",
        pack="arsgoatia-web-injection",
        description="Blind SQL injection via time-based oracle.",
        target_types=[TargetType.HTTP_ENDPOINT],
        required_capabilities=["http.request"],
        risk_tier=RiskTier.R2,
        mutation=MutationClass.none,
    )
    register_technique(custom)
    assert get_technique("web.injection.sql.blind") is not None


def test_action_budget_defaults():
    b = ActionBudget()
    assert b.max_requests == 12
    assert b.timeout_seconds == 60


def test_safety_constraints_defaults():
    s = SafetyConstraints()
    assert s.redirects == "deny"
    assert s.require_pinned_dns is True
    assert "loopback" in s.disallow_network_classes
