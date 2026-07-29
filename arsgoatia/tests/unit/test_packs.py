"""Tests for the packs/ subsystem -- tools, workflows, labs, policy, reports, knowledge."""
from __future__ import annotations

import dataclasses

import pytest

from packs.tools import (
    HTTP_PROBE,
    ToolPack,
    get_tool_pack,
    list_tool_packs,
    register_tool_pack,
)
from packs.workflows import BOLA_ASSESSMENT_FLOW, WorkflowPack, WorkflowStep
from packs.labs import JUICE_SHOP_LAB, LabDefinition
from packs.policy import LAB_SAFE_PROFILE, PRODUCTION_STRICT_PROFILE, PolicyProfile
from packs.reports import (
    CHAIN_REPORT_TEMPLATE,
    FINDING_REPORT_TEMPLATE,
    ReportTemplate,
)
from packs.knowledge import (
    CWE_639,
    CWE_89,
    CWEMapping,
    cwes_for_technique,
    get_cwe,
    list_cwes,
)


# ── Tool packs ────────────────────────────────────────────────────────────

class TestToolPacks:
    def test_http_probe_registered(self) -> None:
        pack = get_tool_pack("http_probe")
        assert pack is not None
        assert pack.adapter_id == "http-probe"

    def test_http_probe_version(self) -> None:
        assert HTTP_PROBE.version == "1.0.0"

    def test_http_probe_supported_methods(self) -> None:
        methods = HTTP_PROBE.parameter_schema["method"]["enum"]
        for m in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
            assert m in methods

    def test_register_and_retrieve_custom_pack(self) -> None:
        custom = ToolPack(pack_id="custom_scanner", version="0.1.0", adapter_id="nmap")
        register_tool_pack(custom)
        assert get_tool_pack("custom_scanner") is custom

    def test_list_tool_packs_contains_http_probe(self) -> None:
        packs = list_tool_packs()
        ids = [p.pack_id for p in packs]
        assert "http_probe" in ids

    def test_get_tool_pack_not_found(self) -> None:
        assert get_tool_pack("nonexistent_tool_pack_xyz") is None

    def test_tool_pack_frozen(self) -> None:
        with pytest.raises(dataclasses.FrozenInstanceError):
            HTTP_PROBE.version = "2.0.0"  # type: ignore[misc]


# ── Workflow packs ────────────────────────────────────────────────────────

class TestWorkflowPacks:
    def test_bola_flow_step_count(self) -> None:
        assert len(BOLA_ASSESSMENT_FLOW.steps) == 11

    def test_bola_flow_step_ids_ordered(self) -> None:
        ids = [s.step_id for s in BOLA_ASSESSMENT_FLOW.steps]
        assert ids == [
            "recon",
            "identity_bootstrap",
            "hypothesis_generation",
            "action_proposal",
            "approval_gate",
            "differential_execution",
            "evidence_validation",
            "finding_confirmation",
            "capability_proof",
            "chain_step",
            "reporting",
        ]

    def test_approval_gate_has_approval_gate_type(self) -> None:
        gate_step = [s for s in BOLA_ASSESSMENT_FLOW.steps if s.step_id == "approval_gate"][0]
        assert gate_step.gate == "approval"

    def test_finding_confirmation_has_stop_condition(self) -> None:
        step = [s for s in BOLA_ASSESSMENT_FLOW.steps if s.step_id == "finding_confirmation"][0]
        assert step.gate == "stop_condition"

    def test_bola_flow_stop_conditions(self) -> None:
        assert "operator_stop" in BOLA_ASSESSMENT_FLOW.stop_conditions

    def test_workflow_step_frozen(self) -> None:
        step = BOLA_ASSESSMENT_FLOW.steps[0]
        with pytest.raises(dataclasses.FrozenInstanceError):
            step.step_id = "tampered"  # type: ignore[misc]


# ── Lab definitions ───────────────────────────────────────────────────────

class TestLabDefinitions:
    def test_juice_shop_image(self) -> None:
        assert JUICE_SHOP_LAB.target_image == "bkimminich/juice-shop"

    def test_juice_shop_port(self) -> None:
        assert JUICE_SHOP_LAB.target_port == 3000

    def test_juice_shop_challenges(self) -> None:
        assert "BOLA on /rest/basket/{id}" in JUICE_SHOP_LAB.challenges
        assert "Admin section access" in JUICE_SHOP_LAB.challenges
        assert "SQL injection on login" in JUICE_SHOP_LAB.challenges

    def test_lab_definition_frozen(self) -> None:
        with pytest.raises(dataclasses.FrozenInstanceError):
            JUICE_SHOP_LAB.name = "hacked"  # type: ignore[misc]


# ── Policy profiles ──────────────────────────────────────────────────────

class TestPolicyProfiles:
    @pytest.mark.parametrize("tier,expected", [
        ("R0", "allow"),
        ("R1", "allow"),
        ("R2", "require_approval"),
        ("R3", "require_approval"),
        ("R4", "deny"),
        ("R5", "deny"),
    ])
    def test_lab_safe_decisions(self, tier: str, expected: str) -> None:
        assert LAB_SAFE_PROFILE.risk_tier_decisions[tier] == expected

    def test_production_strict_r1_allow_with_limits(self) -> None:
        assert PRODUCTION_STRICT_PROFILE.risk_tier_decisions["R1"] == "allow_with_limits"

    def test_production_strict_r4_deny(self) -> None:
        assert PRODUCTION_STRICT_PROFILE.risk_tier_decisions["R4"] == "deny"

    def test_policy_profile_frozen(self) -> None:
        with pytest.raises(dataclasses.FrozenInstanceError):
            LAB_SAFE_PROFILE.profile_id = "hacked"  # type: ignore[misc]


# ── Report templates ─────────────────────────────────────────────────────

class TestReportTemplates:
    def test_finding_report_sections(self) -> None:
        expected = (
            "executive_summary",
            "finding_details",
            "evidence",
            "impact_analysis",
            "remediation",
            "references",
        )
        assert FINDING_REPORT_TEMPLATE.sections == expected

    def test_chain_report_sections(self) -> None:
        expected = (
            "objective",
            "blast_radius",
            "attack_path",
            "cut_points",
            "severity_assessment",
            "evidence_chain",
        )
        assert CHAIN_REPORT_TEMPLATE.sections == expected

    def test_finding_report_export_formats(self) -> None:
        assert "pdf" in FINDING_REPORT_TEMPLATE.export_formats

    def test_report_template_frozen(self) -> None:
        with pytest.raises(dataclasses.FrozenInstanceError):
            FINDING_REPORT_TEMPLATE.name = "hacked"  # type: ignore[misc]


# ── Knowledge / CWE mappings ─────────────────────────────────────────────

class TestKnowledgePacks:
    def test_get_cwe_639(self) -> None:
        mapping = get_cwe(639)
        assert mapping is not None
        assert mapping.name == "Authorization Bypass Through User-Controlled Key"

    def test_get_cwe_89(self) -> None:
        mapping = get_cwe(89)
        assert mapping is not None
        assert "SQL" in mapping.name

    def test_get_cwe_not_found(self) -> None:
        assert get_cwe(999999) is None

    def test_list_cwes_sorted(self) -> None:
        cwes = list_cwes()
        ids = [c.cwe_id for c in cwes]
        assert ids == sorted(ids)

    def test_list_cwes_has_at_least_six(self) -> None:
        assert len(list_cwes()) >= 6

    def test_cwes_for_technique_bola(self) -> None:
        results = cwes_for_technique("web.authz.bola.differential")
        ids = {m.cwe_id for m in results}
        assert 639 in ids
        assert 284 in ids

    def test_cwes_for_technique_no_match(self) -> None:
        assert cwes_for_technique("nonexistent.technique") == []

    def test_cwe_mapping_frozen(self) -> None:
        with pytest.raises(dataclasses.FrozenInstanceError):
            CWE_639.name = "hacked"  # type: ignore[misc]
