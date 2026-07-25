"""Module contract parsing (§14.1).

Guards that the web.authorization.idor module.yaml parses into the versioned
ModuleContract and carries the safety envelope the policy engine keys on.
"""

from __future__ import annotations

from pathlib import Path

from schemas.common import RiskClass
from schemas.module_io import ExecutionMode, ModuleContract

REPO_ROOT = Path(__file__).resolve().parents[2]
IDOR_YAML = REPO_ROOT / "modules" / "web" / "authorization_idor" / "module.yaml"


def test_idor_module_yaml_parses():
    contract = ModuleContract.from_yaml(IDOR_YAML.read_text())
    assert contract.id == "web.authorization.idor"
    assert contract.version == "1.0.0"
    assert contract.domain == "web"
    assert contract.execution_mode is ExecutionMode.DYNAMIC


def test_idor_safety_envelope():
    contract = ModuleContract.from_yaml(IDOR_YAML.read_text())
    assert contract.safety.default_risk_class is RiskClass.R2
    assert contract.safety.approval_class == "normal"
    assert contract.safety.destructive is False
    assert contract.safety.production_default == "read_only"
    assert contract.validation.evidence_profile == "authorization_differential"
    assert contract.runtime.task_queue == "api-testing"


def test_idor_requires_two_standard_identities():
    contract = ModuleContract.from_yaml(IDOR_YAML.read_text())
    ctx = contract.requires.contexts[0]
    assert ctx.identity_count_min == 2
    assert "standard_user" in ctx.privilege_labels
    assert "read_foreign_object" in contract.produces.capabilities
