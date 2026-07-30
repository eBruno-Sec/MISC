"""Contract tests: module output schema validation (§14, §39 DoD).

Verifies that every ConfirmationResult from the IDOR module:
  - Validates against output_schema.json (versioned, per §14)
  - When confirmed: includes evidence_digest and capability_name
  - When refuted/inconclusive: does NOT emit a capability
  - module_id, technique_id, version fields are correct
  - Provenance fields are always present (no silent omissions)
"""

from __future__ import annotations

import json
import pathlib

import pytest

try:
    import jsonschema  # type: ignore[import]

    _HAS_JSONSCHEMA = True
except ImportError:
    _HAS_JSONSCHEMA = False

from modules.web.authorization_idor import MODULE_ID, TECHNIQUE_ID, VERSION
from modules.web.authorization_idor import module as idor_module
from packages.module_sdk import ConfirmationDecision, ConfirmationResult, ModuleContext

# ---------------------------------------------------------------------------
# Load output schema
# ---------------------------------------------------------------------------

_SCHEMA_PATH = (
    pathlib.Path(__file__).resolve().parents[2]
    / "modules"
    / "web"
    / "authorization_idor"
    / "output_schema.json"
)

_OUTPUT_SCHEMA: dict = {}
if _SCHEMA_PATH.exists():
    _OUTPUT_SCHEMA = json.loads(_SCHEMA_PATH.read_text())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ctx(
    identities: list[str] | None = None,
    endpoints: list[str] | None = None,
) -> ModuleContext:
    from uuid import uuid4

    return ModuleContext(
        engagement_id=uuid4(),
        tenant_id=uuid4(),
        target_locator="http://juice-shop:3000",
        metadata={
            "identities": identities or ["alice", "bob"],
            "endpoints": endpoints or ["/rest/basket/{id}"],
        },
    )


def _evidence(
    diff_status: int = 200,
    diff_body: bool = True,
    neg_status: int = 401,
    evidence_digest: str = "sha256:" + "a" * 64,
) -> dict:
    return {
        "evidence_digest": evidence_digest,
        "exchanges": [
            {"label": "baseline_own", "actual_status": 200},
            {
                "label": "differential_cross",
                "actual_status": diff_status,
                "body_contains_object": diff_body,
            },
            {"label": "positive_control", "actual_status": 200},
            {"label": "negative_control", "actual_status": neg_status},
        ],
    }


def _result_to_schema_dict(result: ConfirmationResult) -> dict:
    """Convert a ConfirmationResult to the output schema shape."""
    return {
        "module_id": MODULE_ID,
        "technique_id": TECHNIQUE_ID,
        "version": VERSION,
        "decision": result.decision.value,
        "rule_version": result.rule_version,
        "reason": result.reason,
        "evidence_digest": result.evidence_digest,
        "capability_name": result.capability_name,
        "capability_description": result.capability_description,
        "metadata": result.metadata,
    }


skipif_no_jsonschema = pytest.mark.skipif(
    not _HAS_JSONSCHEMA,
    reason="jsonschema not installed",
)


# ---------------------------------------------------------------------------
# Schema file structural tests (always run)
# ---------------------------------------------------------------------------


class TestOutputSchemaFile:
    def test_schema_file_exists(self):
        assert _SCHEMA_PATH.exists(), f"missing output schema: {_SCHEMA_PATH}"

    def test_schema_is_valid_json(self):
        assert _OUTPUT_SCHEMA, "output_schema.json is empty"
        assert "properties" in _OUTPUT_SCHEMA

    def test_schema_has_required_fields(self):
        required = _OUTPUT_SCHEMA.get("required", [])
        for field in ("module_id", "technique_id", "version", "decision", "rule_version", "reason"):
            assert field in required, f"required field {field!r} missing from schema"

    def test_schema_has_versioned_id(self):
        schema_id = _OUTPUT_SCHEMA.get("$id", "")
        assert "web.authorization.idor.differential" in schema_id
        assert "v1" in schema_id

    def test_schema_decision_enum(self):
        decision_prop = _OUTPUT_SCHEMA["properties"]["decision"]
        enum_vals = set(decision_prop.get("enum", []))
        assert "confirmed" in enum_vals
        assert "refuted" in enum_vals
        assert "inconclusive" in enum_vals

    def test_schema_capability_name_enum(self):
        cap_prop = _OUTPUT_SCHEMA["properties"]["capability_name"]
        enum_vals = set(cap_prop.get("enum", []))
        assert "read_foreign_object" in enum_vals


# ---------------------------------------------------------------------------
# Module output shape (always run, no jsonschema needed)
# ---------------------------------------------------------------------------


class TestModuleOutputShape:
    def test_confirmed_has_capability_name(self):
        result = idor_module.confirm(_evidence(), _ctx())
        assert result.is_confirmed
        assert result.capability_name == "read_foreign_object"

    def test_confirmed_has_evidence_digest(self):
        result = idor_module.confirm(_evidence(), _ctx())
        assert result.evidence_digest is not None
        assert result.evidence_digest.startswith("sha256:")

    def test_refuted_has_no_capability(self):
        result = idor_module.confirm(_evidence(diff_status=403), _ctx())
        assert not result.is_confirmed
        assert result.capability_name is None

    def test_inconclusive_has_no_capability(self):
        result = idor_module.confirm(_evidence(diff_status=200, diff_body=False), _ctx())
        assert result.decision == ConfirmationDecision.INCONCLUSIVE
        assert result.capability_name is None

    def test_rule_version_matches_module(self):
        result = idor_module.confirm(_evidence(), _ctx())
        assert result.rule_version == idor_module.CONFIRMATION_RULE_VERSION

    def test_metadata_has_technique_id(self):
        result = idor_module.confirm(_evidence(), _ctx())
        assert result.metadata.get("technique_id") == TECHNIQUE_ID

    def test_metadata_has_cwe_639(self):
        result = idor_module.confirm(_evidence(), _ctx())
        assert "639" in result.metadata.get("cwe", "")

    def test_metadata_has_owasp_api1(self):
        result = idor_module.confirm(_evidence(), _ctx())
        assert "API1" in result.metadata.get("owasp", "")

    def test_reason_always_non_empty(self):
        for evidence in [
            _evidence(),
            _evidence(diff_status=403),
            _evidence(diff_body=False),
            _evidence(neg_status=200),
        ]:
            result = idor_module.confirm(evidence, _ctx())
            assert result.reason, f"reason is empty for decision={result.decision}"


# ---------------------------------------------------------------------------
# JSON Schema validation (skipped without jsonschema)
# ---------------------------------------------------------------------------


@skipif_no_jsonschema
class TestOutputSchemaValidation:
    def _validate(self, output_dict: dict) -> list[str]:
        validator = jsonschema.Draft202012Validator(_OUTPUT_SCHEMA)
        return [str(e) for e in validator.iter_errors(output_dict)]

    def test_confirmed_output_validates(self):
        result = idor_module.confirm(_evidence(), _ctx())
        d = _result_to_schema_dict(result)
        errors = self._validate(d)
        assert errors == [], f"schema validation errors: {errors}"

    def test_refuted_output_validates(self):
        result = idor_module.confirm(_evidence(diff_status=403), _ctx())
        d = _result_to_schema_dict(result)
        errors = self._validate(d)
        assert errors == [], f"schema validation errors: {errors}"

    def test_inconclusive_output_validates(self):
        result = idor_module.confirm(_evidence(diff_body=False), _ctx())
        d = _result_to_schema_dict(result)
        errors = self._validate(d)
        assert errors == [], f"schema validation errors: {errors}"

    def test_missing_module_id_fails(self):
        d = _result_to_schema_dict(idor_module.confirm(_evidence(), _ctx()))
        del d["module_id"]
        errors = self._validate(d)
        assert errors, "expected validation error for missing module_id"

    def test_wrong_decision_value_fails(self):
        d = _result_to_schema_dict(idor_module.confirm(_evidence(), _ctx()))
        d["decision"] = "maybe"
        errors = self._validate(d)
        assert errors, "expected validation error for invalid decision value"

    def test_confirmed_requires_evidence_digest(self):
        d = _result_to_schema_dict(idor_module.confirm(_evidence(), _ctx()))
        assert d["decision"] == "confirmed"
        # Remove evidence_digest from a confirmed result — should fail
        d["evidence_digest"] = None
        errors = self._validate(d)
        assert errors, "confirmed output without evidence_digest should fail schema"
