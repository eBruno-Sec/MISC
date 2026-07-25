"""Module output validation (§14.5): versioned schema + no raw secrets."""

from __future__ import annotations

from pathlib import Path

from module_sdk.base import validate_output
from schemas.module_io import ModuleOutput, Provenance

SCHEMA = (
    Path(__file__).resolve().parents[2]
    / "modules"
    / "web"
    / "authorization_idor"
    / "output_schema.json"
)


def _output(**over) -> ModuleOutput:
    base = dict(
        module_id="web.authorization.idor",
        module_version="1.0.0",
        provenance=Provenance(
            module_id="web.authorization.idor",
            module_version="1.0.0",
            parser_version="1.0.0",
            confirmation_rule_version="1.0.0",
        ),
        observations=[{"observation_type": "cross_user_response_difference"}],
        capabilities=[{"capability_type": "read_object", "label": "read_foreign_object", "validation_state": "proven"}],
        evidence_refs=["e1", "e2"],
    )
    base.update(over)
    return ModuleOutput(**base)


def test_valid_output_passes_schema():
    ok, errors = validate_output(_output(), SCHEMA)
    assert ok is True, errors


def test_raw_secret_in_output_is_flagged():
    # A leaked Authorization header value must be caught (quarantine, never execute).
    leaked = _output(observations=[{"headers": {"authorization": "Bearer secret.jwt"}}])
    ok, errors = validate_output(leaked, SCHEMA)
    assert ok is False
    assert any("raw secret" in e for e in errors)
