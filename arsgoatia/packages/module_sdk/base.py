"""Module base + output validation (§14.1, §14.5).

A module declares eligibility, proposes actions (proposal-only), runs bounded
tests through the tool SDK, and confirms deterministically. Its output validates
against a versioned JSON schema, carries provenance, and never contains raw
secrets — malformed output is quarantined, never executed.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from schemas.module_io import ModuleContract, ModuleOutput


@dataclass
class ModuleContext:
    """Everything a module run needs. identities carry secret_uris, never raw
    secrets; the tool SDK resolves secrets at call time."""

    assessment_id: str
    tenant_id: str
    context_id: str
    base_url: str
    identities: list[dict] = field(default_factory=list)
    target_asset_id: str | None = None
    parameters: dict[str, Any] = field(default_factory=dict)


class BaseModule(ABC):
    """All modules subclass this. The registry loads module.yaml into `contract`."""

    contract: ModuleContract

    def __init__(self, contract: ModuleContract) -> None:
        self.contract = contract

    @abstractmethod
    def eligibility(self, ctx: ModuleContext) -> tuple[bool, str]:
        """Deterministic precondition check against the contract's `requires`."""

    @abstractmethod
    async def run(self, ctx: ModuleContext, tool) -> ModuleOutput:
        """Execute the bounded test via the tool SDK and return normalized output."""


# Value-oriented markers: a raw bearer token, a JWT ("eyJ"...), or a Basic-auth
# blob. Deliberately NOT the word "authorization" — that legitimately appears as a
# field/class name (e.g. the module id web.authorization.idor).
_SECRET_MARKERS = ("bearer ", "eyj", "basic ", "set-cookie")


def validate_output(output: ModuleOutput, schema_path: str | Path) -> tuple[bool, list[str]]:
    """Validate a module output against its versioned JSON schema and assert it
    carries no raw secrets. Returns (ok, errors); a caller quarantines on failure."""
    errors: list[str] = []
    try:
        import jsonschema

        schema = json.loads(Path(schema_path).read_text())
        jsonschema.validate(output.model_dump(mode="json"), schema)
    except Exception as exc:  # noqa: BLE001 - schema violation -> quarantine
        errors.append(f"schema: {exc}")

    blob = json.dumps(output.model_dump(mode="json"), default=str).lower()
    for marker in _SECRET_MARKERS:
        if marker in blob:
            errors.append(f"possible raw secret in output: {marker!r}")
    return (not errors), errors


def load_contract(yaml_path: str | Path) -> ModuleContract:
    return ModuleContract.from_yaml(Path(yaml_path).read_text())
