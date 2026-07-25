"""Module contract and module I/O (§14.1, §14.5).

A module declares what it requires/consumes/produces and its safety envelope in
module.yaml. Its runtime output is validated against a versioned schema, carries
provenance, separates fact from inference, and never contains raw secrets.
"""

from __future__ import annotations

import enum
from typing import Any

import yaml
from pydantic import BaseModel, Field

from schemas.common import RiskClass


class ExecutionMode(str, enum.Enum):
    STATIC = "static"
    DYNAMIC = "dynamic"


class ContextRequirement(BaseModel):
    identity_count_min: int = 1
    session_types: list[str] = Field(default_factory=list)
    privilege_labels: list[str] = Field(default_factory=list)


class ModuleRequires(BaseModel):
    asset_kinds: list[str] = Field(default_factory=list)
    contexts: list[ContextRequirement] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    observations: list[str] = Field(default_factory=list)


class ModuleProduces(BaseModel):
    observations: list[str] = Field(default_factory=list)
    hypotheses: list[str] = Field(default_factory=list)
    candidate_findings: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)


class ModuleSafety(BaseModel):
    default_risk_class: RiskClass
    mutation: str = "none"
    destructive: bool = False
    production_default: str = "read_only"
    max_requests: int = 500
    default_rps: float = 2.0
    approval_class: str = "normal"


class ModuleValidation(BaseModel):
    evidence_profile: str


class ModuleRuntime(BaseModel):
    task_queue: str
    timeout_seconds: int = 1800
    retry_policy: str = "bounded"


class ModuleContract(BaseModel):
    """Parsed module.yaml (§14.1)."""

    id: str
    version: str
    domain: str
    execution_mode: ExecutionMode
    description: str = ""
    requires: ModuleRequires = Field(default_factory=ModuleRequires)
    consumes: list[str] = Field(default_factory=list)
    produces: ModuleProduces = Field(default_factory=ModuleProduces)
    safety: ModuleSafety
    validation: ModuleValidation
    runtime: ModuleRuntime

    @classmethod
    def from_yaml(cls, text: str) -> "ModuleContract":
        raw = yaml.safe_load(text)
        # module.yaml nests identity under a top-level `module:` key; the rest
        # (requires/consumes/produces/safety/validation/runtime) are siblings.
        module = dict(raw.get("module", {}))
        merged = {**module}
        for key in ("requires", "consumes", "produces", "safety", "validation", "runtime"):
            if key in raw:
                merged[key] = raw[key]
        return cls.model_validate(merged)


class Provenance(BaseModel):
    """Every module output block carries provenance (§14.5)."""

    module_id: str
    module_version: str
    tool_execution_ids: list[str] = Field(default_factory=list)
    parser_version: str = "1.0.0"
    confirmation_rule_version: str | None = None


class ModuleInput(BaseModel):
    assessment_id: str
    context_id: str
    endpoint_refs: list[str] = Field(default_factory=list)
    object_identifiers: list[str] = Field(default_factory=list)
    session_refs: list[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)


class ModuleOutput(BaseModel):
    """Normalized module output. Facts and inferences are separated; consumers
    treat `candidate_findings` as unconfirmed until deterministic confirmation."""

    module_id: str
    module_version: str
    schema_version: int = 1
    provenance: Provenance
    observations: list[dict[str, Any]] = Field(default_factory=list)
    hypotheses: list[dict[str, Any]] = Field(default_factory=list)
    candidate_findings: list[dict[str, Any]] = Field(default_factory=list)
    capabilities: list[dict[str, Any]] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
