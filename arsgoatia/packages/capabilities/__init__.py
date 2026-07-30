"""Capability Pack registry.

A Capability Pack is the compiled ABI between the arsgoatia platform and
a technique implementation. Each pack declares what it detects, what
evidence it produces, what remediation to recommend, and how to invoke
it — so downstream consumers (planner, reports, UI, other services) can
reason about the platform's actual capabilities without reading Python.

Discovery walks ``packs/**/*.capability.yaml`` at import time and yields
strongly-typed :class:`CapabilityPack` instances.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

__all__ = [
    "CapabilityPack",
    "PackMetadata",
    "PackClassification",
    "load_registry",
    "get_registry",
]


class PackMetadata(BaseModel):
    id: str
    name: str
    version: str
    authors: list[str] = Field(default_factory=list)
    license: str | None = None


class PackClassification(BaseModel):
    weakness_id: str | None = None  # CWE-XX
    owasp: str | None = None
    capec: str | None = None
    severity: str = "info"
    risk_tier: str = "R1"
    mutation_class: str = "none"


class PackTargeting(BaseModel):
    applies_when: dict[str, Any] = Field(default_factory=dict)
    requires: dict[str, Any] = Field(default_factory=dict)
    supported_databases: list[str] = Field(default_factory=list)
    supported_targets: list[str] = Field(default_factory=list)


class PackConfirmation(BaseModel):
    strategy: str = "unspecified"
    determinism: str = "strict"
    false_positive_conditions: list[str] = Field(default_factory=list)
    exchanges_required: list[str] = Field(default_factory=list)
    probes: list[str] = Field(default_factory=list)
    audited_headers: list[str] = Field(default_factory=list)
    exchanges: list[str] = Field(default_factory=list)
    bounded_secret_dictionary_size: int | None = None


class PackReliability(BaseModel):
    source_authority: str | None = None
    corroboration: list[str] = Field(default_factory=list)
    historical_success_rate: float | None = None
    # YAML parses bare dates (2026-07-30) as datetime.date; accept either.
    last_validated: str | None = None

    @field_validator("last_validated", mode="before")
    @classmethod
    def _coerce_date(cls, v):
        if v is None or isinstance(v, str):
            return v
        return str(v)


class PackHistoryEntry(BaseModel):
    target: str | None = None
    date: str | None = None
    finding_id: str | None = None

    @field_validator("date", mode="before")
    @classmethod
    def _coerce_date(cls, v):
        if v is None or isinstance(v, str):
            return v
        return str(v)


class PackEvidenceProfile(BaseModel):
    minimum_exchanges: int = 1
    required_kinds: list[str] = Field(default_factory=list)
    stored_fields: list[str] = Field(default_factory=list)


class PackExecution(BaseModel):
    activity: str | None = None
    task_queue: str | None = None
    timeout_seconds: int | None = None
    retry_policy: dict[str, Any] = Field(default_factory=dict)
    reuses: str | None = None
    status: str | None = None


class PackRemediation(BaseModel):
    short: str = ""
    long: str = ""


class CapabilityPack(BaseModel):
    apiVersion: str
    kind: str
    metadata: PackMetadata
    classification: PackClassification
    targeting: PackTargeting = Field(default_factory=PackTargeting)
    confirmation: PackConfirmation = Field(default_factory=PackConfirmation)
    reliability: PackReliability = Field(default_factory=PackReliability)
    evidence_profile: PackEvidenceProfile = Field(default_factory=PackEvidenceProfile)
    execution: PackExecution = Field(default_factory=PackExecution)
    remediation: PackRemediation = Field(default_factory=PackRemediation)
    known_failures: list[PackHistoryEntry] = Field(default_factory=list)
    known_successes: list[PackHistoryEntry] = Field(default_factory=list)
    source_path: str | None = None


def _pack_root_candidates() -> list[Path]:
    """Locations where capability yaml files may live.

    Different services (api, worker) mount the repo at different paths, so
    walk every candidate root that exists and dedupe on file basename.
    """
    here = Path(__file__).resolve().parent
    # packages/capabilities → arsgoatia repo root
    repo_root = here.parent.parent
    candidates = [
        repo_root / "packs",
        Path("/app/packs"),
        Path.cwd() / "packs",
    ]
    return [p for p in candidates if p.exists()]


def load_registry() -> list[CapabilityPack]:
    """Discover every ``*.capability.yaml`` under known pack roots."""
    import yaml  # noqa: PLC0415

    seen: set[str] = set()
    packs: list[CapabilityPack] = []
    for root in _pack_root_candidates():
        for yaml_path in root.rglob("*.capability.yaml"):
            key = yaml_path.name
            if key in seen:
                continue
            seen.add(key)
            try:
                raw = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(raw, dict):
                continue
            raw["source_path"] = str(yaml_path)
            try:
                pack = CapabilityPack.model_validate(raw)
            except Exception:
                continue
            packs.append(pack)
    packs.sort(key=lambda p: (p.classification.severity, p.metadata.id))
    return packs


@lru_cache(maxsize=1)
def get_registry() -> list[CapabilityPack]:
    """Cached registry for the process lifetime."""
    return load_registry()
