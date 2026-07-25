"""Scope definition contract (§6.6).

The compiled scope is the input to the scope firewall (§13.4). Disposition is
explicit: include rules grant, exclude rules deny, and deny overrides allow.
"""

from __future__ import annotations

import enum

from pydantic import BaseModel, Field


class ScopeKind(str, enum.Enum):
    HOSTNAME = "hostname"
    DOMAIN = "domain"
    CIDR = "cidr"
    CLOUD_ACCOUNT = "cloud_account"
    REPOSITORY = "repository"
    API = "api"
    APPLICATION = "application"


class EnvironmentClassification(str, enum.Enum):
    UNKNOWN = "unknown"
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    LAB = "lab"


class ScopeRule(BaseModel):
    kind: ScopeKind
    value: str
    constraints: dict = Field(default_factory=dict)


class ThirdPartyPolicy(BaseModel):
    default: str = "deny"
    exceptions: list[str] = Field(default_factory=list)


class ResolutionPolicy(BaseModel):
    follow_dns: bool = True
    pin_resolved_addresses: bool = True
    recheck_redirects: bool = True
    reject_resolution_drift: bool = True


class ScopeDefinition(BaseModel):
    include_rules: list[ScopeRule] = Field(default_factory=list)
    exclude_rules: list[ScopeRule] = Field(default_factory=list)
    third_party_policy: ThirdPartyPolicy = Field(default_factory=ThirdPartyPolicy)
    resolution_policy: ResolutionPolicy = Field(default_factory=ResolutionPolicy)
    environment_classification: dict = Field(
        default_factory=lambda: {"default": EnvironmentClassification.UNKNOWN.value}
    )
