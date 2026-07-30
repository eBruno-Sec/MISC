from __future__ import annotations

from pydantic import Field

from .common import (
    BaseContract,
    DecisionOutcome,
    RiskTier,
    Sensitivity,
    TimestampTZ,
    UUIDv7,
)


class AuthorizationSpec(BaseContract):
    artifact_digest: str
    issuer: str
    valid_from: TimestampTZ
    valid_until: TimestampTZ


class ScopeRule(BaseContract):
    type: str = Field(
        description="dns_suffix | cidr | url_prefix | exact_host | repository | cloud_account"
    )
    value: str


class ScopeSpec(BaseContract):
    include: list[ScopeRule] = Field(default_factory=list)
    exclude: list[ScopeRule] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    redirect_policy: str = Field(default="reject")
    dns: list[str] = Field(default_factory=list)
    allow_private_targets: bool = Field(
        default=False,
        description=(
            "Opt-in: permit RFC1918 private resolved addresses for in-scope "
            "targets (e.g. Docker-lab bridge IPs). Fail-closed default is False. "
            "Metadata, loopback, and link-local addresses stay blocked even when "
            "this is True — those are never legitimate targets."
        ),
    )


class RulesSpec(BaseContract):
    mode: str = Field(default="autonomous")
    allowed_risk_tiers: list[RiskTier] = Field(default_factory=list)
    approval_mapping: dict[RiskTier, DecisionOutcome] = Field(default_factory=dict)
    data_residency: str | None = None
    persistence: str = Field(default="ephemeral")


class BudgetSpec(BaseContract):
    requests: int | None = None
    requests_per_second: float | None = None
    concurrent_actions: int | None = None
    bytes_received: int | None = None
    ai_cost_usd: float | None = None


class CredentialRef(BaseContract):
    id: str
    secret_ref: str = Field(description="URI pointing to secret storage")


class EngagementSpec(BaseContract):
    authorization: AuthorizationSpec
    scope: ScopeSpec
    rules: RulesSpec
    budgets: BudgetSpec
    credentials: list[CredentialRef] = Field(default_factory=list)
    cleanup: dict[str, str] = Field(
        default_factory=dict,
        description="Cleanup policy keys to handler references",
    )


class EngagementRevision(BaseContract):
    """Immutable, content-addressed engagement snapshot."""

    revision_id: UUIDv7
    engagement_id: UUIDv7
    revision_number: int = Field(ge=1)
    content_digest: str
    spec: EngagementSpec
    created_at: TimestampTZ
    created_by: str
    sensitivity: Sensitivity = Sensitivity.internal
