from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID


class PlatformRole(enum.Enum):
    TENANT_ADMIN = "tenant_admin"
    ENGAGEMENT_OWNER = "engagement_owner"
    OPERATOR = "operator"
    APPROVER = "approver"
    REVIEWER = "reviewer"
    EVIDENCE_CUSTODIAN = "evidence_custodian"
    AUDITOR = "auditor"
    PACK_PUBLISHER = "pack_publisher"
    RUNNER_SERVICE = "runner_service"
    INTEGRATION_SERVICE = "integration_service"


class PrincipalType(enum.Enum):
    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    RUNNER = "runner"


@dataclass(frozen=True)
class Principal:
    id: UUID
    tenant_id: UUID
    principal_type: PrincipalType
    name: str
    roles: frozenset[PlatformRole] = frozenset()
    teams: frozenset[UUID] = frozenset()


@dataclass(frozen=True)
class AuthContext:
    principal: Principal
    tenant_id: UUID
    session_id: UUID
    authenticated_at: datetime
    mfa_verified: bool = False
    step_up_claims: frozenset[str] = frozenset()


def has_role(ctx: AuthContext, role: PlatformRole) -> bool:
    return role in ctx.principal.roles


def has_any_role(ctx: AuthContext, roles: set[PlatformRole]) -> bool:
    return bool(ctx.principal.roles & roles)


def can_approve_high_risk(ctx: AuthContext) -> bool:
    return (
        has_any_role(ctx, {PlatformRole.APPROVER, PlatformRole.ENGAGEMENT_OWNER})
        and ctx.mfa_verified
    )


APPROVAL_ROLES = frozenset({PlatformRole.APPROVER, PlatformRole.ENGAGEMENT_OWNER, PlatformRole.OPERATOR})
ADMIN_ROLES = frozenset({PlatformRole.TENANT_ADMIN})
