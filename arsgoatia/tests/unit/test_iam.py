from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from packages.domain.iam import (
    AuthContext,
    PlatformRole,
    Principal,
    PrincipalType,
    can_approve_high_risk,
    has_any_role,
    has_role,
)


def _ctx(*roles: PlatformRole, mfa: bool = False) -> AuthContext:
    p = Principal(
        id=uuid4(),
        tenant_id=uuid4(),
        principal_type=PrincipalType.USER,
        name="test-user",
        roles=frozenset(roles),
    )
    return AuthContext(
        principal=p,
        tenant_id=p.tenant_id,
        session_id=uuid4(),
        authenticated_at=datetime.now(timezone.utc),
        mfa_verified=mfa,
    )


def test_has_role():
    ctx = _ctx(PlatformRole.OPERATOR, PlatformRole.REVIEWER)
    assert has_role(ctx, PlatformRole.OPERATOR)
    assert not has_role(ctx, PlatformRole.TENANT_ADMIN)


def test_has_any_role():
    ctx = _ctx(PlatformRole.REVIEWER)
    assert has_any_role(ctx, {PlatformRole.REVIEWER, PlatformRole.TENANT_ADMIN})
    assert not has_any_role(ctx, {PlatformRole.TENANT_ADMIN})


def test_can_approve_high_risk_with_mfa():
    ctx = _ctx(PlatformRole.APPROVER, mfa=True)
    assert can_approve_high_risk(ctx)


def test_cannot_approve_high_risk_without_mfa():
    ctx = _ctx(PlatformRole.APPROVER, mfa=False)
    assert not can_approve_high_risk(ctx)


def test_cannot_approve_high_risk_wrong_role():
    ctx = _ctx(PlatformRole.OPERATOR, mfa=True)
    assert not can_approve_high_risk(ctx)


def test_auth_context_tenant():
    ctx = _ctx(PlatformRole.OPERATOR)
    assert ctx.tenant_id == ctx.principal.tenant_id
