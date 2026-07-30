"""Login endpoint — issues a short-lived JWT for a bootstrap operator.

This is deliberately minimal: a single bootstrap operator whose
credentials come from environment variables. Full user management (invite,
role assignments, password reset) is future work.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from apps.api.auth import issue_token

router = APIRouter(tags=["auth"])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1)
    password: str = Field(min_length=1)
    tenant_id: str = Field(min_length=1)


class LoginResponse(BaseModel):
    token: str
    user: str
    role: str
    tenant_id: str
    expires_at: datetime


def _bootstrap_operator() -> tuple[str, str, str]:
    username = os.environ.get("ARSGOATIA_BOOTSTRAP_USER", "operator")
    password = os.environ.get("ARSGOATIA_BOOTSTRAP_PASSWORD", "arsgoatia-dev-password")
    role = os.environ.get("ARSGOATIA_BOOTSTRAP_ROLE", "admin")
    return username, password, role


@router.post("/auth/login", response_model=LoginResponse, summary="Exchange credentials for a JWT")
async def login(body: LoginRequest):
    exp_user, exp_password, role = _bootstrap_operator()
    ok_user = hmac.compare_digest(body.username, exp_user)
    ok_pass = hmac.compare_digest(
        hashlib.sha256(body.password.encode()).digest(),
        hashlib.sha256(exp_password.encode()).digest(),
    )
    if not (ok_user and ok_pass):
        raise HTTPException(status_code=401, detail="invalid credentials")
    ttl = 3600
    token = issue_token(
        user=body.username,
        role=role,
        tenant_id=body.tenant_id,
        ttl_seconds=ttl,
    )
    return LoginResponse(
        token=token,
        user=body.username,
        role=role,
        tenant_id=body.tenant_id,
        expires_at=datetime.now(timezone.utc).replace(microsecond=0),
    )
