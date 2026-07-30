from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field

from temporalio import activity


@dataclass
class IdentityParams:
    target_url: str
    engagement_id: str
    tenant_id: str
    identity_count: int


@dataclass
class AccessContextResult:
    persona: str
    credential_ref: str


@dataclass
class IdentityResult:
    access_contexts: list[AccessContextResult] = field(default_factory=list)


# Endpoint variants tried in order. The first pair that returns a usable token
# wins for that persona. Extend here when adding new target types.
_REGISTRATION_ENDPOINTS = [
    # OWASP Juice Shop
    (
        "/api/Users",
        lambda email, password, persona: {
            "email": email,
            "password": password,
            "passwordRepeat": password,
            "securityQuestion": {"id": 1},
            "securityAnswer": persona,
        },
    ),
    # Generic app conventions
    ("/register", lambda email, password, persona: {"username": persona, "email": email, "password": password}),
    ("/api/register", lambda email, password, persona: {"username": persona, "email": email, "password": password}),
]

_LOGIN_ENDPOINTS = [
    ("/rest/user/login", lambda email, password: {"email": email, "password": password}),
    ("/login", lambda email, password: {"username": email.split("@")[0], "password": password}),
    ("/api/login", lambda email, password: {"email": email, "password": password}),
]


def _extract_token(response_json: object) -> str | None:
    """Pull a bearer token out of common response shapes."""
    if not isinstance(response_json, dict):
        return None
    # Juice Shop: {"authentication": {"token": "...", ...}}
    auth = response_json.get("authentication")
    if isinstance(auth, dict):
        tok = auth.get("token")
        if isinstance(tok, str) and tok:
            return tok
    # Generic conventions
    for key in ("token", "access_token", "jwt", "accessToken"):
        val = response_json.get(key)
        if isinstance(val, str) and val:
            return val
    return None


@activity.defn
async def establish_identities(params: IdentityParams) -> IdentityResult:
    import httpx  # noqa: PLC0415

    result = IdentityResult()
    base = params.target_url.rstrip("/")

    async with httpx.AsyncClient(
        timeout=15.0,
        follow_redirects=False,
        verify=True,
    ) as client:
        for i in range(params.identity_count):
            activity.heartbeat(f"creating identity {i + 1}/{params.identity_count}")

            persona = f"ars{params.engagement_id[:8]}{i}"
            email = f"{persona}@arsgoatia.test"
            password = uuid.uuid4().hex + "Aa1!"

            registered = False
            for path, payload_fn in _REGISTRATION_ENDPOINTS:
                try:
                    r = await client.post(f"{base}{path}", json=payload_fn(email, password, persona))
                except httpx.HTTPError as exc:
                    activity.logger.warning(
                        "Registration probe failed",
                        extra={"path": path, "error": str(exc)},
                    )
                    continue
                if r.status_code in (200, 201):
                    registered = True
                    activity.logger.info(
                        "Registration succeeded",
                        extra={"persona": persona, "path": path},
                    )
                    break

            if not registered:
                activity.logger.warning(
                    "All registration endpoints failed",
                    extra={"persona": persona},
                )

            token: str | None = None
            login_status = 0
            for path, payload_fn in _LOGIN_ENDPOINTS:
                try:
                    r = await client.post(f"{base}{path}", json=payload_fn(email, password))
                except httpx.HTTPError as exc:
                    activity.logger.warning(
                        "Login probe failed",
                        extra={"path": path, "error": str(exc)},
                    )
                    continue
                login_status = r.status_code
                if r.status_code in (200, 201):
                    try:
                        token = _extract_token(r.json())
                    except ValueError:
                        token = None
                    if token:
                        activity.logger.info(
                            "Login token acquired",
                            extra={"persona": persona, "path": path},
                        )
                        break

            credential_data = {
                "persona": persona,
                "registration_ok": registered,
                "login_status": login_status,
                "has_token": token is not None,
            }

            from services.worker.activities.evidence import (  # noqa: PLC0415
                StoreEvidenceParams,
                store_evidence,
            )

            await store_evidence(
                StoreEvidenceParams(
                    engagement_id=params.engagement_id,
                    tenant_id=params.tenant_id,
                    action_id=f"identity-{persona}",
                    kind="identity_establishment",
                    media_type="application/json",
                    payload=json.dumps(credential_data, sort_keys=True).encode(),
                )
            )

            # credential_ref: real bearer token if acquired, else reference so
            # downstream still can distinguish personas even when auth failed.
            credential_ref = token or (
                f"secret://arsgoatia/{params.tenant_id}/{params.engagement_id}/identity/{persona}"
            )

            result.access_contexts.append(
                AccessContextResult(
                    persona=persona,
                    credential_ref=credential_ref,
                )
            )

    activity.logger.info(
        "Identities established",
        extra={
            "count": len(result.access_contexts),
            "with_token": sum(1 for c in result.access_contexts if not c.credential_ref.startswith("secret://")),
        },
    )
    return result
