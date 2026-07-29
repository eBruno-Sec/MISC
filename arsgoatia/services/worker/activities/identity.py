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

            persona = f"arsgoatia-test-{params.engagement_id[:8]}-{i}"
            email = f"{persona}@arsgoatia.test"
            password = uuid.uuid4().hex

            register_payload = {
                "username": persona,
                "email": email,
                "password": password,
            }

            try:
                reg_response = await client.post(
                    f"{base}/register",
                    json=register_payload,
                )
            except httpx.HTTPError as exc:
                activity.logger.warning(
                    "Registration failed",
                    extra={"persona": persona, "error": str(exc)},
                )
                continue

            if reg_response.status_code not in (200, 201):
                activity.logger.warning(
                    "Registration returned non-success",
                    extra={
                        "persona": persona,
                        "status": reg_response.status_code,
                    },
                )

            try:
                login_response = await client.post(
                    f"{base}/login",
                    json={"username": persona, "password": password},
                )
            except httpx.HTTPError as exc:
                activity.logger.warning(
                    "Login failed",
                    extra={"persona": persona, "error": str(exc)},
                )
                continue

            credential_data = {
                "persona": persona,
                "login_status": login_response.status_code,
                "has_token": "token" in login_response.text.lower(),
            }

            secret_ref = (
                f"secret://arsgoatia/{params.tenant_id}"
                f"/{params.engagement_id}/identity/{persona}"
            )

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

            result.access_contexts.append(
                AccessContextResult(
                    persona=persona,
                    credential_ref=secret_ref,
                )
            )

    activity.logger.info(
        "Identities established",
        extra={"count": len(result.access_contexts)},
    )
    return result
