"""Identity bootstrap activity (§10 IdentityBootstrapWorkflow).

Establishes the two standard-user test identities the IDOR module requires:
registers each on the target, logs in, stores the JWT in the secret store (only a
secret_uri + fingerprint leave this activity), and creates the identity,
credential_reference, session, and access_context records.

Runs on the api-testing queue in worker-web. R2 bounded active testing (account
creation is lab-only and counted).
"""

from __future__ import annotations

import logging
from typing import Any

from temporalio import activity

from temporal.workflows.activities.identity_probe import default_identities, parse_login

log = logging.getLogger("identity")


@activity.defn(name="establish_identities")
async def establish_identities(params: dict[str, Any]) -> dict[str, Any]:
    import httpx

    from domain import repositories as repo
    from domain.db import session_scope
    from secrets_store.store import SecretStore

    tenant_id = params["tenant_id"]
    assessment_id = params["assessment_id"]
    base_url = params["base_url"].rstrip("/")
    target_asset_id = params.get("target_asset_id")
    identities = params.get("identities") or default_identities(assessment_id, count=2)

    store = SecretStore()
    results: list[dict[str, Any]] = []

    async with httpx.AsyncClient(timeout=20.0) as client:
        established = []
        for ident in identities:
            # Register (idempotent-ish: a duplicate email just fails, then we log in).
            try:
                await client.post(
                    f"{base_url}/api/Users",
                    json={
                        "email": ident["email"],
                        "password": ident["password"],
                        "passwordRepeat": ident["password"],
                        "securityQuestion": {"id": 1},
                        "securityAnswer": "arsgoatia",
                    },
                )
            except Exception as exc:  # noqa: BLE001 - registration best-effort
                log.warning("register failed for %s: %s", ident["email"], exc)

            token, object_id = None, None
            try:
                resp = await client.post(
                    f"{base_url}/rest/user/login",
                    json={"email": ident["email"], "password": ident["password"]},
                )
                token, object_id = parse_login(resp.json())
            except Exception as exc:  # noqa: BLE001
                log.warning("login failed for %s: %s", ident["email"], exc)
            established.append((ident, token, object_id))

    async with session_scope(tenant_id) as session:
        for ident, token, object_id in established:
            if not token:
                continue
            identity = await repo.create_identity(
                session,
                tenant_id=tenant_id,
                assessment_id=assessment_id,
                principal=ident["email"],
                privilege_label=ident.get("privilege_label", "standard_user"),
                authority=base_url,
            )
            secret = await store.put(
                session, tenant_id=tenant_id, assessment_id=assessment_id, value=token
            )
            cred = await repo.create_credential_reference(
                session,
                tenant_id=tenant_id,
                assessment_id=assessment_id,
                identity_id=identity.id,
                secret_uri=secret["secret_uri"],
                fingerprint=secret["fingerprint"],
            )
            sess = await repo.create_session(
                session,
                tenant_id=tenant_id,
                assessment_id=assessment_id,
                identity_id=identity.id,
                target_asset_id=target_asset_id,
                credential_reference_id=cred.id,
            )
            ctx = await repo.create_access_context(
                session,
                tenant_id=tenant_id,
                assessment_id=assessment_id,
                identity_id=identity.id,
                session_id=sess.id,
                credential_reference_ids=[cred.id],
            )
            results.append(
                {
                    "identity_id": str(identity.id),
                    "principal": ident["email"],
                    "credential_reference_id": str(cred.id),
                    "secret_uri": secret["secret_uri"],
                    "fingerprint": secret["fingerprint"],
                    "session_id": str(sess.id),
                    "access_context_id": str(ctx.id),
                    "object_id": object_id,
                }
            )

    return {"identities": results, "count": len(results)}
