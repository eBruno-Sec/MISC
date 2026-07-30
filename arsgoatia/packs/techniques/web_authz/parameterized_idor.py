"""Generic parameterized-URL BOLA (a.k.a. IDOR) probe.

Not specific to any single application. Callers hand in a URL template
containing a ``{id}`` placeholder and the object IDs owned by each identity.
The probe runs the deterministic 4-exchange protocol and returns a verdict.

Use this whenever a bespoke technique pack knows how to enumerate object IDs
for a target but not how to run the differential auth-bypass check.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class IDORExchange:
    label: str
    url: str
    status_code: int
    expected_codes: list[int]
    matched: bool
    body_preview: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "url": self.url,
            "status_code": self.status_code,
            "expected_codes": self.expected_codes,
            "matched": self.matched,
            "body_preview": self.body_preview,
        }


@dataclass
class IDORResult:
    finding_status: str  # CONFIRMED | INCONCLUSIVE | REJECTED
    reason: str
    exchanges: list[IDORExchange] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_status": self.finding_status,
            "reason": self.reason,
            "exchanges": [e.to_dict() for e in self.exchanges],
        }


async def run_parameterized_idor(
    *,
    client,
    url_template: str,
    id_a: Any,
    id_b: Any,
    token_a: str,
    token_b: str,
    persona_a: str = "identity_a",
    persona_b: str = "identity_b",
    expect_own_read_codes: list[int] | None = None,
    expect_deny_codes: list[int] | None = None,
) -> IDORResult:
    """Run the deterministic 4-exchange BOLA protocol.

    ``url_template`` must contain the substring ``{id}`` — it is substituted
    with each identity's owned object id.
    """
    if "{id}" not in url_template:
        return IDORResult(
            finding_status="INCONCLUSIVE",
            reason="url_template must contain the '{id}' placeholder",
        )
    if id_a == id_b:
        return IDORResult(
            finding_status="INCONCLUSIVE",
            reason=f"identities own the same object id ({id_a!r}) — differential not meaningful",
        )
    if not token_a or not token_b:
        return IDORResult(
            finding_status="INCONCLUSIVE",
            reason="both identities must present real bearer tokens",
        )

    own_codes = expect_own_read_codes or [200]
    deny_codes = expect_deny_codes or [401, 403, 404]

    url_a = url_template.replace("{id}", str(id_a))
    url_b = url_template.replace("{id}", str(id_b))

    exchanges: list[IDORExchange] = []

    async def _do(label: str, url: str, token: str | None, expected: list[int]) -> IDORExchange:
        headers: dict[str, str] = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            r = await client.get(url, headers=headers)
            status = r.status_code
            try:
                preview = json.dumps(r.json())[:200]
            except Exception:
                preview = (r.text[:200] if hasattr(r, "text") else "")
        except Exception as exc:
            status = 0
            preview = f"error: {exc!r}"
        return IDORExchange(
            label=label,
            url=url,
            status_code=status,
            expected_codes=expected,
            matched=status in expected,
            body_preview=preview,
        )

    baseline = await _do(f"baseline_{persona_a}_own", url_a, token_a, own_codes)
    exchanges.append(baseline)

    differential = await _do(
        f"differential_{persona_a}_reads_{persona_b}",
        url_b,
        token_a,
        deny_codes,
    )
    exchanges.append(differential)

    positive = await _do(f"positive_control_{persona_b}_own", url_b, token_b, own_codes)
    exchanges.append(positive)

    negative = await _do("negative_control_noauth", url_b, None, deny_codes)
    exchanges.append(negative)

    if not baseline.matched:
        return IDORResult(
            finding_status="INCONCLUSIVE",
            reason=f"baseline failed (got {baseline.status_code}, wanted {own_codes})",
            exchanges=exchanges,
        )
    if not positive.matched:
        return IDORResult(
            finding_status="INCONCLUSIVE",
            reason=f"positive control failed (got {positive.status_code}, wanted {own_codes})",
            exchanges=exchanges,
        )
    if not negative.matched:
        return IDORResult(
            finding_status="INCONCLUSIVE",
            reason=(
                f"negative control failed (got {negative.status_code}); endpoint may be "
                "public — differential not meaningful"
            ),
            exchanges=exchanges,
        )

    if differential.status_code in own_codes:
        return IDORResult(
            finding_status="CONFIRMED",
            reason=(
                f"cross-user read succeeded: {persona_a} with token {token_a[:12]}… "
                f"read {persona_b}'s object at {url_b} — auth layer does not verify ownership"
            ),
            exchanges=exchanges,
        )

    return IDORResult(
        finding_status="REJECTED",
        reason=f"cross-user request correctly denied ({differential.status_code})",
        exchanges=exchanges,
    )
