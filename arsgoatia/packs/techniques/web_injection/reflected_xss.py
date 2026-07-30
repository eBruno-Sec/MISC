"""Deterministic reflected-XSS technique pack.

Injects a random-per-probe canary string into a query parameter and
checks the response for **unencoded** reflection in an HTML context.
CONFIRMED requires:

  * the canary appears verbatim in the response body,
  * it appears outside HTML-encoded form (no ``&lt;`` / ``&amp;``
    wrappers on its markup characters),
  * the response's ``content-type`` is HTML.

A ``Content-Security-Policy`` header that would neutralise the reflection
downgrades the finding to INCONCLUSIVE (still worth reporting, but not
directly exploitable).
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

TECHNIQUE_ID = "web_xss_reflected"
CWE = "CWE-79"
OWASP = "A03:2021 — Injection"


@dataclass
class XSSExchange:
    label: str
    url: str
    status_code: int
    content_type: str
    canary_reflected: bool
    canary_html_encoded: bool
    csp_present: bool
    body_preview: str = ""

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__


@dataclass
class XSSResult:
    finding_status: str  # CONFIRMED | INCONCLUSIVE | REJECTED
    reason: str
    parameter: str = ""
    canary: str = ""
    exchanges: list[XSSExchange] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_status": self.finding_status,
            "reason": self.reason,
            "parameter": self.parameter,
            "canary": self.canary,
            "exchanges": [e.to_dict() for e in self.exchanges],
        }


def _replace_query_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    new_pairs = [(k, value if k == param else v) for k, v in pairs]
    return urlunparse(parsed._replace(query=urlencode(new_pairs)))


def _build_canary() -> str:
    # Distinctive but contains the meta-characters we care about — angle brackets,
    # double quote, single quote — so we can detect encoding after reflection.
    return f'arsgoatia<>"\'{secrets.token_hex(6)}'


async def _fetch(client, url: str, canary: str, headers: dict[str, str] | None) -> XSSExchange:
    try:
        r = await client.get(url, headers=headers or {})
        text = r.text if hasattr(r, "text") else ""
        content_type = r.headers.get("content-type", "")
        csp = "content-security-policy" in {k.lower() for k in r.headers.keys()}
        reflected = canary in text
        # HTML-encoded reflection: the canary appears only with entity-escaped meta
        # characters, i.e. the raw canary is NOT present but the encoded form is.
        encoded_form = canary.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
        html_encoded = (not reflected) and (encoded_form in text)
        return XSSExchange(
            label="probe",
            url=url,
            status_code=r.status_code,
            content_type=content_type,
            canary_reflected=reflected,
            canary_html_encoded=html_encoded,
            csp_present=csp,
            body_preview=text[:200],
        )
    except Exception as exc:
        return XSSExchange(
            label="probe",
            url=url,
            status_code=0,
            content_type="",
            canary_reflected=False,
            canary_html_encoded=False,
            csp_present=False,
            body_preview=f"error: {exc!r}",
        )


async def probe(
    *,
    client,
    url: str,
    parameter: str,
    token: str | None = None,
) -> XSSResult:
    parsed = urlparse(url)
    pairs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if parameter not in pairs:
        return XSSResult(
            finding_status="INCONCLUSIVE",
            reason=f"parameter {parameter!r} not in URL query string",
            parameter=parameter,
        )
    canary = _build_canary()
    injected_url = _replace_query_param(url, parameter, canary)

    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    result = await _fetch(client, injected_url, canary, headers)

    if not result.canary_reflected and not result.canary_html_encoded:
        return XSSResult(
            finding_status="REJECTED",
            reason="canary was not reflected in the response body at all",
            parameter=parameter,
            canary=canary,
            exchanges=[result],
        )
    if result.canary_html_encoded:
        return XSSResult(
            finding_status="REJECTED",
            reason="canary reflected only in HTML-encoded form — server escapes correctly",
            parameter=parameter,
            canary=canary,
            exchanges=[result],
        )
    is_html = "html" in result.content_type.lower()
    if not is_html:
        return XSSResult(
            finding_status="INCONCLUSIVE",
            reason=(
                f"canary reflected unencoded but content-type is {result.content_type!r} — "
                "not an HTML rendering context, harder to exploit"
            ),
            parameter=parameter,
            canary=canary,
            exchanges=[result],
        )
    if result.csp_present:
        return XSSResult(
            finding_status="INCONCLUSIVE",
            reason=(
                "canary reflected unencoded in HTML but a Content-Security-Policy header "
                "is set; exploitability depends on the policy's directives"
            ),
            parameter=parameter,
            canary=canary,
            exchanges=[result],
        )
    return XSSResult(
        finding_status="CONFIRMED",
        reason=(
            f"parameter {parameter!r} reflected the raw canary "
            f"({canary!r}) into an HTML response with no CSP header"
        ),
        parameter=parameter,
        canary=canary,
        exchanges=[result],
    )
