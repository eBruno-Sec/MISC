"""Passive security-headers audit.

Runs at risk tier R1 (observation only — one GET, no mutation).
Emits an info-level finding per missing/weak header. Never CONFIRMED
as a critical issue on its own; these are hygiene signals.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

TECHNIQUE_ID = "web_security_headers_audit"
CWE = "CWE-693"  # Protection Mechanism Failure


_EXPECTED_HEADERS = {
    "content-security-policy": {
        "severity": "medium",
        "note": "no CSP header — page cannot restrict script sources or inline execution",
    },
    "strict-transport-security": {
        "severity": "medium",
        "note": "no HSTS — browsers will not force HTTPS for this origin",
    },
    "x-frame-options": {
        "severity": "low",
        "note": "no X-Frame-Options — page can be framed, clickjacking risk",
    },
    "x-content-type-options": {
        "severity": "low",
        "note": "no X-Content-Type-Options — MIME sniffing enabled",
    },
    "referrer-policy": {
        "severity": "info",
        "note": "no Referrer-Policy — outbound referrers may leak paths / query strings",
    },
}


@dataclass
class HeaderIssue:
    header: str
    severity: str
    note: str

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__


@dataclass
class HeadersAuditResult:
    finding_status: str  # CONFIRMED | INCONCLUSIVE
    reason: str
    issues: list[HeaderIssue] = field(default_factory=list)
    observed_headers: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_status": self.finding_status,
            "reason": self.reason,
            "issues": [i.to_dict() for i in self.issues],
            "observed_headers": self.observed_headers,
        }


async def audit(*, client, url: str) -> HeadersAuditResult:
    try:
        r = await client.get(url)
    except Exception as exc:
        return HeadersAuditResult(
            finding_status="INCONCLUSIVE",
            reason=f"could not fetch {url}: {exc!r}",
        )

    observed = {k.lower(): v for k, v in r.headers.items()}
    issues: list[HeaderIssue] = []
    for header, meta in _EXPECTED_HEADERS.items():
        if header not in observed:
            issues.append(HeaderIssue(header=header, severity=meta["severity"], note=meta["note"]))

    # Additional weak-config checks on present headers.
    csp = observed.get("content-security-policy", "")
    if csp and "'unsafe-inline'" in csp:
        issues.append(
            HeaderIssue(
                header="content-security-policy",
                severity="medium",
                note="CSP allows 'unsafe-inline' — inline script/style not blocked",
            )
        )

    if issues:
        return HeadersAuditResult(
            finding_status="CONFIRMED",
            reason=f"{len(issues)} missing or weak security header(s) at {url}",
            issues=issues,
            observed_headers=observed,
        )
    return HeadersAuditResult(
        finding_status="INCONCLUSIVE",
        reason="all baseline security headers present with no obvious weak values",
        observed_headers=observed,
    )
