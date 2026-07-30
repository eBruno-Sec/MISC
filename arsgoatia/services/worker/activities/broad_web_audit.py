"""Broad web-audit activity — runs every non-authz technique pack against
each in-scope, parameterised endpoint discovered by recon.

Emits one finding per CONFIRMED pack result and stores per-exchange
evidence. Keeps everything deterministic — no LLM in the control path.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlparse

from temporalio import activity


@dataclass
class BroadWebAuditParams:
    engagement_id: str
    tenant_id: str
    action_id: str
    endpoints: list[dict[str, Any]]  # {"url": str, "content_type": str}
    # Optional shared bearer token — used when authz-context tokens are
    # helpful (e.g. testing an authenticated endpoint). May be empty.
    token: str = ""


@dataclass
class BroadWebFinding:
    technique_id: str
    weakness: str
    target: str
    severity: str  # info | low | medium | high | critical
    status: str  # CONFIRMED
    reason: str
    evidence_refs: list[str] = field(default_factory=list)


@dataclass
class BroadWebAuditResult:
    findings: list[BroadWebFinding] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)


async def _store(store_fn, params: BroadWebAuditParams, label: str, payload: dict) -> str:
    """Persist one evidence artifact and return its digest reference."""
    from services.worker.activities.evidence import StoreEvidenceParams

    body = json.dumps(payload, sort_keys=True, default=str).encode()
    ref = await store_fn(
        StoreEvidenceParams(
            engagement_id=params.engagement_id,
            tenant_id=params.tenant_id,
            action_id=f"{params.action_id}-{label}",
            kind=f"broad_audit_{label}",
            media_type="application/json",
            payload=body,
        )
    )
    return ref


@activity.defn
async def run_broad_web_audit(params: BroadWebAuditParams) -> BroadWebAuditResult:
    import httpx  # noqa: PLC0415

    from packs.techniques.web_injection.path_traversal import (  # noqa: PLC0415
        probe as traversal_probe,
    )
    from packs.techniques.web_injection.reflected_xss import (  # noqa: PLC0415
        probe as xss_probe,
    )
    from packs.techniques.web_injection.sqli import probe as sqli_probe  # noqa: PLC0415
    from packs.techniques.web_passive.security_headers import audit as headers_audit  # noqa: PLC0415
    from services.worker.activities.evidence import store_evidence  # noqa: PLC0415

    result = BroadWebAuditResult()

    async with httpx.AsyncClient(timeout=15.0, follow_redirects=False, verify=True) as client:
        for ep in params.endpoints:
            url = ep.get("url", "")
            if not url:
                continue
            activity.heartbeat(f"auditing {url}")

            # --- Passive headers audit — every endpoint gets one -----------
            try:
                headers_result = await headers_audit(client=client, url=url)
            except Exception as exc:
                activity.logger.warning(f"headers audit failed for {url}: {exc}")
                headers_result = None
            if headers_result and headers_result.finding_status == "CONFIRMED":
                ref = await _store(
                    store_evidence,
                    params,
                    f"headers-{urlparse(url).path.strip('/').replace('/', '_') or 'root'}",
                    headers_result.to_dict(),
                )
                result.evidence_refs.append(ref)
                # Highest-severity issue drives the finding's severity.
                sev_order = ["critical", "high", "medium", "low", "info"]
                worst = min(
                    (i.severity for i in headers_result.issues),
                    key=lambda s: sev_order.index(s) if s in sev_order else 99,
                    default="info",
                )
                result.findings.append(
                    BroadWebFinding(
                        technique_id="web_security_headers_audit",
                        weakness="Missing security headers",
                        target=url,
                        severity=worst,
                        status="CONFIRMED",
                        reason=headers_result.reason,
                        evidence_refs=[ref],
                    )
                )

            # --- Active probes need at least one query parameter -----------
            parsed = urlparse(url)
            params_in_url = [k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]
            if not params_in_url:
                continue

            for parameter in params_in_url:
                # SQLi
                try:
                    sqli_res = await sqli_probe(
                        client=client,
                        url=url,
                        parameter=parameter,
                        token=params.token or None,
                    )
                except Exception as exc:
                    activity.logger.warning(f"sqli probe failed on {url}/{parameter}: {exc}")
                    sqli_res = None
                if sqli_res and sqli_res.finding_status == "CONFIRMED":
                    ref = await _store(
                        store_evidence,
                        params,
                        f"sqli-{parameter}",
                        sqli_res.to_dict(),
                    )
                    result.evidence_refs.append(ref)
                    result.findings.append(
                        BroadWebFinding(
                            technique_id="web_sqli_reflected",
                            weakness="SQL injection",
                            target=f"{url}?{parameter}",
                            severity="high",
                            status="CONFIRMED",
                            reason=sqli_res.reason,
                            evidence_refs=[ref],
                        )
                    )

                # Reflected XSS
                try:
                    xss_res = await xss_probe(
                        client=client,
                        url=url,
                        parameter=parameter,
                        token=params.token or None,
                    )
                except Exception as exc:
                    activity.logger.warning(f"xss probe failed on {url}/{parameter}: {exc}")
                    xss_res = None
                if xss_res and xss_res.finding_status == "CONFIRMED":
                    ref = await _store(
                        store_evidence,
                        params,
                        f"xss-{parameter}",
                        xss_res.to_dict(),
                    )
                    result.evidence_refs.append(ref)
                    result.findings.append(
                        BroadWebFinding(
                            technique_id="web_xss_reflected",
                            weakness="Reflected XSS",
                            target=f"{url}?{parameter}",
                            severity="high",
                            status="CONFIRMED",
                            reason=xss_res.reason,
                            evidence_refs=[ref],
                        )
                    )

                # Path traversal
                try:
                    trav_res = await traversal_probe(
                        client=client,
                        url=url,
                        parameter=parameter,
                        token=params.token or None,
                    )
                except Exception as exc:
                    activity.logger.warning(f"traversal probe failed on {url}/{parameter}: {exc}")
                    trav_res = None
                if trav_res and trav_res.finding_status == "CONFIRMED":
                    ref = await _store(
                        store_evidence,
                        params,
                        f"traversal-{parameter}",
                        trav_res.to_dict(),
                    )
                    result.evidence_refs.append(ref)
                    result.findings.append(
                        BroadWebFinding(
                            technique_id="web_path_traversal",
                            weakness="Path traversal / LFI",
                            target=f"{url}?{parameter}",
                            severity="critical",
                            status="CONFIRMED",
                            reason=trav_res.reason,
                            evidence_refs=[ref],
                        )
                    )

    activity.logger.info(
        "broad web audit complete",
        extra={
            "endpoints_audited": len(params.endpoints),
            "confirmed_findings": len(result.findings),
        },
    )
    return result
