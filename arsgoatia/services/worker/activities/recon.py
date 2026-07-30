from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import urlparse

from temporalio import activity

PROBE_PATHS: list[str] = [
    "/",
    "/api",
    "/rest",
    "/api/v1",
    "/login",
    "/register",
    "/admin",
    "/health",
    "/swagger",
    "/openapi.json",
]


@dataclass
class ScopeRuleParam:
    type: str
    value: str


@dataclass
class ReconParams:
    target_url: str
    scope_rules: list[ScopeRuleParam]
    engagement_id: str
    tenant_id: str


@dataclass
class DiscoveredEndpoint:
    url: str
    method: str
    status_code: int
    headers: dict[str, str]
    content_type: str


@dataclass
class ReconResult:
    discovered_endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    assets: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)


def _is_in_scope(url: str, scope_rules: list[ScopeRuleParam]) -> bool:
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    for rule in scope_rules:
        if rule.type == "exact_host" and hostname == rule.value:
            return True
        if rule.type == "dns_suffix" and hostname.endswith(rule.value):
            return True
        if rule.type == "url_prefix" and url.startswith(rule.value):
            return True
    return len(scope_rules) == 0


@activity.defn
async def safe_http_recon(params: ReconParams) -> ReconResult:
    import httpx  # noqa: PLC0415

    from services.worker.activities.evidence import (  # noqa: PLC0415
        StoreEvidenceParams,
        store_evidence,
    )

    result = ReconResult()
    base = params.target_url.rstrip("/")
    assets_seen: set[str] = set()

    async with httpx.AsyncClient(
        timeout=10.0,
        follow_redirects=False,
        verify=True,
    ) as client:
        for path in PROBE_PATHS:
            probe_url = f"{base}{path}"

            if not _is_in_scope(probe_url, params.scope_rules):
                activity.logger.info("Skipping out-of-scope URL", extra={"url": probe_url})
                continue

            activity.heartbeat(f"probing {path}")

            try:
                response = await client.get(probe_url)
            except httpx.HTTPError as exc:
                activity.logger.warning(
                    "Probe failed",
                    extra={"url": probe_url, "error": str(exc)},
                )
                continue

            content_type = response.headers.get("content-type", "")
            endpoint = DiscoveredEndpoint(
                url=probe_url,
                method="GET",
                status_code=response.status_code,
                headers=dict(response.headers),
                content_type=content_type,
            )
            result.discovered_endpoints.append(endpoint)

            parsed_host = urlparse(probe_url).hostname or ""
            if parsed_host and parsed_host not in assets_seen:
                assets_seen.add(parsed_host)
                result.assets.append(parsed_host)

            evidence_payload = json.dumps(
                {
                    "request": {"method": "GET", "url": probe_url},
                    "response": {
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "body_length": len(response.content),
                    },
                },
                sort_keys=True,
            ).encode()

            evidence_id = await store_evidence(
                StoreEvidenceParams(
                    engagement_id=params.engagement_id,
                    tenant_id=params.tenant_id,
                    action_id=f"recon-{path.strip('/').replace('/', '-') or 'root'}",
                    kind="http_exchange",
                    media_type="application/json",
                    payload=evidence_payload,
                )
            )
            result.evidence_refs.append(evidence_id)

    activity.logger.info(
        "Recon complete",
        extra={
            "endpoints_found": len(result.discovered_endpoints),
            "assets_found": len(result.assets),
        },
    )
    return result
