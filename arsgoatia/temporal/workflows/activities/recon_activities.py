"""Safe HTTP recon activity (§8 PRE_RECON/RECON, R1 read-only).

Runs on the safe-recon queue in worker-web (the only worker with target egress).
Every request is scope-fenced by the ScopeFirewall + target guard, rate-limited,
GET-only, and captured as immutable evidence. Discovered endpoints and the target
asset are persisted.

This is an activity, so non-determinism (HTTP, time, DB, S3) is allowed here and
kept out of the workflow.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from temporalio import activity

from evidence.poc import redact_headers
from evidence.store import EvidenceStore
from policy.scope_firewall import ScopeFirewall
from temporal.workflows.activities.recon_probe import (
    DEFAULT_PROBE_PATHS,
    derive_base_url,
    endpoint_from_url,
    plan_probes,
)

log = logging.getLogger("recon")


@activity.defn(name="safe_http_recon")
async def safe_http_recon(params: dict[str, Any]) -> dict[str, Any]:
    import httpx

    from domain.db import session_scope
    from domain import repositories as repo

    tenant_id = params["tenant_id"]
    assessment_id = params["assessment_id"]
    targets = params.get("targets", [])
    max_rps = float(params.get("max_rps", 2.0))
    probe_paths = params.get("probe_paths", DEFAULT_PROBE_PATHS)

    # Load the compiled scope from the DB when the caller didn't pass it, so the
    # workflow need not carry scope data through history.
    if not targets:
        async with session_scope(tenant_id) as session:
            targets = await repo.get_scope_targets(session, assessment_id)

    firewall = ScopeFirewall.from_targets(targets)
    base_url = params.get("base_url") or derive_base_url(targets)
    if not base_url:
        return {"status": "no_target", "assets": 0, "endpoints": 0, "evidence": 0}

    urls = plan_probes(base_url, probe_paths, firewall)
    store = EvidenceStore()
    delay = 1.0 / max_rps if max_rps > 0 else 0.0

    exchanges: list[dict[str, Any]] = []
    async with httpx.AsyncClient(follow_redirects=False, timeout=15.0) as client:
        for url in urls:
            # Re-validate immediately before the request (fail-closed).
            if not firewall.validate(url).allowed:
                continue
            try:
                resp = await client.get(url)
            except Exception as exc:  # noqa: BLE001 - network errors are recorded, not fatal
                log.warning("probe failed %s: %s", url, exc)
                if delay:
                    await asyncio.sleep(delay)
                continue
            exchanges.append(
                {
                    "method": "GET",
                    "url": url,
                    "request_headers": redact_headers(dict(resp.request.headers)),
                    "status": resp.status_code,
                    "response_headers": dict(resp.headers),
                    "body_snippet": resp.text[:2048],
                }
            )
            if delay:
                await asyncio.sleep(delay)

    execution_id = str(activity.info().workflow_run_id) if activity.in_activity() else None

    # Persist: one web_application asset + one endpoint per non-5xx probe + evidence.
    ev_count = 0
    ep_count = 0
    async with session_scope(tenant_id) as session:
        asset = await repo.create_asset(
            session,
            tenant_id=tenant_id,
            assessment_id=assessment_id,
            asset_type="web_application",
            canonical_name=base_url,
            scope_status="in_scope",
            identifiers={"base_url": base_url},
        )
        for ex in exchanges:
            stored = store.put(
                tenant_id=tenant_id,
                assessment_id=assessment_id,
                evidence_type="http_response",
                content=json.dumps(ex, sort_keys=True).encode("utf-8"),
                media_type="application/json",
                captured_by="recon",
                source_execution_id=execution_id,
                extra={"url": ex["url"], "status": ex["status"]},
            )
            await repo.create_evidence(session, tenant_id=tenant_id, fields=stored)
            ev_count += 1

            host, path = endpoint_from_url(ex["url"])
            auth = ["bearer"] if ex["status"] in (401, 403) else []
            await repo.create_endpoint(
                session,
                tenant_id=tenant_id,
                asset_id=asset.id,
                host=host,
                path_template=path,
                method="GET",
                protocol=base_url.split("://", 1)[0],
                auth_schemes=auth,
                evidence_refs=[stored["id"]],
            )
            ep_count += 1

    return {
        "status": "ok",
        "base_url": base_url,
        "assets": 1,
        "endpoints": ep_count,
        "evidence": ev_count,
        "probed": len(urls),
    }
