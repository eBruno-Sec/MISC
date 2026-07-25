"""HTTP tool executor (§21).

preflight_verify (pure): re-verify the signed envelope and re-run the scope
firewall on every target — the authorization check that queue routing is NOT
(§10.11). execute (async): after preflight, resolve DNS, apply the SSRF policy on
the resolved address, inject the runtime secret, perform the request, and hand the
raw exchange to an evidence sink. Any failure fails closed to policy_denied.
"""

from __future__ import annotations

import logging
import socket
from datetime import datetime, timezone
from typing import Awaitable, Callable
from urllib.parse import urlparse

from policy.envelope import verify
from policy.scope_firewall import ScopeFirewall, is_ssrf_blocked
from schemas.tool_io import ExitState, ToolRequest, ToolResult

log = logging.getLogger("tool-sdk")

SecretGetter = Callable[[str], Awaitable[str]]
EvidenceSink = Callable[[dict], Awaitable[str]]


def preflight_verify(
    request: ToolRequest,
    *,
    signing_key: str,
    firewall: ScopeFirewall,
    expected_revision: int | None = None,
    expected_policy_revision: int | None = None,
) -> tuple[bool, str]:
    """Pure: envelope signature/expiry/revision + scope for every target."""
    env = request.action_envelope
    ok, reason = verify(
        env,
        signing_key,
        expected_revision=expected_revision,
        expected_policy_revision=expected_policy_revision,
    )
    if not ok:
        return False, f"envelope:{reason}"
    for target in env.targets:
        decision = firewall.validate(target.resolved_destination)
        if not decision.allowed:
            return False, f"scope:{decision.reason}"
    return True, "ok"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
        return sorted({i[4][0] for i in infos})
    except Exception:  # noqa: BLE001 - unresolvable host -> caller fails closed
        return []


async def execute(
    request: ToolRequest,
    *,
    signing_key: str,
    firewall: ScopeFirewall,
    secret_getter: SecretGetter | None = None,
    evidence_sink: EvidenceSink | None = None,
    expected_revision: int | None = None,
    expected_policy_revision: int | None = None,
    allow_private: bool = True,
) -> ToolResult:
    import httpx

    started = _now()

    def _denied(reason: str) -> ToolResult:
        return ToolResult(
            exit_state=ExitState.POLICY_DENIED,
            started_at=started,
            finished_at=_now(),
            warnings=[reason],
        )

    ok, reason = preflight_verify(
        request,
        signing_key=signing_key,
        firewall=firewall,
        expected_revision=expected_revision,
        expected_policy_revision=expected_policy_revision,
    )
    if not ok:
        return _denied(reason)

    params = request.parameters or {}
    url = params.get("url")
    method = (params.get("method") or "GET").upper()
    if not url:
        return _denied("no_url")

    # Resolve + SSRF policy on the resolved address (§13.4 steps 1-6). Link-local
    # / loopback / metadata are blocked even in lab; private only when allowed.
    host = urlparse(url).hostname or ""
    resolved = _resolve(host)
    if not resolved:
        return _denied("dns_unresolved")
    for ip in resolved:
        if is_ssrf_blocked(ip, allow_private=allow_private):
            return _denied(f"ssrf_blocked:{ip}")

    # Runtime secret injection — fetched by uri, never logged or returned.
    headers = dict(params.get("headers") or {})
    secret_uri = params.get("secret_uri")
    if secret_uri and secret_getter is not None:
        token = await secret_getter(secret_uri)
        headers["Authorization"] = f"Bearer {token}"

    budget = request.action_envelope.budget
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=budget.timeout_seconds) as client:
            resp = await client.request(method, url, headers=headers)
    except Exception as exc:  # noqa: BLE001
        log.warning("tool request failed: %s", exc)
        return ToolResult(
            exit_state=ExitState.FAILED, started_at=started, finished_at=_now(), warnings=[str(exc)]
        )

    # Build the redacted exchange for evidence (Authorization masked by the sink's
    # redactor; we never place the raw token in normalized_output).
    exchange = {
        "method": method,
        "url": url,
        "request_headers": {k: ("<redacted>" if k.lower() == "authorization" else v)
                            for k, v in headers.items()},
        "status": resp.status_code,
        "response_headers": dict(resp.headers),
        "body_snippet": resp.text[:4096],
    }
    evidence_id = await evidence_sink(exchange) if evidence_sink else None

    body_json = None
    try:
        body_json = resp.json()
    except Exception:  # noqa: BLE001 - non-JSON response
        body_json = None

    return ToolResult(
        exit_state=ExitState.SUCCESS,
        started_at=started,
        finished_at=_now(),
        normalized_output={"status": resp.status_code, "json": body_json},
        raw_output_evidence_ref=evidence_id,
    )
