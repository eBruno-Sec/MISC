"""ArsGoatia tools — reusable runners and parsers for adapter implementations.

Tools are leaf-level executors that adapters compose. Each tool:
- Takes a validated, scope-checked input
- Produces normalized output + evidence references
- Has no policy authority (adapters enforce envelopes)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolResult:
    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    evidence_digests: list[str] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class HttpExchange:
    method: str
    url: str
    request_headers: dict[str, str]
    request_body: bytes | None
    status_code: int
    response_headers: dict[str, str]
    response_body: bytes
    duration_ms: float
    resolved_address: str | None = None


def normalize_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k.lower().strip(): v.strip() for k, v in headers.items()}


def extract_content_type(headers: dict[str, str]) -> str:
    normalized = normalize_headers(headers)
    ct = normalized.get("content-type", "application/octet-stream")
    return ct.split(";")[0].strip()


def compute_body_fingerprint(body: bytes) -> str:
    import hashlib
    return "sha256:" + hashlib.sha256(body).hexdigest()


def redact_exchange_headers(exchange: HttpExchange) -> HttpExchange:
    from packages.domain.evidence import redact_headers
    return HttpExchange(
        method=exchange.method,
        url=exchange.url,
        request_headers=redact_headers(exchange.request_headers),
        request_body=exchange.request_body,
        status_code=exchange.status_code,
        response_headers=redact_headers(exchange.response_headers),
        response_body=exchange.response_body,
        duration_ms=exchange.duration_ms,
        resolved_address=exchange.resolved_address,
    )
