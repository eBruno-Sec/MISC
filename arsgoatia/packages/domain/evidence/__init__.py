from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True)
class EvidenceArtifact:
    digest: str
    size: int
    media_type: str
    storage_uri: str


@dataclass(frozen=True)
class CaptureContext:
    started_at: datetime
    completed_at: datetime
    runner_id: str
    adapter_digest: str
    resolved_peer: str
    tls_peer_digest: str | None = None


@dataclass(frozen=True)
class RedactionRecord:
    profile: str
    source_digest: str
    operations_count: int
    restricted_original_uri: str | None = None


@dataclass(frozen=True)
class LineageRef:
    parent_evidence_id: UUID
    relation: str


@dataclass(frozen=True)
class EvidenceRecord:
    id: UUID
    tenant_id: UUID
    engagement_id: UUID
    action_id: UUID
    kind: str
    artifact: EvidenceArtifact
    capture: CaptureContext
    redaction: RedactionRecord | None = None
    lineage: list[LineageRef] = field(default_factory=list)
    sensitivity: str = "restricted"
    retention_policy: str = "engagement-plus-365d"


def compute_digest(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def verify_digest(data: bytes, expected_digest: str) -> bool:
    return compute_digest(data) == expected_digest


def storage_key(tenant_id: UUID, digest: str) -> str:
    alg, hex_val = digest.split(":", 1)
    return f"tenants/{tenant_id}/{alg}/{hex_val[:2]}/{hex_val}"


SECRET_PATTERNS = frozenset(
    {
        "bearer ",
        "eyj",
        "basic ",
        "set-cookie",
        "authorization:",
        "x-api-key:",
        "password",
        "secret",
        "token",
        "apikey",
        "aws_secret",
        "private_key",
    }
)


def contains_secret_marker(text: str) -> bool:
    lower = text.lower()
    return any(marker in lower for marker in SECRET_PATTERNS)


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    sensitive_keys = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"}
    result = {}
    for k, v in headers.items():
        if k.lower() in sensitive_keys:
            result[k] = "[REDACTED]"
        elif contains_secret_marker(v):
            result[k] = "[REDACTED]"
        else:
            result[k] = v
    return result


def to_curl(method: str, url: str, headers: dict[str, str], body: str | None = None) -> str:
    safe_headers = redact_headers(headers)
    parts = [f"curl -X {method}"]
    for k, v in safe_headers.items():
        parts.append(f"  -H '{k}: {v}'")
    if body:
        parts.append(f"  -d '{body}'")
    parts.append(f"  '{url}'")
    return " \\\n".join(parts)
