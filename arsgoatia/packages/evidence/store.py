"""Content-addressed evidence store (§16).

S3/MinIO layout:
  tenant/{tenant_id}/assessment/{assessment_id}/evidence/{evidence_id}/artifact
  tenant/{tenant_id}/assessment/{assessment_id}/evidence/{evidence_id}/metadata.json

Every artifact is hashed (sha256) and the hash is stored in append-only
metadata; corrections/redactions create derivative evidence rather than
overwriting (the bucket is versioned). Downloads use short-lived signed URLs.

The pure helpers (hash, key layout, metadata) are separated from boto3 I/O so
they are unit-testable without a running MinIO.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4

from config.settings import get_settings


# --------------------------------------------------------------------------- #
# Pure helpers (no I/O)
# --------------------------------------------------------------------------- #
def sha256_hex(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def evidence_prefix(tenant_id: str, assessment_id: str, evidence_id: str) -> str:
    return f"tenant/{tenant_id}/assessment/{assessment_id}/evidence/{evidence_id}"


def artifact_key(tenant_id: str, assessment_id: str, evidence_id: str) -> str:
    return f"{evidence_prefix(tenant_id, assessment_id, evidence_id)}/artifact"


def metadata_key(tenant_id: str, assessment_id: str, evidence_id: str) -> str:
    return f"{evidence_prefix(tenant_id, assessment_id, evidence_id)}/metadata.json"


def build_metadata(
    *,
    evidence_id: str,
    assessment_id: str,
    tenant_id: str,
    evidence_type: str,
    sha256: str,
    size_bytes: int,
    media_type: str,
    captured_by: str,
    source_execution_id: str | None,
    redaction_state: str,
    sensitivity: str,
    extra: dict | None,
) -> dict:
    return {
        "evidence_id": evidence_id,
        "assessment_id": assessment_id,
        "tenant_id": tenant_id,
        "evidence_type": evidence_type,
        "sha256": sha256,
        "size_bytes": size_bytes,
        "media_type": media_type,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "captured_by": captured_by,
        "source_execution_id": source_execution_id,
        "redaction_state": redaction_state,
        "sensitivity": sensitivity,
        "metadata": extra or {},
    }


# --------------------------------------------------------------------------- #
# Store (boto3 I/O)
# --------------------------------------------------------------------------- #
class EvidenceStore:
    def __init__(self, client=None, bucket: str | None = None) -> None:
        self._client = client
        settings = get_settings()
        self._bucket = bucket or settings.s3_bucket

    def _s3(self):
        if self._client is None:
            import boto3

            settings = get_settings()
            self._client = boto3.client(
                "s3",
                endpoint_url=settings.s3_endpoint_url,
                aws_access_key_id=settings.s3_access_key_id,
                aws_secret_access_key=settings.s3_secret_access_key,
                region_name=settings.s3_region,
            )
        return self._client

    def put(
        self,
        *,
        tenant_id: str,
        assessment_id: str,
        evidence_type: str,
        content: bytes,
        media_type: str = "application/octet-stream",
        captured_by: str = "system",
        source_execution_id: str | None = None,
        redaction_state: str = "redacted",
        sensitivity: str | None = None,
        extra: dict | None = None,
    ) -> dict:
        """Store an artifact + metadata; return the Evidence record fields."""
        settings = get_settings()
        evidence_id = str(uuid4())
        digest = sha256_hex(content)
        a_key = artifact_key(tenant_id, assessment_id, evidence_id)
        m_key = metadata_key(tenant_id, assessment_id, evidence_id)
        meta = build_metadata(
            evidence_id=evidence_id,
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            evidence_type=evidence_type,
            sha256=digest,
            size_bytes=len(content),
            media_type=media_type,
            captured_by=captured_by,
            source_execution_id=source_execution_id,
            redaction_state=redaction_state,
            sensitivity=sensitivity or settings.evidence_default_sensitivity,
            extra=extra,
        )
        s3 = self._s3()
        s3.put_object(Bucket=self._bucket, Key=a_key, Body=content, ContentType=media_type)
        s3.put_object(
            Bucket=self._bucket,
            Key=m_key,
            Body=json.dumps(meta, sort_keys=True).encode("utf-8"),
            ContentType="application/json",
        )
        return {
            "id": evidence_id,
            "assessment_id": assessment_id,
            "evidence_type": evidence_type,
            "object_uri": f"s3://{self._bucket}/{a_key}",
            "sha256": digest,
            "size_bytes": len(content),
            "media_type": media_type,
            "captured_by": captured_by,
            "source_execution_id": source_execution_id,
            "redaction_state": redaction_state,
            "sensitivity": meta["sensitivity"],
            "metadata": meta["metadata"],
        }

    def get(self, object_uri: str) -> bytes:
        bucket, key = _parse_s3_uri(object_uri)
        obj = self._s3().get_object(Bucket=bucket, Key=key)
        return obj["Body"].read()

    def verify(self, object_uri: str, expected_sha256: str) -> bool:
        return sha256_hex(self.get(object_uri)) == expected_sha256

    def signed_url(self, object_uri: str, expires_seconds: int = 900) -> str:
        bucket, key = _parse_s3_uri(object_uri)
        return self._s3().generate_presigned_url(
            "get_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=expires_seconds
        )


def _parse_s3_uri(object_uri: str) -> tuple[str, str]:
    assert object_uri.startswith("s3://"), "not an s3 uri"
    rest = object_uri[len("s3://") :]
    bucket, _, key = rest.partition("/")
    return bucket, key
