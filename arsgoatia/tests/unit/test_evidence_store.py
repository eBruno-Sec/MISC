"""Evidence store pure helpers (hash, §16 key layout, metadata)."""

from __future__ import annotations

from evidence.store import (
    artifact_key,
    build_metadata,
    metadata_key,
    sha256_hex,
)


def test_sha256_is_stable():
    assert sha256_hex(b"hello") == sha256_hex(b"hello")
    assert sha256_hex(b"hello") != sha256_hex(b"world")


def test_key_layout_matches_spec():
    a = artifact_key("t1", "a1", "e1")
    m = metadata_key("t1", "a1", "e1")
    assert a == "tenant/t1/assessment/a1/evidence/e1/artifact"
    assert m == "tenant/t1/assessment/a1/evidence/e1/metadata.json"


def test_metadata_records_hash_and_provenance():
    meta = build_metadata(
        evidence_id="e1",
        assessment_id="a1",
        tenant_id="t1",
        evidence_type="http_response",
        sha256="abc",
        size_bytes=10,
        media_type="application/json",
        captured_by="recon",
        source_execution_id="run-1",
        redaction_state="redacted",
        sensitivity="confidential",
        extra={"url": "http://juice-shop:3000/"},
    )
    assert meta["sha256"] == "abc"
    assert meta["redaction_state"] == "redacted"
    assert meta["captured_by"] == "recon"
    assert meta["metadata"]["url"] == "http://juice-shop:3000/"
