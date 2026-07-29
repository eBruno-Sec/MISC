# ADR-0005: MinIO Versioning for Evidence Storage

**Status:** Accepted
**Date:** 2025-01-15
**Deciders:** Architecture team

## Context

ArsGoatia stores evidence artifacts (HTTP exchanges, screenshots, DOM
snapshots, tool output) in object storage. Evidence integrity is a
non-negotiable requirement: once stored, evidence must not be silently
overwritten or deleted, because findings and audit trails depend on it.

Two levels of immutability were considered:

1. **Bucket versioning** -- Every write creates a new version. Previous
   versions are retained and addressable. Overwrites do not destroy history,
   but a sufficiently privileged actor can delete version markers.
2. **Object lock (WORM)** -- Objects are locked for a retention period and
   cannot be deleted or overwritten by anyone, including administrators.

The dev/lab environment uses MinIO as an S3-compatible object store.

## Decision

Enable **bucket versioning** on the MinIO evidence bucket for development and
lab environments. Every evidence artifact is stored with a version ID, and the
application records the version ID alongside the SHA-256 content hash in the
evidence metadata.

Object lock (WORM compliance) is deferred to production deployment.

## Consequences

**Positive:**

- **Tamper detection** -- Combined with SHA-256 content hashing, any
  modification to stored evidence is detectable by comparing the hash.
- **Accidental overwrite protection** -- Versioning ensures that even if the
  same key is written twice, both versions are preserved.
- **Simple MinIO configuration** -- Versioning requires only a bucket policy
  flag, no retention rules or compliance mode setup.
- **Evidence replay** -- Versioned objects support replaying historical
  evidence states for debugging.

**Negative:**

- **Not truly immutable** -- An operator with MinIO admin credentials can
  delete versioned objects. This is acceptable for dev/lab where the threat
  model does not include insider tampering.
- **Storage growth** -- Versioning retains all previous versions, increasing
  storage consumption. Lifecycle rules can mitigate this in dev.

## Notes

- **Production upgrade path:** Enable S3 Object Lock in Compliance mode on the
  evidence bucket with a retention period matching the organization's audit
  requirements. The application code does not change -- only the bucket
  configuration. MinIO supports Object Lock in recent versions; AWS S3
  supports it natively.
- The evidence storage module is in `packages/domain/evidence/`.
- Content hashes are computed before upload and stored in the evidence metadata
  table, providing a second integrity check independent of the storage layer.
- Related: ADR-0004 (evidence records are also signed).
