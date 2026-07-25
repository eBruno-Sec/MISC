# ADR 0003 — Dev-grade signing, secret store, and evidence immutability

- Status: Accepted (slice)
- Date: 2026-07-25

## Context
Production calls for asymmetric/KMS envelope signing, a secret manager (e.g.
Vault), and WORM/object-lock evidence storage. The vertical slice runs on a
single-node Docker Compose stack.

## Decision
For development:
- **Envelope signing** (§13.5): HMAC-SHA256 over canonical JSON, key derived from
  `SESSION_SECRET`. The envelope *shape* and verify path are production-identical;
  only the signer changes.
- **Secret store** (§10 secret handling): a local encrypted store addressed by
  `secret_uri`. Raw secret material never enters Postgres canonical rows, the
  graph, AI prompts, or Temporal history — only a `secret_uri` + sha256 fingerprint.
- **Evidence immutability** (§16): MinIO bucket versioning + content-hash
  verification, `EVIDENCE_ENABLE_OBJECT_LOCK=false`. Append-only semantics and
  derivative-on-redaction are enforced in code.

## Consequences
- The interfaces (`sign`/`verify`, `secret_uri` indirection, content-addressed
  put/get) are stable across the dev→prod boundary; only the backing
  implementation is swapped (KMS, Vault, object-lock) with no caller changes.
