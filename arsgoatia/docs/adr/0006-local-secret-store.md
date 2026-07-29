# ADR-0006: Local Secret Store for Dev

**Status:** Accepted
**Date:** 2025-01-15
**Deciders:** Architecture team

## Context

ArsGoatia requires access to several secrets at runtime:

- **Signing keys** (see ADR-0004) for action envelopes and evidence.
- **Database credentials** for PostgreSQL.
- **Object storage credentials** for MinIO.
- **API keys** for external services (OpenRouter, etc.).
- **Target application credentials** bootstrapped for test identities.

In production, secrets should be managed by a dedicated secrets manager
(HashiCorp Vault, AWS Secrets Manager, etc.) with access control, rotation,
and audit logging. For development, this infrastructure is unnecessary overhead.

## Decision

Use a local in-memory/file-based secret store for development. Secrets are
loaded from environment variables or a `.env` file at startup and held in
memory by the `packages/config` module. No external secrets manager is required
for the dev/lab deployment.

The secret store is accessed through an abstract `SecretProvider` interface so
that production implementations can be swapped in without changing application
code.

## Consequences

**Positive:**

- **Zero external dependencies** -- No Vault server to deploy, unseal, or
  configure in the dev stack.
- **Fast startup** -- Secrets are available immediately from environment
  variables; no network calls to a secrets manager.
- **Simple onboarding** -- New developers copy `.env.example` to `.env` and
  start working.

**Negative:**

- **No rotation** -- Secrets in a `.env` file are static. Rotation requires
  restarting the application.
- **No access control** -- Any process on the host can read environment
  variables. Acceptable for a local dev machine; unacceptable for shared
  environments.
- **No audit trail** -- Secret access is not logged. Production compliance
  requirements demand audit logging of secret retrieval.

## Notes

- **Production upgrade path:** Implement a `VaultSecretProvider` that reads
  secrets from HashiCorp Vault (or equivalent) using AppRole or Kubernetes
  auth. The `SecretProvider` interface in `packages/config` is designed for
  this swap. Rotate the HMAC signing key via Vault's Transit backend.
- `.env` files are listed in `.gitignore`. A `.env.example` with placeholder
  values is committed.
- Related: ADR-0004 (signing key is one of the managed secrets).
