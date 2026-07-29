# ADR-0004: HMAC-SHA256 for Dev Signing

**Status:** Accepted
**Date:** 2025-01-15
**Deciders:** Architecture team

## Context

ArsGoatia signs several artifacts to ensure integrity and authenticity:

- **Action envelopes** -- Every autonomous action the platform takes is wrapped
  in a signed envelope before execution.
- **Evidence records** -- Stored evidence includes a signature to detect
  tampering.
- **API tokens** -- JWT-based authentication tokens for operator sessions.

The signing mechanism must be pluggable so that dev and production environments
can use different key management strategies. For development, simplicity and
speed are priorities; for production, key protection and non-repudiation are
priorities.

Two approaches were evaluated for dev:

1. **Asymmetric keys (RSA/ECDSA) from day one** -- Generate a local key pair,
   store the private key on disk.
2. **HMAC-SHA256 with a shared secret** -- Use a symmetric key stored in an
   environment variable or local config.

## Decision

Use HMAC-SHA256 as the default signing mechanism for development environments.
The signing key is a 256-bit secret loaded from the environment variable
`ARSGOATIA_SIGNING_KEY` (or a local config file). The `packages/crypto` module
abstracts signing behind a `Signer` interface so that the algorithm can be
swapped without changing callers.

## Consequences

**Positive:**

- **Simple setup** -- No key-pair generation, no certificate management, no
  key-file permissions to configure for local dev.
- **Fast** -- HMAC-SHA256 is significantly faster than RSA or ECDSA signing,
  which matters when signing every action envelope in a test run.
- **Deterministic in tests** -- A fixed HMAC key produces deterministic
  signatures, making test assertions straightforward.

**Negative:**

- **No non-repudiation** -- HMAC is symmetric; any party with the key can
  produce valid signatures. This is acceptable in a single-operator dev
  environment but insufficient for production audit trails.
- **Key distribution** -- If multiple services need to verify signatures, they
  all need the same secret. In dev this is trivial (shared env var); in
  production this would be a security concern.

## Notes

- **Production upgrade path:** Replace the HMAC signer with an asymmetric
  signer backed by a KMS (AWS KMS, HashiCorp Vault Transit, or a local HSM).
  The `Signer` interface in `packages/crypto` is designed for this swap. The
  envelope schema includes an `algorithm` field so verifiers can select the
  correct verification path.
- The `ARSGOATIA_SIGNING_KEY` must be at least 32 bytes. The dev default is
  generated on first run if not set.
- Related: ADR-0006 (local secret store holds the signing key in dev).
