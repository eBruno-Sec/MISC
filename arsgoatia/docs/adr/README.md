# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for the ArsGoatia
security validation platform. Each ADR captures a significant architectural
choice, its context, and consequences.

## Index

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-react-vite-over-nextjs.md) | React + Vite over Next.js | Accepted |
| [0002](0002-postgres-outbox-over-nats.md) | PostgreSQL transactional outbox over NATS | Accepted |
| [0003](0003-single-node-compose.md) | Single-node Docker Compose for dev/lab | Accepted |
| [0004](0004-hmac-dev-signing.md) | HMAC-SHA256 for dev signing | Accepted |
| [0005](0005-minio-versioning.md) | MinIO versioning for evidence storage | Accepted |
| [0006](0006-local-secret-store.md) | Local secret store for dev | Accepted |
| [0007](0007-openrouter-default.md) | OpenRouter free-model default for AI | Accepted |
| [0008](0008-chain-severity-method.md) | ArsGoatia chain-severity method | Accepted |

## Format

Each ADR follows a standard template:

- **Status** -- Proposed, Accepted, Deprecated, or Superseded
- **Date** -- When the decision was made
- **Deciders** -- Who was involved
- **Context** -- Why the decision was needed
- **Decision** -- What was decided
- **Consequences** -- Positive and negative outcomes
- **Notes** -- Production upgrade path, references
