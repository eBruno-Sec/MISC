# ADR 0002 — PostgreSQL transactional outbox instead of NATS

- Status: Accepted (slice)
- Date: 2026-07-25

## Context
The spec's event architecture (§9) requires immutable events, at-least-once
delivery, idempotent consumers, and a transactional outbox/inbox pattern. The
`.env.example` (§34) lists both `EVENT_BUS_DRIVER=postgres_outbox` and a
`NATS_URL`, leaving the driver configurable.

## Decision
Use `EVENT_BUS_DRIVER=postgres_outbox`. Events are written to an `outbox` table in
the same transaction as the state change; a relay poller dispatches them. Consumer
idempotency is keyed on `event_id`.

## Consequences
- One fewer piece of infrastructure to run in dev; the transaction boundary makes
  the outbox write atomic with the domain change.
- NATS remains a future swap behind the same `EventEnvelope` (§9) contract; no
  producer/consumer code changes when the driver changes.
- Temporal still owns orchestration durability; the event bus does not.
