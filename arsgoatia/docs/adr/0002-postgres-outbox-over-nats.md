# ADR-0002: PostgreSQL Transactional Outbox over NATS

**Status:** Accepted
**Date:** 2025-01-15
**Deciders:** Architecture team

## Context

ArsGoatia's workflow engine publishes domain events when state changes occur
(engagement started, finding confirmed, evidence stored, etc.). These events
drive downstream processes: the policy engine evaluates them, the reporting
subsystem indexes them, and the audit log records them.

Two patterns were considered:

1. **NATS / dedicated message broker** -- Publish events to a NATS JetStream
   subject directly from the application layer.
2. **PostgreSQL transactional outbox** -- Write events to an `outbox` table in
   the same transaction as the domain write, then poll/notify to dispatch them.

The critical requirement is **transactional consistency**: if a finding is
persisted, its corresponding event must also be persisted -- atomically. A
dual-write to both Postgres and NATS introduces the classic "exactly-once"
problem and requires compensating transactions or sagas.

## Decision

Use the PostgreSQL transactional outbox pattern. Domain events are inserted
into the `events.outbox` table in the same database transaction as the
aggregate write. A lightweight dispatcher process polls the outbox (or listens
via `NOTIFY`) and forwards events to in-process subscribers.

No external message broker is required for the dev/lab deployment.

## Consequences

**Positive:**

- **Atomic consistency** -- Events and domain state are committed in a single
  transaction. No dual-write risk.
- **Fewer moving parts** -- No NATS cluster to deploy, configure, or monitor in
  the dev/lab stack.
- **Replay-friendly** -- The outbox table is an ordered, durable event log.
  Events can be replayed for debugging or rebuilding read models.
- **Simpler failure mode** -- If the dispatcher crashes, events remain in the
  outbox and are delivered on restart. No lost messages.

**Negative:**

- **Polling latency** -- Event dispatch has slightly higher latency than a
  push-based broker (mitigated by PostgreSQL `LISTEN/NOTIFY`).
- **Database load** -- High-throughput scenarios add read pressure to
  PostgreSQL. For lab-scale workloads this is negligible.
- **Single-node ceiling** -- The outbox pattern does not natively fan out to
  multiple consumer groups the way a broker does.

## Notes

- **Production upgrade path:** When horizontal scaling or multi-service
  consumption is needed, introduce NATS JetStream (or equivalent) as a relay
  downstream of the outbox. The outbox remains the source of truth; the broker
  becomes a distribution layer. This preserves transactional guarantees while
  adding fan-out.
- The outbox schema is defined in `infrastructure/postgres/init.sql`.
- Related: ADR-0003 (single-node Compose topology).
