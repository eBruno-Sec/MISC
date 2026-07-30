"""ArsGoatia event system — transactional outbox and relay.

Per §7.7: PostgreSQL outbox for the first release; driver contract permits
NATS JetStream later. Events include event_id, event_type, schema_version,
tenant_id, aggregate info, causation/correlation IDs, actor, occurred time,
trace context, classification, and payload. Consumers are idempotent;
ordering is guaranteed only per aggregate. Unknown versions are quarantined.
"""

from __future__ import annotations

import enum
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Protocol, runtime_checkable
from uuid import UUID, uuid4

# ---------------------------------------------------------------------------
# Outbox entry
# ---------------------------------------------------------------------------


class DeliveryStatus(enum.Enum):
    PENDING = "pending"
    DISPATCHED = "dispatched"
    FAILED = "failed"
    DEAD_LETTER = "dead_letter"


@dataclass
class OutboxEntry:
    entry_id: UUID
    event_id: UUID
    event_type: str
    tenant_id: UUID
    aggregate_type: str
    aggregate_id: UUID
    payload: dict[str, Any]
    status: DeliveryStatus = DeliveryStatus.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    dispatched_at: datetime | None = None
    attempts: int = 0
    max_attempts: int = 5
    last_error: str | None = None


# ---------------------------------------------------------------------------
# Outbox writer port
# ---------------------------------------------------------------------------


@runtime_checkable
class OutboxWriter(Protocol):
    def write(self, entry: OutboxEntry) -> None: ...

    def mark_dispatched(self, entry_id: UUID) -> None: ...

    def mark_failed(self, entry_id: UUID, error: str) -> None: ...

    def mark_dead_letter(self, entry_id: UUID) -> None: ...

    def get_pending(self, batch_size: int = 100) -> list[OutboxEntry]: ...

    def get_dead_letters(self, tenant_id: UUID | None = None) -> list[OutboxEntry]: ...


# ---------------------------------------------------------------------------
# Event handler / subscriber
# ---------------------------------------------------------------------------

EventHandler = Callable[[OutboxEntry], None]


class EventSubscription:
    def __init__(self) -> None:
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)
        self._global_handlers: list[EventHandler] = []

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        self._handlers[event_type].append(handler)

    def subscribe_all(self, handler: EventHandler) -> None:
        self._global_handlers.append(handler)

    def get_handlers(self, event_type: str) -> list[EventHandler]:
        return self._global_handlers + self._handlers.get(event_type, [])


# ---------------------------------------------------------------------------
# Relay — polls outbox and dispatches to subscribers
# ---------------------------------------------------------------------------


class OutboxRelay:
    def __init__(
        self,
        writer: OutboxWriter,
        subscriptions: EventSubscription,
        batch_size: int = 100,
    ) -> None:
        self._writer = writer
        self._subscriptions = subscriptions
        self._batch_size = batch_size
        self._processed_count = 0

    @property
    def processed_count(self) -> int:
        return self._processed_count

    def poll_and_dispatch(self) -> int:
        entries = self._writer.get_pending(self._batch_size)
        dispatched = 0

        for entry in entries:
            handlers = self._subscriptions.get_handlers(entry.event_type)
            if not handlers:
                self._writer.mark_dispatched(entry.entry_id)
                dispatched += 1
                self._processed_count += 1
                continue

            try:
                for handler in handlers:
                    handler(entry)
                self._writer.mark_dispatched(entry.entry_id)
                dispatched += 1
                self._processed_count += 1
            except Exception as exc:
                entry.attempts += 1
                if entry.attempts >= entry.max_attempts:
                    self._writer.mark_dead_letter(entry.entry_id)
                else:
                    self._writer.mark_failed(entry.entry_id, str(exc))

        return dispatched


# ---------------------------------------------------------------------------
# Convenience: create an outbox entry from a domain event dict
# ---------------------------------------------------------------------------


def create_outbox_entry(
    event_type: str,
    tenant_id: UUID,
    aggregate_type: str,
    aggregate_id: UUID,
    payload: dict[str, Any] | None = None,
) -> OutboxEntry:
    return OutboxEntry(
        entry_id=uuid4(),
        event_id=uuid4(),
        event_type=event_type,
        tenant_id=tenant_id,
        aggregate_type=aggregate_type,
        aggregate_id=aggregate_id,
        payload=payload or {},
    )


# ---------------------------------------------------------------------------
# In-memory outbox (for testing / dev)
# ---------------------------------------------------------------------------


class InMemoryOutbox:
    def __init__(self) -> None:
        self._entries: dict[UUID, OutboxEntry] = {}

    def write(self, entry: OutboxEntry) -> None:
        self._entries[entry.entry_id] = entry

    def mark_dispatched(self, entry_id: UUID) -> None:
        if entry_id in self._entries:
            self._entries[entry_id].status = DeliveryStatus.DISPATCHED
            self._entries[entry_id].dispatched_at = datetime.now(timezone.utc)

    def mark_failed(self, entry_id: UUID, error: str) -> None:
        if entry_id in self._entries:
            self._entries[entry_id].status = DeliveryStatus.FAILED
            self._entries[entry_id].last_error = error

    def mark_dead_letter(self, entry_id: UUID) -> None:
        if entry_id in self._entries:
            self._entries[entry_id].status = DeliveryStatus.DEAD_LETTER

    def get_pending(self, batch_size: int = 100) -> list[OutboxEntry]:
        pending = [
            e
            for e in self._entries.values()
            if e.status in (DeliveryStatus.PENDING, DeliveryStatus.FAILED)
        ]
        pending.sort(key=lambda e: e.created_at)
        return pending[:batch_size]

    def get_dead_letters(self, tenant_id: UUID | None = None) -> list[OutboxEntry]:
        dead = [e for e in self._entries.values() if e.status == DeliveryStatus.DEAD_LETTER]
        if tenant_id is not None:
            dead = [e for e in dead if e.tenant_id == tenant_id]
        return dead

    def all_entries(self) -> list[OutboxEntry]:
        return list(self._entries.values())
