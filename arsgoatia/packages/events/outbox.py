"""Transactional outbox writer (§9).

Events are appended to the outbox in the same transaction as the state change
that produced them. The relay poller (relay.py) dispatches undispatched rows and
stamps dispatched_at exactly once. Consumers dedupe on event_id (at-least-once).
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from domain.models import Outbox
from schemas.events import EventEnvelope


def build_outbox_row(envelope: EventEnvelope) -> Outbox:
    """Map a finalized event envelope to an outbox row (no I/O)."""
    final = envelope if envelope.payload_hash else envelope.finalized()
    return Outbox(
        event_id=str(final.event_id),
        tenant_id=str(final.tenant_id),
        event_type=final.event_type.value,
        envelope=final.model_dump(mode="json"),
    )


async def enqueue_event(session: AsyncSession, envelope: EventEnvelope) -> Outbox:
    """Append an event to the outbox within the caller's transaction.

    The caller owns commit/rollback so the event is atomic with the domain write.
    """
    row = build_outbox_row(envelope)
    session.add(row)
    await session.flush()
    return row
