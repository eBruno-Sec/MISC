"""Outbox relay poller (§9).

Polls undispatched outbox rows and dispatches them (in the slice: logs + marks
dispatched). The dispatched_at stamp is guarded by the DB trigger so a row is
never re-dispatched or mutated. Kept intentionally small; a NATS driver would
slot in behind the same envelope without changing producers.
"""

from __future__ import annotations

import logging

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from domain.models import Outbox

log = logging.getLogger("outbox-relay")


async def dispatch_pending(session: AsyncSession, limit: int = 100) -> int:
    """Dispatch up to `limit` undispatched rows. Returns the count dispatched."""
    rows = (
        (
            await session.execute(
                select(Outbox).where(Outbox.dispatched_at.is_(None)).order_by(Outbox.id).limit(limit)
            )
        )
        .scalars()
        .all()
    )
    dispatched = 0
    for row in rows:
        # A real bus publish would go here; the slice records the fact.
        log.info("dispatch event %s type=%s", row.event_id, row.event_type)
        await session.execute(
            update(Outbox)
            .where(Outbox.id == row.id, Outbox.dispatched_at.is_(None))
            .values(dispatched_at=_now())
        )
        dispatched += 1
    return dispatched


def _now():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)
