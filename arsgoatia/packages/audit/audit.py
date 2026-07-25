"""Append-only audit writer (§9).

Every state change, policy decision, and scope-firewall verdict writes an
AuditEvent. The table is append-only (DB trigger); this module never updates.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from domain.models import AuditEvent
from schemas.events import EventEnvelope, payload_hash


def build_audit_row(envelope: EventEnvelope) -> AuditEvent:
    """Map an event envelope to an append-only audit row (no I/O)."""
    return AuditEvent(
        tenant_id=str(envelope.tenant_id),
        assessment_id=str(envelope.assessment_id),
        assessment_revision=envelope.assessment_revision,
        policy_revision=envelope.policy_revision,
        event_type=envelope.event_type.value,
        aggregate_type=envelope.aggregate_type,
        aggregate_id=str(envelope.aggregate_id),
        producer=envelope.producer,
        correlation_id=str(envelope.correlation_id) if envelope.correlation_id else None,
        causation_id=str(envelope.causation_id) if envelope.causation_id else None,
        payload=envelope.payload,
        payload_hash=envelope.payload_hash or payload_hash(envelope.payload),
    )


async def record_audit(session: AsyncSession, envelope: EventEnvelope) -> AuditEvent:
    row = build_audit_row(envelope)
    session.add(row)
    await session.flush()
    return row
