"""ArsGoatia OOB callback service for DNS and HTTP observations.

Receives out-of-band callbacks from external interactions (DNS lookups,
HTTP pingbacks) and records them as observations tied to the originating
action and engagement.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4

logger = logging.getLogger("arsgoatia.services.callback")


@dataclass(frozen=True)
class CallbackObservation:
    """A recorded OOB callback observation."""

    observation_id: UUID
    engagement_id: UUID
    action_id: UUID
    callback_type: str  # "dns" or "http"
    source_address: str
    token: str
    received_at: datetime
    raw_data: dict[str, object] = field(default_factory=dict)


@dataclass
class CallbackService:
    """Handles out-of-band DNS and HTTP callback observations.

    Each technique that uses OOB interactions embeds a unique token in
    payloads.  When the target triggers the callback, this service
    correlates the token back to the originating action.
    """

    _observations: list[CallbackObservation] = field(default_factory=list, init=False, repr=False)

    def handle_dns_callback(
        self,
        *,
        token: str,
        source_address: str,
        query_name: str,
        query_type: str,
        engagement_id: UUID,
        action_id: UUID,
    ) -> CallbackObservation:
        """Record a DNS callback observation.

        Parameters
        ----------
        token:
            Unique token embedded in the DNS query name.
        source_address:
            IP address of the DNS resolver that made the query.
        query_name:
            The full DNS query name received.
        query_type:
            DNS record type (A, AAAA, CNAME, TXT, etc.).
        engagement_id:
            The engagement this callback belongs to.
        action_id:
            The action that triggered this callback.
        """
        obs = CallbackObservation(
            observation_id=uuid4(),
            engagement_id=engagement_id,
            action_id=action_id,
            callback_type="dns",
            source_address=source_address,
            token=token,
            received_at=datetime.now(timezone.utc),
            raw_data={
                "query_name": query_name,
                "query_type": query_type,
            },
        )
        self._observations.append(obs)
        logger.info(
            "DNS callback recorded",
            extra={
                "token": token,
                "source": source_address,
                "query_name": query_name,
                "engagement_id": str(engagement_id),
            },
        )
        return obs

    def handle_http_callback(
        self,
        *,
        token: str,
        source_address: str,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None,
        engagement_id: UUID,
        action_id: UUID,
    ) -> CallbackObservation:
        """Record an HTTP callback observation.

        Parameters
        ----------
        token:
            Unique token embedded in the callback URL path.
        source_address:
            IP address of the HTTP client.
        method:
            HTTP method (GET, POST, etc.).
        path:
            Request path received.
        headers:
            Request headers.
        body:
            Request body bytes, if any.
        engagement_id:
            The engagement this callback belongs to.
        action_id:
            The action that triggered this callback.
        """
        obs = CallbackObservation(
            observation_id=uuid4(),
            engagement_id=engagement_id,
            action_id=action_id,
            callback_type="http",
            source_address=source_address,
            token=token,
            received_at=datetime.now(timezone.utc),
            raw_data={
                "method": method,
                "path": path,
                "headers": headers,
                "body_length": len(body) if body else 0,
            },
        )
        self._observations.append(obs)
        logger.info(
            "HTTP callback recorded",
            extra={
                "token": token,
                "source": source_address,
                "method": method,
                "path": path,
                "engagement_id": str(engagement_id),
            },
        )
        return obs

    def get_observations_by_token(self, token: str) -> list[CallbackObservation]:
        """Return all observations matching the given token."""
        return [obs for obs in self._observations if obs.token == token]

    def get_observations_by_action(self, action_id: UUID) -> list[CallbackObservation]:
        """Return all observations for a given action."""
        return [obs for obs in self._observations if obs.action_id == action_id]


__all__ = ["CallbackObservation", "CallbackService"]
