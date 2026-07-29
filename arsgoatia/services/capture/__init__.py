"""ArsGoatia TrafficMind capture proxy sidecar.

Manages an HTTP/HTTPS capture proxy that records all exchanges between
the platform and target systems.  Captured exchanges form the raw
evidence chain for every action.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from uuid import UUID, uuid4

logger = logging.getLogger("arsgoatia.services.capture")


class ProxyState(Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"


@dataclass(frozen=True)
class CapturedExchange:
    """A single captured HTTP exchange."""

    exchange_id: UUID
    engagement_id: UUID
    action_id: UUID | None
    timestamp: datetime
    method: str
    url: str
    request_headers: dict[str, str]
    request_body: bytes | None
    status_code: int | None
    response_headers: dict[str, str]
    response_body: bytes | None
    duration_ms: float


@dataclass
class CaptureService:
    """TrafficMind capture proxy sidecar.

    Provides start/stop lifecycle management and access to captured
    HTTP exchanges.  In production, this wraps an actual mitmproxy or
    similar capture engine.  The stub records exchanges in memory.
    """

    listen_host: str = "127.0.0.1"
    listen_port: int = 8888
    engagement_id: UUID | None = None

    _state: ProxyState = field(default=ProxyState.STOPPED, init=False, repr=False)
    _exchanges: list[CapturedExchange] = field(
        default_factory=list, init=False, repr=False
    )

    @property
    def state(self) -> ProxyState:
        return self._state

    def start_proxy(self, engagement_id: UUID) -> None:
        """Start the capture proxy for the given engagement.

        Raises
        ------
        RuntimeError
            If the proxy is already running.
        """
        if self._state == ProxyState.RUNNING:
            raise RuntimeError("Capture proxy is already running")

        self._state = ProxyState.STARTING
        self.engagement_id = engagement_id
        self._exchanges.clear()

        # TODO: start actual proxy process (mitmproxy, go-mitmproxy, etc.)

        self._state = ProxyState.RUNNING
        logger.info(
            "Capture proxy started on %s:%d for engagement %s",
            self.listen_host,
            self.listen_port,
            engagement_id,
        )

    def stop_proxy(self) -> None:
        """Stop the capture proxy and finalize captured exchanges.

        Raises
        ------
        RuntimeError
            If the proxy is not running.
        """
        if self._state != ProxyState.RUNNING:
            raise RuntimeError(
                f"Cannot stop proxy in state {self._state.value}"
            )

        self._state = ProxyState.STOPPING

        # TODO: stop actual proxy process, flush buffers

        self._state = ProxyState.STOPPED
        logger.info(
            "Capture proxy stopped (captured %d exchanges)",
            len(self._exchanges),
        )

    def record_exchange(
        self,
        *,
        method: str,
        url: str,
        request_headers: dict[str, str],
        request_body: bytes | None = None,
        status_code: int | None = None,
        response_headers: dict[str, str] | None = None,
        response_body: bytes | None = None,
        duration_ms: float = 0.0,
        action_id: UUID | None = None,
    ) -> CapturedExchange:
        """Record a captured HTTP exchange.

        This is called by the proxy engine as each exchange completes.
        """
        if self.engagement_id is None:
            raise RuntimeError("No active engagement for capture")

        exchange = CapturedExchange(
            exchange_id=uuid4(),
            engagement_id=self.engagement_id,
            action_id=action_id,
            timestamp=datetime.now(timezone.utc),
            method=method,
            url=url,
            request_headers=request_headers,
            request_body=request_body,
            status_code=status_code,
            response_headers=response_headers or {},
            response_body=response_body,
            duration_ms=duration_ms,
        )
        self._exchanges.append(exchange)
        return exchange

    def get_captured_exchanges(
        self,
        *,
        action_id: UUID | None = None,
    ) -> list[CapturedExchange]:
        """Return captured exchanges, optionally filtered by action ID."""
        if action_id is not None:
            return [e for e in self._exchanges if e.action_id == action_id]
        return list(self._exchanges)


__all__ = ["CapturedExchange", "CaptureService", "ProxyState"]
