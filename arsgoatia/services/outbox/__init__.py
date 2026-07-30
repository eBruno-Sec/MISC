"""ArsGoatia outbox relay service.

Polls the transactional outbox at a configurable interval and dispatches
pending events to subscribers.  Designed to run as a standalone process
alongside the API and worker.
"""

from __future__ import annotations

import logging
import os
import signal
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from packages.events import OutboxRelay

logger = logging.getLogger("arsgoatia.services.outbox")

_shutdown_requested = False


def _handle_signal(signum: int, _frame: object) -> None:
    global _shutdown_requested
    sig_name = signal.Signals(signum).name
    logger.info("Received %s -- initiating graceful shutdown", sig_name)
    _shutdown_requested = True


def run_relay_loop(
    relay: OutboxRelay,
    *,
    poll_interval: float | None = None,
) -> None:
    """Run the outbox relay loop until a shutdown signal is received.

    Parameters
    ----------
    relay:
        An ``OutboxRelay`` instance wired to the outbox writer and
        event subscriptions.
    poll_interval:
        Seconds between polls.  Defaults to the ``OUTBOX_POLL_INTERVAL``
        environment variable, falling back to ``1.0``.
    """
    global _shutdown_requested
    _shutdown_requested = False

    if poll_interval is None:
        poll_interval = float(os.environ.get("OUTBOX_POLL_INTERVAL", "1.0"))

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    logger.info(
        "Outbox relay started (poll_interval=%.2fs)",
        poll_interval,
    )

    while not _shutdown_requested:
        try:
            dispatched = relay.poll_and_dispatch()
            if dispatched > 0:
                logger.debug("Dispatched %d events", dispatched)
        except Exception:
            logger.exception("Error during outbox poll cycle")

        time.sleep(poll_interval)

    logger.info(
        "Outbox relay stopped (total_processed=%d)",
        relay.processed_count,
    )


__all__ = ["run_relay_loop"]
