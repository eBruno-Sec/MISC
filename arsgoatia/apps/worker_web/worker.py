"""Web/tool Temporal worker.

Runs recon, module, validation, tool, evidence, and report activities (queues:
safe-recon, api-testing, high-risk-validation, report-generation). This is the
only worker with target egress. M0 scaffold: connect and idle; M1+ registers the
activities and the tool SDK executor.
"""

from __future__ import annotations

import asyncio
import logging
import os

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("worker-web")

QUEUES = ["safe-recon", "api-testing", "high-risk-validation", "report-generation"]


async def main() -> None:
    from temporalio.client import Client

    address = os.getenv("TEMPORAL_ADDRESS", "temporal:7233")
    namespace = os.getenv("TEMPORAL_NAMESPACE", "default")

    while True:
        try:
            await Client.connect(address, namespace=namespace)
            break
        except Exception as exc:  # noqa: BLE001 - connectivity retry
            log.warning("temporal not ready (%s); retrying in 3s", exc)
            await asyncio.sleep(3)

    log.info("worker-web connected to %s (queues: %s)", address, ", ".join(QUEUES))
    log.info("no activities registered yet (M0 scaffold); idling")
    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    asyncio.run(main())
