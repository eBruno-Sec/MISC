"""Web/tool Temporal worker.

The only worker with target egress. Runs recon/module/validation/tool activities
across the safe-recon, api-testing, high-risk-validation, and report-generation
queues. M2 registers the safe HTTP recon activity on safe-recon; later milestones
add the module/validation/report activities on their queues.
"""

from __future__ import annotations

import asyncio
import logging
import os

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("worker-web")


async def _connect():
    from temporalio.client import Client

    address = os.getenv("TEMPORAL_ADDRESS", "temporal:7233")
    namespace = os.getenv("TEMPORAL_NAMESPACE", "default")
    while True:
        try:
            return await Client.connect(address, namespace=namespace)
        except Exception as exc:  # noqa: BLE001 - connectivity retry
            log.warning("temporal not ready (%s); retrying in 3s", exc)
            await asyncio.sleep(3)


async def main() -> None:
    from temporalio.worker import Worker

    from temporal.workflows.activities.recon_activities import safe_http_recon

    client = await _connect()
    # One worker per task queue. As activities for the other queues land, add
    # their workers here and run them concurrently.
    recon_worker = Worker(client, task_queue="safe-recon", activities=[safe_http_recon])
    log.info("worker-web running (queue: safe-recon, activity: safe_http_recon)")
    await recon_worker.run()


if __name__ == "__main__":
    asyncio.run(main())
