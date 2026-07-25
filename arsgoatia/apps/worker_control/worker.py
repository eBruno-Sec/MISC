"""Control-plane Temporal worker.

Runs the root AssessmentWorkflow, its child workflows, and the control + AI
activities (queues: workflow-control, ai-analysis). M0 scaffold: connect to
Temporal and idle so the service is verifiable; M1 registers the workflows and
activities and replaces the idle loop with Worker.run().
"""

from __future__ import annotations

import asyncio
import logging
import os

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("worker-control")

CONTROL_QUEUE = os.getenv("TEMPORAL_TASK_QUEUE_CONTROL", "workflow-control")


async def main() -> None:
    from temporalio.client import Client

    address = os.getenv("TEMPORAL_ADDRESS", "temporal:7233")
    namespace = os.getenv("TEMPORAL_NAMESPACE", "default")

    # Retry connect until Temporal is reachable (compose starts services in
    # parallel; the frontend may not be listening yet).
    while True:
        try:
            await Client.connect(address, namespace=namespace)
            break
        except Exception as exc:  # noqa: BLE001 - connectivity retry
            log.warning("temporal not ready (%s); retrying in 3s", exc)
            await asyncio.sleep(3)

    log.info("worker-control connected to %s (queues: %s, ai-analysis)", address, CONTROL_QUEUE)
    log.info("no workflows registered yet (M0 scaffold); idling")
    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    asyncio.run(main())
