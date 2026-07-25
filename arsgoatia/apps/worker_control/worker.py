"""Control-plane Temporal worker.

Runs the root AssessmentWorkflow (queue: workflow-control). Child workflows and
control/AI activities are added on this worker as later milestones land.
"""

from __future__ import annotations

import asyncio
import logging
import os

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("worker-control")

CONTROL_QUEUE = os.getenv("TEMPORAL_TASK_QUEUE_CONTROL", "workflow-control")


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

    from temporal.workflows.assessment import AssessmentWorkflow

    client = await _connect()
    worker = Worker(client, task_queue=CONTROL_QUEUE, workflows=[AssessmentWorkflow])
    log.info("worker-control running (queue: %s, workflow: AssessmentWorkflow)", CONTROL_QUEUE)
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
