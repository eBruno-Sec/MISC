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
    import asyncio

    from temporalio.worker import Worker

    from temporal.workflows.activities.identity_activities import establish_identities
    from temporal.workflows.activities.recon_activities import safe_http_recon
    from temporal.workflows.activities.report_activities import generate_reports
    from temporal.workflows.activities.validation_activities import run_idor_validation

    client = await _connect()
    # One worker per task queue, run concurrently.
    workers = [
        Worker(client, task_queue="safe-recon", activities=[safe_http_recon]),
        Worker(client, task_queue="api-testing", activities=[establish_identities]),
        Worker(client, task_queue="high-risk-validation", activities=[run_idor_validation]),
        Worker(client, task_queue="report-generation", activities=[generate_reports]),
    ]
    log.info(
        "worker-web running (queues: safe-recon, api-testing, high-risk-validation, report-generation)"
    )
    await asyncio.gather(*(w.run() for w in workers))


if __name__ == "__main__":
    asyncio.run(main())
