"""ArsGoatia Temporal worker entry point.

Starts two task queues:
  - workflow-control: root + child workflows, control activities
  - workflow-web: recon / module / validation / evidence / reporting activities
"""
from __future__ import annotations

import asyncio
import logging
import os

from temporalio.client import Client
from temporalio.worker import Worker

from services.worker.activities.chain import create_chain_step
from services.worker.activities.cleanup import run_cleanup
from services.worker.activities.evidence import store_evidence
from services.worker.activities.identity import establish_identities
from services.worker.activities.recon import safe_http_recon
from services.worker.activities.reporting import generate_reports
from services.worker.activities.validation import run_bola_validation
from services.worker.workflows.engagement import EngagementWorkflow
from services.worker.workflows.recon import ReconWorkflow
from services.worker.workflows.validation import ValidationWorkflow

logger = logging.getLogger("arsgoatia.worker")

TEMPORAL_ADDRESS = os.getenv("TEMPORAL_ADDRESS", "localhost:7233")
TEMPORAL_NAMESPACE = os.getenv("TEMPORAL_NAMESPACE", "default")

CONTROL_QUEUE = "workflow-control"
WEB_QUEUE = "workflow-web"

CONTROL_WORKFLOWS = [EngagementWorkflow, ReconWorkflow, ValidationWorkflow]
CONTROL_ACTIVITIES = [establish_identities, create_chain_step, run_cleanup]
WEB_ACTIVITIES = [safe_http_recon, run_bola_validation, store_evidence, generate_reports]


async def run() -> None:
    client = await Client.connect(TEMPORAL_ADDRESS, namespace=TEMPORAL_NAMESPACE)

    control_worker = Worker(
        client,
        task_queue=CONTROL_QUEUE,
        workflows=CONTROL_WORKFLOWS,
        activities=CONTROL_ACTIVITIES,
    )
    web_worker = Worker(
        client,
        task_queue=WEB_QUEUE,
        activities=WEB_ACTIVITIES,
    )

    logger.info("Starting workers: %s, %s", CONTROL_QUEUE, WEB_QUEUE)
    await asyncio.gather(control_worker.run(), web_worker.run())


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    asyncio.run(run())


if __name__ == "__main__":
    main()
