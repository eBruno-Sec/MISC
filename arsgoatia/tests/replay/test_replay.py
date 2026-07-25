"""Temporal determinism + replay (§32, §39).

Runs the AssessmentWorkflow in a time-skipping test environment with activities
disabled (pure lifecycle path), exercises pause/resume, then replays the recorded
history against the CURRENT workflow code. A determinism break would raise during
replay. Requires temporalio + its test server; skipped where unavailable so the
light unit CI stays fast (a dedicated CI job runs this).
"""

from __future__ import annotations

import asyncio
import uuid

import pytest

pytest.importorskip("temporalio")

from temporalio.testing import WorkflowEnvironment  # noqa: E402
from temporalio.worker import Replayer, Worker  # noqa: E402

from temporal.workflows.assessment import AssessmentWorkflow  # noqa: E402

_PARAMS = {
    "assessment_id": "a-1",
    "tenant_id": "t-1",
    "run_recon": False,
    "run_validation": False,
    "require_validation_approval": False,
}


async def _start_env():
    try:
        return await WorkflowEnvironment.start_time_skipping()
    except Exception as exc:  # noqa: BLE001 - test server download/start failed
        pytest.skip(f"temporal test server unavailable: {exc}")


def test_workflow_completes_and_history_replays():
    async def _run():
        env = await _start_env()
        async with env:
            tq = "replay-tq"
            async with Worker(env.client, task_queue=tq, workflows=[AssessmentWorkflow]):
                handle = await env.client.start_workflow(
                    AssessmentWorkflow.run, _PARAMS, id=f"wf-{uuid.uuid4().hex}", task_queue=tq
                )
                result = await handle.result()
                assert result["final_state"] == "COMPLETED"
                history = await handle.fetch_history()
        # Replay the recorded history against the current workflow code.
        await Replayer(workflows=[AssessmentWorkflow]).replay_workflow(history)

    asyncio.run(_run())


def test_pause_then_resume():
    async def _run():
        env = await _start_env()
        async with env:
            tq = "replay-tq2"
            async with Worker(env.client, task_queue=tq, workflows=[AssessmentWorkflow]):
                handle = await env.client.start_workflow(
                    AssessmentWorkflow.run,
                    {**_PARAMS, "assessment_id": "a-2"},
                    id=f"wf-{uuid.uuid4().hex}",
                    task_queue=tq,
                )
                await handle.signal("pause")
                await handle.signal("resume")
                result = await handle.result()
                assert result["final_state"] == "COMPLETED"

    asyncio.run(_run())


def test_emergency_stop_is_terminal():
    async def _run():
        env = await _start_env()
        async with env:
            tq = "replay-tq3"
            async with Worker(env.client, task_queue=tq, workflows=[AssessmentWorkflow]):
                handle = await env.client.start_workflow(
                    AssessmentWorkflow.run,
                    {**_PARAMS, "assessment_id": "a-3"},
                    id=f"wf-{uuid.uuid4().hex}",
                    task_queue=tq,
                )
                await handle.signal("emergency_stop")
                result = await handle.result()
                assert result["final_state"] == "EMERGENCY_STOPPED"

    asyncio.run(_run())
