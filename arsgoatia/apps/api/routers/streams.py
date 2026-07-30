"""Server-Sent Events streams for live engagement / execution progress."""
from __future__ import annotations

import asyncio
import json
from uuid import UUID

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from apps.api import temporal as temporal_client
from apps.api.deps import AuthCtx, TenantId

router = APIRouter(tags=["streams"])


@router.get(
    "/engagements/{engagement_id}/stream",
    summary="SSE stream of engagement progress (state + phase)",
)
async def stream_engagement(
    engagement_id: UUID,
    tenant_id: TenantId,
    auth: AuthCtx,
):
    """Push a fresh state snapshot every 1s from Temporal, terminate on terminal state."""

    async def gen():
        last_serialised = ""
        yield f'event: connected\ndata: {{"engagement_id": "{engagement_id}"}}\n\n'
        for _ in range(600):  # ~10 minutes hard cap
            state = await temporal_client.query_engagement_state(str(engagement_id))
            if state is None:
                yield "event: waiting\ndata: {}\n\n"
                await asyncio.sleep(2)
                continue
            payload = json.dumps(state, default=str, sort_keys=True)
            if payload != last_serialised:
                yield f"event: state\ndata: {payload}\n\n"
                last_serialised = payload
            if state.get("lifecycle") in ("COMPLETED", "FAILED"):
                yield "event: done\ndata: {}\n\n"
                return
            await asyncio.sleep(1)
        yield 'event: timeout\ndata: {"reason": "stream max duration reached"}\n\n'

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
