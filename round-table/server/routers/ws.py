"""WebSocket live mission feed."""
import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..core import db
from ..core.hub import hub

router = APIRouter()


@router.websocket("/missions/{mid}")
async def mission_feed(ws: WebSocket, mid: str):
    await ws.accept()
    m = db.get_mission(mid)
    if not m:
        await ws.send_json({"type": "error", "message": "mission not found"})
        await ws.close()
        return

    q = await hub.subscribe(mid)
    try:
        # Replay the backlog so a late subscriber still sees the full feed.
        for ev in db.get_events(mid):
            await ws.send_json({"type": "log", **ev})
        await ws.send_json({"type": "status", "status": m["status"]})

        while True:
            try:
                ev = await asyncio.wait_for(q.get(), timeout=30)
                await ws.send_json(ev)
            except asyncio.TimeoutError:
                await ws.send_json({"type": "ping"})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        hub.unsubscribe(mid, q)
