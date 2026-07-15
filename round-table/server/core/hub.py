"""
Event hub + mission runner.

The hub fans out live mission events to any subscribed WebSocket. Missions run
one-at-a-time in a worker thread (recon is blocking network I/O); events are
persisted to SQLite and pushed to subscribers in a thread-safe way.
"""
import asyncio
from typing import Any, Optional

from . import db


class Hub:
    def __init__(self) -> None:
        self._subs: dict[str, set[asyncio.Queue]] = {}
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._run_lock = asyncio.Lock()

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    # ── subscriptions (async side) ──────────────────────────────────────────
    async def subscribe(self, mission_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subs.setdefault(mission_id, set()).add(q)
        return q

    def unsubscribe(self, mission_id: str, q: asyncio.Queue) -> None:
        subs = self._subs.get(mission_id)
        if subs:
            subs.discard(q)
            if not subs:
                self._subs.pop(mission_id, None)

    # ── publishing (thread-safe: callable from worker threads) ──────────────
    def publish(self, mission_id: str, event: dict[str, Any]) -> None:
        loop = self._loop
        if loop is None:
            return
        for q in list(self._subs.get(mission_id, ())):
            loop.call_soon_threadsafe(self._safe_put, q, event)

    @staticmethod
    def _safe_put(q: asyncio.Queue, event: dict[str, Any]) -> None:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            pass

    def emit(self, mission_id: str, level: str, phase: Optional[str], message: str) -> None:
        """Persist a feed line and broadcast it. Safe from a worker thread."""
        rec = db.add_event(mission_id, level, phase, message)
        self.publish(mission_id, {"type": "log", **rec})

    def push(self, mission_id: str, payload: dict[str, Any]) -> None:
        """Broadcast a non-log structured update (status, stats, done)."""
        self.publish(mission_id, payload)

    # ── mission execution (serialized) ──────────────────────────────────────
    async def run_mission(self, mission_id: str) -> None:
        # One mission at a time: recon phases redirect stdout globally, and a
        # single operator box does not benefit from parallel heavy scans.
        async with self._run_lock:
            from ..engine import pipeline

            await asyncio.to_thread(pipeline.execute, mission_id, self)


hub = Hub()
