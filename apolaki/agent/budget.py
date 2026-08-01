"""
Mission request budget — a simple, deterministic cap on how many HTTP requests one mission may
make. Off by default (limit 0 = unlimited, no behaviour change); set BBH_REQUEST_BUDGET (or pass a
limit) to bound a mission so a runaway scan can't hammer a target. Charged at the transport
chokepoint (_http_send); when exhausted, further requests fail gracefully as normal tool errors.

Pure + thread-safe; unit-tested.
"""
from __future__ import annotations

import threading


class MissionBudget:
    def __init__(self, limit: int = 0):
        try:
            self.limit = max(0, int(limit))
        except Exception:
            self.limit = 0
        self._spent = 0
        self._lock = threading.Lock()

    def charge(self, n: int = 1) -> bool:
        """Try to spend n requests. Returns True if allowed (and records the spend), False if this
        would exceed the budget. limit 0 = unlimited (always True)."""
        with self._lock:
            if self.limit and self._spent + n > self.limit:
                return False
            self._spent += n
            return True

    @property
    def spent(self) -> int:
        return self._spent

    def remaining(self) -> int:
        return -1 if not self.limit else max(0, self.limit - self._spent)

    def exhausted(self) -> bool:
        return bool(self.limit) and self._spent >= self.limit

    def to_dict(self) -> dict:
        return {"limit": self.limit or None, "spent": self._spent, "remaining": self.remaining()}
