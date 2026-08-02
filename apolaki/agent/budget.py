"""
Mission WEIGHTED-WORK budget — a deterministic cap on how much request-work one mission may do. It
is NOT an exact request counter: Apolaki's own HTTP calls cost 1 each (charged at _http_send), while
an external tool run costs a fixed WEIGHT estimate (nuclei/ffuf/sqlmap = 100, etc. — an external
tool may actually make anywhere from a handful to tens of thousands of requests, so treat the number
as bounded work, not a precise request count; CHAD re-audit #9). Off by default (limit 0 = unlimited);
set BBH_REQUEST_BUDGET to bound a runaway scan. When exhausted, further work fails as normal errors.

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
