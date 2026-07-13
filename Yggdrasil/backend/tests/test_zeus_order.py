"""Item 2: verify the actual agent execution order is
FRIGG -> HEIMDALL -> TYR -> MIMIR -> BROKKR -> SKULD -> SAGA
i.e. MIMIR runs BEFORE BROKKR/SKULD, not after, so their gating/forging can
consume MIMIR's correlated Attack Path findings.

Drives the real Zeus.execute() with every agent's execute() monkeypatched to
record its name into a shared order list and return the minimal dict shape
zeus.py reads from it. FakeSession stands in for the DB: it accepts any
statement and returns an empty-but-well-shaped result, since this test verifies
call ORDER, not gating data (that's covered by tests/test_triage.py).
"""
import asyncio
import importlib.util
import os
import unittest
from unittest.mock import patch

HAS_SQLALCHEMY = importlib.util.find_spec("sqlalchemy") is not None


class _FakeResult:
    """Stands in for a SQLAlchemy Result: supports both `.all()` (rows) and
    `.scalars().all()` (ORM objects) as empty, since this test only cares about
    agent call order, not the rows gating logic reads."""
    def all(self):
        return []

    def scalars(self):
        return self

    def scalar(self):
        return 0


class FakeSession:
    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)

    async def execute(self, _stmt):
        return _FakeResult()

    async def flush(self):
        for obj in self.added:
            if obj.__class__.__name__ == "ApprovalRequest" and not getattr(obj, "id", None):
                obj.id = f"approval-{len(self.added)}"

    async def commit(self):
        pass

    async def refresh(self, _obj):
        return None


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy is not installed in this local test environment")
class ZeusOrderTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # Force every approval gate to auto-approve so the run reaches SAGA
        # without needing to drive the event-based manual-approval flow.
        self._old_auto = os.environ.get("YGGDRASIL_AUTO_APPROVE")
        os.environ["YGGDRASIL_AUTO_APPROVE"] = "1"

    async def asyncTearDown(self):
        if self._old_auto is None:
            os.environ.pop("YGGDRASIL_AUTO_APPROVE", None)
        else:
            os.environ["YGGDRASIL_AUTO_APPROVE"] = self._old_auto

    def _patched_execute(self, name, order, extra=None):
        async def _execute(_self, target, context=None):
            order.append(name)
            return dict(extra or {})
        return _execute

    async def _run(self, mode: str, order: list):
        from agents.zeus import Zeus
        from agents.athena import Athena
        from agents.hermes import Hermes
        from agents.ares import Ares
        from agents.metis import Metis
        from agents.hephaestus import Hephaestus
        from agents.hades import Hades
        from agents.apollo import Apollo

        with patch.object(Athena, "execute", self._patched_execute("athena", order)), \
             patch.object(Hermes, "execute", self._patched_execute(
                 "hermes", order, {"live_hosts": [{"host": "t.example", "url": "https://t.example"}]})), \
             patch.object(Ares, "execute", self._patched_execute("ares", order)), \
             patch.object(Metis, "execute", self._patched_execute("metis", order, {"chains": 1})), \
             patch.object(Hephaestus, "execute", self._patched_execute(
                 "hephaestus", order, {"exploitable_targets": ["https://t.example/vuln"]})), \
             patch.object(Hades, "execute", self._patched_execute("hades", order)), \
             patch.object(Apollo, "execute", self._patched_execute("apollo", order)):
            zeus = Zeus(FakeSession(), "mission-1")
            await zeus.execute("t.example", {"mode": mode})

    async def test_full_mode_mimir_runs_before_brokkr_and_skuld(self):
        order = []
        await self._run("full", order)
        self.assertEqual(order, ["athena", "hermes", "ares", "metis", "hephaestus", "hades", "apollo"])
        self.assertLess(order.index("metis"), order.index("hephaestus"),
                        "MIMIR must run before BROKKR (Hephaestus)")
        self.assertLess(order.index("metis"), order.index("hades"),
                        "MIMIR must run before SKULD (Hades)")
        self.assertLess(order.index("ares"), order.index("metis"),
                        "MIMIR must run after TYR (Ares)")

    async def test_active_mode_still_runs_mimir_before_saga(self):
        order = []
        await self._run("active", order)
        self.assertEqual(order, ["athena", "hermes", "ares", "metis", "apollo"])

    async def test_passive_mode_runs_mimir_as_finalize_safety_net(self):
        order = []
        await self._run("passive", order)
        self.assertEqual(order, ["athena", "hermes", "metis", "apollo"])


if __name__ == "__main__":
    unittest.main()
