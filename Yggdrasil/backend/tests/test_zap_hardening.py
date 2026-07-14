"""Reliability tests for the hardened ZAP active scan.

The production failure this guards against: two missions shared the one ZAP
daemon, it saturated, a status poll wedged, and with no per-call/wall-clock cap
the mission hung for hours. These tests prove the hardened scan:
  - hard-caps every ZAP API call (a wedged poll can't stall the mission),
  - always releases the process-global serialization lock,
  - returns instead of hanging when ZAP stops responding.
"""
import asyncio
import importlib.util
import unittest
from unittest.mock import patch, AsyncMock

HAS_SQLALCHEMY = importlib.util.find_spec("sqlalchemy") is not None

if HAS_SQLALCHEMY:
    from agents import offensive as off

    class FakeSession:
        def __init__(self):
            self.added = []

        def add(self, obj):
            self.added.append(obj)

        async def execute(self, _stmt):
            return None

        async def commit(self):
            pass

        async def get(self, *_a, **_k):
            return None

    class FakeZapResp:
        def __init__(self, payload):
            self._p = payload

        def raise_for_status(self):
            pass

        def json(self):
            return self._p

    def _default_router(url):
        # Minimal happy-path ZAP responses keyed by endpoint path.
        table = {
            "/JSON/core/view/version/": {"version": "2.17.0"},
            "/JSON/spider/action/scan/": {"scan": "1"},
            "/JSON/spider/view/status/": {"status": "100"},
            "/JSON/pscan/view/recordsToScan/": {"recordsToScan": "0"},
            "/JSON/ascan/action/scan/": {"scan": "2"},
            "/JSON/ascan/view/status/": {"status": "100"},
            "/JSON/core/view/alerts/": {"alerts": []},
        }
        for key, val in table.items():
            if key in url:
                return val
        return {}

    class FakeZapClient:
        def __init__(self, *a, router=_default_router, on_call=None, **k):
            self._router = router
            self._on_call = on_call

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_a):
            return False

        async def get(self, url, params=None):
            if self._on_call:
                await self._on_call(url)
            return FakeZapResp(self._router(url))

    def _make_ares():
        from agents.ares import Ares
        a = Ares(FakeSession(), "m-zap")
        a._tools_missing = set()
        return a


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy not available")
class ZapPrimitiveTests(unittest.TestCase):
    def test_lock_and_call_timeout_defined(self):
        self.assertIsInstance(off._ZAP_LOCK, asyncio.Lock)
        self.assertGreater(off._ZAP_CALL_TIMEOUT, 0)


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy not available")
class ZapScanReliabilityTests(unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        # Never let a test leak a held lock into the next one.
        if off._ZAP_LOCK.locked():
            off._ZAP_LOCK.release()

    async def test_happy_path_returns_and_releases_lock(self):
        ares = _make_ares()
        with patch("httpx.AsyncClient", new=lambda *a, **k: FakeZapClient()), \
             patch("asyncio.sleep", AsyncMock()):
            out = await ares.zap_active_scan("http://t.example",
                                             seed_urls=["http://t.example/a?id=1"])
        self.assertIsInstance(out, list)
        self.assertFalse(off._ZAP_LOCK.locked(), "lock must be released after a normal scan")

    async def test_wedged_zap_poll_does_not_hang_and_releases_lock(self):
        ares = _make_ares()

        async def wedge(url):
            # Simulate a saturated ZAP whose active-scan status poll never
            # answers. The per-call wait_for must cancel it, not hang.
            if "/JSON/ascan/view/status/" in url:
                await asyncio.Event().wait()   # blocks forever until cancelled

        client_factory = lambda *a, **k: FakeZapClient(on_call=wedge)
        with patch("httpx.AsyncClient", new=client_factory), \
             patch("asyncio.sleep", AsyncMock()), \
             patch.object(off, "_ZAP_CALL_TIMEOUT", 0.2):
            out = await asyncio.wait_for(
                ares.zap_active_scan("http://t.example"), timeout=10)
        self.assertIsInstance(out, list)
        self.assertFalse(off._ZAP_LOCK.locked(),
                         "lock must be released even when a ZAP call times out")

    async def test_lock_is_held_during_scan_then_freed(self):
        ares = _make_ares()
        seen = {"locked_during": False}

        async def check_lock(url):
            if off._ZAP_LOCK.locked():
                seen["locked_during"] = True

        client_factory = lambda *a, **k: FakeZapClient(on_call=check_lock)
        with patch("httpx.AsyncClient", new=client_factory), \
             patch("asyncio.sleep", AsyncMock()):
            await ares.zap_active_scan("http://t.example")
        self.assertTrue(seen["locked_during"], "ZAP scan should hold the serialization lock while running")
        self.assertFalse(off._ZAP_LOCK.locked())


if __name__ == "__main__":
    unittest.main()
