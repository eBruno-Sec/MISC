"""Item 3: 'Offensive engine must use parameter intelligence' — a distinct
requirement from building core/parameter_intelligence.py itself. Proves
run_offensive() actually wires the new module in: the URL pool handed to the
injection probes grows with real-path-preserving family probe URLs beyond
what crawl/archive/mining discovered, and the requested log lines appear.

Every other run_offensive() sub-stage (katana crawl, Wayback archive mining,
sqlmap/dalfox/ZAP, ...) is mocked out — those are pre-existing, already-
covered elsewhere; this test isolates the one thing that changed here.
"""
import importlib.util
import unittest
from unittest.mock import AsyncMock, patch

HAS_SQLALCHEMY = importlib.util.find_spec("sqlalchemy") is not None

# Every run_offensive() sub-stage besides the parameter-intelligence wiring
# itself, stubbed to a no-op so this test isolates just that one change.
_NOOP_STAGES = (
    "gather_archive_urls", "mine_params", "seed_endpoints", "import_api_specs",
    "discover_forms", "map_redirects", "test_sqli", "test_xss", "nuclei_dast",
    "test_auth", "test_path_traversal", "content_discovery", "test_ssrf",
    "test_ssti", "test_open_redirect", "test_cors", "test_host_header",
    "deep_fuzz", "test_forms", "dom_xss_scan", "oast_scan", "zap_active_scan",
)


class FakeSession:
    def __init__(self):
        self.added = []
        self.logs = []

    def add(self, obj):
        self.added.append(obj)
        if obj.__class__.__name__ == "AgentLog":
            self.logs.append(obj.message)

    async def execute(self, _stmt):
        return None

    async def commit(self):
        pass


def _make_engine(session):
    from agents.base import BaseAgent
    from agents.offensive import OffensiveEngine
    from agents.auth import AuthEngine

    class TestEngine(BaseAgent, OffensiveEngine, AuthEngine):
        name = "ares"
        symbol = "TY"
        display_name = "TYR"
        role = "Active Assessment"

        async def execute(self, target, context=None):
            return {}

    return TestEngine(session, "mission-1")


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy is not installed in this local test environment")
class RunOffensiveUsesParameterIntelligenceTests(unittest.IsolatedAsyncioTestCase):
    async def test_test_sqli_receives_family_probe_urls_beyond_raw_crawl(self):
        session = FakeSession()
        engine = _make_engine(session)
        base_url = "https://ginandjuice.shop"
        # Only ONE real observed URL, discovered by the (mocked) crawl —
        # parameter intelligence should expand this into targeted probes for
        # every family productId/etc. classify into, preserving the real path.
        crawled = ["https://ginandjuice.shop/catalog/product?productId=3"]

        stage_mocks = {name: AsyncMock(return_value=[]) for name in _NOOP_STAGES}
        with patch.object(engine, "crawl", AsyncMock(return_value=crawled)), \
             patch.multiple(engine, **stage_mocks):
            await engine.run_offensive(base_url)

        mock_sqli = stage_mocks["test_sqli"]
        mock_sqli.assert_called_once()
        _, urls_arg = mock_sqli.call_args.args
        self.assertIn("https://ginandjuice.shop/catalog/product?productId=3", urls_arg)
        # Parameter intelligence's own mutated probe (productId=1, same real
        # path) must also have made it into the pool test_sqli was given —
        # proving the wiring, not just that the raw crawl result passed through.
        self.assertTrue(
            any(u.startswith("https://ginandjuice.shop/catalog/product?") and "productId=1" in u
                for u in urls_arg),
            urls_arg,
        )

    async def test_summary_and_priority_log_lines_are_emitted(self):
        session = FakeSession()
        engine = _make_engine(session)
        base_url = "https://ginandjuice.shop"
        crawled = ["https://ginandjuice.shop/catalog/product?productId=3"]

        stage_mocks = {name: AsyncMock(return_value=[]) for name in _NOOP_STAGES}
        with patch.object(engine, "crawl", AsyncMock(return_value=crawled)), \
             patch.multiple(engine, **stage_mocks):
            await engine.run_offensive(base_url)

        self.assertTrue(any(m.startswith("Parameter intelligence: ") for m in session.logs), session.logs)
        self.assertTrue(any(m.startswith("SQLi priority params: ") for m in session.logs), session.logs)


if __name__ == "__main__":
    unittest.main()
