import asyncio
import importlib.util
import unittest


HAS_SQLALCHEMY = importlib.util.find_spec("sqlalchemy") is not None


class FakeSession:
    def __init__(self):
        self.added = []
        self.commits = 0

    def add(self, obj):
        self.added.append(obj)

    async def execute(self, _stmt):
        return None

    async def flush(self):
        for obj in self.added:
            if obj.__class__.__name__ == "ApprovalRequest" and not obj.id:
                obj.id = "approval-1"

    async def commit(self):
        self.commits += 1

    async def refresh(self, _obj):
        return None


class FakeManager:
    def __init__(self, agent):
        self.agent = agent
        self.events = []
        self.approval_required = asyncio.Event()

    async def broadcast(self, _mission_id, event):
        self.events.append(event)
        if event["type"] == "approval_required":
            assert event["approval_id"] in self.agent.approval_gates
            self.approval_required.set()


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy is not installed in this local test environment")
class ScopeSummaryTests(unittest.TestCase):
    def test_scope_summary_preserves_counts_types_and_examples(self):
        from agents.athena import _summarize_scope_rules

        summary = _summarize_scope_rules({
            "in_scope": [
                {"identifier": "example.com", "type": "domain"},
                {"identifier": "https://app.example.com", "type": "url"},
                {"identifier": "192.0.2.10", "type": "ip"},
            ],
            "out_of_scope": [
                {"identifier": "admin.example.com", "type": "domain"},
            ],
        })

        self.assertTrue(summary["has_rules"])
        self.assertEqual(summary["in_scope_count"], 3)
        self.assertEqual(summary["out_of_scope_count"], 1)
        self.assertEqual(summary["asset_types"]["domain"], 1)
        self.assertIn("admin.example.com (domain)", summary["out_of_scope_examples"])

    def test_scope_notes_extract_declared_paths_and_hints(self):
        from agents.athena import _extract_declared_scope_paths

        rows = _extract_declared_scope_paths("""
/catalog
SQL injection
/resources/js/angular_1-7-7.js
Vulnerable JavaScript dependency
/login
Cross-site scripting (reflected)
""")

        self.assertEqual([r["path"] for r in rows], [
            "/catalog",
            "/resources/js/angular_1-7-7.js",
            "/login",
        ])
        self.assertIn("SQL injection", rows[0]["hints"])
        self.assertIn("Vulnerable JavaScript dependency", rows[1]["hints"])


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy is not installed in this local test environment")
class ApprovalFlowTests(unittest.IsolatedAsyncioTestCase):
    async def test_waiter_exists_before_approval_required_broadcast(self):
        from agents.base import BaseAgent

        class TestAgent(BaseAgent):
            name = "ares"
            symbol = "TY"
            display_name = "TYR"
            role = "Active Assessment"

            async def execute(self, target: str, context: dict = None) -> dict:
                return {}

        session = FakeSession()
        agent = TestAgent(session, "mission-1")
        manager = FakeManager(agent)
        agent.ws_manager = manager

        task = asyncio.create_task(agent.request_approval("Active check", "details"))
        await asyncio.wait_for(manager.approval_required.wait(), timeout=1)

        agent.approval_results["approval-1"] = True
        agent.approval_gates["approval-1"].set()

        self.assertTrue(await asyncio.wait_for(task, timeout=1))
        self.assertFalse(agent.approval_gates)
        self.assertTrue(any(obj.__class__.__name__ == "AgentLog" for obj in session.added))


if __name__ == "__main__":
    unittest.main()
