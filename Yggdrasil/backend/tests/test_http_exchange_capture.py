"""Item 6 + backup integration: HTTP-response-based findings must attach a real
HttpExchange, and those exchanges must survive into a workspace backup export.

Drives the REAL BaseAgent.add_finding/capture/add_exchange and OffensiveEngine.
_validate_and_report_sensitive_hit/_capture_proof against a local http.server —
only the DB session is faked (matches tests/test_approval_flow.py's pattern) so
this exercises production code, not a reimplementation of it.
"""
import importlib.util
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HAS_SQLALCHEMY = importlib.util.find_spec("sqlalchemy") is not None
HAS_HTTPX = importlib.util.find_spec("httpx") is not None


SPA_SHELL = (
    b'<!DOCTYPE html><html><head><title>App</title></head>'
    b'<body><div id="root">Loading...</div><script src="/app.js"></script></body></html>'
)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        # A catch-all SPA router: every path except the real .env probe returns
        # the same client-side-mount shell, exercising the exact false-positive
        # this handler is designed to reproduce (item 7's core bug).
        if ".env" in self.path:
            body = b"DB_PASSWORD=hunter2\nAPI_KEY=sk-test-1234\n"
        else:
            body = SPA_SHELL
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body)


class FakeSession:
    """Matches tests/test_approval_flow.py's FakeSession: records added ORM
    objects instead of hitting a real database."""
    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)

    async def execute(self, _stmt):
        return None

    async def flush(self):
        pass

    async def commit(self):
        pass

    async def refresh(self, _obj):
        return None


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


@unittest.skipUnless(HAS_SQLALCHEMY and HAS_HTTPX, "sqlalchemy/httpx not installed locally")
class HttpExchangeCaptureTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def _exchanges(self, session):
        return [o for o in session.added if o.__class__.__name__ == "HttpExchange"]

    def _findings(self, session):
        return [o for o in session.added if o.__class__.__name__ == "Finding"]

    async def test_validated_sensitive_hit_creates_finding_and_exchange(self):
        session = FakeSession()
        engine = _make_engine(session)
        base = f"http://127.0.0.1:{self.port}"

        fnd = await engine._validate_and_report_sensitive_hit(f"{base}/.env")

        self.assertIsNotNone(fnd)
        self.assertEqual(len(self._findings(session)), 1)
        exchanges = self._exchanges(session)
        self.assertEqual(len(exchanges), 1)
        self.assertEqual(exchanges[0].status_code, 200)
        self.assertEqual(exchanges[0].method, "GET")
        self.assertIn(".env", exchanges[0].url)

    async def test_generic_page_creates_neither_finding_nor_exchange(self):
        # The differential/body-validation guard (item 7) must suppress a hit
        # before any finding/exchange work happens for a non-matching body.
        session = FakeSession()
        engine = _make_engine(session)
        base = f"http://127.0.0.1:{self.port}"

        fnd = await engine._validate_and_report_sensitive_hit(f"{base}/some-random-path")

        self.assertIsNone(fnd)
        self.assertEqual(len(self._findings(session)), 0)
        self.assertEqual(len(self._exchanges(session)), 0)

    async def test_capture_proof_attaches_exchange_to_an_existing_finding(self):
        session = FakeSession()
        engine = _make_engine(session)
        base = f"http://127.0.0.1:{self.port}"

        fnd = await engine.add_finding(
            title="SQL Injection (sqlmap-confirmed): id (GET)", severity="critical",
            description="d", evidence="e", cvss_score=9.8, remediation="r")
        await engine._capture_proof(f"{base}/catalog?id=1", fnd.id, notes="proof")

        exchanges = self._exchanges(session)
        self.assertEqual(len(exchanges), 1)
        self.assertEqual(exchanges[0].finding_id, fnd.id)
        self.assertEqual(exchanges[0].status_code, 200)

    async def test_backup_payload_includes_nonzero_http_exchanges(self):
        from core.backup import build_backup_payload, validate_backup_payload

        session = FakeSession()
        engine = _make_engine(session)
        base = f"http://127.0.0.1:{self.port}"
        fnd = await engine._validate_and_report_sensitive_hit(f"{base}/.env")
        self.assertIsNotNone(fnd)

        exchange_dicts = [{
            "url": ex.url, "method": ex.method, "status_code": ex.status_code,
            "response_body": ex.response_body, "request_headers": ex.request_headers,
            "response_headers": ex.response_headers,
        } for ex in self._exchanges(session)]

        payload = build_backup_payload(
            "workspace-1", mission={"target": "127.0.0.1", "mode": "full"},
            findings=[{"title": fnd.title, "severity": fnd.severity}],
            exchanges=exchange_dicts,
        )
        self.assertGreater(len(payload["state"]["http_exchanges"]), 0)

        # Round-trips through the same validation the import endpoint runs.
        validated = validate_backup_payload(payload)
        self.assertGreater(len(validated["http_exchanges"]), 0)


if __name__ == "__main__":
    unittest.main()
