import copy
import importlib.util
import os
import tempfile
from types import SimpleNamespace
import unittest

from core.backup import (
    BackupValidationError,
    MAX_FINDINGS,
    build_backup_payload,
    safe_backup_filename,
    summarize_backup,
    validate_backup_payload,
)
from core.config import settings
from core.poc import REDACTION, redact_headers, render_markdown_poc

HAS_SQLALCHEMY = importlib.util.find_spec("sqlalchemy") is not None


class BackupContractTests(unittest.TestCase):
    def sample_payload(self):
        return build_backup_payload(
            workspace_id="mission-1",
            mission={
                "target": "example.com",
                "scope": "authorized scope",
                "mode": "passive",
                "scope_rules": {},
                "context": {"api_key": "secret", "safe": "kept"},
            },
            findings=[{
                "title": "Injected header",
                "severity": "high",
                "description": "desc",
                "evidence": "evidence",
                "cvss_score": 7.5,
                "remediation": "fix",
            }],
            notes=[{"content": "note"}],
            logs=[{"agent": "test", "level": "info", "message": "log"}],
            exchanges=[{
                "method": "GET",
                "url": "https://example.com/account",
                "request_headers": {"Authorization": "Bearer secret"},
                "response_status": 200,
            }],
        )

    def test_backup_v2_round_trip_scrubs_and_summarizes(self):
        payload = self.sample_payload()
        data = validate_backup_payload(payload)
        self.assertEqual(data["mission"]["target"], "example.com")
        self.assertEqual(data["mission"]["context"]["api_key"], REDACTION)
        summary = summarize_backup(payload)
        self.assertEqual(summary["findings"], 1)
        self.assertEqual(summary["http_exchanges"], 1)

    def test_backup_hash_mismatch_rejected(self):
        payload = self.sample_payload()
        payload["state"]["mission"]["target"] = "evil.test"
        with self.assertRaises(BackupValidationError):
            validate_backup_payload(payload)

    def test_unsupported_and_oversized_backup_rejected(self):
        payload = self.sample_payload()
        unsupported = copy.deepcopy(payload)
        unsupported["version"] = 99
        with self.assertRaises(BackupValidationError):
            validate_backup_payload(unsupported)

        oversized = copy.deepcopy(payload)
        oversized["state"]["findings"] = [{"title": f"Finding {i}"} for i in range(MAX_FINDINGS + 1)]
        oversized = build_backup_payload(
            workspace_id="mission-1",
            mission=oversized["state"]["mission"],
            findings=oversized["state"]["findings"],
            notes=[],
            logs=[],
        )
        with self.assertRaises(BackupValidationError):
            validate_backup_payload(oversized)

    def test_backup_filename_is_safe(self):
        name = safe_backup_filename("../bad path/mission")
        self.assertTrue(name.startswith("YGGDRASIL_backup_"))
        self.assertTrue(name.endswith(".json"))
        self.assertNotIn("/", name)
        self.assertNotIn("..", name)


class PocContractTests(unittest.TestCase):
    def test_headers_redacted_in_poc(self):
        headers = {"Authorization": "Bearer secret", "X-API-Key": "secret", "Accept": "text/html"}
        clean = redact_headers(headers)
        self.assertEqual(clean["Authorization"], REDACTION)
        self.assertEqual(clean["X-API-Key"], REDACTION)
        self.assertEqual(clean["Accept"], "text/html")

        markdown = render_markdown_poc("GET", "https://example.com/a", headers, None, 200, {"Set-Cookie": "sid=1"}, "ok")
        self.assertIn(REDACTION, markdown)
        self.assertNotIn("Bearer secret", markdown)
        self.assertNotIn("sid=1", markdown)


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy is not installed in this local test environment")
class ReportEscapingTests(unittest.IsolatedAsyncioTestCase):
    async def test_report_escapes_finding_fields(self):
        from agents.apollo import Apollo

        old_reports_dir = settings.reports_dir
        with tempfile.TemporaryDirectory() as tmp:
            settings.reports_dir = tmp
            finding = SimpleNamespace(
                title="<script>alert(1)</script>",
                severity="high",
                description="<img src=x onerror=alert(1)>",
                evidence="<script>steal()</script>",
                remediation="<b>escape me</b>",
                cvss_score=7.5,
                found_by="ares",
                timestamp=None,
            )
            agent = Apollo(session=None, mission_id="mission-escape")
            path = await agent._generate_html_report(
                "<target>",
                [finding],
                {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
                "Summary <script>x</script>",
                {"athena": {"mode": "passive"}},
            )
            html = open(path, encoding="utf-8").read()
            self.assertNotIn("<script>alert(1)</script>", html)
            self.assertNotIn("<img src=x onerror=alert(1)>", html)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
            self.assertIn("&lt;target&gt;", html)
        settings.reports_dir = old_reports_dir

    async def test_report_render_error_is_returned_for_retry(self):
        from agents.apollo import Apollo

        class EmptyResult:
            def scalars(self):
                return self

            def all(self):
                return []

        class FakeSession:
            def __init__(self):
                self.added = []

            async def execute(self, _stmt):
                return EmptyResult()

            def add(self, obj):
                self.added.append(obj)

            async def commit(self):
                return None

            async def refresh(self, _obj):
                return None

        async def boom(*_args, **_kwargs):
            raise RuntimeError("renderer down")

        agent = Apollo(session=FakeSession(), mission_id="mission-render-error")
        agent._generate_html_report = boom

        result = await agent.execute("example.com", {"athena": {"mode": "passive"}})

        self.assertEqual(result["report_path"], "")
        self.assertEqual(result["report_error"], "renderer down")
        self.assertFalse(result["report_available"])


if __name__ == "__main__":
    unittest.main()
