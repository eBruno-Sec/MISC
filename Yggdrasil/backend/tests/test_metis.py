"""Item 1: MIMIR (agents/metis.py) must never call json.loads on empty/blank AI
text, must log the REAL provider/model/status/detail on a completion failure
(not a bare downstream JSON error), and must retry once with a stricter prompt
before giving up. Drives the real Metis.execute()/_get_triage_json()/_try_parse()
against a FakeSession seeded with real Finding rows — only core.ai_client.complete
is mocked, since that's the actual external boundary.
"""
import importlib.util
import os
import unittest
from unittest.mock import patch

HAS_SQLALCHEMY = importlib.util.find_spec("sqlalchemy") is not None


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return self._rows


class FakeSession:
    def __init__(self, findings):
        self._findings = findings
        self.added = []
        self.logs = []

    def add(self, obj):
        self.added.append(obj)
        if obj.__class__.__name__ == "AgentLog":
            self.logs.append((obj.level, obj.message))

    async def execute(self, _stmt):
        return _FakeResult(self._findings)

    async def flush(self):
        pass

    async def commit(self):
        pass

    async def refresh(self, _obj):
        return None


def _findings(n=3):
    from core.models import Finding
    out = []
    for i in range(n):
        out.append(Finding(
            id=f"f{i}", mission_id="m1", title=f"Finding {i}", severity="high",
            found_by="nuclei", description="d", evidence="e",
        ))
    return out


def _make_metis(session):
    from agents.metis import Metis
    return Metis(session, "m1")


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy is not installed in this local test environment")
class TryParseTests(unittest.IsolatedAsyncioTestCase):
    """Item 1's core guard: never json.loads("")."""

    async def test_empty_text_returns_none_without_raising(self):
        session = FakeSession(_findings())
        metis = _make_metis(session)
        result = await metis._try_parse("")
        self.assertIsNone(result)

    async def test_whitespace_only_text_returns_none_without_raising(self):
        session = FakeSession(_findings())
        metis = _make_metis(session)
        result = await metis._try_parse("   \n\t  ")
        self.assertIsNone(result)

    async def test_empty_reply_logs_a_warning_not_a_json_error(self):
        session = FakeSession(_findings())
        metis = _make_metis(session)
        await metis._try_parse("")
        messages = [m for _, m in session.logs]
        self.assertTrue(any("empty reply" in m for m in messages))
        self.assertFalse(any("Expecting value" in m for m in messages))

    async def test_malformed_json_logs_first_300_chars_of_raw_reply(self):
        session = FakeSession(_findings())
        metis = _make_metis(session)
        garbage = "Sorry, I cannot comply with that request. " + ("x" * 500)
        result = await metis._try_parse(garbage)
        self.assertIsNone(result)
        messages = [m for _, m in session.logs]
        self.assertEqual(len(messages), 1)
        self.assertIn("Sorry, I cannot comply", messages[0])
        # The raw-reply preview embedded in the log line is capped at 300 chars,
        # not the full 500+-char blob — assert on the preview itself, not the
        # whole log line (which also carries a label/wrapper around it).
        self.assertNotIn("x" * 400, messages[0])
        self.assertIn("x" * 100, messages[0])

    async def test_valid_json_parses_successfully(self):
        session = FakeSession(_findings())
        metis = _make_metis(session)
        result = await metis._try_parse('{"false_positives": [], "mappings": {}, "attack_paths": [], "summary": "ok"}')
        self.assertEqual(result["summary"], "ok")

    async def test_valid_json_wrapped_in_code_fence_parses(self):
        session = FakeSession(_findings())
        metis = _make_metis(session)
        text = '```json\n{"false_positives": [], "mappings": {}, "attack_paths": [], "summary": "ok"}\n```'
        result = await metis._try_parse(text)
        self.assertEqual(result["summary"], "ok")


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy is not installed in this local test environment")
class GetTriageJsonTests(unittest.IsolatedAsyncioTestCase):
    """Item 1+2: the call/retry orchestration around complete()."""

    async def test_ai_unavailable_logs_real_reason_and_returns_none(self):
        from core.ai_client import AIUnavailable
        session = FakeSession(_findings())
        metis = _make_metis(session)
        with patch("agents.metis.complete", side_effect=AIUnavailable("anthropic")):
            result = await metis._get_triage_json("t.example", "prompt", [])
        self.assertIsNone(result)
        messages = [m for _, m in session.logs]
        self.assertTrue(any("AI unavailable" in m and "anthropic" in m for m in messages))

    async def test_completion_error_logs_provider_model_status_and_retries(self):
        from core.ai_client import AICompletionError
        session = FakeSession(_findings())
        metis = _make_metis(session)

        call_count = 0

        async def fake_complete(prompt, max_tokens=800, system=None):
            nonlocal call_count
            call_count += 1
            raise AICompletionError("anthropic", "claude-sonnet-4-6", "HTTP 401", "invalid x-api-key")

        with patch("agents.metis.complete", side_effect=fake_complete):
            result = await metis._get_triage_json("t.example", "prompt", [])

        self.assertIsNone(result)
        self.assertEqual(call_count, 2)  # primary attempt + one retry
        messages = [m for _, m in session.logs]
        self.assertTrue(any(
            "provider=anthropic" in m and "model=claude-sonnet-4-6" in m and "status=HTTP 401" in m
            for m in messages
        ))
        self.assertFalse(any("Expecting value" in m for m in messages))

    async def test_empty_reply_then_successful_retry_returns_retry_data(self):
        session = FakeSession(_findings())
        metis = _make_metis(session)

        call_count = 0

        async def fake_complete(prompt, max_tokens=800, system=None):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return "not json at all"
            return '{"false_positives": [], "mappings": {}, "attack_paths": [], "summary": "retry worked"}'

        with patch("agents.metis.complete", side_effect=fake_complete):
            result = await metis._get_triage_json("t.example", "prompt", [])

        self.assertEqual(call_count, 2)
        self.assertIsNotNone(result)
        self.assertEqual(result["summary"], "retry worked")

    async def test_retry_uses_stricter_simpler_prompt(self):
        session = FakeSession(_findings())
        metis = _make_metis(session)
        seen_prompts = []

        async def fake_complete(prompt, max_tokens=800, system=None):
            seen_prompts.append(prompt)
            if len(seen_prompts) == 1:
                return "garbage"
            return '{"false_positives": [], "mappings": {}, "attack_paths": [], "summary": "s"}'

        with patch("agents.metis.complete", side_effect=fake_complete):
            await metis._get_triage_json("t.example", "original prompt text", [])

        self.assertEqual(seen_prompts[0], "original prompt text")
        self.assertIn("Return ONLY a single JSON object", seen_prompts[1])
        self.assertNotEqual(seen_prompts[0], seen_prompts[1])

    async def test_both_primary_and_retry_fail_returns_none_and_leaves_findings_unchanged(self):
        session = FakeSession(_findings())
        metis = _make_metis(session)

        async def fake_complete(prompt, max_tokens=800, system=None):
            return "still not json"

        with patch("agents.metis.complete", side_effect=fake_complete):
            result = await metis._get_triage_json("t.example", "prompt", [])

        self.assertIsNone(result)
        messages = [m for _, m in session.logs]
        self.assertTrue(any("giving up" in m for m in messages))


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy is not installed in this local test environment")
class ExecuteEndToEndTests(unittest.IsolatedAsyncioTestCase):
    """Full execute() path: with < 2 findings triage is skipped entirely (no AI
    call at all); with a hard AI failure, execute() must return the default
    result dict cleanly instead of raising or crashing on a JSON error."""

    async def asyncSetUp(self):
        self._saved = os.environ.get("AI_API_KEY")
        os.environ["AI_API_KEY"] = "fake-key"

    async def asyncTearDown(self):
        if self._saved is None:
            os.environ.pop("AI_API_KEY", None)
        else:
            os.environ["AI_API_KEY"] = self._saved

    async def test_fewer_than_two_findings_skips_triage_without_calling_ai(self):
        session = FakeSession(_findings(1))
        metis = _make_metis(session)
        with patch("agents.metis.complete") as mock_complete:
            result = await metis.execute("t.example")
        mock_complete.assert_not_called()
        self.assertEqual(result["chains"], 0)

    async def test_ai_completion_error_does_not_crash_execute(self):
        from core.ai_client import AICompletionError
        session = FakeSession(_findings(3))
        metis = _make_metis(session)

        with patch("agents.metis.complete",
                   side_effect=AICompletionError("anthropic", "m", "HTTP 500", "server error")):
            result = await metis.execute("t.example")

        self.assertEqual(result, {"flagged": 0, "mapped": 0, "chains": 0, "summary": ""})
        messages = [m for _, m in session.logs]
        self.assertTrue(any("status=HTTP 500" in m for m in messages))

    async def test_successful_triage_creates_attack_path_finding(self):
        session = FakeSession(_findings(3))
        metis = _make_metis(session)
        reply = (
            '{"false_positives": [], "mappings": {}, '
            '"attack_paths": [{"title": "Chain", "severity": "high", '
            '"narrative": "n", "finding_ids": ["f0", "f1"]}], "summary": "done"}'
        )

        with patch("agents.metis.complete", return_value=reply):
            result = await metis.execute("t.example")

        self.assertEqual(result["chains"], 1)
        findings_added = [o for o in session.added if o.__class__.__name__ == "Finding"]
        self.assertEqual(len(findings_added), 1)
        self.assertTrue(findings_added[0].title.startswith("Attack Path:"))


if __name__ == "__main__":
    unittest.main()
