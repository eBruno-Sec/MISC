"""ORACLE (agents/oracle.py) had zero try/except around its complete() calls.
That was safe under the OLD ai_client contract (complete() returned "" on any
failure), but became a real regression under the NEW contract (complete() now
raises AIUnavailable/AICompletionError) — solve()/followup() would crash with
an uncaught exception on any AI failure instead of degrading to a fallback.
Fixed via _complete_or_none(); these tests prove the fix, not just that it
compiles.
"""
import unittest
from unittest.mock import patch

from core.ai_client import AIUnavailable, AICompletionError


class CompleteOrNoneTests(unittest.IsolatedAsyncioTestCase):
    async def test_ai_unavailable_becomes_none_with_setup_hint(self):
        from agents.oracle import _complete_or_none
        with patch("agents.oracle.complete", side_effect=AIUnavailable("anthropic")):
            text, error_note = await _complete_or_none("prompt", 100, "system")
        self.assertIsNone(text)
        self.assertIn("AI_PROVIDER", error_note)
        self.assertIn("AI_API_KEY", error_note)

    async def test_completion_error_becomes_none_with_provider_model_status(self):
        from agents.oracle import _complete_or_none
        with patch("agents.oracle.complete",
                   side_effect=AICompletionError("anthropic", "claude-sonnet-4-6", "HTTP 401", "bad key")):
            text, error_note = await _complete_or_none("prompt", 100, "system")
        self.assertIsNone(text)
        self.assertIn("anthropic/claude-sonnet-4-6", error_note)
        self.assertIn("HTTP 401", error_note)
        self.assertIn("bad key", error_note)

    async def test_completion_error_without_detail_omits_trailing_colon(self):
        from agents.oracle import _complete_or_none
        with patch("agents.oracle.complete",
                   side_effect=AICompletionError("anthropic", "m", "empty_response", "")):
            text, error_note = await _complete_or_none("prompt", 100, "system")
        self.assertIsNone(text)
        self.assertIn("anthropic/m empty_response.", error_note)

    async def test_success_passes_text_through_with_no_error_note(self):
        from agents.oracle import _complete_or_none
        with patch("agents.oracle.complete", return_value="the actual reply"):
            text, error_note = await _complete_or_none("prompt", 100, "system")
        self.assertEqual(text, "the actual reply")
        self.assertIsNone(error_note)


class SolveAndFollowupDoNotCrashOnAiFailureTests(unittest.IsolatedAsyncioTestCase):
    """The actual regression: solve()/followup() must degrade to a fallback
    dict, never let an AI exception propagate out of ORACLE."""

    async def test_solve_returns_fallback_on_ai_unavailable_instead_of_raising(self):
        from agents.oracle import solve
        with patch("agents.oracle.complete", side_effect=AIUnavailable("anthropic")):
            result = await solve("SQL injection in login form", "A lab about SQLi")
        self.assertIn("No AI response", result["summary"])
        self.assertEqual(result["steps"], [])
        self.assertEqual(result["payloads"], [])

    async def test_solve_returns_fallback_on_completion_error_instead_of_raising(self):
        from agents.oracle import solve
        with patch("agents.oracle.complete",
                   side_effect=AICompletionError("anthropic", "m", "HTTP 500", "server error")):
            result = await solve("SQL injection in login form", "A lab about SQLi")
        self.assertIn("No AI response", result["summary"])
        self.assertIn("HTTP 500", result["summary"])

    async def test_followup_returns_fallback_on_ai_unavailable_instead_of_raising(self):
        from agents.oracle import followup
        with patch("agents.oracle.complete", side_effect=AIUnavailable("anthropic")):
            result = await followup("Lab", "desc", {"vulnerability": "SQLi"}, "it did not work")
        self.assertIn("No AI response", result["summary"])

    async def test_solve_with_no_ai_failure_returns_parsed_json(self):
        from agents.oracle import solve
        reply = (
            '{"vulnerability": "SQL injection", "summary": "s", "difficulty": "apprentice", '
            '"steps": ["step1"], "payloads": [], "request": null, '
            '"success_indicator": "solved banner", "notes": ""}'
        )
        with patch("agents.oracle.complete", return_value=reply):
            result = await solve("SQLi lab", "desc")
        self.assertEqual(result["vulnerability"], "SQL injection")
        self.assertEqual(result["steps"], ["step1"])


if __name__ == "__main__":
    unittest.main()
