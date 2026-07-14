"""Tests for the optional/deep tool registrations in core.tooling.

gau, trufflehog, and jsluice are registered so scanner-health can show
ran/skipped/missing for them, but — unlike the core scanners — their absence
must NOT emit a warning (it's a normal lightweight-deployment state, and
warning about it would train operators to ignore warnings that matter).
"""
import unittest
from unittest.mock import AsyncMock, patch

from core.tooling import CLI_TOOLS, OPTIONAL_TOOLS, check_cli_tools, format_warnings


class OptionalToolRegistrationTests(unittest.TestCase):
    def test_new_tools_registered(self):
        for name in ("gau", "trufflehog", "jsluice"):
            self.assertIn(name, CLI_TOOLS)

    def test_optional_set_matches(self):
        self.assertEqual(OPTIONAL_TOOLS, frozenset({"gau", "trufflehog", "jsluice"}))

    def test_version_commands_are_non_blocking_flags(self):
        # Each uses a --version-style flag (exits fast) rather than a bare
        # invocation that could block reading stdin.
        for name in OPTIONAL_TOOLS:
            cmd, _ = CLI_TOOLS[name]
            self.assertEqual(cmd[0], name)
            self.assertTrue(any(a.startswith("-") for a in cmd[1:]))


class OptionalToolWarningTests(unittest.TestCase):
    def test_absent_optional_tool_produces_no_warning(self):
        results = {
            "gau": {"available": False, "version": None},
            "trufflehog": {"available": False, "version": None},
            "jsluice": {"available": False, "version": None},
        }
        self.assertEqual(format_warnings(results), [])

    def test_absent_required_tool_still_warns_even_with_optionals_absent(self):
        results = {
            "nmap": {"available": False, "version": None},   # required -> warns
            "gau": {"available": False, "version": None},     # optional -> silent
        }
        warnings = format_warnings(results)
        self.assertEqual(len(warnings), 1)
        self.assertIn("nmap", warnings[0])


class OptionalToolPresenceDetectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_gau_binary_reports_unavailable(self):
        with patch("asyncio.create_subprocess_exec", AsyncMock(side_effect=FileNotFoundError())):
            results = await check_cli_tools({"gau": CLI_TOOLS["gau"]})
        self.assertEqual(results["gau"], {"available": False, "version": None})

    async def test_present_tool_with_unparseable_version_still_available(self):
        # trufflehog present but version banner not matched -> available, unknown.
        class FakeProc:
            returncode = 0

            async def communicate(self):
                return b"trufflehog\n", b""

        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=FakeProc())):
            results = await check_cli_tools({"trufflehog": CLI_TOOLS["trufflehog"]})
        self.assertTrue(results["trufflehog"]["available"])


if __name__ == "__main__":
    unittest.main()
