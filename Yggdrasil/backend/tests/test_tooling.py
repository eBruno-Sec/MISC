"""Tests for core.tooling: CLI tool version parsing and ZAP's boot-race retry.

Prompted by two real production observations, in order:
1. `docker compose exec backend curl http://zap:8090/...` succeeded immediately
   after `docker compose up`, but the startup log's one-shot check_zap() reported
   NOT AVAILABLE — ZAP's daemon hadn't finished booting when the single-shot
   check ran a few seconds earlier.
2. After fixing (1), nuclei still showed "vunknown" in production while katana
   and subfinder correctly showed real versions. The fix that made katana/
   subfinder work had WRONGLY assumed nuclei shares their "Current Version:"
   banner — real captured output (`nuclei -version 2>&1`) shows nuclei prints
   its own "Nuclei Engine Version:" line instead. The version-parsing tests
   below deliberately import CLI_TOOLS and exercise each tool's ACTUAL
   registered (cmd, pattern) entry — not a hand-typed duplicate pattern — so a
   test can no longer pass while the real shipped config is broken, which is
   exactly how the nuclei regression slipped through the first time.
"""
import unittest
from unittest.mock import AsyncMock, patch

from core.tooling import CLI_TOOLS, check_cli_tools, check_zap, format_warnings


class FakeProc:
    def __init__(self, stdout=b"", stderr=b"", returncode=0):
        self._stdout, self._stderr, self.returncode = stdout, stderr, returncode

    async def communicate(self):
        return self._stdout, self._stderr


class CliToolVersionParsingTests(unittest.IsolatedAsyncioTestCase):
    async def _check_real(self, name, stdout=b"", stderr=b"", returncode=0):
        """Run check_cli_tools against `name`'s ACTUAL entry in CLI_TOOLS (the
        real command + regex Yggdrasil ships), not a pattern reconstructed by
        the test. This is the whole point: a test that types out its own
        "equivalent" pattern can drift from production and pass while the real
        config is broken (exactly what happened with nuclei)."""
        cmd, pattern = CLI_TOOLS[name]
        with patch("asyncio.create_subprocess_exec",
                   AsyncMock(return_value=FakeProc(stdout, stderr, returncode))):
            return await check_cli_tools({name: (cmd, pattern)})

    async def _check_one(self, name, cmd, pattern, stdout=b"", stderr=b"", returncode=0):
        with patch("asyncio.create_subprocess_exec",
                   AsyncMock(return_value=FakeProc(stdout, stderr, returncode))):
            return await check_cli_tools({name: (cmd, pattern)})

    async def test_missing_binary_reports_unavailable(self):
        with patch("asyncio.create_subprocess_exec", AsyncMock(side_effect=FileNotFoundError())):
            results = await check_cli_tools({"nope": (["nope", "-v"], r"(\S+)")})
        self.assertEqual(results["nope"], {"available": False, "version": None})

    async def test_nmap_real_output_parsed_bare(self):
        results = await self._check_real(
            "nmap", stdout=b"Nmap version 7.95 ( https://nmap.org )\n")
        self.assertEqual(results["nmap"], {"available": True, "version": "7.95"})

    async def test_nuclei_real_engine_version_banner_parsed(self):
        # Real captured production output — nuclei's OWN format, confirmed to
        # differ from katana/subfinder's shared "Current Version:" banner.
        stdout = (
            b"[INF] Nuclei Engine Version: v3.3.5\n"
            b"[INF] Nuclei Config Directory: /root/.config/nuclei\n"
            b"[INF] Nuclei Cache Directory: /root/.cache/nuclei\n"
            b"[INF] PDCP Directory: /root/.pdcp\n"
        )
        results = await self._check_real("nuclei", stdout=stdout)
        self.assertEqual(results["nuclei"], {"available": True, "version": "3.3.5"})

    async def test_katana_real_projectdiscovery_shared_banner_parsed(self):
        stdout = (
            b"\n     _mm_\n"
            b"[INF] Current Version: v1.1.0\n"
            b"[INF] Latest Version: v1.1.2\n"
        )
        results = await self._check_real("katana", stdout=stdout)
        self.assertEqual(results["katana"], {"available": True, "version": "1.1.0"})

    async def test_subfinder_real_projectdiscovery_shared_banner_parsed(self):
        results = await self._check_real(
            "subfinder", stdout=b"[INF] Current Version: v2.6.6\n")
        self.assertEqual(results["subfinder"], {"available": True, "version": "2.6.6"})

    async def test_nuclei_and_katana_do_not_share_a_regex(self):
        # Guard against re-introducing the exact bug: nuclei's pattern must NOT
        # accidentally be the same object/string as katana's shared-banner one.
        self.assertNotEqual(CLI_TOOLS["nuclei"][1], CLI_TOOLS["katana"][1])

    async def test_leading_v_never_doubles_up(self):
        # Regression: a captured version that already starts with "v" must be
        # stored bare, not re-prefixed downstream into "vv3.3.5" the way the
        # startup log previously showed for nuclei.
        results = await self._check_real(
            "nuclei", stdout=b"[INF] Nuclei Engine Version: v3.3.5\n")
        self.assertEqual(results["nuclei"]["version"], "3.3.5")
        self.assertFalse(results["nuclei"]["version"].startswith("v"))

    async def test_unparseable_output_falls_back_to_unknown_but_still_available(self):
        results = await self._check_one(
            "weird", ["weird", "--version"], r"Version: (\S+)", stdout=b"no matching text here\n")
        self.assertEqual(results["weird"], {"available": True, "version": "unknown"})

    async def test_nonzero_non_127_returncode_still_available_with_unknown_version(self):
        # Only rc==127 (binary not found) means "unavailable"; a tool that runs
        # but exits nonzero on --version (some do) is still present, just with an
        # unparseable version string.
        results = await self._check_one(
            "odd", ["odd", "--version"], r"(\S+)", returncode=-1, stdout=b"")
        self.assertEqual(results["odd"], {"available": True, "version": "unknown"})


class ZapBootRaceRetryTests(unittest.IsolatedAsyncioTestCase):
    """The actual bug from production: verify check_zap() survives ZAP's daemon
    still being mid-boot on the first (or first few) attempts."""

    async def test_succeeds_immediately_when_zap_already_up(self):
        resp = AsyncMock()
        resp.status_code = 200
        resp.json = lambda: {"version": "2.17.0"}
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=client), \
             patch("asyncio.sleep", AsyncMock()) as sleep_mock:
            result = await check_zap("http://zap:8090")

        self.assertEqual(result, {"available": True, "version": "2.17.0"})
        sleep_mock.assert_not_called()   # no retry needed, no wasted sleep

    async def test_recovers_after_zap_finishes_booting_mid_retry(self):
        # First two attempts: connection refused (ZAP not listening yet).
        # Third attempt: ZAP is up. This is exactly what happened in production
        # between the startup check and the user's manual curl seconds later.
        ok_resp = AsyncMock()
        ok_resp.status_code = 200
        ok_resp.json = lambda: {"version": "2.17.0"}

        client = AsyncMock()
        client.get = AsyncMock(side_effect=[
            ConnectionRefusedError("not up yet"),
            ConnectionRefusedError("still not up"),
            ok_resp,
        ])
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=client), \
             patch("asyncio.sleep", AsyncMock()) as sleep_mock:
            result = await check_zap("http://zap:8090", retries=4, delay=2.0)

        self.assertEqual(result, {"available": True, "version": "2.17.0"})
        self.assertEqual(sleep_mock.call_count, 2)   # slept between the 2 failures

    async def test_gives_up_after_exhausting_retries_bounded_not_infinite(self):
        client = AsyncMock()
        client.get = AsyncMock(side_effect=ConnectionRefusedError("never comes up"))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=client), \
             patch("asyncio.sleep", AsyncMock()) as sleep_mock:
            result = await check_zap("http://zap:8090", retries=3, delay=1.0)

        self.assertEqual(result, {"available": False, "version": None})
        self.assertEqual(client.get.call_count, 3)   # bounded: exactly 3 tries, not infinite
        self.assertEqual(sleep_mock.call_count, 2)   # sleeps between tries only, not after the last


class FormatWarningsTests(unittest.TestCase):
    def test_only_unavailable_tools_produce_warnings(self):
        results = {
            "nmap": {"available": True, "version": "7.95"},
            "zap": {"available": False, "version": None},
        }
        warnings = format_warnings(results)
        self.assertEqual(len(warnings), 1)
        self.assertIn("zap", warnings[0])

    def test_all_available_produces_no_warnings(self):
        results = {"nmap": {"available": True, "version": "7.95"}}
        self.assertEqual(format_warnings(results), [])


if __name__ == "__main__":
    unittest.main()
