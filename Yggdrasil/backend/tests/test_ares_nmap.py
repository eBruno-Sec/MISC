"""Item 6: nmap must not silently erase known HTTP liveness. Confirmed against
a real nmap 7.94 binary that -p and --top-ports are mutually exclusive
(whichever is given wins outright, they do not union), so an explicit
host:port target unions 80/443 into its own -p list, and -Pn is always present
so a host that fails nmap's own discovery ping (common behind a WAF/CDN that
filters ICMP) still gets port-scanned instead of marked "down" and skipped.

Drives the real Ares._nmap_scan() with run_command mocked to capture the exact
argv it builds — proving the actual shipped command construction, not a
hand-typed reimplementation of what it "should" look like.
"""
import importlib.util
import os
import unittest
from unittest.mock import patch

HAS_SQLALCHEMY = importlib.util.find_spec("sqlalchemy") is not None


class FakeSession:
    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)

    async def execute(self, _stmt):
        return None

    async def commit(self):
        pass


def _make_ares(session):
    from agents.ares import Ares
    return Ares(session, "m1")


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy is not installed in this local test environment")
class SplitHostPortTests(unittest.TestCase):
    def test_bare_host_has_no_port(self):
        ares = _make_ares(FakeSession())
        host, port = ares._split_hp("t.example")
        self.assertEqual(host, "t.example")
        self.assertIsNone(port)

    def test_host_with_explicit_port_is_split(self):
        ares = _make_ares(FakeSession())
        host, port = ares._split_hp("t.example:3000")
        self.assertEqual(host, "t.example")
        self.assertEqual(port, "3000")

    def test_ipv6_style_multiple_colons_not_treated_as_port(self):
        ares = _make_ares(FakeSession())
        host, port = ares._split_hp("::1:notaport:x")
        self.assertIsNone(port)


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy is not installed in this local test environment")
class NmapCommandConstructionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self._saved_aggr = os.environ.get("YGGDRASIL_NMAP_AGGRESSIVE")
        self._saved_evasion = os.environ.get("YGGDRASIL_NMAP_EVASION")
        os.environ["YGGDRASIL_NMAP_AGGRESSIVE"] = "0"
        os.environ.pop("YGGDRASIL_NMAP_EVASION", None)

    async def asyncTearDown(self):
        for key, val in (("YGGDRASIL_NMAP_AGGRESSIVE", self._saved_aggr),
                         ("YGGDRASIL_NMAP_EVASION", self._saved_evasion)):
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val

    async def _captured_cmd(self, hosts):
        ares = _make_ares(FakeSession())
        captured = {}

        async def fake_run_command(cmd, timeout=300):
            captured["cmd"] = cmd
            return "", "", 0

        with patch.object(ares, "run_command", side_effect=fake_run_command):
            await ares._nmap_scan(hosts)
        return captured["cmd"]

    async def test_dash_pn_always_present(self):
        cmd = await self._captured_cmd([{"host": "t.example"}])
        self.assertIn("-Pn", cmd)

    async def test_no_explicit_port_uses_top_ports_alone(self):
        cmd = await self._captured_cmd([{"host": "t.example"}])
        self.assertIn("--top-ports", cmd)
        self.assertEqual(cmd[cmd.index("--top-ports") + 1], "1000")
        self.assertNotIn("-p", cmd)

    async def test_explicit_port_unions_80_and_443(self):
        cmd = await self._captured_cmd([{"host": "t.example:3000"}])
        self.assertIn("-p", cmd)
        ports = cmd[cmd.index("-p") + 1]
        self.assertEqual(ports, "80,443,3000")
        self.assertNotIn("--top-ports", cmd)

    async def test_explicit_port_already_including_80_does_not_duplicate(self):
        cmd = await self._captured_cmd([{"host": "t.example:80"}])
        ports = cmd[cmd.index("-p") + 1]
        self.assertEqual(ports, "80,443")

    async def test_multiple_hosts_with_different_explicit_ports_union_all(self):
        cmd = await self._captured_cmd([
            {"host": "a.example:8080"}, {"host": "b.example:9090"},
        ])
        ports = cmd[cmd.index("-p") + 1]
        self.assertEqual(ports, "80,443,8080,9090")

    async def test_bare_host_mixed_with_explicit_port_host_still_unions(self):
        # Any host in the batch carrying an explicit port switches the whole
        # nmap invocation (nmap scans one port set for all targets in one run)
        # to the explicit -p branch, which is guaranteed to include 80/443.
        cmd = await self._captured_cmd([{"host": "a.example"}, {"host": "b.example:3000"}])
        self.assertIn("-p", cmd)
        ports = cmd[cmd.index("-p") + 1]
        self.assertEqual(ports, "80,443,3000")

    async def test_dash_pn_present_in_both_port_branches(self):
        cmd_explicit = await self._captured_cmd([{"host": "t.example:3000"}])
        cmd_top = await self._captured_cmd([{"host": "t.example"}])
        self.assertIn("-Pn", cmd_explicit)
        self.assertIn("-Pn", cmd_top)

    async def test_hosts_and_ports_never_collide_with_top_ports_flag(self):
        # Regression guard for the exact bug this fix targets: -p and
        # --top-ports must never both appear (nmap would silently let one win
        # and the other be dead weight / a misleading log message).
        cmd = await self._captured_cmd([{"host": "t.example:3000"}])
        self.assertFalse({"-p", "--top-ports"} <= set(cmd))


if __name__ == "__main__":
    unittest.main()
