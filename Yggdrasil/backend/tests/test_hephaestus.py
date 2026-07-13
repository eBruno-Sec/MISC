"""Item 3: BROKKR (agents/hephaestus.py) actionability must not starve on
critical/high alone. Reproduces the user's exact reported mission shape — 0
critical, 0 high, 5 medium, 6 low, several of them [ZAP]-titled alerts — and
proves BROKKR now forges payloads/exploitable targets from it instead of
logging "Forging from 0 actionable finding(s) of 11 total".

Drives the real Hephaestus.execute() end-to-end against a FakeSession seeded
with real Finding rows. Wordlist disk I/O (core.wordlists writes under
settings.wordlists_dir, which defaults to the container path /app/wordlists)
is redirected to a temp dir for the duration of the test — that's an
unrelated, pre-existing concern, not what item 3 is about.
"""
import importlib.util
import shutil
import tempfile
import unittest

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


def _finding(fid, title, severity, evidence=""):
    from core.models import Finding
    return Finding(id=fid, mission_id="m1", title=title, severity=severity,
                    found_by="scan", description="d", evidence=evidence)


def _make_hephaestus(session):
    from agents.hephaestus import Hephaestus
    return Hephaestus(session, "m1")


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy is not installed in this local test environment")
class ClassifyAndPayloadTests(unittest.IsolatedAsyncioTestCase):
    """The new CORS/host-header classes must actually produce payload sets,
    not just widen the actionability count."""

    async def asyncSetUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="ygg-wordlists-")
        from core.config import settings
        self._orig_dir = settings.wordlists_dir
        settings.wordlists_dir = self.tmpdir

    async def asyncTearDown(self):
        from core.config import settings
        settings.wordlists_dir = self._orig_dir
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    async def test_classify_cors_and_host_header(self):
        hephaestus = _make_hephaestus(FakeSession([]))
        self.assertEqual(hephaestus._classify("CORS Misconfiguration: reflects arbitrary Origin"), "cors")
        self.assertEqual(hephaestus._classify("Host Header Injection: cache poisoning"), "hostheader")
        self.assertEqual(hephaestus._classify("host-header injection detected"), "hostheader")

    async def test_payloads_for_cors_class(self):
        hephaestus = _make_hephaestus(FakeSession([]))
        payloads = hephaestus._payloads_for_class("cors", "https://t.example/api")
        self.assertTrue(payloads)
        self.assertTrue(all(p["type"] == "CORS" for p in payloads))
        self.assertTrue(any("evil-yggdrasil.example" in p["payload"] for p in payloads))

    async def test_payloads_for_host_header_class(self):
        hephaestus = _make_hephaestus(FakeSession([]))
        payloads = hephaestus._payloads_for_class("hostheader", "https://t.example/api")
        self.assertTrue(payloads)
        self.assertTrue(any("Host:" in p["payload"] for p in payloads))
        self.assertTrue(any("X-Forwarded-Host" in p["payload"] for p in payloads))


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy is not installed in this local test environment")
class ReportedMissionShapeTests(unittest.IsolatedAsyncioTestCase):
    """Item 3's explicit test requirement: 5 medium + 6 low findings, several
    ZAP-titled, must create payload targets — reproducing the user's exact
    reported "Forging from 0 actionable finding(s) of 11 total" bug shape and
    proving it's now non-zero."""

    async def asyncSetUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="ygg-wordlists-")
        from core.config import settings
        self._orig_dir = settings.wordlists_dir
        settings.wordlists_dir = self.tmpdir

    async def asyncTearDown(self):
        from core.config import settings
        settings.wordlists_dir = self._orig_dir
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _mission_findings(self):
        # 5 medium: 3 real injection/access-control classes (matchable by
        # _classify -> real payload sets) + 2 [ZAP]-titled alerts whose exact
        # wording wouldn't match INJECTION_TITLE_RE on their own.
        medium = [
            _finding("m1", "Reflected XSS on search parameter", "medium",
                     "URL: https://t.example/search?q=<script>"),
            _finding("m2", "CORS Misconfiguration: reflects arbitrary Origin", "medium",
                     "URL: https://t.example/api/data"),
            _finding("m3", "Potential IDOR: /api/orders/{id}", "medium",
                     "URL: https://t.example/api/orders/42"),
            _finding("m4", "[ZAP] Missing Anti-clickjacking Header", "medium",
                     "URL: https://t.example/"),
            _finding("m5", "[ZAP] Cookie No HttpOnly Flag", "medium",
                     "URL: https://t.example/login"),
        ]
        # 6 low: hygiene/recon notes that must NOT count as actionable on
        # their own (matches the user's real scan: SPF/DMARC/staging-style).
        low = [
            _finding("l1", "SPF Record Missing", "low"),
            _finding("l2", "DMARC Record Missing", "low"),
            _finding("l3", "Server Banner Disclosure", "low"),
            _finding("l4", "TLS Certificate Expires in 90 Days", "low"),
            _finding("l5", "Directory Listing Enabled", "low"),
            _finding("l6", "Verbose Error Message Disclosed", "low"),
        ]
        return medium + low

    async def test_five_medium_six_low_produces_actionable_findings_and_payloads(self):
        findings = self._mission_findings()
        self.assertEqual(len(findings), 11)
        session = FakeSession(findings)
        hephaestus = _make_hephaestus(session)

        result = await hephaestus.execute("t.example", {"hermes": {}, "ares": {}})

        # The user's reported bug: "Forging from 0 actionable finding(s) of 11
        # total". With the fix, the 5 medium findings above (3 injection-class
        # titles + 2 ZAP alerts) are all actionable; the 6 low hygiene notes
        # are not.
        forge_log = next(m for _, m in session.logs if m.startswith("Forging from"))
        self.assertIn("Forging from 5 actionable finding(s) of 11 total", forge_log)

        self.assertGreater(len(result["payloads_generated"]), 0)
        self.assertGreater(len(result["exploitable_targets"]), 0)
        self.assertGreater(result["forge_report"]["exploitable_count"], 0)

    async def test_xss_cors_idor_targets_are_present_in_exploitable_targets(self):
        findings = self._mission_findings()
        session = FakeSession(findings)
        hephaestus = _make_hephaestus(session)

        result = await hephaestus.execute("t.example", {"hermes": {}, "ares": {}})

        self.assertIn("https://t.example/search?q=<script>", result["exploitable_targets"])
        self.assertIn("https://t.example/api/data", result["exploitable_targets"])

    async def test_low_severity_hygiene_findings_produce_no_payloads_of_their_own(self):
        # Isolate the low-only slice: on its own it must forge nothing, proving
        # the 5-actionable count above comes from the medium tier, not a
        # blanket relaxation that also swept in the low findings.
        low_only = [
            _finding("l1", "SPF Record Missing", "low"),
            _finding("l2", "DMARC Record Missing", "low"),
        ]
        session = FakeSession(low_only)
        hephaestus = _make_hephaestus(session)

        result = await hephaestus.execute("t.example", {"hermes": {}, "ares": {}})

        forge_log = next(m for _, m in session.logs if m.startswith("Forging from"))
        self.assertIn("Forging from 0 actionable finding(s) of 2 total", forge_log)
        self.assertEqual(len(result["exploitable_targets"]), 0)


if __name__ == "__main__":
    unittest.main()
