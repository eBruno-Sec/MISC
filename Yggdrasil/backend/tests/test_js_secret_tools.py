"""Tests for the optional/deep tool integrations: gau URL discovery and the
jsluice/trufflehog JS-secret pass.

Two layers:
- Pure output parsers (parse_jsluice_secrets/urls, parse_trufflehog_output,
  redact_secret) exercised against realistic newline-delimited-JSON fixtures,
  including junk lines the tools interleave — a malformed line must degrade to
  'one fewer result', never a crash.
- The engine methods (gather_gau_urls, _emit_secret_finding) driven through a
  real Ares instance with run_command mocked, proving graceful skip on a
  missing binary and that only REDACTED secrets reach a finding.
"""
import importlib.util
import unittest
from unittest.mock import patch

HAS_SQLALCHEMY = importlib.util.find_spec("sqlalchemy") is not None
try:
    from agents.offensive import (
        redact_secret, parse_jsluice_secrets, parse_jsluice_urls,
        parse_trufflehog_output,
    )
    HAS_OFFENSIVE = True
except Exception:
    HAS_OFFENSIVE = False


@unittest.skipUnless(HAS_OFFENSIVE, "agents.offensive not importable (missing PyYAML?)")
class RedactionTests(unittest.TestCase):
    def test_short_secret_fully_masked(self):
        self.assertEqual(redact_secret("abc123"), "******")

    def test_long_secret_shows_head_and_tail_only(self):
        r = redact_secret("AKIAIOSFODNN7EXAMPLE")   # 20 chars
        self.assertTrue(r.startswith("AKIA"))
        self.assertTrue(r.endswith("LE"))
        self.assertNotIn("IOSFODNN7EXAMP", r)       # middle is masked
        self.assertEqual(len(r), len("AKIAIOSFODNN7EXAMPLE"))

    def test_empty_is_safe(self):
        self.assertEqual(redact_secret(""), "")


@unittest.skipUnless(HAS_OFFENSIVE, "agents.offensive not importable (missing PyYAML?)")
class JsluiceParserTests(unittest.TestCase):
    def test_secrets_parsed_and_redacted(self):
        out = (
            '{"kind":"AWS Access Key","severity":"high","data":"AKIAIOSFODNN7EXAMPLE"}\n'
            '{"kind":"generic","severity":"medium","data":{"key":"supersecrettoken1234"}}\n'
            "this is not json\n"
            "\n"
        )
        hits = parse_jsluice_secrets(out)
        self.assertEqual(len(hits), 2)
        self.assertEqual(hits[0]["kind"], "AWS Access Key")
        self.assertEqual(hits[0]["severity"], "high")
        # Raw retained internally, but the display 'secret' is redacted.
        self.assertEqual(hits[0]["raw"], "AKIAIOSFODNN7EXAMPLE")
        self.assertNotEqual(hits[0]["secret"], hits[0]["raw"])
        self.assertNotIn("IOSFODNN7EXAMP", hits[0]["secret"])

    def test_secrets_missing_data_skipped(self):
        self.assertEqual(parse_jsluice_secrets('{"kind":"x","severity":"low"}\n'), [])

    def test_urls_deduped_first_seen(self):
        out = (
            '{"url":"/api/v1/users","method":"GET"}\n'
            '{"url":"/api/v1/login","method":"POST"}\n'
            '{"url":"/api/v1/users","method":"GET"}\n'
            "garbage line\n"
        )
        self.assertEqual(parse_jsluice_urls(out), ["/api/v1/users", "/api/v1/login"])

    def test_empty_output_is_empty_list(self):
        self.assertEqual(parse_jsluice_urls(""), [])
        self.assertEqual(parse_jsluice_secrets(""), [])


@unittest.skipUnless(HAS_OFFENSIVE, "agents.offensive not importable (missing PyYAML?)")
class TrufflehogParserTests(unittest.TestCase):
    def test_verified_is_high_unverified_is_medium(self):
        out = (
            '{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/app.js"}}},'
            '"DetectorName":"AWS","Verified":true,"Raw":"AKIAIOSFODNN7EXAMPLE"}\n'
            '{"SourceMetadata":{"Data":{"Filesystem":{"file":"/tmp/app.js"}}},'
            '"DetectorName":"Slack","Verified":false,"Raw":"xoxb-1234567890-abcdef"}\n'
            '{"level":"info","msg":"scanning..."}\n'   # non-result line: no DetectorName
        )
        hits = parse_trufflehog_output(out)
        self.assertEqual(len(hits), 2)
        aws = next(h for h in hits if h["detector"] == "AWS")
        slack = next(h for h in hits if h["detector"] == "Slack")
        self.assertTrue(aws["verified"])
        self.assertEqual(aws["severity"], "high")
        self.assertFalse(slack["verified"])
        self.assertEqual(slack["severity"], "medium")
        self.assertEqual(aws["file"], "/tmp/app.js")
        self.assertNotEqual(aws["secret"], aws["raw"])   # redacted for display

    def test_non_result_lines_skipped(self):
        self.assertEqual(parse_trufflehog_output('{"msg":"no detector here"}\n'), [])

    def test_malformed_json_never_raises(self):
        self.assertEqual(parse_trufflehog_output("not json at all\n{oops\n"), [])


# ── Engine-method tests (need SQLAlchemy for the real Ares/BaseAgent) ──────────
if HAS_SQLALCHEMY and HAS_OFFENSIVE:
    class FakeSession:
        def __init__(self):
            self.added = []

        def add(self, obj):
            self.added.append(obj)

        async def execute(self, _stmt):
            return None

        async def commit(self):
            pass

        async def get(self, *_a, **_k):
            return None

    def _make_ares():
        from agents.ares import Ares
        return Ares(FakeSession(), "m-test")


@unittest.skipUnless(HAS_SQLALCHEMY and HAS_OFFENSIVE, "SQLAlchemy/offensive not available")
class GauDiscoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_binary_skips_gracefully_and_records_tool(self):
        ares = _make_ares()

        async def fake_run(cmd, timeout=300):
            return "", "Tool not found: gau", 127

        with patch.object(ares, "run_command", side_effect=fake_run):
            out = await ares.gather_gau_urls("https://t.example")
        self.assertEqual(out, [])
        self.assertIn("gau", getattr(ares, "_tools_missing", set()))

    async def test_parses_urls_params_first_static_dropped(self):
        ares = _make_ares()
        stdout = (
            "https://t.example/a?id=1\n"
            "https://t.example/style.css\n"      # static asset -> dropped
            "https://t.example/about\n"
            "https://t.example/b?q=x\n"
            "notaurl\n"
        )

        async def fake_run(cmd, timeout=300):
            self.assertEqual(cmd[0], "gau")
            self.assertIn("t.example", cmd)
            return stdout, "", 0

        with patch.object(ares, "run_command", side_effect=fake_run):
            out = await ares.gather_gau_urls("https://t.example")

        self.assertIn("https://t.example/a?id=1", out)
        self.assertIn("https://t.example/b?q=x", out)
        self.assertIn("https://t.example/about", out)
        self.assertNotIn("https://t.example/style.css", out)
        # Parameterized URLs are ordered ahead of the non-parameterized one.
        self.assertLess(out.index("https://t.example/a?id=1"),
                        out.index("https://t.example/about"))


@unittest.skipUnless(HAS_SQLALCHEMY and HAS_OFFENSIVE, "SQLAlchemy/offensive not available")
class EmitSecretFindingTests(unittest.IsolatedAsyncioTestCase):
    async def test_finding_stores_only_redacted_value_and_flags_verified(self):
        from core.models import Finding
        ares = _make_ares()

        async def fake_capture(*_a, **_k):
            return None

        with patch.object(ares, "_capture_proof", side_effect=fake_capture):
            row = await ares._emit_secret_finding(
                detector="AWS", severity="high", redacted="AKIA****LE",
                source_url="https://t.example/app.js", tool="trufflehog", verified=True)

        self.assertEqual(row["detector"], "AWS")
        self.assertTrue(row["verified"])
        self.assertEqual(row["severity"], "high")
        # A Finding was persisted; its evidence carries the redacted value and
        # the VERIFIED marker, never a raw secret.
        findings = [o for o in ares.session.added if isinstance(o, Finding)]
        self.assertEqual(len(findings), 1)
        self.assertIn("AKIA****LE", findings[0].evidence)
        self.assertIn("VERIFIED", findings[0].title)

    async def test_unverified_finding_is_medium_and_labeled(self):
        from core.models import Finding
        ares = _make_ares()

        async def fake_capture(*_a, **_k):
            return None

        with patch.object(ares, "_capture_proof", side_effect=fake_capture):
            row = await ares._emit_secret_finding(
                detector="Slack", severity="medium", redacted="xoxb****ef",
                source_url="https://t.example/app.js", tool="jsluice", verified=False)

        self.assertEqual(row["severity"], "medium")
        findings = [o for o in ares.session.added if isinstance(o, Finding)]
        self.assertIn("unverified", findings[0].title.lower())


if __name__ == "__main__":
    unittest.main()
