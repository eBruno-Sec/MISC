"""Tests for the CRLF (HTTP response-header injection) and XXE detectors, plus
the flexible dependency-fingerprint that catches underscore/dash versions
(angular_1-7-7.js). Verified live against ginandjuice.shop for CRLF + AngularJS;
these lock in the behavior."""
import importlib.util
import re
import unittest
import urllib.parse
from unittest.mock import patch, AsyncMock

import core.api_attacks as aa
import core.dependency_intel as di

HAS_SQLALCHEMY = importlib.util.find_spec("sqlalchemy") is not None


class PureCrlfXxeTests(unittest.TestCase):
    def test_crlf_payload_and_detect(self):
        self.assertIn("\r\n", aa.crlf_payload("m1"))
        self.assertTrue(aa.crlf_injected({aa.CRLF_HEADER_NAME: "m1", "x": "y"}, "m1"))
        self.assertFalse(aa.crlf_injected({"x": "y"}, "m1"))
        self.assertFalse(aa.crlf_injected({aa.CRLF_HEADER_NAME: "other"}, "m1"))

    def test_xxe_payloads_and_detect(self):
        payloads = aa.xxe_payloads()
        self.assertTrue(all("file:///etc/passwd" in p for p in payloads))
        self.assertTrue(any("<storeId>&xxe;" in p for p in payloads))
        self.assertTrue(aa.xxe_file_read("stuff root:x:0:0:root:/root:/bin/bash stuff", "938"))
        self.assertFalse(aa.xxe_file_read("938", "938"))
        self.assertTrue(aa.xxe_file_read("[fonts]\nMS Sans Serif=", ""))     # win.ini

    def test_flex_fingerprint_underscore_dash(self):
        self.assertEqual([(c["name"], c["version"]) for c in di.fingerprint_url("/resources/js/angular_1-7-7.js")],
                         [("angular", "1.7.7")])
        self.assertEqual([(c["name"], c["version"]) for c in di.fingerprint_url("/lib/react-dom_16-8-0.js")],
                         [("react-dom", "16.8.0")])
        # strict dotted names still work; unversioned still nothing.
        self.assertEqual([(c["name"], c["version"]) for c in di.fingerprint_url("/js/jquery-3.4.1.min.js")],
                         [("jquery", "3.4.1")])
        self.assertEqual(di.fingerprint_url("/vendor/lodash.min.js"), [])


class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self.request = None


if HAS_SQLALCHEMY:
    class FakeSession:
        def __init__(self):
            self.added = []

        def add(self, o):
            self.added.append(o)

        async def commit(self):
            pass

        async def get(self, *a, **k):
            return None

    def _ares():
        from agents.ares import Ares
        a = Ares(FakeSession(), "m-cx")
        a._catch_all = None
        return a


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy not available")
class CrlfEngineTests(unittest.IsolatedAsyncioTestCase):
    class Client:
        def __init__(self, reflect):
            self._reflect = reflect

        async def get(self, url, headers=None):
            # A vulnerable server reflects the injected value into a real header.
            # unquote_plus so the '+' urlencode wrote for the space decodes back.
            dec = urllib.parse.unquote_plus(url)
            m = re.search(aa.CRLF_HEADER_NAME + r":\s*(yggc\w+)", dec)
            if self._reflect and m:
                return FakeResp(200, "ok", {aa.CRLF_HEADER_NAME: m.group(1)})
            return FakeResp(200, "ok", {})

    async def test_crlf_header_injection_detected(self):
        from core.models import Finding
        ares = _ares()
        with patch.object(ares, "capture", AsyncMock(return_value=None)):
            hits = await ares._api_crlf(self.Client(reflect=True),
                                        ["http://t/catalog?category=Juice"])
        self.assertTrue(any(h["type"] == "crlf-header-injection" for h in hits))
        self.assertTrue([o for o in ares.session.added
                         if isinstance(o, Finding) and o.confidence == "confirmed"])

    async def test_no_crlf_when_stripped(self):
        ares = _ares()
        with patch.object(ares, "capture", AsyncMock(return_value=None)):
            hits = await ares._api_crlf(self.Client(reflect=False),
                                        ["http://t/catalog?category=Juice"])
        self.assertEqual(hits, [])


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy not available")
class XxeEngineTests(unittest.IsolatedAsyncioTestCase):
    class Client:
        def __init__(self, vulnerable):
            self._vuln = vulnerable

        async def post(self, url, content=None, headers=None):
            if self._vuln and content and "file:///etc/passwd" in content:
                return FakeResp(200, "error: root:x:0:0:root:/root:/bin/bash")
            return FakeResp(200, "938")

    async def test_xxe_file_read_detected(self):
        from core.models import Finding
        ares = _ares()
        with patch.object(ares, "capture", AsyncMock(return_value=None)):
            hits = await ares._api_xxe(self.Client(vulnerable=True), "http://t",
                                       ["http://t/catalog/product/stock"])
        self.assertTrue(any(h["type"] == "xxe" for h in hits))
        crit = [o for o in ares.session.added if isinstance(o, Finding) and o.severity == "critical"]
        self.assertTrue(crit)
        self.assertEqual(crit[0].confidence, "confirmed")

    async def test_no_xxe_when_not_vulnerable(self):
        ares = _ares()
        with patch.object(ares, "capture", AsyncMock(return_value=None)):
            hits = await ares._api_xxe(self.Client(vulnerable=False), "http://t",
                                       ["http://t/catalog/product/stock"])
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
