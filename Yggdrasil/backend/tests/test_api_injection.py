"""Tests for the API-aware injection engine: JSON login auth-bypass SQLi and
error-based SQLi on JSON APIs. These are what turned an 8-hygiene-finding Juice
Shop scan into real findings. Need SQLAlchemy for the real Ares.

The engine methods take an httpx client as a parameter, so a small fake client
drives them directly without patching global httpx."""
import importlib.util
import unittest
from unittest.mock import patch, AsyncMock

HAS_SQLALCHEMY = importlib.util.find_spec("sqlalchemy") is not None

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2ln"


class FakeResp:
    def __init__(self, status, text):
        self.status_code = status
        self.text = text
        self.request = None


class FakeClient:
    def __init__(self, post_router=None, get_router=None):
        self._post = post_router or (lambda u, j: FakeResp(401, "{}"))
        self._get = get_router or (lambda u: FakeResp(200, "{}"))

    async def post(self, url, json=None):
        return self._post(url, json or {})

    async def get(self, url):
        return self._get(url)


if HAS_SQLALCHEMY:
    class FakeSession:
        def __init__(self):
            self.added = []

        def add(self, obj):
            self.added.append(obj)

        async def execute(self, _s):
            return None

        async def commit(self):
            pass

        async def get(self, *a, **k):
            return None

    def _make_ares():
        from agents.ares import Ares
        a = Ares(FakeSession(), "m-api")
        a._catch_all = None
        return a

    def _ident(body):
        return body.get("email") or body.get("username") or body.get("user") or ""


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy not available")
class EndpointSelectionTests(unittest.TestCase):
    def test_api_endpoints_filters_to_rest_api(self):
        ares = _make_ares()
        urls = ["http://t/rest/products/search?q=x", "http://t/api/Users",
                "http://t/", "http://t/about", "http://t/main.js", "http://t/graphql"]
        eps = ares._api_endpoints("http://t", urls)
        self.assertIn("http://t/rest/products/search?q=x", eps)
        self.assertIn("http://t/api/Users", eps)
        self.assertIn("http://t/graphql", eps)
        self.assertNotIn("http://t/about", eps)     # no params, not api -> excluded
        self.assertNotIn("http://t/main.js", eps)

    def test_traditional_parameterized_endpoints_included_and_prioritized(self):
        # The ginandjuice bug: /catalog?category= is not /rest or /api named but
        # must still be tested. High-injection-family params sort ahead of junk.
        ares = _make_ares()
        urls = ["http://t/about", "http://t/x?junkparam=1",
                "http://t/catalog?category=Juice", "http://t/blog/post?postId=3"]
        eps = ares._api_endpoints("http://t", urls)
        self.assertIn("http://t/catalog?category=Juice", eps)
        self.assertIn("http://t/blog/post?postId=3", eps)
        self.assertNotIn("http://t/about", eps)
        # category (sqli+xss+lfi families) ranks ahead of an unknown junk param.
        self.assertLess(eps.index("http://t/catalog?category=Juice"),
                        eps.index("http://t/x?junkparam=1"))

    def test_login_endpoints_include_defaults_and_discovered(self):
        ares = _make_ares()
        eps = ares._login_endpoints("http://t", ["http://t/api/auth/signin"])
        self.assertTrue(any(e.endswith("/api/auth/signin") for e in eps))
        self.assertTrue(any(e.endswith("/rest/user/login") for e in eps))

    def test_json_has_token(self):
        ares = _make_ares()
        self.assertTrue(ares._json_has_token('{"authentication":{"token":"x"}}'))
        self.assertTrue(ares._json_has_token('{"access_token":"x"}'))
        self.assertFalse(ares._json_has_token('{"status":"success","data":[]}'))
        self.assertFalse(ares._json_has_token("not json"))


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy not available")
class LoginSqliTests(unittest.IsolatedAsyncioTestCase):
    async def test_auth_bypass_detected_as_critical(self):
        from core.models import Finding
        ares = _make_ares()

        def router(url, body):
            ident = _ident(body)
            if "OR 1=1" in ident or "'='" in ident or ident.endswith("'--"):
                return FakeResp(200, '{"authentication":{"token":"' + JWT + '"}}')
            return FakeResp(401, '{"error":"Invalid email or password."}')

        with patch.object(ares, "_capture_proof", AsyncMock(return_value=None)):
            hits = await ares._api_login_sqli(FakeClient(post_router=router),
                                              "http://t", ["http://t/rest/user/login"])
        self.assertTrue(any(h["type"] == "sqli-auth-bypass" for h in hits))
        crit = [o for o in ares.session.added if isinstance(o, Finding) and o.severity == "critical"]
        self.assertTrue(crit)
        self.assertIn("authentication bypass", crit[0].title.lower())

    async def test_no_finding_when_everyone_gets_a_token(self):
        # If the control (invalid) login also returns a token, there's no
        # differential -> must NOT claim an auth bypass.
        from core.models import Finding
        ares = _make_ares()

        def router(url, body):
            return FakeResp(200, '{"token":"' + JWT + '"}')

        with patch.object(ares, "_capture_proof", AsyncMock(return_value=None)):
            hits = await ares._api_login_sqli(FakeClient(post_router=router),
                                              "http://t", ["http://t/rest/user/login"])
        self.assertEqual(hits, [])
        self.assertFalse([o for o in ares.session.added if isinstance(o, Finding)])

    async def test_error_based_login_is_high(self):
        from core.models import Finding
        ares = _make_ares()

        def router(url, body):
            ident = _ident(body)
            if "'" in ident:
                return FakeResp(500, '{"error":"SQLITE_ERROR: near \\"\\": syntax error"}')
            return FakeResp(401, "{}")

        with patch.object(ares, "_capture_proof", AsyncMock(return_value=None)):
            hits = await ares._api_login_sqli(FakeClient(post_router=router),
                                              "http://t", ["http://t/rest/user/login"])
        self.assertTrue(any(h["type"] == "sqli-error-login" for h in hits))
        highs = [o for o in ares.session.added if isinstance(o, Finding) and o.severity == "high"]
        self.assertTrue(highs)


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy not available")
class ApiGetSqliTests(unittest.IsolatedAsyncioTestCase):
    async def test_error_based_get_param(self):
        from core.models import Finding
        ares = _make_ares()

        def get_router(url):
            if "%27" in url:                      # the single-quote injection probe
                return FakeResp(500, '{"error":"SQLITE_ERROR: unrecognized token"}')
            return FakeResp(200, '{"status":"success","data":[]}')

        with patch.object(ares, "capture", AsyncMock(return_value=None)):
            hits = await ares._api_get_sqli(FakeClient(get_router=get_router),
                                            ["http://t/rest/products/search?q=test"])
        self.assertTrue(any(h["type"] == "sqli-error-api" for h in hits))
        self.assertTrue([o for o in ares.session.added if isinstance(o, Finding) and o.severity == "high"])

    async def test_no_false_positive_when_both_clean(self):
        from core.models import Finding
        ares = _make_ares()
        # No SQL error ever -> no finding.
        with patch.object(ares, "capture", AsyncMock(return_value=None)):
            hits = await ares._api_get_sqli(
                FakeClient(get_router=lambda u: FakeResp(200, '{"status":"success"}')),
                ["http://t/rest/products/search?q=test"])
        self.assertEqual(hits, [])
        self.assertFalse([o for o in ares.session.added if isinstance(o, Finding)])

    async def test_status_differential_quote_breaks_and_recovers(self):
        # The ginandjuice case: single quote -> 500 (generic page, NO SQL string),
        # doubled quote -> 200 (recovers). This must be caught by the differential.
        from core.models import Finding
        ares = _make_ares()

        def get_router(url):
            if "%27%27" in url:                       # doubled quote recovers
                return FakeResp(200, "<html>ok</html>")
            if "%27" in url:                          # single quote breaks (no SQL text!)
                return FakeResp(500, "<html>Internal Server Error</html>")
            return FakeResp(200, "<html>ok</html>")   # benign

        with patch.object(ares, "capture", AsyncMock(return_value=None)):
            hits = await ares._api_get_sqli(FakeClient(get_router=get_router),
                                            ["http://t/catalog?category=Juice"])
        self.assertTrue(any(h["type"] == "sqli-error-api" for h in hits))

    async def test_no_fp_when_any_input_500s(self):
        # A param that 500s on the doubled quote too is not SQL string context.
        from core.models import Finding
        ares = _make_ares()

        def get_router(url):
            if "%27" in url:      # both single and doubled quote 500
                return FakeResp(500, "<html>err</html>")
            return FakeResp(200, "<html>ok</html>")

        with patch.object(ares, "capture", AsyncMock(return_value=None)):
            hits = await ares._api_get_sqli(FakeClient(get_router=get_router),
                                            ["http://t/catalog?category=Juice"])
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
