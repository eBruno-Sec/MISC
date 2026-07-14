"""Tests for the all-out API attack suite: pure detectors (core.api_attacks) and
the engine methods (NoSQLi, reflected XSS, SSTI, JWT, IDOR/BOLA). High-precision
by design, so the tests assert both the true-positive and the no-false-positive
paths."""
import hashlib
import hmac
import importlib.util
import json
import unittest
from unittest.mock import patch, AsyncMock

import core.api_attacks as aa

HAS_SQLALCHEMY = importlib.util.find_spec("sqlalchemy") is not None


def _hs256(secret, payload=None):
    h = aa._b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = aa._b64url_encode(json.dumps(payload or {"user": "x", "role": "user"}).encode())
    sig = aa._b64url_encode(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


class PureDetectorTests(unittest.TestCase):
    def test_xss_unencoded_reflection(self):
        self.assertTrue(aa.unencoded_reflection(f"<div>{aa.XSS_PROBE}</div>"))
        self.assertFalse(aa.unencoded_reflection(f"&lt;{aa.XSS_CANARY}&gt;"))

    def test_xss_context(self):
        self.assertEqual(aa.xss_context("text/html; charset=utf-8"), "html")
        self.assertEqual(aa.xss_context("application/json"), "other")

    def test_ssti_evaluated_and_no_fp(self):
        self.assertTrue(aa.ssti_evaluated("out=49", "out=ygg7x7", "49"))
        self.assertFalse(aa.ssti_evaluated("id is 49", "id is 49", "49"))  # 49 in benign too

    def test_jwt_decode_and_crack(self):
        tok = _hs256("secret")
        self.assertIsNotNone(aa.decode_jwt(tok))
        self.assertEqual(aa.crack_jwt_hs256(tok), "secret")
        self.assertIsNone(aa.crack_jwt_hs256(_hs256("Zx9$K2#mQ7!longrandom-not-in-list")))

    def test_jwt_forge_alg_none(self):
        forged = aa.forge_alg_none(_hs256("secret"), {"role": "admin"})
        header, payload = aa.decode_jwt(forged)
        self.assertEqual(header["alg"], "none")
        self.assertEqual(payload["role"], "admin")
        self.assertTrue(forged.endswith("."))   # empty signature

    def test_idor_candidates(self):
        cands = aa.idor_candidates(["http://t/api/Users/1", "http://t/rest/basket/3",
                                    "http://t/x?userId=42", "http://t/about", "http://t/main.js"])
        kinds = {(c["where"], c["id"]) for c in cands}
        self.assertIn(("path", "1"), kinds)
        self.assertIn(("path", "3"), kinds)
        self.assertIn(("param", "42"), kinds)
        self.assertEqual(len([c for c in cands if "about" in c["url"]]), 0)

    def test_swap_numeric_id(self):
        self.assertEqual(set(aa.swap_numeric_id("3")), {"1", "2", "4"})

    def test_looks_like_object(self):
        self.assertTrue(aa.looks_like_object('{"data":{"id":1,"email":"a@b"}}'))
        self.assertTrue(aa.looks_like_object('[{"id":1}]'))
        self.assertFalse(aa.looks_like_object("<html></html>"))
        self.assertFalse(aa.looks_like_object('{"data":{}}'))

    def test_idor_confirmed(self):
        self.assertTrue(aa.idor_confirmed(200, '{"data":{"id":2}}', '{"data":{"id":1}}'))
        self.assertFalse(aa.idor_confirmed(403, '{"data":{"id":2}}', '{"data":{"id":1}}'))
        self.assertFalse(aa.idor_confirmed(200, '{"data":{"id":1}}', '{"data":{"id":1}}'))  # same
        self.assertFalse(aa.idor_confirmed(200, '{"data":{"id":2}}', '{"data":{"id":1}}',
                                           error_signature=True))


# ── Engine method tests ───────────────────────────────────────────────────────
class FakeResp:
    def __init__(self, status, text, headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self.request = None


class FakeClient:
    def __init__(self, post=None, get=None):
        self._post = post or (lambda u, j: FakeResp(401, "{}"))
        self._get = get or (lambda u, h: FakeResp(200, "{}"))

    async def post(self, url, json=None):
        return self._post(url, json or {})

    async def get(self, url, headers=None):
        return self._get(url, headers or {})


if HAS_SQLALCHEMY:
    class FakeSession:
        def __init__(self):
            self.added = []

        def add(self, o):
            self.added.append(o)

        async def execute(self, s):
            return None

        async def commit(self):
            pass

        async def get(self, *a, **k):
            return None

    def _ares():
        from agents.ares import Ares
        a = Ares(FakeSession(), "m-aa")
        a._catch_all = None
        a._api_token = None
        return a


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy not available")
class NoSqliTests(unittest.IsolatedAsyncioTestCase):
    async def test_operator_injection_bypass_is_critical(self):
        from core.models import Finding
        ares = _ares()
        JWT = _hs256("secret")

        def post(url, body):
            ident = body.get("email") or body.get("username") or body.get("user")
            if isinstance(ident, dict):     # NoSQL operator object
                return FakeResp(200, '{"authentication":{"token":"' + JWT + '"}}')
            return FakeResp(401, "{}")

        with patch.object(ares, "_capture_proof", AsyncMock(return_value=None)):
            hits = await ares._api_nosqli_login(FakeClient(post=post), "http://t",
                                                ["http://t/rest/user/login"])
        self.assertTrue(any(h["type"] == "nosqli-auth-bypass" for h in hits))
        self.assertTrue([o for o in ares.session.added if isinstance(o, Finding) and o.severity == "critical"])


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy not available")
class ReflectedXssTests(unittest.IsolatedAsyncioTestCase):
    async def test_html_reflection_is_flagged(self):
        from core.models import Finding
        ares = _ares()

        def get(url, headers):
            if "%3C" in url or aa.XSS_PROBE in url:   # the encoded/raw probe
                return FakeResp(200, f"<html><body>{aa.XSS_PROBE}</body></html>",
                                {"content-type": "text/html"})
            return FakeResp(200, "{}")

        with patch.object(ares, "capture", AsyncMock(return_value=None)):
            hits = await ares._api_reflected_xss(FakeClient(get=get),
                                                 ["http://t/rest/products/search?q=x"])
        self.assertTrue(any(h["type"] == "xss-reflected-api" for h in hits))

    async def test_json_reflection_flagged_low_confidence(self):
        # Report-everything: raw reflection in a JSON (non-HTML) response isn't
        # directly executable, so it's reported as a LOW-confidence candidate,
        # not a HIGH reflected-XSS.
        from core.models import Finding
        ares = _ares()

        def get(url, headers):
            return FakeResp(200, '{"q":"' + aa.XSS_PROBE + '"}', {"content-type": "application/json"})

        with patch.object(ares, "capture", AsyncMock(return_value=None)):
            hits = await ares._api_reflected_xss(FakeClient(get=get),
                                                 ["http://t/rest/products/search?q=x"])
        self.assertTrue(any(h["type"] == "reflection-candidate" and h["severity"] == "low" for h in hits))
        self.assertFalse(any(h["type"] == "xss-reflected-api" for h in hits))


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy not available")
class SstiTests(unittest.IsolatedAsyncioTestCase):
    async def test_template_eval_flagged(self):
        from core.models import Finding
        ares = _ares()

        def get(url, headers):
            if "%7B%7B7%2A7%7D%7D" in url or "{{7*7}}" in url:
                return FakeResp(200, '{"result":"49"}', {"content-type": "application/json"})
            return FakeResp(200, '{"result":"ygg7x7"}', {"content-type": "application/json"})

        with patch.object(ares, "capture", AsyncMock(return_value=None)):
            hits = await ares._api_ssti(FakeClient(get=get), ["http://t/api/render?tpl=x"])
        self.assertTrue(any(h["type"] == "ssti-api" for h in hits))


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy not available")
class JwtAttackTests(unittest.IsolatedAsyncioTestCase):
    async def test_weak_secret_and_alg_none_acceptance(self):
        from core.models import Finding
        ares = _ares()
        token = _hs256("secret", {"role": "user", "id": 5})

        def get(url, headers):
            # alg:none forged token accepted at whoami; no-auth denied.
            if "whoami" in url and headers.get("Authorization", "").startswith("Bearer eyJhbGciOiJub25l"):
                return FakeResp(200, '{"user":{"id":5,"role":"admin"}}')
            if "whoami" in url:
                return FakeResp(401, "")
            return FakeResp(401, "")

        with patch.object(ares, "capture", AsyncMock(return_value=None)):
            hits = await ares._jwt_attacks(FakeClient(get=get), "http://t", token)
        types = {h["type"] for h in hits}
        self.assertIn("jwt-weak-secret", types)        # cracked HS256 'secret'
        self.assertIn("jwt-alg-none-accepted", types)  # forged token accepted
        crit = [o for o in ares.session.added if isinstance(o, Finding) and o.severity == "critical"]
        self.assertTrue(crit)

    async def test_non_jwt_is_noop(self):
        ares = _ares()
        hits = await ares._jwt_attacks(FakeClient(), "http://t", "not-a-jwt")
        self.assertEqual(hits, [])


@unittest.skipUnless(HAS_SQLALCHEMY, "SQLAlchemy not available")
class IdorTests(unittest.IsolatedAsyncioTestCase):
    async def test_bola_detected(self):
        from core.models import Finding
        ares = _ares()

        def get(url, headers):
            authed = headers.get("Authorization", "").startswith("Bearer ")
            if url.endswith("/api/Users/1"):
                return FakeResp(200, '{"data":{"id":1,"email":"me@x"}}') if authed else FakeResp(401, "")
            if url.endswith("/api/Users/2"):
                # another user's object: authed can read it, no-auth cannot.
                return FakeResp(200, '{"data":{"id":2,"email":"victim@x"}}') if authed else FakeResp(401, "")
            return FakeResp(404, "")

        with patch.object(ares, "capture", AsyncMock(return_value=None)):
            hits = await ares._idor_bola(FakeClient(get=get), "http://t",
                                         ["http://t/api/Users/1"], token="regular.user.token")
        self.assertTrue(any(h["type"] == "idor-bola" for h in hits))

    async def test_no_idor_when_others_denied(self):
        ares = _ares()

        def get(url, headers):
            if url.endswith("/api/Users/1"):
                return FakeResp(200, '{"data":{"id":1}}')
            return FakeResp(403, '{"error":"forbidden"}')   # proper access control

        with patch.object(ares, "capture", AsyncMock(return_value=None)):
            hits = await ares._idor_bola(FakeClient(get=get), "http://t",
                                         ["http://t/api/Users/1"], token="regular.user.token")
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
