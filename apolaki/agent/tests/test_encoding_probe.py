"""Encoded-parameter engine (CHAD/Gemini): pure decode/mutate/evaluate logic + the tool-level
jar-free cookie handling. The tool regression guards a real in-mission bug: passing the authed
session's cookies to httpx's jar collided with the server's own `session` Set-Cookie
("Multiple cookies exist with name=session"), which zeroed this find in-mission while it worked
standalone. The fix sends an explicit Cookie header per request and clears the jar."""
import asyncio
import base64
import json

import encoding_probe as ep


def _b64json(obj):
    return base64.b64encode(json.dumps(obj).encode()).decode().rstrip("=")


# ── pure logic ────────────────────────────────────────────────────────────────
def test_unpack_json_roundtrips_same_scheme():
    val = _b64json({"type": "class", "value": "Gifts"})
    up = ep.unpack(val)
    assert up is not None
    kind, obj, reenc = up
    assert kind == "json" and obj["value"] == "Gifts"
    # re-encode round-trips through the SAME base64->json scheme
    obj2 = dict(obj); obj2["value"] = "Gifts'"
    again = ep.unpack(reenc(obj2))
    assert again is not None and again[1]["value"] == "Gifts'"


def test_unpack_rejects_plain_text():
    assert ep.unpack("not-base64-structured") is None
    assert ep.unpack(base64.b64encode(b"just a plain string").decode()) is None


def test_string_fields_only_strings():
    assert ep.string_fields({"a": "x", "n": 3, "b": "y"}) == ["a", "b"]


def test_evaluate_error_based_status_class_change():
    ev = ep.evaluate({"status": 200, "len": 100}, {"status": 500, "len": 80},
                     {"status": 200, "len": 100}, {"status": 200, "len": 100})
    assert ev["confirmed"] and "error-based" in ev["oracle"]


def test_evaluate_boolean_split():
    ev = ep.evaluate({"status": 200, "len": 500}, {"status": 200, "len": 500},
                     {"status": 200, "len": 500}, {"status": 200, "len": 120})
    assert ev["confirmed"] and "boolean-based" in ev["oracle"]


def test_evaluate_no_signal_stays_unconfirmed():
    ev = ep.evaluate({"status": 200, "len": 500}, {"status": 200, "len": 500},
                     {"status": 200, "len": 500}, {"status": 200, "len": 500})
    assert not ev["confirmed"]


# ── tool-level: jar-free Cookie header, no session-cookie collision ─────────────
class _FakeCookies:
    """Stands in for httpx client.cookies — must support .clear() without raising."""
    def clear(self):
        pass

    def items(self):
        return []


class _FakeResp:
    def __init__(self, status, text, set_cookies):
        self.status_code = status
        self.text = text
        self._sc = set_cookies

    class _H:
        def __init__(self, sc):
            self._sc = sc

        def get_list(self, name):
            return self._sc if name == "set-cookie" else []

    @property
    def headers(self):
        return _FakeResp._H(self._sc)


class _FakeClient:
    """Simulates a server that (a) Set-Cookies its own `session` AND a base64 TrackingId, and
    (b) 500s when the decoded TrackingId 'value' carries a stray quote (error-based SQLi tell).
    Records every Cookie header so the test can assert no duplicate-cookie collision."""
    sent_cookie_headers = []

    def __init__(self, **kw):
        # the fix must NOT seed a jar with cookies=...; assert that contract here
        assert "cookies" not in kw, "tool must not pass a cookie jar (collision risk)"
        self.cookies = _FakeCookies()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, headers=None):
        ch = (headers or {}).get("Cookie", "")
        _FakeClient.sent_cookie_headers.append(ch)
        # server always sets its own session + a base64 TrackingId (JSON with an injectable 'value')
        tracking = _b64json({"type": "class", "value": "Gifts"})
        sc = ["session=server-side-xyz; Path=/; HttpOnly",
              "TrackingId=%s; Path=/" % tracking]
        # decode the TrackingId the client sent back; a stray quote in 'value' -> 500
        status = 200
        for part in ch.split(";"):
            part = part.strip()
            if part.startswith("TrackingId="):
                up = ep.unpack(part.split("=", 1)[1])
                if up and "'" in str(up[1].get("value", "")):
                    status = 500
        return _FakeResp(status, "body-of-constant-length", sc)


def test_run_encoded_cookie_no_session_collision(monkeypatch):
    import httpx
    import tools as tools_mod
    from scope import ScopeEngine

    _FakeClient.sent_cookie_headers = []
    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)

    sc = ScopeEngine()
    sc.load_manual(["example.test"], [], "unit")
    # authed session header carrying `session` — the exact value that used to collide with the
    # server's own `session` Set-Cookie in the httpx jar.
    tr = tools_mod.ToolRegistry(sc, mission_id="unit",
                                session_headers={"Cookie": "session=authed-abc"})
    res = asyncio.run(
        tr._run_encoded_cookie({"url": "https://example.test/catalog"}))

    # the engine landed the base64 param finding despite the session-cookie collision hazard
    assert res.success, res.error
    assert len(res.findings) == 1
    assert res.findings[0]["family"] == "base64_param"
    # every request went out as an explicit Cookie header (never through the jar)
    assert _FakeClient.sent_cookie_headers, "no requests were sent"
    assert any("TrackingId=" in h for h in _FakeClient.sent_cookie_headers)
