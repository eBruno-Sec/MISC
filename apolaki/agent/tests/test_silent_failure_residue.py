"""I-5 residue: the load-bearing handlers that RETURN a literal instead of assigning one.

`_swallowed()` in `test_silent_failure_invariant.py` applies `_constant()` to its Assign
branch but not to its Return branch, so a handler ending `return []` was censused into no
category and constrained by no ceiling.  The census was repaired (`_literal_return_swallow`)
and CAPPED the residue at 15 load-bearing sites.  A cap is not a fix.  This file is the fix's
oracle: for each site, the protected call is forced to raise and the swallowed-error ledger
must NAME that owner.

Asserting the return value is unchanged would prove nothing -- the return value was already
correct.  The defect was that a crashed check and a clean target produced byte-identical
output.  Every test here therefore asserts on `reg.swallowed`, and asserts the unchanged
return value only as the control that the fix did not alter behaviour.
"""
from __future__ import annotations

import asyncio
import base64
import json
import sys
import types

import pytest

import browser_engine
import scope
import tools


class _Boom(RuntimeError):
    """A failure that is impossible to confuse with a target's answer."""


def _registry(mission_id="m-residue"):
    engine = scope.ScopeEngine()
    engine.load_manual(["target.tld"], [], "silent failure residue test")
    return tools.ToolRegistry(engine, mission_id=mission_id, lab_mode=True)


def _wheres(reg):
    return [row["where"] for row in reg.swallowed]


def _errors(reg, where):
    return [row["error"] for row in reg.swallowed if row["where"] == where]


@pytest.fixture(autouse=True)
def _no_durable_writes(monkeypatch):
    """`_swallow` writes a durable tool_error row.  Keep that OUT of the shared db in a
    unit test, but keep the in-registry ledger real -- the ledger is what is under test."""
    monkeypatch.setattr(tools.db, "add_log", lambda *_args, **_kwargs: None)


# ── shared fakes ───────────────────────────────────────────────────────────────

class _Headers(dict):
    def get_list(self, _name):
        return []


class _Resp:
    def __init__(self, status=200, text="<html>ok</html>", url="https://target.tld/"):
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.url = url
        self.headers = _Headers({"content-type": "text/html"})


class _RaisingClient:
    """An httpx-shaped async client whose target calls raise after `ok_gets` successes."""

    def __init__(self, ok_gets=0, exc=None):
        self._ok_gets = ok_gets
        self._exc = exc or _Boom("target transport exploded")
        self.cookies = {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def get(self, *_args, **_kwargs):
        if self._ok_gets > 0:
            self._ok_gets -= 1
            return _Resp()
        raise self._exc

    async def request(self, *_args, **_kwargs):
        raise self._exc


def _install_client(monkeypatch, client):
    """`_target_client` builds through browser_engine, exactly as the shipped transport does."""
    monkeypatch.setattr(browser_engine, "rate_limited_async_client",
                        lambda *_args, **_kwargs: client)


def _boom_http_send(exc_text):
    async def _send(*_args, **_kwargs):
        raise _Boom(exc_text)
    return _send


# ── 1. authz_matrix.fetch  (tools.py _run_authz_matrix._fetch) ────────────────

def test_authz_matrix_fetch_crash_is_not_reported_as_a_denied_persona(monkeypatch):
    reg = _registry()
    monkeypatch.setattr(reg, "_http_send", _boom_http_send("authz transport down"))
    result = asyncio.run(reg._run_authz_matrix({
        "base_url": "https://target.tld",
        "roles": [{"role": "anon", "rank": 0}, {"role": "user_a", "rank": 1}],
        "operations": [{"path": "/api/orders/1"}],
    }))
    # A status of 0 is what a genuine refusal produces, so without the recorder this run
    # is indistinguishable from "every persona was denied" -- a false authorization PASS.
    assert "authz_matrix.fetch" in _wheres(reg)
    assert "authz transport down" in " ".join(_errors(reg, "authz_matrix.fetch"))
    assert result.findings == []          # control: behaviour unchanged


# ── 2. header_trust.get  (tools.py _run_header_trust._get) ────────────────────

def test_header_trust_probe_crash_is_not_reported_as_header_not_trusted(monkeypatch):
    reg = _registry()
    monkeypatch.setattr(reg, "_http_send", _boom_http_send("header probe socket died"))
    result = asyncio.run(reg._run_header_trust({"url": "https://target.tld/admin"}))
    assert "header_trust.get" in _wheres(reg)
    assert "header probe socket died" in " ".join(_errors(reg, "header_trust.get"))
    assert result.findings == []


# ── 3/4. service_pack.socket_connect / socket_exchange ────────────────────────

def test_socket_service_connect_crash_is_not_reported_as_a_clean_negative(monkeypatch):
    reg = _registry()

    async def _boom_connect(*_args, **_kwargs):
        raise _Boom("open_connection blew up")

    monkeypatch.setattr(tools.asyncio, "open_connection", _boom_connect)
    out = asyncio.run(reg._socket_service_probe("redis", "target.tld", 6379))
    assert out == {"confirmed": False}    # control: the returned verdict is untouched
    assert "service_pack.socket_connect" in _wheres(reg)


def test_socket_service_exchange_crash_is_separated_from_a_failed_connect(monkeypatch):
    reg = _registry()

    class _Reader:
        async def read(self, _n):
            raise _Boom("peer reset mid-PING")

    class _Writer:
        def write(self, _b):
            return None

        async def drain(self):
            return None

        def close(self):
            return None

    async def _fake_connect(*_args, **_kwargs):
        return _Reader(), _Writer()

    monkeypatch.setattr(tools.asyncio, "open_connection", _fake_connect)
    out = asyncio.run(reg._socket_service_probe("redis", "target.tld", 6379))
    assert out == {"confirmed": False}
    # The socket OPENED and the protocol exchange then failed.  That is a different fact
    # from "nothing listening", and both used to produce the same {"confirmed": False}.
    assert "service_pack.socket_exchange" in _wheres(reg)
    assert "service_pack.socket_connect" not in _wheres(reg)


# ── 5. numeric_abuse.send  (tools.py _test_numeric_abuse._send) ───────────────

def test_numeric_abuse_send_crash_is_not_reported_as_value_rejected(monkeypatch):
    reg = _registry()
    monkeypatch.setattr(reg, "_http_send", _boom_http_send("numeric send failed"))
    result = asyncio.run(reg._test_numeric_abuse({
        "url": "https://target.tld/api/order", "param": "amount", "values": [-1, 999999],
    }))
    # status 0 reads as "server did not accept", i.e. the failure direction that DELETES
    # a candidate from the accepted list.  A crash must not shrink the evidence silently.
    assert "numeric_abuse.send" in _wheres(reg)
    assert result.findings == []


# ── 6. param_discovery.discover  (tools.py _discover_params) ──────────────────

def test_param_discovery_crash_is_not_reported_as_a_page_with_no_params(monkeypatch):
    reg = _registry()

    async def _boom(*_args, **_kwargs):
        raise _Boom("param discovery http layer exploded")

    monkeypatch.setattr(reg, "_http", _boom)
    out = asyncio.run(reg._discover_params("https://target.tld/login"))
    assert out == []                      # control: still the documented empty list
    assert "param_discovery.discover" in _wheres(reg)


# ── 7. form_xss.browser_confirm  (tools.py _form_xss_browser_confirm) ─────────

def test_form_xss_browser_crash_is_not_reported_as_payload_did_not_execute(monkeypatch):
    reg = _registry()

    class _NeverStarts:
        async def __aenter__(self):
            raise _Boom("browser worker never started")

        async def __aexit__(self, *_args):
            return False

    fake_pkg = types.ModuleType("playwright")
    fake_api = types.ModuleType("playwright.async_api")
    fake_api.async_playwright = lambda: _NeverStarts()
    fake_pkg.async_api = fake_api
    monkeypatch.setitem(sys.modules, "playwright", fake_pkg)
    monkeypatch.setitem(sys.modules, "playwright.async_api", fake_api)
    monkeypatch.setattr(tools, "_chrome_path", lambda: "/usr/bin/chromium")

    fired, payload = asyncio.run(reg._form_xss_browser_confirm(
        "https://target.tld/contact", {"text_fields": ["msg"], "fields": {"msg": "x"}}, "msg"))
    assert (fired, payload) == (False, "")   # control: same "did not execute" verdict
    assert "form_xss.browser_confirm" in _wheres(reg)


# ── 8. encoded_cookie.send  (tools.py _run_encoded_cookie._send) ──────────────

def test_encoded_cookie_probe_crash_is_not_reported_as_no_oracle(monkeypatch):
    reg = _registry()
    # Derived, not invented: the cookie value is the real base64 of a real JSON object, so
    # encoding_probe.unpack takes the same path it takes on a live TrackingId cookie.
    packed = base64.b64encode(json.dumps({"value": "abc"}).encode()).decode().rstrip("=")
    reg.session_headers = {"Cookie": "TrackingId=%s" % packed}
    # The FIRST GET is the baseline fetch, outside the handler under test; every probe
    # after it raises, which is what drives `_send`.
    _install_client(monkeypatch, _RaisingClient(ok_gets=1, exc=_Boom("cookie probe died")))
    result = asyncio.run(reg._run_encoded_cookie({"url": "https://target.tld/"}))
    assert result.findings == []
    assert "encoded_cookie.send" in _wheres(reg)


# ── 9. oauth.send  (tools.py _run_oauth.send) ─────────────────────────────────

def test_oauth_redirect_probe_crash_is_not_reported_as_variant_rejected(monkeypatch):
    reg = _registry()
    _install_client(monkeypatch, _RaisingClient(exc=_Boom("oauth probe died")))
    result = asyncio.run(reg._run_oauth({
        "url": "https://target.tld/authorize?client_id=web&response_type=code"
               "&redirect_uri=https://target.tld/cb",
    }))
    # (0, "") is exactly what a correctly-validating server produces.  A probe that never
    # ran must not be able to claim the redirect_uri validator held.
    assert "oauth.send" in _wheres(reg)
    assert result.findings == []


# ── 10/11. race.read_state / race.worker  (tools.py _run_race) ────────────────

def test_race_state_read_and_worker_crashes_are_not_reported_as_a_target_that_held(monkeypatch):
    reg = _registry()

    async def _boom_http(*_args, **_kwargs):
        return {"status": 0, "body": "", "error": "suppressed in test"}

    monkeypatch.setattr(reg, "_http", _boom_http)
    _install_client(monkeypatch, _RaisingClient(exc=_Boom("race transport died")))
    result = asyncio.run(reg._run_race({
        "url": "https://target.tld/api/redeem", "verify_url": "https://target.tld/api/balance",
        "count": 2, "rounds": 1,
    }))
    wheres = _wheres(reg)
    assert "race.read_state" in wheres      # verify_delta on {} reports "not changed"
    assert "race.worker" in wheres          # summarize counts status-0 as a non-success
    assert result.findings == []


# ── 12. sqli_metadata.query  (tools.py _sqli_db_metadata.q) ───────────────────

def test_sqli_metadata_query_crash_is_not_reported_as_a_width_that_did_not_work(monkeypatch):
    reg = _registry()
    _install_client(monkeypatch, _RaisingClient(exc=_Boom("union query died")))
    proof, settings = asyncio.run(reg._sqli_db_metadata("https://target.tld/search?q=1"))
    assert (proof, settings) == ("", "")    # control: same empty extraction
    assert "sqli_metadata.query" in _wheres(reg)


# ── the whole slice, as one assertion ─────────────────────────────────────────

def test_every_repaired_owner_is_reachable_from_a_real_execution_path():
    """No islands: each `where` string above must exist as a literal in the module that
    is supposed to emit it.  A recorder nothing dispatches is a declaration, not a fact --
    the per-site tests above are what prove the dispatch, this only pins the vocabulary."""
    src = tools.inspect.getsource(tools) if hasattr(tools, "inspect") else None
    if src is None:
        import inspect as _inspect
        src = _inspect.getsource(tools)
    for where in ("authz_matrix.fetch", "header_trust.get", "service_pack.socket_connect",
                  "service_pack.socket_exchange", "numeric_abuse.send",
                  "param_discovery.discover", "form_xss.browser_confirm",
                  "encoded_cookie.send", "oauth.send", "race.read_state", "race.worker",
                  "sqli_metadata.query"):
        assert '"%s"' % where in src, where
