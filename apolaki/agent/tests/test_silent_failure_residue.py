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

import bie
import browser_engine
import dns_recon
import enip_audit_tool
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


# ══════════════════════════════════════════════════════════════════════════════
# SLICE 2 -- the three module-level helpers.
#
# They have no ToolRegistry `self`, so they reach the ledger through
# `tools._ACTIVE_REGISTRY`, published for the span of `ToolRegistry.execute`.  These
# tests drive the REAL dispatch, not the helper in isolation: a recorder that a real
# dispatch never reaches is an island, and one of these three was exactly that until
# the executor boundary below was measured.
# ══════════════════════════════════════════════════════════════════════════════

def test_contextvars_do_not_cross_run_in_executor_but_do_cross_to_thread():
    """The MEASURED fact the enip fix depends on, pinned so it cannot be assumed away.

    `loop.run_in_executor(None, fn, ...)` reads a ContextVar's DEFAULT in the worker
    thread; `asyncio.to_thread` runs `ctx.run(fn, ...)` on the same default executor and
    sees the caller's value.  `_run_service_pack`'s enip branch must therefore use
    `to_thread`, or `enip.list_identity_tcp`'s recorder is registered and never reached.
    """
    probe = tools.contextvars.ContextVar("apolaki_residue_probe", default=None)

    def _read():
        return probe.get()

    async def _main():
        probe.set("published")
        loop = asyncio.get_event_loop()
        return (_read(), await loop.run_in_executor(None, _read), await asyncio.to_thread(_read))

    direct, in_executor, in_to_thread = asyncio.run(_main())
    assert direct == "published"
    assert in_executor is None            # the trap
    assert in_to_thread == "published"    # the mechanism the fix relies on


def test_module_level_swallow_reports_whether_it_actually_recorded():
    """Negative control.  Outside a dispatch there is no registry, and the helper says so
    instead of pretending.  A recorder that always returns success cannot detect an island."""
    reg = _registry()
    assert tools._swallow(_Boom("orphan"), "orphan.helper", "") is False
    token = tools._ACTIVE_REGISTRY.set(reg)
    try:
        assert tools._swallow(_Boom("adopted"), "orphan.helper", "") is True
    finally:
        tools._ACTIVE_REGISTRY.reset(token)
    assert "orphan.helper" in _wheres(reg)


# ── 13. dns_recon.doh -- full real dispatch, execute() to helper and back ─────

def test_doh_transport_crash_is_not_reported_as_a_domain_with_no_records(monkeypatch):
    """End-to-end through `ToolRegistry.execute("run_dns", ...)`.

    Every `doh` call returns [], so `gather_dns` reports SPF MISSING / DMARC MISSING /
    0 CAA / 0 vendors and `run_dns` returns ran=True.  That output is byte-identical to a
    real domain with no records -- a DNS transport outage used to read as an email-auth
    finding.  The fix must reach the ledger AND the dispatch's DEGRADED line.
    """
    import httpx

    class _DeadClient:
        def __init__(self, *_args, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def get(self, *_args, **_kwargs):
            raise _Boom("DoH resolver unreachable")

    reg = _registry()
    monkeypatch.setattr(httpx, "AsyncClient", _DeadClient)
    result = asyncio.run(reg.execute("run_dns", {"domain": "target.tld"}, "m-residue"))
    assert "dns_recon.doh" in _wheres(reg)
    assert "DoH resolver unreachable" in " ".join(_errors(reg, "dns_recon.doh"))
    # the dispatch surfaces it -- the ledger row is not enough on its own
    assert "DEGRADED" in result.output and "dns_recon.doh" in result.output


# ── 14. enip.list_identity_tcp -- across the executor boundary ────────────────

def test_enip_socket_crash_is_not_reported_as_no_ics_device(monkeypatch):
    """End-to-end through `execute("run_service_pack", ...)`, which crosses a thread.

    b"" means "nothing answered", so a socket layer that blew up on the SCANNING host
    reported the OT asset as absent rather than as unmeasured.
    """
    def _boom_connect(*_args, **_kwargs):
        raise _Boom("ENIP socket layer refused to open")

    # UDP is tried first and is NOT the handler under test; a silent UDP miss is the real
    # precondition for the TCP attempt.  `enip_audit_tool.socket` IS the stdlib module, so
    # only the one function the TCP path calls is replaced -- patching `socket.socket`
    # wholesale takes the event loop's own socketpair down with it.
    monkeypatch.setattr(enip_audit_tool, "_list_identity_udp", lambda *_a, **_k: b"")
    monkeypatch.setattr(enip_audit_tool.socket, "create_connection", _boom_connect)

    reg = _registry()
    result = asyncio.run(reg.execute(
        "run_service_pack",
        {"host": "target.tld", "port": 44818, "service": "enip"}, "m-residue"))
    assert "enip.list_identity_tcp" in _wheres(reg), _wheres(reg)
    assert "DEGRADED" in result.output


# ── 15. bie.session_fingerprint -- across asyncio.to_thread ───────────────────

def test_bie_session_fingerprint_crash_is_not_reported_as_two_identical_sessions(monkeypatch):
    """Driven the way `_run_browser_persona_bola` drives it: a sync bie call inside
    `asyncio.to_thread`, inside a real dispatch.  Playwright is not needed to prove the
    recorder is reached -- only the same context boundary the shipped call crosses."""
    import bie

    class _BadCookie:
        def get(self, _name):
            raise _Boom("storage state is not readable")

    class _Ctx:
        def storage_state(self):
            return {"cookies": [_BadCookie()], "origins": []}

    reg = _registry()
    captured = {}

    async def _dispatch(name, _inp, _sid):
        captured["fp"] = await asyncio.to_thread(bie.session_fingerprint, _Ctx())
        return tools.ToolResult(name, "https://target.tld/", True, "persona swap complete", [])

    monkeypatch.setattr(reg, "_dispatch_engine", _dispatch)
    result = asyncio.run(reg.execute("browser_persona_bola",
                                     {"base_url": "https://target.tld"}, "m-residue"))
    assert captured["fp"] == {}           # control: the redacted-empty contract is unchanged
    assert "bie.session_fingerprint" in _wheres(reg)
    assert "DEGRADED" in result.output


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
    import inspect as _inspect
    for module, where in ((bie, "bie.session_fingerprint"), (dns_recon, "dns_recon.doh"),
                          (enip_audit_tool, "enip.list_identity_tcp")):
        assert '"%s"' % where in _inspect.getsource(module), where
