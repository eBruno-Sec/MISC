"""Q-055b — `_run_bfla`'s AUTHENTICATED row was ANONYMOUS. The mirror of Q-032, and vacuous.

The sessions lane fixed the case where the ANONYMOUS control row was secretly authenticated. It
suspected, but did not confirm, the mirror on the same engine family. This file is the confirmation.

MEASURED AT THE WIRE on pristine HEAD, with a mission session held on the registry:

    registry session_headers: {'Cookie': 'session=MISSION-IDENTITY'}
    requests actually sent (9):
      GET   /api/admin/users/1                       identity=ANONYMOUS
      GET   /api/admin/users/1                       identity=ANONYMOUS
      POST  /api/admin/users/1                       identity=ANONYMOUS
      ... (PUT, PATCH, both rows, and the nonexistent-id probe) ...
    distinct identities on the wire: {'[]'}
    findings: 0

`test_headers = dict(inp.get("headers") or {})` fed `c.request` directly, bypassing
`_merge_identity`, so BOTH rows were anonymous.

WHY IT IS WORSE THAN A WRONG ROW. `authz.analyze_methods` skips any method whose ANONYMOUS row is
also 2xx. Two byte-identical rows therefore make the BFLA oracle VACUOUS: it could not emit a finding
on any target, ever. And no production caller supplied headers — `agent.py:977` and `agent.py:3193`
both dispatch `{"url": ...}` — while `agent.py:970` gates on a session EXISTING, discards it, and on
the empty result records "privileged control correctly denied the low-priv session". A false claim
produced by an oracle that never ran.

WHY THE SUITE WAS GREEN. Every existing authz test monkeypatches `reg._http_send`. `_run_bfla` never
calls `_http_send` — it builds its own client — so the line under test was never executed by any
test. These tests patch `tools._target_client` instead, i.e. BELOW that, and assert on the headers
that actually reach the wire. Same technique as `tests/test_session_identity.py`.
"""
from __future__ import annotations

import asyncio
import contextlib

import httpx
import pytest

import tools
from scope import ScopeEngine

BASE = "http://target.tld"
ADMIN = BASE + "/api/admin/users/1"
MISSION = {"Cookie": "session=MISSION-IDENTITY"}
LOWPRIV = {"Authorization": "Bearer LOWPRIV-TOKEN"}


def _reg(session_headers=None):
    sc = ScopeEngine()
    sc.load_manual(["target.tld"], [], "truthful-bfla")
    return tools.ToolRegistry(sc, lab_mode=True, session_headers=dict(session_headers or {}))


def _identity(headers: dict) -> dict:
    """Only the identity-bearing headers. User-Agent is not identity."""
    return {k: v for k, v in (headers or {}).items() if k.lower() in ("cookie", "authorization")}


@contextlib.contextmanager
def _wiretap(monkeypatch, responder=None, raiser=None):
    """Capture the headers that actually reach the transport.

    Patches `tools._target_client`, BELOW `_run_bfla`'s own client construction, so the identity
    resolution under test still runs. `responder(method, url, headers) -> (status, body)` drives the
    oracle; `raiser(method)` makes one method's request blow up."""
    seen: list = []

    class _Client:
        async def request(self, method, url, headers=None, content=None):
            seen.append({"method": method, "url": str(url), "headers": dict(headers or {})})
            if raiser is not None and raiser(method, dict(headers or {})):
                raise httpx.ConnectError("simulated transport failure")
            status, body = (responder(method, str(url), dict(headers or {}))
                            if responder else (200, "ok"))
            return httpx.Response(status, text=body, request=httpx.Request(method, url))

        async def get(self, url, headers=None):
            return await self.request("GET", url, headers=headers)

    class _Ctx:
        async def __aenter__(self):
            return _Client()

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(tools, "_target_client", lambda *a, **k: _Ctx())
    yield seen


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------------------------
# THE DEFECT — identity at the wire
# ---------------------------------------------------------------------------------------------
def test_the_authenticated_row_carries_the_mission_session(monkeypatch):
    """FAILS BEFORE THE FIX: every request went out anonymous."""
    reg = _reg(MISSION)
    with _wiretap(monkeypatch) as seen:
        _run(reg._run_bfla({"url": ADMIN}))
    authed = [s for s in seen if _identity(s["headers"]) == MISSION]
    assert authed, "no request carried the mission session; the 'authorized' row is anonymous"


def test_the_anonymous_control_row_is_still_anonymous(monkeypatch):
    """The other half. Fixing the authenticated row must not authenticate the control row — that is
    precisely the Q-032 defect this one mirrors."""
    reg = _reg(MISSION)
    with _wiretap(monkeypatch) as seen:
        _run(reg._run_bfla({"url": ADMIN}))
    anon = [s for s in seen if _identity(s["headers"]) == {}]
    assert anon, "no request went out anonymous; there is no control row"


def test_the_two_rows_are_actually_different_requests(monkeypatch):
    """The property the whole oracle rests on, asserted directly: the sweep must put at least two
    DISTINCT identities on the wire. One identity means the differential compares a row to itself."""
    reg = _reg(MISSION)
    with _wiretap(monkeypatch) as seen:
        _run(reg._run_bfla({"url": ADMIN}))
    identities = {tuple(sorted(_identity(s["headers"]).items())) for s in seen}
    assert len(identities) == 2, identities


def test_a_named_persona_wins_and_does_not_bleed_the_mission_session(monkeypatch):
    """`session=` names WHO the request is made as. Q-032's cross-scheme bleed: a Cookie mission and
    a Bearer persona do not collide on a key, so both would ride the same request and the server
    would choose which identity served it."""
    reg = _reg(MISSION)
    reg._sessions["lowpriv"] = dict(LOWPRIV)
    with _wiretap(monkeypatch) as seen:
        _run(reg._run_bfla({"url": ADMIN, "session": "lowpriv"}))
    authed = [s for s in seen if _identity(s["headers"])]
    assert authed and all(_identity(s["headers"]) == LOWPRIV for s in authed), \
        [_identity(s["headers"]) for s in authed]
    assert not any("Cookie" in s["headers"] for s in seen), "the mission cookie bled into the persona"


def test_explicit_headers_are_used_as_the_token_under_test(monkeypatch):
    reg = _reg(MISSION)
    with _wiretap(monkeypatch) as seen:
        _run(reg._run_bfla({"url": ADMIN, "headers": {"Authorization": "Bearer EXPLICIT"}}))
    authed = [_identity(s["headers"]) for s in seen if _identity(s["headers"])]
    assert authed and all(a.get("Authorization") == "Bearer EXPLICIT" for a in authed), authed


def test_an_unknown_persona_degrades_to_anonymous_not_to_the_mission(monkeypatch):
    """`_identity` returns `Identity()` for an unresolved role: a persona that failed to mint must
    become 'as nobody' (proves nothing), never 'as the mission' (silently proves the wrong thing)."""
    reg = _reg(MISSION)
    with _wiretap(monkeypatch) as seen:
        res = _run(reg._run_bfla({"url": ADMIN, "session": "never-minted"}))
    assert all(_identity(s["headers"]) == {} for s in seen), [s["headers"] for s in seen]
    assert "NOT RUN" in res.output


# ---------------------------------------------------------------------------------------------
# THE ORACLE — vacuous before, and it must SAY so rather than report a clean sweep
# ---------------------------------------------------------------------------------------------
def _priv(method, url, headers):
    """A privileged endpoint: 200 to a bearer of any identity, 401 to nobody."""
    return (200, '{"users": []}') if _identity(headers) else (401, "denied")


def _public(method, url, headers):
    return (200, "public catalogue")


def test_a_real_bfla_is_now_emitted_which_was_impossible_before(monkeypatch):
    """FAILS BEFORE THE FIX for a structural reason, not a threshold one: with both rows anonymous
    the anon row was also 2xx for every method, and `analyze_methods` skips those unconditionally."""
    reg = _reg(MISSION)
    with _wiretap(monkeypatch, responder=_priv):
        res = _run(reg._run_bfla({"url": ADMIN}))
    bfla = [f for f in res.findings if f.get("family") == "bfla"]
    assert bfla, res.output
    assert {f["title"] for f in bfla} >= {"Broken function-level authorization (POST)"}
    assert all(f["cwe"] == "CWE-285" for f in bfla)


def test_a_genuinely_public_endpoint_still_emits_no_bfla(monkeypatch):
    """NEGATIVE CONTROL. Anonymous reaches it too, so the token reaching it proves nothing. Fixing a
    false negative must not buy a false positive on every public API."""
    reg = _reg(MISSION)
    with _wiretap(monkeypatch, responder=_public):
        res = _run(reg._run_bfla({"url": ADMIN}))
    assert [f for f in res.findings if f.get("family") == "bfla"] == []


def test_with_no_identity_anywhere_the_engine_says_it_did_not_run(monkeypatch):
    """The truthful-engines point. No session, no headers, no mission identity: the two rows would
    be the same request, so the differential is meaningless. Reporting '0 authorization signal(s)'
    would be the false-clean shape — a caller cannot tell it from a real clean sweep."""
    reg = _reg()                                        # no mission session
    with _wiretap(monkeypatch, responder=_priv) as seen:
        res = _run(reg._run_bfla({"url": ADMIN}))
    assert all(_identity(s["headers"]) == {} for s in seen)
    assert "NOT RUN" in res.output and "no identity available" in res.output
    assert [f for f in res.findings if f.get("family") == "bfla"] == [], \
        "a vacuous differential must not produce a BFLA finding"


def test_the_side_channel_oracle_still_runs_when_the_differential_is_vacuous(monkeypatch):
    """It needs no authed/anon differential, so suppressing it too would be a second false negative.
    404 on a nonexistent id vs 401 on an existing one is an enumeration oracle either way."""
    def _side(method, url, headers):
        return (404, "nope") if "bbh-nonexistent-" in url else (401, "denied")

    reg = _reg()
    with _wiretap(monkeypatch, responder=_side):
        res = _run(reg._run_bfla({"url": ADMIN}))
    assert [f["cwe"] for f in res.findings] == ["CWE-204"], res.findings
    assert "NOT RUN" in res.output


# ---------------------------------------------------------------------------------------------
# SWALLOWED ERRORS — a dropped row silently weakens the differential
# ---------------------------------------------------------------------------------------------
def test_a_failed_request_is_recorded_not_discarded(monkeypatch):
    """Three bare `except Exception: pass` handlers lived here. A dropped row removes a method from
    the sweep, and the result is byte-identical to 'the token could not reach it'."""
    reg = _reg(MISSION)
    with _wiretap(monkeypatch, responder=_priv, raiser=lambda m, h: m == "PUT"):
        res = _run(reg._run_bfla({"url": ADMIN}))
    wheres = [s["where"] for s in reg.swallowed]
    assert "bfla.authed.PUT" in wheres and "bfla.anon.PUT" in wheres, reg.swallowed
    assert all("simulated transport failure" in s["error"] for s in reg.swallowed)
    assert res.success is True                          # an optional row must not abort the engine


@pytest.mark.parametrize("method", ["GET", "POST", "PATCH"])
def test_every_swept_method_probes_both_rows(method, monkeypatch):
    """The differential is per-method; a method probed on only one row cannot be analysed."""
    reg = _reg(MISSION)
    with _wiretap(monkeypatch, responder=_priv) as seen:
        _run(reg._run_bfla({"url": ADMIN}))
    rows = [s for s in seen if s["method"] == method and s["url"] == ADMIN]
    assert len(rows) == 2
    assert {bool(_identity(r["headers"])) for r in rows} == {True, False}


def test_delete_stays_opt_in(monkeypatch):
    """Never DELETE-fuzz live data (authz_tool's stated rule). Guarding it here too, because the
    identity change makes these requests newly capable of reaching authenticated state."""
    reg = _reg(MISSION)
    with _wiretap(monkeypatch, responder=_priv) as seen:
        _run(reg._run_bfla({"url": ADMIN}))
    assert not any(s["method"] == "DELETE" for s in seen)
    with _wiretap(monkeypatch, responder=_priv) as seen2:
        _run(reg._run_bfla({"url": ADMIN, "allow_delete": True}))
    assert any(s["method"] == "DELETE" for s in seen2)
