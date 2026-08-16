"""Q-032/033/034 — IDENTITY CONTAMINATION, measured at the wire.

`session_headers` is one raw dict on the registry, merged into EVERY request by `_http_send`:

    h = {"User-Agent": _UA, **(self.session_headers or {}), **(headers or {})}

The caller's headers win per-key, so a same-key collision (Cookie vs Cookie) is safe. Two shapes
are NOT safe, and both are oracle defects rather than tidiness defects:

  1. ANONYMOUS IS NOT ANONYMOUS. `_authz_matrix._headers_for` returns `{}` for rank 0 and hands it
     to `_http_send`, which merges the mission session straight back in. The anon control row of
     the authorization matrix is then authenticated. `authz.build_matrix` reads that row three ways
     (missing_authentication fires ON it, bfla and horizontal IDOR require it to be DENIED), so one
     contaminated row produces false POSITIVES in one gap type and false NEGATIVES in two others.
     This is the `x or DEFAULT` shape: an empty header dict is a real input meaning "as nobody",
     not a missing one meaning "as whoever the mission is".

  2. CROSS-SCHEME BLEED. A mission authenticated by Cookie and a persona authenticated by Bearer do
     not collide on a key, so BOTH ride the same request. The server picks; the oracle assumes it
     drove the persona.

WHY THE SUITE IS GREEN ON A REAL DEFECT: every existing authz/IDOR test monkeypatches
`reg._http_send` itself (see tests/test_authz_matrix_driver.py `_reg`/`protected`), which is the
exact function that performs the merge. The contaminating line is never executed under test. These
tests therefore patch BELOW it, at `tools._target_client`, and assert on the headers that actually
reach the wire.

Fixtures here are copied from reality: the registry is a real `ToolRegistry`, the responses are real
`httpx.Response` objects, and the persona/session shapes are the ones
tests/test_authz_matrix_driver.py and tests/test_session_lifecycle.py already use
({"Cookie": "s=A"}, {"Authorization": "Bearer ..."}).
"""
from __future__ import annotations

import asyncio
import contextlib

import httpx
import pytest

import scope as S
import tools


BASE = "http://target.tld"


def _registry(session_headers=None):
    """A real ToolRegistry, scoped like the existing authz-matrix driver test does."""
    sc = S.ScopeEngine()
    sc.load_manual(["target.tld"], [], "T")
    return tools.ToolRegistry(sc, lab_mode=True, session_headers=session_headers or {})


@contextlib.contextmanager
def _wiretap(monkeypatch, status=200, text="ok"):
    """Capture the headers that actually reach the transport.

    Patches `tools._target_client`, i.e. BELOW `_http_send`, so the session_headers merge under
    test still runs. Returns a list that receives one dict of real request headers per request.
    """
    seen: list = []

    class _Client:
        async def request(self, method, url, content=None):
            return httpx.Response(status, text=text, request=httpx.Request(method, url))

    class _Ctx:
        def __init__(self, headers):
            self._headers = dict(headers or {})

        async def __aenter__(self):
            seen.append(dict(self._headers))
            return _Client()

        async def __aexit__(self, *exc):
            return False

    def _fake(*args, headers=None, **kwargs):
        return _Ctx(headers)

    monkeypatch.setattr(tools, "_target_client", _fake)
    yield seen


def _send(reg, headers):
    return asyncio.new_event_loop().run_until_complete(
        reg._http_send("GET", BASE + "/api/orders/1", headers, None, True))


# ── shape 1: the anonymous control row ──────────────────────────────────────────────────────────

@pytest.mark.xfail(strict=True, reason="Q-032 MEASURED defect: _http_send merges the mission "
                                       "session into an explicitly anonymous request")
def test_an_anonymous_persona_request_carries_no_mission_session(monkeypatch):
    """The defect that matters. `_headers_for(role, rank=0)` returns {} to mean 'as nobody'.

    If the mission session rides that request, the anon row of the authorization matrix is
    authenticated, and `authz.build_matrix` then reports missing_authentication on every protected
    endpoint the mission can reach while suppressing every bfla and horizontal-IDOR confirmation
    (all three read the anon row, `authz.py` lines 77-114 and tools.py's `_accessed(sn, bn)` gate).
    """
    reg = _registry({"Cookie": "sid=THE-MISSION-SESSION"})
    with _wiretap(monkeypatch) as seen:
        _send(reg, {})                      # exactly what _headers_for returns for rank 0
    wire = seen[0]
    assert "THE-MISSION-SESSION" not in str(wire), (
        "the anonymous control row carried the mission session; the matrix's anon baseline is "
        "authenticated, so missing_authentication over-fires and bfla/IDOR are suppressed: %r" % wire)


def test_an_explicitly_anonymous_request_is_distinguishable_from_an_absent_one(monkeypatch):
    """Empty is a real input. `{}` must mean 'as nobody' and be honoured as such, while a caller
    that expresses no opinion still inherits the mission identity (today's behaviour, preserved)."""
    reg = _registry({"Cookie": "sid=THE-MISSION-SESSION"})
    with _wiretap(monkeypatch) as seen:
        _send(reg, None)                    # no opinion -> mission identity, unchanged
    assert "THE-MISSION-SESSION" in str(seen[0]), (
        "a caller expressing no identity must still inherit the mission session")


# ── shape 2: cross-scheme bleed between two live identities ─────────────────────────────────────

@pytest.mark.xfail(strict=True, reason="Q-032 MEASURED defect: a Bearer persona request also "
                                       "carries the Cookie-authenticated mission session")
def test_a_bearer_persona_request_does_not_also_carry_the_missions_cookie(monkeypatch):
    """Cookie-mission + Bearer-persona do not collide on a key, so both ride the same request and
    the server chooses which identity served it. Every BOLA proof depends on that choice being ours."""
    reg = _registry({"Cookie": "sid=THE-MISSION-SESSION"})
    reg._sessions["attacker"] = {"Authorization": "Bearer ATTACKER-TOKEN"}
    with _wiretap(monkeypatch) as seen:
        _send(reg, reg._role_headers({"x_session": "attacker"}, "x"))
    wire = seen[0]
    assert "Bearer ATTACKER-TOKEN" in str(wire), "the persona's own credential must be present"
    assert "THE-MISSION-SESSION" not in str(wire), (
        "the attacker persona's request also carried the mission's cookie — two identities on one "
        "request, and the server picks: %r" % wire)


def test_two_personas_do_not_contaminate_each_other(monkeypatch):
    """The owner/attacker pair the BOLA oracle drives. Each request must carry exactly one identity."""
    reg = _registry()
    reg._sessions["owner"] = {"Cookie": "s=OWNER"}
    reg._sessions["attacker"] = {"Authorization": "Bearer ATTACKER-TOKEN"}
    with _wiretap(monkeypatch) as seen:
        _send(reg, reg._role_headers({"o_session": "owner"}, "o"))
        _send(reg, reg._role_headers({"a_session": "attacker"}, "a"))
    owner_wire, atk_wire = str(seen[0]), str(seen[1])
    assert "OWNER" in owner_wire and "ATTACKER-TOKEN" not in owner_wire, owner_wire
    assert "ATTACKER-TOKEN" in atk_wire and "OWNER" not in atk_wire, atk_wire
