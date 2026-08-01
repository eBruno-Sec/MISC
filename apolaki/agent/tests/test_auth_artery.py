"""Auth-artery acceptance test (CHAD section 10): PROVE the flow, don't just assert functions exist.

One end-to-end trace through BBHAgent._do_persona_authz with the network mocked:
  registration -> identity acquisition -> session capture -> authenticated re-crawl ->
  authorization matrix -> deterministic cross-user confirmation -> capabilities recorded,
and: raw secrets never appear in the event trace.
"""
from __future__ import annotations

import asyncio

import agent as agent_mod
import personas as P
import register as R
import scope as S
import tools
import vault


class _R:
    def __init__(self, status, text):
        self.status_code, self.text = status, text
        self.headers = type("H", (), {"items": lambda self: []})()


_SESS = {"user_a": {"Cookie": "s=AAA"}, "user_b": {"Cookie": "s=BBB"}}
_SECRET_PW = "PW_TOP_SECRET_123!"


def _build_agent(tmp_vault):
    sc = S.ScopeEngine()
    sc.load_manual(["target.tld"], [], "T")
    t = tools.ToolRegistry(sc, mission_id=None, lab_mode=True)
    t.urls = ["https://target.tld/rest/basket/2"]     # an object-bearing endpoint discovered in recon
    a = agent_mod.BBHAgent(sc, t, asyncio.Event(), mode="active",
                           authenticated_scan=True, mission_id=None)
    # point the module vault at a temp dir
    vault._DEFAULT = vault.Vault(str(tmp_vault))
    return a, t


def test_full_auth_artery_trace(tmp_path, monkeypatch):
    a, t = _build_agent(tmp_path)

    # (1) mock registration: the target's signup mints two same-privilege users
    async def fake_register(reg_url, label="user", account=None, timeout=15):
        return {"created": True, "headers": _SESS[label], "identity": f"apolaki_{label}@t.local",
                "account": {"username": f"apolaki_{label}", "email": f"apolaki_{label}@t.local",
                            "password": _SECRET_PW},
                "blocked": [], "verified": True, "note": "form signup -> 200"}
    monkeypatch.setattr(R, "register", fake_register)

    # (2) mock the transport: /rest/basket/2 is PROTECTED (anon denied) and user_a + user_b both
    #     read the SAME object -> confirmed cross-user access.
    async def transport(method, url, headers, body, follow):
        if not headers.get("Cookie"):
            return _R(401, "unauthorized"), 0.01
        # the object carries the owner persona's identity -> ownership PROVEN -> confirmed IDOR
        return _R(200, "order for apolaki_user_a@t.local: apples, juice, receipt #2"), 0.01
    t._http_send = transport

    events = asyncio.new_event_loop().run_until_complete(a._do_persona_authz("sess"))
    trace = " || ".join(e.get("content", e.get("finding", {}).get("title", "")) if isinstance(e, dict) else str(e)
                        for e in events)

    # ── the artery flowed, stage by stage ──
    assert "Created test persona 'user_a'" in trace
    assert "Created test persona 'user_b'" in trace
    assert "Authenticated re-crawl" in trace
    assert "Authorization matrix complete" in trace

    # ── a CONFIRMED cross-user finding was produced ──
    findings = [e["finding"] for e in events if e.get("type") == "finding"]
    idor = [f for f in findings if "IDOR" in f["title"]]
    assert len(idor) == 1
    assert idor[0]["confidence"] == "confirmed" and idor[0]["cwe"] == "CWE-639"

    # ── capabilities unlocked (feed planner + attack graph) ──
    assert t.state.has("second_persona_available")
    assert t.state.has("account_created")
    assert t.state.has("authenticated_surface_mapped")

    # ── secrets never entered the event trace ──
    blob = str(events)
    assert _SECRET_PW not in blob
    assert "s=AAA" not in blob and "s=BBB" not in blob

    # ── the secret was vaulted behind a reference ──
    ref = vault.default().list_refs("default")
    assert any(r.endswith("/user_a") for r in ref)
    stored = vault.default().get_role("default", "user_a")
    assert stored["password"] == _SECRET_PW          # retrievable server-side only


def test_scan_credential_reacquire_from_vault(tmp_path):
    # session lifecycle: a prior scan vaulted the discovered credential + login recipe; the next scan
    # recovers it from the vault reference (no plaintext in the snapshot) to acquire a fresh session.
    a, t = _build_agent(tmp_path)
    ref = vault.default().put("prior_mission", "__scan__",
                              {"username": "admin", "password": _SECRET_PW,
                               "recipe": {"login_url": "http://target.tld/rest/user/login"}})
    cred, login = a._creds_from_prior({"scan_auth_ref": ref, "scan_login_url": "http://ignored"})
    assert cred == f"admin:{_SECRET_PW}"
    assert login == "http://target.tld/rest/user/login"      # recipe login_url wins
    # legacy plaintext snapshots still work (backward compat)
    cred2, login2 = a._creds_from_prior({"scan_auth": "bob:legacypw", "scan_login_url": "http://t/login"})
    assert cred2 == "bob:legacypw" and login2 == "http://t/login"
    # nothing recorded -> nothing recovered
    assert a._creds_from_prior({}) == (None, None)


def test_browser_login_fallback_mints_persona(tmp_path, monkeypatch):
    # #55: API/form login yields no session (SPA login) -> the browser-driven fallback promotes a
    # token from web storage into the persona's session, and the persona is still minted.
    a, t = _build_agent(tmp_path)

    async def fake_register(reg_url, label="user", account=None, timeout=15):
        return {"created": True, "headers": {}, "identity": f"{label}@t.local",
                "account": {"username": f"u_{label}", "email": f"{label}@t.local", "password": _SECRET_PW},
                "blocked": [], "verified": False, "note": "json signup (no session)"}
    monkeypatch.setattr(R, "register", fake_register)

    class _TR:
        def __init__(self):
            self.findings, self.output, self.success = [], "{}", True

    async def stub_execute(tool, inp, sid):
        if tool == "browser_navigate":                    # the browser login promotes a token
            t._sessions[inp["promote_session"]] = {"Authorization": "Bearer eyJhbGc.payload.sig"}
        return _TR()                                      # acquire_session/http_read/matrix -> noop
    t.execute = stub_execute

    events = asyncio.new_event_loop().run_until_complete(a._do_persona_authz("sess"))
    trace = " || ".join(e.get("content", "") for e in events if e.get("type") == "info")
    assert "Created test persona 'user_a'" in trace       # minted via the browser fallback
    assert "Created test persona 'user_b'" in trace
    assert _SECRET_PW not in str(events) and "eyJhbGc" not in str(events)   # secrets never leak


def test_artery_noop_without_optin(tmp_path, monkeypatch):
    # authenticated_scan off -> the persona phase does nothing (safe default; no accounts created)
    a, t = _build_agent(tmp_path)
    a.authenticated_scan = False
    called = {"n": 0}

    async def fake_register(*args, **kwargs):
        called["n"] += 1
        return {"created": True, "headers": {"Cookie": "x"}, "account": {}, "blocked": []}
    monkeypatch.setattr(R, "register", fake_register)

    events = asyncio.new_event_loop().run_until_complete(a._do_persona_authz("sess"))
    assert events == []
    assert called["n"] == 0                          # never touched the signup flow
