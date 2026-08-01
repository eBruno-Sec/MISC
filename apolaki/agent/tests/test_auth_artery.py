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
        return _R(200, "victim basket: apples, juice, receipt #2"), 0.01
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
