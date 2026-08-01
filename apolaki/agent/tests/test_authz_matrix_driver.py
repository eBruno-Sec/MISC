"""Integration test for the two-user authorization-matrix DRIVER (_run_authz_matrix). Monkeypatches
the transport (like test_bbh's confirm_idor tests) to prove the oracle is deterministic and does not
over-confirm: protected cross-user read -> CONFIRMED IDOR; anon-accessible -> missing-auth NOT IDOR;
two different objects -> nothing."""
from __future__ import annotations

import asyncio
import json

import scope as S
import tools


class _R:
    def __init__(self, status, text):
        self.status_code, self.text = status, text
        self.headers = type("H", (), {"items": lambda self: []})()


def _reg():
    sc = S.ScopeEngine()
    sc.load_manual(["target.tld"], [], "T")
    reg = tools.ToolRegistry(sc, lab_mode=True)
    reg._sessions["user_a"] = {"Cookie": "s=A"}
    reg._sessions["user_b"] = {"Cookie": "s=B"}
    return reg


_ROLES = [{"role": "anonymous", "rank": 0}, {"role": "user_a", "rank": 1}, {"role": "user_b", "rank": 1}]
_OPS = [{"request": "/basket/2", "path": "/basket/2"}]
_INP = {"base_url": "http://target.tld", "roles": _ROLES, "operations": _OPS, "pair": ("user_a", "user_b")}


def _run(reg):
    return asyncio.new_event_loop().run_until_complete(reg._run_authz_matrix(_INP))


def test_protected_cross_user_read_is_confirmed_idor():
    reg = _reg()

    async def protected(method, url, headers, body, follow):
        if not headers.get("Cookie"):            # anonymous -> denied
            return _R(401, "unauthorized"), 0.01
        return _R(200, "victim basket: apples, juice, receipt #2"), 0.01

    reg._http_send = protected
    r = _run(reg)
    idor = [f for f in r.findings if "IDOR" in f["title"]]
    assert len(idor) == 1
    assert idor[0]["confidence"] == "confirmed" and idor[0]["cwe"] == "CWE-639"


def test_anon_accessible_object_is_missing_auth_not_idor():
    reg = _reg()

    async def public(method, url, headers, body, follow):
        return _R(200, "basket: apples, juice"), 0.01   # everyone, incl anon, sees the same

    reg._http_send = public
    r = _run(reg)
    assert not any("IDOR" in f["title"] for f in r.findings)          # NOT reported as IDOR
    assert any(f["cwe"] == "CWE-306" for f in r.findings)             # it's missing-authentication


def test_distinct_objects_are_not_confirmed():
    reg = _reg()

    async def per_user(method, url, headers, body, follow):
        c = headers.get("Cookie")
        if not c:
            return _R(401, "unauthorized"), 0.01
        return _R(200, "A private basket" if c == "s=A"
                  else "completely different B basket with other items"), 0.01

    reg._http_send = per_user
    r = _run(reg)
    assert not any("IDOR" in f["title"] for f in r.findings)          # different bytes -> no cross-user proof


def test_summary_shape():
    reg = _reg()

    async def protected(method, url, headers, body, follow):
        if not headers.get("Cookie"):
            return _R(401, "no"), 0.01
        return _R(200, "victim basket: apples, juice, receipt #2"), 0.01

    reg._http_send = protected
    r = _run(reg)
    d = json.loads(r.output)
    assert d["ran"] is True and d["confirmed"] >= 1
    assert set(d["roles"]) == {"anonymous", "user_a", "user_b"}
