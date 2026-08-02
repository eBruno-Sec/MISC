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
_INP = {"base_url": "http://target.tld", "roles": _ROLES, "operations": _OPS,
        "pair": ("user_a", "user_b"), "owner_identity": "carlos@t.local"}


def _run(reg):
    return asyncio.new_event_loop().run_until_complete(reg._run_authz_matrix(_INP))


def test_owned_object_read_cross_user_is_confirmed_idor():
    reg = _reg()

    async def protected(method, url, headers, body, follow):
        if not headers.get("Cookie"):            # anonymous -> denied
            return _R(401, "unauthorized"), 0.01
        # object carries the OWNER's identity -> ownership is PROVEN
        return _R(200, "order for carlos@t.local: apples, juice, receipt #2"), 0.01

    reg._http_send = protected
    r = _run(reg)
    idor = [f for f in r.findings if f["confidence"] == "confirmed" and "IDOR" in f["title"]]
    assert len(idor) == 1 and idor[0]["cwe"] == "CWE-639"


def test_object_specific_differential_is_a_strong_lead_not_confirmed():
    # no owner identity in the body; a different id returns different data (object-specific). That's a
    # STRONG signal but NOT proof of ownership (a shared-but-protected paginated resource looks the
    # same), so it must be a LEAD, not confirmed (CHAD re-audit #3).
    reg = _reg()

    async def per_object(method, url, headers, body, follow):
        if not headers.get("Cookie"):
            return _R(401, "unauthorized"), 0.01
        if url.endswith("/basket/2"):
            return _R(200, "victim basket 2: apples, juice, receipt"), 0.01
        return _R(200, "different basket 3: batteries and cables"), 0.01   # control id -> different

    reg._http_send = per_object
    r = asyncio.new_event_loop().run_until_complete(
        reg._run_authz_matrix({**_INP, "owner_identity": ""}))
    assert not any(f["confidence"] == "confirmed" for f in r.findings)     # never over-claims
    idor = [f for f in r.findings if f["family"] == "idor" and "object-specific" in f["evidence"]]
    assert len(idor) == 1 and idor[0]["confidence"] == "lead" and "needs-ownership-proof" in idor[0]["tags"]


def test_shared_object_without_ownership_is_lead_not_confirmed():
    reg = _reg()

    async def protected(method, url, headers, body, follow):
        if not headers.get("Cookie"):
            return _R(401, "unauthorized"), 0.01
        # same protected object for both users, but NO owner identity in it -> could be shared
        return _R(200, "team dashboard: shared widgets and counters"), 0.01

    reg._http_send = protected
    r = _run(reg)
    assert not any(f["confidence"] == "confirmed" for f in r.findings)   # never over-claims
    leads = [f for f in r.findings if f["confidence"] == "lead" and "IDOR" in f["title"]]
    assert len(leads) == 1 and "needs-ownership-proof" in leads[0]["tags"]


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


# ── horizontal WRITE oracle (with restore) ──
def _run_write(reg):
    return asyncio.new_event_loop().run_until_complete(reg._confirm_authz_write(
        {"target_url": "http://target.tld/api/profile/1", "owner_session": "user_a",
         "attacker_session": "user_b"}))


def test_horizontal_write_confirmed_then_restored():
    reg = _reg()
    obj = {"name": "original-name"}

    async def stateful(method, url, headers, body, follow):
        if method == "GET":
            return _R(200, json.dumps(obj)), 0.01
        b = body if isinstance(body, dict) else json.loads(body or "{}")
        obj.update(b)                                    # write persists (vulnerable app)
        return _R(200, "ok"), 0.01

    reg._http_send = stateful
    r = _run_write(reg)
    d = json.loads(r.output)
    assert d["confirmed"] is True and d["restored"] is True
    assert obj["name"] == "original-name"                # restored to the last reversible boundary
    assert r.findings and r.findings[0]["cwe"] == "CWE-639" and r.findings[0]["severity"] == "critical"


def test_horizontal_write_denied_is_not_confirmed():
    reg = _reg()
    obj = {"name": "original-name"}

    async def enforced(method, url, headers, body, follow):
        if method == "GET":
            return _R(200, json.dumps(obj)), 0.01
        if headers.get("Cookie") == "s=B":               # attacker write is properly denied
            return _R(403, "forbidden"), 0.01
        b = body if isinstance(body, dict) else json.loads(body or "{}")
        obj.update(b)
        return _R(200, "ok"), 0.01

    reg._http_send = enforced
    r = _run_write(reg)
    assert json.loads(r.output)["confirmed"] is False
    assert not r.findings
    assert obj["name"] == "original-name"                # never mutated
