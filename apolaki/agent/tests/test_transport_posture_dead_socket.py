"""Q-097 -- a security header cannot be MISSING from a response that never arrived.

FOUND IN THE FIELD. A full deterministic assessment against the Shopify HackerOne program on
2026-08-24 emitted 18 findings without a single socket ever reaching Shopify. `run_transport_posture`
is the ONLY engine in that mission's ledger with a nonzero count (`executed | 3 | 18`), and the
arithmetic is exact: 6 header checks (HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy, Permissions-Policy) x 3 origins = 18. Shopify really does send HSTS, CSP and XFO.

THE DEFECT, `tools.py:_run_transport_posture`:

    headers, set_cookies = {}, []
    try:
        r, _ = await self._http_send("GET", origin + "/", {}, None, True)
        headers = dict(r.headers or {})
        ...
    except Exception as _apolaki_swallowed_2960:
        self._swallow(...)
        pass

The connection fails, the exception is swallowed, `headers` stays `{}`, and
`transport_posture.analyze_security_headers({})` then reports every protective header absent.
**An empty dict from a dead socket is byte-identical to a response that carried no headers** -- the
falsy-default family, the same sentence as Q-092's `_cmd` exit code and Q-093's `r.get("body","")`.

The signal to gate on was ALREADY MEASURED AND ALREADY IGNORED: the mission's own stored result reads
`"tls": {"reachable": false}` beside its 18 header findings.

WHY Q-093 DID NOT COVER THIS. Q-093's chokepoint lives in `_http` (`tools.py:4078`), which catches the
transport error itself and returns `{"status": 0, ...}` so `_http_record` can book it. This path goes
through `_http_send` (`tools.py:2282`), which RAISES, and the raise is caught locally by the block
above. The Q-097 counter never sees it. The I-5 swallow ledger does make the failure VISIBLE, but
nothing gated finding emission on it: **visibility is not enforcement.**

BOTH HALVES ARE PINNED HERE, and that is the point of the file. "0 findings on a dead socket" passes
against an engine that never reports anything, which is exactly as useless as one that reports
everything -- it still cannot tell the two apart, which IS the defect. So every dead-socket assertion
is paired with a control on a page that GENUINELY lacks the header, and with a page that genuinely
SENDS it.

    dead socket           GET never completed      -> ran=False, 0 findings, error names the cause
    live, header absent   200 with no CSP          -> header_missing_csp STILL emitted
    live, header present  200 with CSP + XFO       -> those two NOT emitted

The hermetic tests replace `tools._target_client`, so `_http_send`'s real body and the whole of
`ToolRegistry.execute` (scope check, permission backstop, swallow ledger, dispatch ledger) are the
code under test. The live test at the bottom uses the real lab on `apolaki_default`; its header set
was MEASURED on 2026-08-24 and is two-sided by construction -- Juice Shop sends X-Frame-Options and
X-Content-Type-Options and sends no CSP and no Referrer-Policy, so the same response proves the engine
both reports and withholds.
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile

import httpx
import pytest

import db as dbmod
import scope as scope_mod
import tools as tools_mod
import transport_posture as tp

HOST = "juice-shop:3000"
ORIGIN = "http://juice-shop:3000"

# The verbatim resolver error the field mission produced, 45 times over.
DEAD_ERR = "[Errno -2] Name or service not known"

# The six protective headers whose absence the emitter reports. Named here so the arithmetic in the
# docstring stays checkable.
HEADER_FINDING_IDS = {
    "header_missing_framing_control", "header_missing_csp",
    "header_missing_strict_transport_security", "header_missing_x_content_type_options",
    "header_missing_referrer_policy", "header_missing_permissions_policy",
}


def _fresh(mid: str) -> None:
    dbmod.init(os.path.join(tempfile.mkdtemp(), "q097.db"))
    dbmod.create_mission(mid, "Q-097", "active", "o", {"in_scope": [HOST]}, {})


def _registry(mid: str):
    eng = scope_mod.ScopeEngine()
    eng.load_manual([HOST], [], mid)
    return tools_mod.ToolRegistry(eng, mission_id=mid)


class _FakeClient:
    """httpx-shaped. Either raises the resolver error the field run hit, or answers 200 with a
    scripted header set."""

    def __init__(self, alive: bool, headers: dict, tally: dict):
        self._alive, self._headers, self._tally = alive, headers, tally

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False

    async def request(self, method, url, headers=None, content=None, **_kw):
        if not self._alive:
            self._tally["dead"] += 1
            raise httpx.ConnectError(DEAD_ERR)
        self._tally["live"] += 1
        req = httpx.Request(method, url, headers=headers or {})
        return httpx.Response(200, text="<html></html>",
                              headers={"content-type": "text/html", **self._headers}, request=req)


def _transport(monkeypatch, alive: bool, headers: dict = None):
    tally = {"dead": 0, "live": 0}
    monkeypatch.setattr(tools_mod, "_target_client",
                        lambda *a, **k: _FakeClient(alive, headers or {}, tally))
    return tally


def _dispatch(reg, inp: dict):
    return asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
        reg.execute("run_transport_posture", inp, "s-q097"))


def _summary(res) -> dict:
    """The engine's JSON summary out of `res.output`.

    `execute()` prefixes a real, load-bearing string when calls were swallowed --
    `DEGRADED: 3 load-bearing check(s) failed to execute; latest=tools:_run_transport_posture:3380`
    -- so the output is not pure JSON on the dead path. That prefix is the I-5 visibility work and is
    exactly the evidence that the failure WAS known while the findings were emitted anyway.
    """
    out = res.output or ""
    i = out.find("{")
    return json.loads(out[i:]) if i >= 0 else {}


def _header_ids(res) -> set:
    """The header-family finding ids on a ToolResult. `finding()` stores the rule id at tags[2]."""
    out = set()
    for f in (res.findings or []):
        tags = f.get("tags") or []
        if len(tags) > 2:
            out.add(tags[2])
    return out & HEADER_FINDING_IDS


# ── the defect ────────────────────────────────────────────────────────────────

def test_a_dead_socket_emits_no_header_findings_and_reports_ran_false(monkeypatch):
    """MUST FAIL before the fix. Today: 5 header findings and `"ran": true` from zero responses.

    (5, not 6, only because this fixture is a plaintext origin so the HSTS rule is correctly skipped;
    the field mission was https, which is where the 6th came from.)
    """
    _fresh("q097-dead")
    tally = _transport(monkeypatch, alive=False)
    res = _dispatch(_registry("q097-dead"), {"url": ORIGIN + "/"})

    assert tally["dead"] > 0 and tally["live"] == 0, (
        "the transport script did not run -- this test would be vacuous: %r" % (tally,))
    assert not _header_ids(res), (
        "header findings were emitted from a request that never completed: %r" % (_header_ids(res),))
    assert not res.findings, (
        "a socket that never opened produced findings: %r" % ([f.get("title") for f in res.findings],))

    summary = _summary(res)
    assert summary.get("ran") is False, (
        "the engine reported a completed run over a dead socket: %r" % (summary,))
    assert DEAD_ERR in json.dumps(summary) or DEAD_ERR in (res.error or ""), (
        "nothing names the transport cause, so the operator cannot act on it: %r / %r"
        % (summary.get("note"), res.error))


def test_the_pure_layer_distinguishes_not_observed_from_observed_and_empty(monkeypatch):
    """The distinction the defect erased, pinned at the pure layer so no future caller can lose it.

    `headers={}` means "the response carried no protective headers" and MUST still report them.
    Not-observed is a different thing and must report nothing.
    """
    observed_empty = tp.findings_for(ORIGIN, headers={}, is_https=True)
    ids = {f["tags"][2] for f in observed_empty} & HEADER_FINDING_IDS
    assert len(ids) == 6, (
        "the observed-but-empty case must still report all six: %r" % (sorted(ids),))

    not_observed = tp.findings_for(ORIGIN, headers={}, is_https=True, http_observed=False)
    assert {f["tags"][2] for f in not_observed} & HEADER_FINDING_IDS == set(), (
        "a header claim survived an unobserved response: %r"
        % ([f["tags"][2] for f in not_observed],))


# ── the half that makes the test able to tell them apart ──────────────────────

def test_a_live_page_that_genuinely_lacks_a_header_still_reports_it(monkeypatch):
    """MUST PASS before AND after. The non-vacuity control: a gate that only checks the dead case is
    satisfied by an engine that never reports anything."""
    _fresh("q097-bare")
    tally = _transport(monkeypatch, alive=True, headers={})
    res = _dispatch(_registry("q097-bare"), {"url": ORIGIN + "/"})

    assert tally["live"] > 0 and tally["dead"] == 0, "fixture did not run: %r" % (tally,)
    got = _header_ids(res)
    assert "header_missing_csp" in got, (
        "a page that really sends no CSP stopped being reported -- the fix silenced the engine "
        "instead of gating it: %r" % (sorted(got),))
    assert "header_missing_referrer_policy" in got, sorted(got)
    assert _summary(res).get("ran") is True


def test_a_live_page_that_sends_the_headers_is_not_accused_of_missing_them(monkeypatch):
    """MUST PASS before AND after. The other side of the same coin: the engine reads real values.

    This is the case the field mission got wrong -- Shopify sends HSTS, CSP and X-Frame-Options, and
    the report claimed all three absent.
    """
    _fresh("q097-hardened")
    tally = _transport(monkeypatch, alive=True, headers={
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()",
    })
    res = _dispatch(_registry("q097-hardened"), {"url": ORIGIN + "/"})

    assert tally["live"] > 0, "fixture did not run: %r" % (tally,)
    got = _header_ids(res)
    assert got == set(), "headers that were present were reported missing: %r" % (sorted(got),)


# ── the live lab, real sockets ────────────────────────────────────────────────

def _lab_up() -> bool:
    try:
        return httpx.get(ORIGIN + "/", timeout=8).status_code == 200
    except Exception:
        return False


@pytest.mark.skipif(not _lab_up(), reason="requires the juice-shop lab on apolaki_default")
def test_live_lab_reports_the_headers_it_lacks_and_withholds_the_ones_it_sends():
    """Real sockets, no monkeypatch. MEASURED on juice-shop:3000 2026-08-24: it sends
    `x-frame-options: SAMEORIGIN` and `x-content-type-options: nosniff`, and sends neither
    Content-Security-Policy nor Referrer-Policy. One response therefore proves both directions."""
    _fresh("q097-live")
    res = _dispatch(_registry("q097-live"), {"url": ORIGIN + "/"})
    summary = _summary(res)
    assert summary.get("ran") is True, summary
    got = _header_ids(res)
    assert "header_missing_csp" in got and "header_missing_referrer_policy" in got, sorted(got)
    assert "header_missing_x_content_type_options" not in got, sorted(got)
    assert "header_missing_framing_control" not in got, sorted(got)
