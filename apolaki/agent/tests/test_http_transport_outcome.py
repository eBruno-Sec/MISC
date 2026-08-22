"""Q-093 -- a dead connection must not be byte-identical to a clean page.

I-2b (outcome fidelity on the RETURN edge) in the HTTP path. Q-092 fixed it for subprocesses:
`_cmd` measured the exit code and threw it away, so a tool that ran and failed looked exactly like a
tool that ran and found nothing. `tools.ToolRegistry._http` has the identical defect with a wider
blast radius -- it is the transport for all 21 pure-Python engines.

`_http` is HONEST. On any transport exception it returns

    {"error": str(e), "status": 0, "headers": {}, "body": "", "length": 0, "final_url": url}

**The callers never read `status` or `error`.** Every engine does `r.get("body", "") or ""`, so an
empty body from a connection that never opened is the same VALUE as an empty body from a clean page.

MEASURED live on `apolaki_default` before this file existed (docs/handoff/tool_liveness_audit.md
s10.2-10.3), url = `https://juice-shop:3000/rest/products/search?q=apple`, a host that speaks
plaintext only, so every request failed with `[SSL: WRONG_VERSION_NUMBER]`:

    run_waf_bypass       -> success=True  '0 WAF-bypass finding(s)'       error=None   <-- SILENT
    run_sqli_structural  -> success=True  '0 structural SQLi finding(s)'  error=None   <-- SILENT
    run_css_injection    -> success=True  '0 CSS injection finding(s)'    error=None   <-- SILENT

3241 of 27222 corpus dispatches (11.9%) went to a target that could not answer, and every one of
them is sitting in `logs.etype='tool_result'` wearing a clean-scan summary.

**WHY THE Q-08x SWALLOW LEDGER CANNOT CLOSE THIS.** The ledger catches wrappers that wrap their
requests in a `try/except`. The three above never raise: `_http` catches the transport error itself
and hands back a dict, so **the failure arrives as DATA, not as an exception.** There is no
exception for a ledger to catch. Right mechanism, wrong half of the problem.

WHY BOTH HALVES ARE PINNED HERE, and this is the whole point of the file. A test asserting "0
findings on a dead connection" passes against the BROKEN code and proves nothing. Every dead-
transport assertion below is paired with a reachable-transport assertion on the SAME engine over the
SAME page, because a fix that reports failure for everything is exactly as useless as one that
reports success for everything -- it still cannot tell the two apart, which IS the defect.

    dead      every request failed        -> success=False, error names the transport failure
    clean     every request succeeded     -> success=True,  error=None,  0 findings
    partial   some failed, some succeeded -> success=True   (degraded, not dead -- the existing
                                                             `DEGRADED:` line already covers it)
    silent    the engine made no requests -> untouched

NOTHING HERE TOUCHES THE NETWORK. `tools._target_client` is replaced, so `_http`'s real body --
including its real `except Exception` branch -- and the whole of `ToolRegistry.execute` (scope
check, permission backstop, `getattr(self, "_" + tool_name)` resolution, the swallow ledger, the
dispatch ledger) are the code under test. Stubbing `_http` or `execute` itself would test nothing.
"""
from __future__ import annotations

import asyncio
import os
import tempfile

import httpx
import pytest

import db as dbmod
import scope as scope_mod
import tools as tools_mod

# A plaintext lab host, in scope, and the exact page the live measurement above used. No socket is
# ever opened for it in this file.
HOST = "juice-shop:3000"
URL = "http://juice-shop:3000/rest/products/search?q=apple"

# The verbatim transport error the live reproduction produced. Using the real string keeps the
# assertion about the operator-visible cause rather than about our own wording.
SSL_ERR = "[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:1010)"

CLEAN_BODY = '{"status":"success","data":[]}'


def _fresh(mid: str) -> None:
    dbmod.init(os.path.join(tempfile.mkdtemp(), "q093.db"))
    dbmod.create_mission(mid, "Q-093", "active", "o", {"in_scope": [HOST]}, {})


def _registry(mid: str = "q093"):
    """A REAL ToolRegistry. Only the HTTP transport underneath `_http` is replaced."""
    eng = scope_mod.ScopeEngine()
    eng.load_manual([HOST], [], mid)
    return tools_mod.ToolRegistry(eng, mission_id=mid)


class _FakeClient:
    """An httpx-shaped client whose per-request outcome is scripted.

    `plan(n)` returns True to answer the n-th request with a clean 200, or False to raise the
    transport error `_http` is measured to swallow into `{"status": 0}`.
    """

    def __init__(self, plan, tally):
        self._plan, self._tally = plan, tally

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False

    async def request(self, method, url, headers=None, content=None, **_kw):
        n = self._tally["n"]
        self._tally["n"] = n + 1
        if not self._plan(n):
            self._tally["dead"] += 1
            raise httpx.ConnectError(SSL_ERR)
        self._tally["live"] += 1
        req = httpx.Request(method, url, headers=headers or {})
        return httpx.Response(200, text=CLEAN_BODY,
                              headers={"content-type": "application/json"}, request=req)


def _transport(monkeypatch, plan):
    """Install the scripted transport under `_http`. Returns the tally it fills in."""
    tally = {"n": 0, "dead": 0, "live": 0}
    monkeypatch.setattr(tools_mod, "_target_client",
                        lambda *a, **k: _FakeClient(plan, tally))
    return tally


def _dispatch(reg, tool: str, inp: dict):
    return asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
        reg.execute(tool, inp, "s-q093"))


ALL_DEAD = lambda _n: False
ALL_LIVE = lambda _n: True
EVERY_OTHER = lambda n: n % 2 == 0

# Q-093, OPEN. The defect is filed and MEASURED; the fix is not in this commit. `strict=True` on
# purpose, following `tests/test_outcome_fidelity.py`'s `_KNOWN_OPEN`: the moment the chokepoint
# starts carrying the transport outcome, these XPASS and pytest turns them RED, so the marker
# cannot outlive the defect it describes. A landed fix MUST delete this line.
#
# MEASURED against HEAD 2dd1f7a, `pytest tests/test_http_transport_outcome.py -q`:
#   FFF.....F   -- 4 failed, 5 passed
# the 4 are exactly the ones marked below; the 5 that pass are the negative controls, and they
# passing BEFORE the fix is what proves this file can tell a dead connection from a clean page.
_OPEN = pytest.mark.xfail(strict=True, reason="Q-093: _http drops the transport outcome")


# ── the defect ────────────────────────────────────────────────────────────────
# Each of these three engines was MEASURED returning success=True / error=None over a connection
# that never opened. They are parametrized together because the fix must be at the ONE chokepoint
# every engine already goes through, not bolted onto whichever engine someone thought to check.
SILENT_ENGINES = [
    ("run_waf_bypass", "WAF-bypass"),
    ("run_sqli_structural", "structural SQLi"),
    ("run_css_injection", "CSS injection"),
]


@_OPEN
@pytest.mark.parametrize("tool,_label", SILENT_ENGINES)
def test_a_dispatch_whose_every_request_failed_is_not_a_clean_scan(tool, _label, monkeypatch):
    """MUST FAIL before the fix. Today: success=True, error=None, 'N finding(s)'."""
    _fresh("q093-dead")
    tally = _transport(monkeypatch, ALL_DEAD)
    res = _dispatch(_registry("q093-dead"), tool, {"url": URL})

    assert tally["dead"] > 0 and tally["live"] == 0, (
        "the transport script did not run -- this test would be vacuous: %r" % (tally,))
    assert res is not None
    assert res.success is False, (
        "a dispatch that made %d request(s) and completed NONE of them reported a completed scan: "
        "success=%r output=%r error=%r" % (tally["dead"], res.success, res.output, res.error))
    assert res.error, "no error on the ToolResult: the failure is still invisible to the operator"
    assert "WRONG_VERSION_NUMBER" in res.error, (
        "the error does not name the transport cause, so the operator cannot act on it: %r"
        % (res.error,))


# ── the half that makes the test able to tell them apart ──────────────────────

@pytest.mark.parametrize("tool,_label", SILENT_ENGINES)
def test_a_genuinely_clean_page_still_reports_a_completed_scan(tool, _label, monkeypatch):
    """MUST PASS before AND after. The negative control against a fix that fails everything."""
    _fresh("q093-clean")
    tally = _transport(monkeypatch, ALL_LIVE)
    res = _dispatch(_registry("q093-clean"), tool, {"url": URL})

    assert tally["live"] > 0 and tally["dead"] == 0, (
        "the transport script did not run -- this test would be vacuous: %r" % (tally,))
    assert res.success is True, (
        "a reachable page with nothing wrong was reported as a failure: %r / %r"
        % (res.output, res.error))
    assert res.error is None, "a clean scan grew an error: %r" % (res.error,)
    assert not res.findings, "the clean fixture must not produce findings: %r" % (res.findings,)


def test_partial_failure_stays_degraded_and_does_not_become_dead(monkeypatch):
    """MUST PASS before AND after. Some requests completed, so something WAS scanned."""
    _fresh("q093-partial")
    tally = _transport(monkeypatch, EVERY_OTHER)
    res = _dispatch(_registry("q093-partial"), "run_waf_bypass", {"url": URL})

    assert tally["live"] > 0 and tally["dead"] > 0, (
        "the fixture produced no mixed outcome, so it does not test what it claims: %r" % (tally,))
    assert res.success is True, (
        "a dispatch that completed %d request(s) was reported as having reached nothing"
        % (tally["live"],))


def test_a_dispatch_that_made_no_requests_at_all_is_untouched(monkeypatch):
    """MUST PASS before AND after.

    `run_waf_bypass` returns early on a URL with no query params, without sending anything. Zero
    dead and zero live is NOT a failure, and a fix that treats "no evidence" as "evidence of
    failure" would redden every non-HTTP engine in the registry.
    """
    _fresh("q093-none")
    tally = _transport(monkeypatch, ALL_DEAD)
    res = _dispatch(_registry("q093-none"), "run_waf_bypass",
                    {"url": "http://juice-shop:3000/rest/products"})

    assert tally["n"] == 0, "fixture sent requests it was not supposed to: %r" % (tally,)
    assert res.success is True and res.error is None, (
        "a dispatch that made no requests was reported as a transport failure: %r / %r"
        % (res.output, res.error))


@_OPEN
def test_a_dead_dispatch_does_not_poison_the_next_clean_one(monkeypatch):
    """MUST PASS before AND after -- the cross-attribution negative control.

    The obvious implementation is a counter on the registry read as a delta around the dispatch.
    That is the shape `_swallowed_total` already uses, and it is exactly the shape that mis-bills
    one engine for another's failures if the bracketing is wrong. A dead dispatch followed by a
    clean one on the SAME registry must leave the clean one clean.
    """
    _fresh("q093-seq")
    reg = _registry("q093-seq")

    tally_dead = _transport(monkeypatch, ALL_DEAD)
    dead = _dispatch(reg, "run_waf_bypass", {"url": URL})
    assert tally_dead["dead"] > 0

    tally_live = _transport(monkeypatch, ALL_LIVE)
    clean = _dispatch(reg, "run_waf_bypass", {"url": URL})

    assert tally_live["live"] > 0 and tally_live["dead"] == 0
    assert clean.success is True and clean.error is None, (
        "the previous dispatch's dead requests were billed to this one: %r / %r"
        % (clean.output, clean.error))
    # and the dead one is still reported as dead -- stated here so a fix cannot pass this test by
    # simply never reporting anything.
    assert dead.success is False, "the dead dispatch stopped being reported: %r" % (dead.output,)
