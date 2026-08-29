"""Q-112 -- a middlebox eating our OWN payloads must not be reported as a clean target.

THE MEASUREMENT. The operator scanned an authorized program from his home network. Mid-scan he
opened his ISP gateway's app and found the router's own IPS dropping Apolaki's probes OUTBOUND,
before they ever left the network:

    16:50  HTTP URI Comment Characters SQL Injection was blocked
    16:50  HTTP URI 1=1 SQL Injection was blocked
    16:50  HTTP URI Equal To SQL Injection was blocked
    16:54  HTTP URI Union Select SQL Injection was blocked

Those strings are `sqli_tool`'s payloads. The report for the same run, same endpoints, said:

    run_sqli            | executed | 70 | 0 | tested 3 param(s), 0 confirmed SQLi
    run_sqli_structural | executed | 69 | 0 | 0 structural SQLi finding(s)
    run_xpath / run_ldap / run_ssi / run_css_injection | 69 each | 0

Every one of those zeros is a blocked request, not a tested parameter. Q-092 was `_cmd` discarding
an exit code, Q-093 was `_http` discarding a transport outcome, Q-097 was an empty header dict from
a dead socket reading as a clean response. Same sentence, one layer out: A FAILED ATTEMPT MUST NOT
BE REPORTED AS A CLEAN RESULT. What is new is that the failure is on OUR side of the wire, so
nothing in the process sees an error at all.

THREE HALVES ARE PINNED HERE, and the second and third are the ones that make this an oracle
rather than a downgrade switch:

  1. every payload request fails + the benign control succeeds + ACROSS UNRELATED HOSTS
                                   -> DEGRADED, success=False, results VOID
  2. a genuinely clean target -- benign AND payload requests both answered normally
                                   -> a plain zero, success=True, no DEGRADED anywhere.
                                      A check that turns every quiet scan into a false alarm is
                                      worse than the bug it replaces.
  3. ONE host showing the pattern  -> NOT a middlebox verdict. That is a WAF or a tarpit on the
                                      target: a finding ABOUT THE TARGET. Without this half the
                                      module is a WAF detector wearing the wrong label.

Plus: a host that ANSWERS 403 to every payload does not trip it either -- a response is a response.

NOTHING HERE TOUCHES THE NETWORK. `tools._target_client` is replaced, so the engines' real request
loops, their real `except` branches, `_http`'s real transport handler and the real
`ToolRegistry` return path are the code under test. Asserting only on `middlebox.assess` would
prove the module works and say nothing about whether anything calls it.
"""
from __future__ import annotations

import asyncio
import inspect
import os
import tempfile

import httpx
import pytest

import db as dbmod
import middlebox as mb
import scope as scope_mod
import tools as tools_mod
import xss_tool as xt

HOST_A = "alpha.example.test"
HOST_B = "beta.example.net"                 # UNRELATED registrable domain, deliberately
HOST_A2 = "www.alpha.example.test"          # SAME registrable domain as HOST_A
URL_A = "http://alpha.example.test/p?q=1"
URL_B = "http://beta.example.net/s?id=7"
URL_A2 = "http://www.alpha.example.test/z?k=2"

CLEAN_BODY = '{"status":"success","data":[]}'
DROP_ERR = "timed out"


# ── the fake transport ────────────────────────────────────────────────────────

class _FakeClient:
    """An httpx-shaped client whose per-request outcome is decided by `verdict(url)`.

    `verdict` returns "ok" (200), "drop" (raise, i.e. reset/timeout -- what a dropping middlebox
    produces) or "block" (a 403 answered by something inline).
    """

    def __init__(self, verdict, log):
        self._verdict, self._log = verdict, log

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False

    def _answer(self, method, url, headers=None):
        v = self._verdict(str(url))
        self._log.append((str(url), v))
        req = httpx.Request(method, str(url), headers=headers or {})
        if v == "drop":
            raise httpx.ConnectTimeout(DROP_ERR, request=req)
        if v == "block":
            return httpx.Response(403, text="request blocked", request=req)
        return httpx.Response(200, text=CLEAN_BODY,
                              headers={"content-type": "application/json"}, request=req)

    async def get(self, url, **kw):
        return self._answer("GET", url, kw.get("headers"))

    async def post(self, url, **kw):
        return self._answer("POST", url, kw.get("headers"))

    async def request(self, method, url, headers=None, content=None, **_kw):
        return self._answer(method, url, headers)


def _drops_payloads(url: str) -> str:
    """The measured middlebox: benign requests pass, anything that LOOKS like an attack is dropped
    before it leaves the network. Classification here is `middlebox`'s own, which is the point --
    the device also decides by inspecting the URI."""
    return "drop" if mb.looks_payload_bearing(url) else "ok"


def _answers_everything(url: str) -> str:
    """A genuinely clean, healthy target."""
    return "ok"


def _blocks_payloads_with_403(url: str) -> str:
    """An inline WAF that ANSWERS rather than drops."""
    return "block" if mb.looks_payload_bearing(url) else "ok"


def _registry(monkeypatch, verdict, mid="q112"):
    dbmod.init(os.path.join(tempfile.mkdtemp(), "q112.db"))
    dbmod.create_mission(mid, "Q-112", "active", "o",
                         {"in_scope": [HOST_A, HOST_B, HOST_A2]}, {})
    eng = scope_mod.ScopeEngine()
    eng.load_manual([HOST_A, HOST_B, HOST_A2], [], mid)
    log = []
    monkeypatch.setattr(tools_mod, "_target_client",
                        lambda *a, **k: _FakeClient(verdict, log))
    reg = tools_mod.ToolRegistry(eng, mission_id=mid, lab_mode=True)
    return reg, log


def _run(coro):
    return asyncio.get_event_loop_policy().new_event_loop().run_until_complete(coro)


# ── the differential itself, as a pure function ───────────────────────────────

def _host(name, benign_ok, benign_fail, payload_ok, payload_fail):
    return {"host": name, "domain": mb.registrable(name), "benign_ok": benign_ok,
            "benign_fail": benign_fail, "payload_ok": payload_ok,
            "payload_fail": payload_fail, "sample": ""}


def test_the_pattern_on_two_unrelated_hosts_is_an_upstream_middlebox():
    v = mb.assess([_host(HOST_A, 3, 0, 0, 12), _host(HOST_B, 2, 0, 0, 9)])
    assert v.intercepted is True, v
    assert set(v.domains) == {"example.test", "example.net"}, v.domains
    assert "INTERCEPTED UPSTREAM" in v.note()


def test_the_same_pattern_on_ONE_host_is_a_defence_on_the_target():
    """NEGATIVE CONTROL 3. Without this the module is a WAF detector, mislabelled."""
    v = mb.assess([_host(HOST_A, 3, 0, 0, 40)])
    assert v.intercepted is False, v
    assert v.note() == ""
    assert v.suspect_hosts == [HOST_A]          # seen, and deliberately not escalated
    assert "TARGET" in v.reason


def test_two_hosts_under_ONE_registrable_domain_are_not_two_hosts():
    """`alpha.example.test` and `www.alpha.example.test` are one operator's infrastructure. Counting
    subdomains as unrelated is the cheap way to fake clause 3 and would fire on any WAF that fronts
    a whole domain."""
    v = mb.assess([_host(HOST_A, 3, 0, 0, 12), _host(HOST_A2, 3, 0, 0, 12)])
    assert v.intercepted is False, v
    assert v.domains == ["example.test"], v.domains


def test_a_host_that_answers_every_payload_is_not_suspect():
    """NEGATIVE CONTROL 2, in pure form: nothing failed, so nothing is void."""
    v = mb.assess([_host(HOST_A, 3, 0, 30, 0), _host(HOST_B, 3, 0, 25, 0)])
    assert v.intercepted is False, v
    assert v.suspect_hosts == []


def test_one_payload_that_got_through_disproves_interception_for_that_host():
    """Clause 2 is EVERY, not most. One payload-bearing request that reached the target proves the
    path is not filtered, whatever else failed."""
    v = mb.assess([_host(HOST_A, 3, 0, 1, 40), _host(HOST_B, 3, 0, 0, 40)])
    assert v.intercepted is False, v
    assert v.suspect_hosts == [HOST_B]


def test_a_dead_benign_control_is_not_interception():
    """If the benign request fails too, the host is simply unreachable. Reporting that as an
    injection-specific filter would misattribute every down target."""
    v = mb.assess([_host(HOST_A, 0, 5, 0, 40), _host(HOST_B, 0, 5, 0, 40)])
    assert v.intercepted is False, v


def test_a_couple_of_failures_are_below_the_evidence_floor():
    """Two dropped probes on a flaky link is not evidence of a filter."""
    v = mb.assess([_host(HOST_A, 3, 0, 0, 2), _host(HOST_B, 3, 0, 0, 2)])
    assert v.intercepted is False, v
    assert mb.MIN_PAYLOAD_ATTEMPTS >= 3


def test_assess_does_not_mutate_or_invent():
    assert mb.assess([]).intercepted is False
    assert mb.assess(None).intercepted is False


# ── classification: the engines' REAL payloads, percent-encoded as they go out ─

@pytest.mark.parametrize("value", [
    "1'", "1''", "1' AND '1'='1", "1' AND 1=1-- -", "1 AND 1=2",
    "1' UNION SELECT NULL-- -", "1'); WAITFOR DELAY '0:0:5'--",
    "1; echo APOLAKI$(( 7 * 6 ))", "1| sleep 5", "1`echo x`", "1$(echo x)",
    "1']|//*['", "1*)(", "../../../etc/passwd",
])
def test_a_real_payload_survives_percent_encoding_and_is_classified(value):
    """THE TRAP THIS PINS. `xt.set_param` percent-encodes everything a payload is made of -- `1=1`
    leaves as `1%3D1`, `'` as `%27`. A classifier that matched the raw URL would call every real
    payload benign, which would empty the payload bucket and disable this module silently, with a
    green test suite. The IPS log the ticket is built on named `1=1`, comment characters and
    `union select` specifically."""
    probe = xt.set_param("http://alpha.example.test/p?q=1", "q", value)
    assert "%" in probe or " " not in value      # sanity: it really was encoded
    assert mb.looks_payload_bearing(probe), probe


@pytest.mark.parametrize("url", [
    "http://alpha.example.test/p?q=1",
    "http://alpha.example.test/rest/products/search?q=apple",
    "http://beta.example.net/s?id=7&page=2",
    "http://beta.example.net/users/42/profile",
    "http://alpha.example.test/p?q=bbh_nosqli_9f2a",       # nosqli's deliberate benign control
])
def test_an_ordinary_request_is_not_classified_as_a_payload(url):
    """The other half. If ordinary traffic were classified as payload-bearing there would be no
    benign control left and clause 1 could never be satisfied."""
    assert not mb.looks_payload_bearing(url), url


def test_host_and_domain_extraction():
    assert mb.host_of("http://alpha.example.test:3000/p?q=1") == "alpha.example.test"
    assert mb.host_of("") == ""
    assert mb.registrable("juice-shop") == "juice-shop"
    assert mb.registrable("127.0.0.1") == "127.0.0.1"
    assert mb.registrable("a.b.shop.co.uk") == "shop.co.uk"
    assert mb.registrable("cdn.assets.example.com") == "example.com"


def test_a_port_does_not_make_two_hosts():
    """Two local labs on one machine are ONE host. Otherwise a single box could satisfy the
    unrelated-hosts clause by itself."""
    led = mb.Ledger()
    led.record("http://localhost:3000/a?q=1", True)
    led.record("http://localhost:8080/a?q=1", True)
    assert [s["host"] for s in led.stats()] == ["localhost"]


# ── THE GATE: the real engines, over the real return path ─────────────────────

INJECTION_ENGINES = ["_run_sqli", "_run_nosqli", "_run_cmdi", "_run_xpath", "_run_ldap",
                     "_run_ssi", "_run_css_injection", "_run_sqli_structural"]


def test_GATE_two_unrelated_hosts_void_the_injection_result(monkeypatch):
    """HALF ONE, and HALF THREE in the same run.

    The FIRST host is scanned with only its own evidence available: one host dropping every payload
    is a WAF on that target, so the engine must still report a plain zero. Only after the SECOND,
    unrelated host shows the identical pattern does the verdict flip -- because only then is it
    impossible for any one target to be the cause.
    """
    reg, log = _registry(monkeypatch, _drops_payloads)

    first = _run(reg._run_sqli({"url": URL_A}))
    assert first.success is True, first          # single host: NOT a middlebox verdict
    assert "DEGRADED" not in (first.output or ""), first.output

    second = _run(reg._run_sqli({"url": URL_B}))
    assert second.success is False, second       # ran=False: the ledger must see it
    assert "DEGRADED" in second.output, second.output
    assert "INTERCEPTED UPSTREAM" in second.output, second.output
    assert "VOID" in second.output, second.output

    # and it really was our own payloads being dropped, not an empty run
    dropped = [u for u, v in log if v == "drop"]
    assert len(dropped) >= 2 * mb.MIN_PAYLOAD_ATTEMPTS, len(dropped)


def test_GATE_negative_control_a_clean_target_still_reports_a_plain_zero(monkeypatch):
    """HALF TWO, THE ONE THAT MATTERS. Both hosts answer everything, payloads included. If this
    reports DEGRADED the fix is a false-alarm generator and is worse than the defect."""
    reg, log = _registry(monkeypatch, _answers_everything)

    for url in (URL_A, URL_B):
        res = _run(reg._run_sqli({"url": url}))
        assert res.success is True, res
        assert "DEGRADED" not in (res.output or ""), res.output
        assert "confirmed SQLi" in res.output, res.output
    assert log and all(v == "ok" for _u, v in log)


def test_GATE_negative_control_an_inline_WAF_that_ANSWERS_is_not_our_middlebox(monkeypatch):
    """A 403 is a response: the request reached something on the far side. Calling that our own
    uplink would void real scans of every well-defended target."""
    reg, _log = _registry(monkeypatch, _blocks_payloads_with_403)
    for url in (URL_A, URL_B):
        res = _run(reg._run_sqli({"url": url}))
        assert res.success is True, res
        assert "DEGRADED" not in (res.output or ""), res.output


def test_GATE_subdomains_of_one_domain_do_not_reach_the_verdict(monkeypatch):
    """HALF THREE at the engine level: two hosts, one owner, still a target-side defence."""
    reg, _log = _registry(monkeypatch, _drops_payloads)
    for url in (URL_A, URL_A2):
        res = _run(reg._run_sqli({"url": url}))
        assert res.success is True, res
        assert "DEGRADED" not in (res.output or ""), res.output


def test_the_verdict_reaches_the_http_carried_engines_too(monkeypatch):
    """`_run_xpath` / `_run_ldap` / `_run_ssi` / `_run_css_injection` / `_run_sqli_structural` send
    their GET-parameter probes through `_http`, not through a private client. The Shopify report
    shows all of them reporting a clean zero on the same blocked endpoints, so fixing only the three
    that own a `get()` helper would leave five engines lying."""
    reg, _log = _registry(monkeypatch, _drops_payloads)
    _run(reg._run_sqli({"url": URL_A}))          # first host's evidence
    res = _run(reg._run_xpath({"url": URL_B}))   # second, unrelated
    assert res.success is False, res
    assert "INTERCEPTED UPSTREAM" in res.output, res.output


def test_no_island_every_injection_engine_consults_the_verdict():
    """A `middlebox.py` nothing calls is a failed ticket, not a partial one. `ToolRegistry.execute`
    dispatches by `getattr(self, "_" + tool_name)`, so this walks the engines themselves."""
    for name in INJECTION_ENGINES:
        src = inspect.getsource(getattr(tools_mod.ToolRegistry, name))
        assert "_middlebox_note()" in src, name
        assert "not _mb" in src, name             # success=False, so the ledger sees it


def test_no_island_the_transports_feed_the_ledger():
    """The verdict is only as real as its inputs. These are the two choke points where a dropped
    probe used to become a clean zero."""
    for name in ("_run_sqli", "_run_nosqli", "_run_cmdi", "_http"):
        src = inspect.getsource(getattr(tools_mod.ToolRegistry, name))
        assert "_mb_observe" in src, name


@pytest.mark.parametrize("method", ["_mb_observe", "_mb_ledger"])
def test_the_recorder_is_not_wrapped_in_a_silent_swallow(method):
    """Q-112's own trap: a `try/except: pass` around the recorder for silent failures would be a
    silent failure inside the fix for silent failures -- the exact mistake that has been made twice
    while fixing silent swallows. `Ledger.record` is total instead, so no handler is needed.

    Structural (an AST walk), not a substring match: the first cut of this test matched the word
    `except` inside the method's own docstring, which is a test that fails on prose."""
    import ast
    import textwrap
    tree = ast.parse(textwrap.dedent(inspect.getsource(getattr(tools_mod.ToolRegistry, method))))
    assert not [n for n in ast.walk(tree) if isinstance(n, (ast.Try, ast.ExceptHandler))], method


def test_a_middlebox_verdict_is_durable_in_the_mission_log(monkeypatch):
    """An engine that finished BEFORE the second host made the pattern visible still reported a
    clean zero, and no later edit can change a row already written. The mission-level row is what
    tells the operator the run's injection results are void."""
    reg, _log = _registry(monkeypatch, _drops_payloads, mid="q112log")
    _run(reg._run_sqli({"url": URL_A}))
    _run(reg._run_sqli({"url": URL_B}))
    rows = [r for r in dbmod.get_logs("q112log") if r.get("type") == "tool_error"]
    hits = [r for r in rows if "INTERCEPTED UPSTREAM" in str(r)]
    assert hits, rows[:5]
