"""Probe SHAPES for OS command injection, and the negative control for each.

The shipping payloads all APPEND to the observed value (`<v>; echo ...`). That shape assumes the
value lands inside a string a shell will parse. It is wrong for the other common sink:

    Runtime.exec(cmd)  /  execve(argv)      -- the string is tokenised and run as argv DIRECTLY

There is no shell there, so `;` is just another argv word and no metacharacter payload can ever
execute. The shape that works on an argv sink REPLACES the value with a bare command.

Every shape below is paired with the control that must NOT confirm it, because a probe shape without
a negative control is how this codebase previously shipped an oracle that confirmed on reflection.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cmdi_tool as cmdi  # noqa: E402


# ── argv-sink output payloads ────────────────────────────────────
def test_argv_payloads_replace_the_value_they_do_not_append():
    """The whole point of the shape: an argv sink is destroyed by a prefix."""
    for item in cmdi.argv_payloads("8.8.8.8"):
        assert not item["payload"].startswith("8.8.8.8"), item
        assert "8.8.8.8" not in item["payload"], item


def test_argv_payloads_are_read_only_commands():
    """No-DoS / non-destructive: the shape proves execution, it never changes state."""
    for item in cmdi.argv_payloads(""):
        head = item["payload"].split()[0]
        assert head in {"id", "cat", "uname"}, item


def test_argv_proof_strings_are_absent_from_the_payloads():
    """THE control that makes the shape reflection-immune.

    `id` proves execution through `uid=0(root) gid=0(root)`, which the payload `id` does not
    contain. An endpoint that merely echoes the payload therefore cannot satisfy the oracle -- the
    same property that makes the computed-echo marker safe."""
    for item in cmdi.argv_payloads("x"):
        assert cmdi.analyze_output("", item["payload"]) is None, item


def test_argv_output_confirms_only_on_real_command_output():
    body = "<p>Here is the standard output of the command:<br>uid=0(root) gid=0(root) groups=0(root)"
    assert cmdi.analyze_output("home page", body)["kind"] == "command-output"
    # already present in the baseline -> not caused by us -> not a finding
    assert cmdi.analyze_output(body, body) is None


def test_argv_bare_noncommand_is_the_negative_control():
    """A bare value that is not a command must produce nothing, however the app renders it."""
    for echoed in ("zqnotacmd", "you sent: zqnotacmd", "Cannot run program \"zqnotacmd\""):
        assert cmdi.analyze_output("baseline", echoed) is None


# ── argv-sink time payloads ──────────────────────────────────────
def test_argv_time_payloads_pair_every_probe_with_a_zero_delay_control():
    items = cmdi.argv_time_payloads(5)
    assert items, "argv time shape must exist"
    for item in items:
        assert "control" in item and "payload" in item
        # the control is the SAME command with the delay removed -- a trigger-removed differential
        assert item["control"] != item["payload"]
        assert not item["payload"].startswith(("&", ";", "|", "`", "$"))


def test_argv_time_control_is_the_same_command_with_the_delay_removed():
    for item in cmdi.argv_time_payloads(7):
        assert item["payload"].split()[0] == item["control"].split()[0]


def test_time_oracle_declines_a_uniformly_slow_endpoint():
    """An endpoint slow for EVERY input must not confirm -- the control is compared, not assumed."""
    assert cmdi.analyze_time(4.9, 5.1, 5) is False      # both slow: no differential
    assert cmdi.analyze_time(0.1, 0.4, 5) is False      # no delay at all
    assert cmdi.analyze_time(0.1, 5.3, 5) is True       # real injected delay


# ── argv-sink OOB payloads ───────────────────────────────────────
def test_argv_oob_payloads_are_bare_and_carry_the_probe_url():
    probe = "http://agent:8000/oob/deadbeef"
    payloads = cmdi.argv_oob_payloads(probe)
    assert payloads
    for p in payloads:
        assert p.startswith(("curl", "wget")), p
        assert probe in p
        # bare: no shell separator, because an argv sink never parses one
        assert not any(sep in p for sep in (";", "|", "`", "$(", "&"))


def test_argv_oob_payloads_do_not_prefix_an_observed_value():
    probe = "http://agent:8000/oob/deadbeef"
    for p in cmdi.argv_oob_payloads(probe):
        assert not p.startswith("8.8.8.8")


# ── the append shape must keep working; this is additive ─────────
def test_append_shape_is_unchanged():
    items = cmdi.output_payloads("8.8.8.8")
    assert all(i["payload"].startswith("8.8.8.8") for i in items)
    assert cmdi.EXPECTED not in "".join(i["payload"] for i in items)


# ── WIRING: the shape must be REACHED by the engine, not merely defined ──
# A registered payload that no code path sends is an island, and a guard that checks the declaration
# instead of the fact passes exactly the case it exists to catch. These drive the real engine.
def _new_reg(host="host.local"):
    import scope as scope_mod
    from tools import ToolRegistry
    eng = scope_mod.ScopeEngine()
    eng.load_manual([host], [], "P")
    return ToolRegistry(eng, mission_id=None, lab_mode=True)


def _run_form_cmdi(responder, fields=("host",), reg=None, url="http://host.local/exec",
                   delay=None, clock=None):
    """Drive the shipping _run_form_cmdi against a stubbed transport.

    `responder(value)` is the app: it gets the value the engine put in the field and returns a body.
    `delay(value)` optionally returns how many VIRTUAL seconds that request took -- the caller
    installs a fake perf_counter so a 5s timing probe costs the test nothing."""
    import asyncio
    from urllib.parse import parse_qsl

    from urllib.parse import urlparse as _up
    reg = reg or _new_reg(_up(url).hostname or "host.local")
    sent = []

    async def fake_http(u, method="GET", headers=None, body="", capture=False, **kw):
        val = dict(parse_qsl(body or "", keep_blank_values=True)).get(fields[0], "")
        if headers:
            for k, v in headers.items():
                if k.lower() not in ("content-type",):
                    val = v
        sent.append(val)
        if delay is not None and clock is not None:
            clock[0] += delay(val)
        return {"status": 200, "body": responder(val), "error": "", "final_url": u}

    reg._http = fake_http
    res = asyncio.new_event_loop().run_until_complete(
        reg._run_form_cmdi({"url": url, "fields": list(fields)}))
    return res, sent, reg


def test_engine_reaches_the_argv_shape_on_a_sink_no_separator_can_touch():
    """An argv sink: it runs argv[0] and echoes anything it cannot run.

    The append payloads reflect and must NOT confirm; the bare argv payload must."""
    def argv_sink(value):
        if value.strip() == "id":
            return "<p>uid=0(root) gid=0(root) groups=0(root)</p>"
        return "<p>you sent: %s</p>" % value            # pure reflection for everything else

    res, sent, _ = _run_form_cmdi(argv_sink)
    assert "id" in sent, "engine never sent a bare argv payload: the shape is an island"
    assert res.findings, "argv sink went undetected"
    f = res.findings[0]
    assert f["family"] == "cmdi" and f["confidence"] == "confirmed"
    assert "argv" in " ".join(f["tags"])


def test_engine_does_not_confirm_on_an_endpoint_that_only_reflects():
    """THE negative control for the whole shape. An app that echoes every value, including the bare
    commands, executes nothing -- and must produce no finding."""
    res, sent, _ = _run_form_cmdi(lambda value: "<p>you sent: %s</p>" % value)
    assert "id" in sent, "control is vacuous unless the argv payload was actually sent"
    assert res.findings == [], "confirmed on reflection alone: %r" % (res.findings,)


def test_engine_still_confirms_the_shell_sink_through_the_append_shape():
    """Additive, not a replacement: a real shell sink must still be caught by the old shape."""
    def shell_sink(value):
        if "echo" in value and "$((" in value:
            return "<p>%s</p>" % cmdi.EXPECTED       # the shell computed the product
        return "<p>you sent: %s</p>" % value

    res, _s, _ = _run_form_cmdi(shell_sink)
    assert res.findings and res.findings[0]["family"] == "cmdi"
    assert "argv" not in " ".join(res.findings[0]["tags"])


def test_findings_name_the_shape_that_proved_it():
    f = cmdi.argv_output_finding("https://t/p", "host", "id",
                                 {"kind": "command-output", "match": "uid=0(root) gid=0"})
    assert f["family"] == "cmdi"
    assert f["confidence"] == "confirmed"
    assert f["cwe"] == "CWE-78"
    assert "argv" in " ".join(f["tags"])


# ── BLIND / TIME: the latch, the budget, and the controls ────────
def _fake_clock(monkeypatch):
    """A virtual perf_counter so a 5s timing probe costs the test nothing."""
    import time as _t
    clock = [0.0]
    monkeypatch.setattr(_t, "perf_counter", lambda: clock[0])
    return clock


def _reflect(value):
    return "<p>you sent: %s</p>" % value


def test_timing_shape_is_latched_PER_ENDPOINT_not_once_per_process(monkeypatch):
    """The defect this replaces: the latch was a flag on the registry, so a caller driving many
    endpoints through one registry got the blind shape on the FIRST endpoint and silence after."""
    clock = _fake_clock(monkeypatch)
    reg = _new_reg()
    seen = []
    for n in (1, 2, 3):
        _, sent, reg = _run_form_cmdi(_reflect, reg=reg, url="http://host.local/exec%d" % n,
                                      delay=lambda v: 0.01, clock=clock)
        seen.append(any("sleep" in s for s in sent))
    assert seen == [True, True, True], (
        "blind shape ran on %r of three distinct endpoints" % (seen,))


def test_timing_budget_is_bounded_so_no_dos(monkeypatch):
    """The bound the old flag was protecting is kept: a form-heavy crawl cannot fill with sleeps."""
    clock = _fake_clock(monkeypatch)
    reg = _new_reg()
    reg._timing_cmdi_budget = 2
    ran = []
    for n in range(5):
        _, sent, reg = _run_form_cmdi(_reflect, reg=reg, url="http://host.local/e%d" % n,
                                      delay=lambda v: 0.01, clock=clock)
        ran.append(any("sleep" in s for s in sent))
    assert ran == [True, True, False, False, False], ran


def test_same_endpoint_is_only_timed_once(monkeypatch):
    clock = _fake_clock(monkeypatch)
    reg = _new_reg()
    first = _run_form_cmdi(_reflect, reg=reg, delay=lambda v: 0.01, clock=clock)[1]
    second = _run_form_cmdi(_reflect, reg=reg, delay=lambda v: 0.01, clock=clock)[1]
    assert any("sleep" in s for s in first)
    assert not any("sleep" in s for s in second), "re-timed an endpoint already probed"


def test_uniformly_slow_endpoint_does_not_confirm(monkeypatch):
    """NEGATIVE CONTROL. Every request takes 6s, including the zero-delay control. There is no
    differential, so there is no finding."""
    clock = _fake_clock(monkeypatch)
    res, sent, _ = _run_form_cmdi(_reflect, delay=lambda v: 6.0, clock=clock)
    assert any("sleep" in s for s in sent), "control is vacuous unless a timing probe was sent"
    assert res.findings == [], "confirmed on an endpoint that is slow for every input"


def test_one_off_slow_response_does_not_confirm(monkeypatch):
    """NEGATIVE CONTROL. The delay appears once and does not reproduce; a coincidence under load
    must not become a critical finding."""
    clock = _fake_clock(monkeypatch)
    state = {"n": 0}

    def flaky(value):
        if "sleep" in value and "sleep 0" not in value:
            state["n"] += 1
            return 6.0 if state["n"] == 1 else 0.01     # slow exactly once
        return 0.01

    res, sent, _ = _run_form_cmdi(_reflect, delay=flaky, clock=clock)
    assert state["n"] >= 2, "the repeat probe was never sent"
    assert res.findings == [], "confirmed on a delay that did not reproduce"


def test_real_blind_sink_confirms_through_the_time_shape(monkeypatch):
    """The positive: a sink that sleeps whenever a real delay is injected, twice over."""
    clock = _fake_clock(monkeypatch)

    def sleeps(value):
        v = value.strip()
        if v.startswith("sleep ") and v != "sleep 0":
            return 6.0
        return 0.01

    res, _s, _ = _run_form_cmdi(_reflect, delay=sleeps, clock=clock)
    assert res.findings, "blind argv sink went undetected"
    assert res.findings[0]["family"] == "cmdi"
    assert "time" in " ".join(res.findings[0]["tags"])


# ── OOB: the callback is the only evidence ───────────────────────
_OOB_URL = "http://10.0.0.5/exec"   # an in-network target: the collaborator base is in-network too,
                                   # and reachable_from() correctly refuses the mismatched pairing


def _oob_env(monkeypatch):
    import collaborator as collab
    monkeypatch.setenv("BBH_OOB_BASE", "http://agent:8000")
    monkeypatch.setenv("BBH_OOB_DOMAIN", "")
    monkeypatch.setattr("asyncio.sleep", _instant_sleep)
    return collab


async def _instant_sleep(_secs):
    return None


def test_form_engine_sends_oob_probes(monkeypatch):
    """WIRING. _run_cmdi has had an OOB path all along; the form/header engine never did, so a
    blind body-parameter sink was invisible to the product."""
    _oob_env(monkeypatch)
    _, sent, _ = _run_form_cmdi(_reflect, url=_OOB_URL)
    assert any("/oob/" in s for s in sent), "form engine never sent an OOB probe"
    assert any(s.strip().startswith(("curl", "wget")) for s in sent), "no bare argv OOB probe"


def test_oob_callback_that_never_arrives_is_a_non_detection(monkeypatch):
    """NEGATIVE CONTROL. No interaction is recorded, so nothing may be reported -- a timeout is
    never a timeout-flavoured confirmation."""
    _oob_env(monkeypatch)
    res, sent, _ = _run_form_cmdi(_reflect, url=_OOB_URL)
    assert any("/oob/" in s for s in sent), "control is vacuous unless a probe was sent"
    assert res.findings == [], "reported an OOB finding with no callback"


def test_oob_confirms_when_the_target_actually_calls_back(monkeypatch):
    """The positive: the stub app 'runs' the fetch, which records an interaction for that token."""
    collab = _oob_env(monkeypatch)

    def calls_back(value):
        if "/oob/" in value:
            token = value.split("/oob/")[1].split()[0].strip("/")
            collab.record(token, {"source_ip": "10.0.0.9", "method": "GET",
                                  "path": "/oob/" + token, "host": "agent", "ua": "wget"})
        return _reflect(value)

    res, _s, _ = _run_form_cmdi(calls_back, url=_OOB_URL)
    assert res.findings, "OOB callback arrived and nothing was reported"
    f = res.findings[0]
    assert f["family"] == "cmdi" and f["confidence"] == "confirmed"
    assert "oob" in " ".join(f["tags"])
    assert "10.0.0.9" in f["evidence"]


# ── XSS: the request-header carrier ──────────────────────────────
# Same delivery gap the cmdi engine already closed. The ORACLE is not touched: xss_tool's breakout
# analysis decides exploitability, so a correctly-encoded reflection still cannot confirm.
def _run_xss(responder, url="http://host.local/p?q=1", page=""):
    """Drive the shipping _run_xss. `responder(headers, url)` returns the body."""
    import asyncio

    import httpx
    reg = _new_reg()

    async def fake_http(u, method="GET", headers=None, body="", capture=False, **kw):
        return {"status": 200, "body": page, "error": "", "final_url": u}

    reg._http = fake_http
    reg._discover_params = lambda _u: _empty_list()
    reg._xss_execute = lambda _u, _p: _empty_list()

    class _Resp:
        def __init__(self, text):
            self.text = text

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, u, headers=None, **kw):
            return _Resp(responder(headers or {}, u))

    orig = httpx.AsyncClient
    httpx.AsyncClient = lambda **kw: _Client()
    try:
        return asyncio.new_event_loop().run_until_complete(reg._run_xss({"url": url}))
    finally:
        httpx.AsyncClient = orig


async def _empty_list():
    return []


_HDR_PAGE = ('<html><body><input type="button" method="submitHeaderForm" testcase="X-Trace-Id">'
             '</body></html>')


def test_xss_reaches_a_reflection_that_only_arrives_in_a_request_header():
    """The gap: the query loop rewrites the URL and nothing else, so a header-carried reflection is
    invisible -- the canary never arrives and the endpoint reads clean."""
    def app(headers, _u):
        v = headers.get("X-Trace-Id", "")
        return "<html><body><div>hello %s</div></body></html>" % v      # raw, unencoded

    res = _run_xss(app, page=_HDR_PAGE)
    assert res.findings, "header-carried XSS went undetected"
    assert any("header" in f["title"] for f in res.findings), [f["title"] for f in res.findings]


def test_xss_header_carrier_declines_a_correctly_encoded_reflection():
    """NEGATIVE CONTROL, and the one that matters: the value reflects, but encoded for its context.
    Reflection alone must never confirm -- that defect is what a previous oracle shipped."""
    import html as _html

    def safe_app(headers, _u):
        v = _html.escape(headers.get("X-Trace-Id", ""), quote=True)
        return "<html><body><div>hello %s</div></body></html>" % v

    res = _run_xss(safe_app, page=_HDR_PAGE)
    assert res.findings == [], "confirmed on a correctly-encoded reflection: %r" % (res.findings,)


def test_xss_header_carrier_declines_an_endpoint_that_reflects_nothing():
    res = _run_xss(lambda headers, _u: "<html><body>static</body></html>", page=_HDR_PAGE)
    assert res.findings == []
