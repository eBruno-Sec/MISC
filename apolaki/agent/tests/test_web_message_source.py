"""Q-003 -- `postMessage` as a DOM source (CWE-346 -> CWE-79), WSTG-CLNT-11: the PURE half.

EVERY FIXTURE IN THIS FILE WAS FETCHED FROM A LIVE SOURCE AND PASTED, NOT WRITTEN FROM MEMORY.
Four defects in this project came from invented fixtures making vacuous tests pass, so each constant
below carries the URL it was copied from and the date, and the negatives are real libraries that a
naive scanner really does misreport.

The four NEGATIVES are the point of the file. `onmessage` and `"message"` listeners are everywhere in
production JavaScript and almost none of them are web-message handlers:

  * Juice Shop's ONLY `onmessage` is socket.io's WebSocket transport.
  * React's scheduler drives its work loop through a MessageChannel port -- and it even calls
    `postMessage`, so a scanner keying on that verb reports React itself.
  * iframe-resizer registers a genuine window handler but reaches no sink, so it must be SEEN and
    then NOT reported.

A detector that cannot tell those apart produces a finding on every SPA on the internet.
"""
import pytest

import dom_tool as dom
import proof_schema


# ── VULNERABLE, copied verbatim ────────────────────────────────────────────────────────────────
# https://portswigger.net/web-security/dom-based/controlling-the-web-message-source (fetched
# 2026-08-18). PortSwigger's own example of the base case: no origin verification, eval() sink.
PS_NO_ORIGIN = """window.addEventListener('message', function(e) {
  eval(e.data);
});"""

# Same page, "Origin verification" section. PortSwigger's words for why this is still vulnerable:
# indexOf "only checks whether the string ... is contained anywhere in the origin URL", so
# http://www.normal-website.com.evil.net passes.
PS_WEAK_INDEXOF = """window.addEventListener('message', function(e) {
    if (e.origin.indexOf('normal-website.com') > -1) {
        eval(e.data);
    }
});"""

# Same page: the endsWith variant, which treats http://www.malicious-websitenormal-website.com as safe.
PS_WEAK_ENDSWITH = """window.addEventListener('message', function(e) {
    if (e.origin.endsWith('normal-website.com')) {
        eval(e.data);
    }
});"""

# ── SAFE, copied verbatim ──────────────────────────────────────────────────────────────────────
# https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage (fetched 2026-08-18), the
# "dispatched event" section -- MDN's recommended equality check with an early return.
MDN_STRICT = """window.addEventListener("message", (event) => {
  if (event.origin !== "http://example.org:8080") return;

  // ...
});"""

# ── NEGATIVES: real production code a naive scanner misreports ─────────────────────────────────
# http://127.0.0.1:42000/main.js (the running Juice Shop lab, fetched 2026-08-18). This is the ONLY
# `onmessage` in the entire 783,793-byte bundle, and it is socket.io's WebSocket transport. A
# `postMessage` to the window can never reach it.
JUICE_SHOP_WS = ("""this.ws.binaryType=this.socket.binaryType||aC,this.addEventListeners()}"""
                 """addEventListeners(){let a=this;this.ws.onopen=function(){a.onOpen()},"""
                 """this.ws.onclose=function(){a.onClose()},this.ws.onmessage=function(e){"""
                 """a.onData(e.data)},this.ws.onerror=function(e){a.onError("websocket error",e)}}""")

# https://ginandjuice.shop/resources/js/react.development.js (fetched 2026-08-18), the scheduler's
# host-callback path. Note the `port.postMessage(null)` two lines down: a scanner keying on the verb
# `postMessage` reports React on every page that ships it.
REACT_MESSAGE_CHANNEL = """  } else if (typeof MessageChannel !== 'undefined') {
    // DOM and Worker environments.
    // We prefer MessageChannel because of the 4ms setTimeout clamping.
    var channel = new MessageChannel();
    var port = channel.port2;
    channel.port1.onmessage = performWorkUntilDeadline;

    schedulePerformWorkUntilDeadline = function () {
      port.postMessage(null);
    };
  } else {"""

# https://cdn.jsdelivr.net/npm/iframe-resizer@4.3.9/js/iframeResizer.js (fetched 2026-08-18).
# A REAL window message listener registered through the library's own 3-argument wrapper. It is a
# true positive for DETECTION and a true negative for REPORTING: the handler reaches no sink.
IFRAME_RESIZER = """  function addEventListener(el, evt, func) {
    el.addEventListener(evt, func, false)
  }

  function iFrameListener(event) {
    function checkAllowedOrigin() {
      function checkList() {
        for (; i < checkOrigin.length; i++) {
          if (checkOrigin[i] === origin) {
            retCode = true
            break
          }
        }
        return retCode
      }
      function checkSingle() {
        var remoteHost = settings[iframeId] && settings[iframeId].remoteHost
        return origin === remoteHost
      }
      return checkOrigin.constructor === Array ? checkList() : checkSingle()
    }

    var origin = event.origin,
      checkOrigin = settings[iframeId] && settings[iframeId].checkOrigin

    if (checkOrigin && '' + origin !== 'null' && !checkAllowedOrigin()) {
      throw new Error('Unexpected message received from: ' + origin)
    }

    return true
  }

  addEventListener(window, 'message', iFrameListener)
"""

# The JSON.parse shape. PROVENANCE IS DIFFERENT AND IS STATED RATHER THAN GLOSSED: PortSwigger's lab
# page https://portswigger.net/web-security/dom-based/controlling-the-web-message-source/
# lab-dom-xss-using-web-messages-and-json-parse (fetched 2026-08-18) does not publish the handler
# source, only its behaviour -- "the event listener expects a `type` property and ... the
# `load-channel` case of the `switch` statement changes the `iframe src` attribute". This fixture is
# written to that description. What IS verbatim from that page is the exploit it documents:
#     this.contentWindow.postMessage("{\\"type\\":\\"load-channel\\",\\"url\\":\\"javascript:print()\\"}","*")
# which is why `wm_payloads` has to emit a JSON body carrying BOTH the literal gate and the property.
JSON_PARSE_SHAPE = """window.addEventListener('message', function(e){
    var iframe = document.createElement('iframe'), ACMEplayer = {element: iframe}, d;
    document.body.appendChild(iframe);
    try { d = JSON.parse(e.data); } catch(e) { return; }
    switch(d.type) {
        case "page-load":
            ACMEplayer.element.scrollIntoView();
            break;
        case "load-channel":
            ACMEplayer.element.src = d.url;
            break;
    }
});"""

INNERHTML_SHAPE = """window.addEventListener('message', function(e) {
    document.getElementById('ads').innerHTML = e.data;
});"""


def _one(js):
    recs = dom.find_message_listeners(js, source="fixture.js")
    assert len(recs) == 1, "expected exactly one window message listener, got %d" % len(recs)
    return recs[0]


# ══ detection ══════════════════════════════════════════════════════════════════════════════════
def test_portswigger_no_origin_check_is_detected_with_its_sink():
    rec = _one(PS_NO_ORIGIN)
    assert rec["receiver"] == "window"
    assert rec["registration"] == "addEventListener"
    assert rec["reads_data"] is True
    assert "eval" in rec["sinks"]
    assert dom.wm_reportable(rec) is True


def test_iframe_resizer_wrapper_form_is_detected():
    """The 3-argument wrapper `addEventListener(window, 'message', fn)`.

    MEASURED before the fix on the real 38,291-byte jsDelivr build: 0 listeners AND
    `wm_scan_hint` False, so the page would never have been loaded in a browser either. A real
    library on millions of pages was invisible to both rungs of the ladder.
    """
    rec = _one(IFRAME_RESIZER)
    assert rec["receiver"] == "window"
    assert rec["resolved"] is True, "the named handler `iFrameListener` must resolve to its body"
    assert "checkAllowedOrigin" in rec["handler"], "resolved the wrong function body"


def test_named_handler_reference_is_resolved_not_guessed():
    js = """function handleMsg(e) { document.body.innerHTML = e.data; }
window.addEventListener('message', handleMsg, false);"""
    rec = _one(js)
    assert rec["resolved"] is True
    assert "innerHTML" in rec["sinks"]


def test_unresolvable_handler_is_marked_unresolved_rather_than_analysed():
    """A handler we never read must not be given an analysis. `resolved` False and no sinks is the
    honest answer; inventing "no sinks found => safe" from an unread body is the falsy-default
    failure this codebase has been bitten by repeatedly."""
    js = "window.addEventListener('message', someModule.handlers.onMessage);"
    rec = _one(js)
    assert rec["resolved"] is False
    assert rec["sinks"] == []
    assert dom.wm_reportable(rec) is False


# ══ the negatives: real libraries a naive scanner misreports ═══════════════════════════════════
@pytest.mark.parametrize("name,js", [
    ("juice_shop_websocket", JUICE_SHOP_WS),
    ("react_message_channel", REACT_MESSAGE_CHANNEL),
])
def test_non_window_message_transports_are_not_web_message_listeners(name, js):
    assert dom.find_message_listeners(js, source=name) == [], (
        "%s is a WebSocket/MessagePort transport; postMessage to the window cannot reach it" % name)


def test_the_negative_fixtures_do_contain_the_token_that_would_fool_a_naive_scanner():
    """POSITIVE CONTROL ON THE NEGATIVES. Two empty lists above prove nothing unless the fixtures
    really do carry the bait -- otherwise the test passes because the strings are inert."""
    assert "onmessage" in JUICE_SHOP_WS
    assert "onmessage" in REACT_MESSAGE_CHANNEL
    assert "postMessage" in REACT_MESSAGE_CHANNEL
    assert dom.wm_scan_hint(JUICE_SHOP_WS) is True
    assert dom.wm_scan_hint(REACT_MESSAGE_CHANNEL) is True


def test_iframe_resizer_is_seen_but_not_reported():
    """Detection and reporting are different questions. iframe-resizer registers a real window
    handler, so it must be SEEN; its handler reaches no sink, so it must NOT be reported."""
    rec = _one(IFRAME_RESIZER)
    assert rec["sinks"] == []
    assert dom.wm_reportable(rec) is False


def test_handler_that_never_reads_event_data_is_not_reportable():
    """NEGATIVE CONTROL on the source->sink rule: a sink in the handler is not enough; the handler
    has to carry the ATTACKER's value into it."""
    js = """window.addEventListener('message', function(e) {
        document.getElementById('status').innerHTML = 'a message arrived';
    });"""
    rec = _one(js)
    assert "innerHTML" in rec["sinks"], "the sink must still be seen"
    assert rec["reads_data"] is False
    assert dom.wm_reportable(rec) is False


def test_scan_hint_is_false_on_a_page_with_no_message_listener_at_all():
    """The cheap gate is deliberately loose, but it is not stuck on."""
    assert dom.wm_scan_hint("") is False
    assert dom.wm_scan_hint("<html><body><h1>hello</h1></body></html>") is False
    assert dom.wm_scan_hint("el.addEventListener('click', go); ws.send('message')") is False


# ══ origin grading ═════════════════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("name,js,grade", [
    ("portswigger_none", PS_NO_ORIGIN, "none"),
    ("portswigger_indexOf", PS_WEAK_INDEXOF, "weak"),
    ("portswigger_endsWith", PS_WEAK_ENDSWITH, "weak"),
    ("mdn_strict_equality", MDN_STRICT, "strict"),
])
def test_origin_validation_is_graded_three_ways(name, js, grade):
    """Reporting a handler that validates its origin identically to one that does not is the noise
    that makes a report worthless. All four fixtures are published code from the two canonical
    sources for this vulnerability class."""
    assert dom.find_message_listeners(js)[0]["origin_check"] == grade


def test_allowlist_membership_grades_strict_and_substring_test_does_not():
    """The distinction is WHICH SIDE the origin is on. `ALLOWED.includes(e.origin)` is exact
    membership; `e.origin.includes(ALLOWED)` is a substring test an attacker origin satisfies."""
    strict = """window.addEventListener('message', function(e) {
        if (["https://a.example","https://b.example"].includes(e.origin)) { eval(e.data); }
    });"""
    weak = """window.addEventListener('message', function(e) {
        if (e.origin.includes('a.example')) { eval(e.data); }
    });"""
    assert dom.find_message_listeners(strict)[0]["origin_check"] == "strict"
    assert dom.find_message_listeners(weak)[0]["origin_check"] == "weak"


def test_origin_referenced_but_never_compared_grades_weak_not_strict():
    """Silence about how a value is used is not evidence that it gates anything. Logging the origin
    is not validating it, and grading it `strict` would suppress a real finding."""
    js = """window.addEventListener('message', function(e) {
        console.log('message from ' + e.origin);
        document.body.innerHTML = e.data;
    });"""
    assert dom.find_message_listeners(js)[0]["origin_check"] == "weak"


# ══ payloads: shaped by the handler, not by a wordlist ═════════════════════════════════════════
def test_payloads_follow_the_sinks_the_handler_actually_reaches():
    ev = dom.wm_payloads(_one(PS_NO_ORIGIN))
    labels = {p["label"] for p in ev}
    assert "js" in labels, "an eval() sink needs a raw-JS payload"
    assert "html" not in labels, "markup into eval() is wasted budget"

    html = dom.wm_payloads(_one(INNERHTML_SHAPE))
    hlabels = {p["label"] for p in html}
    assert "html" in hlabels
    assert "js" not in hlabels


def test_json_parse_handler_yields_a_payload_carrying_both_the_gate_and_the_property():
    """The lab PortSwigger documents needs {"type":"load-channel","url":"javascript:..."}. Both the
    gate literal and the property name are READ OFF the handler; neither is guessed."""
    rec = _one(JSON_PARSE_SHAPE)
    assert rec["gates"].get("type") == "load-channel", rec["gates"]
    assert "url" in rec["props"], rec["props"]
    assert "element.src" in rec["sinks"]

    bodies = [p["value"] for p in dom.wm_payloads(rec) if p["kind"] == "json"]
    hit = [b for b in bodies
           if b.get("type") == "load-channel" and str(b.get("url", "")).startswith("javascript:")]
    assert hit, "no payload reproduced the documented {type: load-channel, url: javascript:...} shape"
    assert dom.WM_MARK in hit[0]["url"], "the payload must carry the canary that proves execution"


def test_the_property_that_flows_into_the_sink_outranks_the_sink_s_own_property():
    """`ACMEplayer.element.src = d.url` -- `url` carries attacker data, `src` is the sink's own name.

    MEASURED before the fix: sink-proximity ranking alone put `src` first, so the first probes set a
    property the handler never reads and the engine would report clean on a page it was looking
    straight at. This is the "probe with an invented value" failure in a different costume.
    """
    props = _one(JSON_PARSE_SHAPE)["props"]
    assert props.index("url") < props.index("src"), props


def test_a_structured_handler_gets_its_structured_payloads_before_the_cap():
    """ORDER IS LOAD-BEARING. `try { JSON.parse(e.data) } catch { return }` discards every plain
    string, so for that handler the strings are the waste. MEASURED before the fix: the one payload
    reproducing the documented exploit sat at index 10 of a list capped at 10."""
    small = dom.wm_payloads(_one(JSON_PARSE_SHAPE), cap=4)
    assert all(p["kind"] in ("json", "object") for p in small), [p["label"] for p in small]

    # ...and the reverse holds: a plain `eval(e.data)` handler must not have its string payload
    # pushed out by speculative structured ones.
    plain = dom.wm_payloads(_one(PS_NO_ORIGIN), cap=2)
    assert plain[0]["kind"] == "string"


def test_payloads_are_bounded_and_deduplicated():
    p = dom.wm_payloads(_one(JSON_PARSE_SHAPE), cap=6)
    assert len(p) <= 6
    assert len({(x["kind"], repr(x["value"])) for x in p}) == len(p)


# ══ the oracle ═════════════════════════════════════════════════════════════════════════════════
def test_confirmation_requires_the_web_message_canary():
    assert dom.confirmed_wm('alert fired: %s' % dom.WM_MARK) is True
    assert dom.confirmed_wm("") is False
    assert dom.confirmed_wm(None) is False
    assert dom.confirmed_wm("some other alert") is False


def test_web_message_canary_is_distinct_from_the_url_source_canary():
    """A hash-sourced DOM XSS confirmation must never be re-attributed to the message source."""
    assert dom.WM_MARK != dom.MARK
    assert dom.confirmed_wm(dom.MARK) is False


def test_nav_family_needs_a_real_navigation_to_the_attacker_host():
    """Host-parse discipline, the same false positive `confirmed_redirect` already documents: our
    own probe URL mentions the attacker host, and a substring test would confirm on the initial
    same-origin load."""
    own = "http://target.example/page#https://%s/" % dom.EVIL
    assert dom.wm_family("nav", navs=[own]) == ""
    assert dom.wm_family("nav", navs=["https://%s/x" % dom.EVIL]) == "open_redirect"
    assert dom.wm_family("exec", navs=["https://%s/x" % dom.EVIL]) == "", \
        "an exec payload is confirmed by execution, never by a navigation"
    assert dom.wm_family("nav", dialog_msg="alert %s" % dom.WM_MARK) == "dom_xss"


def test_nothing_fired_confirms_nothing():
    assert dom.wm_family("exec", dialog_msg=None, navs=[]) == ""
    assert dom.wm_family("nav", dialog_msg="", navs=[]) == ""


# ══ findings: the grading gate ═════════════════════════════════════════════════════════════════
def test_static_detection_produces_a_LEAD_and_never_a_confirmation():
    """THE RULE THIS TICKET TURNS ON. A static match graded `confirmed` is the most expensive defect
    class in this platform, and `dom_tool._base` stamps `confirmed` on everything it touches -- so
    the lead builder deliberately does not go through it."""
    f = dom.wm_lead_finding("http://target.example/", _one(PS_NO_ORIGIN))
    assert f["confidence"] == "lead"
    assert f["confidence"] in proof_schema.UNPROVEN_CONFIDENCE
    assert proof_schema.is_confirmed(f) is False
    assert "NOT DRIVEN TO EXECUTION" in f["evidence"]
    assert f["cwe"] == "CWE-346"


def test_lead_names_the_origin_grade_so_two_handlers_do_not_read_alike():
    none_f = dom.wm_lead_finding("http://t.example/", _one(PS_NO_ORIGIN))
    weak_f = dom.wm_lead_finding("http://t.example/", _one(PS_WEAK_INDEXOF))
    assert "none" in none_f["title"] and "weak" in weak_f["title"]
    assert none_f["description"] != weak_f["description"]
    assert "NO check on event.origin" in none_f["description"]
    assert "substring/prefix" in weak_f["description"]


def test_confirmed_finding_is_proven_and_satisfies_the_proof_schema():
    rec = _one(PS_NO_ORIGIN)
    payload = dom.wm_payloads(rec)[0]
    f = dom.wm_finding("http://target.example/", rec, payload, "dom_xss",
                       control="Negative control: the same payload sent with targetOrigin "
                               "https://wrong.example did not fire.")
    assert f["confidence"] == "confirmed"
    assert f["cwe"] == "CWE-79"
    assert f["family"] == "dom_xss"
    ok, missing = proof_schema.validate_confirmed(f)
    assert ok, missing
    assert dom.WM_MARK in f["evidence"]
    assert "targetOrigin" in f["success_oracle"], "the negative control belongs in the oracle"


def test_confirmed_lead_and_redirect_findings_all_pass_the_proof_schema():
    rec = _one(JSON_PARSE_SHAPE)
    payload = [p for p in dom.wm_payloads(rec) if p["flavor"] == "nav"][0]
    for f in (dom.wm_lead_finding("http://t.example/", rec),
              dom.wm_finding("http://t.example/", rec, payload, "open_redirect"),
              dom.wm_finding("http://t.example/", rec, payload, "dom_xss")):
        ok, missing = proof_schema.validate_confirmed(f)
        assert ok, (f["title"], missing)
        assert f["target"] and f["severity"] and f["cvss_vector"]


def test_severity_never_contradicts_the_cvss_band():
    """The label can never contradict the score printed beside it (report_integrity_check)."""
    for f in (dom.wm_lead_finding("http://t.example/", _one(PS_NO_ORIGIN)),
              dom.wm_finding("http://t.example/", _one(PS_NO_ORIGIN),
                             dom.wm_payloads(_one(PS_NO_ORIGIN))[0], "dom_xss")):
        score = f["cvss_score"]
        band = ("critical" if score >= 9 else "high" if score >= 7
                else "medium" if score >= 4 else "low")
        assert f["severity"] == band, (f["title"], f["severity"], score)


# ===============================================================================================
# THE ENGINE HALF (run 2). Everything above tests pure functions; a green file of those is exactly
# what an ISLAND looks like, and this project has 32 engines that never executed across 151
# missions. These tests are about REACHABILITY and about the wiring's own behaviour.
# ===============================================================================================
import ast
import asyncio
import os

import tools as tools_mod

_AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: The whole web-message surface. `wm_origin_grade`, `wm_handler_facts` and `confirmed_wm` are
#: reached THROUGH the others, so they are listed separately from the entry points the engine calls.
_WM_ENTRY_POINTS = ("wm_scan_hint", "find_message_listeners", "wm_reportable", "wm_lead_finding",
                    "wm_payloads", "wm_family", "wm_finding")
_WM_INTERNAL = ("wm_origin_grade", "wm_handler_facts", "confirmed_wm")


def _called_identifiers(source: str) -> set:
    """Every name USED in code, read off the AST -- so comments and docstrings cannot count.

    Deliberately stricter than `deadcode_gate.scan_qualified`, which regex-matches the bare name
    anywhere in the defining module INCLUDING COMMENTS. Two of these helpers were invisible to the
    ratchet for exactly that reason: `find_message_listeners` and `wm_scan_hint` are named in an
    explanatory comment in `dom_tool.py`, so the gate counted them used while nothing called them.
    A comment describing what a function is for must never make that function look wired.
    """
    out = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Attribute):
            out.add(node.attr)
        elif isinstance(node, ast.Name):
            out.add(node.id)
    return out


def _src(name):
    return open(os.path.join(_AGENT_DIR, name), encoding="utf8").read()


def test_the_identifier_reader_ignores_comments_and_reads_calls():
    """POSITIVE AND NEGATIVE CONTROL for the apparatus the next tests depend on. Without it, a
    checker that silently returned an empty set would make every reachability claim below vacuous."""
    assert "wm_ghost" not in _called_identifiers("# wm_ghost is a great helper\nx = 1\n")
    assert "wm_ghost" not in _called_identifiers('"""wm_ghost does things."""\nx = 1\n')
    assert "wm_ghost" in _called_identifiers("y = wm_ghost(1)\n")
    assert "wm_ghost" in _called_identifiers("y = dom.wm_ghost(1)\n")


def test_every_web_message_entry_point_is_called_by_the_engine_not_just_defined():
    """NO ISLANDS, checked at the only level that matters: does `tools.py` actually call these?

    A test file calling them proves they are exercised, not that they are wired."""
    used = _called_identifiers(_src("tools.py"))
    missing = [n for n in _WM_ENTRY_POINTS if n not in used]
    assert not missing, ("web-message helpers nothing in tools.py calls: %s -- an island, which is "
                         "what this ticket exists to avoid" % missing)


def test_the_internal_helpers_are_reached_through_the_entry_points():
    """The three no engine calls directly must still be called by something that IS called."""
    used = _called_identifiers(_src("dom_tool.py"))
    missing = [n for n in _WM_INTERNAL if n not in used]
    assert not missing, "unreachable inside dom_tool.py: %s" % missing


def test_the_web_message_phase_is_dispatched_by_the_registered_engine():
    """REGISTRATION IS NOT INVOCATION. `_wm_audit` is reachable only because `_run_dom_audit` awaits
    it, and `run_dom_audit` is registered, dispatchable and deterministically fired."""
    body = None
    for node in ast.walk(ast.parse(_src("tools.py"))):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "_run_dom_audit":
            body = node
    assert body is not None, "_run_dom_audit not found"
    calls = {n.func.attr for n in ast.walk(body)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert "_wm_audit" in calls, "run_dom_audit does not call _wm_audit -- the phase is unreachable"
    assert "run_dom_audit" in tools_mod.TOOL_PERMISSIONS
    assert callable(getattr(tools_mod.ToolRegistry, "_run_dom_audit", None)), \
        "not dispatchable via getattr(self, '_' + tool_name)"
    assert any(t["name"] == "run_dom_audit" for t in tools_mod.CLAUDE_TOOLS), \
        "CLAUDE_TOOLS is a SECOND emitter and the engine must appear there too"


def test_the_engine_declares_the_tier_it_is_registered_at_on_both_surfaces():
    import description_gate as dg
    facts = dg.analyse(_src("tools.py"))
    assert facts.permissions["run_dom_audit"] == "ACTIVE"
    assert dg.declared_tiers(facts.docstrings["run_dom_audit"]) == ["ACTIVE"]
    assert dg.declared_tiers(facts.descriptions["run_dom_audit"]) == ["ACTIVE"]


# -- the static half of the phase, driven through the REAL method body --------------------------
class _StubScope:
    def __init__(self, allow=True):
        self.allow = allow

    def validate(self, u):
        return (self.allow, "")


class _Reg:
    """The smallest object `_wm_audit` needs. The METHOD ITSELF is the shipped one, taken off
    ToolRegistry, so these tests exercise production code rather than a copy of it."""
    _WM_MAX_RECORDS = tools_mod.ToolRegistry._WM_MAX_RECORDS
    _WM_MAX_PAYLOADS = tools_mod.ToolRegistry._WM_MAX_PAYLOADS
    _WM_SETTLE_MS = tools_mod.ToolRegistry._WM_SETTLE_MS
    _wm_audit = tools_mod.ToolRegistry._wm_audit

    def __init__(self, pages, confirm=None, allow=True):
        self.pages, self.confirm_impl = pages, confirm
        self.fetched, self.swallowed, self.confirm_calls = [], [], []
        self.scope = _StubScope(allow)

    async def _http(self, u, method="GET", capture=False):
        self.fetched.append(u)
        return {"body": self.pages.get(u, "")}

    def _swallow(self, exc, where, target=""):
        self.swallowed.append((where, str(exc)))

    async def _wm_confirm(self, browser, url, rec):
        self.confirm_calls.append(rec)
        return self.confirm_impl(url, rec) if self.confirm_impl else None


_BASE = "http://lab.local:8099/"
_JS = "http://lab.local:8099/app.js"
_HTML = '<!doctype html><html><body><script src="/app.js"></script></body></html>'


def _run(reg, url=_BASE):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(reg._wm_audit(None, url))
    finally:
        loop.close()


def test_a_vulnerable_handler_that_cannot_be_driven_is_reported_as_a_LEAD():
    """The grading bar. `_wm_confirm` returning None means nothing was observed firing, and an
    unobserved handler must never be graded `confirmed`."""
    reg = _Reg({_BASE: _HTML, _JS: PS_NO_ORIGIN})
    out = _run(reg)
    assert len(out) == 1 and out[0]["confidence"] == "lead"
    assert out[0]["cwe"] == "CWE-346"
    assert "NOT DRIVEN TO EXECUTION" in out[0]["evidence"]


def test_a_driven_handler_is_reported_with_the_confirmation_not_the_lead():
    def _confirm(url, rec):
        return dom.wm_finding(url, rec, dom.wm_payloads(rec)[0], "dom_xss",
                              control="control stayed silent", origin="http://127.0.0.1:1234")

    reg = _Reg({_BASE: _HTML, _JS: PS_NO_ORIGIN}, confirm=_confirm)
    out = _run(reg)
    assert len(out) == 1 and out[0]["confidence"] == "confirmed"
    assert out[0]["cwe"] == "CWE-79"
    assert "127.0.0.1:1234" in out[0]["evidence"], "evidence must name the origin that really posted"


def test_the_juice_shop_bundle_costs_no_browser_time_and_yields_nothing():
    """THE REAL-WORLD FALSE-POSITIVE CONTROL, on the real bundle. The cheap gate FIRES (positive
    control: the apparatus was looking), the receiver check then rejects it, so `_wm_confirm` is
    never called and nothing is reported."""
    assert dom.wm_scan_hint(JUICE_SHOP_WS) is True, "positive control: the gate must see this"
    reg = _Reg({_BASE: _HTML, _JS: JUICE_SHOP_WS})
    assert _run(reg) == []
    assert reg.confirm_calls == [], "spent browser budget on socket.io's WebSocket transport"


def test_a_page_with_no_message_listener_never_reaches_the_browser():
    """The cheap gate's whole purpose: zero browser spend on the overwhelming majority of pages."""
    reg = _Reg({_BASE: _HTML, _JS: "var x = 1; el.addEventListener('click', f);"})
    assert _run(reg) == []
    assert reg.confirm_calls == []


def test_iframe_resizer_is_seen_by_the_gate_and_still_not_reported():
    """A REAL window handler on millions of pages that reaches no sink. Seen, then dropped."""
    assert dom.wm_scan_hint(IFRAME_RESIZER) is True
    reg = _Reg({_BASE: _HTML, _JS: IFRAME_RESIZER})
    assert _run(reg) == []
    assert reg.confirm_calls == []


def test_third_party_scripts_are_not_fetched_or_analysed():
    """A CDN copy of a library is not this target's handler, and fetching it spends the target's
    request budget on someone else's code."""
    page = ('<!doctype html><html><body><script src="https://cdn.example.net/lib.js"></script>'
            '<script src="/app.js"></script></body></html>')
    reg = _Reg({_BASE: page, _JS: PS_NO_ORIGIN})
    assert len(_run(reg)) == 1
    assert not any("cdn.example.net" in u for u in reg.fetched), reg.fetched


def test_an_out_of_scope_script_is_never_fetched():
    reg = _Reg({_BASE: _HTML, _JS: PS_NO_ORIGIN}, allow=False)
    _run(reg)
    assert reg.fetched == [_BASE], "scope block must stop the script fetch"


def test_one_handler_served_under_two_urls_is_reported_once():
    page = ('<!doctype html><html><body><script src="/app.js"></script>'
            '<script src="/copy.js"></script></body></html>')
    reg = _Reg({_BASE: page, _JS: PS_NO_ORIGIN,
                "http://lab.local:8099/copy.js": PS_NO_ORIGIN})
    assert len(_run(reg)) == 1


def test_a_fetch_failure_is_recorded_rather_than_dissolved():
    """A crashed check and a clean target must never look identical."""
    class _Boom(_Reg):
        async def _http(self, u, method="GET", capture=False):
            raise RuntimeError("connection reset")

    reg = _Boom({})
    assert _run(reg) == []
    assert any("web_message" in w for w, _ in reg.swallowed), reg.swallowed


def test_the_number_of_records_driven_is_bounded():
    """Each payload is a page load inside the product's most expensive tool call."""
    many = "\n".join(INNERHTML_SHAPE.replace("'ads'", "'ads%d'" % i) for i in range(6))
    reg = _Reg({_BASE: _HTML, _JS: many})
    assert len(_run(reg)) <= tools_mod.ToolRegistry._WM_MAX_RECORDS


def test_the_harness_is_a_real_loopback_listener_not_a_synthetic_origin():
    """MEASURED root cause: a route-intercepted origin opens no connection, so Chromium classifies
    it PUBLIC and Local Network Access blocks it from reaching any loopback or private target. The
    harness must therefore be a REAL listener, and it must be bound to loopback only."""
    reg = tools_mod.ToolRegistry.__new__(tools_mod.ToolRegistry)
    reg.swallowed = []
    url = tools_mod.ToolRegistry._wm_harness_server(reg)
    try:
        assert url.startswith("http://127.0.0.1:"), url
        assert url.endswith("/wm-harness"), url
        assert tools_mod.ToolRegistry._wm_harness_server(reg) == url, "must be started once, reused"
        import urllib.request
        with urllib.request.urlopen(url, timeout=5) as r:
            assert r.status == 200
            assert b"<html" in r.read().lower()
    finally:
        try:
            reg._wm_harness_httpd.shutdown()
            reg._wm_harness_httpd.server_close()
        except Exception:
            pass
