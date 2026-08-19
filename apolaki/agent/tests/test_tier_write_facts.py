"""Q-052 slice 2 — the tier of an engine, checked against what the engine DOES.

The taxonomy Q-052 settled is: **ACTIVE sends requests and payloads and is READ-ONLY;
INTRUSIVE CHANGES STATE.** Slice 1 classified 31 engines by name and by reading, and reading got
four of them wrong (`http_request`, `run_mass_assign`, `test_numeric_abuse`, `run_bfla` all write).

So this file does not check a docstring, a registry entry, or anyone's opinion. It **drives the
shipping engine** through a recording transport and asks the only question the taxonomy cares about:
did it send a request that changes state? An engine that did, and is registered ACTIVE, is a
state-changing operation running under a mode an operator authorised as read-only.

The two engines pinned here were deferred by slice 1 and settled by slice 2 against a live
write-observing lab: `run_form_cmdi` created **58 persisted rows** and `run_web_probes` **28**, on one
page carrying one ordinary HTML form (docs/handoff/tier_split2.md). This is that measurement in a
form that runs in the suite.
"""
import asyncio

import pytest

import tools
from scope import PermissionLevel

# GET/HEAD/OPTIONS/TRACE are read-only by HTTP semantics. Anything else is the engine asking the
# application to change. TRACE is included deliberately: `_run_web_probes` uses it as a read-only
# XST oracle, and calling it a write would make this guard fire on a check that changes nothing.
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}

FORM_PAGE = """<!doctype html><html><body>
<form method="POST" action="/post">
  <input type="text" name="name" value="anon">
  <input type="text" name="comment" value="hello">
  <input type="submit" name="submit" value="Sign">
</form></body></html>"""

GET_FORM_PAGE = """<!doctype html><html><body>
<form method="GET" action="/post">
  <input type="text" name="q" value="shoes">
  <input type="submit" name="submit" value="Search">
</form></body></html>"""

FORMLESS_PAGE = """<!doctype html><html><body><h1>About</h1><p>No forms here at all.</p></body></html>"""


def _new_reg(host="host.local"):
    import scope as scope_mod
    eng = scope_mod.ScopeEngine()
    eng.load_manual([host], [], "P")
    return tools.ToolRegistry(eng, mission_id=None, lab_mode=False)


def _drive(engine, page, url="http://host.local/?id=1"):
    """Run a SHIPPING engine against a stubbed app and return every request it sent.

    The app is inert: it serves `page` and answers everything with 200. Nothing here is
    vulnerable, so any non-safe request is the engine's own choice, not a reaction to a finding."""
    sent = []
    reg = _new_reg()

    async def fake_http(u, method="GET", headers=None, body="", capture=False, **kw):
        method = (method or "GET").upper()
        sent.append({"method": method, "url": u, "body": body or ""})
        return {"status": 200, "body": page, "error": "", "final_url": u,
                "headers": {"Set-Cookie": "sid=abc123; Path=/", "Content-Type": "text/html"}}

    reg._http = fake_http
    res = asyncio.new_event_loop().run_until_complete(getattr(reg, "_" + engine)({"url": url}))
    return res, sent


def _writes(sent):
    return [r for r in sent if r["method"] not in SAFE_METHODS]


@pytest.mark.parametrize("engine", ["run_form_cmdi", "run_web_probes"])
def test_engine_sends_state_changing_requests_and_is_registered_intrusive(engine):
    """The fact, then the declaration — in that order, because the declaration is what was wrong.

    Both engines submit forms the page advertises. A form submission is how a comment box, a
    registration form and a feedback box all take input, so "the app advertised the form" is not a
    reason to believe the submission is read-only -- advertising the form is how the app INVITES the
    write. Measured against a real server: 58 and 28 persisted rows respectively."""
    _res, sent = _drive(engine, FORM_PAGE)
    writes = _writes(sent)
    assert writes, "%s sent no state-changing request: the premise of this guard is gone" % engine
    assert all(w["method"] == "POST" for w in writes), sorted({w["method"] for w in writes})
    assert tools.TOOL_PERMISSIONS[engine] is PermissionLevel.INTRUSIVE, (
        "%s sends %d state-changing request(s) against an inert page and is registered %s. "
        "ACTIVE means READ-ONLY. Remove the writes before re-tiering it, or leave it INTRUSIVE."
        % (engine, len(writes), tools.TOOL_PERMISSIONS[engine].name))


@pytest.mark.parametrize("engine", ["run_form_cmdi", "run_web_probes"])
def test_negative_control_a_formless_page_produces_no_writes(engine):
    """THE control that makes the assertion above mean something.

    If the recorder counted writes on any page at all, the test above would pass on an engine that
    never posts. Same apparatus, same engine, a page with no form: zero. So the writes are caused by
    the form, and a zero from this apparatus is a real zero. MEASURED identically against the live
    lab -- 0 requests beyond the baseline GETs, 0 rows created."""
    _res, sent = _drive(engine, FORMLESS_PAGE)
    assert sent, "the engine sent nothing at all -- the drive is vacuous, not clean"
    assert _writes(sent) == [], "form-less page still produced writes: %r" % (_writes(sent),)


def test_form_cmdi_posts_a_form_the_application_declared_get():
    """`tools.py` discovery filter: `if method == "POST" or fm.get("inputs")`.

    The `or` makes the method test vacuous -- any form with inputs qualifies -- so the one
    declaration the application made about this form ("GET: safe and idempotent") is overridden and
    it is submitted as a POST. MEASURED against the live lab: 30 POSTs, 30 rows created, on a page
    whose only form is `<form method="GET">`."""
    _res, sent = _drive("run_form_cmdi", GET_FORM_PAGE, url="http://host.local/getform?q=shoes")
    writes = _writes(sent)
    assert writes, "no POST at all -- if the method filter has been fixed, delete this test"
    assert any("q=" in w["body"] for w in writes), (
        "the GET form's field was never submitted: %r" % (writes[:3],))
