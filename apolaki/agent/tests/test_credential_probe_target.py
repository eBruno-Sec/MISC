"""Q-174 - an absent login URL means NOT TESTED, not a probe against a 404.

Mission `bed9ffcd` emitted `Exposed application credentials for 'root<U+FFFD>'` (MEDIUM,
candidate) against `http://mutillidae/login`, which is a 278-byte Apache 404. It tested an
invented username against a page that cannot authenticate anything, and reported the failure as
a fact about the credential: "a single verification login did not yield a session (form/flow
mismatch)".

WHERE THE FALSY DEFAULT ACTUALLY IS. A triage report placed it at the call site:

    login_url = prior_login or self._discover_login_url(base) or base.rstrip("/") + "/login"

MEASURED with an empty URL surface, that is wrong:

    _discover_login_url -> 'http://mutillidae/login'
    is it falsy?        -> False
    did the trailing `or base+'/login'` fire? -> False

`_discover_login_url` appends the guess to its OWN candidate list, so it is never falsy for an
in-scope base and the trailing `or` is dead code. Deleting it, as proposed, would have changed
nothing. The guess is manufactured inside the function, and that is what had to stop.

TWO further measured facts that shaped the fix:

1. The mission DID see the real login, three times, and discovery still failed:

       login-ish URLs in the mission's exchanges: 3
         http://mutillidae/includes/index.php?page=login.php
         http://mutillidae/includes/pop-up-help-context-generator.php?pagename=login.php
         http://mutillidae/index.php?page=login.php?do&popUpNotificationCode
       regex r"/(login|signin|sign-in|session|auth)\b" matched: 0 of 3

   It requires a `/` before the keyword, so a query-routed login is invisible to it.

2. Recognising those URLs would NOT have been enough. Of the three, one is a 404 and another
   renders with zero password inputs:

       /index.php?page=login.php?do&popUpNotificationCode  HTTP 200 <form=1 password-input=0
       /includes/index.php?page=login.php                  HTTP 404 <form=0 password-input=0

   A name-shaped login URL is not a login endpoint, exactly as a name-shaped `accounts.txt` is
   not a credential file. Both defects decided on the string instead of the response.
"""
import asyncio

import agent as A


class _Scope:
    def __init__(self, ok=True):
        self.ok = ok

    def validate(self, u):
        return (self.ok, "")


class _Intel:
    def get(self, kind):
        return []


class _Tools:
    def __init__(self, urls=None):
        self.urls = list(urls or [])
        self.intel = _Intel()

    def _swallow(self, *a, **k):
        pass


def _agent(urls=None, scope_ok=True):
    o = object.__new__(A.BBHAgent)
    o.tools = _Tools(urls)
    o.scope = _Scope(scope_ok)
    return o


# ── the falsy default, at the place it actually lives ───────────────────────────
def test_discovery_without_a_guess_returns_nothing_when_nothing_was_seen():
    """MUTANT "restore the falsy default" DIES HERE.

    Restoring the unconditional `cands.append(base + "/login")` makes this return the guess."""
    o = _agent(urls=[])
    assert o._discover_login_url("http://mutillidae", allow_guess=False) is None


def test_the_default_caller_contract_is_unchanged():
    """Other callers still get the fallback; only the credential probe opts out."""
    o = _agent(urls=[])
    assert o._discover_login_url("http://mutillidae") == "http://mutillidae/login"


def test_a_login_url_actually_on_the_target_is_still_discovered():
    o = _agent(urls=["http://h/app/login", "http://h/index.php"])
    assert o._discover_login_url("http://h", allow_guess=False) == "http://h/app/login"


def test_the_trailing_or_at_the_call_site_was_dead_code():
    """Documents the correction to the triage report, as an executable claim."""
    o = _agent(urls=[])
    assert o._discover_login_url("http://mutillidae") is not None, (
        "if this is ever falsy the `or base + '/login'` fallback would fire; it never was")


# ── a URL is only a login surface if the response says so ───────────────────────
class _Resp:
    def __init__(self, status=200, ct="text/html", text=""):
        self.status_code = status
        self.headers = {"content-type": ct}
        self.text = text


def _with_response(o, resp):
    """Stub the transport `_login_surface` uses, leaving its decision logic intact."""
    class _C:
        async def get(self, url):
            if isinstance(resp, Exception):
                raise resp
            return resp

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

    import browser_engine
    o.__dict__["_saved"] = browser_engine.rate_limited_async_client
    browser_engine.rate_limited_async_client = lambda *a, **k: _C()
    return browser_engine


def _restore(o, be):
    be.rate_limited_async_client = o.__dict__["_saved"]


def _surface(resp, url="http://h/login"):
    o = _agent()
    be = _with_response(o, resp)
    try:
        return asyncio.run(o._login_surface(url))
    finally:
        _restore(o, be)


def test_a_404_is_not_a_login_surface():
    """THE DEFECT: the credential was POSTed to a 278-byte Apache 404."""
    assert _surface(_Resp(404, "text/html", "<html><body>Not Found</body></html>")) is False


def test_an_html_page_with_no_password_input_is_not_a_login_surface():
    """The second measured case: a 200 that renders without a password field."""
    assert _surface(_Resp(200, "text/html", "<html><form><input name=q></form></html>")) is False


def test_a_real_login_form_is_a_login_surface():
    assert _surface(_Resp(200, "text/html",
                          '<form><input type="password" name=p></form>')) is True


def test_a_json_api_login_is_still_a_login_surface():
    """An API login answers a GET with 405 and carries no form; do not exclude it."""
    assert _surface(_Resp(405, "application/json", "")) is True


def test_an_api_login_that_errors_on_get_is_still_a_login_surface():
    """MEASURED on juice-shop: its real API login answers a GET with

        HTTP 500  <title>Error: Unexpected path: /rest/user/login</title>

    A GET is not the method a login endpoint answers, so an error is not evidence of absence.
    Only a 404/410, or a page that rendered fine and is not a login form, is evidence."""
    assert _surface(_Resp(500, "text/html",
                          "<html><title>Error: Unexpected path</title></html>")) is True
    assert _surface(_Resp(401, "text/html", "<html>UnauthorizedError</html>")) is True


def test_an_empty_url_is_never_a_login_surface():
    assert _surface(_Resp(200, "text/html", 'type="password"'), url="") is False


def test_an_out_of_scope_url_is_never_probed():
    o = _agent(scope_ok=False)
    assert asyncio.run(
        o._login_surface("http://evil.test/login")) is False


def test_a_transport_failure_is_not_treated_as_a_login_surface():
    assert _surface(RuntimeError("connection refused")) is False


# ── the over-correction: probing anything at all ────────────────────────────────
def test_over_correction_probe_anything_is_rejected():
    """OVER-CORRECTION MUTANT for defect 2 DIES HERE.

    "Probe anything even without a real login URL" means `_login_surface` returns True for a
    404 and for a page with no password input. Both are asserted False above; this states the
    combined property directly so the mutant cannot survive by weakening one branch only."""
    assert _surface(_Resp(404, "text/html", "Not Found")) is False
    assert _surface(_Resp(200, "text/html", "<html>no form here</html>")) is False
    assert _surface(_Resp(200, "text/html", '<input type="password">')) is True, (
        "the fix must not swing the other way and refuse a genuine login page")
