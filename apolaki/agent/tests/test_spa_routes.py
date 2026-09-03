"""Q-163 -- param-bearing SPA route discovery by driving the rendered controls.

The pure tests pin the URL algebra. The live tests are the ones that matter: a route list is only
worth anything if a real browser, on a real application, produced it from no hand-supplied URL.
"""
import os
import socket
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import spa_routes as SR                                                   # noqa: E402
import surface                                                            # noqa: E402

JUICE = "http://juice-shop:3000/"


def _lab_up(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=4):
            return True
    except Exception:
        return False


def _require(host: str, port: int):
    """Conftest turns this exact wording into a hard session failure, so a networkless container
    cannot quietly shrink this file into nothing."""
    if not _lab_up(host, port):
        pytest.skip("%s lab unreachable (%s:%d)" % (host, host, port))


# ─────────────────────────────────────────────────────────────────── pure: URL algebra
def test_route_fragment_is_a_route_not_an_in_page_anchor():
    assert SR.is_route_fragment("http://h/#/search?q=1")
    assert SR.is_route_fragment("http://h/#/login")
    # "#top" is a position in the SAME document. Counting those as pages would multiply the
    # surface by every in-page link on the site, which is why surface.build_inventory refuses them.
    assert not SR.is_route_fragment("http://h/#top")
    assert not SR.is_route_fragment("http://h/")
    assert not SR.is_route_fragment(None)


def test_split_fragment_keeps_blank_values():
    assert SR.split_fragment("http://h/#/search?q=x&r=") == ("/search", [("q", "x"), ("r", "")])
    assert SR.split_fragment("http://h/#/login") == ("/login", [])


def test_blank_marked_values_empties_only_the_marker_it_carried():
    got = SR.blank_marked_values("http://h/#/search?q=apolakirt7&lang=en")
    route, pairs = SR.split_fragment(got)
    assert route == "/search"
    # The marker was a vehicle; `lang=en` is a value the APPLICATION put there and is an observed
    # fact. Blanking both would destroy real intel; blanking neither would push a meaningless
    # literal into every reproduction step.
    assert pairs == [("q", ""), ("lang", "en")]


def test_blank_marked_values_handles_a_real_query_string_too():
    got = SR.blank_marked_values("http://h/s?term=apolakirt7#/x?q=apolakirt7")
    assert got == "http://h/s?term=#/x?q="
    assert SR.split_fragment(got) == ("/x", [("q", "")])


def test_blank_marked_values_never_raises_on_junk():
    assert SR.blank_marked_values(None) == ""
    assert SR.blank_marked_values("") == ""


def test_inventory_path_agrees_with_the_real_inventory():
    """Not a restatement: the module's idea of the page key is checked against the function that
    actually files it. If these two ever drift, this module reports a discovery the planner never
    receives -- which is precisely the Q-161 failure it exists to finish."""
    url = "http://juice-shop:3000/#/search?q="
    inv = surface.build_inventory([url])
    assert len(inv) == 1
    assert inv[0]["path"] == SR.inventory_path(url) == "#/search"
    assert inv[0]["params"] == ["q"]
    assert inv[0]["parameterized"] is True


def test_inventory_path_agrees_on_a_subdirectory_app():
    url = "http://h/app/#/report?id="
    assert surface.build_inventory([url])[0]["path"] == SR.inventory_path(url) == "/app#/report"


# ─────────────────────────────────────────────────────────── pure: the route record is a FACT
def test_route_record_is_empty_when_the_app_did_not_navigate():
    assert SR.route_record("http://h/#/", "http://h/#/") == {}
    assert SR.route_record("http://h/#/", "") == {}


def test_route_record_names_the_parameter_the_application_chose():
    rec = SR.route_record("http://h/#/", "http://h/#/search?q=apolakirt7",
                          control={"id": "searchQuery"})
    assert rec["params"] == ["q"]
    assert rec["parameterized"] is True
    assert rec["url"] == "http://h/#/search?q="
    assert rec["observed_url"] == "http://h/#/search?q=apolakirt7"   # the raw fact is kept
    assert rec["path"] == "#/search"
    assert rec["control"]["id"] == "searchQuery"
    assert rec["source"] == "typed-control"


def test_route_record_refuses_to_call_a_bare_route_parameterized():
    """NEGATIVE CONTROL. `parameterized` is the single field the sweep keys on. A record that
    asserted it instead of computing it would push every param-free route into the probe queue and
    the module would look like it worked."""
    rec = SR.route_record("http://h/#/", "http://h/#/login")
    assert rec["params"] == []
    assert rec["parameterized"] is False
    assert SR.parameterized_urls([rec]) == []


def test_route_record_survives_a_full_page_navigation_too():
    """A non-SPA form that submits by GET is also a discovery, and its parameter lives in the real
    query string. Nothing about this mechanism is hash-specific."""
    rec = SR.route_record("http://h/", "http://h/results?term=apolakirt7")
    assert rec["params"] == ["term"] and rec["parameterized"] is True
    assert rec["hash_route"] is False
    assert rec["path"] == "/results"


def test_merge_routes_dedupes_by_page_and_params():
    a = SR.route_record("http://h/#/", "http://h/#/search?q=apolakirt7")
    b = SR.route_record("http://h/#/", "http://h/#/search?q=apolakirt7")
    c = SR.route_record("http://h/#/", "http://h/#/login")
    assert len(SR.merge_routes([a, b, c])) == 2
    assert SR.parameterized_urls([a, b, c]) == ["http://h/#/search?q="]
    assert SR.merge_routes([None, {}, {"url": ""}]) == []


# ─────────────────────────────────────────────────── the read-only guarantee is a MECHANISM
class _FakeRequest:
    def __init__(self, method):
        self.method = method


class _FakeRoute:
    def __init__(self, method):
        self.request = _FakeRequest(method)
        self.calls = []

    def abort(self):
        self.calls.append("abort")

    def fallback(self):
        self.calls.append("fallback")

    def continue_(self):
        self.calls.append("continue")


@pytest.mark.parametrize("method,expected", [
    ("GET", "fallback"), ("HEAD", "fallback"), ("get", "fallback"),
    ("POST", "abort"), ("PUT", "abort"), ("DELETE", "abort"), ("PATCH", "abort"),
])
def test_read_only_gate_aborts_every_write(method, expected):
    """The drive types into real controls and presses Enter. Without this gate that is a login
    attempt, a comment, an order. `fallback()` rather than `continue_()` on the safe methods so
    browser_engine's rate gate further down the handler chain is not silently shadowed."""
    r = _FakeRoute(method)
    SR._read_only_gate(r)
    assert r.calls == [expected]


def test_password_is_not_a_typeable_control():
    assert "password" not in SR.TYPEABLE_TYPES
    assert '"password"' not in SR.control_js()


def test_module_issues_no_fixed_sleep():
    """A fixed settle is a race with the framework. Three iterations of this cycle were lost to one,
    twice with no error to show for it, so the absence is asserted rather than remembered.

    Asserted over the AST, not the text: a substring check would fire on the docstring that explains
    the rule, and (worse) would pass a `getattr(page, "wait_" + "for_timeout")()`. It is the CALL
    that is the race."""
    import ast
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "spa_routes.py")
    tree = ast.parse(open(path, encoding="utf-8").read())
    # BREAKER F5. This matched only `ast.Attribute` calls, so it caught `time.sleep()` and missed
    # a BARE `sleep()` (ast.Name) entirely -- and the getattr form its own docstring names was
    # never checked either. A guard that misses two of the three ways to write the banned thing is
    # the "guard scoped to its author's attention" shape. All three are covered now.
    banned = {"wait_for_timeout", "sleep"}
    calls = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        if isinstance(f, ast.Attribute) and f.attr in banned:
            calls.append(f.attr)
        elif isinstance(f, ast.Name) and f.id in banned:          # bare sleep(...)
            calls.append(f.id)
        elif isinstance(f, ast.Call) and isinstance(f.func, ast.Name) and f.func.id == "getattr":
            calls.append("getattr-built call")                    # getattr(page, "wait_for_" + x)()
    assert calls == [], calls
    # positive control: the same walk DOES find the bounded condition waits, so an empty result
    # above means "no sleeps", not "the walk found nothing at all".
    waits = {n.func.attr for n in ast.walk(tree)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr.startswith("wait_for")}
    assert waits == {"wait_for_function", "wait_for_load_state"}, waits


# ────────────────────────────────────────────────────────────── degradation is LABELLED
def test_discover_refuses_an_out_of_scope_base_without_starting_a_browser():
    res = SR.discover("http://evil.example/", scope_ok=lambda _u: False)
    assert res["ran"] is False and res["routes"] == [] and res["urls"] == []
    assert "out of scope" in res["note"]


def test_discover_with_no_base_is_labelled_not_silent():
    res = SR.discover("")
    assert res["ran"] is False and res["note"] == "no base url"


# ───────────────────────────────────────────────────────────────────────── LIVE: the point
def test_available_reports_a_real_browser():
    usable, note = SR.available()
    assert usable, note


def test_control_enumeration_rejects_the_password_field_it_was_offered():
    """NEGATIVE CONTROL WITH TEETH. A guard that never meets its target proves nothing, so this
    drives the enumeration against a page that really does render a password input and asserts BOTH
    halves: the password field is refused, and other controls on the same page are not."""
    _require("juice-shop", 3000)
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b = p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
        try:
            pg = b.new_context(ignore_https_errors=True).new_page()
            pg.goto(JUICE + "#/login", wait_until="domcontentloaded", timeout=20000)
            pg.wait_for_function("() => document.querySelectorAll('input[type=password]').length > 0",
                                 timeout=20000)
            pw_count = pg.evaluate("() => document.querySelectorAll('input[type=password]').length")
            got = pg.evaluate(SR.control_js(), SR.CONTROL_SELECTOR)
        finally:
            b.close()
    assert pw_count > 0, "the negative control never met a password field"
    assert got, "enumeration returned nothing at all -- the guard cannot be said to have run"
    assert [c for c in got if c["type"] == "password"] == []


def test_discovers_a_parameterised_spa_route_from_no_hand_supplied_url():
    """THE ACCEPTANCE TEST (Q-163).

    Given only the origin, the module must come back with a route that carries a parameter. On
    juice-shop that is `#/search?q=`, which no anchor on the site points at -- `_spa_hash_routes`
    harvests five routes from this same page and not one of them is parameterised.

    The route name is asserted HERE and nowhere in the module: `spa_routes.py` contains no route
    literal and no parameter-name list. This test states what juice-shop happens to answer; the
    mechanism asks the question."""
    _require("juice-shop", 3000)
    res = SR.discover(JUICE, max_pages=1)
    assert res["browser"] and res["ran"], res["note"]
    assert res["attempts"], "no control was driven at all: %s / %s" % (res["note"], res["errors"])
    paths = {r["path"]: r for r in res["routes"]}
    assert "#/search" in paths, "routes=%r attempts=%r" % (res["routes"], res["attempts"])
    assert paths["#/search"]["params"] == ["q"]
    assert paths["#/search"]["parameterized"] is True
    assert JUICE.rstrip("/") + "/#/search?q=" in res["urls"], res["urls"]
    # and the discovery survives the hand-off: the planner's own inventory files it as a
    # parameterised page, which is the thing Q-161 fixed and Q-163 finally feeds.
    inv = {e["path"]: e for e in surface.build_inventory(res["urls"])}
    assert inv["#/search"]["parameterized"] is True and inv["#/search"]["params"] == ["q"]


def test_discovered_route_is_a_page_the_application_really_serves():
    """A route the module invented would still satisfy the assertion above. This one re-drives the
    discovered URL in a fresh browser and requires the application to route to it -- the value we
    typed has to come back rendered somewhere in the document."""
    _require("juice-shop", 3000)
    res = SR.discover(JUICE, max_pages=1)
    urls = res["urls"]
    assert urls, res["note"]
    probe = urls[0].replace("q=", "q=apolakiproof9") if "q=" in urls[0] else urls[0]
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b = p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
        try:
            pg = b.new_context(ignore_https_errors=True).new_page()
            pg.goto(probe, wait_until="domcontentloaded", timeout=20000)
            pg.wait_for_function("() => document.body && document.body.innerText.length > 0",
                                 timeout=20000)
            pg.wait_for_function("(m) => document.documentElement.innerHTML.includes(m)",
                                 arg="apolakiproof9", timeout=20000)
            hash_now = pg.evaluate("() => location.hash")
        finally:
            b.close()
    assert hash_now.startswith("#/"), hash_now


# ───────────────────────────── GENERALITY: a second, structurally different application
#
# Every other lab on apolaki_default renders ZERO typeable controls on its root page -- MEASURED:
# domsource:8080 and dvga:5013 and bwapp:80 and wpreach:80 have no input at all, and mutillidae:80's
# only input is a `type=submit` button (correctly not typeable). juice-shop is the sole lab with a
# search control on its landing page, so a second REAL application cannot supply this proof.
#
# So the second application is served here. It is deliberately nothing like juice-shop: no Angular,
# no router, no framework at all, a route named `/find` and `#/lookup`, and parameters named `term`
# and `needle` -- four names that appear nowhere in spa_routes.py. If the module carried a
# juice-shop signature, it would find neither.
_FIXTURE_HTML = """<!doctype html><html><head><title>fixture</title></head><body>
<form id="f1" action="/find" method="get"><input id="term" name="term" type="text"></form>
<input id="needle" type="text">
<form id="f3" action="/save" method="post"><input id="note" name="note" type="text"></form>
<form id="f4" action="/login" method="post">
  <input id="user" name="user" type="text">
  <input id="pw" name="pw" type="password">
  <input type="submit" value="go">
</form>
<script>
document.getElementById('needle').addEventListener('keydown', function (e) {
  if (e.key === 'Enter') { location.hash = '/lookup?needle=' + encodeURIComponent(e.target.value); }
});
</script></body></html>"""


class _Fixture:
    """A tiny second application, plus the LOG of what actually reached it. The log is the point:
    it is how "no POST was sent" is proved rather than asserted."""

    def __init__(self):
        import http.server
        import threading
        self.seen = []
        log = self.seen

        class H(http.server.BaseHTTPRequestHandler):
            def _reply(self, body=b"ok"):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                log.append(("GET", self.path))
                self._reply(_FIXTURE_HTML.encode() if self.path in ("/", "") else b"<html>hit</html>")

            def do_POST(self):
                log.append(("POST", self.path))
                self._reply()

            def log_message(self, *a):
                pass

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.base = "http://127.0.0.1:%d/" % self.srv.server_address[1]
        self.t = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.t.start()

    def close(self):
        try:
            self.srv.shutdown()
            self.srv.server_close()
        except Exception:
            pass


@pytest.fixture()
def fixture_app():
    fx = _Fixture()
    try:
        yield fx
    finally:
        fx.close()


def test_finds_routes_on_an_application_that_is_nothing_like_juice_shop(fixture_app):
    """Anti-signature proof. Same code, a different framework (none), a different navigation kind
    (a real GET form AND a hand-rolled hash route), and four names the module has never heard of."""
    res = SR.discover(fixture_app.base, max_pages=1)
    assert res["ran"], res["note"]
    by_path = {r["path"]: r for r in res["routes"]}
    assert by_path["/find"]["params"] == ["term"]
    assert by_path["/find"]["parameterized"] is True and by_path["/find"]["hash_route"] is False
    assert by_path["#/lookup"]["params"] == ["needle"]
    assert by_path["#/lookup"]["parameterized"] is True and by_path["#/lookup"]["hash_route"] is True
    assert sorted(res["urls"]) == sorted([fixture_app.base + "find?term=",
                                          fixture_app.base + "#/lookup?needle="])


def test_the_drive_never_sends_a_write_and_the_password_field_is_never_driven(fixture_app):
    """The read-only guarantee, proved against a server that would have RECORDED the write.

    The fixture posts to /save and /login. After a full drive the server log must contain no POST at
    all -- and it must contain the GET the drive DID make, so "no POST" means the gate worked and
    not that the drive never ran."""
    res = SR.discover(fixture_app.base, max_pages=1)
    assert res["attempts"], res["note"]
    methods = [m for m, _ in fixture_app.seen]
    assert "POST" not in methods, fixture_app.seen
    assert any(p.startswith("/find?term=") for m, p in fixture_app.seen if m == "GET"), \
        fixture_app.seen
    driven = {a["control"]["id"] for a in res["attempts"]}
    assert "pw" not in driven, driven
    # and the write-shaped controls WERE driven -- the gate is what stopped them, not a skip
    assert {"note", "user"} <= driven, driven


def test_the_fixture_really_would_have_posted(fixture_app):
    """POSITIVE CONTROL for the test above. Drive the same control with NO gate installed and the
    server records the POST. Without this, a fixture that simply never submits would make the
    read-only claim unfalsifiable."""
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b = p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
        try:
            pg = b.new_context().new_page()
            pg.goto(fixture_app.base, wait_until="domcontentloaded", timeout=20000)
            pg.fill("#note", "apolakirt7")
            pg.press("#note", "Enter")
            pg.wait_for_function("() => location.pathname === '/save'", timeout=20000)
        finally:
            b.close()
    assert ("POST", "/save") in fixture_app.seen, fixture_app.seen


def test_scope_gate_is_honoured_on_every_discovered_url():
    """A discovery path that outruns the scope gate is how a scanner ends up touching a host nobody
    authorised. With the gate closed the run still happens -- and still returns nothing."""
    _require("juice-shop", 3000)
    res = SR.discover(JUICE, max_pages=1, scope_ok=lambda u: u.rstrip("/") == JUICE.rstrip("/"))
    assert res["ran"] is True
    assert res["routes"] == [] and res["urls"] == []


# =================================================================================================
# BREAKER F3. THE READ-ONLY GATE FAILED OPEN when the request method could not be read:
# `except Exception: method = "GET"` put the PERMISSIVE answer as the default, in the one place
# this module promises a mechanical guarantee.
# =================================================================================================

class _RaisingRequest:
    @property
    def method(self):
        raise RuntimeError("method unreadable")


class _BreakerRoute:
    def __init__(self, request):
        self.request, self.aborted, self.continued = request, False, False

    def abort(self):
        self.aborted = True

    def continue_(self):
        self.continued = True


class _BreakerReq:
    def __init__(self, m):
        self.method = m


def test_the_gate_refuses_when_the_method_cannot_be_read():
    """Unreadable must mean REFUSED. A lost request is a false negative; an escaped write is a
    change to someone else's system, and only one of those is recoverable."""
    r = _BreakerRoute(_RaisingRequest())
    SR._read_only_gate(r)
    assert r.aborted is True and r.continued is False


def test_the_gate_still_allows_a_readable_GET():
    """POSITIVE CONTROL. A gate that aborts everything would pass the test above and silently
    stop the module from loading any page at all."""
    r = _BreakerRoute(_BreakerReq("GET"))
    SR._read_only_gate(r)
    assert r.aborted is False


def test_the_gate_refuses_a_readable_POST():
    r = _BreakerRoute(_BreakerReq("POST"))
    SR._read_only_gate(r)
    assert r.aborted is True
