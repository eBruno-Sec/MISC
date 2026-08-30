"""Q-128 - 314 of 322 findings on a stock WordPress were "DOM manipulation" that never touched JS.

The reach lab exists so ground truth is checkable by hand, and this is what it caught. A stock
`wordpress:6-apache` with five latest plugins produced:

    162  Reflected DOM data manipulation in 'X'
    152  Reflected DOM link manipulation in 'X'
      8  everything else

MEASURED, and it is one line of the target's own HTML. Fetching the probe URL with curl -- no
browser, no JavaScript -- already contains the canary:

    <a rel="nofollow" id="cancel-comment-reply-link"
       href="/?p=1&#038;ref=nav&#038;lang=domtr7168079a#respond">

WordPress echoes the request URI into its comment-reply link. The SERVER put the canary in an
`href`. The oracle then rendered the page, found the canary in an `href`, and reported "Reflected
DOM link manipulation", CWE-79, MEDIUM, CVSS 5.4. Three hundred and fourteen times.

PRESENCE IN THE DOM IS NOT A DOM FLOW. `in_href` / `in_src` / `in_attr` / `in_text` are evidence of
a client-side sink only if CLIENT-SIDE CODE put the value there. When the value arrived in the HTML,
the browser is showing us the application's own markup and nothing was traced. Server-side
reflection is a real thing worth reporting -- by `run_xss` and `run_injection_probes`, under its own
name, and only when it does something.

THE HALF THAT KEEPS THIS AN ORACLE, and it is the more important half: `dom_xss`, `open_redirect`
and `request_url_override` are NOT gated. Those are BEHAVIOURS the browser performed -- a dialog
fired, a navigation happened, a fetch reached the attacker host. Reflected input that also EXECUTES
is still XSS, and suppressing it because the server echoed it would trade a false-positive flood for
a missed real bug. That is the wrong trade and this file pins it.
"""
import dom_trace as dt


URL = "http://wpreach/?p=1&ref=nav&lang=x"
CANARY = "domtr7168079a"


def _fams(sig):
    return {h["family"] for h in dt.classify(URL, "lang", CANARY, sig)}


# -- the field failure ---------------------------------------------------------

def test_a_server_reflected_canary_in_an_href_is_not_dom_link_manipulation():
    """The exact WordPress case: the canary reached the href in the HTTP response body."""
    assert _fams({"in_href": "a[href]", "server_reflected": True}) == set()


def test_a_server_reflected_canary_in_dom_text_is_not_dom_data_manipulation():
    assert _fams({"in_text": True, "server_reflected": True}) == set()
    assert _fams({"in_attr": "title", "server_reflected": True}) == set()


def test_the_whole_wordpress_signal_shape_yields_nothing():
    """All four presence signals at once, as a real render of that page produced them."""
    assert _fams({"in_href": "a[href]", "in_src": "img[src]", "in_attr": "title",
                  "in_text": True, "server_reflected": True}) == set()


# -- non-vacuity: a genuine client-side flow still fires ------------------------

def test_a_client_side_sink_is_still_reported():
    """Without this, gating everything satisfies every test above and deletes the engine."""
    assert _fams({"in_href": "a[href]", "server_reflected": False}) == {"dom_link_manipulation"}
    assert _fams({"in_text": True, "server_reflected": False}) == {"dom_data_manipulation"}


def test_an_absent_flag_behaves_as_not_server_reflected():
    """Every existing caller and test omits the key. Absent must mean "no evidence of server
    reflection", never "assume it" -- defaulting the other way would silence the engine wholesale."""
    assert _fams({"in_href": "a[href]"}) == {"dom_link_manipulation"}


# -- THE HALF THAT MATTERS: behaviours are never gated -------------------------

def test_executed_xss_is_reported_even_when_the_server_reflected_it():
    """Reflected input that EXECUTES is XSS. A dialog fired; the mechanism is not in dispute."""
    got = _fams({"executed": True, "in_href": "a[href]", "server_reflected": True})
    assert "dom_xss" in got, got


def test_a_navigation_to_the_attacker_host_is_reported_regardless():
    got = _fams({"redirect": "https://bbh-evil.example/", "server_reflected": True})
    assert "open_redirect" in got, got


def test_a_client_side_request_override_is_reported_regardless():
    got = _fams({"req_override": "https://bbh-evil.example/api", "server_reflected": True})
    assert "request_url_override" in got, got


def test_a_behaviour_and_a_presence_signal_together_keep_only_the_behaviour():
    """The precise line: the page both executed AND echoed. The execution is real evidence; the
    echo is not additional evidence and must not become a second finding."""
    got = _fams({"executed": True, "in_href": "a[href]", "in_text": True, "server_reflected": True})
    assert got == {"dom_xss"}, got


# -- the discriminator itself --------------------------------------------------

def test_the_same_signals_differ_only_by_where_the_canary_came_from():
    """The whole fix in one assertion. Identical sink signals; the ONLY difference is whether the
    server had already emitted the canary before any script ran."""
    sig = {"in_href": "a[href]", "in_attr": "title"}
    assert _fams({**sig, "server_reflected": False}) == {"dom_link_manipulation", "dom_data_manipulation"}
    assert _fams({**sig, "server_reflected": True}) == set()


def test_a_clean_render_reports_nothing():
    assert _fams({}) == set()
    assert _fams({"server_reflected": True}) == set()
