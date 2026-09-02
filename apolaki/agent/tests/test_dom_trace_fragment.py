"""The URL FRAGMENT as a client-side source (#125, blind-recall grind).

WHY THE FRAGMENT IS A DIFFERENT KIND OF SOURCE. Everything after '#' is never transmitted to the server.
No server-side reflection test can observe it, it never appears in an access log or a proxy capture, and
a request replay cannot reproduce it. A fragment-sourced DOM bug is therefore invisible to every engine
that reasons about request/response pairs — the only way to see it is to render the page and watch the
sink, which is what dom_trace does. `dom_trace`'s own docstring listed this as the planned extension
("a query parameter today; fragment/window.name extensible").

Two shapes are probed because applications parse the hash two ways: `#name=value` (hash-as-query, the
deparam / router-query style) and `#value` (the whole hash as one value).
"""
import dom_trace as dt


BASE = "http://t/app?q=1"


# ── probe-URL construction ────────────────────────────────────────────────────
def test_set_fragment_adds_a_pair_without_touching_the_query():
    u = dt.set_fragment(BASE, "redirect", "CANARY")
    assert u == "http://t/app?q=1#redirect=CANARY"
    assert dt.params_of(u) == ["q"], "the query string must be untouched"


def test_set_fragment_replaces_an_existing_fragment_pair():
    u = dt.set_fragment("http://t/app#redirect=old&keep=1", "redirect", "NEW")
    assert "redirect=NEW" in u and "keep=1" in u and "old" not in u


def test_set_raw_fragment_replaces_the_whole_hash():
    assert dt.set_raw_fragment("http://t/app?q=1#anything", "CANARY") == "http://t/app?q=1#CANARY"


def test_probe_url_dispatches_on_source_and_defaults_to_query():
    assert dt.probe_url(BASE, "p", "V") == dt.set_param(BASE, "p", "V")
    assert dt.probe_url(BASE, "p", "V", "query") == dt.set_param(BASE, "p", "V")
    assert dt.probe_url(BASE, "p", "V", "fragment") == dt.set_fragment(BASE, "p", "V")
    assert dt.probe_url(BASE, "p", "V", "fragment_raw") == dt.set_raw_fragment(BASE, "V")


def test_the_fragment_never_leaks_into_the_query_string():
    """THE load-bearing property. If the canary ended up in the query, the engine would be re-testing the
    server-side source it already covers and the 'invisible to the server' claim would be false."""
    for src in ("fragment", "fragment_raw"):
        u = dt.probe_url(BASE, "redirect", "CANARY", src)
        query = u.split("#", 1)[0]
        assert "CANARY" not in query, (src, u)
        assert "CANARY" in u.split("#", 1)[1]


# ── classification carries the source through ─────────────────────────────────
_REFLECTED = {"executed": False, "redirect": "", "req_override": "", "in_href": "",
              "in_src": "", "in_attr": "DIV@title", "in_text": True}


def test_query_classification_is_unchanged_by_the_new_parameter():
    """No regression: the default path must behave exactly as before the source model existed."""
    hits = dt.classify(BASE, "search", "CAN", _REFLECTED)
    assert [h["family"] for h in hits] == ["dom_data_manipulation"]
    assert hits[0]["target"] == dt.set_param(BASE, "search", "CAN")
    assert "query parameter 'search'" in hits[0]["evidence"]


def test_fragment_classification_targets_the_fragment_url():
    hits = dt.classify(BASE, "search", "CAN", _REFLECTED, source="fragment")
    assert hits[0]["target"] == dt.set_fragment(BASE, "search", "CAN")
    assert "fragment" in hits[0]["evidence"]
    assert hits[0]["source"] == "fragment"


def test_raw_fragment_classification_does_not_invent_a_parameter_name():
    hits = dt.classify(BASE, "(hash)", "CAN", _REFLECTED, source="fragment_raw")
    assert hits[0]["target"] == dt.set_raw_fragment(BASE, "CAN")
    assert "URL fragment" in hits[0]["evidence"]


# ── the finding a human reads ─────────────────────────────────────────────────
def test_fragment_finding_warns_that_a_request_replay_cannot_reproduce_it():
    """A reader handed ordinary reproduction steps would replay the request, see nothing, and close the
    finding as a false positive. The fragment never reaches the server."""
    hit = dt.classify(BASE, "search", "CAN", _REFLECTED, source="fragment")[0]
    f = dt.finding(hit)
    assert "via the URL fragment" in f["title"]
    assert f["source"] == "fragment"
    assert any("never sends to the server" in s for s in f["reproduction_steps"])
    assert f["confidence"] == "confirmed"


def test_query_finding_title_and_steps_are_untouched():
    f = dt.finding(dt.classify(BASE, "search", "CAN", _REFLECTED)[0])
    assert f["title"] == "Reflected DOM data manipulation in 'search'"   # the pre-existing wording
    assert "fragment" not in f["title"]
    assert not any("fragment" in s for s in f["reproduction_steps"])
    assert f["source"] == "query"


def test_every_declared_source_is_constructible():
    """A source named in SOURCES that probe_url cannot build would be a silent no-op branch."""
    for src in dt.SOURCES:
        u = dt.probe_url(BASE, "p", "V", src)
        assert "V" in u and u.startswith("http://t/app")


# =================================================================================================
# Q-153. HASH-ROUTE PARAMETERS. A hash-routed SPA (Angular, Vue, React Router) keeps its parameters
# INSIDE the fragment -- `#/search?q=...` -- where the server never sees them, so no
# request/response engine can reach them and neither could this one.
#
# MEASURED on juice-shop, whose DOM XSS is exactly `#/search?q=`. All three existing sources miss
# it, and two ACTIVELY DESTROY the route:
#
#   fragment      #%2Fsearch%3Fq=test&q=CANARY   the route is percent-encoded into a parameter NAME
#   fragment_raw  #CANARY                        the route is replaced outright
#   query         ?q=CANARY#/search?q=test       a server parameter the SPA never reads
#
# With the source added, `_run_dom_trace` reports juice-shop's DOM XSS. It had been invisible.
# =================================================================================================

def test_hash_route_parameters_are_discovered():
    assert dt.fragment_route_params("http://h:3000/#/search?q=test") == ["q"]
    assert dt.fragment_route_params("http://h:3000/#/r?a=1&b=2") == ["a", "b"]


def test_a_url_with_no_hash_query_yields_no_route_params():
    """The negative control: a bare hash route and a plain URL both offer nothing to probe, and
    inventing a parameter for them would spend a browser render on nothing."""
    assert dt.fragment_route_params("http://h:3000/#/account") == []
    assert dt.fragment_route_params("http://h:3000/x?a=1") == []
    assert dt.fragment_route_params("http://h:3000/") == []


def test_the_probe_keeps_the_route_and_replaces_only_the_value():
    """THE DEFECT, stated as an assertion. The payload has to land where the application reads it,
    and that means the route must survive."""
    got = dt.probe_url("http://h:3000/#/search?q=test", "q", "CANARY", "fragment_route")
    assert got == "http://h:3000/#/search?q=CANARY"
    assert "%2F" not in got and "%3F" not in got, "the route was percent-encoded again"


def test_the_probe_preserves_sibling_hash_parameters():
    assert dt.probe_url("http://h:3000/#/r?a=1&b=2", "b", "C", "fragment_route") == \
        "http://h:3000/#/r?a=1&b=C"


def test_the_old_sources_still_do_what_they_did():
    """Non-vacuity from the other direction: this added a source, it did not change the three that
    existed, so a regression in them cannot hide behind the new one."""
    u = "http://h:3000/x"
    assert dt.probe_url(u, "p", "C", "query") == "http://h:3000/x?p=C"
    assert dt.probe_url(u, "(hash)", "C", "fragment_raw") == "http://h:3000/x#C"
    assert dt.probe_url(u, "p", "C", "fragment") == "http://h:3000/x#p=C"


def test_the_source_phrase_names_where_the_payload_actually_went():
    """A reader who cannot tell WHICH source was injected cannot reproduce the bug -- and a
    fragment-sourced finding described as a query parameter is not reproducible at all."""
    phrase = dt.source_phrase("fragment_route", "q")
    assert "q" in phrase and "fragment" in phrase.lower()


# =================================================================================================
# Q-159. THE DOM SWEEP'S DEDUP KEY WAS THE PATH, and on a hash-routed SPA every route shares one.
#
# `urlparse("http://h/#/contact").path` is "/". So #/contact, #/login, #/about and the bare page
# all collapsed to a single key: the base page claimed it, and every route discovered by Q-157 was
# then declared "already swept". Two fixes had landed upstream and still nothing was probed.
# =================================================================================================

import agent as _agentmod


def test_hash_routes_are_distinct_pages_to_the_sweep():
    keys = {_agentmod._dom_sweep_key(u) for u in (
        "http://h:3000/", "http://h:3000/#/contact", "http://h:3000/#/login")}
    assert len(keys) == 3, keys


def test_an_ordinary_url_keys_exactly_as_it_did_before():
    """The fragment is empty on a normal URL, so this must be the OLD behaviour verbatim -- a
    change that also re-keyed ordinary pages would quietly re-sweep the whole surface."""
    assert _agentmod._dom_sweep_key("http://h:3000/x?a=1") == "/x"
    assert _agentmod._dom_sweep_key("http://h:3000/") == "/"


def test_the_key_is_not_vacuously_unique():
    """NEGATIVE CONTROL. Two URLs that ARE the same page must still collapse, or the dedup stops
    deduping and the sweep re-renders the same document until the budget is gone."""
    assert _agentmod._dom_sweep_key("http://h:3000/x?a=1") == \
        _agentmod._dom_sweep_key("http://h:3000/x?a=2")
    assert _agentmod._dom_sweep_key("http://h:3000/#/contact") == \
        _agentmod._dom_sweep_key("http://other:9/#/contact")


# =================================================================================================
# Q-161. THE LAST LINK. `build_inventory` groups by (host, path), and
# `urlparse("http://h/#/contact").path` is "/" -- so every route of a hash-routed SPA collapsed
# into the single bare-page entry and vanished before the planner could ever see it.
#
# This is why Q-153 (probe the source), Q-157 (discover the routes) and Q-159 (stop deduping them
# together) each landed correct and each changed nothing: the routes were removed one layer below.
# =================================================================================================

import surface as _surface


def _paths(urls):
    return [i["path"] for i in _surface.build_inventory(urls)]


def test_hash_routes_survive_the_inventory_as_separate_pages():
    got = _paths(["http://h:3000/", "http://h:3000/#/contact", "http://h:3000/#/login"])
    assert got == ["/", "#/contact", "#/login"], got


def test_a_hash_route_with_a_query_is_parameterized():
    """The point of the whole chain. The planner probes PARAMETERIZED endpoints, and juice-shop's
    DOM XSS lives at `#/search?q=` -- so `q` has to arrive as a parameter of a real entry."""
    inv = _surface.build_inventory(["http://h:3000/#/search?q=x"])[0]
    assert inv["path"] == "#/search" and inv["params"] == ["q"] and inv["parameterized"] is True


def test_the_route_is_the_identity_and_the_query_is_not():
    """Two searches are ONE page. Keying on the value would make every search term its own
    endpoint and exhaust the budget on a single route."""
    assert _paths(["http://h:3000/#/search?q=a", "http://h:3000/#/search?q=b"]) == ["#/search"]


def test_a_bare_anchor_is_NOT_a_page():
    """NEGATIVE CONTROL, and the reason this checks for "#/" rather than any fragment. `#section`
    is a position in the SAME document; treating those as pages would multiply the surface by every
    in-page link on the site."""
    assert _paths(["http://h:3000/page#section", "http://h:3000/page#other"]) == ["/page"]


def test_ordinary_urls_are_grouped_exactly_as_before():
    assert _paths(["http://h:3000/a?x=1", "http://h:3000/a?x=2", "http://h:3000/b"]) == ["/a", "/b"]
