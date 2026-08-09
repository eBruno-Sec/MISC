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
