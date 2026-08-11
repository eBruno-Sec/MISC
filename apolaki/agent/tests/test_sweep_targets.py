"""Which endpoints the deterministic injection sweep actually schedules.

The selection used to keep ONLY query-bearing URLs, so a page whose sole injectable input is a POST
form was never handed to any injection engine — sqli and path traversal grew POST form passes that
nothing would ever have invoked. These pin the widened contract and its bounds.
"""
import agent as agent_mod

_ALL = lambda _u: True


def test_query_urls_are_deduped_by_path_and_param_signature():
    urls = ["https://t/a?x=1", "https://t/a?x=2", "https://t/a?y=1", "https://t/b?x=1", "https://t/plain"]
    out = agent_mod.sweep_targets(urls, [], _ALL)
    assert out == ["https://t/a?x=1", "https://t/a?y=1", "https://t/b?x=1"]   # ?x=2 is the same signature
    assert "https://t/plain" not in out          # a bare URL is still not a query target


def test_form_page_is_scheduled_even_with_no_query_string():
    """The whole point: this page has no '?' anywhere and must still be probed."""
    forms = [{"action": "https://t/servlet", "method": "POST", "fields": ["a"], "page": "https://t/form.html"}]
    out = agent_mod.sweep_targets([], forms, _ALL)
    assert out == ["https://t/form.html"]


def test_form_contributes_its_page_not_its_action():
    """Engines re-parse the document to rebuild the form; a bare action answers without a <form>."""
    forms = [{"action": "https://t/servlet", "method": "POST", "fields": ["a"], "page": "https://t/p.html"}]
    out = agent_mod.sweep_targets([], forms, _ALL)
    assert out == ["https://t/p.html"] and "https://t/servlet" not in out
    # ...but a record with no page recorded still contributes something rather than being dropped.
    assert agent_mod.sweep_targets([], [{"action": "https://t/only-action"}], _ALL) == ["https://t/only-action"]


def test_form_pages_respect_scope_and_dedupe_against_query_targets():
    forms = [{"action": "https://t/s", "page": "https://evil.test/x.html"},
             {"action": "https://t/s2", "page": "https://t/a"},          # same path as a query target
             {"action": "https://t/s3", "page": "https://t/a"}]          # duplicate page
    out = agent_mod.sweep_targets(["https://t/a?x=1"], forms, lambda u: "evil.test" not in u)
    assert out == ["https://t/a?x=1"]            # out-of-scope dropped; /a already covered; dupe dropped


def test_selection_stays_bounded_and_order_stable():
    urls = ["https://t/p%d?x=1" % i for i in range(30)]
    forms = [{"action": "https://t/s%d" % i, "page": "https://t/f%d.html" % i} for i in range(30)]
    out = agent_mod.sweep_targets(urls, forms, _ALL, limit=20)
    assert len(out) == 20                                   # cap still enforced with forms admitted
    assert out == agent_mod.sweep_targets(urls, forms, _ALL, limit=20)   # deterministic across runs
    assert agent_mod.sweep_targets([], [], _ALL) == []


# ── Q-019: the cap is a BUDGET, and the ORDER decides what the budget buys ────────────────────────
# MEASURED, mission 90cee81c: `limit` defaulted to 20 and the mission call site never passed one, so
# twenty endpoints was the real bound on a 2756-URL surface — and because candidates were emitted in
# discovery order, all twenty landed in the first category directory the crawl walked into.

def test_the_default_cap_is_the_module_budget_and_the_call_site_passes_it():
    """The trap was a function-signature default that nobody could see from the call site. Pin the
    default TO the named budget so there is exactly one number, and it is env-tunable."""
    assert agent_mod.sweep_targets.__defaults__[-1] == agent_mod.SWEEP_TARGET_CAP
    assert agent_mod.SWEEP_TARGET_CAP >= 200, "a budget below the surface of a real app is the old bug"


def test_a_truncated_budget_spans_every_shape_instead_of_one_directory():
    """THE regression this exists to catch. Three directories, 30 endpoints each, budget 6: the old
    discovery-order truncation returned six files from directory `a` and never touched `b` or `c`."""
    urls = ["https://t/%s/Case%04d.html?Case%04d=x" % (d, i, i)
            for d in ("a", "b", "c") for i in range(30)]
    out = agent_mod.sweep_targets(urls, [], _ALL, limit=6)
    dirs = {u.split("/")[3] for u in out}
    assert len(out) == 6
    assert dirs == {"a", "b", "c"}, "budget spent inside %s only" % dirs


def test_shape_spread_does_not_dedupe_distinct_endpoints():
    """The shape is an ORDERING key, never a dedup key: two files in one directory hit different sinks
    and collapsing them would be exactly the case-specific cheating this project forbids."""
    urls = ["https://t/a/Case%04d.html?Case%04d=x" % (i, i) for i in range(30)]
    out = agent_mod.sweep_targets(urls, [], _ALL, limit=999)
    assert len(out) == 30 and len(set(out)) == 30


def test_shape_collapses_identifier_segments_but_not_siblings():
    shape = agent_mod.target_shape
    assert shape("https://t/a/Case0001.html?q=1") == shape("https://t/a/Case0002.html?q=1")
    assert shape("https://t/a-04/x.html?q=1") == shape("https://t/a-09/x.html?q=1")
    assert shape("https://t/a/x.html?q=1") != shape("https://t/b/x.html?q=1")   # sibling dir differs
    assert shape("https://t/a/x.html?q=1") != shape("https://t/a/x.html?r=1")   # param names differ


def test_under_budget_the_original_discovery_order_is_preserved():
    """Reordering is a truncation strategy, not a behaviour change: when everything fits, nothing moves."""
    urls = ["https://t/b/x.html?q=1", "https://t/a/y.html?q=1", "https://t/c/z.html?q=1"]
    assert agent_mod.sweep_targets(urls, [], _ALL, limit=999) == urls


def test_spread_is_deterministic():
    urls = ["https://t/%s/Case%04d.html?q=1" % (d, i) for d in ("a", "b") for i in range(20)]
    a = agent_mod.sweep_targets(urls, [], _ALL, limit=7)
    assert a == agent_mod.sweep_targets(urls, [], _ALL, limit=7)
