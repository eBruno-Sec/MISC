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
    out = agent_mod.sweep_targets(urls, forms, _ALL)
    assert len(out) == 20                                   # cap still enforced with forms admitted
    assert out == agent_mod.sweep_targets(urls, forms, _ALL)   # deterministic across runs
    assert agent_mod.sweep_targets([], [], _ALL) == []
