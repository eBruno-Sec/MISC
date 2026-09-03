"""Q-172. A query parameter whose VALUE names a page is a route selector.

MEASURED on mutillidae: 45 distinct `index.php?page=<x>.php` targets are linked directly from the
home page, one hop from the root. Every one collapsed into the single inventory key
("mutillidae", "/index.php") with params {"page"}, and a full-mode mission reached only 10 of them.

`dns-lookup.php` was never among the 10 -- so its `target_host` command injection was never seen.
Verified by hand that it is real:

    target_host=127.0.0.1;id  ->  uid=33(www-data) gid=33(www-data) groups=33(www-data)

`run_form_cmdi` ran twelve times that mission and found nothing, and was RIGHT every time: the form
parser handles that page correctly when pointed at it, and it never was. 78% of the application's
surface was discarded before any engine ran, which makes every zero on it correct and meaningless.

This is the server-side twin of Q-161's hash-route rule, and the detection is on the VALUE's shape,
never the parameter's NAME -- `page`, `file`, `view`, `module`, `do` are one construct, and a name
list only ever catches the names somebody thought of.
"""
import surface


PAGES = ["home.php", "dns-lookup.php", "add-to-your-blog.php", "user-info.php", "login.php"]
ROUTED = ["http://t.local/index.php?page=" + p for p in PAGES]


def _paths(inv):
    return {e["path"] for e in inv}


def test_each_routed_page_gets_its_own_inventory_entry():
    inv = surface.build_inventory(ROUTED)
    for p in PAGES:
        assert "/index.php?page=" + p in _paths(inv), (
            "%s collapsed into the shared /index.php entry and would never be probed" % p)


def test_the_collapsed_entry_survives_so_the_selector_itself_is_still_tested():
    """ADDITIVE. `page` is itself a traversal/LFI sink and that probe must not be lost."""
    inv = surface.build_inventory(ROUTED)
    collapsed = [e for e in inv if e["path"] == "/index.php"]
    assert len(collapsed) == 1, "the collapsed entry is gone; the LFI probe on `page` went with it"
    assert "page" in collapsed[0]["params"]


def test_the_derived_pages_do_not_repeat_the_selector_probe():
    """Cost control: without this, the same `page` probe runs once per discovered route."""
    inv = surface.build_inventory(ROUTED)
    for e in inv:
        if e["path"].startswith("/index.php?page="):
            assert "page" not in e["params"], (
                "%s repeats the selector probe already covered by the collapsed entry" % e["path"])


def test_other_parameters_on_a_routed_page_are_still_collected():
    inv = surface.build_inventory([
        "http://t.local/index.php?page=user-info.php&username=a&password=b"])
    hit = [e for e in inv if e["path"] == "/index.php?page=user-info.php"]
    assert hit, _paths(inv)
    assert sorted(hit[0]["params"]) == ["password", "username"]


def test_a_search_term_is_not_a_route():
    """THE negative control. Promoting every parameter value would make each search a page."""
    inv = surface.build_inventory(["http://t.local/search?q=shoes",
                                   "http://t.local/search?q=hats",
                                   "http://t.local/search?q=boots"])
    assert len(inv) == 1, "search terms became separate pages: %r" % _paths(inv)
    assert sorted(inv[0]["params"]) == ["q"]


def test_a_numeric_or_word_value_is_not_a_route():
    inv = surface.build_inventory(["http://t.local/item?id=7", "http://t.local/item?id=8",
                                   "http://t.local/sort?by=price"])
    assert _paths(inv) == {"/item", "/sort"}, _paths(inv)


def test_the_rule_is_not_keyed_on_the_parameter_name():
    """`page` is not special. A name list would only catch the names somebody thought of."""
    inv = surface.build_inventory(["http://t.local/app.cgi?module=admin.cgi",
                                   "http://t.local/app.cgi?module=report.cgi"])
    assert "/app.cgi?module=admin.cgi" in _paths(inv)
    assert "/app.cgi?module=report.cgi" in _paths(inv)
