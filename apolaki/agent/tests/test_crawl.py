"""Pure BFS-frontier selection for the authenticated recursive crawl (CHAD capability D)."""
from __future__ import annotations

import crawl


def test_same_origin():
    assert crawl.same_origin("http://h/a", "http://h/")
    assert not crawl.same_origin("http://other/a", "http://h/")
    assert not crawl.same_origin("mailto:x@y", "http://h/")


def test_frontier_keeps_new_same_origin_nonasset():
    base = "http://h/"
    seen = {"http://h/seen"}
    cands = ["http://h/new1", "http://h/seen", "http://h/app.js", "http://other/x",
             "http://h/new1", "http://h/new2", "http://h/logo.png"]
    fr = crawl.bfs_frontier(cands, base, seen)
    assert fr == ["http://h/new1", "http://h/new2"]     # deduped, assets + off-origin + seen dropped


def test_frontier_is_bounded_and_ordered():
    base = "http://h/"
    cands = ["http://h/p%d" % i for i in range(100)]
    fr = crawl.bfs_frontier(cands, base, set(), limit=10)
    assert len(fr) == 10 and fr[0] == "http://h/p0"     # first-occurrence order, capped


def test_extract_forms_parses_action_method_fields():
    html = ('<html><body>'
            '<form action="/login" method="POST"><input name="email"><input name="password"></form>'
            '<form><input name="q"><textarea name="comment"></textarea></form>'
            '</body></html>')
    forms = crawl.extract_forms(html, "http://h/page")
    assert forms[0]["action"] == "http://h/login" and forms[0]["method"] == "POST"
    assert forms[0]["fields"] == ["email", "password"]
    # a form with no action resolves to the page URL, default method GET
    assert forms[1]["action"] == "http://h/page" and forms[1]["method"] == "GET"
    assert set(forms[1]["fields"]) == {"q", "comment"}


def test_extract_forms_empty_when_no_forms():
    assert crawl.extract_forms("<html><p>no forms here</p></html>", "http://h/") == []


def test_extract_forms_keeps_input_values_not_just_names():
    """`fields` (names) is unchanged for existing consumers; `inputs` adds the VALUE that was discarded.
    A serialized object lives in a hidden field's value, so dropping it made that carrier invisible."""
    html = ('<form action="/prefs" method="post">'
            '<input type="hidden" name="state" value="a:1:{s:4:&quot;role&quot;;s:4:&quot;user&quot;;}">'
            '<input type=text name=nick value=bob>'
            '<input type="submit" value="Save">'          # no name -> not a field
            '</form>')
    f = crawl.extract_forms(html, "http://h/p")[0]
    assert f["fields"] == ["state", "nick"]               # unnamed submit excluded, order preserved
    by_name = {i["name"]: i for i in f["inputs"]}
    # entity-decoded: the blob must be its real bytes, not &quot;-escaped, or detect_format cannot see it
    assert by_name["state"]["value"] == 'a:1:{s:4:"role";s:4:"user";}'
    assert by_name["state"]["type"] == "hidden"
    assert by_name["nick"]["value"] == "bob" and by_name["nick"]["type"] == "text"


def test_extract_forms_survives_hostile_markup_without_backtracking():
    """The tag pattern is bounded on purpose — an unbounded [^>]* inside a repeat is a ReDoS foothold."""
    import time
    hostile = "<form>" + "<input " + ("a" * 40000) + "\n" + "</form>"
    t0 = time.perf_counter()
    crawl.extract_forms(hostile, "http://h/")
    assert time.perf_counter() - t0 < 2.0
