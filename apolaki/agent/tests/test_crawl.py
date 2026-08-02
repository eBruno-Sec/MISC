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
