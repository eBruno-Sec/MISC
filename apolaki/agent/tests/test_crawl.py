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
