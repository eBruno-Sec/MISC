"""The canonical graph is LIVE: it grows on the ToolRegistry as the surface is discovered, so the
planner reads a current world model instead of one rebuilt only at finalize (CHAD review #7)."""
from __future__ import annotations

import scope
import tools


def _reg():
    sc = scope.ScopeEngine()
    sc.load_manual(["t.tld"], [], "T")
    return tools.ToolRegistry(sc, lab_mode=True)


def test_graph_grows_as_urls_are_added():
    reg = _reg()
    assert reg.graph.stats()["nodes"] == 0                     # empty at start
    reg._add_urls(["http://t.tld/api/orders/1", "http://t.tld/login", "http://t.tld/rest/products"])
    kinds = reg.graph.stats()["by_kind"]
    assert kinds.get("host") == 1
    assert kinds.get("endpoint", 0) >= 2
    assert kinds.get("object", 0) == 1                         # /api/orders/1 is object-bearing
    assert any("foreign_object_read" in n["enables"] for n in reg.graph.nodes("object"))
    # host -> endpoint edge exists (live provenance)
    assert reg.graph.neighbors("host:t.tld", rel="serves")


def test_offscope_url_does_not_enter_graph():
    reg = _reg()
    reg._add_urls(["http://evil.example/api/orders/1"])        # out of scope -> filtered
    assert reg.graph.stats()["nodes"] == 0
