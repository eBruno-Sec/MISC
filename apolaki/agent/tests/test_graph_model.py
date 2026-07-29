"""Tests for the path-prefix knowledge-graph builder (tree, not host->all-endpoints starburst)."""
from __future__ import annotations

import graph_model


def test_dir_prefix():
    assert graph_model._dir_prefix("/api/products/1") == ["/api/products/", "/api/"]
    assert graph_model._dir_prefix("/feed/123") == ["/feed/"]
    assert graph_model._dir_prefix("/feed.xml") == []
    assert graph_model._dir_prefix("/") == []


def test_graph_is_a_tree_not_a_starburst():
    urls = ["https://x.io/feed/123", "https://x.io/feed/456", "https://x.io/feed.xml",
            "https://x.io/.well-known/ai-plugin.json", "https://x.io/api/products/1",
            "https://x.io/api/products"]
    g = graph_model.build_graph(urls=urls)
    byid = {n["id"]: n for n in g["nodes"]}
    host = next(n["id"] for n in g["nodes"] if n["kind"] == "host")

    def parents(label):
        nid = next(n["id"] for n in g["nodes"] if n.get("label") == label)
        return [e["source"] for e in g["edges"] if e["target"] == nid]

    # path groups were created
    assert any(n["kind"] == "pathgroup" and n["label"] == "/feed/" for n in g["nodes"])
    assert any(n["kind"] == "pathgroup" and n["label"] == "/api/" for n in g["nodes"])

    # deep endpoints hang off a PATH GROUP, never straight off the host
    for deep in ("/feed/123", "/feed/456", "/api/products/1"):
        ps = parents(deep)
        assert ps and byid[ps[0]]["kind"] == "pathgroup"
        assert host not in ps

    # /api/products/1 is nested under /api/products/ under /api/
    assert byid[parents("/api/products/1")[0]]["label"] == "/api/products/"

    # genuinely top-level endpoints still hang directly off the host
    assert host in parents("/feed.xml")

    # host connects only to first-level groups/endpoints (never a deep leaf)
    assert host not in parents("/api/products/1")
