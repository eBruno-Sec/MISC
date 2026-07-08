"""Unit tests for the attack-surface inventory builder (core/surface.py)."""
from core import surface


def test_dedupes_by_path_and_unions_params():
    urls = [
        "https://t.example/catalog?category=1",
        "https://t.example/catalog?sort=asc",
        "https://t.example/catalog?category=2",   # same path, seen param again
        "https://t.example/about",
    ]
    inv = surface.build_inventory(urls)
    paths = {e["path"]: e for e in inv}
    assert set(paths) == {"/catalog", "/about"}
    assert paths["/catalog"]["params"] == ["category", "sort"]   # unioned + sorted
    assert paths["/catalog"]["parameterized"] is True
    assert paths["/about"]["parameterized"] is False


def test_distinct_hosts_are_separate_endpoints():
    inv = surface.build_inventory([
        "https://a.example/x?p=1",
        "https://b.example/x?p=1",
    ])
    assert len(inv) == 2
    assert {e["host"] for e in inv} == {"a.example", "b.example"}


def test_prefers_parameterized_example():
    inv = surface.build_inventory([
        "https://t.example/search",
        "https://t.example/search?q=hello",
    ])
    assert len(inv) == 1
    assert inv[0]["example"].endswith("?q=hello")


def test_skips_junk_and_respects_cap():
    urls = ["not-a-url", "", None, 123, "https://t.example/a", "https://t.example/b"]
    inv = surface.build_inventory(urls, cap=1)
    assert len(inv) == 1                          # cap honored
    # junk entries never produced an endpoint
    assert all(e["host"] == "t.example" for e in inv)


def test_empty_input():
    assert surface.build_inventory([]) == []
    assert surface.build_inventory(None) == []
