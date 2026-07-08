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


# ── OpenAPI / Swagger import ─────────────────────────────────────
def test_openapi3_paths_params_and_templates():
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "/api/v1"}],
        "paths": {
            "/products/{id}": {"get": {}},
            "/search": {"get": {"parameters": [
                {"in": "query", "name": "q"}, {"in": "query", "name": "limit"},
                {"in": "header", "name": "X-Trace"},  # ignored (not query)
            ]}},
        },
    }
    eps = surface.endpoints_from_openapi(spec, "http://t.example")
    assert "http://t.example/api/v1/products/1" in eps      # {id} -> 1
    hit = [e for e in eps if e.startswith("http://t.example/api/v1/search?")]
    assert hit and "q=test" in hit[0] and "limit=test" in hit[0] and "X-Trace" not in hit[0]


def test_swagger2_basepath():
    spec = {"swagger": "2.0", "basePath": "/v2", "paths": {"/pet": {"post": {}}}}
    eps = surface.endpoints_from_openapi(spec, "http://t.example")
    assert eps == ["http://t.example/v2/pet"]


def test_openapi_anchors_to_target_not_foreign_host():
    # A spec that declares an absolute foreign server must NOT redirect scanning there.
    spec = {"openapi": "3.0.0", "servers": [{"url": "http://evil.internal/api"}],
            "paths": {"/x": {"get": {}}}}
    eps = surface.endpoints_from_openapi(spec, "http://t.example")
    assert eps == ["http://t.example/api/x"]
    assert all("evil.internal" not in e for e in eps)


def test_openapi_rejects_junk():
    assert surface.endpoints_from_openapi({}, "http://t.example") == []
    assert surface.endpoints_from_openapi({"paths": "nope"}, "http://t.example") == []
    assert surface.endpoints_from_openapi(None, "http://t.example") == []
