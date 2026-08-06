"""Deterministic external-recon primitives (#114): favicon hashing + subdomain permutation. Pure/offline
— generation only, never resolves or probes. Permuted subs are UNVERIFIED candidates."""
import base64

import recon_expand as RE


def test_favicon_hash_is_deterministic_and_matches_mmh3_when_available():
    assert RE.favicon_hash(b"") == 0                      # empty -> base64 empty -> mmh3 0
    a = RE.favicon_hash(b"<svg>icon</svg>")
    assert a == RE.favicon_hash(b"<svg>icon</svg>")       # deterministic
    assert a != RE.favicon_hash(b"different-icon")
    try:
        import mmh3
        expect = mmh3.hash(base64.encodebytes(b"<svg>icon</svg>"))
        assert a == expect                                # exact Shodan-style value
    except ImportError:
        pass


def test_favicon_pivot_query_carries_the_hash():
    q = RE.favicon_pivot_queries(-1234567890)
    assert q["shodan"] == "http.favicon.hash:-1234567890"


def test_permute_generates_unverified_candidates():
    subs = RE.permute("acme.com")
    assert "api.acme.com" in subs and "dev.acme.com" in subs
    assert subs == sorted(set(subs)) and "acme.com" not in subs      # unique, sorted, excludes the root
    assert RE.permute("notadomain") == [] and RE.permute("") == []


def test_permute_recurses_over_the_existing_label():
    subs = RE.permute("shop.acme.com")
    assert "api.shop.acme.com" in subs and "shop-api.acme.com" in subs


def test_seed_candidates_lands_unverified_subdomains_in_the_graph():
    import asset_graph as AG
    g = AG.AssetGraph("m")
    n = RE.seed_candidates(g, "acme.com", RE.permute("acme.com")[:5], scope_asset="acme.com")
    assert n >= 1
    node = g.nodes("subdomain")[0]
    assert (node.get("props") or {}).get("reachable") == "unverified"
    assert node["sources"][0]["source"] == "permutation" and node["confidence"] <= 0.3
