"""Web cache deception engine (CWE-525), distilled from OWASP WSTG / PortSwigger (RedCyber corpus). Confirmed
only when an ANONYMOUS fetch of a path-confused URL returns tokens private to the authenticated page — a leak
that only a shared cache can explain (an anon request has no session to regenerate the tester's private data)."""
import blind_benchmark as bb
import cache_deception_tool as cd


def test_variants_are_path_confused_and_unique():
    v = cd.deception_variants("https://x/account", "beef")
    assert any(u.endswith("/wcdbeef.css") for u in v)          # classic append
    assert any(";wcdbeef" in u for u in v)                     # path parameter
    assert any("%2fwcdbeef" in u for u in v)                   # encoded slash
    assert all("wcdbeef" in u for u in v)                      # our unique marker in every variant


def test_private_tokens_are_authed_only():
    authed = "<html>Welcome carlos@evil.net your api_key is SECRETTOKEN12345 <a>logout</a></html>"
    anon = "<html>Please log in <a>login</a></html>"
    toks = cd.private_tokens(authed, anon)
    assert "carlos@evil.net" in toks and "SECRETTOKEN12345" in toks
    assert "logout" not in toks                                # generic chrome excluded
    # nothing private when the pages don't differ
    assert cd.private_tokens(anon, anon) == []


def test_cacheable_detection():
    assert cd.looks_cacheable({"Cache-Control": "public, max-age=60"})
    assert cd.looks_cacheable({"X-Cache": "HIT from edge"})
    assert cd.looks_cacheable({"CF-Cache-Status": "HIT"})
    assert not cd.looks_cacheable({"Cache-Control": "no-store, private"})
    assert not cd.looks_cacheable({"Cache-Control": "max-age=0"})


def test_leaked_tokens_only_from_private_set():
    private = ["SECRETTOKEN12345", "carlos@evil.net"]
    assert cd.leaked_tokens("...SECRETTOKEN12345...", private) == ["SECRETTOKEN12345"]
    assert cd.leaked_tokens("nothing sensitive here", private) == []


def test_finding_is_benchmark_proof():
    f = cd.finding("https://x/account", "https://x/account/wcd1.css", ["SECRETTOKEN12345"], True)
    assert f["family"] == "cache_deception" and f["cwe"] == "CWE-525"
    assert f["confidence"] == "confirmed" and bb._has_proof(f)
