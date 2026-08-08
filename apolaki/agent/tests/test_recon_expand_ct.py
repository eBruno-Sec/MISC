"""#114 external attack-surface: the CT parser. Everything it emits is a CANDIDATE, and it must never
leak names outside the authorized root — shared certificates routinely name other people's domains."""
import recon_expand as rx


ROWS = [
    {"name_value": "www.example.com\n*.example.com", "common_name": "example.com"},
    {"name_value": "api.example.com", "common_name": "api.example.com"},
    # a shared/SAN certificate that also covers someone else entirely
    {"name_value": "shop.example.com\nunrelated-victim.org\nmail.other.net", "common_name": "shop.example.com"},
]


def test_names_are_harvested_and_wildcards_unfolded():
    got = rx.parse_ct_names(ROWS, "example.com")
    assert "www.example.com" in got and "api.example.com" in got and "shop.example.com" in got
    assert "example.com" in got            # *.example.com unfolds to the bare root
    assert not any(n.startswith("*") for n in got)


def test_names_outside_the_authorized_root_are_dropped():
    """The load-bearing rule: a certificate mentioning someone else's domain must not put that domain
    into our engagement."""
    got = rx.parse_ct_names(ROWS, "example.com")
    assert "unrelated-victim.org" not in got
    assert "mail.other.net" not in got


def test_a_lookalike_suffix_does_not_match():
    got = rx.parse_ct_names([{"name_value": "evil-example.com\nx.notexample.com"}], "example.com")
    assert got == []


def test_parser_is_defensive_about_shape():
    assert rx.parse_ct_names(None, "example.com") == []
    assert rx.parse_ct_names([], "example.com") == []
    assert rx.parse_ct_names(["api.example.com"], "example.com") == ["api.example.com"]
    assert rx.parse_ct_names([{"name_value": None}], "example.com") == []


def test_junk_entries_are_skipped():
    rows = [{"name_value": "admin@example.com\nsome name.example.com\ngood.example.com"}]
    got = rx.parse_ct_names(rows, "example.com")
    assert got == ["good.example.com"]      # email and space-bearing junk dropped


def test_ct_query_url_is_returned_not_executed():
    u = rx.ct_query_url("example.com")
    assert u.startswith("https://crt.sh/?q=") and "example.com" in u and "output=json" in u
    assert rx.ct_query_url("") == ""


def test_permutations_are_candidates_for_the_right_root():
    got = rx.permute("app.example.com", max_out=50)
    assert all(g.endswith("example.com") for g in got)
    assert "api.example.com" in got
    assert "app-api.example.com" in got     # recursion over the existing leftmost label


def test_favicon_hash_is_deterministic_and_pivotable():
    h1, h2 = rx.favicon_hash(b"icon-bytes"), rx.favicon_hash(b"icon-bytes")
    assert h1 == h2 and isinstance(h1, int)
    assert rx.favicon_hash(b"other") != h1
    assert rx.favicon_pivot_queries(h1)["shodan"] == "http.favicon.hash:%d" % h1
