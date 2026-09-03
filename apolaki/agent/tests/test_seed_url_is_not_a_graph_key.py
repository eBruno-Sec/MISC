"""Q-178. A graph key is an IDENTITY, not an ADDRESS -- and one leaked into the address space.

`asset_graph.observe_param` mints a query parameter's node key as `{endpoint}?{name}`. That is
deliberate and documented. Those keys are stored in `memory_assets` under kind `endpoints`, and
warm start rebuilds every endpoint asset into a seed URL -- so the scanner requested node
identities as if they were pages.

MEASURED on mutillidae: 63 stored "endpoints" of that shape, 52 actually requested in one mission:

    mutillidae/index.php?page=credits.php?do
    mutillidae/includes/index.php?page=document-viewer.php?PathToDocument

The wasted requests are not the damage. The malformed variants OUTNUMBERED the well-formed
root-router URLs, so `/index.php?page=<x>.php` -- the application's real entry point -- lost the
form-discovery budget to `/includes/index.php?page=<x>.php`, and mutillidae's dns-lookup command
injection (`target_host=127.0.0.1;id` -> `uid=33(www-data)`) was never handed to an engine.
A key in the wrong namespace cost a CRITICAL finding.

The rule is structural and needs no knowledge of who produced the value: a URL has ONE query
string. This is the same intake-side reasoning `_add_urls` already documents for `&amp;` poisoning
-- a fix at the producer leaves every previously-stored record intact, so the boundary has to hold.
"""
import main


BASES = {"mutillidae": "http://mutillidae", "t.local": "http://t.local:3000"}


def test_a_param_node_key_is_not_seeded_as_a_url():
    """THE regression, with the two real shapes from the mission."""
    for key in ["mutillidae/index.php?page=credits.php?do",
                "mutillidae/includes/index.php?page=document-viewer.php?PathToDocument",
                "mutillidae/index.php?page=dns-lookup.php?do"]:
        assert main._seed_url(key, BASES) == "", (
            "a `{endpoint}?{name}` graph key was rebuilt into a request URL: %r" % key)


def test_an_ordinary_parameterised_url_still_seeds():
    """The negative control. One query string is a URL and must survive untouched."""
    got = main._seed_url("mutillidae/index.php?page=dns-lookup.php", BASES)
    assert got == "http://mutillidae/index.php?page=dns-lookup.php", got


def test_a_multi_parameter_url_still_seeds():
    """`&` is how a URL carries more than one parameter; only a second `?` is malformed."""
    got = main._seed_url("t.local/search?q=a&lang=en&page=2", BASES)
    assert got == "http://t.local:3000/search?q=a&lang=en&page=2", got


def test_a_plain_path_still_seeds():
    assert main._seed_url("mutillidae/robots.txt", BASES) == "http://mutillidae/robots.txt"


def test_an_absolute_url_with_two_question_marks_is_also_rejected():
    """The check is on the VALUE, before the scheme branch -- a stored absolute must not slip past."""
    assert main._seed_url("http://mutillidae/index.php?page=x.php?do", BASES) == ""
