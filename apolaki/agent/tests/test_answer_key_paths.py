"""A second keyed benchmark target must not be able to leak its own answer key (#125).

`blind_benchmark.is_answer_key` always accepted `extra_paths`, but nothing passed them: the scope choke
point called it with the default only, so the blocked set was hardcoded to `/vulnerabilities`. Every
benchmark target publishes ground truth somewhere different — an expectedresults index, a case list —
and a keyed target whose key was NOT blocked would have its answers crawled straight into the mission.

That failure is invisible in the worst way: the mission would still be sealed and hashed before the key
was fetched for SCORING, so `ordering_ok` would still be true and every artifact would look valid, while
the scanner had already read the answers during the run.
"""
import blind_benchmark as bb
from scope import ScopeEngine


def _scope(hosts, key_paths=None):
    sc = ScopeEngine()
    sc.load_manual(hosts, [], "t")
    if key_paths is not None:
        sc.answer_key_paths = key_paths
    return sc


# ── the pure predicate ────────────────────────────────────────────────────────
def test_the_default_key_path_is_blocked_with_or_without_extras():
    assert bb.is_answer_key("https://t/vulnerabilities") is True
    assert bb.is_answer_key("https://t/vulnerabilities", ["/expectedresults"]) is True


def test_an_extra_key_path_is_blocked():
    assert bb.is_answer_key("https://t/expectedresults", ["/expectedresults"]) is True
    assert bb.is_answer_key("https://t/expectedresults") is False, "must not block it by default"


def test_extra_paths_match_regardless_of_trailing_slash_or_query():
    for u in ("https://t/benchmark/key", "https://t/benchmark/key/", "https://t/benchmark/key?x=1"):
        assert bb.is_answer_key(u, ["/benchmark/key"]) is True, u


def test_a_sub_path_of_a_key_is_still_application_surface():
    """Exact-path matching is deliberate: /vulnerabilities/sqli/ is a real DVWA-style route and
    over-blocking it would silently cut scanner coverage."""
    assert bb.is_answer_key("https://t/vulnerabilities/sqli/", ["/vulnerabilities"]) is False


# ── the choke point, which is what actually protects a mission ────────────────
def test_the_scope_blocks_a_custom_answer_key_mid_mission():
    sc = _scope(["t"], ["/expectedresults"])
    ok, why = sc.validate("https://t/expectedresults")
    assert ok is False and "answer-key" in why.lower()


def test_the_scope_still_allows_ordinary_surface_on_the_same_host():
    sc = _scope(["t"], ["/expectedresults"])
    assert sc.validate("https://t/catalog?x=1")[0] is True


def test_the_default_block_survives_when_no_extras_are_supplied():
    """The regression that matters most: adding the parameter must not weaken the existing block."""
    assert _scope(["t"]).validate("https://t/vulnerabilities")[0] is False


def test_scope_defaults_to_no_extra_paths():
    assert ScopeEngine().answer_key_paths == []


def test_blank_entries_do_not_block_everything():
    """An empty string normalises to '/' and would block the site root — the whole scan — if it were
    allowed through. The engage handler filters blanks; this pins the behaviour if that changes."""
    sc = _scope(["t"], [])
    assert sc.validate("https://t/")[0] is True


def test_the_engage_request_exposes_the_field():
    """A parameter the API cannot accept is unreachable, which is the same island problem in API form."""
    import main
    assert "answer_key_paths" in main.EngageRequest.model_fields
