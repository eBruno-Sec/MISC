"""Q-100 — a Burp/HackerOne scope export must yield TARGETS, not a refusal.

The fixture is the operator's real Shopify scope export, the same file that produced the 18
fabricated findings of Q-096/Q-097/Q-098. Committed rather than synthesised, because every
synthetic version of this file I could write would be a version I already understood, and the
whole defect was that nobody had looked at what the real one contains.

Q-096 stopped the harm: every host in that file is an anchored regex, so all of them typed as
`pattern`, `in_scope` came out empty and the mission was refused. Correct, and it left the
operator unable to scan. Q-100 asks the second question — not "is this entry an address?" but
"what does this pattern DENOTE?" — and answers it in vocabulary the codebase already has.

The controls that matter here are the ones that prove the derivation does not INVENT
authorization. Deriving too much is a far worse failure than deriving too little: an over-derived
target is an unauthorised request sent to a real company under a real program's rules.
"""
import json
import os

import pytest

import scope as scope_mod


FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "burp_scope_shopify.json")


def _engine():
    parsed = scope_mod.parse_scope(open(FIXTURE, encoding="utf8").read())
    eng = scope_mod.ScopeEngine()
    eng.load_manual([e["identifier"] for e in parsed["in_scope"]],
                    [e["identifier"] for e in parsed["out_of_scope"]],
                    "shopify")
    return parsed, eng


# ── the parser ────────────────────────────────────────────────────────────────

def test_the_fixture_is_the_real_export_and_is_detected_as_burp_json():
    parsed = scope_mod.parse_scope(open(FIXTURE, encoding="utf8").read())
    assert parsed["format"] == "burp_json", "nested target.scope must still be unwrapped"
    # 30 include entries collapse to 15 hosts, 14 exclude entries to 7: Burp writes one rule per
    # protocol, so without dedup every host is carried, reported and recon-seeded twice.
    assert len(parsed["in_scope"]) == 15, [e["identifier"] for e in parsed["in_scope"]]
    assert len(parsed["out_of_scope"]) == 7, [e["identifier"] for e in parsed["out_of_scope"]]


def test_a_disabled_rule_is_not_a_rule():
    """`enabled: false` was read as though every rule were live. The dangerous half is the
    EXCLUDE side: a disabled carve-out honoured as active is a host the operator believes is
    protected and is not."""
    doc = {"target": {"scope": {
        "include": [{"enabled": True,  "host": r"^live\.example\.com$"},
                    {"enabled": False, "host": r"^off\.example\.com$"}],
        "exclude": [{"enabled": False, "host": r"^stale\.example\.com$"}]}}}
    parsed = scope_mod.parse_scope(json.dumps(doc))
    got = [e["identifier"] for e in parsed["in_scope"]]
    assert got == [r"^live\.example\.com$"], got
    assert parsed["out_of_scope"] == [], parsed["out_of_scope"]


# ── the derivation, in isolation ──────────────────────────────────────────────

@pytest.mark.parametrize("pattern,expected", [
    (r"^partners\.shopify\.com$", "partners.shopify.com"),
    (r"^shop\.app$", "shop.app"),
    (r"^arrive-server\.shopifycloud\.com$", "arrive-server.shopifycloud.com"),
])
def test_an_anchored_literal_is_a_hostname_wearing_punctuation(pattern, expected):
    assert scope_mod.literal_host_from_pattern(pattern) == expected


@pytest.mark.parametrize("pattern", [
    r"^a.b\.com$",          # BARE dot still matches any character -> denotes a SET
    r"^.*\.shopify\.com$",  # a wildcard is not one host
    r"^(a|b)\.com$",        # alternation
    r"^host\d\.com$",       # a class escape is not `\.`
    r"partners\.shopify\.com",  # unanchored: matches as a substring of other hosts
])
def test_anything_that_denotes_more_than_one_host_derives_nothing(pattern):
    """Declining to derive costs coverage. Deriving wrongly sends an unauthorised request to a
    real company, so every ambiguous shape must return nothing."""
    assert scope_mod.literal_host_from_pattern(pattern) == ""


def test_a_wildcard_yields_a_recon_root_and_never_the_bare_apex():
    """`^.*\\.shopify\\.com$` authorizes the SUBdomains of shopify.com and says nothing about
    shopify.com itself. The `*.` prefix keeps that in the type instead of in a comment, and it is
    the form `base_urls()` already refuses to dial."""
    assert scope_mod.wildcard_host_from_pattern(r"^.*\.shopify\.com$") == "*.shopify.com"
    assert scope_mod.wildcard_host_from_pattern(r"^.*\.pci\.shopifyinc\.com$") == "*.pci.shopifyinc.com"
    assert scope_mod.literal_host_from_pattern(r"^.*\.shopify\.com$") == ""


# ── the engine, end to end on the real file ───────────────────────────────────

def test_the_real_export_no_longer_refuses_the_engagement():
    _, eng = _engine()          # the assertion: load_manual does not raise
    assert eng.in_scope, "a scope with 15 usable hosts must not produce an empty target world"


def test_the_export_yields_eight_dialable_hosts_and_six_recon_roots():
    _, eng = _engine()
    concrete = sorted(e.value for e in eng.in_scope if e.asset_type == "domain")
    roots = sorted(e.value for e in eng.in_scope if e.asset_type == "wildcard")
    assert concrete == sorted([
        "accounts.shopify.com", "admin.shopify.com", "arrive-server.shopifycloud.com",
        "linkpop.com", "partners.shopify.com", "shop.app", "shopify.plus",
        "shopifyinbox.com", "your-store.myshopify.com",
    ]), concrete
    assert roots == sorted([
        "*.pci.shopifyinc.com", "*.shopify.com", "*.shopify.io",
        "*.shopifycloud.com", "*.shopifycs.com", "*.shopifykloud.com",
    ]), roots


def test_no_recon_root_is_ever_dialable():
    """The apex must be searched, never requested. `base_urls()` is the list the mission actually
    sends traffic to, so this is the assertion that keeps a wildcard from becoming a target."""
    _, eng = _engine()
    for url in eng.base_urls():
        assert "*" not in url, url
    assert not any(u.rstrip("/").endswith("//shopify.com") for u in eng.base_urls()), eng.base_urls()


def test_the_patterns_still_do_their_original_job_as_a_predicate():
    """The derivation is ADDITIVE. If it cost the boundary anything it would be a worse bug than
    the one it fixes, so both directions are asserted here."""
    _, eng = _engine()
    assert eng.validate("https://checkout.shopifycs.com/")[0] is True
    assert eng.validate("https://partners.shopify.com/")[0] is True
    assert eng.validate("https://evil.example.com/")[0] is False


def test_a_disabled_carve_out_aside_every_exclusion_still_excludes():
    """`cdn.shopify.com` matches the `^.*\\.shopify\\.com$` INCLUDE and is explicitly excluded.
    An exclusion that loses to an include is how an operator gets removed from a program."""
    _, eng = _engine()
    for host in ("cdn.shopify.com", "community.shopify.com", "academy.shopify.com",
                 "investors.shopify.com", "livechat.shopify.com"):
        assert eng.validate("https://%s/" % host)[0] is False, host


def test_the_regex_scope_that_started_this_is_still_not_a_target():
    """The Q-096 regression control. The reproduction command in the field report was
    `curl 'https://^.*\\.shopifycs\\.com$'`, so the raw pattern must never reappear as an address
    no matter how much the derivation now recovers around it."""
    _, eng = _engine()
    assert all("^" not in u and "$" not in u and "\\" not in u for u in eng.base_urls()), eng.base_urls()
    assert eng.validate(r"https://^.*\.shopifycs\.com$")[0] is False


def test_a_scope_that_denotes_nothing_still_raises():
    """The refusal Q-096 added must survive: it now means "nothing here can be turned into a
    target", which is a true statement, rather than "no entry is literally a hostname"."""
    eng = scope_mod.ScopeEngine()
    with pytest.raises(scope_mod.ScopeConfigurationError):
        eng.load_manual([r"^(a|b)\.example\.com$", r"^\d+\.example\.com$"], [], "unusable")
