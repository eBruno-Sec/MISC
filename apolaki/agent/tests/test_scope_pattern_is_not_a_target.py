"""Q-096 -- a scope PATTERN is a filter, never an address.

FOUND IN THE FIELD, same 2026-08-24 Shopify assessment as Q-097. The scope was entered as anchored
regexes (`^.*\\.shopify\\.com$`). `ScopeEngine.load_manual` typed an entry `wildcard` only when it
started with `*`; **a regex starts with `^`**, so it was typed `domain`, survived the wildcard filter
in `base_urls()`/`base_map()`, and was emitted verbatim as a base URL. The reproduction command the
report generated, verbatim:

    curl -i -sS -k --path-as-is 'https://^.*\\.shopifycs\\.com$'

MEASURED at HEAD 08158c2, in the agent image, three anchored patterns and nothing else:

    base_urls()   ['https://^.*\\.shopify\\.com$', 'https://^.*\\.shopifycs\\.com$', ...]
    base_map()    {'^.*\\.shopify\\.com$': 'https://^.*\\.shopify\\.com$', ...}
    base_roots    ['^.*\\.shopify\\.com$', ...]        <- agent.py:3758, seeds subfinder/crtsh/dns/asn
    validate('https://^.*\\.shopify\\.com$')  -> (True,  'In scope via ^.*\\.shopify\\.com$')
    validate('https://www.shopify.com')       -> (False, 'www.shopify.com not in scope')

**Read the last two lines together.** The predicate was not merely useless, it was INVERTED: the
unresolvable pattern string was authorised (it literally equals itself, so `_matches` accepted it),
and every real asset the operator owns was refused. Even if recon had discovered a live Shopify host,
scope would have blocked it. That is why one bad seed voided the entire engagement -- ledger from the
same mission: subfinder 15 calls / 0 subdomains, katana 15 calls / 0 URLs, httpx 0 live hosts,
`Surface Urls: 0`, and `[Errno -2] Name or service not known` 45 times.

WHAT THE FIX IS AND IS NOT. Scope has two jobs and they were conflated:

    PREDICATE   "is this discovered host authorised?"   -> must keep working, patterns included
    ADDRESS     "what do I connect to?"                 -> a pattern can never be one

A non-host entry is still stored and now matches as a real anchored regex -- which is what the
operator meant and what literal comparison never delivered -- but it lives in `in_scope_patterns`, so
it is absent from `in_scope`, and `in_scope` is the list three drivers in `agent.py` read as their
target list (`:3003` path seeding, `:3317` graph host observation, `:3758` recon roots). When EVERY
entry is a pattern there is no boundary that can become a target at all, and `load_manual` refuses to
build the engine rather than handing back one that quietly scans nothing -- the discipline already
written down at `main.py:3081`: *"Unknown is not permission. The fix is not to make `load_manual`
tolerant."*

HALF OF THIS FILE IS NEGATIVE CONTROLS, because widening a matcher is the dangerous direction in a
tool whose whole job is to stay inside an authorisation boundary. A plain host must never be read as
a regex (`example.com` must not match `exampleXcom`), a wildcard must keep exactly its old suffix
semantics, and an out-of-scope entry must still win over an in-scope one.
"""
from __future__ import annotations

import asyncio
import os
import tempfile

import pytest

import db as dbmod
import scope as scope_mod
import tools as tools_mod

# The operator's real entries, verbatim from the engagement.
SHOPIFY = [r"^.*\.shopify\.com$", r"^.*\.shopifycs\.com$", r"^.*\.myshopify\.com$"]
# The address that was built out of the first one and handed to every engine.
PATTERN_URL = "https://" + SHOPIFY[0]

LAB = "juice-shop:3000"
LAB_ORIGIN = "http://juice-shop:3000"


# ── the defect ────────────────────────────────────────────────────────────────

def test_a_scope_made_only_of_patterns_is_refused_instead_of_scanning_nothing():
    """MUST FAIL before the fix (no such exception exists; nothing refuses).

    Every entry is a filter, so no target can be derived from any of them. A ScopeEngine built from
    this cannot address anything, and the mission it would have produced is the 18-finding report.
    """
    eng = scope_mod.ScopeEngine()
    with pytest.raises(scope_mod.ScopeConfigurationError) as ex:
        eng.load_manual(list(SHOPIFY), [], "Shopify")
    msg = str(ex.value)
    assert SHOPIFY[0] in msg, "the error must name the entry the operator has to fix: %r" % (msg,)


def test_a_pattern_never_becomes_an_address():
    """MUST FAIL before the fix. MEASURED at HEAD: base_urls() returned the three curl targets.

    A mixed scope, so `load_manual` has a real host to work with and the refusal above is not what is
    being tested here -- this is about which entries can become an address.
    """
    eng = scope_mod.ScopeEngine()
    eng.load_manual([LAB] + SHOPIFY, [], "mixed")

    assert eng.base_urls() == [LAB_ORIGIN], (
        "a regex was emitted as a base URL: %r" % (eng.base_urls(),))
    assert list(eng.base_map()) == ["juice-shop"], (
        "a regex became a base-map host key: %r" % (eng.base_map(),))
    # The exact expression `agent.py:3758` uses to seed subfinder / crtsh / run_dns / run_asn.
    base_roots = [e.value.lower().lstrip("*.") for e in eng.in_scope]
    assert base_roots == ["juice-shop"], (
        "recon would be seeded with a pattern -- this is the self-amplifying half of the defect, and "
        "the reason run_dns reported 'SPF MISSING' for a name that does not exist: %r" % (base_roots,))


def test_the_pattern_string_is_not_in_its_own_scope():
    """MUST FAIL before the fix. MEASURED at HEAD: (True, 'In scope via ^.*\\.shopify\\.com$').

    `_matches` compared literally, so the pattern equalled itself and every engine was authorised to
    connect to it. This is the assertion that makes the whole class impossible: even a driver that
    invents the address cannot get it past the choke point.
    """
    eng = scope_mod.ScopeEngine()
    eng.load_manual([LAB] + SHOPIFY, [], "mixed")
    ok, why = eng.validate(PATTERN_URL)
    assert ok is False, "a regex is still an authorised target: %r" % (why,)


def test_validate_matches_real_hosts_against_those_same_patterns():
    """MUST FAIL before the fix. MEASURED at HEAD: validate('https://www.shopify.com') was (False,
    'www.shopify.com not in scope') -- the operator's own asset, refused, while the pattern was
    allowed. The predicate half of the fix: a pattern is a predicate and must behave like one."""
    eng = scope_mod.ScopeEngine()
    eng.load_manual([LAB] + SHOPIFY, [], "mixed")
    for host in ("https://www.shopify.com", "https://checkout.shopifycs.com",
                 "https://acme.myshopify.com"):
        assert eng.validate(host)[0] is True, "%s is in the operator's scope: %r" % (host, eng.validate(host))
    # and it is ANCHORED -- `.*\.shopify\.com` unanchored would swallow this one
    assert eng.validate("https://www.shopify.com.evil.tld")[0] is False, \
        "the pattern matched a suffix-confusion host, so it is not anchored"


def test_an_out_of_scope_pattern_actually_excludes():
    """MUST FAIL before the fix -- an exclusion that never matches is an exclusion that is not there.

    Host in scope by wildcard, carved out by a pattern. At HEAD the carve-out matched nothing, so the
    host came back authorised.
    """
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["*.example.com"], [r"^admin\..*\.example\.com$"], "carve")
    assert eng.validate("https://admin.eu.example.com")[0] is False, \
        "the operator's exclusion was not enforced"
    assert eng.validate("https://shop.eu.example.com")[0] is True, \
        "the carve-out swallowed a host it does not name"


def test_no_active_engine_can_be_dispatched_at_a_pattern():
    """MUST FAIL before the fix -- the end-to-end statement, through the real ToolRegistry.

    `execute()` runs the real scope check, permission backstop and ledger. Nothing here is stubbed and
    no socket is opened, because the refusal happens before the engine body.
    """
    dbmod.init(os.path.join(tempfile.mkdtemp(), "q096.db"))
    dbmod.create_mission("q096", "Q-096", "active", "o", {"in_scope": [LAB] + SHOPIFY}, {})
    eng = scope_mod.ScopeEngine()
    eng.load_manual([LAB] + SHOPIFY, [], "mixed")
    reg = tools_mod.ToolRegistry(eng, mission_id="q096")

    for tool in ("run_transport_posture", "run_header_trust", "http_probe"):
        res = asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
            reg.execute(tool, {"url": PATTERN_URL, "target": PATTERN_URL}, "s-q096"))
        assert not (res.findings or []), "%s produced findings against a regex: %r" % (tool, res.findings)
        # SCOPE BLOCK specifically, not merely "it failed". `_dispatch_engine` refuses BEFORE
        # `getattr(self, "_"+tool)` is called, so the engine body never runs and no packet is
        # attempted. "It failed anyway" is not the same claim -- Q-097 already makes
        # run_transport_posture return success=False on a dead socket, and a test satisfied by that
        # would still pass on an engine that was dispatched at the pattern and merely could not
        # resolve it.
        assert "SCOPE BLOCK" in (res.error or ""), (
            "%s was DISPATCHED at a regex instead of refused: success=%r error=%r"
            % (tool, res.success, res.error))


# ── negative controls: MUST PASS before AND after ─────────────────────────────

def test_a_real_host_scope_is_completely_unaffected():
    eng = scope_mod.ScopeEngine()
    eng.load_manual([LAB], [], "lab")
    assert eng.base_urls() == [LAB_ORIGIN]
    assert eng.base_map() == {"juice-shop": LAB_ORIGIN}
    assert eng.validate(LAB_ORIGIN + "/rest/products")[0] is True
    assert eng.validate("https://evil.example/admin")[0] is False
    assert [e.asset_type for e in eng.in_scope] == ["domain"]


def test_a_wildcard_keeps_exactly_its_old_semantics():
    """A wildcard is not a regex and must not become one. `*.example.com` matches a subdomain and the
    apex is a separate question; suffix confusion must stay refused."""
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["*.example.com"], [], "wc")
    assert eng.validate("https://a.example.com/x")[0] is True
    assert eng.validate("https://example.com/x")[0] is True      # `lstrip('*.')` semantics, unchanged
    assert eng.validate("https://example.com.evil.tld")[0] is False
    assert eng.validate("https://notexample.com")[0] is False
    assert [e.asset_type for e in eng.in_scope] == ["wildcard"]
    assert eng.base_urls() == [], "a wildcard is not an address either"


def test_a_plain_host_is_never_interpreted_as_a_regex():
    """THE control on the fix itself. `example.com` read as a regex would match `exampleXcom`,
    `example-com` and `exampleacom`, silently widening the authorisation boundary. It must not."""
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["example.com"], [], "plain")
    assert eng.validate("https://example.com")[0] is True
    for imposter in ("https://exampleXcom", "https://example-com", "https://exampleacom"):
        assert eng.validate(imposter)[0] is False, "%s was authorised by regex-reading a plain host" % imposter


def test_an_entry_that_is_neither_a_host_nor_a_pattern_is_refused_by_name():
    """The third state, which nobody had a word for before this ticket.

    An entry is a HOST, a PATTERN, or NEITHER. MEASURED: `_split_scope_entry("[::1]")` returns the
    bare host `"["` -- it splits on `:` before `]`, so IPv6 has never been supported here -- and
    handing `"["` to `re.compile` raises `unterminated character set at position 0`, which is true
    and useless to whoever typed the address. The refusal must name what they wrote.
    """
    for bad in ("[::1]", "my host.com"):
        eng = scope_mod.ScopeEngine()
        with pytest.raises(scope_mod.ScopeConfigurationError) as ex:
            eng.load_manual([LAB, bad], [], "junk")
        assert bad in str(ex.value), "the refusal does not name the entry: %r" % (str(ex.value),)


def test_an_explicit_port_and_path_pin_still_work():
    """SEC-1 / SEC-2 must be untouched by a change to how entries are typed."""
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["https://app.example.com:8443/api/*"], [], "pinned")
    assert eng.validate("https://app.example.com:8443/api/v1/users")[0] is True
    assert eng.validate("https://app.example.com:8443/admin")[0] is False
    assert eng.validate("https://app.example.com:9443/api/v1")[0] is False
