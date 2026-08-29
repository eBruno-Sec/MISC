"""Q-122 + Q-118 - the third road into the phantom parameters, and the bypass that made a road.

Q-122 IS MY OWN FIX FAILING, and the shape of the failure is the reusable part.

Q-111 fixed the PRODUCER (`intel._add_ref` unescapes markup). Q-111b fixed the URL INTAKE
(`html.unescape` in `_add_urls`) because a producer fix cannot clean history. The operator's next
run -- on a build carrying BOTH -- still raised three findings on parameters that do not exist, and
his report shows why in one string:

    https://admin.shopify.com/signup?locale=en&amp%3Blanguage=domtr...&amp%3Bsignup_page=...

`amp%3B`. The semicolon is PERCENT-ENCODED. There is no `&amp;` text left for `html.unescape` to
find: the split into the literal token `amp;language` already happened upstream, and the URL was
then REBUILT -- `urlencode` over a `parse_qsl` result escapes the `;` -- producing a well-formed URL
that both earlier fixes inspect and correctly find nothing wrong with.

I fixed the road I had already been looking at. The repair has to happen on the PARSED NAME, and
`amp;` as a literal prefix is diagnostic: to actually send a parameter named `amp;x` a client must
encode the ampersand, which arrives as `&amp;x` after decoding, never as `amp;x`.

Q-118 is the second half and the reason this is one file. `agent.py` mined code-intelligence
endpoints into `tools.urls` with its OWN append loop, having retrofitted exactly one of `_add_urls`'s
four guarantees (the session-kill quarantine). The other three -- `clean_url`, `scope.validate`, and
now the entity repair -- were simply absent, so a mined endpoint entered the surface every other
reader treats as clean without ever being checked against the operator's scope. On a bug-bounty
engagement that is the guarantee that matters most, and a fix to the chokepoint is worth nothing
while a producer can walk around it.

BOTH HALVES ASSERT THE SECOND PROPERTY: the REAL parameters behind the entity must survive. A repair
that stopped emitting `amp;language` while also losing `language` would trade a false positive for a
blind spot, which is the failure Q-111's own gate was written against.
"""
from urllib.parse import parse_qs, urlparse

import scope as scope_mod
import tools


def _registry():
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["x.test"], [], "t")
    return tools.ToolRegistry(eng, mission_id="q122", lab_mode=True)


def _params(url):
    return set(parse_qs(urlparse(url).query, keep_blank_values=True))


# -- Q-122: the field case, which is the one both earlier fixes miss --------------

def test_the_percent_encoded_split_from_the_field_is_repaired():
    """VERBATIM from the operator's report. `html.unescape` is a no-op on this string, which is
    exactly why Q-111b did not close the ticket."""
    reg = _registry()
    reg._add_urls(["https://x.test/signup?locale=en&amp%3Blanguage=fr"
                   "&amp%3Bsignup_page=%2Fhome&amp%3Bsignup_types%5B%5D=paid"])
    got = _params(reg.urls[0])
    assert not [p for p in got if p.startswith("amp;")], got


def test_the_real_parameters_behind_the_entity_are_recovered_not_dropped():
    """THE HALF THAT MATTERS. Suppressing the phantom while losing the real parameter would trade a
    false positive for a blind spot."""
    reg = _registry()
    reg._add_urls(["https://x.test/signup?locale=en&amp%3Blanguage=fr&amp%3Bsignup_page=%2Fhome"])
    assert {"locale", "language", "signup_page"} == _params(reg.urls[0])


def test_the_still_raw_entity_is_also_repaired():
    """Q-111b's case must keep working. The unescape runs first and this runs after; neither
    subsumes the other, so both roads are asserted in one place."""
    reg = _registry()
    reg._add_urls(["https://x.test/p?locale=en&amp;language=fr"])
    assert {"locale", "language"} == _params(reg.urls[0])


def test_a_double_encoded_entity_is_repaired_too():
    """`&amp;amp;` is ordinary in markup that has been escaped twice, and it welds `amp;amp;` to the
    name. Chasing one encoding depth is how Q-106 needed a second round."""
    reg = _registry()
    reg._add_urls(["https://x.test/p?a=1&amp%3Bamp%3Blanguage=fr"])
    assert {"a", "language"} == _params(reg.urls[0])


# -- the negative controls -------------------------------------------------------

def test_a_clean_url_is_returned_byte_identical():
    """Rebuilding a URL changes its identity for de-duplication, so the repair must not fire on the
    99%. Byte-identical, not merely equivalent."""
    reg = _registry()
    clean = "https://x.test/p?a=1&b=2&c=%2Fhome%3Fx%3D1"
    reg._add_urls([clean])
    assert reg.urls == [clean], reg.urls


def test_a_url_with_no_query_is_untouched():
    reg = _registry()
    reg._add_urls(["https://x.test/just/a/path"])
    assert reg.urls == ["https://x.test/just/a/path"], reg.urls


def test_a_parameter_merely_containing_amp_is_not_mangled():
    """`amp` is a real word. The signature is the `amp;` prefix, not the substring, or a parameter
    named `ampersand` or `lamp` loses its name."""
    reg = _registry()
    reg._add_urls(["https://x.test/p?lamp=1&ampersand=2&amplitude=3"])
    assert {"lamp", "ampersand", "amplitude"} == _params(reg.urls[0])


def test_a_value_containing_amp_semicolon_is_left_alone():
    """The repair is on NAMES. A value may legitimately carry anything."""
    reg = _registry()
    reg._add_urls(["https://x.test/p?q=amp%3Bnot-a-param"])
    assert parse_qs(urlparse(reg.urls[0]).query)["q"] == ["amp;not-a-param"]


# -- Q-118: the bypass that let a producer skip all of the above ------------------

def test_the_code_intelligence_append_no_longer_bypasses_the_intake():
    """NO ISLANDS, asserted structurally because the alternative is driving a whole harvest. The
    defect was a second writer to `tools.urls`; the fix is that there is only one again."""
    import inspect

    import agent as agent_mod
    src = inspect.getsource(agent_mod)
    assert "self.tools.urls.append(" not in src, (
        "something appends to tools.urls past _add_urls, so clean_url / scope.validate / the "
        "entity repair / the session-kill quarantine are all optional again")


def test_add_urls_is_the_only_writer_in_the_tools_module():
    """The other half of the same invariant. `_add_urls` may of course append to its own list;
    nothing else in the module may."""
    import inspect

    src = inspect.getsource(tools)
    appends = [ln for ln in src.splitlines() if "self.urls.append(" in ln]
    assert len(appends) == 1, appends


def test_an_out_of_scope_mined_endpoint_never_reaches_the_surface():
    """The guarantee the bypass was actually costing. `scope.validate` is the one that matters on a
    bug-bounty engagement: a request to a host nobody authorised."""
    reg = _registry()
    reg._add_urls(["https://evil.example/mined/from/js", "https://x.test/mined/from/js"])
    assert reg.urls == ["https://x.test/mined/from/js"], reg.urls


# -- Q-125: the fix that was corrupting the surface it protected -----------------
#
# `html.unescape` decodes a named reference WITHOUT its semicolon -- correct for HTML text content,
# catastrophic for a query string, where every parameter name is preceded by `&`. Q-111 and Q-111b
# both shipped that blanket call. MEASURED in one line:
#
#     in       ?lamp=1&ampersand=2&amplitude=3
#     blanket  ?lamp=1&ersand=2&litude=3
#
# `copy`, `reg`, `sect`, `not`, `times`, `lt`, `gt`, `para`, `sup`, `deg`, `micro` are all real
# parameter names and all legacy entities. Requiring the semicolon IS the HTML5 attribute-value rule,
# which is why a browser given `<a href="?ampersand=2">` requests `ampersand`, not `ersand`.

_LEGACY_ENTITY_NAMES = ("times", "lt", "gt", "copy", "reg", "sect", "not", "para", "sup", "deg",
                        "micro", "amp", "quot", "middot", "plusmn")


def test_no_legacy_entity_named_parameter_is_corrupted():
    """THE REGRESSION, as a family rather than as the one example I happened to hit. Every one of
    these is a plausible real parameter name AND an HTML5 legacy entity."""
    reg = _registry()
    q = "&".join("%s=%d" % (n, i) for i, n in enumerate(_LEGACY_ENTITY_NAMES))
    reg._add_urls(["https://x.test/p?" + q])
    assert _params(reg.urls[0]) == set(_LEGACY_ENTITY_NAMES), _params(reg.urls[0])


def test_a_parameter_name_that_merely_starts_with_an_entity_name_survives():
    """`ampersand` and `amplitude` are the measured casualties, verbatim."""
    reg = _registry()
    reg._add_urls(["https://x.test/p?ampersand=2&amplitude=3&copyright=4&notation=5"])
    assert _params(reg.urls[0]) == {"ampersand", "amplitude", "copyright", "notation"}


def test_the_semicolon_terminated_entity_still_decodes():
    """NON-VACUITY. Refusing to decode anything would pass every test above and reopen Q-111.
    `&amp;` is what every HTML escaper emits for a literal `&` and is the only case that mattered."""
    import surface as surface_mod
    assert surface_mod.unescape_url_entities("?a=1&amp;b=2") == "?a=1&b=2"
    assert surface_mod.unescape_url_entities("?a=1&#38;b=2") == "?a=1&b=2"
    assert surface_mod.unescape_url_entities("?a=1&#x26;b=2") == "?a=1&b=2"


def test_the_unsemicoloned_reference_is_left_alone():
    """The discriminator, stated on its own: identical entity NAME, the only difference is the
    semicolon, and that is exactly the line between markup escaping and a parameter."""
    import surface as surface_mod
    assert surface_mod.unescape_url_entities("?x=1&amp;y=2") == "?x=1&y=2"
    assert surface_mod.unescape_url_entities("?x=1&ampy=2") == "?x=1&ampy=2"


def test_neither_chokepoint_uses_the_blanket_decoder_any_more():
    """NO ISLANDS. Both producers shipped the same wrong call, so pinning one would leave the other.
    `intel._add_ref` is where markup becomes a URL; `tools._add_urls` is the surface intake."""
    import inspect

    import intel as intel_mod
    for mod, name in ((intel_mod, "intel"), (tools, "tools")):
        # CODE lines only. The first draft of this test grepped the whole module and failed on the
        # comment explaining the fix -- a guard that cannot tell code from prose.
        code = [ln for ln in inspect.getsource(mod).splitlines()
                if not ln.lstrip().startswith("#")]
        for bad in ("_html_mod.unescape(ref", "_html.unescape(u)"):
            hits = [ln for ln in code if bad in ln]
            assert not hits, "%s still blanket-unescapes a URL: %s" % (name, hits)


def test_the_producer_recovers_the_real_parameter_from_markup():
    """END TO END on the producer side, which is where Q-111 lives. An entity-encoded href must
    still yield the REAL parameters and no phantom."""
    import intel as intel_mod
    store = intel_mod.IntelStore()
    intel_mod._add_ref("https://x.test/p?locale=en&amp;language=fr&amp;ampersand=1", "t", store)
    got = set(store.get("param"))
    assert {"locale", "language", "ampersand"} <= got, got
    assert not [p for p in got if p.startswith("amp;")], got
