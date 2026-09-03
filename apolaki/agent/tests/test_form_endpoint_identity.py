"""Q-186. A route selector is part of a form's address, and dropping it merged 47 forms into one.

THE FIFTH APPEARANCE of one bug, and the one that kept a command injection hidden after the other
four were fixed:

    Q-172  surface.build_inventory keyed on (host, path)
    Q-174  the form-discovery loop deduped on _abs(u)
    Q-174  ...and its step key dropped the query as well
    Q-185  the form-CAPTURE loop did both again
    Q-186  the graph's endpoint key for a captured form (here)

MEASURED on a mutillidae mission: 47 route pages were probed and their forms captured CORRECTLY,
and then every one collapsed onto the node `mutillidae/index.php`. `_forms_from_graph` rebuilds
recon["forms"] by grouping on that key, so the planner received ONE form whose fields were the
union of all 47 -- 52 names, from `blog_entry` and `background_color` through `target_host` to
`xml` -- with the bare router as its action.

`run_form_cmdi` then POSTed 52 fields to `/index.php` with no `page` parameter, received the home
page, and reported "no body command injection in the page's forms". It was right. The aggregate
described no page that exists.

Only a ROUTE-SHAPED value earns identity, so an ordinary `?q=shoes` search form still merges by
path exactly as before -- otherwise every search term would mint its own endpoint node.
"""
import asyncio

import agent as A
import asset_graph as AG
import scope as S
import tools


def _agent_with_forms(forms):
    sc = S.ScopeEngine()
    sc.load_manual(["t.local"], [], "T")
    t = tools.ToolRegistry(sc, mission_id=None, lab_mode=True)
    t.recon["forms"] = list(forms)
    ag = A.BBHAgent(sc, t, asyncio.Event(), mode="active", mission_id=None)
    g = AG.AssetGraph()
    ag._seed_and_project_graph(g)
    return ag._forms_from_graph(g, {"t.local": "http://t.local"})


ROUTED_FORMS = [
    {"action": "http://t.local/index.php?page=dns-lookup.php", "method": "POST",
     "fields": ["target_host", "dns-lookup-submit"]},
    {"action": "http://t.local/index.php?page=add-to-your-blog.php", "method": "POST",
     "fields": ["blog_entry", "blog-submit"]},
    {"action": "http://t.local/index.php?page=set-background-color.php", "method": "POST",
     "fields": ["background_color", "colour-submit"]},
]


def test_each_routed_form_keeps_its_own_identity():
    """THE regression: three forms on one script must not become one."""
    got = _agent_with_forms(ROUTED_FORMS)
    actions = {str(f.get("action")) for f in got}
    for want in ("dns-lookup.php", "add-to-your-blog.php", "set-background-color.php"):
        assert any(want in a for a in actions), (
            "%s lost its identity and merged into the shared router: %r" % (want, sorted(actions)))


def test_fields_are_not_unioned_across_pages():
    """The damage was not the count, it was the CONTENT: a form describing no real page."""
    got = _agent_with_forms(ROUTED_FORMS)
    for f in got:
        act, flds = str(f.get("action")), list(f.get("fields") or [])
        if "dns-lookup" in act:
            assert "target_host" in flds, flds
            assert "blog_entry" not in flds and "background_color" not in flds, (
                "the dns-lookup form carries fields from other pages: %r" % flds)


def test_an_ordinary_query_form_still_merges_by_path():
    """NEGATIVE CONTROL. Only a route-shaped value earns identity -- otherwise every search term
    would mint its own endpoint node, which is the opposite defect."""
    searches = [
        {"action": "http://t.local/search?q=shoes", "method": "POST", "fields": ["q"]},
        {"action": "http://t.local/search?q=hats", "method": "POST", "fields": ["q"]},
        {"action": "http://t.local/search?q=boots", "method": "POST", "fields": ["q"]},
    ]
    got = _agent_with_forms(searches)
    assert len(got) == 1, (
        "search terms minted separate form identities: %r" % [f.get("action") for f in got])


def test_a_plain_form_is_unchanged():
    got = _agent_with_forms([{"action": "http://t.local/login", "method": "POST",
                              "fields": ["user", "pass"]}])
    assert len(got) == 1
    assert sorted(got[0]["fields"]) == ["pass", "user"]
