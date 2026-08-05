"""Prototype-pollution GADGET discovery (pure logic): confirming pollution proves the source; a real
DOM-XSS/redirect needs a gadget property that a sink reads. Here we test the target-derived property
harvest, the bounded probe generator, and the confirmed-finding builder. Browser confirmation is
exercised in-mission (tools._run_dom_audit), not here."""
import blind_benchmark as bb
import dom_tool as dom


def test_harvest_ranks_sink_adjacent_props_first():
    js = """
      var cfg = {};
      function boot(o){ var s=document.createElement('script'); s.src = o.transport_url; document.body.appendChild(s); }
      var label = data.title;           // benign, far from a sink
      el.innerHTML = opts.widget_html;  // sink-adjacent
    """
    props = dom.harvest_gadget_props(js, cap=8)
    assert "transport_url" in props and "widget_html" in props
    # sink-adjacent gadgets outrank the benign 'title'
    assert props.index("transport_url") < props.index("title")
    # builtins are excluded
    assert "createElement" not in props and "appendChild" not in props and "length" not in props


def test_harvest_bounded_and_deduped():
    js = ".src .src .src .href .href .url"
    out = dom.harvest_gadget_props(js, cap=2)
    assert len(out) == 2 and len(set(out)) == 2


def test_gadget_probes_cover_flavors_and_sources():
    probes = dom.gadget_probes("https://x/blog?a=1", extra_props=["transport_url"], cap=4)
    flavors = {p["flavor"] for p in probes}
    srcs = {p["src"] for p in probes}
    assert flavors == {"exec", "resource", "nav"} and srcs == {"hash", "query"}
    # harvested prop is probed first
    assert probes[0]["prop"] == "transport_url"
    # every nav is a real crafted URL carrying the __proto__ pollution
    assert all("__proto__" in p["nav"] for p in probes)


def test_gadget_exec_flavor_confirms_dom_xss_on_dialog():
    probe = next(p for p in dom.gadget_probes("https://x/blog", extra_props=["transport_url"])
                 if p["flavor"] == "exec")
    f = dom.build_finding(probe, dialog_msg="/%s/" % dom.MARK)
    assert f is not None and f["family"] == "dom_xss"
    assert "transport_url" in f["title"]
    assert bb.finding_family(f) == "dom_xss" and bb._has_proof(f)
    assert f["cvss_score"] == 6.1 and f["severity"] == "medium"


def test_gadget_resource_flavor_confirms_dom_xss_on_attacker_request():
    probe = next(p for p in dom.gadget_probes("https://x/blog", extra_props=["transport_url"])
                 if p["flavor"] == "resource")
    # the gadget loaded a script from the attacker host (non-navigation request)
    f = dom.build_finding(probe, evil_reqs=["https://%s/%s.js" % (dom.EVIL, dom.MARK)])
    assert f is not None and f["family"] == "dom_xss"
    assert bb.finding_family(f) == "dom_xss" and bb._has_proof(f)


def test_gadget_nav_flavor_confirms_open_redirect_on_navigation():
    probe = next(p for p in dom.gadget_probes("https://x/blog", extra_props=["redirect"])
                 if p["flavor"] == "nav")
    f = dom.build_finding(probe, nav_targets=["https://%s/x" % dom.EVIL])
    assert f is not None and f["family"] == "open_redirect"
    assert bb.finding_family(f) == "open_redirect" and bb._has_proof(f)


def test_gadget_no_sink_fire_is_not_a_finding():
    probe = dom.gadget_probes("https://x/blog", extra_props=["transport_url"])[0]
    # no dialog, no navigation, no attacker-host request -> no false positive
    assert dom.build_finding(probe, dialog_msg=None, nav_targets=["https://x/blog"], evil_reqs=[]) is None
    # a same-origin request must NOT be mistaken for the attacker host
    res = next(p for p in dom.gadget_probes("https://x/blog", extra_props=["transport_url"])
               if p["flavor"] == "resource")
    assert dom.build_finding(res, evil_reqs=["https://x/legit.js"]) is None
