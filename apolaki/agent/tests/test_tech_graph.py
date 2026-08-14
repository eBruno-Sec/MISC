"""Q-021B - a TechnologyFact must reach the durable world model, not just a function's return value.

The definition of done for this ticket is a persisted fact: version, source, confidence and
provenance surviving a path that is NOT `fingerprint()`'s return value. That path is
`record_facts` -> `recon["technology"]` -> `build_from_engagement` -> a `component` node -> JSON
on disk -> `load()`.

The node kind is deliberately the EXISTING `component`, with the technology detail as props. Same
instinct as `observe_param`, which put `location` on the param instead of inventing a `schema`
node kind: a dimension on an existing node is schedulable through the path already built and
tested, a new kind is not.
"""
import dependency_intel as di
import fingerprint as fp
from asset_graph import AssetGraph, build_from_engagement


def _recon(url="http://box:3000/", headers=None, now=100.0):
    recon = {"live_hosts": []}
    fp.record_facts(recon, url, headers or {"Server": "nginx/1.18.0"}, "", "", now=now)
    return recon


# ── the fact lands as a component node, with everything on it ──────────────────────────────────
def test_a_fact_becomes_a_component_node_carrying_its_version_and_provenance():
    """ORACLE 2."""
    g = AssetGraph("m1")
    fact = di.make_tech_fact("nginx", version="1.18.0", source="Server header",
                             detector="fingerprint.headers", category="server",
                             evidence="Server: nginx/1.18.0", location="http://box:3000/",
                             host="box:3000", now=100.0)
    nid = g.observe_technology(fact, scope_asset="box:3000")
    node = g.node(nid)
    assert node["kind"] == "component"
    p = node["props"]
    assert p["version"] == "1.18.0"
    assert p["product"] == "nginx"
    assert p["vendor"] == "nginx"
    assert p["detection_source"] == "Server header", \
        "which HTTP artifact proved it - distinct from the node's `sources`, which is which PHASE " \
        "contributed the node"
    assert [s["source"] for s in node["sources"]] == ["fingerprint"]
    assert p["detector"] == "fingerprint.headers"
    assert p["evidence"] == "Server: nginx/1.18.0"
    assert p["source_url"] == "http://box:3000/"
    assert p["version_confidence"] == di.LOW
    assert p["cve_eligible"] is False
    assert p["proof_state"] == di.VERSION_SUSPECTED
    assert p["component_status"] == di.POTENTIALLY_AFFECTED
    assert p["authenticated"] is False
    assert p["observed_first"] == 100.0 and p["observed_last"] == 100.0
    assert node["label"] == "nginx 1.18.0"
    assert node["scope_asset"] == "box:3000"


def test_the_host_that_runs_it_is_linked():
    g = AssetGraph("m1")
    fact = di.make_tech_fact("nginx", version="1.18.0", source="Server header", host="box:3000",
                             now=1.0)
    nid = g.observe_technology(fact)
    assert g.node("host:box:3000") is not None
    assert nid in g.neighbors("host:box:3000", "runs")


def test_a_detection_is_never_stored_as_a_verified_fact():
    """The graph's CONFIRMED (1.0) means VERIFIED. Detection is an observation, so the strongest a
    fact may reach is HIGH - and a spoofable banner sits at the bottom rung."""
    from asset_graph import CONFIRMED as G_CONFIRMED, HIGH as G_HIGH, LOW as G_LOW, MEDIUM as G_MEDIUM
    g = AssetGraph("m1")
    banner = di.make_tech_fact("nginx", version="1.18.0", source="Server header", host="h", now=1.0)
    served = di.make_tech_fact("jquery", version="3.4.1", source="js-content-banner", host="h", now=1.0)
    path = di.make_tech_fact("bootstrap", version="3.3.7", source="script-filename", host="h", now=1.0)
    assert g.node(g.observe_technology(banner))["confidence"] == G_LOW
    assert g.node(g.observe_technology(path))["confidence"] == G_MEDIUM
    assert g.node(g.observe_technology(served))["confidence"] == G_HIGH
    assert all(n["confidence"] < G_CONFIRMED for n in g.nodes("component"))
    assert all(n["tested"] is False for n in g.nodes("component")), \
        "nothing has been tested; detection is not a test"


def test_the_node_key_is_identity_so_two_products_never_collide():
    """CONTROL. Same version, two products, one host."""
    g = AssetGraph("m1")
    a = g.observe_technology(di.make_tech_fact("AlphaCMS", version="2.1.0", source="meta generator",
                                               host="h", now=1.0))
    b = g.observe_technology(di.make_tech_fact("BetaCMS", version="2.1.0", source="meta generator",
                                               host="h", now=1.0))
    assert a != b
    assert len(g.nodes("component")) == 2


def test_re_observing_one_technology_is_one_node():
    g = AssetGraph("m1")
    for _ in range(3):
        g.observe_technology(di.make_tech_fact("nginx", version="1.18.0", source="Server header",
                                               host="h", now=1.0))
    assert len(g.nodes("component")) == 1


def test_a_junk_fact_is_refused_rather_than_stored_as_an_empty_node():
    g = AssetGraph("m1")
    assert g.observe_technology(None) == ""
    assert g.observe_technology({"host": "h"}) == "", "a fact with no product has no identity"
    assert g.nodes("component") == []


# ── through the engagement projection, which is the real path ──────────────────────────────────
def test_build_from_engagement_projects_recon_technology():
    """The seam that was missing. `recon` already reaches `build_from_engagement`; before this it
    carried nothing but display strings."""
    g = build_from_engagement("m1", recon=_recon(), urls=[], findings=[])
    comps = g.nodes("component")
    assert len(comps) == 1
    assert comps[0]["props"]["version"] == "1.18.0"
    assert comps[0]["props"]["detection_source"] == "Server header"


def test_the_projection_survives_save_and_load():
    """ORACLE 2, durably. A fact that does not survive JSON is not persisted, it is cached."""
    import tempfile
    d = tempfile.mkdtemp()
    g = build_from_engagement("m1", recon=_recon(), urls=[], findings=[])
    assert g.save(base_dir=d)
    reloaded = AssetGraph.load("m1", base_dir=d)
    comps = reloaded.nodes("component")
    assert len(comps) == 1
    p = comps[0]["props"]
    assert p["version"] == "1.18.0"
    assert p["version_confidence"] == di.LOW
    assert p["evidence"] == "Server: nginx/1.18.0"
    assert p["detector"] == "fingerprint.headers"
    assert p["observed_first"] == 100.0


def test_an_engagement_with_no_technology_projects_nothing_and_does_not_error():
    """CONTROL (c) at the graph layer: a real zero, not a crash and not a phantom node."""
    for recon in ({}, {"technology": []}, {"technology": None}, {"technology": "garbage"}):
        g = build_from_engagement("m1", recon=recon, urls=[], findings=[])
        assert g.nodes("component") == []


def test_the_display_list_is_not_read_by_the_projection():
    """REGRESSION. `live_hosts[i]["tech"]` stays a display list; it must not become a second, weaker
    source of component nodes now that a real one exists."""
    g = build_from_engagement("m1", recon={"live_hosts": [{"url": "http://box/", "tech": ["nginx"]}]},
                              urls=[], findings=[])
    assert g.nodes("component") == []


# ── has_versions must mean what it says ────────────────────────────────────────────────────────
def test_has_versions_needs_an_actual_version():
    """A versionless detection is a real fact and must NOT make the planner believe it knows a
    version. `Server: nginx` is exactly that case."""
    g = build_from_engagement("m1", recon=_recon(headers={"Server": "nginx"}), urls=[], findings=[])
    assert len(g.nodes("component")) == 1
    assert "has_versions" not in g.to_observations()


def test_has_versions_fires_when_a_version_is_actually_known():
    g = build_from_engagement("m1", recon=_recon(), urls=[], findings=[])
    assert "has_versions" in g.to_observations()


def test_legacy_component_nodes_still_count_as_versions():
    """REGRESSION. `ingest_intel` keys a component node ON the harvested version string and stores no
    `version` prop. Requiring the prop would have silently switched that observation off."""
    g = AssetGraph("m1")
    g.ingest_intel({"candidates": {"version": ["jquery@3.4.1"]}})
    assert g.nodes("component") and "version" not in (g.nodes("component")[0]["props"] or {})
    assert "has_versions" in g.to_observations()


def test_a_mixed_graph_reports_has_versions_once_any_version_is_known():
    g = build_from_engagement("m1", recon=_recon(headers={"Server": "nginx"}), urls=[], findings=[])
    g.ingest_intel({"candidates": {"version": ["jquery@3.4.1"]}})
    assert "has_versions" in g.to_observations()


# ── end to end: response bytes -> durable graph, without touching fingerprint()'s return value ──
def test_end_to_end_a_served_version_reaches_disk():
    """The definition of done for Q-021B, in one test."""
    import tempfile
    d = tempfile.mkdtemp()
    recon = {"live_hosts": []}
    body = '<script src="/assets/jquery-3.4.1.min.js"></script>'
    fp.record_facts(recon, "http://box:3000/", {"Server": "nginx/1.18.0"}, "", body, now=42.0)
    g = build_from_engagement("mission-e2e", recon=recon, urls=["http://box:3000/"], findings=[])
    g.save(base_dir=d)

    props = {n["props"]["product"]: n["props"] for n in AssetGraph.load("mission-e2e", base_dir=d).nodes("component")}
    assert props["nginx"]["version"] == "1.18.0"
    assert props["nginx"]["cve_eligible"] is False, "a banner may not pull CVEs"
    assert props["jquery"]["version"] == "3.4.1"
    assert props["jquery"]["version_confidence"] == di.HIGH
    assert props["jquery"]["cve_eligible"] is True, "a versioned filename may"
    assert all(p["component_status"] == di.POTENTIALLY_AFFECTED for p in props.values()), \
        "nothing here has been probed, so nothing may be AFFECTED"
