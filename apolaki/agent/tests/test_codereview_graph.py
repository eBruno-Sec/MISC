"""Code review as pre-recon (#114 Part 2): static source review seeds the ONE engagement graph with
CANDIDATE facts (never confirmed findings), the planner validates them (white->black), and a runtime
confirmation links back to the exact source location (black->white). Boundaries enforced. Pure."""
import codereview
import codereview_graph as CRG
import asset_graph as AG

_SRC = '''
const AWS_KEY = "AKIA1234567890ABCDEF";
function run(userInput){ eval(userInput); }
fetch("/api/admin/config");
'''


def _seeded():
    g = AG.AssetGraph("m")
    CRG.seed(g, codereview.review(_SRC, "app.js"), scope_asset="app")
    return g


def test_seed_projects_static_facts_with_boundaries():
    g = _seeded()
    # endpoint: STATIC, reachable UNVERIFIED (never assumed reachable), provenance code_review
    eps = g.nodes("endpoint")
    assert eps and any("/api" in (e.get("label") or "") for e in eps)
    p = eps[0].get("props") or {}
    assert p.get("evidence_kind") == "static" and p.get("reachable") == "unverified"
    assert eps[0]["sources"][0]["source"] == "code_review"
    # sink: CANDIDATE hypothesis with vuln-class + source location, confidence <= 0.3
    sinks = g.nodes("sink")
    assert sinks
    sp = sinks[0].get("props") or {}
    assert sp.get("vuln_class") and str(sp.get("source_location", "")).startswith("app.js")
    assert sinks[0]["confidence"] <= 0.3
    # secret: DISTINCT source_secret (hash only), not auto-tested, NOT the runtime credential kind
    secs = g.nodes("source_secret")
    assert secs and secs[0]["label"] == "source-secret" and secs[0].get("tested") is False
    assert (secs[0].get("props") or {}).get("external_test") == "requires_authorization"
    assert not g.nodes("credential")


def test_no_raw_secret_leaks_into_the_graph():
    g = _seeded()
    assert "AKIA1234567890ABCDEF" not in str(g.to_dict())


def test_seeded_endpoint_feeds_the_planner_observation_vocabulary():
    # white -> black: a code-discovered /api endpoint becomes a planner observation to validate at runtime
    assert "has_api" in _seeded().to_observations()


def test_link_runtime_to_source_cross_references_black_to_white():
    g = _seeded()
    vc = (g.nodes("sink")[0].get("props") or {}).get("vuln_class")
    locs = CRG.link_runtime_to_source(g, vc)
    assert locs and str(locs[0]).startswith("app.js")
    assert (g.nodes("sink")[0].get("props") or {}).get("confirmed_at_runtime") is True
    assert CRG.hypotheses(g)[0]["confirmed_at_runtime"] is True


def test_build_from_engagement_accepts_and_seeds_code_review():
    g = AG.build_from_engagement("m", code_review=codereview.review(_SRC, "app.js"), scope_asset="app")
    assert g.nodes("sink") and g.nodes("source_secret") and g.nodes("endpoint")
