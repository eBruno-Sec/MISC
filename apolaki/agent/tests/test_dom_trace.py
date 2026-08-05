"""DOM source-to-sink tracer pure logic: classify() maps runtime signals to confirmed families, and
finding() builds a well-formed confirmed finding. Covers the request_url_override family (client-side
request forgery: a param that overrides a script-initiated fetch/XHR target) added alongside the existing
dom_xss / open_redirect / dom_link / dom_data families. Runtime rendering is exercised in-mission, not here."""
import blind_benchmark as bb
import dom_trace as dt


def test_classify_request_url_override():
    sig = {"executed": False, "redirect": "", "req_override": "https://evilcabcd1234.example/steal",
           "reqov_target": "https://x/api?url=https://evilcabcd1234.example/steal",
           "in_href": "", "in_src": "", "in_attr": "", "in_text": False}
    hits = dt.classify("https://x/api?url=1", "url", "domtrabcd1234", sig)
    fams = [h["family"] for h in hits]
    assert "request_url_override" in fams
    h = next(h for h in hits if h["family"] == "request_url_override")
    assert h["target"] == sig["reqov_target"]
    assert "fetch/XHR" in h["evidence"]


def test_classify_navigation_is_redirect_not_override():
    sig = {"executed": False, "redirect": "https://evilcabcd1234.example/", "req_override": "",
           "in_href": "", "in_src": "", "in_attr": "", "in_text": False}
    fams = [h["family"] for h in dt.classify("https://x/go?next=1", "next", "domtrabcd1234", sig)]
    assert "open_redirect" in fams and "request_url_override" not in fams


def test_classify_orders_most_severe_first_and_dom_xss_wins():
    sig = {"executed": True, "redirect": "", "req_override": "",
           "in_href": "A:/x", "in_src": "", "in_attr": "", "in_text": True}
    hits = dt.classify("https://x/p?q=1", "q", "domtrabcd1234", sig)
    assert hits[0]["family"] == "dom_xss"


def test_request_url_override_finding_shape_and_benchmark_family():
    hit = {"family": "request_url_override", "param": "url",
           "target": "https://x/api?url=https://evilcabcd1234.example/s", "canary": "domtrabcd1234",
           "evidence": "param 'url' overrides a client-side fetch/XHR request target at runtime: https://evilcabcd1234.example/s"}
    f = dt.finding(hit)
    assert f["confidence"] == "confirmed"
    assert f["family"] == "request_url_override"
    assert f["cwe"] == "CWE-918"
    assert f["cvss_score"] == 5.4 and f["severity"] == "medium"
    # the benchmark canonicalises it to the same family AND accepts it as proof
    assert bb.finding_family(f) == "request_url_override"
    assert bb._has_proof(f)


def test_run_dom_trace_skips_static_assets():
    """The tracker.gif DOM link/data false positives came from probing a static image endpoint. dom_trace
    must skip static assets (no DOM sinks live there) and return zero findings without launching a browser."""
    import asyncio
    import tools as tools_mod
    from scope import ScopeEngine
    sc = ScopeEngine()
    sc.load_manual(["ginandjuice.shop"], [], "unit")
    tr = tools_mod.ToolRegistry(sc, mission_id="unit")
    for u in ("https://ginandjuice.shop/resources/images/tracker.gif?searchTerms=x",
              "https://ginandjuice.shop/resources/css/app.css?v=1",
              "https://ginandjuice.shop/analytics/collect?u=1"):
        res = asyncio.run(tr._run_dom_trace({"url": u}))
        assert res.success and res.findings == [], u
        assert "static asset" in res.output


def test_finding_has_oracle_and_repro():
    f = dt.finding({"family": "open_redirect", "param": "next",
                    "target": "https://x/go?next=https://evilcabcd1234.example/",
                    "canary": "domtrabcd1234", "evidence": "navigation to attacker host from param 'next': ..."})
    assert f["success_oracle"] and f["reproduction_steps"]
    assert bb.finding_family(f) == "open_redirect"
