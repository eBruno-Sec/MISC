"""Q-021B, the producer half - `tools._run_fingerprint` must stop discarding the version.

This is the line the whole ticket was named after. The fact model, the ladder, the identity dedupe
and the graph projection all existed and were tested, and every one of them was INERT while this
one call kept `[t["name"] for t in techs]` and dropped the rest. A record type nothing produces is
an island; this suite is what stops this ticket from becoming the ninth.

The transport is stubbed, so these are deterministic. The LIVE-mission proof is separate and is
recorded in docs/handoff/tech_intel.md.
"""
import asyncio

import dependency_intel as di
import scope
import tools


HDRS = {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3", "Set-Cookie": "PHPSESSID=abc123"}
BODY = '<script src="/assets/jquery-3.4.1.min.js"></script>'
PROSE = ("This deployment is running a MultiJuicer Kubernetes cluster in safety mode. "
         "powered by nothing on.")


def _reg():
    sc = scope.ScopeEngine()
    sc.load_manual(["box:3000"], [], "T")
    return tools.ToolRegistry(sc, lab_mode=True)


def _run(headers=None, body="", url="http://box:3000/", session_headers=None):
    reg = _reg()
    if session_headers:
        reg.session_headers = session_headers

    async def fake_http(u, method="GET", headers_=None, body_=None, capture=True, finding_id=None):
        return {"status": 200, "headers": dict(headers or {}), "body": body,
                "length": len(body), "final_url": url}

    reg._http = fake_http
    return reg, asyncio.new_event_loop().run_until_complete(reg._run_fingerprint({"url": url}))


# ── THE defect: the version now survives the call ──────────────────────────────────────────────
def test_the_producer_persists_the_version_it_computes():
    reg, r = _run(HDRS, BODY)
    assert r.success
    facts = {f["product"]: f for f in reg.recon["technology"]}
    assert set(facts) == {"nginx", "php", "jquery"}
    assert facts["nginx"]["version"] == "1.18.0"
    assert facts["nginx"]["source"] == "Server header"
    assert facts["nginx"]["evidence"] == "Server: nginx/1.18.0"
    assert facts["nginx"]["detector"] == "fingerprint.headers"
    assert facts["nginx"]["host"] == "box:3000"
    assert facts["php"]["version"] == "7.4.3"
    assert facts["jquery"]["version"] == "3.4.1"


def test_the_confidence_ladder_travels_with_the_fact():
    """A banner and a versioned filename are not equally trustworthy, and the producer must not
    flatten that distinction on the way into recon."""
    reg, _ = _run(HDRS, BODY)
    facts = {f["product"]: f for f in reg.recon["technology"]}
    assert facts["nginx"]["version_confidence"] == di.LOW
    assert di.cve_eligible(facts["nginx"]) is False
    assert facts["jquery"]["version_confidence"] == di.HIGH
    assert di.cve_eligible(facts["jquery"]) is True
    assert all(f["component_status"] == di.POTENTIALLY_AFFECTED for f in reg.recon["technology"])


def test_the_producer_records_refusals_rather_than_dropping_them():
    reg, r = _run({}, PROSE)
    assert r.success
    assert reg.recon["technology"] == []
    assert {x["reason"] for x in reg.recon["technology_rejected"]} == \
        {"prose_leading_stopword", "trailing_sentence_punctuation"}
    assert all(x["detector"] == "fingerprint.body.prose" for x in reg.recon["technology_rejected"])


def test_authenticated_scans_mark_their_facts():
    reg, _ = _run(HDRS, "", session_headers={"Cookie": "session=x"})
    assert reg.recon["technology"] and all(f["authenticated"] is True for f in reg.recon["technology"])


def test_an_unauthenticated_scan_does_not_claim_authentication():
    reg, _ = _run(HDRS, "")
    assert all(f["authenticated"] is False for f in reg.recon["technology"])


def test_two_hosts_accumulate_as_two_facts_not_one():
    reg = _reg()

    async def http_a(u, method="GET", **kw):
        return {"status": 200, "headers": {"Server": "nginx/1.18.0"}, "body": "",
                "length": 0, "final_url": "http://a:3000/"}

    async def http_b(u, method="GET", **kw):
        return {"status": 200, "headers": {"Server": "nginx/1.25.0"}, "body": "",
                "length": 0, "final_url": "http://b:3000/"}

    loop = asyncio.new_event_loop()
    reg._http = http_a
    loop.run_until_complete(reg._run_fingerprint({"url": "http://a:3000/"}))
    reg._http = http_b
    loop.run_until_complete(reg._run_fingerprint({"url": "http://b:3000/"}))
    assert sorted(f["host"] for f in reg.recon["technology"]) == ["a:3000", "b:3000"]
    assert sorted(f["version"] for f in reg.recon["technology"]) == ["1.18.0", "1.25.0"]


def test_refingerprinting_one_host_is_one_fact():
    reg = _reg()

    async def fake_http(u, method="GET", **kw):
        return {"status": 200, "headers": HDRS, "body": "", "length": 0,
                "final_url": "http://box:3000/"}

    reg._http = fake_http
    loop = asyncio.new_event_loop()
    for _ in range(3):
        loop.run_until_complete(reg._run_fingerprint({"url": "http://box:3000/"}))
    assert len(reg.recon["technology"]) == 2


def test_a_target_with_no_identifying_bytes_yields_a_real_zero():
    """CONTROL (c) at the producer. Zero facts, zero refusals, no error - distinguishable from a
    detector that crashed."""
    reg, r = _run({}, "<html><body>hello</body></html>")
    assert r.success
    assert reg.recon["technology"] == []
    assert reg.recon["technology_rejected"] == []


def test_a_transport_error_persists_nothing():
    reg = _reg()

    async def broken(u, method="GET", **kw):
        return {"error": "connect timeout", "status": 0, "headers": {}, "body": "",
                "length": 0, "final_url": u}

    reg._http = broken
    r = asyncio.new_event_loop().run_until_complete(reg._run_fingerprint({"url": "http://box:3000/"}))
    assert r.success is False
    # `in (None, [])` would have passed here whether or not the keys were declared -- measured, it
    # left the mutant that deletes the declaration alive. Both keys must EXIST and be empty, so no
    # consumer ever has to tell "nothing was detected" from "the key was never created". That falsy
    # -default shape has bitten this codebase twice.
    assert reg.recon["technology"] == []
    assert reg.recon["technology_rejected"] == []


def test_the_technology_keys_exist_before_anything_is_fingerprinted():
    reg = _reg()
    assert reg.recon["technology"] == []
    assert reg.recon["technology_rejected"] == []


# ── everything the producer did before, unchanged ──────────────────────────────────────────────
def test_the_display_list_keeps_its_bare_string_shape():
    """REGRESSION. `live_hosts[i]["tech"]` is read by the UI and by report.py's delta section."""
    reg, _ = _run(HDRS, BODY)
    lh = [h for h in reg.recon["live_hosts"] if h["url"] == "http://box:3000/"][0]
    assert lh["tech"] == ["nginx", "PHP", "jQuery"]


def test_the_tool_payload_still_carries_four_key_technology_dicts():
    """REGRESSION. The `{"technologies": techs}` payload is a public tool result; adding `evidence`
    to it would change a shape other readers see."""
    reg, r = _run(HDRS, BODY)
    payload = [d for d in r.findings if "technologies" in d][0]["technologies"]
    assert payload
    assert all(set(t) == {"name", "version", "source", "category"} for t in payload)


def test_version_disclosure_findings_are_unchanged():
    reg, r = _run(HDRS, BODY)
    titles = sorted(f["title"] for f in r.findings if f.get("family") == "fingerprint")
    assert titles == ["Version disclosure: PHP 7.4.3",
                      "Version disclosure: jQuery 3.4.1",
                      "Version disclosure: nginx 1.18.0"]
    assert all(f["confidence"] == "candidate" for f in r.findings if f.get("family") == "fingerprint")


def test_the_summary_string_is_unchanged():
    reg, r = _run(HDRS, BODY)
    assert r.output == "stack: nginx 1.18.0, PHP 7.4.3, jQuery 3.4.1"


def test_the_live_planning_graph_is_deliberately_untouched():
    """Q-021B is recon PERSISTENCE, not detection. `tools.graph` is the graph the planner reads
    (`technique_planner:135` unions `graph.to_observations()`), so writing technology into it would
    change which techniques get scheduled -- that is Q-021E's job and it would move numbers. The
    report-time `build_from_engagement` projection already carries these facts."""
    reg, _ = _run(HDRS, BODY)
    assert reg.recon["technology"], "the facts are persisted..."
    assert reg.graph.nodes("component") == [], "...but not into the planner's graph, not in this ticket"
    assert "has_versions" not in reg.graph.to_observations()
