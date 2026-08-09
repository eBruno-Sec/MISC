"""Request targets read from the page, not from the code (#125).

The script below is the REAL /resources/js/stockCheck.js from ginandjuice.shop, captured while working
the blind benchmark. It is the shape the runtime tracer cannot see: the fetch target comes from the
form's `action` ATTRIBUTE, which no URL parameter controls, so there is nothing for dom_trace to inject
into and a render alone would report the class absent.

The engine reports a LEAD, never a confirmation. Whether an attacker can reach that DOM node depends on
some other defect (HTML injection, DOM clobbering, a pollution gadget) that reading the code cannot
establish. Claiming it as confirmed would be exactly the kind of unearned certainty the platform's
oracles exist to prevent.
"""
import client_request_source as crs

REAL_STOCK_CHECK = """
document.getElementById("stockCheckForm").addEventListener("submit", function(e) {
    checkStock(this.getAttribute("method"), this.getAttribute("action"), new FormData(this));
    e.preventDefault();
});

function checkStock(method, path, data) {
    const retry = (tries) => tries == 0
        ? null
        : fetch(path, { method, headers: { 'Content-Type': window.contentType }, body: payload(data) })
            .then(res => res.text());
    retry(3);
}
"""


def test_detects_a_fetch_target_taken_from_a_dom_attribute():
    hits = crs.scan(REAL_STOCK_CHECK, "/resources/js/stockCheck.js")
    assert len(hits) == 1, hits
    assert hits[0]["call"] == "fetch()"
    assert "attribute" in hits[0]["source"]


def test_direct_dom_read_in_the_call_is_detected():
    hits = crs.scan('fetch(form.getAttribute("action"));')
    assert len(hits) == 1 and "attribute" in hits[0]["source"]


def test_dataset_and_location_sources_are_detected():
    assert crs.scan("fetch(el.dataset.endpoint);")
    assert crs.scan("var x = location.hash; fetch(x);")
    assert crs.scan("xhr.open('GET', document.baseURI);")


def test_a_constant_target_is_never_reported():
    """THE precision control. A rule that fired on any non-literal expression would flag most SPAs."""
    assert crs.scan('fetch("/api/stock", {method:"POST"});') == []
    assert crs.scan('const u = "/api/x"; fetch(u);') == []
    assert crs.scan("fetch(`/api/x/1`);") == []
    assert crs.scan("") == []
    assert crs.scan(None) == []


def test_a_variable_from_a_non_dom_source_is_not_reported():
    assert crs.scan('const u = buildUrl(id); fetch(u);') == []
    assert crs.scan('let p = config.endpoint; fetch(p);') == []


def test_duplicate_call_sites_collapse():
    js = 'fetch(a.getAttribute("action")); fetch(a.getAttribute("action"));'
    assert len(crs.scan(js)) == 1


def test_the_lead_is_a_lead_and_says_why():
    """It must not look like a confirmed finding to a report reader or to the benchmark's proof test."""
    hit = crs.scan(REAL_STOCK_CHECK, "/resources/js/stockCheck.js")[0]
    f = crs.lead(hit, "https://t/catalog/product")
    assert f["confidence"] == "lead"
    assert f["family"] == "request_url_override"
    assert "STATIC ONLY" in f["oracle"]
    assert "not proven" in f["oracle"]
    assert f["severity"] == "low"


def test_scan_never_raises_on_hostile_input():
    for bad in ("fetch(", "fetch((((", "\x00\x01", "fetch(a.getAttribute(", "}{)(", "fetch(" * 500):
        crs.scan(bad)


def test_the_registry_records_both_views_of_this_class():
    """dom_trace confirms the runtime case; this reports the static one. The technique must describe both
    or a reader cannot tell a lead from a confirmation."""
    import techniques as T
    rec = T.TECHNIQUES["request_url_override"]
    assert "LEAD" in rec["oracle"] and "RUNTIME" in rec["oracle"]
    assert rec["wstg"] == "WSTG-CLNT-06"


def test_hostile_script_cannot_stall_the_scan():
    """REGRESSION (ReDoS in our own engine). The parameter heuristic originally used
    `\w+\s*\(\s*[^)]*\bident\b[^)]*\)\s*{`, which backtracks catastrophically on unbalanced input:
    a body of bare `fetch(` tokens took this scan from milliseconds to MINUTES. A scanner reads
    JavaScript served by the target, so a hostile or merely malformed bundle must never stall it.
    Threshold is deliberately loose — the broken version took ~280s on a smaller input."""
    import time
    t0 = time.monotonic()
    crs.scan("fetch(" * 5000)
    crs.scan('a.getAttribute("action")' * 5000)
    crs.scan("function f(" * 3000)
    assert time.monotonic() - t0 < 5.0, "scan is superlinear on malformed input again"


def test_input_is_bounded_so_a_huge_bundle_cannot_set_the_scan_cost():
    huge = 'fetch(el.getAttribute("action"));\n' * 40000
    hits = crs.scan(huge)
    assert len(hits) <= 1                       # deduped
    assert crs._MAX_JS > 0 and crs._MAX_CALLS > 0
