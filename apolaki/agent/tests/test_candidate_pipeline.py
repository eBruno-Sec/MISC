"""The candidate-validation pipeline normalizes noisy leads, derives a canonical family, and
routes each to a real validator. The load-bearing rule (target-agnostic, not GinAndJuice-specific):
a sink found inside a .js LIBRARY file is retargeted at the APPLICATION PAGES that use it, never
tested as the .js URL — runtime reachability then decides confirmed vs dismissed."""
from __future__ import annotations

import candidate_pipeline as cp


def test_canonical_family_derived_from_noisy_signals():
    assert cp.canonical_family({"title": "Dangerous sink: AngularJS ng-app (client-side template injection (CSTI))",
                                "cwe": "CWE-94", "tags": ["sink", "client-side template injection (CSTI)"]}) == "csti"
    assert cp.canonical_family({"title": "deparam prototype-pollution gadget", "cwe": "CWE-1321"}) == "prototype_pollution"
    assert cp.canonical_family({"title": "JSONP Info Leak", "tags": ["jsonp"]}) == "jsonp"
    assert cp.canonical_family({"title": "Exposed Credentials", "cwe": "CWE-522"}) == "exposed_credentials"
    assert cp.canonical_family({"title": "Math.random usage", "cwe": "CWE-330"}) == "weak_random"
    assert cp.canonical_family({"title": "Revealing developer comments", "cwe": "CWE-615"}) == "dev_comments"
    assert cp.canonical_family({"title": "BFLA Privileged Action", "cwe": "CWE-285"}) == "bfla"


def test_static_js_lead_retargets_at_application_pages_not_the_js_url():
    # A CSTI hit inside React vendor source must NOT be tested as the .js URL.
    lead = {"title": "Dangerous sink: AngularJS ng-app (CSTI)", "cwe": "CWE-94",
            "tags": ["client-side template injection (CSTI)"],
            "target": "https://t/resources/js/ReactElement.js"}
    n = cp.normalize(lead)
    assert n["family"] == "csti" and n["static_js_hit"] is True and n["validator"] == "run_dom_audit"
    pages = ["https://t/", "https://t/blog", "https://t/resources/js/ReactElement.js", "https://t/style.css"]
    app = cp.application_pages(pages)
    assert app == ["https://t/", "https://t/blog"]            # .js + .css dropped
    targets = cp.plan_targets(n, app)
    assert "https://t/resources/js/ReactElement.js" not in targets   # never the lib file
    assert targets == app                                             # the pages that USE the lib


def test_every_listed_family_routes_to_a_validator_and_oracle():
    for fam in ("prototype_pollution", "csti", "dom_xss", "eval_sink", "reflected_xss", "stored_xss",
                "exposed_credentials", "exposed_files", "bfla", "jsonp", "weak_random", "dev_comments"):
        v, oracle, _prereq = cp._ROUTES[fam]
        assert v and oracle, fam


def test_prereqs_named_so_blocked_is_explicit():
    assert cp.normalize({"title": "Prototype Pollution", "target": "https://t/js/deparam.js"})["prerequisite"] == "browser"
    assert cp.normalize({"title": "BFLA Privileged Action", "cwe": "CWE-285", "target": "https://t/admin"})["prerequisite"] == "low_priv_session"
    assert cp.normalize({"title": "Exposed Credentials", "cwe": "CWE-522", "target": "https://t/"})["prerequisite"] is None


def test_parameterized_reflected_xss_keeps_its_url():
    n = cp.normalize({"title": "Reflected XSS", "cwe": "CWE-79", "target": "https://t/search?q=1"})
    assert n["family"] == "reflected_xss" and n["param"] == "q"
    assert cp.plan_targets(n, ["https://t/"]) == ["https://t/search?q=1"]
