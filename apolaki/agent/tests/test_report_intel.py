"""The HTML report renders a Target Intelligence section from a harvested intel snapshot,
filters the noisy encoded bucket, keeps secrets redacted, and stays unchanged without intel."""
from __future__ import annotations

import report


def _intel():
    return {"total": 5,
            "by_kind": {"email": 1, "route": 2, "encoded": 98, "secret": 1},
            "candidates": {"email": ["admin@juice-sh.op"],
                           "route": ["/#recycle", "/administration"],
                           "encoded": ["QUJDDQUJDDQUJDDQUJDD"],   # minified-JS noise — must NOT show
                           "secret": ["<redacted:40>"]}}


def test_report_renders_target_intelligence_section():
    html = report.generate_html_report("P", [], {"in_scope": ["juice-shop"]}, intel=_intel())
    assert "Target Intelligence" in html
    assert "admin@juice-sh.op" in html
    assert "/administration" in html
    assert "redacted:40" in html            # secret surfaced only in redacted form


def test_report_omits_noisy_encoded_bucket():
    html = report.generate_html_report("P", [], {"in_scope": ["x"]}, intel=_intel())
    assert "QUJDDQUJDD" not in html          # encoded noise never rendered


def test_markdown_report_renders_target_intelligence_section():
    f = {"title": "SQLi", "severity": "high", "family": "sqli", "cwe": "CWE-89",
         "target": "http://juice-shop/x", "evidence": "proof", "confidence": "confirmed"}
    md = report.generate_report("P", [f], {"in_scope": ["juice-shop"]}, intel=_intel())
    assert "## Target Intelligence" in md
    assert "admin@juice-sh.op" in md
    assert "QUJDDQUJDD" not in md          # encoded noise omitted in markdown too


def test_report_without_intel_has_no_section():
    html = report.generate_html_report("P", [], {"in_scope": ["x"]})
    assert "Target Intelligence" not in html


def test_report_with_empty_intel_has_no_section():
    html = report.generate_html_report("P", [], {"in_scope": ["x"]}, intel={"candidates": {}})
    assert "Target Intelligence" not in html


def test_findings_json_carries_intel_provenance():
    # the JSON data package surfaces WHERE the world model came from (feed counts + worklist), so a
    # consumer can see the wayback/github/cloud contribution and what still needs live validation.
    import json
    prov = {"by_source": {"recon": 40, "wayback": 12, "github": 3},
            "passive_intel": {"wayback": 12, "github": 3},
            "needs_validation": [{"id": "endpoint:acme/old", "label": "/old", "provenance": "archive"}],
            "needs_validation_count": 1}
    pkg = json.loads(report.findings_json("P", [], {"in_scope": ["x"]}, intel_provenance=prov))
    assert pkg["intel_provenance"]["passive_intel"]["wayback"] == 12
    assert pkg["intel_provenance"]["needs_validation_count"] == 1
    # additive + backwards-compatible: absent provenance is an empty dict, never a crash
    pkg2 = json.loads(report.findings_json("P", [], {"in_scope": ["x"]}))
    assert pkg2["intel_provenance"] == {}


def test_html_report_renders_authentication_assurance_panel():
    aa = {"ran": True, "auth_success": 2,
          "personas": [{"role": "user_a"}, {"role": "user_b"}],
          "matrix": {"operations": 39, "findings": 34},
          "authenticated_requests": {"attempted": 78, "succeeded": 70, "both_personas_succeeded": True,
                                     "status_dist": {"200": 60, "401": 10}}}
    prov = {"by_source": {"wayback": 12, "recon": 40}, "needs_validation_count": 12}
    html = report.generate_html_report("P", [], {"in_scope": ["x"]}, auth_artery=aa, intel_provenance=prov)
    assert "Authentication &amp; Assurance" in html
    assert "attempted <b>78</b>" in html and "succeeded <b>70</b>" in html
    assert "both personas succeeded: <b>yes</b>" in html
    assert "wayback=12" in html
    # no auth artery + no provenance -> panel absent (never fabricated)
    assert "Authentication &amp; Assurance" not in report.generate_html_report("P", [], {"in_scope": ["x"]})


def test_degraded_run_is_visible_in_report_json_and_html():
    # CHAD final #3: a halted primary cycle must be VISIBLE — a degraded run cannot look complete.
    import json
    deg = {"reason": "graph_projection_failed", "detail": "graph down"}
    pkg = json.loads(report.findings_json("P", [], {"in_scope": ["x"]}, degraded=deg))
    assert pkg["degraded"] == deg
    html = report.generate_html_report("P", [], {"in_scope": ["x"]}, degraded=deg)
    assert "RUN DEGRADED" in html and "graph_projection_failed" in html
    # a normal run shows no degraded banner
    assert "RUN DEGRADED" not in report.generate_html_report("P", [], {"in_scope": ["x"]})
    assert json.loads(report.findings_json("P", [], {"in_scope": ["x"]}))["degraded"] is None


def test_target_not_reached_warning_when_active_scan_reaches_zero_live_hosts():
    # Optest gap: an active/full scan that reached 0 live hosts never touched the target (a bare
    # host defaults to https:443, or the target is down). A "complete" run with no findings must
    # NOT read as "target is secure" — it must loudly say the target was never reached.
    import json
    pkg = json.loads(report.findings_json("P", [], {"in_scope": ["x"]},
                                          config={"mode": "active"}, attack_surface={"live_hosts": 0}))
    assert pkg["target_reachability"] and "TARGET NOT REACHED" in pkg["target_reachability"]
    html = report.generate_html_report("P", [], {"in_scope": ["x"]}, mode="active",
                                       attack_surface={"live_hosts": 0})
    assert "TARGET NOT REACHED" in html
    # a scan that DID reach a host shows no warning (JSON None, no HTML banner)
    pkg2 = json.loads(report.findings_json("P", [], {"in_scope": ["x"]},
                                           config={"mode": "active"}, attack_surface={"live_hosts": 5}))
    assert pkg2["target_reachability"] is None
    assert "TARGET NOT REACHED" not in report.generate_html_report(
        "P", [], {"in_scope": ["x"]}, mode="active", attack_surface={"live_hosts": 5})
    # passive mode never probes hosts, so the warning does not apply (no false alarm)
    pkg3 = json.loads(report.findings_json("P", [], {"in_scope": ["x"]},
                                           config={"mode": "passive"}, attack_surface={"live_hosts": 0}))
    assert pkg3["target_reachability"] is None


def test_authenticated_requests_note_explains_zero_success_honestly():
    # A 0-success authenticated pass must NOT read as broken auth. When every authz candidate
    # 4xx'd (e.g. 404), the note says it is NOT an auth failure; a 401/403 says the session was
    # rejected. Some success, or nothing attempted, yields no note (no false caveat).
    import json
    n404 = report.auth_requests_note({"attempted": 3, "succeeded": 0, "status_dist": {"404": 6}})
    assert "NOT an authentication failure" in n404 and "404" in n404
    n401 = report.auth_requests_note({"attempted": 2, "succeeded": 0, "status_dist": {"401": 2}})
    assert "rejected" in n401.lower()
    assert report.auth_requests_note({"attempted": 3, "succeeded": 2, "status_dist": {"200": 2, "404": 1}}) == ""
    assert report.auth_requests_note({"attempted": 0, "succeeded": 0}) == ""
    # the JSON package surfaces the note on a real 0-success artery so the UI/consumers can render it
    artery = {"ran": True, "authenticated_requests": {"attempted": 3, "succeeded": 0, "status_dist": {"404": 6}}}
    pkg = json.loads(report.findings_json("P", [], {"in_scope": ["x"]}, auth_artery=artery))
    assert "NOT an authentication failure" in pkg["auth_artery"]["authenticated_requests"]["note"]
    # HTML assurance panel renders the caveat too
    html = report.generate_html_report("P", [], {"in_scope": ["x"]}, auth_artery=artery)
    assert "not an authentication failure" in html.lower()


def test_findings_json_carries_auth_artery_proof():
    # the report exposes whether the autonomous auth artery actually fired, so "authenticated scan"
    # is PROVABLE (personas, auth_success, matrix ops) — not merely requested in the payload.
    import json
    artery = {"ran": True, "persona_count": 2, "auth_success": 2,
              "personas": [{"role": "user_a", "rank": 1, "method": "registered", "identity": "a@t"},
                           {"role": "user_b", "rank": 1, "method": "registered", "identity": "b@t"}],
              "matrix": {"operations": 39, "findings": 34, "ran": True}}
    pkg = json.loads(report.findings_json("P", [], {"in_scope": ["x"]}, auth_artery=artery))
    assert pkg["auth_artery"]["ran"] is True
    assert pkg["auth_artery"]["auth_success"] == 2
    assert pkg["auth_artery"]["matrix"]["operations"] == 39
    assert "password" not in str(pkg["auth_artery"])   # personas carry labels/refs, never secrets
    # an unauthenticated scan is distinguishable, never silently "looks authenticated"
    pkg0 = json.loads(report.findings_json("P", [], {"in_scope": ["x"]}))
    assert pkg0["auth_artery"] == {"ran": False}
