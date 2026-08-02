"""The deep full-mission asserter must PASS a healthy authenticated mission and, crucially, FAIL
the exact regressions CHAD's audit named — a lost auth artery, a degenerate one-node graph, a
naked confirmed finding. Monkeypatches the HTTP layer so no live server/mission is needed."""
from __future__ import annotations

import benchmark_assert as BA


def _healthy():
    """Canned API surfaces for a healthy deterministic authenticated Juice Shop mission."""
    sid = "abc123"
    report = {
        "report_id": sid,
        "auth_artery": {"ran": True, "auth_success": 2,
                        "personas": [{"role": "user_a", "rank": 1, "method": "registered"},
                                     {"role": "user_b", "rank": 1, "method": "registered"}],
                        "matrix": {"ran": True, "operations": 39, "findings": 34}},
        "findings": [{"title": "BOLA basket", "family": "access_control", "confidence": "lead"}],
        "leads": [{"title": "reflected marker", "family": "xss", "confidence": "candidate"}],
    }
    graph = {"mission_id": sid, "stats": {"nodes": 990, "edges": 500,
             "by_kind": {"host": 1, "endpoint": 120, "finding": 34, "object": 40}},
             "provenance": {"by_source": {"live-recon": 900}, "needs_validation": [],
                            "needs_validation_count": 0}}
    j = {"/status/%s" % sid: {"status": "complete"},
         "/report/%s/json" % sid: report,
         "/graph/canonical/%s" % sid: graph,
         "/graph/%s" % sid: {"ok": True},
         "/missions/%s" % sid: {"id": sid}}
    d = {"/report/%s/md" % sid: (200, "# Report\n"),
         "/report/%s/html" % sid: (200, "<!doctype html><html></html>")}
    return sid, j, d


def _install(monkeypatch, jmap, dmap):
    def fake_get_json(base, path, timeout=30):
        return (200, jmap[path]) if path in jmap else (404, None)

    def fake_get(base, path, timeout=30):
        if path in dmap:
            return dmap[path]
        if path in jmap:
            import json as _j
            return (200, _j.dumps(jmap[path]))
        return (404, "")
    monkeypatch.setattr(BA, "_get_json", fake_get_json)
    monkeypatch.setattr(BA, "_get", fake_get)


def _fails(checks):
    return [name for name, ok, _ in checks if not ok]


def test_healthy_mission_passes_every_assertion(monkeypatch):
    sid, jmap, dmap = _healthy()
    _install(monkeypatch, jmap, dmap)
    checks = BA.run_checks("http://x", sid)
    assert _fails(checks) == [], "unexpected failures: %s" % _fails(checks)
    assert len(checks) >= 18   # it is actually a broad check set, not a token few


def test_lost_auth_artery_is_caught(monkeypatch):
    # THE CHAD #1 REGRESSION: mission ran unauthenticated (artery no-op) but everything else looks fine.
    sid, jmap, dmap = _healthy()
    jmap["/report/%s/json" % sid]["auth_artery"] = {"ran": False}
    _install(monkeypatch, jmap, dmap)
    fails = _fails(BA.run_checks("http://x", sid))
    assert "auth_artery_ran" in fails
    assert "auth_personas_minted" in fails
    assert "auth_success" in fails
    assert "authz_matrix_ran" in fails


def test_degenerate_one_node_graph_is_caught(monkeypatch):
    sid, jmap, dmap = _healthy()
    jmap["/graph/canonical/%s" % sid]["stats"] = {"nodes": 1, "edges": 0, "by_kind": {"host": 1}}
    _install(monkeypatch, jmap, dmap)
    fails = _fails(BA.run_checks("http://x", sid))
    assert "graph_nodes_floor" in fails
    assert "graph_has_endpoints" in fails
    assert "graph_has_findings" in fails


def test_naked_confirmed_finding_is_caught(monkeypatch):
    # a CONFIRMED finding with no evidence/reproduction violates the truth-first invariant
    sid, jmap, dmap = _healthy()
    jmap["/report/%s/json" % sid]["findings"] = [
        {"title": "SQLi", "family": "sql_injection", "confidence": "confirmed"}]   # no proof fields
    _install(monkeypatch, jmap, dmap)
    fails = _fails(BA.run_checks("http://x", sid))
    assert "no_confirmed_without_proof" in fails


def test_session_id_mismatch_is_caught(monkeypatch):
    # report/graph for a DIFFERENT mission must never pass as this one's proof
    sid, jmap, dmap = _healthy()
    jmap["/report/%s/json" % sid]["report_id"] = "someone-else"
    jmap["/graph/canonical/%s" % sid]["mission_id"] = "someone-else"
    _install(monkeypatch, jmap, dmap)
    fails = _fails(BA.run_checks("http://x", sid))
    assert "report_session_id_matches" in fails
    assert "graph_session_id_matches" in fails


def test_signature_captures_deterministic_facts(monkeypatch):
    sid, jmap, dmap = _healthy()
    _install(monkeypatch, jmap, dmap)
    sig = BA.signature("http://x", sid)
    assert sig["families"] == ["access_control", "xss"]           # sorted, deduped
    assert sig["counts"] == {"findings": 1, "leads": 1, "confirmed": 0}
    assert sig["auth"] == {"personas": 2, "auth_success": 2, "matrix_operations": 39}
    assert sig["graph_kinds"]["endpoint"] == 120


def test_determinism_identical_runs_pass():
    sig = {"families": ["access_control", "xss"], "counts": {"findings": 3, "leads": 5, "confirmed": 0},
           "graph_kinds": {"host": 1, "endpoint": 120}, "auth": {"personas": 2, "auth_success": 2, "matrix_operations": 39}}
    fails = [n for n, ok, _ in BA.compare_signatures(sig, dict(sig)) if not ok]
    assert fails == []


def test_determinism_family_drift_is_caught():
    a = {"families": ["access_control", "xss"], "counts": {}, "graph_kinds": {}, "auth": {}}
    b = {"families": ["access_control"], "counts": {}, "graph_kinds": {}, "auth": {}}   # xss vanished
    fails = [n for n, ok, _ in BA.compare_signatures(a, b) if not ok]
    assert "determinism_families_stable" in fails


def test_determinism_count_within_variance_but_big_drift_caught():
    base = {"families": [], "counts": {"findings": 100, "leads": 0, "confirmed": 0},
            "graph_kinds": {"endpoint": 100}, "auth": {"personas": 2, "auth_success": 2, "matrix_operations": 40}}
    # +10% findings and endpoints = within 15% variance -> OK
    near = {"families": [], "counts": {"findings": 110, "leads": 0, "confirmed": 0},
            "graph_kinds": {"endpoint": 110}, "auth": {"personas": 2, "auth_success": 2, "matrix_operations": 40}}
    assert [n for n, ok, _ in BA.compare_signatures(base, near) if not ok] == []
    # personas changed 2 -> 1 = exact-match invariant broken, always caught regardless of variance
    drift = dict(near); drift["auth"] = {"personas": 1, "auth_success": 2, "matrix_operations": 40}
    assert "determinism_personas_stable" in [n for n, ok, _ in BA.compare_signatures(base, drift) if not ok]


def test_401_on_endpoint_is_caught(monkeypatch):
    # "no 5xx" was too weak — a 401/404 must FAIL, not pass
    sid, jmap, dmap = _healthy()

    def fake_get_json(base, path, timeout=30):
        if path == "/missions/%s" % sid:
            return (401, None)
        return (200, jmap[path]) if path in jmap else (404, None)
    monkeypatch.setattr(BA, "_get_json", fake_get_json)
    monkeypatch.setattr(BA, "_get", lambda b, p, timeout=30: dmap.get(p, (200, "{}")))
    fails = _fails(BA.run_checks("http://x", sid))
    assert any(nm.startswith("endpoint_200_json") and "/missions/" in nm for nm in fails)
