"""
Deep end-to-end CORRECTNESS assertions for a completed full-mission run.

This is the layer that turns the full-mission SMOKE test (status==complete, findings>=1,
graph nodes>=1, no 5xx) into a real CORRECTNESS proof — the gap CHAD's read-only audit called
out: a mission could lose the entire auth artery, emit one unrelated header lead, produce a
one-node graph, and still pass 6/6.

It reads the SAME HTTP surfaces a consumer sees (/status, /report/{sid}/json,
/graph/canonical/{sid}) — never the DB directly, so it proves what a real client would get —
and asserts structural invariants that a broken orchestration cannot satisfy:

  - the AUTH ARTERY actually fired: personas>=2, auth_success>=2, matrix ran with operations>0
    (matrix operations ARE authenticated requests — each op is replayed as every persona)
  - the canonical GRAPH carries the expected node kinds (host/endpoint/finding) and edges
  - INTEL PROVENANCE has a valid schema (by_source / needs_validation / count)
  - the REPORT covers a minimum breadth of technique families and the mission's own session id
  - every rendered endpoint returns 200 with a schema valid for its content type (not 401/404)
  - NO confirmed finding lacks proof fields (evidence/reproduction) — truth-first invariant

Pure standard library (urllib + json). Exit code 0 iff every assertion holds. Import
`run_checks` for tests, or run as: python benchmark_assert.py <base_url> <session_id>
"""
from __future__ import annotations

import json
import sys
import urllib.request

# Evidence-based floors, measured on a real deterministic authenticated Juice Shop run (mission
# 6beae1cd/364f47d6: ~990 graph nodes, ~39 matrix operations, families incl. access_control). Set
# well BELOW the observed values so normal run-to-run variance never flaps, but far ABOVE the
# degenerate "one node / one lead" a broken run would emit. Overridable per call for other targets.
DEFAULTS = {
    "min_personas": 2,
    "min_auth_success": 2,
    "min_matrix_operations": 1,
    "min_graph_nodes": 50,
    "min_graph_edges": 1,
    "min_endpoints": 10,
    "min_signal": 1,            # confirmed + leads (a deterministic pass confirms little — honest)
    "min_families": 1,          # distinct technique families across findings+leads
    "require_families": ("access_control",),   # Juice Shop must at least surface authz signal
}


def _get(base: str, path: str, timeout: int = 30):
    """(status_code, raw_text). A transport error is status 0 — a hard fail, never silently ok."""
    url = base.rstrip("/") + path
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.getcode(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, (e.read().decode("utf-8", "replace") if e.fp else "")
    except Exception as e:
        return 0, "%s" % e


def _get_json(base: str, path: str):
    code, body = _get(base, path)
    try:
        return code, json.loads(body)
    except Exception:
        return code, None


def run_checks(base: str, sid: str, floors: dict = None) -> list:
    """Return a list of (name, ok, detail). Every tuple with ok=False is a correctness failure."""
    f = dict(DEFAULTS)
    f.update(floors or {})
    checks = []

    def ck(name, ok, detail=""):
        checks.append((name, bool(ok), detail))

    # ── status: the mission actually completed ──
    scode, sjson = _get_json(base, "/status/%s" % sid)
    status = (sjson or {}).get("status") if sjson else None
    ck("status_complete", scode == 200 and status == "complete", "http=%s status=%s" % (scode, status))

    # ── report JSON: the surface a consumer parses ──
    rcode, rep = _get_json(base, "/report/%s/json" % sid)
    ck("report_json_200_valid", rcode == 200 and isinstance(rep, dict), "http=%s parsed=%s" % (rcode, rep is not None))
    rep = rep or {}

    # session identity is consistent — the report is FOR this mission, not a stale/other one
    ck("report_session_id_matches", rep.get("report_id") == sid, "report_id=%s" % rep.get("report_id"))

    # ── AUTH ARTERY actually fired (CHAD #1) ──
    artery = rep.get("auth_artery") or {"ran": False}
    personas = artery.get("personas") or []
    matrix = artery.get("matrix") or {}
    ck("auth_artery_ran", bool(artery.get("ran")), "ran=%s" % artery.get("ran"))
    ck("auth_personas_minted", len(personas) >= f["min_personas"], "personas=%d" % len(personas))
    ck("auth_success", (artery.get("auth_success") or 0) >= f["min_auth_success"],
       "auth_success=%s" % artery.get("auth_success"))
    ck("authz_matrix_ran", bool(matrix.get("ran")) and (matrix.get("operations") or 0) >= f["min_matrix_operations"],
       "ran=%s operations=%s" % (matrix.get("ran"), matrix.get("operations")))
    # matrix operations ARE authenticated requests (each replayed as every persona)
    ck("authenticated_requests_made", (matrix.get("operations") or 0) * max(1, len(personas)) > 0,
       "ops*personas=%s" % ((matrix.get("operations") or 0) * max(1, len(personas))))
    # personas must never carry secrets
    ck("personas_carry_no_secret", "password" not in json.dumps(artery).lower(), "")

    # ── report breadth: families + no unproven "confirmed" ──
    findings = rep.get("findings") or []
    leads = rep.get("leads") or []
    fams = set()
    for item in list(findings) + list(leads):
        fam = (item.get("family") or "").strip().lower()
        if fam:
            fams.add(fam)
    ck("report_signal_present", (len(findings) + len(leads)) >= f["min_signal"],
       "findings=%d leads=%d" % (len(findings), len(leads)))
    ck("report_family_breadth", len(fams) >= f["min_families"], "families=%s" % sorted(fams))
    missing_req = [r for r in f["require_families"] if r not in fams]
    ck("report_required_families", not missing_req, "missing=%s have=%s" % (missing_req, sorted(fams)))
    # truth-first: a CONFIRMED finding must carry proof (evidence or reproduction) — no naked confirms
    naked = [x.get("title") for x in findings
             if (x.get("confidence") == "confirmed") and not (x.get("evidence") or x.get("reproduction_steps"))]
    ck("no_confirmed_without_proof", not naked, "naked_confirmed=%s" % naked[:3])

    # ── canonical graph: real world-model, not a single node ──
    gcode, graph = _get_json(base, "/graph/canonical/%s" % sid)
    graph = graph or {}
    stats = graph.get("stats") or {}
    by_kind = stats.get("by_kind") or {}
    ck("graph_json_200_valid", gcode == 200 and isinstance(graph, dict), "http=%s" % gcode)
    ck("graph_session_id_matches", graph.get("mission_id") == sid, "mission_id=%s" % graph.get("mission_id"))
    ck("graph_nodes_floor", (stats.get("nodes") or 0) >= f["min_graph_nodes"], "nodes=%s" % stats.get("nodes"))
    ck("graph_edges_floor", (stats.get("edges") or 0) >= f["min_graph_edges"], "edges=%s" % stats.get("edges"))
    ck("graph_has_host", by_kind.get("host", 0) >= 1, "host=%s" % by_kind.get("host"))
    ck("graph_has_endpoints", by_kind.get("endpoint", 0) >= f["min_endpoints"], "endpoint=%s" % by_kind.get("endpoint"))
    ck("graph_has_findings", by_kind.get("finding", 0) >= 1, "finding=%s" % by_kind.get("finding"))

    # ── intel provenance schema valid (even if empty on a lab with no wayback/github footprint) ──
    prov = graph.get("provenance") or {}
    prov_ok = (isinstance(prov.get("by_source"), dict)
               and isinstance(prov.get("needs_validation"), list)
               and isinstance(prov.get("needs_validation_count"), int))
    ck("provenance_schema_valid", prov_ok, "keys=%s" % sorted(prov.keys()))

    # ── every rendered endpoint: 200 + schema valid for its content type (401/403/404 FAIL) ──
    ep_json = ["/report/%s/json" % sid, "/graph/canonical/%s" % sid, "/status/%s" % sid,
               "/graph/%s" % sid, "/missions/%s" % sid]
    for p in ep_json:
        c, j = _get_json(base, p)
        ck("endpoint_200_json %s" % p, c == 200 and j is not None, "http=%s json=%s" % (c, j is not None))
    for p, needle in [("/report/%s/md" % sid, "#"), ("/report/%s/html" % sid, "<")]:
        c, b = _get(base, p)
        ck("endpoint_200_doc %s" % p, c == 200 and needle in (b or ""), "http=%s len=%d" % (c, len(b or "")))

    return checks


def main(argv):
    if len(argv) < 3:
        print("usage: python benchmark_assert.py <base_url> <session_id>")
        return 2
    base, sid = argv[1], argv[2]
    checks = run_checks(base, sid)
    npass = sum(1 for _, ok, _ in checks if ok)
    for name, ok, detail in checks:
        print("  %s  %-32s %s" % ("PASS" if ok else "FAIL", name, detail))
    nfail = len(checks) - npass
    print("[assert] ==== %d passed, %d failed ====" % (npass, nfail))
    return 0 if nfail == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
