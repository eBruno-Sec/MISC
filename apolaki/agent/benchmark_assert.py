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


# Bump when the assertion set / signature shape changes so a baseline written by an older schema is
# rejected rather than silently compared against different semantics (CHAD re-audit #4).
SCHEMA_VERSION = "1.0"


def _env_metadata(floors: dict) -> dict:
    """Provenance the benchmark output must be bound to (CHAD #4): the exact code + lab it ran
    against, so a stored baseline can never silently compare across different code/image/lab/config.
    git commit + image digests are supplied by the host runner via env (it can see docker/git);
    schema_version + config_fingerprint are computed here."""
    import os
    import hashlib
    cfg = json.dumps(floors or {}, sort_keys=True)
    return {
        "schema_version": SCHEMA_VERSION,
        "git_commit": os.environ.get("APOLAKI_GIT_COMMIT", ""),
        "agent_image": os.environ.get("APOLAKI_IMAGE_DIGEST", ""),
        "juice_shop_image": os.environ.get("APOLAKI_JUICESHOP_DIGEST", ""),
        "config_fingerprint": hashlib.sha256(cfg.encode("utf-8")).hexdigest()[:16],
    }


def baseline_compatible(stored_env: dict, cur_env: dict) -> tuple:
    """(ok, reason). A baseline is only comparable against a run on the SAME schema, SAME agent +
    juice-shop image digests, and SAME assertion config. Any drift => reject (re-seed), never compare
    stale. git_commit is recorded for humans but the image digest is the real code identity."""
    stored_env, cur_env = stored_env or {}, cur_env or {}
    for k in ("schema_version", "config_fingerprint"):
        if stored_env.get(k) != cur_env.get(k):
            return False, "%s mismatch (baseline=%s current=%s)" % (k, stored_env.get(k), cur_env.get(k))
    for k in ("agent_image", "juice_shop_image"):
        # only enforce when BOTH sides recorded it (host runner may omit in a bare invocation)
        if stored_env.get(k) and cur_env.get(k) and stored_env.get(k) != cur_env.get(k):
            return False, "%s mismatch (baseline=%s current=%s)" % (k, stored_env.get(k), cur_env.get(k))
    return True, "compatible"


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
    # REAL transport proof (CHAD re-audit #2): counted at the wire, NOT matrix_ops*personas arithmetic.
    areq = artery.get("authenticated_requests") or {}
    ck("authenticated_requests_attempted", (areq.get("attempted") or 0) > 0, "attempted=%s" % areq.get("attempted"))
    ck("authenticated_requests_succeeded", (areq.get("succeeded") or 0) > 0,
       "succeeded=%s status_dist=%s" % (areq.get("succeeded"), areq.get("status_dist")))
    ck("both_personas_authenticated", bool(areq.get("both_personas_succeeded")),
       "by_role=%s" % areq.get("by_role"))
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

    # ── EDGE assertions, not just a node census (CHAD re-audit #6): a graph can be full of nodes
    # with broken relationships. Assert the critical connectivity a real world-model must carry. ──
    nodes_by_id = {n.get("id"): n.get("kind") for n in (graph.get("nodes") or [])}
    typed = {}   # (src_kind, rel, dst_kind) -> count
    for e in (graph.get("edges") or []):
        key = (nodes_by_id.get(e.get("source")), e.get("rel"), nodes_by_id.get(e.get("target")))
        typed[key] = typed.get(key, 0) + 1

    def edges(src, rel, dst):
        return typed.get((src, rel, dst), 0)

    ck("edge_host_serves_endpoint", edges("host", "serves", "endpoint") >= f["min_endpoints"],
       "count=%s" % edges("host", "serves", "endpoint"))
    ck("edge_endpoint_has_param", edges("endpoint", "has_param", "param") >= 1,
       "count=%s" % edges("endpoint", "has_param", "param"))
    ck("edge_finding_on_asset",
       edges("endpoint", "found_on", "finding") + edges("host", "found_on", "finding") >= 1,
       "count=%s" % (edges("endpoint", "found_on", "finding") + edges("host", "found_on", "finding")))
    # persona->session connectivity must match the auth artery's authenticated personas (both users)
    ck("edge_persona_authenticated_as_session",
       edges("persona", "authenticated_as", "session") >= max(1, (artery.get("auth_success") or 0)),
       "count=%s auth_success=%s" % (edges("persona", "authenticated_as", "session"), artery.get("auth_success")))

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


def signature(base: str, sid: str) -> dict:
    """A COMPACT, order-stable fingerprint of a mission's outcome — the deterministic-engine facts
    that should reproduce run-to-run: which technique families surfaced, the confirmed/lead counts,
    the graph's node-kind census, and the auth-artery shape. Used to enforce determinism (CHAD #5):
    two runs of the same deterministic scan must agree on families/auth exactly and on counts within
    a documented variance. Structural facts only — never per-run ids/timestamps/payloads."""
    _, rep = _get_json(base, "/report/%s/json" % sid)
    _, graph = _get_json(base, "/graph/canonical/%s" % sid)
    rep, graph = rep or {}, graph or {}
    findings, leads = rep.get("findings") or [], rep.get("leads") or []
    fams = sorted({(x.get("family") or "").strip().lower()
                   for x in list(findings) + list(leads) if x.get("family")})
    artery = rep.get("auth_artery") or {}
    matrix = artery.get("matrix") or {}
    return {
        "schema_version": SCHEMA_VERSION,
        "families": fams,
        "counts": {"findings": len(findings), "leads": len(leads),
                   "confirmed": sum(1 for x in findings if x.get("confidence") == "confirmed")},
        "graph_kinds": (graph.get("stats") or {}).get("by_kind") or {},
        "auth": {"personas": len(artery.get("personas") or []),
                 "auth_success": artery.get("auth_success") or 0,
                 "matrix_operations": matrix.get("operations") or 0,
                 "auth_requests_succeeded": (artery.get("authenticated_requests") or {}).get("succeeded") or 0},
    }


def compare_signatures(base_sig: dict, new_sig: dict, variance: float = 0.15) -> list:
    """(name, ok, detail) per invariant. EXACT agreement is required on the deterministic facts
    (technique families, persona count, auth_success); numeric counts may differ within `variance`
    to tolerate benign timing jitter (an endpoint discovered a beat later). Drift beyond that is a
    determinism regression, not noise."""
    out = []

    def ck(name, ok, detail=""):
        out.append((name, bool(ok), detail))

    def within(a, b):
        hi = max(abs(a), abs(b))
        return hi == 0 or abs(a - b) <= variance * hi

    ck("determinism_families_stable", base_sig.get("families") == new_sig.get("families"),
       "base=%s new=%s" % (base_sig.get("families"), new_sig.get("families")))
    ba, na = base_sig.get("auth", {}), new_sig.get("auth", {})
    ck("determinism_personas_stable", ba.get("personas") == na.get("personas"),
       "base=%s new=%s" % (ba.get("personas"), na.get("personas")))
    ck("determinism_auth_success_stable", ba.get("auth_success") == na.get("auth_success"),
       "base=%s new=%s" % (ba.get("auth_success"), na.get("auth_success")))
    ck("determinism_matrix_ops_within_variance", within(ba.get("matrix_operations", 0), na.get("matrix_operations", 0)),
       "base=%s new=%s" % (ba.get("matrix_operations"), na.get("matrix_operations")))
    ck("determinism_auth_requests_within_variance",
       within(ba.get("auth_requests_succeeded", 0), na.get("auth_requests_succeeded", 0)),
       "base=%s new=%s" % (ba.get("auth_requests_succeeded"), na.get("auth_requests_succeeded")))
    bc, nc = base_sig.get("counts", {}), new_sig.get("counts", {})
    for k in ("findings", "leads", "confirmed"):
        ck("determinism_%s_within_variance" % k, within(bc.get(k, 0), nc.get(k, 0)),
           "base=%s new=%s" % (bc.get(k), nc.get(k)))
    bk, nk = base_sig.get("graph_kinds", {}), new_sig.get("graph_kinds", {})
    for k in sorted(set(bk) | set(nk)):
        ck("determinism_graph_%s_within_variance" % k, within(bk.get(k, 0), nk.get(k, 0)),
           "base=%s new=%s" % (bk.get(k), nk.get(k)))
    return out


def _arg(argv, flag):
    return argv[argv.index(flag) + 1] if flag in argv and argv.index(flag) + 1 < len(argv) else None


def _seal(obj: dict) -> str:
    """Tamper-evident integrity seal: sha256 over the canonical JSON of the artifact body. Reuses the
    same tamper-EVIDENT posture as audit.py (a hash, not a secret-key signature) — anyone can re-hash
    the retained artifact and detect edits."""
    import hashlib
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def main(argv):
    if len(argv) < 3:
        print("usage: python benchmark_assert.py <base_url> <session_id> "
              "[--signature | --baseline FILE | --artifact FILE]")
        return 2
    base, sid = argv[1], argv[2]
    floors = dict(DEFAULTS)
    env = _env_metadata(floors)

    if "--signature" in argv:
        print(json.dumps(signature(base, sid), indent=2, sort_keys=True))
        return 0

    checks = run_checks(base, sid, floors)
    sig = signature(base, sid)
    baseline_record = None

    # --baseline FILE: enforce determinism vs a stored golden — but ONLY across a compatible env
    # (same schema/image/config). Incompatible or missing => (re)write, never compare stale (CHAD #4).
    path = _arg(argv, "--baseline")
    if path is not None:
        import os
        try:
            if not os.path.exists(path):
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump({"env": env, "signature": sig}, fh, indent=2, sort_keys=True)
                print("[assert] wrote new determinism baseline -> %s (compare on the next compatible run)" % path)
                baseline_record = {"path": path, "written": True, "env": env}
            else:
                with open(path, "r", encoding="utf-8") as fh:
                    stored = json.load(fh)
                stored_env = stored.get("env", {}) if isinstance(stored, dict) else {}
                stored_sig = stored.get("signature", stored) if isinstance(stored, dict) else stored
                compat, reason = baseline_compatible(stored_env, env)
                checks.append(("baseline_env_compatible", compat, reason))
                if compat:
                    cmp_checks = compare_signatures(stored_sig, sig)
                    checks = checks + cmp_checks
                    baseline_record = {"path": path, "written": False, "env": stored_env,
                                       "comparison": [{"name": n, "ok": ok, "detail": d} for n, ok, d in cmp_checks]}
                else:
                    baseline_record = {"path": path, "written": False, "env": stored_env, "incompatible": reason}
        except Exception as e:
            checks = checks + [("determinism_baseline_io", False, "%s" % e)]

    npass = sum(1 for _, ok, _ in checks if ok)
    for name, ok, detail in checks:
        print("  %s  %-34s %s" % ("PASS" if ok else "FAIL", name, detail))
    nfail = len(checks) - npass
    print("[assert] ==== %d passed, %d failed ====" % (npass, nfail))

    # --artifact FILE: durable, sanitized, integrity-sealed evidence (CHAD #7). No secrets — checks
    # carry only names/booleans/short details, signature is structural counts, env is digests.
    apath = _arg(argv, "--artifact")
    if apath is not None:
        body = {
            "kind": "apolaki_full_mission_benchmark",
            "schema_version": SCHEMA_VERSION,
            "generated_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
            "env": env,
            "mission_id": sid,
            "summary": {"passed": npass, "failed": nfail},
            "checks": [{"name": n, "ok": ok, "detail": d} for n, ok, d in checks],
            "signature": sig,
            "baseline": baseline_record,
        }
        artifact = {**body, "integrity": {"algo": "sha256", "hash": _seal(body)}}
        try:
            with open(apath, "w", encoding="utf-8") as fh:
                json.dump(artifact, fh, indent=2, sort_keys=True)
            print("[assert] wrote sealed benchmark artifact -> %s (sha256 %s)" % (apath, artifact["integrity"]["hash"][:16]))
        except Exception as e:
            print("[assert] artifact write failed: %s" % e)
            return 1

    return 0 if nfail == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
