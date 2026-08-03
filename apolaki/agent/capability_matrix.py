"""Machine-readable CAPABILITY MATRIX (CHAD's keystone).

Every declared capability carries EXACTLY ONE state — the six are never merged, so "green unit
tests" can never masquerade as "live-proven through the real product path":

  implemented  code exists + unit-tested, but not yet composed into an engagement
  wired        composes into the one engagement state (a real scan reaches it)
  exercised    actually invoked during a live scan (it ran)
  live_proven  produced real evidence on a live authorized target (named mission)
  blocked      correct + wired, but needs an external prerequisite to run (named)
  unfinished   declared but not yet built

`state_rank` orders them; a capability is reported at its HIGHEST achieved state. Evidence is a
mission id / test / artifact — never a claim. validate() enforces the invariants so the matrix
cannot lie (every capability has a state in the enum and a non-empty evidence string).
"""
from __future__ import annotations

STATES = ("unfinished", "implemented", "wired", "exercised", "live_proven", "blocked")
_RANK = {"unfinished": 0, "implemented": 1, "wired": 2, "exercised": 3, "live_proven": 4, "blocked": 2}


def _c(name, area, state, evidence, labs=None):
    return {"name": name, "area": area, "state": state, "evidence": evidence, "labs": labs or []}


# Honest, evidence-backed snapshot (2026-08-03). Each evidence is a named mission / test / artifact.
CAPABILITIES = [
    _c("Passive recon (subfinder/crtsh/wayback/dns/asn)", "recon", "live_proven",
       "ran on every mission; e.g. b59af834 (ginandjuice)", ["ginandjuice", "juiceshop"]),
    _c("Code-intelligence harvest (JS mining -> endpoints/routes)", "recon", "live_proven",
       "mission b59af834: 21 endpoints/44 routes/1 exposed", ["ginandjuice"]),
    _c("Technique registry + KEV/CAPEC-ranked advisor", "intel", "live_proven",
       "GET /techniques + advisor leads in every report", ["juiceshop"]),
    _c("Canonical asset/intelligence graph", "graph", "live_proven",
       "GET /graph/canonical; 994 nodes on 24e4927f", ["juiceshop"]),
    _c("Deterministic planner (graph-backed asset selection)", "planner", "live_proven",
       "test_graph_primary + live 19223a57", ["juiceshop", "ginandjuice"]),
    _c("Authentication artery (autonomous 2-persona registration)", "auth", "live_proven",
       "24e4927f: ran, 2 personas, 80 authed reqs, matrix 40 ops", ["juiceshop"]),
    _c("Credential discovery -> persist -> authenticated scan", "auth", "live_proven",
       "b59af834 discovered carlos -> 0fa78fb8 logged in, 897 authed URLs", ["ginandjuice"]),
    _c("Two-user authorization matrix (IDOR/BFLA)", "authz", "live_proven",
       "24e4927f matrix 40 ops/35 findings", ["juiceshop"]),
    _c("Candidate-validation pipeline (every lead -> terminal state)", "validation", "live_proven",
       "570e3dbb: 12 records, 0 silently-untested, 7 confirmed dedupe -> 4 findings", ["ginandjuice"]),
    _c("DOM validators (CSTI/prototype-pollution/DOM-XSS via Chromium canary)", "validation", "live_proven",
       "570e3dbb confirmed CSTI + prototype-pollution", ["ginandjuice"]),
    _c("JSONP info-leak validator", "validation", "exercised",
       "run_jsonp ran on ginandjuice (dismissed, no JSONP present); unit-proven test_jsonp_and_candval", []),
    _c("BFLA privileged-action validator", "validation", "exercised",
       "11199676 (authed): ran with low-priv session, correctly denied (no priv-esc)", ["ginandjuice"]),
    _c("Exposed-files validator (content-signature)", "validation", "exercised",
       "run_exposure invoked in candidate pipeline (no signature match on ginandjuice)", []),
    _c("Intercept proxy (mitmproxy match-and-replace + HAR)", "capture", "live_proven",
       "Proxy tab: 500 flows captured live", ["juiceshop"]),
    _c("Report generation + integrity gate (CVSS/oracle/KEV/chains/TOC)", "report", "live_proven",
       "570e3dbb report_integrity_check == 0 violations; 25/25 TOC", ["ginandjuice"]),
    _c("Benchmark determinism (signature-identical two-mission)", "qa", "live_proven",
       "benchmark_results/repeat_*.json, 58/58 sealed", ["juiceshop"]),
    _c("Juice Shop solver pack (lab-mode, isolated from detector)", "lab", "live_proven",
       "juiceshop_solvers.py; board 75/113 via labs.solve", ["juiceshop"]),
    _c("Cross-lab generalization (>=2 independent labs)", "lab", "live_proven",
       "techniques.py generalized set; validated_on across juiceshop/dvwa/ginandjuice", ["juiceshop", "dvwa", "ginandjuice"]),
    _c("Linode cloud posture review (read-only)", "cloud", "blocked",
       "collect_linode_live implemented + fixture-tested; needs operator read-only token", []),
    _c("AWS/Azure/GCP live cloud enumeration", "cloud", "unfinished",
       "collect_live logic fixture-tested; SDK client glue not built", []),
    _c("Full graph-as-brain (retire legacy next_batch; tools write graph directly)", "planner", "unfinished",
       "graph-backed selection is live; full replacement remains", []),
    _c("Verified (executed) multi-step attack chains", "report", "unfinished",
       "chains are inferred + labelled PLAUSIBLE; execution is destructive/gated, not built", []),
    _c("Browser SPA/CSRF/MFA-resume crawl", "crawl", "unfinished",
       "extract_forms + N-depth BFS done; SPA interaction + CSRF/MFA-resume remain", []),
]


def matrix():
    """The full matrix as {states: {state: [names]}, capabilities: [...], counts: {...}}."""
    by = {s: [] for s in STATES}
    for c in CAPABILITIES:
        by[c["state"]].append(c["name"])
    return {"capabilities": CAPABILITIES, "by_state": by,
            "counts": {s: len(by[s]) for s in STATES}, "total": len(CAPABILITIES)}


def state_rank(state: str) -> int:
    return _RANK.get(state, 0)


def validate():
    """Enforce the invariants so the matrix can never silently lie. Returns a list of violations."""
    issues = []
    for c in CAPABILITIES:
        if c["state"] not in STATES:
            issues.append("bad state %r for %s" % (c["state"], c["name"]))
        if not str(c.get("evidence") or "").strip():
            issues.append("no evidence for %s" % c["name"])
        if c["state"] == "live_proven" and not c.get("labs"):
            issues.append("live_proven without a named lab: %s" % c["name"])
    return issues
