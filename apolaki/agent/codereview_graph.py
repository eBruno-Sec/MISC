"""Code review as pre-recon: seed the ONE engagement graph from static source review (#114 Part 2).

White-box source review is the FIRST reconnaissance sensor. It projects routes, dangerous sinks, and
secrets from the target's own source into the shared AssetGraph as STATIC (source-derived) facts +
CANDIDATE hypotheses — never confirmed findings. The planner then reaches for the matching black-box test
to VALIDATE them (white -> black); when a runtime oracle confirms, link_runtime_to_source() maps the
dynamic evidence back to the exact source location (black -> white). Static + dynamic stay DISTINCT but
LINKED, through one graph — no isolated code-review island. Pure + deterministic; no network.

Boundaries encoded here:
  * a code pattern is a CANDIDATE, not a confirmed finding (confidence <= 0.3, evidence_kind='static');
  * a source route is reachable='unverified' until a live probe proves it (never assumed reachable);
  * a hardcoded secret is stored as a HASH + location only (never the raw value), as a distinct
    'source_secret' node (NOT the runtime 'credential' kind, so it can't auto-trigger cred-testing),
    tested=False, external_test='requires_authorization'.
"""
from __future__ import annotations

import hashlib

# code-review sink tag SUBSTRING -> (vuln-class hypothesis, capability it would unlock) for black-box
# validation. Tags are free-text labels ("dom xss", "code injection / RCE"), so match by substring, most
# specific first. Order matters (e.g. 'sql' before generic 'injection').
_SINK_CLASS = [
    ("xss", ("xss", None)),
    ("sql", ("sqli", "database_read")),
    ("command", ("command_injection", "os_command")),
    ("deserial", ("deserialization", "rce")),
    ("ssrf", ("ssrf", "internal_request")),
    ("ssti", ("ssti", "rce")),
    ("template", ("ssti", "rce")),
    ("traversal", ("path_traversal", "arbitrary_file_read")),
    ("path", ("path_traversal", "arbitrary_file_read")),
    ("upload", ("file_upload", "file_upload")),
    ("code injection", ("code_injection", "rce")),
    ("code", ("code_injection", "rce")),
    ("rce", ("code_injection", "rce")),
]


def _loc(finding: dict) -> str:
    """A 'source:line' location from a code-review finding (its evidence carries 'line N')."""
    src = str(finding.get("target") or "")
    ev = str(finding.get("evidence") or "")
    ln = ""
    if "line" in ev:
        ln = ev.split("line", 1)[1].strip().split(":")[0].strip()
    return ("%s:%s" % (src, ln)) if ln else src


def _sink_class(tags: list):
    for key, val in _SINK_CLASS:
        if any(key in t for t in tags):
            return val
    return ("injection", None)


def seed(graph, review: dict, *, scope_asset: str = "", repo: str = "") -> dict:
    """Project a codereview.review() result into the AssetGraph as STATIC facts + CANDIDATE hypotheses.
    Returns {endpoints, sinks, secrets, nodes_added}. Mutates the graph deterministically."""
    review = review or {}
    n0 = graph.stats()["nodes"]
    counts = {"endpoints": 0, "sinks": 0, "secrets": 0}
    pfx = (repo + ":") if repo else "src:"

    for ep in (review.get("endpoints") or []):
        path = str(ep)
        graph.observe("endpoint", pfx + path, label=path, source="code_review", confidence=0.3,
                      scope_asset=scope_asset, evidence_kind="static", reachable="unverified",
                      provenance_kind="repo")
        counts["endpoints"] += 1

    for f in (review.get("findings") or []):
        tags = [str(t).lower() for t in (f.get("tags") or [])]
        loc = _loc(f)
        if "secrets" in tags:
            # NEVER store the raw secret: hash of (location+title) + type + location only; not auto-tested.
            h = hashlib.sha256((loc + "|" + str(f.get("title"))).encode("utf-8")).hexdigest()[:12]
            graph.observe("source_secret", h, label="source-secret", source="code_review", confidence=0.6,
                          scope_asset=scope_asset, evidence_kind="static", tested=False,
                          external_test="requires_authorization", source_location=loc,
                          secret_type=str(f.get("title") or ""))
            counts["secrets"] += 1
        elif "sink" in tags:
            vc, cap = _sink_class(tags)
            graph.observe("sink", loc + "|" + vc, label=vc, source="code_review", confidence=0.3,
                          scope_asset=scope_asset, evidence_kind="static", vuln_class=vc,
                          source_location=loc, enables=[cap] if cap else [],
                          hypothesis="static sink — needs black-box confirmation to become a finding")
            counts["sinks"] += 1

    counts["nodes_added"] = graph.stats()["nodes"] - n0
    return counts


def link_runtime_to_source(graph, finding_family: str, endpoint: str = "") -> list:
    """Black -> white: when a runtime oracle confirms a finding, cross-reference the matching STATIC sink
    node(s) of the same vuln-class so the report ties exploit evidence to the exact source location.
    Marks those sinks confirmed_at_runtime and returns the linked source location(s)."""
    fam = str(finding_family or "").lower()
    out = []
    for s in graph.nodes("sink"):
        props = s.get("props") or {}
        vc = str(props.get("vuln_class") or "")
        if vc and (vc in fam or fam in vc):
            props["confirmed_at_runtime"] = True
            if props.get("source_location"):
                out.append(props["source_location"])
    return out


def hypotheses(graph) -> list:
    """The static CANDIDATE hypotheses code review seeded (for the planner/report: 'source says X here,
    runtime not yet confirmed'). Distinct from confirmed findings."""
    out = []
    for s in graph.nodes("sink"):
        p = s.get("props") or {}
        out.append({"vuln_class": p.get("vuln_class"), "source_location": p.get("source_location"),
                    "confirmed_at_runtime": bool(p.get("confirmed_at_runtime")),
                    "evidence_kind": "static", "confidence": s.get("confidence")})
    return out
