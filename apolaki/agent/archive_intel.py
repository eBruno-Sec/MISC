"""
Web-archive + source-code intelligence -> provenance-tagged asset-graph facts.

Archived (Wayback) endpoints and GitHub-discovered routes/secret-references are RECOVERED
intelligence, NOT present vulnerabilities — so they enter the canonical graph flagged UNVALIDATED
(tested=False) with their source and LOW confidence, and needs_validation() lists them for a bounded
CURRENT check before they are ever treated as findings. This implements the provenance flow CHAD
asked for (review #9):

    archived/repo fact  ->  graph node (source, low confidence, tested=False)
                        ->  current validation against the in-scope target
                        ->  matched technique  ->  tested result recorded

Pure: it only shapes facts into the graph + reports the validation queue. The live validation runs
through the scoped transport; the raw secret NEVER lands here — a repo secret is a vault reference.
"""
from __future__ import annotations

from urllib.parse import urlparse

import asset_graph as _ag


def ingest_archived_endpoints(graph, host: str, urls, source: str = "wayback") -> int:
    """Archived endpoints -> endpoint nodes tagged (source, archived=True, tested=False, LOW conf).
    An archived path is a HINT to validate against the current target, not a live finding."""
    n = 0
    for u in (urls or []):
        p = urlparse(str(u))
        path = p.path or "/"
        h = p.netloc or host
        if not path or path == "/":
            continue
        graph.observe("endpoint", (h + path) if h else path, label=path, source=source,
                      confidence=_ag.LOW, archived=True, tested=False, provenance_kind="archive")
        n += 1
    return n


def ingest_repo_findings(graph, repo: str, items, source: str = "github") -> int:
    """GitHub-discovered facts -> graph nodes with provenance. Each item is
    {kind: route|secret|cloud_name, value: <path/name>, ref: <vault:// for a secret>} — a SECRET's
    raw value is NEVER stored here (only its vault reference); everything is flagged for bounded,
    authorized current validation."""
    n = 0
    for it in (items or []):
        kind = (it or {}).get("kind")
        val = (it or {}).get("value") or ""
        if kind == "route" and val:
            graph.observe("endpoint", val, label=val, source=source, confidence=_ag.LOW,
                          tested=False, provenance_kind="repo", repo=repo)
            n += 1
        elif kind == "secret":
            # store only a HASH fingerprint + vault reference — never the raw secret value
            import hashlib
            fp = hashlib.sha256((val or "").encode("utf-8")).hexdigest()[:12]
            graph.observe("credential", "%s:%s" % (repo, fp), label="repo-secret",
                          source=source, confidence=_ag.LOW, tested=False, provenance_kind="repo",
                          identity_ref=it.get("ref"), repo=repo)
            n += 1
        elif kind == "cloud_name" and val:
            graph.observe("cloud_account", val, label=val, source=source, confidence=_ag.LOW,
                          tested=False, provenance_kind="repo", repo=repo)
            n += 1
    return n


def needs_validation(graph) -> list:
    """The validation queue: archive/repo-derived nodes not yet checked against the CURRENT target.
    The planner turns each into a bounded live probe before it can become a finding."""
    out = []
    for node in graph._nodes.values():
        if node.get("props", {}).get("provenance_kind") in ("archive", "repo") and not node.get("tested"):
            out.append({"id": node["id"], "kind": node["kind"], "label": node["label"],
                        "source": (node.get("sources") or [{}])[0].get("source"),
                        "provenance": node["props"].get("provenance_kind")})
    return out


def mark_validated(graph, node_id: str, present: bool) -> None:
    """Record the current-validation result: present=True means the archived/repo fact EXISTS on the
    live target now (so downstream techniques may run); present=False retires it as historical-only."""
    graph.mark_tested(node_id, ok=present)
    n = graph.node(node_id)
    if n is not None:
        n["props"]["current_state"] = "present" if present else "gone"
        if present:
            n["confidence"] = max(n.get("confidence", 0), _ag.MEDIUM)
