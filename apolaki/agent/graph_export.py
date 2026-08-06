"""Sanitized OpenGraph / BloodHound-style export of the canonical AssetGraph (Codex cross-check Tier-2 #7).

An interoperability PROJECTION, not the internal model. The critical discipline (Codex): traversability is
not free — not every graph edge is an attack path.
  * TOPOLOGY edges (has_host / resolves_to / exposes / serves / belongs_to / owns / runs / found_on / ...)
    describe structure. They are NEVER marked as attack-path edges.
  * CAPABILITY edges (enables / authenticated_as) describe a capability transition. `enables` is traversable
    only when EVIDENCE supports it (high confidence or a tested source). `authenticated_as` is a
    capability-bearing, TEMPORARY edge (a session/credential expires).
  * Capability edges carry a precondition + the resulting capability.

Sanitization: NO raw secrets, cookies, or Authorization headers ever leave. Credential/session nodes export a
hash/vault REF only. Evidence/provenance is exported by ID/source-name, never as raw sensitive material.
Every export is labelled with its scope + environment. Pure + offline.
"""
from __future__ import annotations

import hashlib
import time

NAMESPACE = "Apolaki"
FORMAT = "apolaki_opengraph/v1"

_KIND_NS = {
    "host": "Host", "ip": "Host", "domain": "Domain", "subdomain": "Domain", "cidr": "Cidr", "asn": "Asn",
    "webapp": "WebApp", "api": "Api", "endpoint": "Endpoint", "param": "Param", "object": "Object",
    "service": "Service", "port": "Port", "component": "Component",
    "credential": "Credential", "persona": "Persona", "session": "Session", "cloud_account": "CloudAccount",
    "capability": "Capability", "finding": "Finding", "technique": "Technique",
    "repo": "Repo", "commit": "Commit", "org": "Org", "mission": "Mission",
}

# edges that describe STRUCTURE — never an attack path
TOPOLOGY_RELS = {"has_host", "resolves_to", "exposes", "serves", "has_param", "belongs_to", "runs",
                 "found_on", "references", "confirms", "owns"}
# edges that describe a CAPABILITY TRANSITION — candidate attack-path edges
CAPABILITY_RELS = {"enables", "authenticated_as"}
# capability edges whose validity EXPIRES (session/credential-scoped)
TEMPORAL_RELS = {"authenticated_as"}

# node kinds whose value is sensitive — export a ref only, never the raw material
SECRET_KINDS = {"credential", "session", "secret", "source_secret"}
# prop keys that must never be exported raw
_SENSITIVE_PROP = ("secret", "password", "passwd", "token", "authorization", "cookie", "api_key",
                   "apikey", "private_key", "credential", "raw", "value", "session_id", "bearer")

_HIGH = 0.9


def _ns_kind(kind: str) -> str:
    return "%s_%s" % (NAMESPACE, _KIND_NS.get(kind, str(kind or "Node").title().replace("_", "")))


def _ref(s: str) -> str:
    return "ref:" + hashlib.sha256(str(s or "").encode("utf-8", "replace")).hexdigest()[:12]


def _sanitize_props(props: dict) -> dict:
    out = {}
    for k, v in (props or {}).items():
        kl = str(k).lower()
        if any(tok in kl for tok in _SENSITIVE_PROP):
            continue                                    # drop anything sensitive
        if isinstance(v, (str, int, float, bool)):
            out[k] = v
    return out


def _safe_id(n: dict) -> str:
    """The exported node id. For secret kinds the raw AssetGraph id embeds the secret (id = kind:key), so
    it is replaced with a hashed id — the raw value must never leave, not even inside an id or an edge."""
    if n.get("kind") in SECRET_KINDS:
        return "%s:%s" % (n.get("kind"), hashlib.sha256(str(n.get("key") or "").encode("utf-8", "replace")).hexdigest()[:12])
    return n.get("id")


def _export_node(n: dict, scope: str, safe_id: str) -> dict:
    kind = n.get("kind", "")
    is_secret = kind in SECRET_KINDS
    label = _ref(n.get("key") or n.get("label")) if is_secret else n.get("label")
    raw_props = n.get("props") or {}
    props = _sanitize_props(raw_props)
    props.pop("reachable", None)
    props.pop("provenance_kind", None)
    out = {
        "id": safe_id, "kind": _ns_kind(kind), "label": label,
        "scope": n.get("scope_asset") or scope,
        "properties": {
            "confidence": round(float(n.get("confidence") or 0.0), 3),
            "tested": bool(n.get("tested")),
            "reachable": raw_props.get("reachable"),
            "provenance_kind": raw_props.get("provenance_kind"),
            **props,
        },
        # evidence/provenance by ID/source-name, never raw material
        "evidence_refs": [s.get("source") for s in (n.get("sources") or []) if s.get("source")],
        "capabilities": list(n.get("enables") or []),
    }
    if is_secret:
        out["properties"]["ref"] = label            # hash/vault ref only — no raw secret
        out["properties"]["redacted"] = True
    if kind == "session":
        out["expires"] = (n.get("props") or {}).get("expires")   # temporary node
    return out


def _classify_edge(edge: dict, nodes_by_id: dict, id_map: dict) -> dict:
    rel = edge.get("rel", "")
    conf = float(edge.get("confidence") or 0.0)
    tgt = nodes_by_id.get(edge.get("target")) or {}
    src = nodes_by_id.get(edge.get("source")) or {}
    src_id = id_map.get(edge.get("source"), edge.get("source"))
    tgt_id = id_map.get(edge.get("target"), edge.get("target"))
    if rel in CAPABILITY_RELS:
        edge_class = "capability"
        if rel == "enables":
            # capability-bearing ONLY when evidence supports it
            traversable = conf >= _HIGH or bool(src.get("tested"))
            resulting = tgt.get("key") if tgt.get("kind") == "capability" else (tgt.get("label") or edge.get("target"))
            precondition = "control of %s" % (src.get("label") or edge.get("source"))
        else:  # authenticated_as
            traversable = True
            resulting = "authenticated_access:%s" % (tgt.get("label") or edge.get("target"))
            precondition = "valid session/credential"
    else:
        edge_class, traversable, resulting, precondition = "topology", False, None, None
    out = {
        "source": src_id, "target": tgt_id, "kind": rel,
        "edge_class": edge_class, "traversable": bool(traversable),
        "confidence": round(conf, 3),
        "precondition": precondition, "resulting_capability": resulting,
    }
    if rel in TEMPORAL_RELS:
        out["temporary"] = True
        out["expires"] = (edge.get("expires") or (src.get("props") or {}).get("expires"))
    return out


def export_graph(graph, *, scope: str = "", environment: str = "unknown") -> dict:
    """Project an AssetGraph (or its to_dict()) into a sanitized, namespaced OpenGraph document. Topology
    edges are never attack paths; only capability edges with traversable=true are."""
    data = graph.to_dict() if hasattr(graph, "to_dict") else (graph or {})
    raw_nodes = data.get("nodes") or []
    raw_edges = data.get("edges") or []
    nodes_by_id = {n.get("id"): n for n in raw_nodes}
    id_map = {n.get("id"): _safe_id(n) for n in raw_nodes}
    nodes = [_export_node(n, scope, id_map[n.get("id")]) for n in raw_nodes]
    edges = [_classify_edge(e, nodes_by_id, id_map) for e in raw_edges]
    traversable = [e for e in edges if e["traversable"]]
    return {
        "format": FORMAT, "namespace": NAMESPACE,
        "scope": scope, "environment": environment,
        "generated_at": int(time.time()),
        "node_count": len(nodes), "edge_count": len(edges),
        "traversable_edge_count": len(traversable),
        "nodes": nodes, "edges": edges,
        "note": ("Topology edges describe structure and are NOT attack paths; only capability edges with "
                 "traversable=true are traversable capability transitions. Secrets are exported as refs only."),
    }
