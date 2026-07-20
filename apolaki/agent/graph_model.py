"""
Knowledge graph over the discovered attack surface.

A deterministic VIEW built from data Apolaki already holds — the recon
accumulator, the URL/endpoint inventory, and confirmed findings — as typed nodes
and edges so the agent (and the topology UI) can reason over RELATIONSHIPS
instead of a flat list. Pure: no AI, no network. The graph is the brain; the UI
renders the same tidy layered tree and highlights a node's neighbours on demand
(no hairball).

Node kinds : domain, host, endpoint, tech, finding
Edges      : domain -has_host-> host, host -serves-> endpoint,
             host -runs-> tech, endpoint -found-> finding (or host -found-> finding)
"""
from __future__ import annotations

from urllib.parse import urlparse

import surface as surface_mod


def _root(host: str) -> str:
    h = (host or "").split(":")[0]
    parts = h.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else h


def _host_of(url: str) -> str:
    try:
        return urlparse(url).netloc
    except Exception:
        return ""


def build_graph(recon: dict = None, urls: list = None, findings: list = None,
                cap_endpoints: int = 400) -> dict:
    """Return {"nodes":[...], "edges":[...], "stats":{...}} — deterministic."""
    recon = recon or {}
    urls = urls or []
    findings = findings or []
    nodes: dict = {}
    edges: list = []
    seen_edge = set()

    def node(nid: str, kind: str, label: str, **meta):
        if nid and nid not in nodes:
            nodes[nid] = {"id": nid, "kind": kind, "label": label, **meta}

    def edge(s: str, t: str, rel: str):
        if s in nodes and t in nodes:
            k = (s, t, rel)
            if k not in seen_edge:
                seen_edge.add(k)
                edges.append({"source": s, "target": t, "rel": rel})

    # ── hosts (live hosts + subdomains + url hosts) ──
    live = {}
    for h in (recon.get("live_hosts") or []):
        host = _host_of(h.get("url") or "") or (h.get("url") or "")
        if host:
            live[host] = h
    hosts = set(live)
    hosts |= {s for s in (recon.get("subdomains") or []) if s}
    hosts |= {_host_of(u) for u in urls if _host_of(u)}
    for host in sorted(hosts):
        hid = f"host:{host}"
        node(hid, "host", host)
        did = f"domain:{_root(host)}"
        node(did, "domain", _root(host))
        edge(did, hid, "has_host")

    # ── tech per host ──
    for host, h in live.items():
        hid = f"host:{host}"
        for t in (h.get("tech") or []):
            tid = f"tech:{t}"
            node(tid, "tech", t)
            edge(hid, tid, "runs")

    # ── endpoints from the URL inventory ──
    ep_index = {}   # (host, path) -> endpoint id
    inv = surface_mod.build_inventory(urls)
    per_host = {}
    for e in inv:
        host = e["host"]
        if per_host.get(host, 0) >= cap_endpoints:
            continue
        per_host[host] = per_host.get(host, 0) + 1
        hid = f"host:{host}"
        node(hid, "host", host)
        node(f"domain:{_root(host)}", "domain", _root(host))
        edge(f"domain:{_root(host)}", hid, "has_host")
        eid = f"ep:{host}{e['path']}"
        node(eid, "endpoint", e["path"], host=host, params=e.get("params") or [],
             example=e.get("example"))
        edge(hid, eid, "serves")
        ep_index[(host, e["path"])] = eid

    # ── findings, linked to their endpoint (else host) ──
    for f in findings:
        fid = f"finding:{f.get('id') or f.get('title', '')[:24]}"
        sev = (f.get("severity") or "info").lower()
        node(fid, "finding", f.get("title", "Finding"), severity=sev,
             target=f.get("target", ""), cwe=f.get("cwe", ""))
        tgt = f.get("target", "")
        host = _host_of(tgt)
        path = (urlparse(tgt).path or "/") if tgt else ""
        linked = ep_index.get((host, path))
        if linked:
            edge(linked, fid, "found")
        elif host and f"host:{host}" in nodes:
            edge(f"host:{host}", fid, "found")

    stats = {"nodes": len(nodes), "edges": len(edges),
             "hosts": sum(1 for n in nodes.values() if n["kind"] == "host"),
             "endpoints": sum(1 for n in nodes.values() if n["kind"] == "endpoint"),
             "findings": sum(1 for n in nodes.values() if n["kind"] == "finding")}
    return {"nodes": list(nodes.values()), "edges": edges, "stats": stats}


def neighbors(graph: dict, node_id: str) -> list:
    """All node ids directly connected to node_id (either direction)."""
    out = []
    for e in graph.get("edges", []):
        if e["source"] == node_id:
            out.append(e["target"])
        elif e["target"] == node_id:
            out.append(e["source"])
    return list(dict.fromkeys(out))


def related_findings(graph: dict, node_id: str) -> list:
    """Finding nodes reachable within 2 hops (endpoint->finding, host->ep->finding)."""
    byid = {n["id"]: n for n in graph.get("nodes", [])}
    reach = set(neighbors(graph, node_id))
    for nb in list(reach):
        reach |= set(neighbors(graph, nb))
    return [byid[n] for n in reach if byid.get(n, {}).get("kind") == "finding"]
