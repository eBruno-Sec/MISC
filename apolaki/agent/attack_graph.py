"""
Unified attack graph -- one queryable engagement graph that every subsystem publishes into, so recon,
observations, techniques, findings and leads live in ONE model the planner can traverse (CHAD's
keystone: no island of state). Deterministic aggregation over the shared engagement state -- it does
not invent a new source of truth, it composes the existing ones. No LLM.

Node kinds: host, observation, technique, finding, lead.
Edge rels:  observed   (host -> observation)      what recon established
            activates  (observation -> technique) evidence that makes a technique applicable
            confirms   (technique -> finding)      a technique proven into a finding
            surfaced   (host -> lead)              an unconfirmed candidate
            found      (host -> finding)           a confirmed finding on the target
"""
from __future__ import annotations


def build(findings=None, leads=None, observations=None, plan=None, host=""):
    """Assemble the unified attack graph from the engagement's shared state. Pure, deterministic."""
    nodes, edges, seen = [], [], set()

    def node(nid, kind, label, **extra):
        if nid not in seen:
            seen.add(nid)
            nodes.append({"id": nid, "kind": kind, "label": str(label)[:60], **extra})
        return nid

    def edge(a, b, rel):
        edges.append({"source": a, "target": b, "rel": rel})

    h = node("host:" + (host or "target"), "host", host or "target")

    for o in sorted(observations or []):
        oid = node("obs:" + o, "observation", o)
        edge(h, oid, "observed")

    # techniques from the deterministic plan, each ACTIVATED by the observations that gated it in
    fam_tech = {}
    for a in (plan or []):
        tid = node("tech:" + a["id"], "technique", a.get("name") or a["id"],
                   score=a.get("score"), family=a.get("family"))
        if a.get("family"):
            fam_tech.setdefault(str(a["family"]).lower(), tid)
        for pre in (a.get("preconditions_met") or []):
            if ("obs:" + pre) in seen:
                edge("obs:" + pre, tid, "activates")

    # confirmed findings -> the technique of their family CONFIRMS them
    for f in (findings or []):
        fid = node("find:" + str(f.get("title", "finding"))[:40], "finding", f.get("title", "finding"),
                   severity=f.get("severity", "info"))
        edge(h, fid, "found")
        t = fam_tech.get(str(f.get("family", "")).lower())
        if t:
            edge(t, fid, "confirms")

    # unconfirmed leads SURFACED on the target
    for l in (leads or []):
        lid = node("lead:" + str(l.get("title", "lead"))[:40], "lead", l.get("title", "lead"),
                   severity=l.get("severity", "info"))
        edge(h, lid, "surfaced")

    kinds = {}
    for n in nodes:
        kinds[n["kind"]] = kinds.get(n["kind"], 0) + 1
    return {"host": host or "target", "nodes": nodes, "edges": edges,
            "stats": {"nodes": len(nodes), "edges": len(edges), **kinds}}
