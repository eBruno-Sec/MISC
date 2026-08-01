"""
Canonical asset & intelligence graph.

ONE node/edge store that every phase reads AND writes. Where graph_model.py renders a tidy
topology TREE for the UI, this is the durable brain: each fact is a node or edge that carries
PROVENANCE — where it came from, when, how confident, which scope asset owns it, what it might
unlock, and whether it has been tested yet. The planner queries it ("what do I know, what is
untested, what could it enable?") instead of re-deriving from flat lists.

Pure + deterministic: no AI, no network. Persists to JSON per mission so a later scan resumes the
world model. Secrets never live here — a credential/persona node stores a vault reference, never the
raw secret (see vault.py).

Node kinds (open set): org, scope_rule, domain, subdomain, host, ip, cidr, asn, port, service,
webapp, api, endpoint, param, object, credential, persona, session, cloud_account, repo, commit,
component, finding, capability, technique, mission.
Edge rels (open set): has_host, resolves_to, exposes, serves, has_param, owns, authenticated_as,
enables, confirms, references, belongs_to, runs, found_on.
"""
from __future__ import annotations

import json
import os
import time

# confidence rungs — a fact's strength, raised (never silently lowered) as evidence accrues.
LOW, MEDIUM, HIGH, CONFIRMED = 0.3, 0.6, 0.9, 1.0


def _now() -> float:
    return time.time()


def _nid(kind: str, key: str) -> str:
    return f"{kind}:{key}"


class AssetGraph:
    def __init__(self, mission_id: str = "default"):
        self.mission_id = mission_id
        self._nodes: dict = {}
        self._edges: dict = {}   # (src, dst, rel) -> edge

    # ── writing facts ──
    def observe(self, kind: str, key: str, *, label: str = None, source: str = "",
                confidence: float = MEDIUM, scope_asset: str = "", enables=None,
                tested: bool = None, **props) -> str:
        """Add or MERGE a fact. Idempotent by (kind, key). Appends the source to provenance, raises
        confidence to the max seen, refreshes last_seen, and merges props. Returns the node id."""
        nid = _nid(kind, key)
        n = self._nodes.get(nid)
        now = _now()
        if n is None:
            n = {"id": nid, "kind": kind, "key": key, "label": label or key,
                 "confidence": float(confidence), "scope_asset": scope_asset,
                 "sources": [], "enables": [], "consumed_by": [],
                 "tested": bool(tested) if tested is not None else False,
                 "tested_ts": None, "first_seen": now, "last_seen": now, "props": {}}
            self._nodes[nid] = n
        else:
            n["confidence"] = max(n["confidence"], float(confidence))
            n["last_seen"] = now
            if label:
                n["label"] = label
            if scope_asset and not n.get("scope_asset"):
                n["scope_asset"] = scope_asset
            if tested is not None:
                n["tested"] = n["tested"] or bool(tested)
        if source and source not in [s["source"] for s in n["sources"]]:
            n["sources"].append({"source": source, "ts": now})
        for cap in (enables or []):
            if cap not in n["enables"]:
                n["enables"].append(cap)
        for k, v in props.items():
            if v is not None:
                n["props"][k] = v
        return nid

    def link(self, src_id: str, dst_id: str, rel: str, *, source: str = "",
             confidence: float = MEDIUM) -> bool:
        """Add a typed edge (idempotent). Both endpoints must already be nodes."""
        if src_id not in self._nodes or dst_id not in self._nodes:
            return False
        k = (src_id, dst_id, rel)
        e = self._edges.get(k)
        now = _now()
        if e is None:
            self._edges[k] = {"source": src_id, "target": dst_id, "rel": rel,
                              "provenance": source, "confidence": float(confidence),
                              "first_seen": now, "last_seen": now}
        else:
            e["last_seen"] = now
            e["confidence"] = max(e["confidence"], float(confidence))
        return True

    def mark_tested(self, node_id: str, ok: bool = True) -> None:
        n = self._nodes.get(node_id)
        if n:
            n["tested"] = True
            n["tested_ts"] = _now()
            n["props"]["test_result"] = "confirmed" if ok else "negative"

    def mark_consumed(self, node_id: str, tool: str) -> None:
        n = self._nodes.get(node_id)
        if n and tool and tool not in n["consumed_by"]:
            n["consumed_by"].append(tool)

    def add_enable(self, node_id: str, capability: str) -> None:
        n = self._nodes.get(node_id)
        if n and capability and capability not in n["enables"]:
            n["enables"].append(capability)

    # ── reading facts ──
    def node(self, node_id: str):
        return self._nodes.get(node_id)

    def nodes(self, kind: str = None) -> list:
        return [n for n in self._nodes.values() if kind is None or n["kind"] == kind]

    def edges(self, rel: str = None) -> list:
        return [e for e in self._edges.values() if rel is None or e["rel"] == rel]

    def neighbors(self, node_id: str, rel: str = None) -> list:
        out = []
        for e in self._edges.values():
            if rel is not None and e["rel"] != rel:
                continue
            if e["source"] == node_id:
                out.append(e["target"])
            elif e["target"] == node_id:
                out.append(e["source"])
        return list(dict.fromkeys(out))

    def untested(self, kind: str = None) -> list:
        """Nodes not yet tested — the planner's worklist ('what might this unlock, was it tested?')."""
        return [n for n in self.nodes(kind) if not n.get("tested")]

    def in_scope(self, scope_asset: str) -> list:
        return [n for n in self._nodes.values() if n.get("scope_asset") == scope_asset]

    def enabling(self, capability: str) -> list:
        """Nodes whose provenance says they could unlock a given capability/technique."""
        return [n for n in self._nodes.values() if capability in (n.get("enables") or [])]

    def next_best_actions(self, limit: int = 10) -> list:
        """Deterministic next-best-action list — the planner querying the world model. Ranks
        unrealized capability chains (a confirmed finding enables X, but X isn't achieved yet) above
        untested services above untested object endpoints. Pure; drives the autonomy loop."""
        have = {n["key"] for n in self.nodes("capability")}
        out = []
        for f in self.nodes("finding"):
            for cap in (f.get("enables") or []):
                if cap not in have:
                    out.append({"score": 8, "action": "chase_capability", "capability": cap,
                                "target": f["label"],
                                "rationale": "a confirmed finding enables '%s' — chase it" % cap})
        for s in self.untested("service"):
            out.append({"score": 6, "action": "run_service_pack", "service": s["label"],
                        "target": s["key"], "enables": s.get("enables", []),
                        "rationale": "a %s service was discovered but its technique pack has not run" % s["label"]})
        for o in self.untested("object"):
            out.append({"score": 4, "action": "cross_user_test", "target": o["label"],
                        "rationale": "object endpoint not yet compared across personas (IDOR/BOLA)"})
        seen, uniq = set(), []
        for a in sorted(out, key=lambda x: -x["score"]):
            k = (a["action"], a.get("target"), a.get("capability"))
            if k in seen:
                continue
            seen.add(k)
            uniq.append(a)
        return uniq[:limit]

    # ── persistence ──
    def to_dict(self) -> dict:
        return {"mission_id": self.mission_id,
                "nodes": list(self._nodes.values()),
                "edges": list(self._edges.values())}

    @classmethod
    def from_dict(cls, data: dict) -> "AssetGraph":
        g = cls((data or {}).get("mission_id", "default"))
        for n in (data or {}).get("nodes", []):
            g._nodes[n["id"]] = n
        for e in (data or {}).get("edges", []):
            g._edges[(e["source"], e["target"], e["rel"])] = e
        return g

    def stats(self) -> dict:
        by_kind: dict = {}
        for n in self._nodes.values():
            by_kind[n["kind"]] = by_kind.get(n["kind"], 0) + 1
        return {"nodes": len(self._nodes), "edges": len(self._edges),
                "by_kind": by_kind, "untested": len(self.untested())}

    def save(self, base_dir: str = None) -> str:
        base = base_dir or os.path.join(os.environ.get("BBH_DATA_DIR", "/app/data"), "graph")
        try:
            os.makedirs(base, exist_ok=True)
            safe = "".join(c for c in str(self.mission_id) if c.isalnum() or c in "-_") or "default"
            path = os.path.join(base, f"{safe}.json")
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f)
            os.replace(tmp, path)
            return path
        except Exception:
            return ""

    @classmethod
    def load(cls, mission_id: str, base_dir: str = None) -> "AssetGraph":
        base = base_dir or os.path.join(os.environ.get("BBH_DATA_DIR", "/app/data"), "graph")
        safe = "".join(c for c in str(mission_id) if c.isalnum() or c in "-_") or "default"
        try:
            with open(os.path.join(base, f"{safe}.json"), "r", encoding="utf-8") as f:
                return cls.from_dict(json.load(f))
        except Exception:
            return cls(mission_id)


# finding family/class -> the capability it typically UNLOCKS (advisory provenance, not a hardcoded
# exploit). Lets the planner ask "which fact could give me database_read / a foreign object read?"
_FINDING_ENABLES = {
    "sql_injection": ["database_read"], "sqli": ["database_read"],
    "nosql_injection": ["database_read"],
    "idor": ["foreign_object_read"], "access_control": ["foreign_object_read"],
    "sensitive_exposure": ["credential_material"], "xxe": ["internal_request", "arbitrary_file_read"],
    "ssrf": ["internal_request"], "file_upload": ["file_upload"],
}


def build_from_engagement(mission_id: str, *, recon: dict = None, urls: list = None,
                          findings: list = None, personas: dict = None, capabilities: list = None,
                          services: list = None, scope_asset: str = "") -> "AssetGraph":
    """Project the engagement's gathered intelligence into the canonical graph WITH provenance —
    hosts, endpoints, object endpoints, params, findings (+ what they enable), personas (vault refs
    only), confirmed capabilities, and non-web services (beyond-web routing). Deterministic; reuses
    surface.build_inventory. Every phase's output lands as connected, provenance-tagged nodes."""
    import surface as _surface
    import authz_matrix as _am
    from urllib.parse import urlparse as _up
    g = AssetGraph(mission_id)
    recon, urls, findings = recon or {}, urls or [], findings or []

    def _host(u):
        try:
            return _up(u).netloc
        except Exception:
            return ""

    # hosts + endpoints + object endpoints + params
    for inv in _surface.build_inventory(urls):
        host = inv.get("host") or ""
        path = inv.get("path") or "/"
        hid = g.observe("host", host, source="recon", scope_asset=scope_asset or host) if host else None
        eid = g.observe("endpoint", (host + path) if host else path, label=path, source="recon",
                        scope_asset=scope_asset)
        if hid:
            g.link(hid, eid, "serves", source="recon")
        if _am.is_object_path(path):
            oid = g.observe("object", (host + path) if host else path, label=path, source="recon",
                            scope_asset=scope_asset, enables=["foreign_object_read"])
            g.link(eid, oid, "exposes", source="recon")
        for p in (inv.get("params") or []):
            pid = g.observe("param", (host + path + "?" + str(p)), label=str(p), source="recon")
            g.link(eid, pid, "has_param", source="recon")

    # findings + what they unlock
    for f in findings:
        key = f.get("id") or (f.get("title", "")[:40] + "@" + (f.get("target", "") or ""))
        fam = (f.get("family") or "").lower()
        fid = g.observe("finding", key, label=f.get("title", "Finding"), source="scan",
                        confidence=CONFIRMED if f.get("confidence") == "confirmed" else MEDIUM,
                        scope_asset=scope_asset, enables=_FINDING_ENABLES.get(fam, []),
                        severity=(f.get("severity") or "info"), cwe=f.get("cwe", ""), family=fam)
        g.mark_tested(fid, ok=(f.get("confidence") == "confirmed"))
        tgt = f.get("target", "")
        th = _host(tgt)
        tp = (_up(tgt).path or "/") if tgt else ""
        ep = g.node(_nid("endpoint", th + tp))
        if ep:
            g.link(ep["id"], fid, "found_on", source="scan")
        elif th and g.node(_nid("host", th)):
            g.link(_nid("host", th), fid, "found_on", source="scan")

    # personas (vault refs only — never secrets)
    for p in ((personas or {}).get("personas") or []):
        role = p.get("role")
        if not role:
            continue
        pid = g.observe("persona", role, label=role, source="registration",
                        rank=p.get("rank"), method=p.get("method"), has_session=p.get("has_session"),
                        identity=p.get("identity"))
        if p.get("has_session"):
            g.observe("session", role, label="session:" + role, source="acquire_session")
            g.link(pid, _nid("session", role), "authenticated_as", source="acquire_session")

    # non-web services (beyond-web routing) -> service nodes + what their checks could unlock
    try:
        import service_router as _sr
        for r in _sr.route(services or []):
            if r["is_web"] or r["service"] == "unknown":
                continue
            key = "%s:%s" % (r.get("host", ""), r.get("port"))
            enables = sorted({e for c in r["checks"] for e in c.get("enables", [])})
            sid = g.observe("service", key, label=r["service"], source="service_router",
                            scope_asset=scope_asset, enables=enables, service=r["service"], port=r.get("port"))
            if r.get("host"):
                hid = g.observe("host", r["host"], source="recon", scope_asset=scope_asset or r["host"])
                g.link(hid, sid, "runs", source="service_router")
    except Exception:
        pass

    # confirmed capabilities
    for cap in (capabilities or []):
        cid = g.observe("capability", cap, label=cap, source="engagement", confidence=CONFIRMED, tested=True)
        for fn in g.nodes("finding"):
            if cap in (fn.get("enables") or []):
                g.link(fn["id"], cid, "enables", source="scan")
    return g
