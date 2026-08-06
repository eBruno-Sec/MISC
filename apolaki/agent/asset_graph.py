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

# ── Cosmos-style temporal confidence decay ──
# An UNVERIFIED fact loses PLANNING weight as it ages, so a stale discovered-but-unconfirmed asset
# never drives the plan like a freshly-seen one. A TESTED fact is ground truth and does NOT decay
# (the retest/closure loop re-verifies those). Half-life is env-tunable. Deterministic, pure.
CONF_HALFLIFE_DAYS = float(os.environ.get("ASSET_CONF_HALFLIFE_DAYS", "14") or 14.0)
CONF_FLOOR = 0.05           # decay never silently reaches zero — a fact keeps a trace of weight
_DAY = 86400.0

# ── Pentera-style attack-path utility ──
# Business-impact weight per capability a step would UNLOCK (advisory + evidence-aware — it ranks
# opportunities, it never inflates a finding's severity beyond what an oracle proved).
_IMPACT = {
    "rce": 1.0, "remote_code_execution": 1.0, "os_command": 1.0,
    "arbitrary_file_write": 0.9, "database_read": 0.9, "credential_material": 0.85,
    "arbitrary_file_read": 0.85, "account_takeover": 0.85, "internal_request": 0.7,
    "ssrf": 0.7, "file_upload": 0.7, "foreign_object_read": 0.6,
}
_DEFAULT_IMPACT = 0.4


def _now() -> float:
    return time.time()


def decay_factor(age_seconds, halflife_days=None, now=None):
    """Exponential decay in [CONF_FLOOR, 1.0] for a fact of the given age. age<=0 -> 1.0. Pure."""
    hl = (halflife_days if halflife_days is not None else CONF_HALFLIFE_DAYS) or 14.0
    if age_seconds is None or age_seconds <= 0:
        return 1.0
    f = 0.5 ** ((age_seconds / _DAY) / hl)
    return max(CONF_FLOOR, min(1.0, f))


def utility_score(probability, impact, evidence_confidence, cost=1.0, risk=1.0, duplication=1.0):
    """Pentera-style utility = P(success) x impact x evidence_confidence / (cost x risk x duplication).
    Simplest defensible form; every factor is bounded > 0. Deterministic, no LLM. The graph's ranking
    of WHICH opportunity to pursue next — most valuable, most certain, cheapest, least risky, first."""
    denom = max(1e-6, float(cost) * float(risk) * float(duplication))
    return round(float(probability) * float(impact) * float(evidence_confidence) / denom, 4)


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

    def decayed_confidence(self, node, now: float = None) -> float:
        """Effective PLANNING confidence for a node (Cosmos lifecycle): a TESTED fact holds its stored
        confidence (it was verified); an UNVERIFIED fact decays from last_seen toward CONF_FLOOR so
        stale unconfirmed intel loses weight in ranking + gating. Pure; missing timestamps -> no decay."""
        if not node:
            return MEDIUM
        base = float(node.get("confidence", MEDIUM))
        if node.get("tested"):
            return base
        ls = node.get("last_seen")
        if not ls:
            return base
        return round(base * decay_factor((now or _now()) - ls, now=now), 4)

    _REDIRECT_HINTS = ("redirect", "return", "returnurl", "next", "goto", "dest", "url", "continue", "callback")
    _SEARCH_HINTS = ("q", "query", "search", "s", "keyword", "term")
    _UPLOAD_HINTS = ("file", "upload", "filename", "path", "dir")

    def ingest_intel(self, intel: dict, source: str = "harvest") -> int:
        """Project the intel HARVEST (candidates by kind) into the graph as typed nodes so the planner
        reads the FULL observation vocabulary from the graph, not from flat lists. Secrets are never
        stored raw — a credential is hashed. Returns the number of nodes added. Pure."""
        import hashlib
        cands = (intel or {}).get("candidates") or {}
        n0 = len(self._nodes)
        for oid in cands.get("object_id", []) or []:
            self.observe("object", str(oid), label=str(oid), source=source, enables=["foreign_object_read"])
        for pm in cands.get("param", []) or []:
            name = str(pm).lower()
            role = ("redirect" if any(h in name for h in self._REDIRECT_HINTS)
                    else "search" if name in self._SEARCH_HINTS or "search" in name
                    else "upload" if any(h in name for h in self._UPLOAD_HINTS)
                    else "generic")
            self.observe("param", str(pm), label=str(pm), source=source, role=role)
        for v in cands.get("version", []) or []:
            self.observe("component", str(v), label=str(v), source=source)
        for c in cands.get("credential", []) or []:
            self.observe("credential", hashlib.sha256(str(c).encode("utf-8")).hexdigest()[:12],
                         label="exposed-credential", source=source)
        for cp in cands.get("coupon", []) or []:
            self.observe("coupon", str(cp)[:24], label="coupon-code", source=source)
        for r in (cands.get("route", []) or []) + (cands.get("endpoint", []) or []):
            self.observe("endpoint", str(r), label=str(r), source=source)
        return len(self._nodes) - n0

    def to_observations(self) -> set:
        """Project the graph to the planner's observation vocabulary (technique_planner.OBSERVATIONS)
        so the deterministic planner reads the WORLD MODEL directly. With ingest_intel() feeding it,
        this now covers most of the vocabulary the flat recon path derives (the flat path remains a
        fallback for serves_js / has_workflow, which come from code-intelligence)."""
        obs = set()
        if self.nodes("object"):
            obs.add("has_object_id")
        if self.nodes("component"):
            obs.add("has_versions")
        if self.nodes("coupon"):
            obs.add("has_coupon")
        caps = {n["key"] for n in self.nodes("capability")}
        if self.nodes("credential") or "credentials_exposed" in caps:
            obs.add("credentials_exposed")
        if "session_acquired" in caps:
            obs.add("authenticated")
        for pnode in self.nodes("param"):
            role = (pnode.get("props") or {}).get("role")
            if role == "redirect":
                obs.add("has_redirect_param")
            elif role == "search":
                obs.add("has_search_param")
            elif role == "upload":
                obs.add("has_file_upload")
        for e in self.nodes("endpoint"):
            low = (e.get("label") or e.get("key") or "").lower()
            if any(k in low for k in ("/login", "/signin", "/sign-in", "/auth", "/session")):
                obs.add("has_login")
            if "/api" in low or "/rest" in low or "/graphql" in low:
                obs.add("has_api")
            if "upload" in low or "/file" in low:
                obs.add("has_file_upload")
            if any(k in low for k in ("xml", "soap", "xxe")):
                obs.add("has_xml_input")
            if any(k in low for k in ("/admin", "/manage", "/internal", "/config", "/settings", "/debug", "/audit")):
                obs.add("has_sensitive_route")
        for f in self.nodes("finding"):
            fam = ((f.get("props") or {}).get("family") or "").lower()
            if fam in ("xss", "reflected_xss", "stored_xss", "dom_xss"):
                obs.add("reflects_input")
            if fam in ("sqli", "sql_injection", "nosqli", "nosql_injection"):
                obs.add("sql_error_seen")
        return obs

    def next_best_actions(self, limit: int = 10, now: float = None) -> list:
        """Deterministic next-best-action list — the planner querying the world model, RANKED BY
        UTILITY (Pentera) with Cosmos-decayed evidence confidence. Ranks unrealized capability chains
        (a confirmed finding enables X, but X isn't achieved yet) above untested services above
        untested object endpoints, but WITHIN and ACROSS those by expected value: impact x certainty /
        cost / risk. Each action carries its utility + the factor breakdown so the ranking is
        inspectable, never a black box. Pure; drives the autonomy loop."""
        now = now or _now()
        have = {n["key"] for n in self.nodes("capability")}
        out = []

        def _emit(base_score, action, evidence_conf, probability, impact, cost, risk, **extra):
            fac = {"probability": round(probability, 3), "impact": round(impact, 3),
                   "evidence_confidence": round(evidence_conf, 3), "cost": cost, "risk": risk,
                   "duplication": 1.0}
            out.append({"score": base_score, "action": action,
                        "utility": utility_score(**fac), "utility_factors": fac, **extra})

        for f in self.nodes("finding"):
            fconf = self.decayed_confidence(f, now)
            for cap in (f.get("enables") or []):
                if cap not in have:
                    # a CONFIRMED finding already enables this — high odds the chain completes
                    _emit(8, "chase_capability", fconf, 0.8, _IMPACT.get(cap, _DEFAULT_IMPACT), 1.0, 1.0,
                          capability=cap, target=f["label"],
                          rationale="a confirmed finding enables '%s' — chase it" % cap)
        for s in self.untested("service"):
            enables = s.get("enables", []) or []
            impact = max([_IMPACT.get(e, _DEFAULT_IMPACT) for e in enables] or [0.5])
            # beyond-web probe: service exists (medium prob its pack confirms), slightly higher risk/cost
            _emit(6, "run_service_pack", self.decayed_confidence(s, now), 0.5, impact, 1.5, 1.2,
                  service=s["label"], target=s["key"], enables=enables,
                  rationale="a %s service was discovered but its technique pack has not run" % s["label"])
        for o in self.untested("object"):
            _emit(4, "cross_user_test", self.decayed_confidence(o, now), 0.5, _IMPACT["foreign_object_read"],
                  1.8, 1.0, target=o["label"],
                  rationale="object endpoint not yet compared across personas (IDOR/BOLA)")

        seen, uniq = set(), []
        # utility-primary, then the tier score, so ties fall back to the old ordering (stable, testable)
        for a in sorted(out, key=lambda x: (-x.get("utility", 0), -x["score"])):
            k = (a["action"], a.get("target"), a.get("capability"))
            if k in seen:
                continue
            seen.add(k)
            uniq.append(a)
        return uniq[:limit]

    def plan_next(self):
        """The SINGLE next action the graph recommends (top of next_best_actions), or None when the
        world model has nothing left to pursue. This is the planner querying the graph as its brain —
        the action is chosen from graph state (unrealized capabilities, untested services/objects),
        not from a flat script."""
        acts = self.next_best_actions(limit=1)
        return acts[0] if acts else None

    def apply_result(self, action: dict, *, tested_ok=None, gained_capability=None) -> None:
        """Fold an executed action's RESULT back into the graph so the NEXT plan_next() reflects it —
        the close-the-loop step that makes the graph the source of truth (plan -> act -> update ->
        REPLAN), not a one-shot read. Marks the action's target node tested and/or records a newly
        gained capability node so a satisfied precondition stops being suggested."""
        tgt = (action or {}).get("target")
        if tgt and tested_ok is not None:
            # mark EVERY node matching the target (an endpoint and its object may share a label); a
            # single-match break could mark the wrong kind and leave the intended node forever untested.
            for n in list(self._nodes.values()):
                if n.get("key") == tgt or n.get("label") == tgt:
                    self.mark_tested(n["id"], ok=tested_ok)
        if gained_capability:
            self.observe("capability", gained_capability, source="planner")

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

    # intel feeds whose facts are RECOVERED (historical / external), not observed live on the
    # target — every one of these carries a needs-current-validation obligation before its facts
    # may be treated as present. Kept in one place so the report and the planner agree.
    _PASSIVE_SOURCES = ("wayback", "github", "cloud_intel", "cloud_probe")

    def provenance_summary(self) -> dict:
        """WHERE the world model came from: per-source node contribution, the passive-intel feeds
        (wayback / github / cloud) broken out, and the needs-validation worklist — archive/repo
        facts not yet checked against the CURRENT target, which must NOT be reported as live
        findings until validated. Pure; credentials are already hashes/vault refs, so nothing raw
        leaks here. This is what turns provenance from a decoration into something the operator sees."""
        by_source: dict = {}
        passive: dict = {}
        needs_val = []
        for n in self._nodes.values():
            srcs = [s.get("source") for s in (n.get("sources") or []) if s.get("source")]
            for s in srcs:
                by_source[s] = by_source.get(s, 0) + 1
                if s in self._PASSIVE_SOURCES:
                    passive[s] = passive.get(s, 0) + 1
            pk = (n.get("props") or {}).get("provenance_kind")
            if pk in ("archive", "repo") and not n.get("tested"):
                needs_val.append({"id": n["id"], "kind": n["kind"], "label": n["label"],
                                  "source": (srcs[0] if srcs else None), "provenance": pk})
        return {"by_source": dict(sorted(by_source.items(), key=lambda kv: -kv[1])),
                "passive_intel": passive,
                "needs_validation": needs_val,
                "needs_validation_count": len(needs_val)}

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

# Content signals that UPGRADE a finding's enables beyond its family alone: an `exposure` finding that
# actually leaks credentials/secrets unlocks credential_material (chase: try those creds), while a
# schema/info exposure of the same family does not. Keyed on the finding's OWN text so a whole family is
# never blunt-mapped into a capability it doesn't always unlock (avoids false attack-paths). Deterministic.
_CRED_SIGNALS = ("credential", "password", "passwd", "secret", "api key", "api-key", "apikey",
                 "token", "private key", "access key", "aws_secret", "authorization header")


def _content_enables(finding) -> list:
    """Capabilities a finding unlocks by its CONTENT (title/evidence), not just its family. Conservative:
    only a clear credential/secret leak upgrades. Pure keyword match."""
    blob = " ".join(str(finding.get(k, "")) for k in
                    ("title", "name", "summary", "evidence", "impact")).lower()
    return ["credential_material"] if any(s in blob for s in _CRED_SIGNALS) else []


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
        _enables = sorted(set(_FINDING_ENABLES.get(fam, [])) | set(_content_enables(f)))
        fid = g.observe("finding", key, label=f.get("title", "Finding"), source="scan",
                        confidence=CONFIRMED if f.get("confidence") == "confirmed" else MEDIUM,
                        scope_asset=scope_asset, enables=_enables,
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
