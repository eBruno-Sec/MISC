"""
The first-class Technique -- Apolaki's canonical offensive-knowledge entity.

Everything the platform learns normalizes into a Technique. Scanners, recon, exploit planning,
reporting, and autonomous reasoning query TECHNIQUES, not articles or raw CVEs. A CVE, a CAPEC
pattern, a disclosed report, a blog -- each is only a SOURCE that contributes fields (and provenance)
to a technique; the technique is what persists.

One schema, many sources:
  - hand-authored, oracle-proven techniques (techniques.py = the proven seed)
  - deterministically extracted candidates (CAPEC/KEV -> from_capec, no LLM)
  - LLM-extracted candidates from trusted prose (Phase 1 extractor, sandboxed, pending review)

Each Technique carries lifecycle status, source provenance, an auditable confidence score, version
history, and parent/child relationships. Confidence is DETERMINISTIC and explainable (a list of
scored factors) -- never an opaque model output. Nothing is ever silently overwritten: an improved
technique is versioned, a conflicting one is flagged, a wrong one is deprecated but kept (legacy
systems still exist).

This module is pure and dependency-light: it defines the schema, adapts other sources into it, and
scores confidence. Persistence + lifecycle transitions live in technique_store.py; ingestion lives in
the extractors. Consumers depend on THIS shape.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------- schema
# The canonical field set. Every Technique is a plain JSON-serializable dict with exactly these keys
# (keeps the codebase's dict-first style, trivial to serialize over the API, easy to diff/version).
FIELDS = (
    "id", "name", "summary", "vuln_class",
    # taxonomy lenses (lists -- a technique can map to several)
    "cwe", "owasp", "wstg", "capec", "attack",
    # applicability
    "applicable_products", "product_versions",
    # the offensive method
    "preconditions", "discovery_methods", "payloads", "detection_logic", "mitigations",
    # trust + lineage
    "evidence", "provenance", "confidence", "status", "version", "version_history",
    "success_metrics", "parents", "children",
    # operational
    "transferable", "permission", "try_it", "tags",
)

# Lifecycle. Knowledge is never deleted, only reclassified -- historical techniques stay valuable
# because legacy systems keep existing.
STATUSES = (
    "proven",          # oracle-confirmed on a lab (highest trust)
    "catalogued",      # known/documented, not yet demonstrated here
    "pending_review",  # ingested candidate awaiting human promotion
    "experimental",    # promoted but unproven, in trial
    "superseded",      # replaced by a higher-confidence version (kept)
    "deprecated",      # no longer effective, retained for legacy targets
    "historical",      # old technique, kept for old systems
    "conflicting",     # sources disagree -- needs human resolution
    "rejected",        # reviewed and discarded (kept for audit, never surfaced to scanners)
)

_LIST_FIELDS = ("cwe", "owasp", "wstg", "capec", "attack", "applicable_products", "product_versions",
                "preconditions", "discovery_methods", "payloads", "detection_logic", "mitigations",
                "evidence", "provenance", "version_history", "parents", "children", "tags")


def blank(id, name=""):
    """A fully-formed canonical Technique with every field defaulted. Callers fill what they know."""
    t = {f: [] for f in _LIST_FIELDS}
    t.update({"id": id, "name": name or _humanize(id), "summary": "", "vuln_class": "",
              "confidence": {"score": 0, "tier": "low", "factors": []}, "status": "catalogued",
              "version": 1, "success_metrics": {}, "transferable": True, "permission": "auto",
              "try_it": None})
    return t


def _humanize(tid):
    return str(tid or "").replace("_", " ").replace("-", " ").strip().title()


def _as_list(v):
    if v is None or v == "":
        return []
    return list(v) if isinstance(v, (list, tuple, set)) else [v]


# ---------------------------------------------------------------------------- confidence (deterministic)
# Reliability scoring is a transparent sum of named factors -- reproducible, auditable, and tunable in
# one place. Higher confidence wins during dedup/merge; newer never auto-beats higher-confidence.
_STATUS_BASE = {"proven": 55, "experimental": 30, "catalogued": 22, "pending_review": 12,
                "superseded": 20, "deprecated": 10, "historical": 15, "conflicting": 10, "rejected": 0}


def confidence_score(t):
    """Return {'score': 0..100, 'tier': high|medium|low, 'factors': [{name, points}]} for a technique.
    Deterministic and explainable: every point is attributed to a named factor."""
    factors = []

    def add(name, pts):
        if pts:
            factors.append({"name": name, "points": pts})

    add("status:" + str(t.get("status", "catalogued")), _STATUS_BASE.get(t.get("status"), 10))
    labs = {e.get("lab") for e in (t.get("evidence") or []) if isinstance(e, dict) and e.get("lab")}
    add("oracle-validated x%d" % len(labs), min(24, 12 * len(labs)))
    if len(labs) >= 2:
        add("cross-lab generalized", 8)
    if any(p.get("known_exploited") for p in (t.get("provenance") or []) if isinstance(p, dict)):
        add("CISA KEV known-exploited", 15)
    sources = {p.get("source") for p in (t.get("provenance") or []) if isinstance(p, dict) and p.get("source")}
    add("multi-source corroboration", min(15, 5 * max(0, len(sources) - 1)))
    add("has payload", 3 if t.get("payloads") else 0)
    add("has detection logic", 3 if t.get("detection_logic") else 0)
    m = t.get("success_metrics") or {}
    succ, att = m.get("successes", 0), m.get("attempts", 0)
    if att:
        rate = succ / att
        add("execution success %d%%" % int(rate * 100), int(round((rate - 0.5) * 20)))  # +/-10 around 50%
    score = max(0, min(100, sum(f["points"] for f in factors)))
    tier = "high" if score >= 70 else ("medium" if score >= 40 else "low")
    return {"score": score, "tier": tier, "factors": factors}


# ---------------------------------------------------------------------------- adapters (source -> canonical)
def from_registry(rec, try_it=None, known_exploited=False, kev_cves=None, capec=None):
    """Adapt a techniques.py record + optional intel-feeds enrichment into a canonical Technique.
    The proven registry is the authoritative seed; this projects it into the first-class shape."""
    t = blank(rec.get("id", ""), _humanize(rec.get("id", "")))
    validated = rec.get("validated_on") or []
    t.update({
        "summary": rec.get("summary", ""),
        "vuln_class": rec.get("vuln_class", ""),
        "cwe": _as_list(rec.get("cwe")),
        "owasp": _as_list(rec.get("owasp")),
        "wstg": _as_list(rec.get("wstg")),
        "attack": _as_list(rec.get("mitre")),
        "capec": [c.get("id") if isinstance(c, dict) else c for c in (capec or [])],
        "discovery_methods": _as_list(rec.get("detect")),
        "detection_logic": _as_list(rec.get("oracle")),
        "payloads": ([{"name": "reference", "payload": try_it}] if try_it else []),
        "preconditions": _as_list(rec.get("preconditions")),
        "status": "proven" if validated else "catalogued",
        "transferable": bool(rec.get("transferable", True)),
        "permission": rec.get("permission", rec.get("execution", "auto")),
        "try_it": try_it,
    })
    # evidence: which labs/challenges proved it
    maps = rec.get("maps_to") or {}
    for lab in validated:
        t["evidence"].append({"lab": lab, "challenges": maps.get(lab, [])})
    # provenance: internal, authoritative, carrying the real-world KEV signal for confidence
    prov = {"source": "apolaki-registry", "tier": "internal", "ref": rec.get("id", "")}
    if known_exploited:
        prov["known_exploited"] = True
        prov["kev_cves"] = list(kev_cves or [])[:8]
    t["provenance"].append(prov)
    if capec:
        t["provenance"].append({"source": "mitre-capec", "tier": "A",
                                "ref": ",".join(c.get("id") if isinstance(c, dict) else c for c in capec[:6])})
    t["confidence"] = confidence_score(t)
    return t


def from_capec(capec_id, pattern, fetched_at=None):
    """Deterministically extract a CANDIDATE Technique from one MITRE CAPEC attack pattern.
    No LLM: CAPEC already IS a structured catalog of attack techniques. Lands as pending_review."""
    t = blank("capec_" + str(capec_id).replace("CAPEC-", ""), pattern.get("name", ""))
    t.update({
        "summary": pattern.get("name", ""),
        "cwe": list(pattern.get("cwes") or []),
        "capec": [capec_id],
        "preconditions": list(pattern.get("prerequisites") or []),
        "mitigations": list(pattern.get("mitigations") or []),
        "attack": list(pattern.get("attack") or []),
        "parents": ["capec_" + str(p).replace("CAPEC-", "") for p in (pattern.get("parents") or [])],
        "children": ["capec_" + str(c).replace("CAPEC-", "") for c in (pattern.get("children") or [])],
        # Tier-A deterministic extraction from an authoritative catalog -> trusted-but-unproven, no human
        # gate needed. (LLM-extracted prose lands as pending_review instead.)
        "status": "catalogued",
        "tags": [x for x in ("abstraction:" + pattern.get("abstraction", ""),
                             "severity:" + pattern.get("severity", ""),
                             "likelihood:" + pattern.get("likelihood", "")) if not x.endswith(":")],
        "provenance": [{"source": "mitre-capec", "tier": "A", "ref": capec_id, "fetched_at": fetched_at}],
    })
    t["confidence"] = confidence_score(t)
    return t


def validate(t):
    """Return a list of schema violations (empty = valid). Cheap deterministic gate before storing."""
    errs = []
    if not t.get("id"):
        errs.append("missing id")
    if t.get("status") not in STATUSES:
        errs.append("bad status: %r" % t.get("status"))
    for f in _LIST_FIELDS:
        if f in t and not isinstance(t[f], list):
            errs.append("field %s must be a list" % f)
    return errs
