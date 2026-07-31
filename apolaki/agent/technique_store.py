"""
Technique knowledge store -- persistence + lifecycle for the first-class Technique.

The hand-authored, oracle-proven techniques in techniques.py are the canonical SEED. This store holds
everything the ingestion pipeline learns on top: deterministically-extracted CAPEC techniques,
LLM-extracted candidates, and the human decisions applied to them. Consumers read a UNIFIED view
(seed + store); this module owns the mutable half.

Invariants (the reason this is disciplined rather than a bag of dicts):
  - Nothing is deleted. A wrong technique becomes `deprecated`/`rejected`; a replaced one becomes
    `superseded` with a pointer to its successor. History is append-only.
  - Every change bumps `version` and appends a `version_history` entry (what, when, who, why).
  - Confidence is recomputed deterministically on every transition -- never hand-set.
  - Dedup keys are DETERMINISTIC (CAPEC id / CWE+name), never embedding similarity. Semantics only
    SUGGEST a merge for a human; keys decide identity.

Pure functions operate on a `store` dict so they are trivially testable; load()/save() are the only I/O.
"""
from __future__ import annotations

import json
import os
import time


def _dir(d=None):
    return d or os.environ.get("TECHNIQUE_STORE_DIR", "/app/data/techniques")


def _path(d=None):
    return os.path.join(_dir(d), "technique_candidates.json")


def load(d=None):
    p = _path(d)
    if os.path.exists(p):
        try:
            return json.load(open(p, encoding="utf-8"))
        except Exception:
            pass
    return {"techniques": {}, "updated_at": None}


def save(store, d=None):
    os.makedirs(_dir(d), exist_ok=True)
    store["updated_at"] = time.time()
    tmp = _path(d) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(store, fh)
    os.replace(tmp, _path(d))   # atomic swap so a crashed write never corrupts the store
    return store


# ---------------------------------------------------------------------------- identity + versioning (pure)
def dedup_key(t):
    """Deterministic identity key. CAPEC id is authoritative; else CWE-set + normalized name.
    Embedding similarity is NEVER used for identity -- only to suggest a human-reviewed merge."""
    caps = t.get("capec") or []
    if caps:
        return "capec:" + sorted(caps)[0]
    cwes = "+".join(sorted(t.get("cwe") or []))
    return "cwe:%s|name:%s" % (cwes, str(t.get("name") or t.get("id") or "").strip().lower())


def _history(t, action, by, note="", version=None):
    t.setdefault("version_history", []).append(
        {"version": version if version is not None else t.get("version", 1),
         "at": time.time(), "action": action, "by": by, "note": note})


def _content_sig(t):
    keep = {k: t.get(k) for k in ("summary", "cwe", "capec", "attack", "preconditions", "payloads",
                                  "detection_logic", "mitigations", "parents", "children", "vuln_class")}
    # provenance sources are content: a NEW corroborating source (e.g. CISA KEV cross-ref) is a real,
    # version-worthy change even when the method fields are identical.
    keep["_prov"] = sorted({p.get("source") for p in (t.get("provenance") or [])
                            if isinstance(p, dict) and p.get("source")})
    return json.dumps(keep, sort_keys=True, default=str)


_MERGE_LISTS = ("cwe", "capec", "attack", "preconditions", "discovery_methods", "payloads",
                "detection_logic", "mitigations", "parents", "children", "tags", "provenance", "evidence")


def _merge_fields(cur, new):
    """Union list fields, fill empty scalars from the newcomer. Deterministic, order-preserving."""
    out = dict(cur)
    for f in _MERGE_LISTS:
        merged = list(cur.get(f) or [])
        for x in (new.get(f) or []):
            if x not in merged:
                merged.append(x)
        out[f] = merged
    for f in ("summary", "vuln_class", "name"):
        if not out.get(f) and new.get(f):
            out[f] = new[f]
    return out


def upsert(store, tech, by="system"):
    """Add a technique, or version it if its content changed. Returns 'created'|'updated'|'unchanged'."""
    import technique_model
    techs = store.setdefault("techniques", {})
    tid = tech["id"]
    if tid not in techs:
        tech = dict(tech)
        tech["version"] = 1
        tech.setdefault("version_history", [])
        _history(tech, "created", by, "ingested from " + _prov_src(tech))
        tech["confidence"] = technique_model.confidence_score(tech)
        techs[tid] = tech
        return "created"
    cur = techs[tid]
    if _content_sig(cur) == _content_sig(tech):
        return "unchanged"
    merged = _merge_fields(cur, tech)
    merged["version"] = cur.get("version", 1) + 1
    merged["version_history"] = list(cur.get("version_history", []))
    _history(merged, "updated", by, "re-ingested with changes", merged["version"])
    merged["confidence"] = technique_model.confidence_score(merged)
    techs[tid] = merged
    return "updated"


def _prov_src(t):
    return (t.get("provenance") or [{}])[0].get("source", "?")


def transition(store, tid, status, by, note=""):
    """Move a technique through its lifecycle. Bumps version, appends history, re-scores confidence."""
    import technique_model
    t = (store.get("techniques") or {}).get(tid)
    if not t:
        return None
    if status not in technique_model.STATUSES:
        raise ValueError("bad status %r" % status)
    t["status"] = status
    t["version"] = t.get("version", 1) + 1
    _history(t, status, by, note, t["version"])
    t["confidence"] = technique_model.confidence_score(t)
    return t


def merge(store, keep_id, drop_id, by):
    """Fold drop_id into keep_id (union of knowledge), then mark drop_id superseded -> keep_id. Never deletes."""
    import technique_model
    techs = store.get("techniques") or {}
    keep, drop = techs.get(keep_id), techs.get(drop_id)
    if not keep or not drop:
        return None
    merged = _merge_fields(keep, drop)
    merged["version"] = keep.get("version", 1) + 1
    merged["version_history"] = list(keep.get("version_history", []))
    _history(merged, "merged", by, "merged %s into %s" % (drop_id, keep_id), merged["version"])
    merged["confidence"] = technique_model.confidence_score(merged)
    techs[keep_id] = merged
    drop["status"] = "superseded"
    drop["superseded_by"] = keep_id
    _history(drop, "superseded", by, "merged into " + keep_id)
    return merged


# ---------------------------------------------------------------------------- read views (pure)
def get(store, tid):
    return (store.get("techniques") or {}).get(tid)


def listing(store, status=None, limit=None):
    ts = list((store.get("techniques") or {}).values())
    if status:
        ts = [t for t in ts if t.get("status") == status]
    ts.sort(key=lambda t: (t.get("confidence") or {}).get("score", 0), reverse=True)
    return ts[:limit] if limit else ts


def stats(store):
    by = {}
    for t in (store.get("techniques") or {}).values():
        s = t.get("status", "?")
        by[s] = by.get(s, 0) + 1
    return {"total": len(store.get("techniques") or {}), "by_status": by,
            "updated_at": store.get("updated_at")}
