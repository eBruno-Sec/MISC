"""Staged intel-knowledge promotion (#114): candidate -> validating -> validated -> fixture_backed ->
reviewed -> production, ONE gated step at a time. Internet intel stays UNTRUSTED (candidate) until it
earns each promotion with EVIDENCE; auto-promotion into production is PROHIBITED (production requires a
human reviewer). Deterministic in-memory store. No contamination: a guess never silently becomes trusted.
"""
from __future__ import annotations

import time
from collections import Counter

import intel_sources as _src

_STORE: dict = {}          # rec_id -> record (carries validation_state, evidence, history)

_CONF = {"candidate": 0.3, "validating": 0.35, "validated": 0.55, "fixture_backed": 0.7,
         "reviewed": 0.85, "production": 0.95, "rejected": 0.0}


def reset():
    _STORE.clear()


def _rid(rec: dict) -> str:
    return "%s|%s|%s" % (rec.get("source"), rec.get("cve") or (rec.get("references") or [""])[0],
                         rec.get("source_type"))


def ingest(records: list) -> int:
    """Add ingested provenance records as CANDIDATES (dedup by id). Ingest is ALWAYS candidate — an
    ingested record can never enter above candidate, no matter what state it claims."""
    n = 0
    for r in records or []:
        rid = _rid(r)
        if rid in _STORE:
            continue
        rec = dict(r)
        rec["validation_state"] = "candidate"
        rec["confidence"] = _CONF["candidate"]
        rec["_id"] = rid
        rec["_history"] = [["candidate", time.time()]]
        _STORE[rid] = rec
        n += 1
    return n


def advance(rec_id: str, to_state: str, *, evidence=None, reviewed_by: str = None):
    """Advance one record exactly ONE gated step. Returns (ok, reason). Anti-contamination requirements:
      validated       -> needs deterministic validation `evidence`
      fixture_backed  -> needs a regression `evidence` (fixture)
      production      -> needs a human `reviewed_by` (internet intel never auto-promotes to production)."""
    rec = _STORE.get(rec_id)
    if not rec:
        return False, "unknown record"
    frm = rec["validation_state"]
    if not _src.can_promote(frm, to_state):
        return False, "illegal transition %s -> %s (one gated step only, no queue-jump)" % (frm, to_state)
    if to_state == "validated" and not evidence:
        return False, "validated requires deterministic validation evidence"
    if to_state == "fixture_backed" and not evidence:
        return False, "fixture_backed requires a regression fixture"
    if to_state == "production" and not reviewed_by:
        return False, "production requires a human reviewer (no auto-promotion of internet intel)"
    rec["validation_state"] = to_state
    rec["confidence"] = _CONF.get(to_state, rec.get("confidence", 0.3))
    rec["_history"].append([to_state, time.time()])
    if evidence:
        rec.setdefault("_evidence", []).append(str(evidence)[:200])
    if reviewed_by:
        rec["reviewed_by"] = reviewed_by
    return True, "ok"


def by_state(state: str) -> list:
    return [r for r in _STORE.values() if r["validation_state"] == state]


def production() -> list:
    """Only PRODUCTION-state records are trusted knowledge safe to drive engines."""
    return by_state("production")


def stats() -> dict:
    return {"total": len(_STORE),
            "by_state": dict(Counter(r["validation_state"] for r in _STORE.values()))}
