"""
Continuous learning (Phase 3) -- execution evidence adjusts confidence deterministically, zero-token.

Every confirm/dismiss already lands in the per-target attack-chain memory. This rolls those outcomes up
ACROSS all targets into a per-vuln-class reliability signal (how often a class actually confirms when
tried), which reweights the planner: a class that reliably pays off is prioritized, one that never pans
out is demoted. Only ORACLE-confirmed outcomes raise reliability -- failed attempts never become
trusted intelligence. No LLM, no embeddings.
"""
from __future__ import annotations

import glob
import json
import os

_POS = {"confirmed"}
_NEG = {"failed", "dismissed", "no_progress"}


def _dir(d=None):
    return d or os.environ.get("ATTACK_CHAIN_DIR", "/app/data/attack_chains")


def reliability(d=None):
    """Per-class {attempts, confirmed, rate} rolled up from every attack-chain ledger. Deterministic."""
    tally = {}
    for p in glob.glob(os.path.join(_dir(d), "*.json")):
        try:
            ch = json.load(open(p, encoding="utf-8"))
        except Exception:
            continue
        for s in ch.get("steps", []):
            cls = str(s.get("technique", "")).lower()
            o = s.get("outcome", "")
            if not cls or o not in (_POS | _NEG):
                continue
            t = tally.setdefault(cls, {"attempts": 0, "confirmed": 0})
            t["attempts"] += 1
            if o in _POS:
                t["confirmed"] += 1
    for t in tally.values():
        t["rate"] = round(t["confirmed"] / t["attempts"], 2) if t["attempts"] else 0.0
    return tally


def class_weight(cls, rel=None, d=None):
    """A bounded ranking delta for a vuln class from its LEARNED reliability. Needs >=2 attempts before
    it moves anything (don't overfit to a single data point). +/- ~10 around a 50% baseline, scaled by
    evidence volume. Canonicalizes the class so technique vocab (sql_injection) matches chain vocab (sqli)."""
    import attack_chain
    rel = rel if rel is not None else reliability(d)
    t = rel.get(attack_chain._canon(cls))
    if not t or t["attempts"] < 2:
        return 0.0
    return round((t["rate"] - 0.5) * 20 * min(1.0, t["attempts"] / 5.0), 1)
