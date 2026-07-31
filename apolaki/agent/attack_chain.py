"""
Attack-chain memory -- a deterministic, append-only record of what was TRIED, what WORKED, and what
FAILED against each target, so the next engagement starts smarter instead of re-deriving from zero.

Inspired by RedAmon's EvoGraph (Neo4j attack-chain memory) but kept deterministic and dependency-light:
a per-target JSON ledger, no graph DB, no LLM. Every confirm / dismiss appends a ChainStep; the planner
reads the roll-up to sink what's already confirmed and demote what already failed, so repeat runs stop
wasting effort on dead ends. Append-only -- nothing is ever deleted (a failure staying on the record is
the whole point).
"""
from __future__ import annotations

import json
import os
import time
from urllib.parse import urlparse


def _dir(d=None):
    return d or os.environ.get("ATTACK_CHAIN_DIR", "/app/data/attack_chains")


# Collapse the two family vocabularies (technique vuln_class vs tool-emitted finding family) onto one
# canonical key so a `sql_injection` technique and a `sqli` finding recognise each other.
_ALIAS = {"sql_injection": "sqli", "nosql_injection": "sqli", "nosqli": "sqli",
          "stored_xss": "xss", "reflected_xss": "xss", "dom_xss": "xss", "csti": "template_injection",
          "ssti": "template_injection", "command_injection": "cmdi",
          "idor": "access_control", "bola": "access_control", "bfla": "access_control"}


def _canon(x):
    x = str(x or "").strip().lower()
    return _ALIAS.get(x, x)


def target_key(target):
    """Normalize a target URL/host to a stable per-host key."""
    s = str(target or "").strip().lower()
    if not s:
        return ""
    if "://" in s:
        try:
            s = urlparse(s).netloc or s
        except Exception:
            pass
    return s.split("/")[0]


def _path(target, d=None):
    key = target_key(target).replace(":", "_") or "unknown"
    return os.path.join(_dir(d), key + ".json")


def load(target, d=None):
    p = _path(target, d)
    if os.path.exists(p):
        try:
            return json.load(open(p, encoding="utf-8"))
        except Exception:
            pass
    return {"target": target_key(target), "steps": []}


def record(target, technique, outcome, evidence="", session="", name="", d=None):
    """Append a ChainStep. outcome in confirmed|failed|dismissed|no_progress|attempted. Never deletes."""
    key = target_key(target)
    if not key or not technique:
        return None
    technique = _canon(technique)
    ch = load(target, d)
    ch["steps"].append({"technique": technique, "name": name or technique, "outcome": outcome,
                        "evidence": str(evidence)[:300], "session": session, "at": time.time()})
    ch["steps"] = ch["steps"][-500:]
    os.makedirs(_dir(d), exist_ok=True)
    tmp = _path(target, d) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(ch, fh)
    os.replace(tmp, _path(target, d))
    return ch


_RANK = {"confirmed": 0, "failed": 1, "dismissed": 2, "no_progress": 3, "attempted": 4}


def summary(target, d=None):
    """Best-known outcome per technique for this target (confirmed beats failed beats attempted)."""
    out = {}
    for s in load(target, d).get("steps", []):
        t, o = s.get("technique"), s.get("outcome", "attempted")
        if t and (t not in out or _RANK.get(o, 9) < _RANK.get(out.get(t), 9)):
            out[t] = o
    return out


def annotate_plan(target, plan, d=None):
    """Fold prior outcomes into a fresh plan: flag already-confirmed (sink it), demote previously-failed
    (keep it, lower). This is how yesterday's engagement makes today's plan smarter, deterministically."""
    prior = summary(target, d)
    for a in plan:
        o = prior.get(_canon(a.get("family"))) or prior.get(_canon(a.get("id")))
        if o == "confirmed":
            a["prior"] = "already confirmed"
            a["score"] = a.get("score", 0) - 100
        elif o in ("failed", "dismissed"):
            a["prior"] = "previously " + o
            a["score"] = a.get("score", 0) - 20
    plan.sort(key=lambda x: x.get("score", 0), reverse=True)
    return plan
