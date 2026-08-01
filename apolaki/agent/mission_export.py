"""
Portable mission export — a redacted, self-contained JSON bundle of everything a mission produced:
metadata, findings, surface counts, the canonical asset graph, and confirmed capabilities. It is the
unit of archival, hand-off, and the one-command diagnostic artifact. Secrets are scrubbed via
vault.redact (only vault:// references survive), so a bundle is always safe to share.

Pure builder + a strict validator. The endpoints (main.py) wire it to a live mission.
"""
from __future__ import annotations

import time

import vault

BUNDLE_VERSION = "1"
_MISSION_KEYS = ("id", "name", "mode", "status", "created_at", "scope")


def build_bundle(*, mission: dict = None, findings: list = None, snapshot: dict = None,
                 graph: dict = None, capabilities: list = None, extra: dict = None) -> dict:
    """Assemble a portable, redacted mission bundle. Deterministic (apart from exported_at)."""
    graph = graph or {}
    bundle = {
        "apolaki_bundle_version": BUNDLE_VERSION,
        "exported_at": int(time.time()),
        "mission": {k: (mission or {}).get(k) for k in _MISSION_KEYS},
        "findings": findings or [],
        "surface": (snapshot or {}).get("counts") or {},
        "graph": {"stats": graph.get("stats") or {},
                  "nodes": graph.get("nodes") or [],
                  "edges": graph.get("edges") or []},
        "capabilities": list(capabilities or []),
    }
    if extra:
        bundle["extra"] = extra
    # defense in depth: scrub any secret-bearing keys anywhere in the bundle; vault refs pass through.
    return vault.redact(bundle)


def validate(bundle: dict) -> tuple:
    """(ok, reason). A bundle must carry the version marker and the core sections."""
    if not isinstance(bundle, dict):
        return False, "not an object"
    if bundle.get("apolaki_bundle_version") != BUNDLE_VERSION:
        return False, "unknown or missing apolaki_bundle_version"
    for k in ("mission", "findings", "graph"):
        if k not in bundle:
            return False, f"missing section: {k}"
    return True, "ok"


def summary(bundle: dict) -> dict:
    """A compact overview of an imported bundle (for the UI / a re-hydration preview)."""
    ok, reason = validate(bundle)
    g = bundle.get("graph") or {}
    return {"valid": ok, "reason": reason,
            "mission": (bundle.get("mission") or {}).get("name"),
            "findings": len(bundle.get("findings") or []),
            "graph_nodes": len((g.get("nodes") or [])),
            "capabilities": list(bundle.get("capabilities") or []),
            "exported_at": bundle.get("exported_at")}
