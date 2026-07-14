"""
TBHM (The Bug Hunter's Methodology) integration.

Loads the distilled TBHM catalogs shipped under backend/data/tbhm/ and exposes
them to the rest of Yggdrasil:

  - param_catalog(mode)        -> extra parameter names for mining (default/deep)
  - checklist()                -> the Fast Testing Checklist, by category
  - checklist_coverage_summary()-> covered/partial/manual counts for the report
  - payload_profiles()         -> per-family payload policy (safe vs. gated)
  - references()               -> source attribution (Jason Haddix TBHM + WAHH)
  - parse_marker_wordlist(text)-> normalize a HOSTMARKER/PORTMAKER marker corpus
                                  into deduped parameter names

Design boundary (see data/tbhm/references.yaml): this is a DISTILLED
integration. Catalogs are bounded and attributed; the raw multi-hundred-MB
marker corpus is parsed OFFLINE into a small subset, never loaded at runtime.

Pure/deterministic apart from a one-time, cached read of the bundled YAML data
files — no network, no DB — so it is directly unit-testable.
"""
import os
import re
from pathlib import Path

import yaml

from core.parameter_intelligence import normalize_param_name, classify_param

_DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "tbhm"
_CACHE: dict = {}


def _load(name: str) -> dict:
    """Read and cache one bundled YAML catalog. A missing/broken file degrades to
    an empty dict (the TBHM layer is additive — its absence must never break a
    scan), so callers always get a dict."""
    if name in _CACHE:
        return _CACHE[name]
    path = _DATA_DIR / f"{name}.yaml"
    data: dict = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f)
        if isinstance(loaded, dict):
            data = loaded
    except Exception:
        data = {}
    _CACHE[name] = data
    return data


def deep_mode_enabled() -> bool:
    """Deep TBHM coverage (larger param catalog, heavier fuzzing) is opt-in via
    YGGDRASIL_TBHM_DEEP=1 so default scans stay fast. Kept as a tiny helper so
    the gate is defined in exactly one place."""
    return (os.getenv("YGGDRASIL_TBHM_DEEP", "").strip().lower() in ("1", "true", "yes"))


def param_catalog(mode: str = None) -> list:
    """Extra parameter names for active mining, on top of the engine's built-in
    candidates. `mode`:
      - "default" (or None with deep mode off): curated high-signal names only.
      - "deep" (or None with deep mode on): curated + the bounded deep catalog.
    Deduped, first-seen order, curated names first."""
    data = _load("params")
    curated = [str(x) for x in (data.get("curated_default") or [])]
    if mode is None:
        mode = "deep" if deep_mode_enabled() else "default"
    names = list(curated)
    if mode == "deep":
        names += [str(x) for x in (data.get("deep") or [])]
    seen, out = set(), []
    for n in names:
        n = normalize_param_name(n)
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out


def checklist() -> list:
    """Fast Testing Checklist as a list of {id, title, items:[...]} categories.
    Each item: {id, text, coverage, agent, mode, note?}."""
    data = _load("checklist")
    cats = data.get("categories")
    return cats if isinstance(cats, list) else []


def checklist_items() -> list:
    """Flat list of every checklist item (category folded in as `category`)."""
    out = []
    for cat in checklist():
        for item in (cat.get("items") or []):
            row = dict(item)
            row["category"] = cat.get("title") or cat.get("id")
            out.append(row)
    return out


def checklist_coverage_summary() -> dict:
    """Counts by coverage tier across the whole checklist, for the report header:
    {"automated": n, "partial": n, "manual": n, "total": n}."""
    summary = {"automated": 0, "partial": 0, "manual": 0, "total": 0}
    for item in checklist_items():
        cov = str(item.get("coverage") or "manual").lower()
        if cov not in ("automated", "partial", "manual"):
            cov = "manual"
        summary[cov] += 1
        summary["total"] += 1
    return summary


def payload_profiles() -> dict:
    """Per-family payload policy: {family: {default, requires_authorization,
    guardrail, strategy, ...}}."""
    data = _load("payload_profiles")
    fams = data.get("families")
    return fams if isinstance(fams, dict) else {}


def references() -> list:
    """Source attribution entries (Jason Haddix TBHM, WAHH, etc.)."""
    data = _load("references")
    srcs = data.get("sources")
    return srcs if isinstance(srcs, list) else []


def attribution_line() -> str:
    """One-line credit string for the report footer / logs."""
    names = []
    for s in references():
        author = s.get("author")
        name = s.get("name")
        if author and name:
            names.append(f"{name} ({author})")
        elif name:
            names.append(name)
    return "Methodology sources: " + "; ".join(names) if names else "Methodology sources: TBHM"


# ---------------------------------------------------------------------------
# Marker-corpus normalizer (v4/all2.txt). The source corpus templates every
# parameter as `&name=//HOSTMARKER:PORTMAKER/...` (and includes pure path-
# traversal lines with no parameters at all). This extracts just the bare,
# normalized, de-duplicated parameter names — the offline step that produced
# params.yaml's `deep` list, kept in-code so it's unit-tested against the real
# marker format and an operator can regenerate/extend the catalog from source.
# ---------------------------------------------------------------------------
_MARKER_TOKEN = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_.\-]{0,39})=")


def parse_marker_wordlist(text: str, *, classified_only: bool = False) -> list:
    """Extract parameter names from a HOSTMARKER/PORTMAKER-templated corpus.

    Returns deduped, lowercased names in first-seen order. Marker tokens
    (HOSTMARKER, PORTMAKER/PORTMARKER) and pure traversal lines yield nothing —
    only real `?name=`/`&name=` parameter names survive. With classified_only,
    keeps just the names that map to a known vulnerability family (via
    core.parameter_intelligence.classify_param)."""
    seen, out = set(), []
    for raw in _MARKER_TOKEN.findall(text or ""):
        n = normalize_param_name(raw)
        if not n or n in seen:
            continue
        # Drop the marker placeholders themselves if they ever slip through.
        if n in ("hostmarker", "portmaker", "portmarker"):
            continue
        if classified_only and not classify_param(n):
            continue
        seen.add(n)
        out.append(n)
    return out
