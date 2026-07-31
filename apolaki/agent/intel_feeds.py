"""
Offensive intelligence feeds (Phase 0) -- deterministic ingestion of authoritative, redistributable
sources that ENRICH the technique registry. No crawl, no LLM, no untrusted prose.

This is the funnel in FRONT of the knowledge repository (techniques.py), not a second store. Tier-A
sources only: authoritative, machine-readable, redistributable, near-zero data-poisoning risk.

  kev    CISA Known Exploited Vulnerabilities -> a real-world "exploited in the wild" flag, keyed by CWE
  capec  MITRE CAPEC (STIX)                   -> attack patterns (severity, likelihood) mapped to CWE
  attack MITRE ATT&CK Enterprise (STIX, big)  -> technique catalog to validate registry ATT&CK codes

CAPEC/ATT&CK are pulled from MITRE's OWN official cti distribution repo (the canonical machine-readable
channel), which is categorically different from arbitrary user repos/gists. Every registry technique
already carries a CWE, so all enrichment keys cleanly off CWE.

Flow: the optional `intel-feeds` sidecar runs `python -m intel_feeds serve <dir> <interval>` to refresh
JSON snapshots into a shared directory on a schedule; Apolaki reads them read-only and merges the
enrichment. With no snapshots present, every consumer degrades cleanly to "no feeds loaded" -- nothing
is faked, nothing auto-executes.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.request

_UA = {"User-Agent": "apolaki-intel-feeds/0 (+deterministic; no-crawl)"}

# Tier-A sources only. `large` marks feeds too big for the default scheduled refresh (opt-in).
SOURCES = {
    "kev":    {"tier": "A", "name": "CISA Known Exploited Vulnerabilities",
               "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"},
    "capec":  {"tier": "A", "name": "MITRE CAPEC",
               "url": "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"},
    "attack": {"tier": "A", "name": "MITRE ATT&CK (Enterprise)", "large": True,
               "url": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"},
}

_DEFAULT_DIR = "/app/data/intel_feeds"


def _dir(dest_dir=None):
    return dest_dir or os.environ.get("INTEL_FEEDS_DIR", _DEFAULT_DIR)


def _norm_cwe(c):
    """'cwe-89' / ' CWE-89 ' / 89 -> 'CWE-89'; anything without a numeric id -> ''."""
    s = str(c or "").strip().upper()
    if not s:
        return ""
    if s.isdigit():
        return "CWE-" + s
    if s.startswith("CWE-") and s[4:].isdigit():
        return s
    return ""


# ---------------------------------------------------------------------------- pure parsers
def parse_kev(raw):
    """CISA KEV JSON -> {cwes: {CWE: [cve,...]}, cves_meta: {cve: {...}}, catalog_version, count}."""
    d = json.loads(raw)
    by_cwe, cves_meta = {}, {}
    for v in d.get("vulnerabilities", []):
        cid = str(v.get("cveID") or "").strip()
        if not cid:
            continue
        cves_meta[cid] = {
            "product": (str(v.get("vendorProject", "")) + " " + str(v.get("product", ""))).strip(),
            "date_added": v.get("dateAdded", ""),
            "ransomware": str(v.get("knownRansomwareCampaignUse") or "").strip().lower() == "known",
        }
        for c in (v.get("cwes") or []):
            nc = _norm_cwe(c)
            if nc:
                by_cwe.setdefault(nc, []).append(cid)
    return {"source": "kev", "tier": "A", "catalog_version": d.get("catalogVersion", ""),
            "count": len(cves_meta),
            "cwes": {k: sorted(set(v)) for k, v in by_cwe.items()}, "cves_meta": cves_meta}


def parse_capec(raw):
    """CAPEC STIX -> {patterns: {CAPEC-id: {name, severity, likelihood, abstraction, cwes, attack,
    prerequisites, parents, children}}, cwes: {CWE: [CAPEC-id,...]}, count}. Rich enough that the
    deterministic extractor can mint a candidate Technique straight from a pattern -- no LLM."""
    d = json.loads(raw)
    objs = d.get("objects", [])
    # pass 1: STIX object id -> CAPEC id, so parent/child refs (which are STIX ids) resolve to CAPEC ids
    stix2capec = {}
    for o in objs:
        if o.get("type") == "attack-pattern":
            for r in o.get("external_references", []):
                if r.get("source_name") == "capec" and r.get("external_id"):
                    stix2capec[o.get("id")] = r["external_id"]
                    break
    patterns, by_cwe = {}, {}
    for o in objs:
        if o.get("type") != "attack-pattern" or o.get("x_capec_status") == "Deprecated":
            continue
        capec_id, cwes, attack = "", [], []
        for r in o.get("external_references", []):
            sn, ex = r.get("source_name"), r.get("external_id")
            if sn == "capec" and ex:
                capec_id = ex
            elif sn == "cwe" and ex:
                nc = _norm_cwe(ex)
                if nc:
                    cwes.append(nc)
            elif sn == "ATTACK" and ex:
                attack.append(ex)
        if not capec_id:
            continue
        cwes = sorted(set(cwes))
        parents = sorted({stix2capec[r] for r in (o.get("x_capec_child_of_refs") or []) if r in stix2capec})
        children = sorted({stix2capec[r] for r in (o.get("x_capec_parent_of_refs") or []) if r in stix2capec})
        patterns[capec_id] = {"name": o.get("name", ""),
                              "severity": o.get("x_capec_typical_severity", ""),
                              "likelihood": o.get("x_capec_likelihood_of_attack", ""),
                              "abstraction": o.get("x_capec_abstraction", ""), "cwes": cwes,
                              "attack": sorted(set(attack)),
                              "prerequisites": list(o.get("x_capec_prerequisites") or []),
                              "parents": parents, "children": children}
        for c in cwes:
            by_cwe.setdefault(c, []).append(capec_id)
    return {"source": "capec", "tier": "A", "count": len(patterns),
            "patterns": patterns, "cwes": {k: sorted(set(v)) for k, v in by_cwe.items()}}


def parse_attack(raw):
    """ATT&CK Enterprise STIX -> {techniques: {Txxxx: {name, tactics}}, count}. Skips revoked/deprecated."""
    d = json.loads(raw)
    techs = {}
    for o in d.get("objects", []):
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        tid = ""
        for r in o.get("external_references", []):
            if r.get("source_name") == "mitre-attack" and r.get("external_id"):
                tid = r["external_id"]
                break
        if not tid:
            continue
        tactics = [p.get("phase_name") for p in o.get("kill_chain_phases", [])
                   if p.get("kill_chain_name") == "mitre-attack"]
        techs[tid] = {"name": o.get("name", ""), "tactics": tactics}
    return {"source": "attack", "tier": "A", "count": len(techs), "techniques": techs}


_PARSERS = {"kev": parse_kev, "capec": parse_capec, "attack": parse_attack}


# ---------------------------------------------------------------------------- fetch / refresh / load
def fetch(name, timeout=60):
    """Return raw bytes for a source, or None on any failure (never raises)."""
    src = SOURCES.get(name)
    if not src:
        return None
    try:
        req = urllib.request.Request(src["url"], headers=_UA)
        return urllib.request.urlopen(req, timeout=timeout).read()
    except Exception:
        return None


def refresh(dest_dir=None, feeds=None, timeout=90):
    """Fetch + parse + write normalized snapshots + manifest. Per-feed graceful. Returns the manifest.
    Default feeds = kev + capec (ATT&CK is large -> opt-in via feeds=['attack'] or INTEL_FEEDS_ATTACK=1)."""
    dest_dir = _dir(dest_dir)
    os.makedirs(dest_dir, exist_ok=True)
    if feeds is None:
        feeds = ["kev", "capec"]
        if os.environ.get("INTEL_FEEDS_ATTACK") in ("1", "true", "yes"):
            feeds.append("attack")
    manifest = {"refreshed_at": time.time(), "feeds": {}}
    for name in feeds:
        raw = fetch(name, timeout=timeout)
        if raw is None:
            manifest["feeds"][name] = {"ok": False, "error": "unreachable", "tier": SOURCES.get(name, {}).get("tier")}
            continue
        try:
            parsed = _PARSERS[name](raw)
        except Exception as e:
            manifest["feeds"][name] = {"ok": False, "error": "parse: " + str(e)[:80]}
            continue
        with open(os.path.join(dest_dir, name + ".json"), "w", encoding="utf-8") as fh:
            json.dump(parsed, fh)
        manifest["feeds"][name] = {"ok": True, "count": parsed.get("count"),
                                   "tier": parsed.get("tier"), "version": parsed.get("catalog_version", "")}
    with open(os.path.join(dest_dir, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)
    return manifest


def load(dest_dir=None):
    """Load whatever snapshots exist (missing -> absent key). Never raises."""
    dest_dir = _dir(dest_dir)
    out = {}
    for name in ("kev", "capec", "attack", "manifest"):
        p = os.path.join(dest_dir, name + ".json")
        if os.path.exists(p):
            try:
                out[name] = json.load(open(p, encoding="utf-8"))
            except Exception:
                pass
    return out


# ---------------------------------------------------------------------------- enrichment (pure)
def known_exploited_cwes(snapshots):
    """Set of CWE ids CISA lists as known-exploited-in-the-wild."""
    return set((snapshots.get("kev") or {}).get("cwes") or {})


def enrich_techniques(techniques, snapshots):
    """Pure. techniques = iterable of dicts carrying id + cwe. Returns {id: enrichment}.
    enrichment = {cwe, known_exploited, kev_cves, kev_ransomware, capec:[{id,name,severity,likelihood}]}."""
    kev = snapshots.get("kev") or {}
    capec = snapshots.get("capec") or {}
    kev_cwes = kev.get("cwes") or {}
    kev_meta = kev.get("cves_meta") or {}
    capec_by_cwe = capec.get("cwes") or {}
    capec_pat = capec.get("patterns") or {}
    out = {}
    for t in techniques:
        tid = t.get("id")
        if not tid:
            continue
        cwe = _norm_cwe(t.get("cwe") or "")
        cves = kev_cwes.get(cwe, []) if cwe else []
        cap_ids = (capec_by_cwe.get(cwe, []) if cwe else [])[:6]
        out[tid] = {
            "cwe": cwe,
            "known_exploited": bool(cves),
            "kev_cves": cves[:8],
            "kev_ransomware": any((kev_meta.get(c) or {}).get("ransomware") for c in cves),
            "capec": [{"id": cid, "name": capec_pat.get(cid, {}).get("name", ""),
                       "severity": capec_pat.get(cid, {}).get("severity", ""),
                       "likelihood": capec_pat.get(cid, {}).get("likelihood", "")} for cid in cap_ids],
        }
    return out


def status(dest_dir=None):
    """Feed freshness + counts for the /intel/feeds endpoint. Safe when nothing is loaded."""
    snaps = load(dest_dir)
    man = snaps.get("manifest") or {}
    kev = snaps.get("kev") or {}
    capec = snaps.get("capec") or {}
    st = {
        "loaded": [k for k in ("kev", "capec", "attack") if k in snaps],
        "refreshed_at": man.get("refreshed_at"),
        "feeds": man.get("feeds", {}),
        "sources": {k: {"tier": v["tier"], "name": v["name"]} for k, v in SOURCES.items()},
        "kev_catalog_version": kev.get("catalog_version"),
        "kev_count": kev.get("count"),
        "kev_known_exploited_cwes": len(kev.get("cwes") or {}),
        "capec_patterns": capec.get("count"),
    }
    if man.get("refreshed_at"):
        st["age_seconds"] = max(0, int(time.time() - man["refreshed_at"]))
    return st


# ---------------------------------------------------------------------------- sidecar CLI
def _serve(dest_dir, interval):
    interval = max(300, int(interval))
    while True:
        try:
            refresh(dest_dir)
        except Exception:
            pass
        time.sleep(interval)


if __name__ == "__main__":
    args = sys.argv[1:]
    cmd = args[0] if args else "refresh"
    dest = args[1] if len(args) > 1 else _dir()
    if cmd == "serve":
        _serve(dest, int(args[2]) if len(args) > 2 else 21600)
    else:
        print(json.dumps(refresh(dest), indent=2))
