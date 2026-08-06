"""Trusted intel-source ALLOWLIST + governance layer (#114 internal architecture).

The single source of truth for "what outside feeds may Apolaki ever talk to, under what config, with what
provenance." This is the internal scaffolding the operator asked for: an EXPLICIT, per-source configurable
allowlist with license/rate-limit/cache metadata, the strict provenance schema every ingested record must
carry, the ingestion-lifecycle gate that keeps internet intel UNTRUSTED until validated, and the
outward-request log contract. Pure + deterministic: this module performs NO network I/O. Connectors stay
DISABLED by default and only turn on when their individual allowlist entry is explicitly enabled (and, for
key-gated sources, a credential is present). The actual fetchers for the already-live Tier-1 feeds live in
intel_feeds.py; sources marked live=False are registered but have no fetcher yet (connector off).

Hard boundaries encoded here (see PROHIBITED): official API/feed only, no scraping when a feed exists, no
active probing of OSINT-discovered assets, no leaked-credential databases, no auto-promotion of internet
intel into executable production skills, no sending proprietary code/secrets outward.
"""
from __future__ import annotations

import os
import time

# ── the allowlist ──
# tier 1 = structured defensive intel, default-ON *intent* (still gated by the master switch below so
# nothing fetches until configured). tier 2 = enrichment, API-key-gated, default-OFF, authorized targets
# only. source_type drives which parser/normalizer applies. `live` = a fetcher exists today (intel_feeds).
SOURCES = {
    # ── Tier 1 (structured defensive intelligence) ──
    "cve_v5":       {"tier": 1, "type": "vuln_record", "license": "CC0-1.0", "requires_key": False,
                     "live": False, "rate_per_min": 30, "cache_ttl_s": 86400, "parser_version": "0",
                     "endpoint": "https://cveawg.mitre.org/api/cve/", "purpose": "CVE records + affected products/refs"},
    "nvd":          {"tier": 1, "type": "vuln_enrichment", "license": "public-domain", "requires_key": False,
                     "live": False, "rate_per_min": 30, "cache_ttl_s": 86400, "parser_version": "0",
                     "endpoint": "https://services.nvd.nist.gov/rest/json/cves/2.0", "purpose": "CVSS/CPE/CWE enrichment"},
    "cisa_kev":     {"tier": 1, "type": "known_exploited", "license": "public-domain", "requires_key": False,
                     "live": True, "rate_per_min": 6, "cache_ttl_s": 86400, "parser_version": "1",
                     "endpoint": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                     "purpose": "confirmed exploited-in-the-wild + due dates", "feed": "kev"},
    "epss":         {"tier": 1, "type": "exploit_probability", "license": "free-attribution", "requires_key": False,
                     "live": False, "rate_per_min": 30, "cache_ttl_s": 86400, "parser_version": "0",
                     "endpoint": "https://api.first.org/data/v1/epss", "purpose": "exploitation-probability score"},
    "cert_cc":      {"tier": 1, "type": "vuln_note", "license": "free-attribution", "requires_key": False,
                     "live": False, "rate_per_min": 15, "cache_ttl_s": 86400, "parser_version": "0",
                     "endpoint": "https://www.kb.cert.org/vuls/api/", "purpose": "technical notes + affected vendors"},
    "ghsa":         {"tier": 1, "type": "package_advisory", "license": "CC-BY-4.0", "requires_key": False,
                     "live": False, "rate_per_min": 30, "cache_ttl_s": 86400, "parser_version": "0",
                     "endpoint": "https://api.github.com/advisories", "purpose": "package advisories + vulnerable/patched versions"},
    "vendor_adv":   {"tier": 1, "type": "vendor_advisory", "license": "per-vendor", "requires_key": False,
                     "live": False, "rate_per_min": 10, "cache_ttl_s": 86400, "parser_version": "0",
                     "endpoint": "", "purpose": "product-specific impact/fix/version (per-vendor feed)"},
    "nuclei_templates": {"tier": 1, "type": "detection_template", "license": "MIT", "requires_key": False,
                     "live": False, "rate_per_min": 6, "cache_ttl_s": 86400, "parser_version": "0",
                     "endpoint": "https://github.com/projectdiscovery/nuclei-templates",
                     "purpose": "candidate matchers/extractors/workflows (VALIDATE before trust)"},
    "owasp":        {"tier": 1, "type": "methodology", "license": "CC-BY-SA", "requires_key": False,
                     "live": False, "rate_per_min": 6, "cache_ttl_s": 604800, "parser_version": "0",
                     "endpoint": "https://owasp.org/", "purpose": "WSTG/ASVS methodology + remediation mappings"},
    "mitre_cwe":    {"tier": 1, "type": "weakness_catalog", "license": "free-attribution", "requires_key": False,
                     "live": False, "rate_per_min": 6, "cache_ttl_s": 604800, "parser_version": "0",
                     "endpoint": "https://cwe.mitre.org/data/", "purpose": "weakness taxonomy mappings"},
    "mitre_capec":  {"tier": 1, "type": "attack_pattern", "license": "free-attribution", "requires_key": False,
                     "live": True, "rate_per_min": 6, "cache_ttl_s": 604800, "parser_version": "1",
                     "endpoint": "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json",
                     "purpose": "attack-pattern mappings", "feed": "capec"},
    "mitre_attack": {"tier": 1, "type": "ttp_catalog", "license": "free-attribution", "requires_key": False,
                     "live": True, "rate_per_min": 6, "cache_ttl_s": 604800, "parser_version": "1",
                     "endpoint": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
                     "purpose": "ATT&CK TTP mappings", "feed": "attack"},

    # ── Tier 2 (enrichment — API-key-gated, DEFAULT-OFF, authorized targets only, passive) ──
    "censys":       {"tier": 2, "type": "asset_observation", "license": "commercial", "requires_key": True,
                     "live": False, "rate_per_min": 10, "cache_ttl_s": 3600, "parser_version": "0",
                     "endpoint": "https://search.censys.io/api", "purpose": "passive service/cert observations (authorized assets)"},
    "shodan":       {"tier": 2, "type": "asset_observation", "license": "commercial", "requires_key": True,
                     "live": False, "rate_per_min": 10, "cache_ttl_s": 3600, "parser_version": "0",
                     "endpoint": "https://api.shodan.io", "purpose": "passive banners/services (authorized assets)"},
    "virustotal":   {"tier": 2, "type": "reputation", "license": "commercial", "requires_key": True,
                     "live": False, "rate_per_min": 4, "cache_ttl_s": 3600, "parser_version": "0",
                     "endpoint": "https://www.virustotal.com/api/v3", "purpose": "passive DNS / URL relationships (licensed)"},
    "ct_logs":      {"tier": 2, "type": "certificate_transparency", "license": "public", "requires_key": True,
                     "live": False, "rate_per_min": 6, "cache_ttl_s": 3600, "parser_version": "0",
                     "endpoint": "https://crt.sh", "purpose": "candidate subdomains for an AUTHORIZED root (not proof of ownership)"},
    "urlhaus":      {"tier": 2, "type": "abuse_feed", "license": "CC0-1.0", "requires_key": True,
                     "live": False, "rate_per_min": 6, "cache_ttl_s": 3600, "parser_version": "0",
                     "endpoint": "https://urlhaus-api.abuse.ch/v1", "purpose": "abuse.ch URL/malware relationships"},
    "github_api":   {"tier": 2, "type": "repo_scanning", "license": "commercial", "requires_key": True,
                     "live": False, "rate_per_min": 30, "cache_ttl_s": 3600, "parser_version": "0",
                     "endpoint": "https://api.github.com", "purpose": "code/dependency/secret findings for OWNED/authorized repos"},
}

# env var holding the credential for a key-gated source (never the value here — presence gates enablement).
_KEY_ENV = {"censys": "CENSYS_API_KEY", "shodan": "SHODAN_API_KEY", "virustotal": "VIRUSTOTAL_API_KEY",
            "ct_logs": "CT_LOGS_ENABLED", "urlhaus": "URLHAUS_API_KEY", "github_api": "GITHUB_TOKEN"}

# ingestion lifecycle — internet intel stays UNTRUSTED (candidate) until it earns promotion. This is the
# staged-promotion gate: a guess never silently becomes production knowledge.
VALIDATION_STATES = ("candidate", "validating", "validated", "fixture_backed", "reviewed", "production", "rejected")
_ORDER = {s: i for i, s in enumerate(VALIDATION_STATES)}

# the strict provenance schema every ingested record MUST carry (order = documentation).
PROVENANCE_FIELDS = ("source", "source_type", "retrieved_at", "published_at", "last_modified", "license",
                     "affected_product", "affected_versions", "fixed_versions", "cve", "cwe", "capec",
                     "attack", "references", "confidence", "validation_state")

# the outward-request audit contract — every external call must log exactly these.
REQUEST_LOG_FIELDS = ("source", "endpoint", "purpose", "target_scope", "timestamp", "status",
                      "rate_limit_state", "cache_status", "parser_version")

# explicitly prohibited without separate approval (documented so the boundary is in code, not just prose).
PROHIBITED = (
    "crawl random blogs/forums/exploit-dumps/social-media",
    "scrape a site when an official API/feed exists",
    "query leaked-credential databases",
    "download or execute untrusted exploit code automatically",
    "active-probe assets merely discovered via OSINT",
    "treat Shodan/Censys/CT/VirusTotal relationships as proof of ownership",
    "auto-promote internet intel into executable production skills",
    "send proprietary source/secrets/customer-data to external services",
    "ingest any source whose license/terms forbid automated ingestion",
)


def get(name: str) -> dict | None:
    return SOURCES.get(name)


def allowlist(tier: int = None) -> list:
    return [{"name": n, **m} for n, m in SOURCES.items() if tier is None or m["tier"] == tier]


def is_enabled(name: str, env: dict = None) -> bool:
    """A connector is LIVE only when: (1) it's on the allowlist, (2) it is explicitly enabled — a per-source
    `INTEL_SRC_<NAME>=1`, or the master `INTEL_CONNECTORS=1` for a Tier-1 source — and (3) for a key-gated
    source, its credential env var is present. DEFAULT = everything OFF (no outward I/O until configured)."""
    env = os.environ if env is None else env
    m = SOURCES.get(name)
    if not m:
        return False
    per = str(env.get("INTEL_SRC_" + name.upper(), "")).lower() in ("1", "true", "yes")
    master = m["tier"] == 1 and str(env.get("INTEL_CONNECTORS", "")).lower() in ("1", "true", "yes")
    if not (per or master):
        return False
    if m["requires_key"]:
        return bool(env.get(_KEY_ENV.get(name, ""), ""))
    return True


def enabled_sources(env: dict = None) -> list:
    return [n for n in SOURCES if is_enabled(n, env)]


def provenance_record(source: str, *, validation_state: str = "candidate", confidence: float = 0.3,
                      retrieved_at: float = None, **fields) -> dict:
    """Build a strict-provenance intel record. Internet intel defaults to 'candidate' + low confidence:
    it is UNTRUSTED until deterministic validation promotes it. Unknown source -> still recorded, flagged."""
    m = SOURCES.get(source) or {}
    rec = {f: None for f in PROVENANCE_FIELDS}
    rec.update({"source": source, "source_type": m.get("type", "unknown"),
                "license": m.get("license", "review"),
                "retrieved_at": retrieved_at if retrieved_at is not None else time.time(),
                "confidence": float(confidence),
                "validation_state": validation_state if validation_state in VALIDATION_STATES else "candidate"})
    for k, v in fields.items():
        if k in rec:
            rec[k] = v
    rec["allowlisted"] = source in SOURCES
    return rec


def can_promote(frm: str, to: str) -> bool:
    """Lifecycle may only advance one defined step at a time (or move to 'rejected'). No skipping straight
    to production — internet intel earns trust through validation + fixtures + review."""
    if to == "rejected":
        return frm in VALIDATION_STATES
    if frm not in _ORDER or to not in _ORDER:
        return False
    return _ORDER[to] == _ORDER[frm] + 1


def request_log_entry(source: str, endpoint: str, purpose: str, target_scope: str, status,
                      *, rate_limit_state: str = "n/a", cache_status: str = "miss",
                      parser_version: str = None, timestamp: float = None) -> dict:
    """The mandatory outward-request audit record. Built here so every connector logs the SAME contract."""
    m = SOURCES.get(source) or {}
    return {"source": source, "endpoint": endpoint, "purpose": purpose, "target_scope": target_scope,
            "timestamp": timestamp if timestamp is not None else time.time(), "status": status,
            "rate_limit_state": rate_limit_state, "cache_status": cache_status,
            "parser_version": parser_version if parser_version is not None else m.get("parser_version", "0")}
