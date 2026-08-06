"""Governed intel connectors (#114): fetch -> cache -> rate-limit -> log -> normalize -> dedup -> provenance.

Every outward request goes through fetch(), which HARD-GATES on intel_sources.is_enabled() FIRST: a
DISABLED source performs ZERO network I/O (default = every source disabled). When a source is explicitly
enabled (and, if key-gated, its credential is present), the pipeline serves fresh cache, enforces a
per-source rate limit, appends the mandatory outward-request audit record, then normalizes the raw feed
into strict-provenance CANDIDATE records (untrusted until validated). The HTTP call is INJECTABLE, so the
whole pipeline is unit-tested with no network. No connector is on by default; the fetchers here just make
the already-approved Tier-1 feeds reachable once the operator flips them on.
"""
from __future__ import annotations

import json
import time

import intel_sources as _src

_AUDIT: list = []           # outward-request audit log (the mandatory contract)
_CACHE: dict = {}           # (source, key) -> (fetched_at, raw_text)
_RL: dict = {}              # source -> [recent request timestamps]


def reset():
    """Clear connector state (cache / rate-limit / audit). For tests + a fresh engagement."""
    _AUDIT.clear()
    _CACHE.clear()
    _RL.clear()


def audit_log(limit: int = 200) -> list:
    return _AUDIT[-limit:]


def _rate_ok(source: str, per_min: int, now: float) -> bool:
    win = [t for t in _RL.get(source, []) if now - t < 60]
    if len(win) >= max(1, int(per_min)):
        _RL[source] = win
        return False
    win.append(now)
    _RL[source] = win
    return True


def _log(source, endpoint, purpose, cache, status, now, rl="ok") -> dict:
    m = _src.get(source) or {}
    e = _src.request_log_entry(source, endpoint, purpose, "self", status, rate_limit_state=rl,
                               cache_status=cache, parser_version=m.get("parser_version", "0"), timestamp=now)
    _AUDIT.append(e)
    return e


def _default_http(url: str, headers: dict = None):
    import httpx
    r = httpx.get(url, headers=headers or {}, timeout=30, follow_redirects=True)
    return r.status_code, r.text


def fetch(source: str, key: str = "", *, url: str = None, http=None, now: float = None, env: dict = None) -> dict:
    """Governed fetch. Returns {status, records, cache, log?}. A DISABLED source does ZERO network I/O."""
    now = time.time() if now is None else now
    m = _src.get(source)
    if not m:
        return {"status": "unknown_source", "records": [], "cache": "n/a"}
    if not _src.is_enabled(source, env):
        # the hard gate — no network, no cache read, nothing outward.
        return {"status": "disabled", "records": [], "cache": "n/a",
                "note": "connector disabled; enable its allowlist entry (+ credential) to use it"}
    endpoint = url or m.get("endpoint", "")
    cached = None
    hit = _CACHE.get((source, key))
    if hit and (now - hit[0]) < m.get("cache_ttl_s", 3600):
        cached = hit[1]
    if cached is not None:
        return {"status": "ok", "records": normalize(source, cached), "cache": "hit",
                "log": _log(source, endpoint, "cache-hit", "hit", 200, now)}
    if not _rate_ok(source, m.get("rate_per_min", 10), now):
        return {"status": "rate_limited", "records": [], "cache": "miss",
                "log": _log(source, endpoint, "rate-limited", "miss", 429, now, rl="throttled")}
    try:
        status, text = (http or _default_http)(endpoint, None)
    except Exception as ex:
        return {"status": "error", "records": [], "cache": "miss",
                "log": _log(source, endpoint, "fetch-failed:%s" % str(ex)[:80], "miss", 0, now)}
    log = _log(source, endpoint, "fetched", "miss", status, now)
    if status != 200:
        return {"status": "http_%d" % status, "records": [], "cache": "miss", "log": log}
    _CACHE[(source, key)] = (now, text)
    return {"status": "ok", "records": normalize(source, text), "cache": "miss", "log": log}


# ── normalize: raw feed -> strict-provenance CANDIDATE records (untrusted until validated) ──
def normalize(source: str, raw) -> list:
    fn = _PARSERS.get(source)
    if not fn:
        return []
    try:
        return _dedup(fn(raw))
    except Exception:
        return []


def _dedup(recs: list) -> list:
    seen, out = set(), []
    for r in recs:
        k = (r.get("source"), r.get("cve"), r.get("source_type"))
        if k in seen:
            continue
        seen.add(k)
        out.append(r)
    return out


def _load(raw):
    return json.loads(raw) if isinstance(raw, (str, bytes)) else raw


def _parse_epss(raw) -> list:
    d = _load(raw)
    out = []
    for row in (d.get("data") or []):
        r = _src.provenance_record("epss", cve=row.get("cve"), published_at=row.get("date"), confidence=0.3)
        r["epss"] = row.get("epss")
        r["percentile"] = row.get("percentile")
        out.append(r)
    return out


def _nvd_cwe(cve: dict):
    for w in (cve.get("weaknesses") or []):
        for de in (w.get("description") or []):
            if str(de.get("value", "")).upper().startswith("CWE-"):
                return de["value"]
    return None


def _parse_nvd(raw) -> list:
    d = _load(raw)
    out = []
    for v in (d.get("vulnerabilities") or []):
        c = v.get("cve") or {}
        metrics = ((c.get("metrics") or {}).get("cvssMetricV31") or [{}])[0].get("cvssData", {})
        r = _src.provenance_record("nvd", cve=c.get("id"), published_at=c.get("published"),
                                   last_modified=c.get("lastModified"), cwe=_nvd_cwe(c),
                                   references=[x.get("url") for x in (c.get("references") or [])][:10], confidence=0.3)
        r["cvss"] = metrics.get("baseScore")
        out.append(r)
    return out


def _parse_ghsa(raw) -> list:
    d = _load(raw)
    rows = d if isinstance(d, list) else (d.get("advisories") or [])
    out = []
    for a in rows:
        ids = a.get("identifiers") or []
        cve = next((i.get("value") for i in ids if str(i.get("type")).upper() == "CVE"), a.get("cve_id"))
        vulns = a.get("vulnerabilities") or []
        r = _src.provenance_record("ghsa", cve=cve, published_at=a.get("published_at"),
                                   last_modified=a.get("updated_at"),
                                   affected_product=(vulnerabilities_pkg(vulns)),
                                   affected_versions=[v.get("vulnerable_version_range") for v in vulns],
                                   fixed_versions=[v.get("first_patched_version") for v in vulns],
                                   references=[a.get("html_url")], confidence=0.3)
        out.append(r)
    return out


def vulnerabilities_pkg(vulns: list):
    for v in vulns:
        pkg = (v.get("package") or {}).get("name")
        if pkg:
            return pkg
    return None


_PARSERS = {"epss": _parse_epss, "nvd": _parse_nvd, "ghsa": _parse_ghsa}
