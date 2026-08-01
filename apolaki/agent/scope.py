"""
Scope enforcement engine + multi-format scope-file parsing.

Enforces scope at the tool-wrapper level (deny-overrides-allow, wildcard match)
and parses program scope from HackerOne / Bugcrowd CSV, Burp JSON, and
section/prefix/markdown plain-text. The parser is adapted from OLYMPUS
routers/scope.py; the engine keeps Apolaki's original wildcard semantics and adds a
structured-rules view for web_security.is_url_in_scope.
"""
import csv
import io
import json
import posixpath
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional
from urllib.parse import urlparse


class PermissionLevel(Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    INTRUSIVE = "intrusive"


@dataclass
class ScopeEntry:
    value: str            # bare host (used for host-level scope matching)
    asset_type: str
    base: Optional[str] = None   # explicit scheme://host:port when the operator gave one
    port: str = ""        # explicit non-default port the operator pinned ("" = any port)
    path: str = ""        # explicit path-prefix the operator pinned ("" = whole host)


def _scope_path(d: str) -> str:
    """Normalized path-prefix from a scope entry that pins one, e.g.
    `https://example.com/api/*` or `example.com/api` -> `/api`. Returns '' for a
    host-level entry (no path, bare '/', or a wildcard host) so nothing is enforced.
    Path scope keeps a path-restricted bug-bounty asset from bleeding into the whole host."""
    d = (d or "").strip().lower()
    if not d or d.startswith("*"):
        return ""
    if "://" in d:
        raw = urlparse(d).path
    else:
        parts = d.split("/", 1)
        raw = "/" + parts[1] if len(parts) > 1 else ""
    raw = (raw or "").split("?")[0].split("#")[0].rstrip("*")
    if not raw or raw == "/":
        return ""
    norm = posixpath.normpath("/" + raw.lstrip("/"))
    return "" if norm in ("", ".", "/") else norm


def _path_prefix_match(req_path: str, scope_path: str) -> bool:
    """True when a concrete request path falls under the pinned scope prefix
    (exact, or a `/prefix/...` descendant). Normalized to defeat `/api/../admin`."""
    a = posixpath.normpath("/" + (req_path or "/").lstrip("/"))
    b = posixpath.normpath("/" + (scope_path or "/").lstrip("/"))
    if b in ("", ".", "/"):
        return True
    return a == b or a.startswith(b.rstrip("/") + "/")


def _split_scope_entry(d: str):
    """(bare_host, base_url|None) from a scope entry that may carry a scheme and/or
    port. The bare host drives scope-matching (always port/scheme-free); the base
    carries scheme+port for probing when the operator gave a non-default one, e.g. a
    local app on http://host.docker.internal:42000. Plain hosts and wildcards default
    to https on the standard port and record no explicit base."""
    d = (d or "").strip().lower()
    if not d:
        return "", None
    if d.startswith("*"):
        return d, None                       # wildcard — no single base URL
    scheme = ""
    if "://" in d:
        p = urlparse(d)
        scheme, netloc = p.scheme, p.netloc
    else:
        netloc = d.split("/")[0]
    host = netloc.split(":")[0]
    port = netloc.split(":")[1] if ":" in netloc else ""
    if not scheme and not port:
        return host, None                    # plain host -> default https, no explicit base
    if not scheme:                           # host:port with no scheme -> infer
        scheme = "https" if port == "443" else "http"
    if scheme == "https" and port in ("", "443"):
        return host, None                    # default https:443 needs no explicit base
    base = f"{scheme}://{host}" + (f":{port}" if port else "")
    return host, base


class ScopeEngine:
    def __init__(self):
        self.in_scope: list = []
        self.out_of_scope: list = []
        self.program_name: str = ""

    def load_manual(self, in_scope: list, out_of_scope: list, program_name: str = "Program") -> None:
        self.program_name = program_name
        for d in in_scope:
            host, base = _split_scope_entry(d)
            if host:
                # capture the explicit port (if the operator pinned one) so validate()
                # can enforce it against concrete request targets — see SEC-1.
                port = ""
                if base and ":" in urlparse(base).netloc:
                    port = urlparse(base).netloc.rsplit(":", 1)[1]
                # SEC-2: capture the path-prefix (if pinned) so a path-restricted asset
                # (https://host/api/*) doesn't silently widen to the whole host.
                path = "" if host.startswith("*") else _scope_path(d)
                self.in_scope.append(ScopeEntry(host, "wildcard" if host.startswith("*") else "domain", base, port, path))
        for d in out_of_scope:
            host, _ = _split_scope_entry(d)
            if host:
                self.out_of_scope.append(ScopeEntry(host, "wildcard" if host.startswith("*") else "domain"))

    def validate(self, target: str) -> tuple:
        host, port, is_request = self._parse_target(target)
        if not host:
            return False, "Invalid target"
        req_path = self._target_path(target)
        for entry in self.out_of_scope:
            if self._matches(host, entry.value):
                return False, f"{host} is explicitly out of scope"
        host_in_scope, path_pinned = False, False
        for entry in self.in_scope:
            if self._matches(host, entry.value):
                host_in_scope = True
                # SEC-1: when the operator pinned an explicit port, enforce it — but
                # only against a concrete REQUEST target (a URL / host:port an HTTP
                # tool will actually hit). A bare hostname (subdomain / DNS recon,
                # is_request=False) stays host-level so domain recon isn't broken.
                if entry.port and is_request and port != entry.port:
                    continue
                # SEC-2: same for a pinned path-prefix — a concrete request outside the
                # authorized path is out of scope; bare-host recon (is_request=False) is
                # never blocked by path. Another in-scope entry can still allow the host.
                if entry.path and is_request:
                    path_pinned = True
                    if not _path_prefix_match(req_path, entry.path):
                        continue
                suffix = f":{entry.port}" if entry.port else ""
                psuffix = entry.path if entry.path else ""
                return True, f"In scope via {entry.value}{suffix}{psuffix}"
        if host_in_scope:
            if path_pinned:
                return False, (f"{host}{req_path} not in scope "
                               "(host is in scope, but the request path is outside the pinned scope path)")
            return False, (f"{host}:{port or '?'} not in scope "
                           "(host is in scope, but the operator pinned a different port)")
        return False, f"{host} not in scope"

    def _target_path(self, target: str) -> str:
        """Path of a concrete request target ('/' when none). Scheme-less host:port/path
        is handled too so validate() can enforce a pinned path-prefix."""
        t = (target or "").strip()
        if "://" in t:
            p = urlparse(t).path or "/"
        else:
            after = t.split("?")[0].split("#")[0].split("/", 1)
            p = "/" + after[1] if len(after) > 1 else "/"
        return (p.split("?")[0].split("#")[0]) or "/"

    def _extract_host(self, target: str) -> str:
        if "://" in target:
            return urlparse(target).netloc.split(":")[0].lower()
        return target.split(":")[0].split("/")[0].lower()

    def _parse_target(self, target: str) -> tuple:
        """(host, effective_port, is_request). is_request is True when the target
        carries a scheme or an explicit port — i.e. a concrete HTTP endpoint whose
        port can be enforced. A bare hostname (no scheme, no port) is a recon host:
        is_request=False, so port pinning never blocks domain-level recon."""
        t = (target or "").strip()
        has_scheme = "://" in t
        netloc = urlparse(t).netloc if has_scheme else t.split("/")[0]
        host = netloc.split(":")[0].lower()
        explicit_port = netloc.rsplit(":", 1)[1] if ":" in netloc else ""
        if explicit_port:
            port = explicit_port
        elif has_scheme:
            scheme = urlparse(t).scheme
            port = "443" if scheme == "https" else "80" if scheme == "http" else ""
        else:
            port = ""
        return host, port, (has_scheme or bool(explicit_port))

    def _matches(self, host: str, pattern: str) -> bool:
        clean = pattern.lstrip("*.").lower()
        return host == clean or host.endswith("." + clean)

    def to_dict(self) -> dict:
        return {
            "program": self.program_name,
            "in_scope": [e.value for e in self.in_scope],
            "out_of_scope": [e.value for e in self.out_of_scope],
            # base URLs carry scheme+port for concrete hosts; consumers like the
            # cross-session memory key use these so apps on the same host but
            # different ports don't collide. Additive — in_scope stays bare hosts.
            "bases": self.base_urls(),
        }

    def to_rules(self) -> dict:
        """Structured rules view consumed by web_security.is_url_in_scope
        (host/path aware). Every domain/wildcard becomes an identifier rule; a
        path-pinned host is emitted as a full scheme://host/path URL identifier so
        _rule_matches_url binds host AND path together (no cross-host path bleed)."""
        def _ident(e):
            if e.path and e.asset_type != "wildcard":
                base = (e.base or f"https://{e.value}").rstrip("/")
                return base + e.path
            return e.value

        def _type(e):
            return "url" if (e.path and e.asset_type != "wildcard") else e.asset_type
        return {
            "in_scope": [{"identifier": _ident(e), "type": _type(e)} for e in self.in_scope],
            "out_of_scope": [{"identifier": e.value, "type": e.asset_type} for e in self.out_of_scope],
        }

    def base_urls(self) -> list:
        """Base URLs for concrete (non-wildcard) in-scope hosts — the operator's
        explicit scheme+port when given, else default https."""
        out = []
        for e in self.in_scope:
            if e.asset_type == "wildcard":
                continue
            out.append(e.base or f"https://{e.value}")
        return out

    def base_map(self) -> dict:
        """host -> base URL (scheme+port) for concrete in-scope hosts, so the planner
        probes a non-standard port/scheme instead of assuming https on 443."""
        return {e.value: (e.base or f"https://{e.value}")
                for e in self.in_scope if e.asset_type != "wildcard"}


# ── Multi-format scope-file parsing (adapted from OLYMPUS) ────────
def _extract_md_url(line: str) -> Optional[str]:
    m = re.match(r'\[.*?\]\(https?://([^/)\s]+)', line)
    return m.group(1).lstrip("www.") if m else None


def _strip_platform_suffix(line: str):
    m = re.match(r'^(.+?)\s+\((Android|iOS|Apple|Google Play)\)\s*$', line, re.I)
    if m:
        kind = m.group(2).lower().replace("google play", "android").replace("apple", "ios")
        return m.group(1).strip(), kind
    return line.strip(), None


def _classify(identifier: str) -> str:
    i = identifier.strip()
    if re.match(r'^\d+$', i):
        return "ios_app_id"
    if re.match(r'^com\.[a-z]', i.lower()):
        return "android_package"
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}(/\d+)?$', i):
        return "ip"
    if re.match(r'^https?://', i, re.I):
        return "url"
    return "domain"


def _parse_target(raw: str) -> Optional[dict]:
    line = raw.strip()
    if not line:
        return None
    md = _extract_md_url(line)
    if md:
        line = md
    line = re.split(r'\s+#\s+', line)[0].strip()
    line, platform = _strip_platform_suffix(line)
    if not line:
        return None
    return {"identifier": line, "type": platform or _classify(line)}


def _parse_sections(content: str) -> dict:
    in_scope, out_of_scope, section = [], [], "in"
    for raw in content.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            u = line.upper()
            if any(k in u for k in ("OUT-OF-SCOPE", "OUT OF SCOPE", "INELIGIBLE", "EXCLUDE", "NOT IN SCOPE")):
                section = "out"
            elif any(k in u for k in ("IN-SCOPE", "IN SCOPE", "ELIGIBLE", "INCLUDE")):
                section = "in"
            continue
        if line.startswith("-"):
            entry = _parse_target(line[1:])
            if entry:
                out_of_scope.append(entry)
            continue
        if line.startswith("+"):
            entry = _parse_target(line[1:])
            if entry:
                in_scope.append(entry)
            continue
        entry = _parse_target(line)
        if entry:
            (in_scope if section == "in" else out_of_scope).append(entry)
    return {"in_scope": in_scope, "out_of_scope": out_of_scope, "format": "section_based"}


def _parse_hackerone_csv(content: str) -> dict:
    in_scope, out_of_scope = [], []
    reader = csv.DictReader(io.StringIO(content))
    hdrs = [h.lower().strip() for h in (reader.fieldnames or [])]
    id_col = next((h for h in hdrs if "identifier" in h or "target" in h), None)
    bounty_col = next((h for h in hdrs if "bounty" in h or "eligible" in h), None)
    type_col = next((h for h in hdrs if "type" in h), None)
    if not id_col:
        return _parse_sections(content)
    skipped = 0
    for row in reader:
        raw = (row.get(id_col) or "").strip()
        if not raw or raw.lower() in ("n/a", "none", "-", ""):
            skipped += 1
            continue
        entry = _parse_target(raw)
        if not entry:
            skipped += 1
            continue
        if type_col:
            entry["type"] = (row.get(type_col) or entry["type"]).strip().lower()
        eligible = (row.get(bounty_col) or "true").strip().lower()
        (in_scope if eligible in ("true", "yes", "1") else out_of_scope).append(entry)
    return {"in_scope": in_scope, "out_of_scope": out_of_scope, "format": "hackerone_csv", "skipped": skipped}


def _parse_bugcrowd_csv(content: str) -> dict:
    in_scope, out_of_scope = [], []
    reader = csv.DictReader(io.StringIO(content))
    hdrs = [h.lower().strip() for h in (reader.fieldnames or [])]
    target_col = next((h for h in hdrs if "target" in h), None)
    focus_col = next((h for h in hdrs if "focus" in h), None)
    if not target_col:
        return _parse_sections(content)
    skipped = 0
    for row in reader:
        raw = (row.get(target_col) or "").strip()
        if not raw:
            skipped += 1
            continue
        entry = _parse_target(raw)
        if not entry:
            skipped += 1
            continue
        focus = (row.get(focus_col) or "in").strip().lower()
        (out_of_scope if "out" in focus or "excluded" in focus else in_scope).append(entry)
    return {"in_scope": in_scope, "out_of_scope": out_of_scope, "format": "bugcrowd_csv", "skipped": skipped}


_ID_HINTS = ("identifier", "target", "asset", "endpoint", "url", "domain", "host", "scope", "name")


def _parse_generic_csv(content: str) -> dict:
    """Best-effort CSV for platforms beyond H1/Bugcrowd (Intigriti, YesWeHack,
    plain exports). Heuristically finds an identifier column and an optional
    eligibility/scope column; unparseable/empty rows are counted, not dropped
    silently."""
    in_scope, out_of_scope, skipped = [], [], 0
    reader = csv.DictReader(io.StringIO(content))
    hdrs = [h.lower().strip() for h in (reader.fieldnames or [])]
    if not hdrs:
        return {"in_scope": [], "out_of_scope": [], "format": "csv", "skipped": 0}
    id_col = next((h for h in hdrs if any(k in h for k in _ID_HINTS)), hdrs[0])
    elig_col = next((h for h in hdrs if any(k in h for k in ("eligible", "bounty", "submission"))), None)
    focus_col = next((h for h in hdrs if any(k in h for k in ("focus", "in_scope", "in scope", "out_of_scope", "out of scope"))), None)
    type_col = next((h for h in hdrs if h == "type" or h.endswith("_type") or "asset_type" in h), None)
    for row in reader:
        raw = (row.get(id_col) or "").strip()
        if not raw or raw.lower() in ("n/a", "none", "-"):
            skipped += 1
            continue
        entry = _parse_target(raw)
        if not entry:
            skipped += 1
            continue
        if type_col:
            tv = (row.get(type_col) or "").strip().lower()
            if tv:
                entry["type"] = tv
        is_out = False
        if elig_col is not None:
            v = (row.get(elig_col) or "true").strip().lower()
            is_out = v in ("false", "no", "0", "ineligible", "out")
        elif focus_col is not None:
            is_out = "out" in (row.get(focus_col) or "").strip().lower()
        (out_of_scope if is_out else in_scope).append(entry)
    return {"in_scope": in_scope, "out_of_scope": out_of_scope, "format": "csv", "skipped": skipped}


def _parse_burp_json(content: str) -> dict:
    data = json.loads(content)
    if "target" in data and "scope" in data.get("target", {}):
        data = data["target"]["scope"]

    def extract(items: list) -> list:
        result = []
        for item in (items or []):
            if isinstance(item, str):
                entry = _parse_target(item)
            elif isinstance(item, dict):
                raw = item.get("host") or item.get("url") or item.get("file") or ""
                entry = _parse_target(raw)
            else:
                entry = None
            if entry:
                result.append(entry)
        return result

    return {
        "in_scope": extract(data.get("include") or data.get("inclusions") or []),
        "out_of_scope": extract(data.get("exclude") or data.get("exclusions") or []),
        "format": "burp_json",
    }


def parse_scope(content: str) -> dict:
    """Auto-detect format and return {in_scope, out_of_scope, format}."""
    content = (content or "").strip()
    if not content:
        return {"in_scope": [], "out_of_scope": [], "format": "empty"}
    if content.startswith("{"):
        try:
            return _parse_burp_json(content)
        except Exception:
            pass
    first = content.splitlines()[0].lower().strip()
    cols = [c.strip() for c in first.split(",")]
    if "," in first and len(cols) >= 2:
        if "asset_identifier" in first or "eligible_for_bounty" in first or ("identifier" in cols and "eligible_for_submission" in first):
            return _parse_hackerone_csv(content)
        if "target" in first and any(k in first for k in ("category", "severity", "focus")):
            return _parse_bugcrowd_csv(content)
        # any other CSV with a recognizable identifier/scope column (Intigriti,
        # YesWeHack, plain exports) -> generic best-effort parser
        if any(any(k in c for k in _ID_HINTS) for c in cols):
            return _parse_generic_csv(content)
    return _parse_sections(content)


# Asset types that are scannable web targets (skip mobile-app ids etc.)
_WEB_TYPES = {"domain", "url", "ip", "wildcard"}


def web_targets(parsed: dict) -> tuple:
    """From a parsed scope, return (in_scope_hosts, out_of_scope_hosts) as plain
    host strings for the scan engine, dropping non-web assets (mobile app ids)."""
    def hosts(entries):
        out = []
        for e in entries:
            if e.get("type", "domain") not in _WEB_TYPES:
                continue
            ident = e["identifier"]
            if ident.startswith("http"):
                ident = urlparse(ident).netloc or ident
            out.append(ident)
        return out
    return hosts(parsed.get("in_scope", [])), hosts(parsed.get("out_of_scope", []))
