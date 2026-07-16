"""
Scope guard.

Round Table never fires exploits, but the Advanced cURL console lets an operator
send real requests for manual verification. Those requests are constrained to the
mission scope so the tool cannot be pointed at out-of-scope infrastructure.
"""
import ipaddress
import socket
from urllib.parse import urlparse


def normalize_target(raw: str) -> str:
    t = raw.strip().lower()
    for p in ("https://", "http://"):
        if t.startswith(p):
            t = t[len(p):]
    t = t.split("/")[0].split("@")[-1]
    if t.startswith("www."):
        t = t[4:]
    return t.strip("/").strip()


def split_host_port(target: str) -> tuple[str, str]:
    """'juice-shop:3000' -> ('juice-shop', '3000'); 'example.com' -> ('example.com', '')."""
    t = normalize_target(target)
    if ":" in t:
        h, _, p = t.rpartition(":")
        if p.isdigit() and h:
            return h, p
    return t, ""


def default_scope(target: str) -> dict:
    """Host (port-stripped) + all subdomains are in scope by default for a mission."""
    host, _ = split_host_port(target)
    return {
        "in_scope": [host, f"*.{host}"],
        "out_of_scope": [],
        "allow_active": False,
    }


def _host_of(url_or_host: str) -> str:
    s = url_or_host.strip()
    if "://" in s:
        return (urlparse(s).hostname or "").lower()
    return normalize_target(s)


def _matches(host: str, rule: str) -> bool:
    host = host.lower().strip(".")
    rule = rule.lower().strip()
    if not host or not rule:
        return False
    # CIDR rule → resolve host and test membership.
    if "/" in rule:
        try:
            net = ipaddress.ip_network(rule, strict=False)
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                ip = ipaddress.ip_address(socket.gethostbyname(host))
            return ip in net
        except Exception:
            return False
    if rule.startswith("*."):
        base = rule[2:]
        return host == base or host.endswith("." + base)
    return host == rule or host.endswith("." + rule)


def in_scope(url_or_host: str, scope: dict) -> tuple[bool, str]:
    host = _host_of(url_or_host)
    if not host:
        return False, "no host in request"
    for rule in scope.get("out_of_scope", []):
        if _matches(host, rule):
            return False, f"{host} matches out-of-scope rule '{rule}'"
    in_rules = scope.get("in_scope", [])
    if not in_rules:
        return True, "no in-scope restriction set"
    for rule in in_rules:
        if _matches(host, rule):
            return True, f"{host} in scope via '{rule}'"
    return False, f"{host} is not covered by any in-scope rule"


def parse_scope_text(text: str) -> dict:
    """
    Accept pasted scope: one entry per line. Prefix '!' or '-' marks out-of-scope.
    Lines starting with '#' are comments.
    """
    in_s, out_s = [], []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        bucket = out_s if line[0] in "!-" else in_s
        entry = line[1:].strip() if line[0] in "!-" else line
        if "/" in entry or entry.startswith("*."):
            bucket.append(entry.lower())
        else:
            bucket.append(normalize_target(entry))
    return {"in_scope": in_s, "out_of_scope": out_s, "allow_active": False}


# ── bug-bounty scope CSV import (HackerOne structured scope) ─────────────────
# Asset types that map to something Round Table can scan over HTTP. Mobile app
# IDs, source-code repos, "OTHER", etc. are recorded but not scannable here.
_WEB_ASSET_TYPES = {"URL", "WILDCARD", "DOMAIN", "IP_ADDRESS", "CIDR", "API"}


def _normalize_rule(host: str) -> str:
    """Canonicalize a scope host/pattern. Fix HackerOne's occasional malformed
    wildcards ('*tiktokv.us' → '*.tiktokv.us') and keep proper '*.x' patterns."""
    h = (host or "").strip().lower().strip(".")
    if h.startswith("*.") or "/" in h:
        return h
    if h.startswith("*"):
        return "*." + h[1:].lstrip(".")
    return h


def _split_identifier(ident: str) -> tuple[str, str]:
    """Return (host, path) from a scope identifier that may be a bare host, a
    wildcard, or a full URL with a path (e.g. https://x.com/minis/)."""
    s = (ident or "").strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("@")[-1]
    host, _, rest = s.partition("/")
    path = "/" + rest if rest.strip("/") else ""
    return host.strip().lower(), path


def parse_bounty_scope_csv(text: str) -> dict:
    """
    Parse a bug-bounty scope CSV export (HackerOne structured scope) into Round
    Table scope. Columns used: identifier, asset_type, eligible_for_submission
    (falls back to eligible_for_bounty). Returns in/out scope rules, a list of
    scannable target hosts, notes for things needing manual review, and a summary.
    """
    import csv
    import io

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or "identifier" not in reader.fieldnames:
        raise ValueError("not a recognized scope CSV (missing an 'identifier' column)")

    in_scope, out_scope, targets, skipped, notes = [], [], [], [], []
    seen_in, seen_out, seen_t, asset_counts = set(), set(), set(), {}

    def _add(bucket, seen, rule):
        if rule and rule not in seen:
            seen.add(rule)
            bucket.append(rule)

    for row in reader:
        ident = (row.get("identifier") or "").strip()
        if not ident:
            continue
        atype = (row.get("asset_type") or "URL").strip().upper()
        asset_counts[atype] = asset_counts.get(atype, 0) + 1
        elig_raw = row.get("eligible_for_submission")
        if elig_raw is None or str(elig_raw).strip() == "":
            elig_raw = row.get("eligible_for_bounty", "true")
        eligible = str(elig_raw).strip().lower() in ("true", "1", "yes")

        if atype not in _WEB_ASSET_TYPES:
            skipped.append({"identifier": ident, "asset_type": atype})
            continue

        host, path = _split_identifier(ident)
        rule = _normalize_rule(host)
        if not rule:
            skipped.append({"identifier": ident, "asset_type": atype})
            continue

        # A path-specific out-of-scope URL (e.g. .../minis/) can't be enforced by
        # host-level scope — flag it for manual review instead of blocking the
        # whole host (which may be in scope elsewhere).
        if not eligible and path:
            notes.append(f"path-specific out-of-scope, verify manually: {host}{path}")
            continue

        if eligible:
            _add(in_scope, seen_in, rule)
            t = rule[2:] if rule.startswith("*.") else rule
            t = t.strip(".")
            if t.startswith("www."):
                t = t[4:]
            if t and "/" not in t and t not in seen_t:
                seen_t.add(t)
                targets.append(t)
        else:
            _add(out_scope, seen_out, rule)

    return {
        "in_scope": in_scope,
        "out_of_scope": out_scope,
        "targets": targets,
        "skipped": skipped,
        "notes": notes,
        "asset_counts": asset_counts,
        "summary": {
            "in_scope": len(in_scope),
            "out_of_scope": len(out_scope),
            "targets": len(targets),
            "skipped": len(skipped),
            "notes": len(notes),
        },
    }
