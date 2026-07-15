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
