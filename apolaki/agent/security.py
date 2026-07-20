"""
Apolaki security helpers: target validation + CIDR expansion.

Target validation rejects anything that is not a bare hostname, wildcard
hostname, IPv4, or IPv4 CIDR, and rejects any value beginning with '-'
(argument-injection guard for nmap/nuclei/ffuf/httpx) or containing shell
metacharacters. Ported from OLYMPUS core/security.py.
"""
import ipaddress
import re

# hostname: labels of alnum/hyphen, no leading hyphen, TLD-ish tail
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
# allow a single leading wildcard label for scope-style entries: *.example.com
_WILDCARD_RE = re.compile(
    r"^\*\.(?=.{1,251}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)

_SHELL_META = (";", "&", "|", "$", "`", " ", "\t", "\n", "'", '"', "\\", "<", ">")


def is_valid_target(value: str) -> bool:
    """True for a hostname, 'localhost', IPv4, IPv4 CIDR, wildcard hostname, or
    any of these with a :port. Blocks leading '-' and shell metacharacters."""
    if not value or value.startswith("-"):
        return False
    value = value.strip()
    if len(value) > 261:  # 253 host + ':' + 5 port + slack
        return False
    if any(c in value for c in _SHELL_META):
        return False

    host = value
    if "/" not in value and value.count(":") == 1:
        host, _, port = value.rpartition(":")
        if not (port.isdigit() and 1 <= int(port) <= 65535):
            return False

    if host == "localhost":
        return True

    try:
        if "/" in host:
            ipaddress.ip_network(host, strict=False)
            return True
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    return bool(_HOSTNAME_RE.match(host) or _WILDCARD_RE.match(host))


def expand_cidr(target: str, cap: int = 1024):
    """If target is an IPv4 CIDR, return its host IPs as strings, capped at `cap`.
    Returns None for any non-CIDR target. /32 -> single host; /31 -> both hosts
    (RFC 3021); otherwise the usable host range, capped."""
    t = re.sub(r"^https?://", "", (target or "").strip())
    t = t.split()[0] if t else ""
    if "/" not in t:
        return None
    try:
        net = ipaddress.ip_network(t, strict=False)
    except ValueError:
        return None
    if net.version != 4:
        return None
    if net.prefixlen == 32:
        return [str(net.network_address)]
    ips = []
    for i, ip in enumerate(net.hosts()):
        if i >= max(1, cap):
            break
        ips.append(str(ip))
    return ips or None


def validate_targets(values: list) -> tuple:
    """Split a list into (valid, rejected)."""
    valid, rejected = [], []
    for v in values:
        v = (v or "").strip()
        if not v:
            continue
        (valid if is_valid_target(v) else rejected).append(v)
    return valid, rejected


def safe_flags(flag_string: str, allowed_prefixes: tuple) -> list:
    """Split a user/AI-provided flag string into tokens, dropping anything that
    isn't a plain value or an allow-listed flag. Defense-in-depth for tool
    wrappers that accept a free-form `flags` argument."""
    out = []
    for tok in (flag_string or "").split():
        if tok.startswith("-"):
            if any(tok.split("=")[0] == p or tok.startswith(p) for p in allowed_prefixes):
                out.append(tok)
        elif not any(c in tok for c in _SHELL_META):
            out.append(tok)
    return out
