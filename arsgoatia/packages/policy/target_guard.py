"""Target validation guard.

Ported from olympus/backend/core/security.py (is_valid_target, expand_cidr,
validate_targets). Rejects argument-injection (leading '-') and shell
metacharacters before any target string reaches a tool, DNS resolver, or the
scope engine. This runs first in the scope firewall (§13.4 step 1).
"""

from __future__ import annotations

import ipaddress
import re

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
_WILDCARD_RE = re.compile(
    r"^\*\.(?=.{1,251}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def is_valid_target(value: str) -> bool:
    """True for a hostname, 'localhost', IPv4, IPv4 CIDR, or any with a :port.
    Blocks leading '-' (argument-injection guard) and shell characters."""
    if not value or value.startswith("-"):
        return False
    value = value.strip()
    if len(value) > 261:  # 253 host + ':' + 5 port + slack
        return False
    if any(c in value for c in (";", "&", "|", "$", "`", " ", "\t", "\n", "'", '"', "\\", "<", ">")):
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


def expand_cidr(target: str, cap: int = 1024) -> list[str] | None:
    """Expand an IPv4 CIDR to host IPs (capped). None for non-CIDR targets."""
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
    ips: list[str] = []
    for i, ip in enumerate(net.hosts()):
        if i >= max(1, cap):
            break
        ips.append(str(ip))
    return ips or None


def validate_targets(values: list[str]) -> tuple[list[str], list[str]]:
    """Split a list into (valid, rejected)."""
    valid, rejected = [], []
    for v in values:
        v = (v or "").strip()
        if not v:
            continue
        (valid if is_valid_target(v) else rejected).append(v)
    return valid, rejected
