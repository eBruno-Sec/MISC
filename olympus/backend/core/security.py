"""
OLYMPUS security helpers: API-key gate and target validation.

API key:
  Set OLYMPUS_API_KEY in .env. All /api and /ws requests must send it via
  the X-API-Key header (or ?api_key= for the WebSocket, which cannot set headers).
  If OLYMPUS_API_KEY is unset/blank, the gate is DISABLED (single-user localhost
  convenience) and a warning is logged at startup.

Target validation:
  Rejects anything that is not a bare hostname, IPv4, or IPv4 CIDR, and rejects
  any value beginning with '-' (argument-injection guard for nmap/nuclei/ffuf).
"""
import ipaddress
import os
import re
from fastapi import Request, HTTPException, WebSocket

# hostname: labels of alnum/hyphen, no leading hyphen, TLD-ish tail
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
# allow a single leading wildcard label for scope-style entries: *.example.com
_WILDCARD_RE = re.compile(
    r"^\*\.(?=.{1,251}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def api_key_enabled() -> bool:
    return bool(os.getenv("OLYMPUS_API_KEY", "").strip())


def _expected_key() -> str:
    return os.getenv("OLYMPUS_API_KEY", "").strip()


async def require_api_key(request: Request):
    """FastAPI dependency: enforce X-API-Key on REST routes when a key is configured."""
    if not api_key_enabled():
        return
    provided = request.headers.get("x-api-key", "")
    if not provided or provided != _expected_key():
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


async def check_ws_key(websocket: WebSocket) -> bool:
    """WebSocket cannot send custom headers from the browser; accept ?api_key=."""
    if not api_key_enabled():
        return True
    provided = websocket.query_params.get("api_key", "")
    return bool(provided) and provided == _expected_key()


def is_valid_target(value: str) -> bool:
    """True for a hostname, 'localhost', IPv4, IPv4 CIDR, or any of these with a :port.
    Blocks leading '-' (argument-injection guard) and shell characters."""
    if not value or value.startswith("-"):
        return False
    value = value.strip()
    if len(value) > 261:  # 253 host + ':' + 5 port + slack
        return False
    # reject shell metacharacters outright
    if any(c in value for c in (";", "&", "|", "$", "`", " ", "\t", "\n", "'", '"', "\\", "<", ">")):
        return False

    # split optional :port (but not for CIDR, and not for bare IPv6 which we do not accept)
    host = value
    if "/" not in value and value.count(":") == 1:
        host, _, port = value.rpartition(":")
        if not (port.isdigit() and 1 <= int(port) <= 65535):
            return False

    # localhost is explicitly allowed (local testing)
    if host == "localhost":
        return True

    # IPv4 or CIDR
    try:
        if "/" in host:
            ipaddress.ip_network(host, strict=False)
            return True
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    # hostname or single-wildcard hostname
    return bool(_HOSTNAME_RE.match(host) or _WILDCARD_RE.match(host))


def expand_cidr(target: str, cap: int = 1024):
    """If target is an IPv4 CIDR (e.g. 10.0.0.0/24), return its host IPs as strings,
    capped at `cap`. Returns None for any non-CIDR target so callers fall back to
    normal hostname handling.

    /32 -> the single host; /31 -> both hosts (RFC 3021); otherwise the usable host
    range (network + broadcast excluded), capped."""
    t = re.sub(r"^https?://", "", (target or "").strip())
    t = t.split()[0] if t else ""      # first token; keep the /mask intact
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


def validate_targets(values: list[str]) -> tuple[list[str], list[str]]:
    """Split a list into (valid, rejected)."""
    valid, rejected = [], []
    for v in values:
        v = (v or "").strip()
        if not v:
            continue
        (valid if is_valid_target(v) else rejected).append(v)
    return valid, rejected
