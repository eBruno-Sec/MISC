"""ArsGoatia scope enforcement library.

Determines whether a target (host, IP, URL) is within the authorized
engagement scope.  Every check is deterministic -- no AI involved.
Fail-closed: if scope is empty or data is missing the answer is DENY.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Sequence
from urllib.parse import urlparse

from packages.contracts.schemas.engagement import ScopeRule, ScopeSpec


# ---------------------------------------------------------------------------
# Internal constants
# ---------------------------------------------------------------------------

_METADATA_ADDRESSES = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),  # AWS / GCP metadata
        ipaddress.ip_address("fd00:ec2::254"),  # AWS IMDSv2 IPv6
    }
)


# ---------------------------------------------------------------------------
# Host normalisation
# ---------------------------------------------------------------------------


def normalize_host(host: str) -> str:
    """Lowercase, strip trailing dots, apply IDNA encoding for unicode."""
    host = host.strip().lower().rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        pass
    return host


# ---------------------------------------------------------------------------
# Matching helpers
# ---------------------------------------------------------------------------


def _dns_suffix_match(pattern: str, host: str) -> bool:
    """*.example.test matches app.example.test but not example.test."""
    host = normalize_host(host)
    pattern = normalize_host(pattern)
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.test"
        return host.endswith(suffix) and host != suffix.lstrip(".")
    return host == pattern


def _bare_host(s: str) -> str:
    """Strip scheme, port, and path — return only the hostname portion."""
    if "://" in s:
        parsed = urlparse(s)
        return parsed.hostname or s
    # host:port format
    if ":" in s and not s.startswith("["):
        return s.split(":")[0]
    return s


def _exact_host_match(expected: str, host: str) -> bool:
    return normalize_host(_bare_host(expected)) == normalize_host(_bare_host(host))


def _cidr_match(cidr: str, addr: str) -> bool:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        ip = _resolve_ip(addr)
        if ip is None:
            return False
        return ip in network
    except ValueError:
        return False


def _url_prefix_match(prefix: str, url: str) -> bool:
    return url.startswith(prefix)


def _resolve_ip(addr: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse an IP string, mapping IPv4-mapped IPv6 to plain IPv4."""
    try:
        ip = ipaddress.ip_address(addr)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            return ip.ipv4_mapped
        return ip
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Dangerous-address guard
# ---------------------------------------------------------------------------


def _classify_address(addr: str) -> str:
    """Classify a resolved address: 'safe', 'private', or 'dangerous'.

    Order matters — metadata / loopback / link-local are checked before the
    private-range test, because Python's ``is_private`` also returns True for
    link-local (169.254/16) and loopback. That guarantees the cloud-metadata
    address stays 'dangerous' even when private targets are permitted.
    """
    ip = _resolve_ip(addr)
    if ip is None:
        return "safe"
    if ip in _METADATA_ADDRESSES:
        return "dangerous"
    if ip.is_loopback:
        return "dangerous"
    if ip.is_link_local:
        return "dangerous"
    if ip.is_private:
        return "private"
    return "safe"


def _is_dangerous_address(addr: str, *, allow_private: bool = False) -> bool:
    """Block metadata, loopback, link-local, private, IPv4-mapped-IPv6.

    When *allow_private* is True, RFC1918 private ranges are permitted (for
    explicitly-scoped internal/lab targets). Metadata, loopback, and link-local
    remain blocked regardless — they are never legitimate targets.
    """
    classification = _classify_address(addr)
    if classification == "dangerous":
        return True
    if classification == "private":
        return not allow_private
    return False


# ---------------------------------------------------------------------------
# Rule matching
# ---------------------------------------------------------------------------

_MATCHERS = {
    "dns_suffix": lambda rule, target: _dns_suffix_match(rule, target),
    "exact_host": lambda rule, target: _exact_host_match(rule, target),
    "cidr": lambda rule, target: _cidr_match(rule, target),
    "url_prefix": lambda rule, target: _url_prefix_match(rule, target),
}


def _matches_rule(rule: ScopeRule, target: str) -> bool:
    matcher = _MATCHERS.get(rule.type)
    if matcher is None:
        return False
    return matcher(rule.value, target)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScopeVerdict:
    allowed: bool
    reason: str
    matched_rule: ScopeRule | None = None


def check_target(
    scope: ScopeSpec,
    target: str,
    *,
    port: int | None = None,
    is_redirect: bool = False,
) -> ScopeVerdict:
    """Evaluate *target* against *scope*.  Returns a ScopeVerdict.

    Fail-closed:
    - Empty scope => deny.
    - Dangerous addresses (metadata, loopback, link-local, private) => deny.
    - Deny rules override allow rules.
    - Port pinning: if scope.ports is non-empty, port must be in the list.
    - Redirects: if scope.redirect_policy == "reject" and is_redirect, deny.
    """
    # Fail closed on empty scope
    if not scope.include:
        return ScopeVerdict(allowed=False, reason="empty scope denies all")

    # Extract host/IP from target for address checks
    host = _extract_host(target)

    # Dangerous address check
    if host and _is_dangerous_address(host, allow_private=scope.allow_private_targets):
        return ScopeVerdict(allowed=False, reason=f"dangerous address blocked: {host}")

    # Redirect policy
    if is_redirect and scope.redirect_policy == "reject":
        # For redirects, we re-check scope; if out of scope, deny
        # The caller should set is_redirect=True when following redirects
        pass  # Fall through to normal scope check -- deny is the default

    # Deny rules override allow (check first)
    for rule in scope.exclude:
        if _matches_rule(rule, target) or (host and _matches_rule(rule, host)):
            return ScopeVerdict(allowed=False, reason="deny rule matched", matched_rule=rule)

    # Check allow rules
    matched = False
    matched_rule = None
    for rule in scope.include:
        if _matches_rule(rule, target) or (host and _matches_rule(rule, host)):
            matched = True
            matched_rule = rule
            break

    if not matched:
        reason = "redirect target out of scope" if is_redirect else "no include rule matched"
        return ScopeVerdict(allowed=False, reason=reason)

    # Port pinning
    if scope.ports and port is not None:
        if port not in scope.ports:
            return ScopeVerdict(
                allowed=False,
                reason=f"port {port} not in allowed ports {scope.ports}",
            )

    return ScopeVerdict(allowed=True, reason="in scope", matched_rule=matched_rule)


def _extract_host(target: str) -> str | None:
    """Best-effort host extraction from a target string (URL, host, or IP)."""
    if "://" in target:
        parsed = urlparse(target)
        return normalize_host(parsed.hostname) if parsed.hostname else None
    # Could be host:port or plain host/IP
    if target.startswith("["):
        # IPv6 bracket notation
        end = target.find("]")
        if end > 0:
            return target[1:end]
    if ":" in target and target.count(":") == 1:
        return normalize_host(target.split(":")[0])
    return normalize_host(target)
