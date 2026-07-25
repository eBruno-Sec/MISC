"""Scope firewall — core (§13.4).

The engine is ported from apolaki/agent/scope.py (ScopeEngine): deny overrides
allow, wildcard suffix matching, and operator port-pinning enforced against
concrete request targets. It is fronted by the target guard (arg-injection /
shell-metachar rejection) so nothing reaches DNS or a tool unchecked.

M2 provides the in/out-of-scope + port-pin decision used by safe recon. M3 wraps
this in the executor with DNS resolution+pinning, RFC1918/link-local blocking,
redirect re-checks, and rebinding/resolution-drift rejection (§13.4 steps 3-8).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse

from policy.target_guard import is_valid_target


@dataclass
class ScopeEntry:
    value: str  # bare host used for matching
    asset_type: str  # "domain" | "wildcard"
    port: str = ""  # operator-pinned port ("" = any)


class ScopeDecision:
    def __init__(self, allowed: bool, reason: str) -> None:
        self.allowed = allowed
        self.reason = reason

    def __bool__(self) -> bool:  # pragma: no cover - convenience
        return self.allowed

    def __repr__(self) -> str:  # pragma: no cover
        return f"ScopeDecision(allowed={self.allowed!r}, reason={self.reason!r})"


class ScopeFirewall:
    """Deny-overrides-allow host/port scope engine."""

    def __init__(self) -> None:
        self.in_scope: list[ScopeEntry] = []
        self.out_of_scope: list[ScopeEntry] = []

    @classmethod
    def from_targets(cls, targets: list[dict]) -> "ScopeFirewall":
        """Build from persisted scope_target rows (dicts with value/disposition/
        constraints). A constraints.port pins a port for request-level checks."""
        fw = cls()
        for t in targets:
            value = (t.get("value") or "").strip().lower()
            if not value:
                continue
            host, port = _split_host_port(value)
            asset_type = "wildcard" if host.startswith("*") else "domain"
            entry = ScopeEntry(value=host, asset_type=asset_type, port=port or _pinned_port(t))
            if t.get("disposition", "include") == "exclude":
                fw.out_of_scope.append(ScopeEntry(value=host, asset_type=asset_type))
            else:
                fw.in_scope.append(entry)
        return fw

    def validate(self, target: str) -> ScopeDecision:
        # Guard first: reject argument-injection / shell metacharacters (§13.4 s1).
        if not is_valid_target(_strip_scheme(target)):
            return ScopeDecision(False, "invalid or unsafe target")

        host, port, is_request = _parse_target(target)
        if not host:
            return ScopeDecision(False, "invalid target")

        # Deny overrides allow (§13.4): excluded hosts are rejected first.
        for entry in self.out_of_scope:
            if _matches(host, entry.value):
                return ScopeDecision(False, f"{host} is explicitly out of scope")

        host_in_scope = False
        for entry in self.in_scope:
            if _matches(host, entry.value):
                host_in_scope = True
                # Port pin only applies to concrete request targets (a URL or
                # host:port), never to bare-host recon.
                if entry.port and is_request and port != entry.port:
                    continue
                suffix = f":{entry.port}" if entry.port else ""
                return ScopeDecision(True, f"in scope via {entry.value}{suffix}")

        if host_in_scope:
            return ScopeDecision(
                False, f"{host}:{port or '?'} not in scope (host in scope, pinned to a different port)"
            )
        return ScopeDecision(False, f"{host} not in scope")


def _pinned_port(target: dict) -> str:
    constraints = target.get("constraints") or {}
    port = constraints.get("port")
    return str(port) if port else ""


def _strip_scheme(target: str) -> str:
    t = (target or "").strip()
    return urlparse(t).netloc or t.split("/")[0] if "://" in t else t


def _split_host_port(value: str) -> tuple[str, str]:
    netloc = urlparse(value).netloc if "://" in value else value.split("/")[0]
    host = netloc.split(":")[0].lower()
    port = netloc.rsplit(":", 1)[1] if ":" in netloc else ""
    return host, port


def _parse_target(target: str) -> tuple[str, str, bool]:
    """(host, effective_port, is_request). is_request is True when the target
    carries a scheme or an explicit port — a concrete endpoint whose port can be
    enforced. A bare hostname is recon: is_request=False."""
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


def _matches(host: str, pattern: str) -> bool:
    clean = pattern.lstrip("*.").lower()
    return host == clean or host.endswith("." + clean)


# --------------------------------------------------------------------------- #
# Resolved-address SSRF checks (§13.4 steps 4-6). The executor resolves the
# destination, then calls these on the resolved IP before connecting — catching
# DNS rebinding to internal ranges and cloud metadata even for an in-scope host.
# --------------------------------------------------------------------------- #
def classify_ip(ip: str) -> str:
    """Classify a resolved IP for egress policy."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link_local"  # 169.254.0.0/16 — includes the cloud metadata IP
    if addr.is_multicast:
        return "multicast"
    if addr.is_reserved or addr.is_unspecified:
        return "reserved"
    if addr.is_private:
        return "private"
    return "public"


def is_ssrf_blocked(ip: str, *, allow_private: bool = False) -> bool:
    """True if the resolved IP must be blocked. Loopback/link-local/multicast/
    reserved/invalid are ALWAYS blocked (so 169.254.169.254 is denied even in a
    lab). Private (RFC1918) is blocked unless allow_private — lab targets like a
    dockerized juice-shop legitimately resolve to a private bridge address."""
    kind = classify_ip(ip)
    if kind in {"loopback", "link_local", "multicast", "reserved", "invalid"}:
        return True
    if kind == "private":
        return not allow_private
    return False
