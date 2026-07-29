from __future__ import annotations

from packages.contracts.schemas.engagement import ScopeRule, ScopeSpec
from packages.scope import _is_dangerous_address, check_target, normalize_host
from packages.scope.firewall import ScopeFirewall


def _scope(include=None, exclude=None, ports=None):
    return ScopeSpec(
        include=include or [],
        exclude=exclude or [],
        ports=ports or [],
    )


def _rule(type_: str, value: str):
    return ScopeRule(type=type_, value=value)


# ---------------------------------------------------------------------------
# DNS rebinding: hostname is in scope, but the resolved address is dangerous.
# The firewall must catch this at the address-classification stage, not the
# scope-rule stage (which only ever sees the hostname).
# ---------------------------------------------------------------------------

_REBINDING_TARGETS = [
    "169.254.169.254",  # AWS/GCP metadata
    "fd00:ec2::254",  # AWS IMDSv2 IPv6 metadata
    "::ffff:169.254.169.254",  # IPv4-mapped IPv6 metadata
    "127.0.0.1",
    "0.0.0.0",
    "::1",
]


def test_dns_rebinding_resolved_addresses_blocked_by_firewall():
    fw = ScopeFirewall(_scope(include=[_rule("dns_suffix", "*.evil.test")]))
    for addr in _REBINDING_TARGETS:
        result = fw.preflight("app.evil.test", resolved_addresses=[addr])
        assert result.allowed is False, f"{addr} should be blocked by DNS rebinding guard"
        assert result.failed_check == "address_classification"


def test_dns_rebinding_via_check_dns_answers():
    fw = ScopeFirewall(_scope(include=[_rule("dns_suffix", "*.evil.test")]))
    for addr in _REBINDING_TARGETS:
        result = fw.check_dns_answers("app.evil.test", [addr])
        assert result.allowed is False, f"{addr} should be blocked as a dangerous DNS answer"


def test_dns_rebinding_one_safe_one_dangerous_answer_blocked():
    fw = ScopeFirewall(_scope(include=[_rule("dns_suffix", "*.evil.test")]))
    result = fw.check_dns_answers("app.evil.test", ["93.184.216.34", "169.254.169.254"])
    assert result.allowed is False


# ---------------------------------------------------------------------------
# IPv6 loopback
# ---------------------------------------------------------------------------


def test_ipv6_loopback_is_dangerous():
    assert _is_dangerous_address("::1") is True


def test_ipv6_loopback_blocked_in_check_target():
    scope = _scope(include=[_rule("cidr", "::/0")])
    result = check_target(scope, "::1")
    assert result.allowed is False
    assert "dangerous" in result.reason


# ---------------------------------------------------------------------------
# Cloud metadata addresses (all forms)
# ---------------------------------------------------------------------------


def test_all_metadata_ips_blocked():
    scope = _scope(include=[_rule("cidr", "0.0.0.0/0")])
    for addr in ["169.254.169.254", "fd00:ec2::254"]:
        assert _is_dangerous_address(addr) is True
        result = check_target(scope, addr)
        assert result.allowed is False


def test_metadata_ip_blocked_via_url_target():
    scope = _scope(include=[_rule("dns_suffix", "*.internal.test")])
    result = check_target(scope, "http://169.254.169.254/latest/meta-data/")
    assert result.allowed is False


# ---------------------------------------------------------------------------
# 0.0.0.0 (unspecified address)
# ---------------------------------------------------------------------------


def test_zero_address_is_dangerous():
    assert _is_dangerous_address("0.0.0.0") is True


def test_zero_address_blocked_in_scope():
    scope = _scope(include=[_rule("cidr", "0.0.0.0/0")])
    assert check_target(scope, "0.0.0.0").allowed is False


# ---------------------------------------------------------------------------
# URL-encoded bypass attempts
# ---------------------------------------------------------------------------


def test_percent_encoded_path_does_not_bypass_url_prefix_scope():
    scope = _scope(include=[_rule("url_prefix", "https://api.example.test/")])
    # %2f-encoded traversal segments must not grant access outside the prefix.
    result = check_target(scope, "https://api.example.test%2f..%2f@evil.test/")
    assert result.allowed is False


def test_userinfo_bypass_resolves_to_real_host_not_scope_bait():
    # http://<scope-host>@evil.test/ -- the part before '@' is HTTP userinfo,
    # not the host. The real target host is evil.test and must be denied.
    scope = _scope(include=[_rule("exact_host", "api.example.test")])
    result = check_target(scope, "http://api.example.test@evil.test/")
    assert result.allowed is False


def test_encoded_slash_in_exact_host_does_not_match():
    scope = _scope(include=[_rule("exact_host", "target.test")])
    result = check_target(scope, "target.test%2f.evil.test")
    assert result.allowed is False


# ---------------------------------------------------------------------------
# Extremely long hostnames
# ---------------------------------------------------------------------------


def test_extremely_long_hostname_does_not_crash_and_is_denied():
    scope = _scope(include=[_rule("exact_host", "target.test")])
    long_host = "a" * 100_000
    result = check_target(scope, long_host)
    assert result.allowed is False


def test_extremely_long_hostname_normalizes_without_error():
    long_host = ("sub." * 5000) + "test"
    normalized = normalize_host(long_host)
    assert isinstance(normalized, str)
    assert len(normalized) > 0


# ---------------------------------------------------------------------------
# Null bytes in hostname
# ---------------------------------------------------------------------------


def test_null_byte_in_hostname_does_not_match_scope():
    scope = _scope(include=[_rule("exact_host", "target.test")])
    result = check_target(scope, "target.test\x00.evil.test")
    assert result.allowed is False


def test_null_byte_in_hostname_normalizes_without_crashing():
    normalized = normalize_host("target.test\x00evil.test")
    assert isinstance(normalized, str)
