from __future__ import annotations

from packages.contracts.schemas.engagement import ScopeRule, ScopeSpec
from packages.scope import (
    _is_dangerous_address,
    check_target,
    normalize_host,
)


def _scope(include=None, exclude=None, ports=None, redirect_policy="same-scope-only"):
    return ScopeSpec(
        include=include or [],
        exclude=exclude or [],
        ports=ports or [],
        redirect_policy=redirect_policy,
    )


def _rule(type_: str, value: str):
    return ScopeRule(type=type_, value=value)


def test_dns_suffix_match():
    scope = _scope(include=[_rule("dns_suffix", "*.example.test")])
    assert check_target(scope, "app.example.test").allowed is True


def test_dns_suffix_no_match():
    scope = _scope(include=[_rule("dns_suffix", "*.example.test")])
    assert check_target(scope, "other.test").allowed is False


def test_exact_host_match():
    scope = _scope(include=[_rule("exact_host", "api.target.test")])
    assert check_target(scope, "api.target.test").allowed is True
    assert check_target(scope, "other.target.test").allowed is False


def test_cidr_match():
    scope = _scope(include=[_rule("cidr", "8.8.8.0/24")])
    assert check_target(scope, "8.8.8.4").allowed is True


def test_cidr_no_match():
    scope = _scope(include=[_rule("cidr", "8.8.8.0/24")])
    assert check_target(scope, "1.1.1.1").allowed is False


def test_url_prefix_match():
    scope = _scope(include=[_rule("url_prefix", "https://api.example.test/")])
    assert check_target(scope, "https://api.example.test/v1/users").allowed is True
    assert check_target(scope, "https://billing.example.test/").allowed is False


def test_deny_overrides_allow():
    scope = _scope(
        include=[_rule("dns_suffix", "*.example.test")],
        exclude=[_rule("url_prefix", "https://billing.example.test/")],
    )
    assert check_target(scope, "app.example.test").allowed is True
    assert check_target(scope, "https://billing.example.test/api").allowed is False


def test_port_pinning():
    scope = _scope(
        include=[_rule("exact_host", "target.test")],
        ports=[80, 443],
    )
    assert check_target(scope, "target.test", port=443).allowed is True
    assert check_target(scope, "target.test", port=8080).allowed is False


def test_metadata_address_blocked():
    scope = _scope(include=[_rule("cidr", "0.0.0.0/0")])
    assert check_target(scope, "169.254.169.254").allowed is False


def test_loopback_blocked():
    scope = _scope(include=[_rule("cidr", "0.0.0.0/0")])
    assert check_target(scope, "127.0.0.1").allowed is False


def test_link_local_blocked():
    assert _is_dangerous_address("fe80::1") is True


def test_private_addresses_blocked():
    scope = _scope(include=[_rule("cidr", "0.0.0.0/0")])
    for addr in ["10.0.0.1", "192.168.1.1", "172.16.0.1"]:
        assert check_target(scope, addr).allowed is False, f"{addr} should be blocked"


def test_ipv4_mapped_ipv6():
    assert _is_dangerous_address("::ffff:127.0.0.1") is True


def test_redirect_out_of_scope_denied():
    scope = _scope(include=[_rule("exact_host", "target.test")])
    result = check_target(scope, "evil.test", is_redirect=True)
    assert result.allowed is False


def test_empty_scope_denies_all():
    scope = _scope(include=[])
    assert check_target(scope, "anything.test").allowed is False


def test_normalize_host():
    assert normalize_host("Example.TEST.") == "example.test"
    assert normalize_host("  APP.test  ") == "app.test"
