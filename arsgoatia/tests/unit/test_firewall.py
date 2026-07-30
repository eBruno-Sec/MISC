from __future__ import annotations

from packages.contracts.schemas.engagement import ScopeRule, ScopeSpec
from packages.scope.firewall import ScopeFirewall


def _scope(include=None, exclude=None, ports=None):
    return ScopeSpec(
        include=include or [],
        exclude=exclude or [],
        ports=ports or [],
    )


def _rule(type_: str, value: str):
    return ScopeRule(type=type_, value=value)


def test_preflight_allows_valid_target():
    fw = ScopeFirewall(_scope(include=[_rule("exact_host", "api.target.test")]))
    result = fw.preflight("api.target.test", resolved_addresses=["8.8.8.8"])
    assert result.allowed


def test_preflight_blocks_dangerous_resolved_address():
    fw = ScopeFirewall(_scope(include=[_rule("exact_host", "api.target.test")]))
    result = fw.preflight("api.target.test", resolved_addresses=["127.0.0.1"])
    assert not result.allowed
    assert result.failed_check == "address_classification"


def test_preflight_blocks_metadata_address():
    fw = ScopeFirewall(_scope(include=[_rule("exact_host", "api.target.test")]))
    result = fw.preflight("api.target.test", resolved_addresses=["169.254.169.254"])
    assert not result.allowed


def test_preflight_port_pinning():
    fw = ScopeFirewall(
        _scope(
            include=[_rule("exact_host", "api.target.test")],
            ports=[443],
        )
    )
    assert fw.preflight("api.target.test", ["8.8.8.8"], port=443).allowed
    assert not fw.preflight("api.target.test", ["8.8.8.8"], port=8080).allowed


def test_redirect_in_scope():
    fw = ScopeFirewall(_scope(include=[_rule("dns_suffix", "*.target.test")]))
    result = fw.check_redirect("https://app.target.test", "https://api.target.test/v2")
    assert result.allowed


def test_redirect_out_of_scope():
    fw = ScopeFirewall(_scope(include=[_rule("exact_host", "app.target.test")]))
    result = fw.check_redirect("https://app.target.test", "https://evil.test")
    assert not result.allowed
    assert result.failed_check == "redirect_scope"


def test_dns_answers_safe():
    fw = ScopeFirewall(_scope(include=[_rule("exact_host", "target.test")]))
    result = fw.check_dns_answers("target.test", ["8.8.8.8", "8.8.4.4"])
    assert result.allowed


def test_dns_answers_dangerous():
    fw = ScopeFirewall(_scope(include=[_rule("exact_host", "target.test")]))
    result = fw.check_dns_answers("target.test", ["8.8.8.8", "10.0.0.1"])
    assert not result.allowed
    assert result.failed_check == "dns_answer_classification"


def test_preflight_tracks_checks():
    fw = ScopeFirewall(_scope(include=[_rule("exact_host", "api.target.test")]))
    result = fw.preflight("api.target.test", ["8.8.8.8"])
    assert "scope" in result.checks_passed
    assert "address_classification" in result.checks_passed
    assert "port_pin" in result.checks_passed
