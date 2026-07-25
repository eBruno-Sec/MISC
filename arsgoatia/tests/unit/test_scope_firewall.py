"""Scope firewall core (ported apolaki ScopeEngine): deny-overrides-allow,
wildcard, port pin, and the arg-injection guard."""

from __future__ import annotations

from policy.scope_firewall import ScopeFirewall


def _fw(*targets: dict) -> ScopeFirewall:
    return ScopeFirewall.from_targets(list(targets))


def test_in_scope_and_out_of_scope():
    fw = _fw({"value": "juice-shop:3000", "disposition": "include"})
    assert fw.validate("http://juice-shop:3000/api/Users").allowed is True
    # A different host is not in scope (fail-closed).
    assert fw.validate("http://example.com/").allowed is False


def test_ssrf_metadata_endpoint_denied():
    fw = _fw({"value": "juice-shop:3000", "disposition": "include"})
    # The cloud metadata service is not in scope -> denied.
    assert fw.validate("http://169.254.169.254/latest/meta-data/").allowed is False


def test_deny_overrides_allow():
    fw = _fw(
        {"value": "example.com", "disposition": "include"},
        {"value": "admin.example.com", "disposition": "exclude"},
    )
    assert fw.validate("https://admin.example.com/").allowed is False
    assert fw.validate("https://app.example.com/").allowed is True


def test_port_pin_enforced_for_requests_not_bare_hosts():
    fw = _fw({"value": "juice-shop:3000", "disposition": "include"})
    assert fw.validate("http://juice-shop:3000/x").allowed is True
    # Same host, wrong pinned port -> denied for a concrete request.
    assert fw.validate("http://juice-shop:8080/x").allowed is False
    # Bare host recon is not port-pinned.
    assert fw.validate("juice-shop").allowed is True


def test_argument_injection_denied():
    # The guard fences the destination host/authority (an httpx executor never
    # shells out, so a URL path is data). A host that is itself an injected
    # argument or contains shell metacharacters is rejected.
    fw = _fw({"value": "juice-shop:3000", "disposition": "include"})
    assert fw.validate("http://-oProxyCommand=evil/").allowed is False
    assert fw.validate("juice-shop; rm -rf /").allowed is False
