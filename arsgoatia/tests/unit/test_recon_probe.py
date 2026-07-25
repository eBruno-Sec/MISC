"""Safe-recon planning: base URL derivation + scope-fenced probe list."""

from __future__ import annotations

from policy.scope_firewall import ScopeFirewall
from temporal.workflows.activities.recon_probe import (
    derive_base_url,
    endpoint_from_url,
    plan_probes,
)


def test_derive_base_url_defaults_to_http_for_bare_hostport():
    targets = [{"value": "juice-shop:3000", "disposition": "include"}]
    assert derive_base_url(targets) == "http://juice-shop:3000"


def test_derive_base_url_prefers_included_target():
    targets = [
        {"value": "excluded.example.com", "disposition": "exclude"},
        {"value": "https://app.example.com", "disposition": "include"},
    ]
    assert derive_base_url(targets) == "https://app.example.com"


def test_plan_probes_only_returns_in_scope_urls():
    fw = ScopeFirewall.from_targets([{"value": "juice-shop:3000", "disposition": "include"}])
    urls = plan_probes("http://juice-shop:3000", ["/", "/api/Users"], fw)
    assert urls == ["http://juice-shop:3000/", "http://juice-shop:3000/api/Users"]

    # Out-of-scope base yields nothing (fail-closed).
    empty = plan_probes("http://evil.example.com", ["/"], fw)
    assert empty == []


def test_endpoint_from_url():
    assert endpoint_from_url("http://juice-shop:3000/rest/basket/1") == (
        "juice-shop:3000",
        "/rest/basket/1",
    )
