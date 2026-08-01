"""Path-aware scope (SEC-2): a path-restricted in-scope asset (https://host/api/*) must
NOT silently widen to the whole host. Covers the ScopeEngine tool-level gate (validate)
AND the web_security.is_url_in_scope surface matcher fed by to_rules(). Pure -- no network."""
from __future__ import annotations

import scope as S
import web_security as W


def _eng(entries):
    e = S.ScopeEngine()
    e.load_manual(entries, [], "T")
    return e


def test_path_scoped_entry_blocks_offpath_request():
    e = _eng(["https://example.com/api"])
    ok, _ = e.validate("https://example.com/api/users/1")
    assert ok, "on-path request must be in scope"
    ok2, why = e.validate("https://example.com/admin")
    assert not ok2, "off-path request must be blocked when a path is pinned"
    assert "path" in why.lower()


def test_path_scope_normalizes_traversal():
    e = _eng(["https://example.com/api"])
    # /api/../admin escapes the pinned prefix even though it textually starts with /api
    ok, _ = e.validate("https://example.com/api/../admin")
    assert not ok


def test_bare_host_recon_not_blocked_by_path():
    # a bare hostname (subdomain/DNS recon, is_request=False) must stay allowed so a
    # path pin never breaks host-level recon.
    e = _eng(["https://example.com/api"])
    ok, _ = e.validate("example.com")
    assert ok


def test_second_host_entry_unions_the_path():
    # if the operator also lists the whole host, everything on it is in scope again.
    e = _eng(["https://example.com/api", "example.com"])
    ok, _ = e.validate("https://example.com/anything")
    assert ok


def test_host_only_entry_is_unchanged():
    # regression: no path pinned -> every path on the host is in scope (labs rely on this).
    e = _eng(["http://juice-shop:3000"])
    ok, _ = e.validate("http://juice-shop:3000/rest/products/1")
    assert ok


def test_to_rules_emits_url_identifier_and_surface_matcher_agrees():
    e = _eng(["https://example.com/api"])
    rules = e.to_rules()
    ident = rules["in_scope"][0]["identifier"]
    assert ident == "https://example.com/api", ident
    base = "https://example.com"
    assert W.is_url_in_scope("https://example.com/api/orders", base, rules)
    assert not W.is_url_in_scope("https://example.com/admin", base, rules)


def test_wildcard_host_never_carries_a_path():
    e = _eng(["*.example.com"])
    assert e.in_scope[0].path == ""
    ok, _ = e.validate("https://api.example.com/whatever")
    assert ok
