"""Resolved-address SSRF checks (§13.4)."""

from __future__ import annotations

from policy.scope_firewall import classify_ip, is_ssrf_blocked


def test_classify_ip():
    assert classify_ip("169.254.169.254") == "link_local"  # cloud metadata
    assert classify_ip("127.0.0.1") == "loopback"
    assert classify_ip("10.1.2.3") == "private"
    assert classify_ip("172.18.0.2") == "private"  # docker bridge
    assert classify_ip("8.8.8.8") == "public"
    assert classify_ip("not-an-ip") == "invalid"


def test_metadata_and_loopback_always_blocked_even_in_lab():
    # Even with allow_private (lab), link-local + loopback are never reachable.
    assert is_ssrf_blocked("169.254.169.254", allow_private=True) is True
    assert is_ssrf_blocked("127.0.0.1", allow_private=True) is True


def test_private_allowed_only_in_lab():
    # A dockerized juice-shop resolves to a private bridge IP: allowed in lab,
    # blocked otherwise.
    assert is_ssrf_blocked("172.18.0.2", allow_private=True) is False
    assert is_ssrf_blocked("172.18.0.2", allow_private=False) is True


def test_public_always_allowed():
    assert is_ssrf_blocked("8.8.8.8", allow_private=False) is False
