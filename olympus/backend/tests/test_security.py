"""Unit tests for CIDR expansion + target validation (core/security.py)."""
from core.security import expand_cidr, is_valid_target


def test_expand_cidr_24_excludes_net_and_broadcast():
    ips = expand_cidr("10.0.0.0/24")
    assert ips is not None and len(ips) == 254
    assert "10.0.0.1" in ips and "10.0.0.254" in ips
    assert "10.0.0.0" not in ips and "10.0.0.255" not in ips


def test_expand_cidr_respects_cap():
    ips = expand_cidr("10.0.0.0/16", cap=50)
    assert ips is not None and len(ips) == 50


def test_expand_cidr_32_is_single_host():
    assert expand_cidr("192.168.1.5/32") == ["192.168.1.5"]


def test_expand_cidr_31_both_usable():
    assert expand_cidr("192.168.1.0/31") == ["192.168.1.0", "192.168.1.1"]


def test_expand_cidr_strips_scheme():
    assert expand_cidr("https://10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]


def test_expand_cidr_non_cidr_is_none():
    assert expand_cidr("example.com") is None
    assert expand_cidr("10.0.0.5") is None                 # single IP, no mask
    assert expand_cidr("http://example.com/path") is None  # URL path, not a CIDR
    assert expand_cidr("juice-shop:3000") is None
    assert expand_cidr("") is None


def test_is_valid_target_accepts_cidr():
    assert is_valid_target("10.0.0.0/24") is True
    assert is_valid_target("192.168.1.5") is True
