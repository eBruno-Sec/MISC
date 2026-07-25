"""Target guard (ported olympus is_valid_target / expand_cidr)."""

from __future__ import annotations

from policy.target_guard import expand_cidr, is_valid_target, validate_targets


def test_valid_targets():
    assert is_valid_target("juice-shop:3000") is True
    assert is_valid_target("localhost") is True
    assert is_valid_target("example.com") is True
    assert is_valid_target("10.0.0.0/24") is True
    assert is_valid_target("192.168.1.10") is True
    assert is_valid_target("*.example.com") is True


def test_argument_injection_and_shell_chars_rejected():
    assert is_valid_target("-oProxyCommand=evil") is False  # leading dash
    assert is_valid_target("host; rm -rf /") is False  # shell metachar + space
    assert is_valid_target("a|b") is False
    assert is_valid_target("$(whoami)") is False


def test_port_range_enforced():
    assert is_valid_target("host:0") is False
    assert is_valid_target("host:70000") is False
    assert is_valid_target("host:8080") is True


def test_expand_cidr():
    assert expand_cidr("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]
    assert expand_cidr("10.0.0.5/32") == ["10.0.0.5"]
    assert expand_cidr("not-a-cidr") is None


def test_validate_targets_splits():
    valid, rejected = validate_targets(["good.com", "-bad", "  ", "10.0.0.1"])
    assert valid == ["good.com", "10.0.0.1"]
    assert rejected == ["-bad"]
