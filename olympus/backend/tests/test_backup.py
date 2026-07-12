"""Unit tests for progress-backup validation (core/backup.py).

Pure, no DB / no network — same style as the rest of tests/. Run from backend:
  python -m pytest tests/ -q
"""
import pytest

from core.backup import validate_backup, BackupError
from core.security import is_valid_target


def _backup(**over):
    """A minimal valid v1 backup, overridable per test."""
    data = {
        "version": "1",
        "platform": "OLYMPUS",
        "exported_at": "2026-07-12T10:00:00",
        "mission": {
            "target": "example.com",
            "scope": "example.com",
            "mode": "active",
            "status": "complete",
            "context": {"hermes": {"live_hosts": []}},
            "scope_rules": {"in_scope": [], "out_of_scope": []},
        },
        "findings": [
            {"title": "SQL Injection", "severity": "critical", "cvss_score": "9.8",
             "tag": "confirmed", "is_manual": True, "timestamp": "2026-07-12T09:00:00"},
        ],
        "notes": [{"content": "check the login form", "timestamp": "2026-07-12T09:30:00"}],
        "logs": [{"agent": "ares", "level": "info", "message": "scan complete",
                  "timestamp": "2026-07-12T09:45:00"}],
        "status": "complete",
        "current_phase": None,
    }
    data.update(over)
    return data


def test_valid_backup_normalizes():
    norm = validate_backup(_backup(), is_valid_target)
    assert norm["target"] == "example.com"
    assert norm["mode"] == "active"
    assert norm["status"] == "complete"
    assert len(norm["findings"]) == 1
    f = norm["findings"][0]
    assert f["severity"] == "critical"
    assert f["cvss_score"] == 9.8          # string coerced to float
    assert f["is_manual"] is True
    assert len(norm["notes"]) == 1
    assert len(norm["logs"]) == 1


def test_missing_version_rejected():
    b = _backup()
    del b["version"]
    with pytest.raises(BackupError):
        validate_backup(b, is_valid_target)


def test_unsupported_version_rejected():
    with pytest.raises(BackupError):
        validate_backup(_backup(version="99"), is_valid_target)


def test_missing_mission_rejected():
    b = _backup()
    del b["mission"]
    with pytest.raises(BackupError):
        validate_backup(b, is_valid_target)


def test_invalid_target_rejected():
    # a target carrying a scheme/shell char must be refused by the injected guard
    with pytest.raises(BackupError):
        validate_backup(_backup(mission={"target": "http://evil.com; rm -rf /"}), is_valid_target)


def test_empty_target_rejected():
    with pytest.raises(BackupError):
        validate_backup(_backup(mission={"target": "   "}), is_valid_target)


def test_not_an_object_rejected():
    with pytest.raises(BackupError):
        validate_backup(["not", "a", "dict"], is_valid_target)


def test_findings_without_title_skipped():
    norm = validate_backup(_backup(findings=[
        {"title": "", "severity": "high"},          # dropped (no title)
        {"severity": "low"},                          # dropped (no title)
        {"title": "Real finding", "severity": "medium"},
    ]), is_valid_target)
    assert len(norm["findings"]) == 1
    assert norm["findings"][0]["title"] == "Real finding"


def test_top_level_findings_preferred_over_nested():
    b = _backup()
    b["mission"]["findings"] = [{"title": "nested only", "severity": "low"}]
    # top-level findings (from _backup) should win
    norm = validate_backup(b, is_valid_target)
    assert norm["findings"][0]["title"] == "SQL Injection"


def test_falls_back_to_nested_when_top_level_absent():
    b = _backup()
    del b["findings"]
    b["mission"]["findings"] = [{"title": "nested finding", "severity": "high"}]
    norm = validate_backup(b, is_valid_target)
    assert len(norm["findings"]) == 1
    assert norm["findings"][0]["title"] == "nested finding"


def test_malformed_findings_array_rejected():
    with pytest.raises(BackupError):
        validate_backup(_backup(findings={"not": "a list"}), is_valid_target)


def test_bad_cvss_and_timestamp_are_tolerated():
    norm = validate_backup(_backup(findings=[
        {"title": "x", "severity": "info", "cvss_score": "not-a-number", "timestamp": "garbage"},
    ]), is_valid_target)
    f = norm["findings"][0]
    assert f["cvss_score"] is None            # unparseable float -> None
    assert f["timestamp"] is not None          # unparseable date -> now() fallback
