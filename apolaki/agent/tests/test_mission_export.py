"""Portable mission export: bundle shape, secret redaction, validate/summary round-trip. Pure."""
from __future__ import annotations

import mission_export as ME


def _bundle():
    return ME.build_bundle(
        mission={"id": "m1", "name": "Juice Shop", "mode": "active", "status": "complete",
                 "created_at": 123, "scope": {"in_scope": ["juice-shop"]}, "secret_note": "IGNORED"},
        findings=[{"title": "IDOR", "cwe": "CWE-639", "confidence": "confirmed",
                   "evidence": "ok", "password": "LEAK_ME"}],
        snapshot={"counts": {"endpoints": 12, "findings": 1}},
        graph={"stats": {"nodes": 3}, "nodes": [{"id": "host:h", "kind": "host"}], "edges": []},
        capabilities=["foreign_object_read"])


def test_bundle_shape_and_versioned():
    b = _bundle()
    assert b["apolaki_bundle_version"] == ME.BUNDLE_VERSION
    assert b["mission"]["name"] == "Juice Shop"
    assert "secret_note" not in b["mission"]              # only whitelisted mission keys travel
    assert b["surface"]["endpoints"] == 12
    assert b["graph"]["stats"]["nodes"] == 3
    assert b["capabilities"] == ["foreign_object_read"]


def test_secrets_scrubbed_from_bundle():
    b = _bundle()
    assert b["findings"][0]["password"] == "<redacted>"   # secret-bearing key scrubbed
    assert "LEAK_ME" not in str(b)


def test_validate_and_summary():
    b = _bundle()
    ok, reason = ME.validate(b)
    assert ok and reason == "ok"
    s = ME.summary(b)
    assert s["valid"] and s["findings"] == 1 and s["graph_nodes"] == 1
    # a malformed bundle is rejected
    bad_ok, _ = ME.validate({"findings": []})
    assert not bad_ok
    assert ME.summary({"apolaki_bundle_version": "1", "mission": {}, "findings": [], "graph": {}})["valid"]
