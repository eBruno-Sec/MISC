"""Tests for the headless-browser (CDP) runtime collector — graceful degrade + pure parsing."""
from __future__ import annotations

import cdp


def test_collect_degrades_cleanly_without_browser(monkeypatch):
    monkeypatch.delenv("CDP_BROWSER_URL", raising=False)
    r = cdp.collect("http://x.io")
    assert r["configured"] is False
    assert r["service_workers"] == [] and r["runtime_endpoints"] == []
    assert "note" in r and "headless browser" in r["note"]     # honest label, nothing faked


def test_parse_result_normalises_shape():
    data = {"serviceWorkers": ["/sw.js"],
            "runtimeEndpoints": ["/api/x", "/api/x", "/graphql"],
            "lazyScripts": ["/chunk.a.js", "/chunk.a.js"],
            "storageKeys": {"local": ["auth_token"], "session": []},
            "globalHints": ["__APP_CONFIG"]}
    r = cdp.parse_result("http://x.io", data)
    assert r["configured"] is True
    assert r["runtime_endpoints"] == ["/api/x", "/graphql"]      # deduped + sorted
    assert r["lazy_scripts"] == ["/chunk.a.js"]
    assert r["storage_keys"]["local"] == ["auth_token"]
    assert r["global_hints"] == ["__APP_CONFIG"]
    assert r["counts"]["service_workers"] == 1 and r["counts"]["runtime_endpoints"] == 2


def test_collect_unreachable_browser_is_labelled():
    r = cdp.collect("http://x.io", browser_url="http://127.0.0.1:1")
    assert r["configured"] is False and "unreachable" in r["note"]
