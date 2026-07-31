"""Tests for the browser engine -- pure observation mapping + graceful degrade (no browser needed)."""
from __future__ import annotations

import browser_engine as BE


def test_degrades_without_browser(monkeypatch):
    monkeypatch.delenv("CDP_BROWSER_URL", raising=False)
    r = BE.observe("http://x.io")
    assert r["browser"] is False and "no headless browser" in r["note"]
    assert BE.drive("http://x.io", "js")["browser"] is False        # never raises, always labelled


def test_to_observations_maps_browser_sensor_to_planner():
    obs = {"browser": True, "scripts": ["a.js"], "runtime_api": ["http://x/api/products"],
           "inputs": [{"name": "password", "type": "password", "placeholder": ""},
                      {"name": "q", "type": "text", "placeholder": "search"}],
           "forms": [{"action": "/login", "method": "post", "inputs": ["email", "password"]}],
           "links": ["/redirect?to=x"], "graphql": ["http://x/graphql"], "runtime_ws": []}
    o = BE.to_observations(obs)
    assert {"serves_js", "has_api", "has_login", "has_search_param", "has_redirect_param"} <= o


def test_to_observations_empty_when_degraded():
    assert BE.to_observations({"browser": False}) == set()
    assert BE.to_observations(None) == set()
