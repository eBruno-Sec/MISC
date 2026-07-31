"""Tests for the intercept-proxy integration -- pure: flow parsing/HAR, rule validate/match/serialize,
replay spec, launch args, and graceful degrade when no proxy sidecar is present. No mitmproxy needed."""
from __future__ import annotations

import json
import os

import proxy


def _write_flows(d, records):
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, proxy.FLOWS_FILE), "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def test_flowstore_load_and_summarize(tmp_path):
    _write_flows(str(tmp_path), [
        {"host": "juice-shop", "method": "GET", "url": "http://juice-shop/a", "status": 200,
         "req_headers": {"Authorization": "Bearer x"}, "resp_headers": {"Server": "nginx"},
         "resp_ct": "text/html", "resp_len": 12, "ts": 1_700_000_000.0, "matched_rule": "r1"},
        {"host": "juice-shop", "method": "POST", "url": "http://juice-shop/b", "status": 404,
         "req_headers": {}, "resp_headers": {}, "resp_ct": "", "resp_len": 0, "ts": 1_700_000_001.0},
    ])
    d = proxy.FlowStore.load(str(tmp_path)).to_dict()
    assert d["count"] == 2
    assert d["by_status"] == {"2xx": 1, "4xx": 1}
    assert d["by_host"]["juice-shop"] == 2
    assert d["rule_hits"] == {"r1": 1}


def test_flowstore_har_shape(tmp_path):
    _write_flows(str(tmp_path), [{"host": "h", "method": "GET", "url": "http://h/x", "status": 200,
                                  "req_headers": {"X": "y"}, "resp_headers": {"Server": "s"},
                                  "resp_ct": "application/json", "resp_len": 5, "ts": 1_700_000_000.0}])
    har = proxy.FlowStore.load(str(tmp_path)).har()
    assert har["log"]["version"] == "1.2" and har["log"]["creator"]["name"] == "apolaki-proxy"
    e = har["log"]["entries"][0]
    assert e["request"]["url"] == "http://h/x" and e["response"]["status"] == 200


def test_flowstore_missing_file_is_empty():
    s = proxy.FlowStore.load("/nonexistent/proxy/dir")
    assert s.flows == [] and s.to_dict()["count"] == 0


def test_ruleset_validate_normalizes_and_requires_a_match():
    good = proxy.RuleSet([{"match": {"host": "juice-shop", "method": "get"},
                           "set_request_headers": {"X-Bypass": "1"},
                           "replace_response_body": [{"find": "admin", "replace": "pwned"}]}])
    norm = good.validate()
    assert norm[0]["id"] == "rule_0" and norm[0]["match"]["host"] == "juice-shop"
    assert norm[0]["set_request_headers"]["X-Bypass"] == "1"

    for bad in ([{"match": {}}], [{"match": {"path_contains": 5}}], ["notadict"]):
        try:
            proxy.RuleSet(bad).validate()
            assert False, "expected ValueError for %r" % bad
        except ValueError:
            pass


def test_ruleset_save_and_reload_roundtrip(tmp_path):
    proxy.RuleSet([{"match": {"path_contains": "/api/"}, "set_response_status": 200}]).save(str(tmp_path))
    reloaded = proxy.RuleSet.load(str(tmp_path))
    assert reloaded.rules[0]["set_response_status"] == 200
    assert os.path.exists(os.path.join(str(tmp_path), proxy.RULES_FILE))


def test_rule_matches_logic():
    r = {"match": {"host": "juice-shop", "path_contains": "/rest/", "method": "POST"}}
    assert proxy.RuleSet.matches(r, "POST", "juice-shop:3000", "/rest/user/login")
    assert not proxy.RuleSet.matches(r, "GET", "juice-shop:3000", "/rest/user/login")   # method differs
    assert not proxy.RuleSet.matches(r, "POST", "juice-shop:3000", "/api/Products")     # path differs
    assert not proxy.RuleSet.matches({"match": {}}, "GET", "h", "/")                     # empty never matches


def test_replay_builds_spec_without_sending():
    flow = {"method": "GET", "url": "http://h/x", "req_headers": {"User-Agent": "ua", "Cookie": "<redacted>"}}
    r = proxy.replay(flow, mutations={"method": "post", "headers": {"X-Test": "1"}}, send=False)
    assert r["sent"] is False
    assert r["request"]["method"] == "POST" and r["request"]["url"] == "http://h/x"
    assert r["request"]["headers"]["X-Test"] == "1"
    assert "Cookie" not in r["request"]["headers"]      # redaction placeholder is dropped, never resent


def test_replay_no_url_is_labelled():
    assert proxy.replay({}, send=True)["sent"] is False


def test_status_degrades_without_proxy(monkeypatch):
    monkeypatch.delenv("PROXY_URL", raising=False)
    monkeypatch.setenv("PROXY_FLOWS_DIR", "/nonexistent/proxy/dir")
    s = proxy.status()
    assert s["configured"] is False and s["active"] is False and "no intercept proxy" in s["note"]


def test_to_observations_maps_proxy_traffic_to_planner_vocab(tmp_path):
    _write_flows(str(tmp_path), [
        {"host": "h", "method": "POST", "url": "http://h/rest/user/login", "path": "/rest/user/login",
         "status": 200, "resp_ct": "application/json"},
        {"host": "h", "method": "GET", "url": "http://h/main.js", "path": "/main.js", "status": 200,
         "resp_ct": "application/javascript"},
        {"host": "h", "method": "GET", "url": "http://h/api/products?q=x", "path": "/api/products",
         "status": 200, "resp_ct": "application/json"},
    ])
    obs = proxy.to_observations(proxy.FlowStore.load(str(tmp_path)))
    assert {"serves_js", "has_api", "has_login", "has_search_param"} <= obs   # proxy feeds the planner vocab


def test_to_observations_empty_when_no_flows():
    assert proxy.to_observations(proxy.FlowStore([])) == set()


def test_browser_launch_args_toggle(monkeypatch):
    monkeypatch.delenv("PROXY_URL", raising=False)
    assert proxy.browser_launch_args() == []
    monkeypatch.setenv("PROXY_URL", "http://mitmproxy:8080")
    args = proxy.browser_launch_args()
    assert any("--proxy-server=http://mitmproxy:8080" in a for a in args)
    assert any("ignore-certificate-errors" in a for a in args)
