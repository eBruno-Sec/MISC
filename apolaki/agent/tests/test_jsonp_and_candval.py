"""The JSONP validator confirms ONLY an executable wrapper carrying a data payload that is usable
cross-origin (a plain JSON echo, or a nosniff'd non-JS body, is NOT a JSONP leak). The
candidate-validation ledger reaches the report JSON + HTML so no testable lead is left invisible."""
from __future__ import annotations

import asyncio
import json

import httpx
import report
import scope as scope_mod
from tools import ToolRegistry


class _Resp:
    def __init__(self, text, headers):
        self.text = text
        self.headers = headers


class _Client:
    def __init__(self, mode):
        self.mode = mode

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url):
        import urllib.parse as up
        q = up.parse_qs(up.urlparse(url).query)
        cb = (q.get("callback") or q.get("jsonp") or q.get("cb") or q.get("jsoncallback") or ["x"])[0]
        if self.mode == "jsonp":                      # executable wrapper + data + js content-type
            return _Resp(cb + '({"user":"admin","email":"a@b"})', {"content-type": "application/javascript"})
        if self.mode == "json":                       # plain JSON, nosniff -> NOT usable cross-origin
            return _Resp('{"user":"admin"}', {"content-type": "application/json", "x-content-type-options": "nosniff"})
        return _Resp("<html>nope</html>", {"content-type": "text/html"})


def _reg():
    eng = scope_mod.ScopeEngine(); eng.load_manual(["t.local"], [], "P")
    return ToolRegistry(eng, mission_id=None)


def test_jsonp_confirms_only_executable_wrapper_with_data(monkeypatch):
    reg = _reg()
    monkeypatch.setattr(httpx, "AsyncClient", lambda **k: _Client("jsonp"))
    r = asyncio.run(reg._run_jsonp({"url": "https://t.local/api/me"}))
    assert r.success and r.findings and "JSONP" in r.findings[0]["title"]
    assert r.findings[0]["confidence"] == "confirmed"
    # a plain JSON body with nosniff is NOT a JSONP info leak (no false positive)
    monkeypatch.setattr(httpx, "AsyncClient", lambda **k: _Client("json"))
    r2 = asyncio.run(reg._run_jsonp({"url": "https://t.local/api/me"}))
    assert r2.success and not r2.findings
    # off-scope url is blocked, not tested
    r3 = asyncio.run(reg._run_jsonp({"url": "https://evil.example/api"}))
    assert not r3.success and "SCOPE BLOCK" in (r3.error or "")


def test_candidate_validation_surfaces_in_report_json_and_html():
    cv = {"counts": {"confirmed": 1, "dismissed": 2, "blocked": 1},
          "records": [
              {"candidate": "AngularJS ng-app (CSTI)", "family": "csti", "validator": "run_dom_audit",
               "attempted": True, "oracle": "angular arithmetic proof", "result": "dismissed",
               "evidence": "canary never fired across application pages", "missing_prerequisite": None},
              {"candidate": "BFLA Privileged Action", "family": "bfla", "validator": "run_bfla",
               "attempted": False, "oracle": "prohibited action", "result": "blocked",
               "evidence": "needs a low-priv session", "missing_prerequisite": "authenticated low-privilege session"}]}
    pkg = json.loads(report.findings_json("P", [], {"in_scope": ["x"]}, candidate_validation=cv))
    assert pkg["candidate_validation"]["counts"]["confirmed"] == 1
    assert pkg["candidate_validation"]["records"][0]["family"] == "csti"
    html = report.generate_html_report("P", [], {"in_scope": ["x"]}, candidate_validation=cv)
    assert "Candidate Validation" in html and "csti" in html and "blocked" in html.lower()
