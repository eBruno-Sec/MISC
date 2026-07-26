"""Wiring test: ToolRegistry auto-harvests every fetched response into its intel store and
exposes it (redacted) via the PASSIVE mission_intel tool."""
from __future__ import annotations

import asyncio
import json

import scope as scope_mod
import tools
from tools import ToolRegistry


class _Resp:
    """Minimal httpx-Response-like stub for _harvest_response (has .text and .headers)."""
    def __init__(self, text, headers):
        self.text = text
        self.headers = headers


def _registry():
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["host.local"], [], "P")
    return ToolRegistry(eng, mission_id=None)


def test_registry_has_empty_intel_store_on_init():
    t = _registry()
    assert t.intel is not None and t.intel.count() == 0


def test_harvest_response_fills_store_routes_json_and_redacts_secret():
    t = _registry()
    t._harvest_response(
        "http://host.local/api/x",
        _Resp('{"email":"admin@host.local","id":7,"token":"eyJabc.def.ghi"}',
              {"content-type": "application/json"}))
    d = t.intel.to_dict(redact_secrets=True)
    assert "admin@host.local" in d["candidates"].get("email", [])
    assert "7" in d["candidates"].get("object_id", [])
    secrets = d["candidates"].get("secret", [])
    assert secrets and all(s.startswith("<redacted:") for s in secrets)
    assert not any("eyJabc" in s for s in secrets)   # raw token never exposed


def test_harvest_response_routes_javascript_content_type():
    t = _registry()
    t._harvest_response("http://host.local/main.js",
                        _Resp("const r=[{path:'administration'}]; var v='1.2.3';",
                              {"content-type": "application/javascript"}))
    d = t.intel.to_dict()
    assert "/administration" in d["candidates"].get("route", [])
    assert "1.2.3" in d["candidates"].get("version", [])


def test_harvest_response_never_raises_on_bad_response():
    t = _registry()
    # a broken stub (no .text) must not blow up a request
    class Bad:
        headers = {"content-type": "text/html"}
        @property
        def text(self):
            raise RuntimeError("boom")
    t._harvest_response("http://host.local/x", Bad())   # should swallow
    assert t.intel.count() == 0


def test_mission_intel_tool_returns_redacted_store():
    t = _registry()
    t._harvest_response("http://host.local/main.js",
                        _Resp("path:'admin'", {"content-type": "application/javascript"}))
    res = asyncio.run(t._mission_intel({}))
    assert res.success
    payload = json.loads(res.output)
    assert "/admin" in payload["candidates"].get("route", [])


def test_harvest_body_handles_dict_headers_from_deterministic_http():
    # _http passes a plain dict for headers (not httpx.Headers) — must still route + harvest
    t = _registry()
    t._harvest_body("http://host.local/x.js",
                    {"content-type": "application/javascript"},
                    "const r=[{path:'admin'}]; var v='9.9.9';")
    d = t.intel.to_dict()
    assert "/admin" in d["candidates"].get("route", [])
    assert "9.9.9" in d["candidates"].get("version", [])


def test_mission_intel_registered_passive():
    assert tools.TOOL_PERMISSIONS.get("mission_intel") == tools.PermissionLevel.PASSIVE
