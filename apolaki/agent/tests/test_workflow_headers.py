"""Workflow response-header extraction: a `header` extract rule must read the real
response headers (was wired with an empty map, so it could never fire). Pure -- no network."""
from __future__ import annotations

import asyncio
import json

import workflow


class _State:
    def __init__(self):
        self.variables = {}
        self._caps = set()

    def has(self, c):
        return c in self._caps

    def set_var(self, k, v):
        self.variables[k] = v

    def add_capability(self, c, src):
        self._caps.add(c)


class _Res:
    def __init__(self, output, success=True, error=None):
        self.output, self.success, self.error = output, success, error


class _Reg:
    """Minimal ToolRegistry stand-in: one transport method returning a shaped output."""
    def __init__(self, output):
        self.state = _State()
        self.intel = None
        self._output = output

    async def _http_read(self, inp):
        return _Res(self._output)


def _run(reg, wf):
    return asyncio.new_event_loop().run_until_complete(workflow.run(reg, wf))


def test_header_extract_reads_real_response_header():
    out = json.dumps({"status": 302, "headers": {"Location": "/dashboard?id=42"}, "body": "{}"})
    reg = _Reg(out)
    wf = {"id": "t", "steps": [
        {"do": "http_read", "url": "https://x/login",
         "extract": {"loc": {"header": "Location"}}},
    ]}
    res = _run(reg, wf)
    assert res["ran"] is True
    assert res["variables"].get("loc") == "/dashboard?id=42", res["variables"]


def test_json_body_extract_still_works():
    out = json.dumps({"status": 200, "headers": {}, "body": json.dumps({"id": 7})})
    reg = _Reg(out)
    wf = {"id": "t", "steps": [
        {"do": "http_read", "url": "https://x/api", "extract": {"oid": "$.id"}},
    ]}
    res = _run(reg, wf)
    assert res["variables"].get("oid") == 7, res["variables"]


def test_missing_header_leaves_var_unset():
    out = json.dumps({"status": 200, "headers": {"Content-Type": "text/html"}, "body": "{}"})
    reg = _Reg(out)
    wf = {"id": "t", "steps": [
        {"do": "http_read", "url": "https://x/", "extract": {"loc": {"header": "Location"}}},
    ]}
    res = _run(reg, wf)
    assert "loc" not in res["variables"]
