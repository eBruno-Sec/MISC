"""Network service-pack execution driver (beyond web): it actually RUNS the pack + applies the oracle
and writes findings into the live graph — not just a plan/description (CHAD review #6)."""
from __future__ import annotations

import asyncio
import json

import scope
import tools


class _R:
    def __init__(self, status, text):
        self.status_code, self.text = status, text
        self.headers = type("H", (), {"items": lambda self: []})()


def _reg(host):
    sc = scope.ScopeEngine()
    sc.load_manual([host], [], "T")
    return tools.ToolRegistry(sc, lab_mode=True)


def _run(reg, inp):
    return asyncio.new_event_loop().run_until_complete(reg._run_service_pack(inp))


def test_exposed_docker_api_is_confirmed_and_graphed():
    reg = _reg("dockerbox")

    async def open_docker(method, url, headers, body, follow):
        return _R(200, '{"Version":"24.0.5","ApiVersion":"1.43"}'), 0.01

    reg._http_send = open_docker
    r = _run(reg, {"host": "dockerbox", "port": 2375, "service": "docker"})
    d = json.loads(r.output)
    assert d["ran"] and d["confirmed"] == 1
    assert r.findings[0]["severity"] == "critical" and "docker" in r.findings[0]["tags"]
    assert reg.graph.nodes("service") and reg.graph.nodes("finding")   # written to the LIVE graph


def test_authenticated_service_yields_no_finding():
    reg = _reg("box")

    async def denied(method, url, headers, body, follow):
        return _R(401, "unauthorized"), 0.01

    reg._http_send = denied
    r = _run(reg, {"host": "box", "port": 9200, "service": "elasticsearch"})
    assert json.loads(r.output)["confirmed"] == 0 and not r.findings


def test_unknown_service_has_no_pack():
    reg = _reg("box")
    r = _run(reg, {"host": "box", "port": 9999, "service": "unknown"})
    assert json.loads(r.output)["ran"] is False
