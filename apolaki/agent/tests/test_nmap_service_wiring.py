"""Port scan -> service classification -> service-pack EXECUTION wiring (CHAD next-order #1)."""
from __future__ import annotations

import asyncio

import agent as A
import scope
import service_router as SR
import tools


def test_parse_nmap_ports():
    lines = ["6379/tcp open redis 7.0.0", "80/tcp open http nginx",
             "22/tcp open ssh OpenSSH_8.9", "not a port line"]
    svcs = SR.parse_nmap_ports(lines, "box")
    by = {s["service"]: s for s in svcs}
    assert by["redis"]["port"] == 6379 and by["redis"]["host"] == "box"
    assert "ssh" in by and "http" in by
    assert len(svcs) == 3                                  # the junk line is skipped


def test_agent_runs_packs_for_nonweb_only():
    sc = scope.ScopeEngine()
    sc.load_manual(["box"], [], "T")
    t = tools.ToolRegistry(sc, mission_id=None, lab_mode=True)
    t.recon["target"] = "box"
    t.recon["nmap"]["open_ports"] = ["6379/tcp open redis", "80/tcp open http", "9999/tcp open weird"]
    a = A.BBHAgent(sc, t, asyncio.Event(), mode="active", mission_id=None)
    calls = []

    async def stub_execute(tool, inp, sid):
        calls.append(inp.get("service"))

        class _TR:
            def __init__(self):
                self.output, self.success = "{}", True
                self.findings = ([{"title": "redis exposed", "target": "box:6379", "family": "access_control"}]
                                 if inp.get("service") == "redis" else [])
        return _TR()
    t.execute = stub_execute

    evs = asyncio.new_event_loop().run_until_complete(a._run_service_packs("s"))
    assert "redis" in calls                               # non-web service pack RAN
    assert "http" not in calls                            # web deferred to the web engine
    assert "unknown" not in calls                         # unknown skipped
    assert any(e.get("type") == "finding" for e in evs)   # its finding was recorded
