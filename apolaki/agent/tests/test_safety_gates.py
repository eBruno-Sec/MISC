"""Fix-pass safety gates (#1 passive-mode no-live-contact, #2 internal HITL/passive dispatch).

Proves an internal (non-model) caller can no longer bypass the passive-mode + intrusive-HITL gates: the
auth artery + service sweep now route through BBHAgent._exec_internal, and the two unconditional recon
entries (served-JS harvest, service-pack socket sweep) skip themselves in passive mode.
"""
import asyncio

import agent as agent_mod
import scope as scope_mod
from tools import ToolResult


class _RecordingTools:
    """Minimal stub: records every execute() call and returns a benign ToolResult (no network)."""
    def __init__(self):
        self.calls = []
        self.recon = {"target": "app", "nmap": {"open_ports": []}}
        self.urls = []
        self.session_headers = {}

    async def execute(self, name, inp, sid):
        self.calls.append(name)
        return ToolResult(name, "", True, "{}", [])


def _agent(mode, **kw):
    eng = scope_mod.ScopeEngine()
    eng.load_manual(["app"], [], "P")
    return agent_mod.BBHAgent(eng, _RecordingTools(), asyncio.Event(), mode=mode,
                              strategy="deterministic", mission_id=None, **kw)


def _run(coro):
    return asyncio.run(coro)          # fresh loop each call (a prior TestClient test can close the default loop)


# ── #2: central internal dispatch enforces passive + HITL ────────
def test_exec_internal_blocks_active_tool_in_passive_mode():
    a = _agent("passive")
    res = _run(a._exec_internal("run_authz_matrix", {}, "s"))
    assert a.tools.calls == []                                  # never dispatched
    assert '"ran": false' in res.output and "passive" in res.output


def test_exec_internal_blocks_intrusive_without_approval():
    a = _agent("active")                                        # active mode, intrusive NOT approved
    assert a.intrusive_state is None and a.auto_approve is False
    res = _run(a._exec_internal("confirm_create_object_idor", {}, "s"))
    assert a.tools.calls == []                                  # HITL gate held it
    assert "intrusive" in res.output.lower()


def test_exec_internal_allows_intrusive_when_autoapproved():
    a = _agent("active", auto_approve=True)                     # autonomous pre-authorization
    res = _run(a._exec_internal("confirm_create_object_idor", {}, "s"))
    assert a.tools.calls == ["confirm_create_object_idor"]      # fired
    assert a.intrusive_state == "approved"


def test_exec_internal_allows_active_tool_in_active_mode():
    a = _agent("active")
    _run(a._exec_internal("confirm_read_object_idor", {}, "s"))     # ACTIVE, no HITL
    _run(a._exec_internal("run_service_pack", {}, "s"))            # ACTIVE, no HITL
    assert a.tools.calls == ["confirm_read_object_idor", "run_service_pack"]


def test_exec_internal_allows_passive_tool_in_passive_mode():
    a = _agent("passive")
    _run(a._exec_internal("store_finding", {}, "s"))              # PASSIVE — allowed even in passive mode
    assert a.tools.calls == ["store_finding"]


# ── #1: passive mode makes NO live target contact from the two recon entries ──
def test_recon_code_intelligence_is_silent_in_passive_mode():
    a = _agent("passive")
    evs = _run(_drain(a._recon_code_intelligence("s")))
    assert evs == [] and a.tools.calls == []                     # no served-JS harvest, no contact


def test_service_pack_sweep_is_silent_in_passive_mode():
    a = _agent("passive")
    evs = _run(a._run_service_packs("s"))                         # returns a list (not a generator)
    assert evs == [] and a.tools.calls == []                     # no socket scan, no packs


async def _drain(agen):
    return [ev async for ev in agen]
