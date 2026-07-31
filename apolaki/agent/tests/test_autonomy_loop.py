"""Integration test for CHAD's deterministic autonomy loop closing at scan end: the scan records its
confirmed findings into per-target attack-chain memory, then emits a memory-aware next-best-action plan
(already-confirmed classes are demoted, not re-recommended). Duck-types the agent -- no network/model."""
from __future__ import annotations

import asyncio

import agent
import attack_chain


class _Intel:
    def to_dict(self, redact_secrets=True):
        return {"by_kind": {"object_id": [1, 2], "version": ["1.0"]}}


class _Tools:
    def __init__(self):
        self.intel = _Intel()
        self.urls = {"http://demo.loop/rest/user/login", "http://demo.loop/api/products?q=x"}
        self._sessions = {}


class _Agent:
    def __init__(self):
        self.findings = [{"family": "sql_injection", "title": "SQLi", "target": "http://demo.loop/",
                          "confidence": "confirmed"},
                         {"family": "access_control", "title": "IDOR", "target": "http://demo.loop/",
                          "confidence": "confirmed"}]
        self.leads = [{"family": "xss", "title": "reflected?", "target": "http://demo.loop/"}]
        self.tools = _Tools()

    def _primary_base(self):
        return "http://demo.loop/"


def test_autonomy_loop_records_evidence_and_demotes_confirmed(tmp_path, monkeypatch):
    monkeypatch.setenv("ATTACK_CHAIN_DIR", str(tmp_path))     # isolate the memory to a temp dir
    a = _Agent()

    async def run():
        return [e async for e in agent.BBHAgent._close_autonomy_loop(a, "sess-loop")]

    try:
        events = asyncio.run(run())
    finally:
        # asyncio.run() closes the loop it created; restore a current loop so later tests that use the
        # deprecated asyncio.get_event_loop() (e.g. test_bbh) still find one (test-isolation hygiene).
        asyncio.set_event_loop(asyncio.new_event_loop())

    # 1) Evidence -> State: the two confirmed findings + the attempted lead are now in per-target memory.
    outcomes = attack_chain.summary("http://demo.loop/")
    assert outcomes.get("sqli") == "confirmed" and outcomes.get("access_control") == "confirmed"
    assert outcomes.get("xss") == "attempted"

    # 2) an event announces the loop closed with the recorded count + next-best actions
    assert events and "Autonomy loop closed" in events[0]["content"]

    # 3) Next-Best-Action is memory-aware: already-confirmed classes are not the top recommendation
    nxt = [x.get("id") for x in getattr(a, "_next_best", [])]
    assert nxt, "expected a ranked next-best-action plan"
    assert nxt[0] not in ("sqli_auth_bypass", "sqli_union_extract"), "confirmed sqli should be demoted, not re-run first"
