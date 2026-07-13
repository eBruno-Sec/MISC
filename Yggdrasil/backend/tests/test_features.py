import asyncio
from types import SimpleNamespace

import pytest

from agents.base import BaseAgent
from core.backup import (
    BackupValidationError,
    build_backup_payload,
    validate_backup,
    validate_backup_payload,
)
from core.brand import agent_display_name, agent_symbol
from core.security import is_valid_target
from core.config import settings
from core import wordlists as wl
from routers.missions import severity_counts_shape
from routers.wordlists import list_wordlists, preview_wordlist


class FakeSession:
    def __init__(self, mission_context=None):
        self.mission = SimpleNamespace(context=mission_context or {})
        self.added = []
        self.commits = 0

    async def get(self, _model, _id):
        return self.mission

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        for obj in self.added:
            if obj.__class__.__name__ == "ApprovalRequest" and not obj.id:
                obj.id = "approval-1"

    async def commit(self):
        self.commits += 1


class FakeManager:
    def __init__(self):
        self.events = []

    async def broadcast(self, _mission_id, event):
        self.events.append(event)


class TestAgent(BaseAgent):
    name = "ares"
    symbol = "TY"
    display_name = "TYR"
    role = "Active Assessment"

    async def execute(self, target: str, context: dict = None) -> dict:
        return {}


def test_auto_approve_records_gate_and_audit_log_without_blocking():
    async def run():
        session = FakeSession({"auto_approve": True})
        manager = FakeManager()
        agent = TestAgent(session, "mission-1", ws_manager=manager)

        approved = await asyncio.wait_for(agent.request_approval("Active check", "details"), timeout=1)

        approvals = [obj for obj in session.added if obj.__class__.__name__ == "ApprovalRequest"]
        logs = [obj for obj in session.added if obj.__class__.__name__ == "AgentLog"]
        assert approved is True
        assert approvals and approvals[0].status == "approved"
        assert logs and "Auto-authorized" in logs[0].message
        assert not agent.approval_gates
        event_types = [e["type"] for e in manager.events]
        assert "log" in event_types
        assert any(e["type"] == "approval_resolved" and e["approval_id"] == "approval-1" for e in manager.events)

    asyncio.run(run())


def test_wordlist_catalog_preview_and_selected_generated_flow(tmp_path, monkeypatch):
    async def run():
        monkeypatch.setattr(settings, "wordlists_dir", str(tmp_path))
        generated = wl.write_list("custom", ["admin", "login", "debug"])

        catalog = await list_wordlists()
        assert any(entry["id"] == generated["id"] for entry in catalog["wordlists"])

        preview = await preview_wordlist(generated["id"], lines=2)
        assert preview == "admin\nlogin"

        paths = wl.content_wordlists_for("mission-1", {"domain": "example.com"}, [generated["id"]])
        assert paths == [generated["path"]]

    asyncio.run(run())


def test_v2_backup_hash_accepts_clean_payload_and_rejects_tamper():
    payload = build_backup_payload(
        workspace_id="mission-1",
        mission={"target": "example.com", "mode": "passive", "context": {"api_key": "secret"}},
        findings=[{"title": "Finding", "severity": "high"}],
        notes=[{"content": "note"}],
        logs=[{"agent": "ares", "level": "info", "message": "ok"}],
        exchanges=[{"method": "GET", "url": "https://example.com", "request_headers": {"Cookie": "sid=1"}}],
    )

    state = validate_backup_payload(payload)
    assert state["mission"]["context"]["api_key"] == "<redacted>"
    norm = validate_backup(payload, is_valid_target)
    assert norm["target"] == "example.com"
    assert len(norm["exchanges"]) == 1
    assert norm["exchanges"][0]["request_headers"]["Cookie"] == "<redacted>"

    payload["state"]["mission"]["target"] = "evil.test"
    with pytest.raises(BackupValidationError):
        validate_backup_payload(payload)


def test_severity_counts_shape_is_complete_and_numeric():
    counts = severity_counts_shape({"critical": 1, "low": "2"})
    assert counts == {"critical": 1, "high": 0, "medium": 0, "low": 2, "info": 0}


def test_backend_stage_branding_uses_yggdrasil_labels():
    assert agent_display_name("zeus") == "ODIN"
    assert agent_symbol("ares") == "TY"
    assert agent_display_name("apollo") == "SAGA"
