"""Cloud posture INGESTION endpoint (CHAD final #1/#2/#4/#6): GET is preview-only, POST ingests with
dedup keyed by (provider,account_id), multiple accounts are isolated + preserved, and results are
honest (attempted/stored/deduped/failed/context_persisted)."""
from __future__ import annotations

import os
import tempfile

import cloud_iam
import db as dbmod
import main as mainmod
from fastapi.testclient import TestClient


def _res(account_id, findings, partial=False):
    return {"provider": "linode", "blocked": False, "partial": partial, "account_id": account_id,
            "account_label": account_id, "reason": "", "counts": {}, "manifest": {"complete": not partial},
            "model": {"roles": [], "resources": []}, "findings": [dict(f) for f in findings]}


_F = [{"title": "SSH open to internet", "target": "fw-web", "severity": "high",
       "family": "cloud_misconfig", "tags": ["cloud", "cloud_firewall_open_to_internet"]}]


def test_multi_account_ingest_dedup_isolation_and_honest_results(monkeypatch):
    dbmod.DB_PATH = os.path.join(tempfile.mkdtemp(), "t.db")
    with TestClient(mainmod.app) as c:
        dbmod.create_mission("cloudm", "P", "active", "o", {"in_scope": ["x"]}, {})
        # account A
        monkeypatch.setattr(cloud_iam, "collect", lambda p: _res("acctA-euuid", _F))
        r1 = c.post("/cloud/posture/linode/ingest?session_id=cloudm&account=labelA").json()
        assert r1["ingested"] is True and r1["account_id"] == "acctA-euuid"
        assert r1["results"]["findings_stored"] == 1 and r1["results"]["findings_failed"] == 0
        assert r1["results"]["context_persisted"] is True
        # re-ingest A -> deduped, not re-stored
        r2 = c.post("/cloud/posture/linode/ingest?session_id=cloudm&account=labelA").json()
        assert r2["results"]["findings_stored"] == 0 and r2["results"]["findings_deduped"] == 1
        # account B with the SAME finding -> NOT suppressed by A (CHAD #1)
        monkeypatch.setattr(cloud_iam, "collect", lambda p: _res("acctB-euuid", _F))
        r3 = c.post("/cloud/posture/linode/ingest?session_id=cloudm&account=labelB").json()
        assert r3["results"]["findings_stored"] == 1 and r3["account_id"] == "acctB-euuid"
        # both accounts preserved in context (CHAD #2)
        postures = dbmod.get_mission("cloudm")["context"]["cloud_postures"]
        assert "linode:acctA-euuid" in postures and "linode:acctB-euuid" in postures
        # canonical graph rebuilds cloud nodes for BOTH accounts even when archived (CHAD #2/#5)
        g = c.get("/graph/canonical/cloudm").json()
        assert isinstance(g.get("cloud_postures"), list) and len(g["cloud_postures"]) >= 2


def test_blocked_collection_is_not_ingested(monkeypatch):
    dbmod.DB_PATH = os.path.join(tempfile.mkdtemp(), "t.db")
    with TestClient(mainmod.app) as c:
        dbmod.create_mission("cloudm3", "P", "active", "o", {"in_scope": ["x"]}, {})
        monkeypatch.setattr(cloud_iam, "collect",
                            lambda p: {"provider": "linode", "blocked": True, "partial": True,
                                       "reason": "bad token", "findings": [], "manifest": {}})
        r = c.post("/cloud/posture/linode/ingest?session_id=cloudm3&account=x").json()
        assert r["ingested"] is False
        assert dbmod.get_mission("cloudm3")["context"].get("cloud_postures") in (None, {})


def test_get_preview_does_not_change_state(monkeypatch):
    dbmod.DB_PATH = os.path.join(tempfile.mkdtemp(), "t.db")
    with TestClient(mainmod.app) as c:
        dbmod.create_mission("cloudm4", "P", "active", "o", {"in_scope": ["x"]}, {})
        monkeypatch.setattr(cloud_iam, "collect", lambda p: _res("acctX", _F))
        c.get("/cloud/posture/linode")
        assert not dbmod.get_mission("cloudm4")["context"].get("cloud_postures")
        assert len(dbmod.get_findings("cloudm4")) == 0


def test_unverified_identity_is_refused_then_namespaced(monkeypatch):
    # CHAD final #2: a collection with NO real account id must not be ingested under the operator label
    # as if it were a real identity — refused unless allow_unverified, then keyed 'unverified:'.
    dbmod.DB_PATH = os.path.join(tempfile.mkdtemp(), "t.db")
    with TestClient(mainmod.app) as c:
        dbmod.create_mission("cloudm5", "P", "active", "o", {"in_scope": ["x"]}, {})
        monkeypatch.setattr(cloud_iam, "collect", lambda p: _res("", _F))   # empty account_id
        r = c.post("/cloud/posture/linode/ingest?session_id=cloudm5&account=lab").json()
        assert r["ingested"] is False and r["identity_verified"] is False
        # explicit opt-in -> ingested under an UNVERIFIED-namespaced key
        r2 = c.post("/cloud/posture/linode/ingest?session_id=cloudm5&account=lab&allow_unverified=true").json()
        assert r2["ingested"] is True and r2["account_id"] == "unverified:lab"
        assert "linode:unverified:lab" in dbmod.get_mission("cloudm5")["context"]["cloud_postures"]


def test_ingestion_is_transactional_context_first(monkeypatch):
    # CHAD final #4: if context persistence fails, NO findings are written (no orphaned findings).
    dbmod.DB_PATH = os.path.join(tempfile.mkdtemp(), "t.db")
    with TestClient(mainmod.app) as c:
        dbmod.create_mission("cloudm6", "P", "active", "o", {"in_scope": ["x"]}, {})
        monkeypatch.setattr(cloud_iam, "collect", lambda p: _res("acctZ", _F))

        def _boom(*a, **k):
            raise RuntimeError("db down")
        monkeypatch.setattr(dbmod, "update_mission", _boom)   # context persistence fails
        r = c.post("/cloud/posture/linode/ingest?session_id=cloudm6&account=z").json()
        assert r["ingested"] is False and r["results"]["context_persisted"] is False
        assert r["results"]["findings_stored"] == 0
        assert len(dbmod.get_findings("cloudm6")) == 0        # NO orphaned findings
