"""Archive/GitHub provenance flow: recovered intel enters the graph flagged UNVALIDATED, gets a
validation queue, and only after a current check is it treated as present (CHAD review #9)."""
from __future__ import annotations

import archive_intel as AI
import asset_graph as AG


def test_archived_endpoints_flagged_unvalidated():
    g = AG.AssetGraph("m")
    n = AI.ingest_archived_endpoints(g, "t.example", [
        "https://t.example/old/admin", "https://t.example/legacy/api/v1", "https://t.example/"])
    assert n == 2                                              # the bare "/" is skipped
    ep = g.nodes("endpoint")[0]
    assert ep["props"]["archived"] is True and ep["tested"] is False
    assert ep["confidence"] == AG.LOW                          # archived != present -> low confidence


def test_repo_secret_stores_ref_not_raw():
    g = AG.AssetGraph("m")
    AI.ingest_repo_findings(g, "acme/app", [
        {"kind": "secret", "value": "AKIA...", "ref": "vault://mission/m/repo1"},
        {"kind": "route", "value": "/internal/debug"},
        {"kind": "cloud_name", "value": "acme-prod-bucket"}])
    cred = g.nodes("credential")[0]
    assert cred["props"]["identity_ref"] == "vault://mission/m/repo1"
    assert "AKIA" not in str(g.to_dict())                      # raw secret never stored
    assert g.nodes("endpoint") and g.nodes("cloud_account")


def test_validation_queue_and_mark():
    g = AG.AssetGraph("m")
    AI.ingest_archived_endpoints(g, "t", ["https://t/old/panel"])
    q = AI.needs_validation(g)
    assert len(q) == 1 and q[0]["provenance"] == "archive"
    # validate: it's gone on the current target -> retired, drops off the queue
    AI.mark_validated(g, q[0]["id"], present=False)
    assert AI.needs_validation(g) == []
    assert g.node(q[0]["id"])["props"]["current_state"] == "gone"


def test_present_validation_raises_confidence():
    g = AG.AssetGraph("m")
    AI.ingest_archived_endpoints(g, "t", ["https://t/still/here"])
    nid = AI.needs_validation(g)[0]["id"]
    AI.mark_validated(g, nid, present=True)
    assert g.node(nid)["confidence"] >= AG.MEDIUM and g.node(nid)["tested"] is True
