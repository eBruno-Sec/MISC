"""Central finding write-gate + DB tenant isolation — the fix-pass safety/truth invariants (#6/#7/#8/#10).

Pure gate helpers PLUS the db.add_finding chokepoint that enforces them, so a lead can't be stored as a
confirmed finding, an off-scope WEB finding can't be written, non-web (cloud/network) findings are never
falsely dropped, and a finding id from one mission can't mutate/delete another mission's row.
"""
import os
import tempfile

import db as dbmod
import findings_gate as fg


# ── pure gate helpers ────────────────────────────────────────────
def test_normalize_reproduction_steps_to_list():
    # a numbered string becomes discrete list steps (#6 — SARIF/report/retest index it as a list)
    f = fg.normalize({"title": "x", "reproduction_steps": "1) do a 2) do b"})
    assert isinstance(f["reproduction_steps"], list) and len(f["reproduction_steps"]) == 2
    # an existing list is preserved (whitespace-trimmed)
    assert fg.normalize({"reproduction_steps": ["a", " b "]})["reproduction_steps"] == ["a", "b"]
    # missing -> []
    assert fg.normalize({"title": "x"})["reproduction_steps"] == []
    # defaults filled without clobbering
    assert fg.normalize({})["confidence"] == "confirmed" and fg.normalize({})["severity"] == "info"
    assert fg.normalize({"confidence": "lead"})["confidence"] == "lead"


def test_is_lead():
    for c in ("lead", "needs-confirmation", "unconfirmed", "tentative", "possible"):
        assert fg.is_lead({"confidence": c}) is True
    for c in ("confirmed", "", None, "high"):
        assert fg.is_lead({"confidence": c}) is False
    assert fg.is_lead({}) is False                       # missing confidence == confirmed default


def test_off_scope_only_blocks_proven_offscope_web_targets():
    scope = {"in_scope": ["app"], "bases": ["http://app:3000"], "out_of_scope": []}
    # off-scope http host -> blocked
    assert fg.off_scope({"target": "http://evil.com/x"}, scope) is True
    # in-scope http host -> admitted
    assert fg.off_scope({"target": "http://app:3000/rest/x"}, scope) is False
    # NON-http target (cloud posture label, network host) -> never judged by the web scope
    assert fg.off_scope({"target": "fw-web"}, scope) is False
    assert fg.off_scope({"target": "10.0.0.5:445"}, scope) is False
    # no scope configured -> nothing to enforce
    assert fg.off_scope({"target": "http://evil.com"}, {"in_scope": []}) is False
    # no target -> admit (fail-open)
    assert fg.off_scope({"title": "no target"}, scope) is False


# ── db chokepoint integration ────────────────────────────────────
def _fresh_db():
    dbmod.DB_PATH = os.path.join(tempfile.mkdtemp(), "t.db")
    dbmod._conn = None
    dbmod.init(dbmod.DB_PATH)


def test_lead_confidence_finding_is_routed_to_leads_not_confirmed():
    _fresh_db()
    dbmod.create_mission("m", "P", "active", "o", {"in_scope": ["app"]}, {})
    lid = dbmod.add_finding("m", {"title": "maybe", "confidence": "lead", "target": "http://app/x"})
    assert lid                                            # returns an id
    assert dbmod.get_findings("m") == []                 # NOT in the confirmed table (#7)
    leads = (dbmod.get_mission("m").get("context") or {}).get("leads") or []
    assert len(leads) == 1 and leads[0]["title"] == "maybe"   # routed to leads


def test_offscope_web_finding_is_not_persisted():
    _fresh_db()
    dbmod.create_mission("m", "P", "active", "o",
                         {"in_scope": ["app"], "bases": ["http://app:3000"]}, {})
    fid = dbmod.add_finding("m", {"title": "off", "confidence": "confirmed",
                                  "target": "http://evil.com/p"})
    assert fid == ""                                     # rejected (#8)
    assert dbmod.get_findings("m") == []


def test_inscope_and_cloud_findings_persist_normally():
    _fresh_db()
    dbmod.create_mission("m", "P", "active", "o",
                         {"in_scope": ["app"], "bases": ["http://app:3000"]}, {})
    a = dbmod.add_finding("m", {"title": "web", "confidence": "confirmed", "target": "http://app:3000/x"})
    b = dbmod.add_finding("m", {"title": "cloud", "confidence": "confirmed", "target": "fw-web",
                                "family": "cloud_misconfig"})
    assert a and b and len(dbmod.get_findings("m")) == 2
    # #6: reproduction_steps normalized to a list on the way in
    assert all(isinstance(f["reproduction_steps"], list) for f in dbmod.get_findings("m"))


def test_cross_mission_update_delete_isolation():
    _fresh_db()
    dbmod.create_mission("m1", "P", "active", "o", {"in_scope": ["app"]}, {})
    dbmod.create_mission("m2", "P", "active", "o", {"in_scope": ["app"]}, {})
    fid = dbmod.add_finding("m1", {"title": "f1", "confidence": "confirmed"})
    # m2 cannot update or delete m1's finding by its id (#10)
    assert dbmod.update_finding("m2", fid, {"title": "hacked"}).verdict == dbmod.UPDATE_MISSING
    assert dbmod.delete_finding("m2", fid) is False
    assert dbmod.get_findings("m1")[0]["title"] == "f1"          # untouched
    # the owning mission CAN
    assert dbmod.update_finding("m1", fid, {"title": "f1b", "confidence": "confirmed"}).verdict == dbmod.UPDATED
    assert dbmod.get_finding("m1", fid)["title"] == "f1b"
    assert dbmod.delete_finding("m1", fid) is True
    assert dbmod.get_findings("m1") == []
