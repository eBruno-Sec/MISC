"""Q-014 — an operator's decision about a lead must survive, or be refused where they can see it.

Two pre-fix defects, both measured:

  (a) A gate-routed lead could not be addressed AT ALL. `db.add_lead` (the TRUTH invariant's re-route,
      findings_gate #7) stamps `lead["id"]`; `confirm_lead`/`dismiss_lead` looked leads up by `_lid`,
      which only `main._record_execution` ever wrote. Every lead the gate itself created 404'd. And
      `_record_execution` then CLOBBERED those leads at teardown (`ctx["leads"] = <agent leads only>`),
      so they were gone from the report as well.

  (b) An operator confirmation was silently re-demoted. `confirm_lead` stored `confidence:"confirmed"`;
      every presentation surface reads `db.get_findings_gated` -> `proof_schema.demote_unproven`, which
      re-ran `validate_confirmed` and wrote `confidence:"lead"` back. The endpoint returned
      `{"ok": true}` and the report showed a lead.

THE DESIGN, which these tests pin. Operator confirmation is an ATTESTATION on its own axis — who,
when, why — never a value of `confidence`. `confidence` stays the ORACLE's verdict. A lead is released
to `confirmed` if and only if the lead's OWN, engine-produced evidence already satisfies
`proof_schema.validate_confirmed`; operator-supplied prose is recorded as attestation text and is NEVER
fed into that check. That distinction is the whole point and
`test_operator_prose_cannot_manufacture_machine_proof` is its negative control: the same words that
make an ENGINE's evidence pass must NOT make an operator's typed rationale pass.

FAIL-BEFORE-FIX (measured on the pre-fix tree; none of these were import/attribute errors — the
endpoint, the models it uses and every helper already existed):
  * addressable      : POST /leads/{sid}/{gate-routed lid}/confirm -> 404 "lead not found"
  * teardown         : gate-routed lead absent from ctx["leads"] after _record_execution
  * round trip       : no `operator_attestation` anywhere; gated confidence == "lead", no signal
  * unsigned refused : an empty body returned 200 {"ok": true} and minted a finding
  * prose            : rationale stuffed with "owner ... denied ... impact" produced confidence
                       "confirmed" in raw storage
  * re-confirm       : PUT /findings with confidence "confirmed" landed on a gate-demoted row
"""
import os
import tempfile

import pytest

import db as dbmod
import proof_schema as ps

pytest.importorskip("fastapi")

SCOPE = {"in_scope": ["app"], "bases": ["http://app:3000"], "out_of_scope": []}

#: An engine-produced IDOR evidence string that `proof_schema.validate_confirmed` accepts. Used BOTH as
#: a lead's own evidence (must release) and as operator-typed prose (must NOT release) — same words,
#: different provenance, which is exactly the discrimination under test.
ENGINE_PROOF = ("GET /api/orders/2 as user A -> 200 with user B's owner record (identical body to B's "
                "own read); the same request anon -> 403 denied. Cross-user object read.")


def _client():
    from fastapi.testclient import TestClient
    import main as mainmod
    dbmod.DB_PATH = os.path.join(tempfile.mkdtemp(), "t.db")
    dbmod._conn = None
    return TestClient(mainmod.app)


def _mission(mid="m"):
    dbmod.create_mission(mid, "P", "active", "o", SCOPE, {})
    return mid


def _gate_routed_lead(mid, **over):
    """A lead created by the TRUTH invariant itself: a lead-confidence finding handed to db.add_finding,
    which reroutes it to the leads list. This is the shape the confirm endpoint could not see."""
    f = {"title": "possible IDOR on /api/orders/2", "confidence": "lead", "severity": "high",
         "target": "http://app:3000/api/orders/2", "family": "idor", "cwe": "CWE-639",
         "evidence": "id parameter looks object-scoped", "reproduction_steps": ["swap the id"]}
    f.update(over)
    return dbmod.add_finding(mid, f)


ATTEST = {"operator": "e.bruno", "rationale": "Replayed by hand in Burp; I take responsibility."}


# ── (a) a gate-routed lead is addressable ────────────────────────
def test_gate_routed_lead_is_addressable_by_the_confirm_endpoint():
    with _client() as c:
        mid = _mission()
        lid = _gate_routed_lead(mid)
        listed = c.get("/leads/%s" % mid).json()["leads"]
        assert len(listed) == 1
        # the endpoint resolves the lead by whichever key stamped it — no 404
        r = c.post("/leads/%s/%s/confirm" % (mid, lid), json=ATTEST)
        assert r.status_code == 200, r.text
        # and the UI's affordance key is present, so the confirm button renders at all
        assert listed[0].get("_lid"), "gate-routed lead has no _lid; ui/index.html hides its buttons"


def test_dismiss_also_resolves_a_gate_routed_lead():
    with _client() as c:
        mid = _mission()
        lid = _gate_routed_lead(mid)
        assert c.post("/leads/%s/%s/dismiss" % (mid, lid)).status_code == 200
        assert c.get("/leads/%s" % mid).json()["leads"] == []


def test_mission_teardown_does_not_clobber_gate_routed_leads():
    """_record_execution rebuilt ctx["leads"] from agent.leads alone, deleting every lead the gate
    wrote during the run."""
    import main as mainmod
    dbmod.DB_PATH = os.path.join(tempfile.mkdtemp(), "t.db")
    dbmod._conn = None
    dbmod.init(dbmod.DB_PATH)
    mid = _mission()
    _gate_routed_lead(mid)

    class _Agent:
        strategy, ai_calls, max_ai_calls, ai_note = "deterministic", 0, 0, ""
        leads = [{"title": "agent-side lead", "target": "http://app:3000/z", "severity": "low"}]

    mainmod.sessions[mid] = {"agent": _Agent()}
    try:
        mainmod._record_execution(mid)
    finally:
        mainmod.sessions.pop(mid, None)
    titles = {l["title"] for l in (dbmod.get_mission(mid).get("context") or {}).get("leads") or []}
    assert "possible IDOR on /api/orders/2" in titles      # the gate-routed one survived
    assert "agent-side lead" in titles                     # the agent-side one still lands


# ── (b) the attestation itself ───────────────────────────────────
def test_operator_attestation_is_refused_without_an_attester_or_grounds():
    """Silent discard is the defect; an explicit refusal is acceptable. An unsigned attestation is
    refused with the reason in the response body, and NOTHING is written."""
    with _client() as c:
        mid = _mission()
        lid = _gate_routed_lead(mid)
        for body in ({}, {"operator": "e.bruno"}, {"rationale": "trust me"},
                     {"operator": "   ", "rationale": "  "}):
            r = c.post("/leads/%s/%s/confirm" % (mid, lid), json=body)
            assert r.status_code == 400, (body, r.text)
            detail = r.json()["detail"].lower()
            assert "operator" in detail or "rationale" in detail
            assert "nothing was changed" in detail
        assert dbmod.get_findings(mid) == []                       # no finding minted
        lead = c.get("/leads/%s" % mid).json()["leads"][0]
        assert "operator_attestation" not in lead                  # no attestation recorded


def test_operator_attestation_survives_the_round_trip():
    """The operator's decision is durable and readable: who, why, when, and the machine-proof verdict."""
    with _client() as c:
        mid = _mission()
        lid = _gate_routed_lead(mid)
        r = c.post("/leads/%s/%s/confirm" % (mid, lid), json=ATTEST).json()
        assert r["ok"] is True and r["promoted"] is False          # attested, not released
        assert r["provenance"] == "operator-attested" and r["machine_proof"] is False
        assert r["proof_gap"]                                      # the operator is TOLD what is missing
        assert "attest" in r["note"].lower()
        # re-read through the API — the attestation is still there
        lead = c.get("/leads/%s" % mid).json()["leads"][0]
        att = lead["operator_attestation"]
        assert att["operator"] == "e.bruno" and att["rationale"].startswith("Replayed")
        assert att["attested_at"] and att["machine_proof"] is False and att["proof_gap"]


def test_operator_prose_cannot_manufacture_machine_proof():
    """THE discriminator. `validate_confirmed` is a substring contract over evidence prose. If operator
    text were fed into it, an operator could type the signal words and mint `confirmed` with no proof at
    all — a guard checking a declaration instead of a fact. The SAME words that release an ENGINE's
    evidence (next test) must not release a typed rationale.

    The lead deliberately carries a legitimate engine-supplied `impact` and WEAK evidence, so the ONLY
    thing standing between it and `confirmed` is the evidence signal groups. A first version of this
    test omitted `impact`; the missing-impact gap alone then blocked promotion, so the test passed even
    with the operator's prose spliced into the evidence field — it asserted the outcome without
    discriminating the cause. Measured: mutant M4 SURVIVED against that version and is KILLED by this
    one."""
    with _client() as c:
        mid = _mission()
        lid = _gate_routed_lead(mid, impact="Any user can read any other user's order.")
        r = c.post("/leads/%s/%s/confirm" % (mid, lid), json={
            "operator": "e.bruno", "rationale": ENGINE_PROOF, "notes": ENGINE_PROOF}).json()
        assert r["proof_gap"] == ["evidence_signal:owner", "evidence_signal:denied"], (
            "the ONLY gap must be the evidence signals, or this test does not discriminate: %s"
            % r["proof_gap"])
        assert r["promoted"] is False and r["machine_proof"] is False
        assert dbmod.get_findings(mid) == []               # nothing entered the confirmed table
        lead = c.get("/leads/%s" % mid).json()["leads"][0]
        # the prose is recorded as an attestation, and is NOT laundered into the evidence field the
        # oracle reads — otherwise the next demote_unproven pass would accept it.
        assert ENGINE_PROOF in lead["operator_attestation"]["rationale"]
        assert ENGINE_PROOF not in str(lead.get("evidence") or "")
        assert not ps.is_confirmed(lead)


def test_lead_whose_own_engine_evidence_proves_it_is_released_to_confirmed():
    """The gate must be SATISFIABLE, or people route around it (which is how PUT /findings got used).
    When the lead's OWN evidence already passes the oracle, the operator's act is a release, not a
    claim — and it survives get_findings_gated, which is where the old path lost it."""
    with _client() as c:
        mid = _mission()
        lid = _gate_routed_lead(mid, evidence=ENGINE_PROOF,
                                impact="Any user can read any other user's order.")
        r = c.post("/leads/%s/%s/confirm" % (mid, lid), json=ATTEST).json()
        assert r["promoted"] is True and r["machine_proof"] is True
        assert r["provenance"] == "operator-released" and r["finding_id"]
        gated = dbmod.get_findings_gated(mid)
        assert len(gated) == 1 and ps.is_confirmed(gated[0])       # SURVIVES the proof gate
        att = gated[0]["operator_attestation"]
        assert att["operator"] == "e.bruno" and att["machine_proof"] is True
        assert c.get("/leads/%s" % mid).json()["leads"] == []      # consumed


def test_attestation_citing_an_unrecorded_exchange_is_refused():
    """An attestation may cite exchange ids Apolaki itself recorded, which makes it checkable. An id
    this mission never recorded is refused rather than stored as an unverifiable citation."""
    with _client() as c:
        mid = _mission()
        lid = _gate_routed_lead(mid)
        eid = dbmod.add_exchange(mid, {"request": "GET /api/orders/2", "status": 200})
        r = c.post("/leads/%s/%s/confirm" % (mid, lid),
                   json=dict(ATTEST, exchange_ids=[eid, "nope-not-real"]))
        assert r.status_code == 400 and "nope-not-real" in r.json()["detail"]
        ok = c.post("/leads/%s/%s/confirm" % (mid, lid), json=dict(ATTEST, exchange_ids=[eid])).json()
        lead = c.get("/leads/%s" % mid).json()["leads"][0]
        assert ok["ok"] is True and lead["operator_attestation"]["exchange_ids"] == [eid]


# ── the demoted-lead ratchet: writing it back must not re-confirm it ──
def test_a_gate_demoted_lead_cannot_be_reconfirmed_by_writing_it_back():
    """Q-013 and Q-014 meet here. A row the proof gate demoted must not return to `confirmed` through
    EITHER path: not by PUT-ing it back, and not by an operator asserting it."""
    with _client() as c:
        mid = _mission()
        # a confirmed-but-unproven access-control finding: stored raw, demoted by the proof gate
        fid = dbmod.add_finding(mid, {"title": "IDOR", "confidence": "confirmed", "family": "idor",
                                      "cwe": "CWE-639", "target": "http://app:3000/api/orders/2",
                                      "evidence": "the id parameter is sequential, looks guessable",
                                      "reproduction_steps": ["GET /api/orders/2"]})
        assert not ps.is_confirmed(dbmod.get_findings_gated(mid)[0])        # demoted by the gate

        # (1) write it back through PUT /findings with an even louder confirmation
        c.put("/findings/%s/%s" % (mid, fid), json={
            "title": "IDOR", "confidence": "confirmed", "confirmed": True, "family": "idor",
            "cwe": "CWE-639", "target": "http://app:3000/api/orders/2",
            "evidence": "the id parameter is sequential, looks guessable",
            "reproduction_steps": ["GET /api/orders/2"]})
        assert not ps.is_confirmed(dbmod.get_findings_gated(mid)[0])        # still demoted

        # (2) and an operator cannot assert it into place either
        dbmod.add_lead(mid, {"title": "IDOR lead", "confidence": "lead", "family": "idor",
                             "cwe": "CWE-639", "target": "http://app:3000/api/orders/2",
                             "evidence": "the id parameter is sequential, looks guessable"})
        lead = c.get("/leads/%s" % mid).json()["leads"][0]
        r = c.post("/leads/%s/%s/confirm" % (mid, lead["_lid"]), json=ATTEST).json()
        assert r["promoted"] is False and r["machine_proof"] is False
        assert all(not ps.is_confirmed(f) for f in dbmod.get_findings_gated(mid))
