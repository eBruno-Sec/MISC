"""Staged intel promotion (#114): ingest lands as candidate; promotion is one gated step at a time with
evidence; internet intel NEVER auto-promotes to production (needs a human reviewer). Anti-contamination."""
import intel_registry as R
import intel_sources as S


def _rec():
    return S.provenance_record("nvd", cve="CVE-2024-9999")


def test_ingest_is_always_candidate():
    R.reset()
    assert R.ingest([_rec()]) == 1
    assert R.ingest([_rec()]) == 0                      # dedup
    assert R.stats()["by_state"] == {"candidate": 1}
    rid = R.by_state("candidate")[0]["_id"]
    # even a record CLAIMING production is stored as candidate
    R.reset()
    r = _rec(); r["validation_state"] = "production"
    R.ingest([r])
    assert R.by_state("production") == [] and len(R.by_state("candidate")) == 1


def test_promotion_is_one_gated_step_with_evidence():
    R.reset(); R.ingest([_rec()])
    rid = R.by_state("candidate")[0]["_id"]
    assert R.advance(rid, "production")[0] is False     # no queue-jump
    assert R.advance(rid, "validating")[0] is True
    assert R.advance(rid, "validated")[0] is False      # validated needs evidence
    assert R.advance(rid, "validated", evidence="oracle differential passed")[0] is True
    assert R.advance(rid, "fixture_backed", evidence="fixture.json")[0] is True
    assert R.advance(rid, "reviewed")[0] is True


def test_production_requires_a_human_reviewer():
    R.reset(); R.ingest([_rec()])
    rid = R.by_state("candidate")[0]["_id"]
    for st, ev in [("validating", None), ("validated", "v"), ("fixture_backed", "f"), ("reviewed", None)]:
        assert R.advance(rid, st, evidence=ev)[0] is True
    assert R.advance(rid, "production")[0] is False              # no reviewer -> refused
    ok, _ = R.advance(rid, "production", reviewed_by="erwin")
    assert ok and R.production()[0]["reviewed_by"] == "erwin"
    assert R.production()[0]["confidence"] >= 0.9


def test_reject_is_always_allowed():
    R.reset(); R.ingest([_rec()])
    rid = R.by_state("candidate")[0]["_id"]
    assert R.advance(rid, "rejected")[0] is True


def test_closed_loop_fetch_normalizes_into_candidate_registry():
    # fetch (enabled, injected http) -> normalize -> registry ingest as CANDIDATES (the full pipeline)
    import intel_connectors as C
    C.reset(); R.reset()
    def http(url, headers=None):
        return 200, '{"data":[{"cve":"CVE-2024-7","epss":"0.9","percentile":"0.9","date":"2024-01-01"}]}'
    res = C.fetch("epss", env={"INTEL_SRC_EPSS": "1"}, http=http, now=1.0)
    assert R.ingest(res["records"]) == 1
    assert R.stats()["by_state"] == {"candidate": 1}     # lands untrusted, as candidate only
    assert R.production() == []
