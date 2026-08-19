"""Q-021D — the promotion path: candidate -> validating -> validated, driven by product code.

Before this, `intel_registry.advance()` had callers in `tests/test_intel_registry.py` ONLY, so
`production()` was structurally always empty and a consumer wired to it would read `[]` forever
while its test stayed green. These tests hold the ladder to its contract from both sides: a record
WITH an independent witness must climb, and a record without one must not.

FIXTURES ARE COPIED FROM THE REAL SNAPSHOT, never invented. Every literal below was read out of
`/data/intel_feeds/kev.json` in the `apolaki_bbh_data` volume on 2026-08-18:

    kev.source='kev'  kev.tier='A'  kev.catalog_version='2026.07.29'  kev.count=1656
    kev.cves_meta['CVE-2024-38475'] = {"product": "Apache HTTP Server",
                                       "date_added": "2025-05-01", "ransomware": false}
    kev.cves_meta['CVE-2025-24813'] = {"product": "Apache Tomcat",
                                       "date_added": "2025-04-01", "ransomware": false}
    manifest.refreshed_at = 1785445474.3897574

`cves_meta` is the field the real parser writes; `cves` and `items` do NOT exist on this snapshot
(both read back empty) and reading either would have produced a silent "KEV has no CVEs".
"""
import intel_registry as R
import intel_sources as S

# ── the real snapshot, reduced to three entries. Shape and values are verbatim. ────────────────
KEV = {
    "kev": {"source": "kev", "tier": "A", "catalog_version": "2026.07.29", "count": 1656,
            "cwes": {"CWE-22": 1},
            "cves_meta": {
                "CVE-2024-38475": {"product": "Apache HTTP Server", "date_added": "2025-05-01",
                                   "ransomware": False},
                "CVE-2025-24813": {"product": "Apache Tomcat", "date_added": "2025-04-01",
                                   "ransomware": False},
                "CVE-2002-0367": {"product": "Microsoft Windows", "date_added": "2022-03-03",
                                  "ransomware": False},
            }},
    "manifest": {"refreshed_at": 1785445474.3897574,
                 "feeds": {"kev": {"ok": True, "count": 1656, "tier": "A", "version": "2026.07.29"}}},
}

WITNESSED = "CVE-2024-38475"        # really in KEV
UNWITNESSED = "CVE-2024-9999"       # really NOT in KEV (checked against all 1656 entries)


def _rec(cve, source="nvd"):
    """A real provenance record, built by the real constructor — not a hand-written dict."""
    return S.provenance_record(source, cve=cve)


# ── POSITIVE CONTROL ───────────────────────────────────────────────────────────────────────────
def test_a_witnessed_candidate_climbs_to_validated_with_evidence():
    R.reset()
    R.ingest([_rec(WITNESSED)])
    res = R.corroborate(KEV)
    assert res["status"] == "ok" and res["catalog"] == 3
    assert res["examined"] == 1 and res["validated"] == 1
    rec = R.by_state("validated")[0]
    assert rec["cve"] == WITNESSED
    # the ladder was climbed one rung at a time, through the real states, in order
    assert [h[0] for h in rec["_history"]] == ["candidate", "validating", "validated"]
    # the evidence names the source AND the snapshot stamp — oracle 1
    ev = " ".join(rec["_evidence"])
    assert "cisa_kev" in ev and "2026.07.29" in ev and "1785445474" in ev
    assert rec["witness"]["snapshot_at"] == 1785445474.3897574
    assert rec["witness"]["product"] == "Apache HTTP Server"     # the CATALOGUE's string, not ours
    assert rec["confidence"] == R._CONF["validated"]


# ── NEGATIVE CONTROL (b): a record that was never advanced is not visible to the consumer ──────
def test_an_unwitnessed_candidate_stops_at_validating_and_is_invisible_to_the_consumer():
    R.reset()
    R.ingest([_rec(UNWITNESSED)])
    res = R.corroborate(KEV)
    assert res["examined"] == 1 and res["validated"] == 0 and res["unwitnessed"] == 1
    assert R.by_state("validated") == []
    assert R.by_state("validating")[0]["cve"] == UNWITNESSED
    assert R.trusted("validated") == []                 # the consumer sees nothing
    assert R.production() == []


def test_the_pass_is_a_real_filter_not_a_conveyor():
    """Both records go through the same pass; only the witnessed one comes out validated. Run
    together, because a filter that passes everything and a filter that passes nothing each satisfy
    one of the two tests above on its own."""
    R.reset()
    R.ingest([_rec(WITNESSED), _rec(UNWITNESSED)])
    res = R.corroborate(KEV)
    assert res["examined"] == 2 and res["validated"] == 1 and res["unwitnessed"] == 1
    assert [r["cve"] for r in R.by_state("validated")] == [WITNESSED]
    assert [r["cve"] for r in R.by_state("validating")] == [UNWITNESSED]


# ── NEGATIVE CONTROL: a catalogue may not corroborate itself ───────────────────────────────────
def test_a_kev_sourced_record_is_never_witnessed_by_the_kev_snapshot():
    R.reset()
    R.ingest([_rec(WITNESSED, source="cisa_kev")])       # same CVE that validates when it is NVD's
    res = R.corroborate(KEV)
    assert res["same_source"] == 1 and res["validated"] == 0
    assert R.by_state("validated") == []


# ── NON-VACUITY: an empty catalogue is reported, never rendered as "nothing corroborated" ───────
def test_a_missing_snapshot_is_labelled_not_silently_read_as_clean():
    R.reset()
    R.ingest([_rec(WITNESSED)])
    res = R.corroborate({})
    assert res["status"] == "no_witness_snapshot"
    assert res["examined"] == 0 and res["catalog"] == 0
    assert R.by_state("candidate")[0]["cve"] == WITNESSED    # untouched, not parked at validating


def test_the_catalogue_is_non_empty_before_any_no_spam_claim_is_believed():
    """Guards every count above: assert the fixture really carries entries, or 'validated == 0'
    would pass over an empty catalogue for free."""
    assert len(KEV["kev"]["cves_meta"]) == 3
    assert WITNESSED in KEV["kev"]["cves_meta"]
    assert UNWITNESSED not in KEV["kev"]["cves_meta"]


# ── the ceiling: this pass may not reach the top of the ladder ─────────────────────────────────
def test_corroboration_can_never_reach_fixture_backed_reviewed_or_production():
    R.reset()
    R.ingest([_rec(WITNESSED)])
    for _ in range(5):                                   # re-run: idempotent, never climbs further
        R.corroborate(KEV)
    assert R.stats()["by_state"] == {"validated": 1}
    assert R.production() == [] and R.by_state("fixture_backed") == []


def test_rerunning_the_pass_validates_a_record_a_refreshed_catalogue_now_names():
    """A record parked at `validating` is re-examined, so a catalogue refresh can promote it."""
    R.reset()
    R.ingest([_rec("CVE-2025-24813")])
    empty = {"kev": {"catalog_version": "old", "cves_meta": {"CVE-0000-0000": {"product": "x"}}},
             "manifest": {"refreshed_at": 1.0}}
    R.corroborate(empty)
    assert R.by_state("validating") and R.by_state("validated") == []
    R.corroborate(KEV)                                   # refreshed catalogue now names it
    assert R.by_state("validated")[0]["cve"] == "CVE-2025-24813"
    assert R.by_state("validated")[0]["witness"]["product"] == "Apache Tomcat"


# ── the consumer contract ──────────────────────────────────────────────────────────────────────
def test_trusted_reads_validated_and_above_and_never_ranks_rejected_above_production():
    """`rejected` is the LAST element of VALIDATION_STATES, so its index is the highest. A naive
    `index >= threshold` would rank a rejected record above a production one."""
    R.reset()
    R.ingest([_rec(WITNESSED), _rec(UNWITNESSED)])
    R.corroborate(KEV)
    rid = R.by_state("validating")[0]["_id"]
    assert R.advance(rid, "rejected")[0] is True
    got = R.trusted("validated")
    assert [r["cve"] for r in got] == [WITNESSED]         # rejected excluded, validated included
    assert R.trusted("candidate") == got                  # rejected excluded at every threshold
    assert R.trusted("nonsense") == []


def test_the_consumer_default_is_validated_and_above_not_production_only():
    """The ticket's central warning: a consumer wired to `production()` reads `[]` forever, because
    production needs a human reviewer that an unattended run never supplies. So the DEFAULT
    threshold is load-bearing and is asserted here — calling `trusted()` with no argument must
    return the corroborated record. A mutation to `min_state="production"` survives every other test
    in this file, because they all pass the threshold explicitly."""
    R.reset()
    R.ingest([_rec(WITNESSED)])
    R.corroborate(KEV)
    assert [r["cve"] for r in R.trusted()] == [WITNESSED]
    assert R.production() == []


def test_confidence_weight_orders_the_rungs_so_a_candidate_cannot_outrank_a_fixture_backed_record():
    R.reset()
    R.ingest([_rec(WITNESSED), _rec("CVE-2025-24813")])
    R.corroborate(KEV)
    hi = R.by_state("validated")[0]["_id"]
    assert R.advance(hi, "fixture_backed", evidence="tests/test_intel_promotion.py")[0] is True
    ranked = R.trusted("validated")
    assert ranked[0]["validation_state"] == "fixture_backed"
    assert ranked[0]["confidence"] > ranked[-1]["confidence"]


# ── the wiring: ingest DRIVES the pass ─────────────────────────────────────────────────────────
def test_ingest_drives_the_promotion_pass(monkeypatch):
    """The island check. `ingest()` is the only registry entry point product code reaches
    (`main.intel_fetch` -> `intel_registry.ingest`), so the pass has to run from there or the ladder
    has no driver outside a test."""
    import intel_feeds
    monkeypatch.setattr(intel_feeds, "load", lambda *a, **k: KEV)
    R.reset()
    assert R.ingest([_rec(WITNESSED)]) == 1
    assert R.stats()["by_state"] == {"validated": 1}      # climbed without any test calling advance()


def test_entry_is_still_always_candidate_even_when_the_pass_would_validate(monkeypatch):
    """The #114 invariant is about ENTRY. A record claiming production still enters at candidate,
    and only the evidence-carrying pass may move it."""
    import intel_feeds
    monkeypatch.setattr(intel_feeds, "load", lambda *a, **k: KEV)
    R.reset()
    r = _rec(UNWITNESSED)
    r["validation_state"] = "production"
    R.ingest([r])
    assert R.production() == []
    assert R.by_state("validating")[0]["_history"][0][0] == "candidate"


# ── labelled emptiness: an empty registry must say WHICH kind of empty it is ───────────────────
def test_an_empty_registry_distinguishes_disabled_from_cold_from_clean(monkeypatch):
    """`{'total': 0, 'by_state': {}}` was mute: switched-off, restarted-and-lost, and
    fetched-and-found-nothing all rendered identically, and all three read as clean."""
    R.reset()
    monkeypatch.setattr(S, "enabled_sources", lambda *a, **k: [])
    st = R.stats()
    assert st["state"] == "disabled" and "configuration state, not a clean result" in st["why"]
    assert st["last_pass"] == {}                       # the pass has never run in this process

    monkeypatch.setattr(S, "enabled_sources", lambda *a, **k: ["nvd"])
    assert R.stats()["state"] == "cold"

    R.ingest([_rec(WITNESSED)])
    assert R.stats()["state"] == "populated"


def test_the_endpoint_can_tell_a_missing_catalogue_from_a_catalogue_that_matched_nothing():
    R.reset()
    R.ingest([_rec(WITNESSED)])
    R.corroborate({})                                   # no snapshot on disk
    lp = R.stats()["last_pass"]
    assert lp["status"] == "no_witness_snapshot" and lp["catalog"] == 0 and lp["validated"] == 0

    R.reset(); R.ingest([_rec(UNWITNESSED)])
    R.corroborate(KEV)                                  # real catalogue, no match
    lp = R.stats()["last_pass"]
    assert lp["status"] == "ok" and lp["catalog"] == 3 and lp["validated"] == 0
    assert lp["examined"] == 1 and lp["unwitnessed"] == 1


def test_the_store_never_claims_durability_it_does_not_have():
    R.reset()
    assert "NOT persisted" in R.stats()["store"]
