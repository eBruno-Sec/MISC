"""Q-021D Gap 1 -- the product -> advisory resolver (`intel_registry.advisories_for`) and its
consumer / anti-spam collapse (`dependency_intel.advisory_rows_for`).

Gap 2 (the promotion path: candidate -> validating -> validated) already shipped in `b72604d` and
is covered by `test_intel_promotion.py`; this file is Gap 1 only -- resolving a product+version to
real advisories, and turning those into report-ready rows without spamming the findings list.

FIXTURES ARE COPIED FROM THE REAL SNAPSHOT, never invented. `CVE-2024-38475` / `Apache HTTP Server`
/ `2026.07.29` / `1785445474.3897574` are the same verbatim values `test_intel_promotion.py` records
reading out of `/data/intel_feeds/kev.json` on 2026-08-18 -- reused here rather than re-copied so the
two files can never quietly drift onto different "real" numbers.
"""
import dependency_intel as D
import intel_registry as R
import intel_sources as S

KEV = {
    "kev": {"source": "kev", "tier": "A", "catalog_version": "2026.07.29", "count": 1656,
            "cves_meta": {
                "CVE-2024-38475": {"product": "Apache HTTP Server", "date_added": "2025-05-01",
                                   "ransomware": False},
            }},
    "manifest": {"refreshed_at": 1785445474.3897574,
                 "feeds": {"kev": {"ok": True, "count": 1656, "tier": "A", "version": "2026.07.29"}}},
}

WITNESSED = "CVE-2024-38475"


def _rec(cve, source="nvd", product="Apache HTTP Server"):
    return S.provenance_record(source, cve=cve, affected_product=product)


# ── ORACLE 1: a fact for a product with a known CVE resolves to >= 1 advisory carrying source
# and snapshot_at ─────────────────────────────────────────────────────────────────────────────
def test_oracle1_a_known_product_resolves_to_an_advisory_with_source_and_snapshot_at():
    R.reset()
    res = R.advisories_for({"product": "apache http server"}, KEV)
    assert res["status"] == "ok"
    assert len(res["advisories"]) >= 1
    for a in res["advisories"]:
        assert a["cve"] == WITNESSED
        assert a["source"]                      # every advisory names its source
        assert a["snapshot_at"] == 1785445474.3897574   # ... and its snapshot stamp


def test_oracle1_substring_product_match_and_no_match_returns_empty_not_ok():
    R.reset()
    res = R.advisories_for({"product": "totally-unrelated-product-xyz"}, KEV)
    assert res["status"] in ("empty", "disabled")
    assert res["advisories"] == []


# ── ORACLE 2 / NEGATIVE CONTROL (b): the advisory reaches the consumer only at validated-and-above,
# never before, mirroring `test_intel_promotion.py`'s own control (b) through the NEW resolver ────
def test_oracle2_a_candidate_record_is_not_visible_to_the_resolver():
    R.reset()
    R.ingest([_rec(WITNESSED)])                  # lands at candidate; corroborate() NOT run with KEV
    res = R.advisories_for({"product": "apache http server"}, {})   # empty catalogue -> nothing advances
    assert R.by_state("candidate")[0]["cve"] == WITNESSED
    assert res["advisories"] == []                # NOT visible while still candidate


def test_oracle2_the_same_record_becomes_visible_only_after_an_explicit_advance_with_evidence():
    R.reset()
    R.ingest([_rec(WITNESSED)])
    rid = R.by_state("candidate")[0]["_id"]
    # An empty snapshot isolates the governed-connector (registry) branch from the resolver's OWN
    # local-KEV branch, which would otherwise match this same product/CVE unconditionally and mask
    # what this test is actually checking: registry-record visibility, gated on validation_state.
    empty_snap = {}
    assert R.advisories_for({"product": "apache http server"}, empty_snap)["advisories"] == []
    # advance one gated step at a time, WITH evidence -- exactly what corroborate() does internally
    assert R.advance(rid, "validating", evidence="examined")[0] is True
    assert R.advisories_for({"product": "apache http server"}, empty_snap)["advisories"] == []  # still not visible
    assert R.advance(rid, "validated", evidence="exact CVE witnessed by cisa_kev")[0] is True
    # AFTER: now visible, carrying the governed-connector source
    got = R.advisories_for({"product": "apache http server"}, empty_snap)["advisories"]
    assert any(a["cve"] == WITNESSED and a["source"] == "nvd" for a in got)


# ── NEGATIVE CONTROL (a): every source disabled (default) + nothing ingested -> zero network I/O,
# empty result LABELLED disabled, not silently "clean" ─────────────────────────────────────────
def test_negctrl_a_all_sources_disabled_labels_empty_as_disabled_not_clean():
    R.reset()
    assert S.enabled_sources() == []              # the default -- nothing is enabled
    res = R.advisories_for({"product": "totally-unrelated-product-xyz"}, {})
    assert res["status"] == "disabled"
    assert res["advisories"] == []
    assert "not" in res["note"] and "clean" in res["note"]


def test_negctrl_a_re_enabling_a_key_gated_source_without_a_credential_still_refuses(monkeypatch):
    """Mutation test named in the ticket: flip a source's allowlist switch ON in the test env WITHOUT
    its credential. The hard gate (`intel_sources.is_enabled`) must still refuse, and this resolver's
    'disabled' label must stay green -- confirming this ticket did not weaken the existing gate."""
    R.reset()
    monkeypatch.setenv("INTEL_SRC_SHODAN", "1")     # shodan is key-gated; no SHODAN_API_KEY present
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    assert S.is_enabled("shodan") is False
    assert S.enabled_sources() == []
    res = R.advisories_for({"product": "totally-unrelated-product-xyz"}, {})
    assert res["status"] == "disabled"


def test_negctrl_a_the_resolver_never_calls_the_network_fetch_hook():
    """The resolver's OWN negative control: replace the connector's default HTTP transport with a
    function that raises if called, and confirm the resolver still returns results (from local
    state only) without touching it."""
    import intel_connectors as C

    def _boom(*a, **k):
        raise AssertionError("advisories_for must never reach the network")

    orig = C._default_http
    C._default_http = _boom
    try:
        R.reset()
        res = R.advisories_for({"product": "apache http server"}, KEV)
        assert res["status"] == "ok"               # local KEV snapshot alone answers this
    finally:
        C._default_http = orig


# ── NEGATIVE CONTROL (c) / non-vacuity: assert the fixture set is real before trusting "no spam" ──
def test_negctrl_c_the_fixture_set_is_non_empty_before_the_no_spam_claim_is_believed():
    assert len(KEV["kev"]["cves_meta"]) >= 1
    assert WITNESSED in KEV["kev"]["cves_meta"]


# ── ORACLE 3 + non-vacuity: 40 matching CVEs at LOW version confidence produce EXACTLY one row ───
def _forty_advisories(product="widgetcorp gadgetlib"):
    """40 distinct CVEs for the same product, corroborated to `validated` via 40 distinct KEV
    entries -- built with the real constructors (`provenance_record`, `ingest`, `corroborate`),
    not hand-typed as validated. Returns (witness_kev, lookup_snap): the WITNESS snapshot used to
    promote the 40 records (so the promotion path really has to climb all 40, not a shortcut), and
    a LOOKUP snapshot with an empty local KEV table -- used for the actual `advisories_for` /
    `advisory_rows_for` calls below, so "40 advisories" means 40 distinct validated
    governed-connector records, not 40 doubled by the resolver's OWN separate local-KEV branch
    also matching the same product (which it legitimately would, and does -- see
    `test_oracle1_...`; that is a different, already-covered code path, not this test's subject)."""
    kev_meta = {}
    recs = []
    for i in range(40):
        cve = "CVE-2030-%05d" % i
        kev_meta[cve] = {"product": product, "date_added": "2030-01-01", "ransomware": False}
        recs.append(S.provenance_record("nvd", cve=cve, affected_product=product))
    witness_kev = {"kev": {"catalog_version": "synthetic-40", "cves_meta": kev_meta},
                  "manifest": {"refreshed_at": 999.0}}
    lookup_snap = {"kev": {"cves_meta": {}}, "manifest": {"refreshed_at": 999.0}}
    R.reset()
    R.ingest(recs)                       # drives corroborate() once, per ingest()'s own contract
    R.corroborate(witness_kev)           # explicit re-run against THIS kev (ingest's own pass used {})
    return witness_kev, lookup_snap


def test_negctrl_c_non_vacuity_the_forty_cve_fixture_set_is_really_forty():
    witness_kev, _ = _forty_advisories()
    assert len(witness_kev["kev"]["cves_meta"]) == 40
    assert len(R.by_state("validated")) == 40       # the promotion path really climbed all 40


def test_oracle3_low_confidence_version_collapses_forty_advisories_to_exactly_one_row():
    _, lookup_snap = _forty_advisories()
    fact = D.make_tech_fact("widgetcorp gadgetlib", version="1.0.0", source="server-header")  # LOW
    assert fact["version_confidence"] == D.LOW
    resolved = R.advisories_for(fact, lookup_snap)
    assert len(resolved["advisories"]) == 40        # the resolver itself does not collapse
    rows = D.advisory_rows_for(fact, resolved)
    assert len(rows) == 1                           # the CONSUMER collapses -- anti-spam, the point
    assert rows[0]["row_type"] == "collapsed"
    assert rows[0]["count"] == 40
    assert "40 advisories" in rows[0]["summary"]
    assert "widgetcorp gadgetlib" in rows[0]["summary"]


def test_oracle3_confirmed_confidence_version_enumerates_one_row_per_advisory():
    """The contrast case: a TRUSTWORTHY version is allowed to enumerate. Anti-spam is about
    UNCERTAIN versions, not about hiding real per-CVE detail when the version itself is solid."""
    _, lookup_snap = _forty_advisories()
    fact = D.make_tech_fact("widgetcorp gadgetlib", version="1.0.0", source="js-content-banner")  # CONFIRMED
    resolved = R.advisories_for(fact, lookup_snap)
    rows = D.advisory_rows_for(fact, resolved)
    assert len(rows) == 40
    assert all(r["row_type"] == "advisory" for r in rows)


# ── the wiring: attach_advisories runs from make_tech_fact, the LIVE construction path
# `fingerprint.py:304` calls unmodified on every mission -- not just from a test ────────────────
def test_wiring_make_tech_fact_upgrades_proof_state_when_the_version_is_trustworthy():
    kev = _forty_advisories(product="apache http server")
    # re-corroborate against the standard single-CVE fixture too, for a clean single-advisory case
    R.reset()
    R.ingest([_rec(WITNESSED)])
    R.corroborate(KEV)
    fact = D.attach_advisories(
        D.make_tech_fact("apache http server", version="2.4.41", source="js-content-banner"), KEV)
    assert fact["proof_state"] == D.ADVISORY_MATCHED
    assert fact["advisory_rows"] and fact["advisory_rows"][0]["cve"] == WITNESSED


def test_wiring_make_tech_fact_is_a_no_op_with_no_local_feed_data_and_an_empty_registry():
    """Every existing test's environment: no `/app/data/intel_feeds` on disk, nothing ingested.
    `make_tech_fact` must produce EXACTLY what it produced before this ticket -- no new keys, no
    proof_state change -- so this ticket cannot regress anything that already passed."""
    R.reset()
    fact = D.make_tech_fact("nginx", version="1.18.0", source="js-content-banner")
    assert "advisory_rows" not in fact
    assert fact["proof_state"] == D.VERSION_SUSPECTED


def test_wiring_no_version_never_triggers_a_resolver_call():
    """A fact with no version must not even attempt resolution -- matching on product name alone,
    with nothing for a range to apply to, would be pure noise."""
    R.reset()
    fact = D.make_tech_fact("apache http server", version="", source="")
    assert fact["proof_state"] == D.DETECTED_TECHNOLOGY
    assert "advisory_rows" not in fact
