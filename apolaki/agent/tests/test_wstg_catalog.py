"""OWASP WSTG coverage engine — the honest catalog-vs-capability map (RedCyber corpus WSTG table)."""
import wstg_catalog as wc


def test_catalog_is_complete_and_consistent():
    assert len(wc.CATALOG) == 109                       # full WSTG v4.2 active-test set
    assert all(wid.startswith("WSTG-") for wid in wc.CATALOG)
    # every FULL/PARTIAL/EXCLUDED id is a real catalog id (no typos drifting out of the catalog)
    for m in (wc.FULL, wc.PARTIAL, wc.EXCLUDED):
        assert set(m).issubset(set(wc.CATALOG))
    # an id is never in two states at once
    assert not (set(wc.FULL) & set(wc.PARTIAL))
    assert not (set(wc.FULL) & set(wc.EXCLUDED))


def test_coverage_tally_sums_to_total():
    cov = wc.coverage()
    t = cov["tally"]
    assert t["full"] + t["partial"] + t["none"] == cov["total_tests"] == 109
    assert t["excluded"] <= t["none"]
    assert 0 < cov["full_pct"] < 100 and cov["any_coverage_pct"] >= cov["full_pct"]


def test_new_book_engines_are_marked_full():
    cov_full = set(wc.FULL)
    for wid in ("WSTG-INPV-06", "WSTG-INPV-08", "WSTG-INPV-09", "WSTG-SESS-10", "WSTG-CONF-13"):
        assert wid in cov_full                          # ldap, ssi, xpath, jwt, cache-deception (path confusion)


def test_safety_exclusions_have_honest_reasons():
    # the tests we deliberately do NOT run must say WHY (never silently missing)
    assert "brute" in wc.EXCLUDED["WSTG-ATHN-03"].lower()
    assert "collateral" in wc.EXCLUDED["WSTG-INPV-15"].lower() or "other users" in wc.EXCLUDED["WSTG-INPV-15"].lower()
    assert "oracle" in wc.EXCLUDED["WSTG-CRYP-02"].lower()
    # every none-with-reason surfaces in the coverage output
    cov = wc.coverage()
    inpv_none = {x["id"]: x["reason"] for x in cov["categories"]["INPV"]["none"]}
    assert "WSTG-INPV-15" in inpv_none and inpv_none["WSTG-INPV-15"]
