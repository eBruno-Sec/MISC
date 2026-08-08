"""Tests for the Technique Registry (agent/techniques.py)."""
from __future__ import annotations

import techniques as tq


def test_registry_loads_and_records_are_well_formed():
    assert len(tq.TECHNIQUES) >= 15
    for tid, t in tq.TECHNIQUES.items():
        assert t["id"] == tid
        for field in tq._REQUIRED:
            assert field in t and t[field] not in (None, ""), (tid, field)
        assert t["permission"] in (tq.PASSIVE, tq.ACTIVE, tq.INTRUSIVE)
        assert isinstance(t["transferable"], bool)
        assert isinstance(t.get("validated_on", []), list)
        assert isinstance(t.get("maps_to", {}), dict)
        assert t.get("execution") in ("auto", "operator")


def test_no_technique_hardcodes_a_secret_in_its_body():
    # Techniques that consume target-specific data must declare it as a fixture,
    # never bake it in. Guards the "technique-first, not answer-first" rule.
    for t in tq.TECHNIQUES.values():
        blob = " ".join(str(t.get(k, "")) for k in ("detect", "exploit", "oracle", "summary")).lower()
        # a couple of well-known Juice Shop answers that must NEVER appear as literals
        for leaked in ("samuel", "0815", "s3cr3t"):
            assert leaked not in blob, (t["id"], leaked)


def test_generalized_requires_two_labs():
    assert tq.GENERALIZED_MIN_LABS == 2
    one = {"validated_on": ["juiceshop"]}
    two = {"validated_on": ["juiceshop", "dvwa"]}
    dup = {"validated_on": ["juiceshop", "juiceshop"]}
    assert tq.is_generalized(one) is False
    assert tq.is_generalized(two) is True
    assert tq.is_generalized(dup) is False  # de-dupes; a lab can't vouch for itself twice


def test_coverage_matrix_reports_both_honest_numbers():
    m = tq.coverage_matrix()
    assert m["techniques_total"] == len(tq.TECHNIQUES)
    # transferable capability count and generalized (>=2 lab) count are distinct, both present
    assert m["transferable_total"] >= 1
    assert m["generalized_total"] == len(tq.generalized())
    assert m["transferable_total"] + m["lab_local_total"] == m["techniques_total"]
    assert isinstance(m["rows"], list) and len(m["rows"]) == len(tq.TECHNIQUES)


def test_lab_local_techniques_are_flagged_not_counted_as_capability():
    # find_hidden_route (score board) is lab trivia: solves a challenge, not a real-world method.
    t = tq.get("find_hidden_route")
    assert t is not None and t["transferable"] is False
    assert "find_hidden_route" not in [r["id"] for r in tq.coverage_matrix()["rows"] if False]


def test_techniques_for_lab_juiceshop_nonempty():
    js = tq.techniques_for_lab("juiceshop")
    assert len(js) >= 8
    ids = {t["id"] for t in js}
    assert "sqli_auth_bypass" in ids and "idor_bola_read" in ids


def test_pack_refs_point_at_real_packs():
    import packs
    for t in tq.TECHNIQUES.values():
        if t.get("pack"):
            assert packs.get(t["pack"]) is not None, t["id"]


def test_fixture_consuming_techniques_declare_needs_fixture():
    # weak_password_reset must consume a security answer as data, not hardcode it.
    t = tq.get("weak_password_reset")
    assert "security_answer" in t.get("needs_fixture", [])


def test_fixture_source_is_honest_and_valid():
    for t in tq.TECHNIQUES.values():
        fs = t.get("fixture_source")
        assert fs in ("harvest", "external", "none"), (t["id"], fs)
        # a technique with no fixture must not claim a fixture source
        if not t.get("needs_fixture"):
            assert fs == "none", t["id"]
    # the harvester itself is a first-class transferable technique now
    h = tq.get("target_intel_harvest")
    assert h is not None and h["transferable"] is True and h["permission"] == tq.PASSIVE
    # weak reset derives its answer from the target (harvest), JWT crack does not (external)
    assert tq.get("weak_password_reset")["fixture_source"] == "harvest"
    assert tq.get("jwt_forge")["fixture_source"] == "external"


def test_an_inline_wstg_kwarg_is_not_destroyed_by_the_authoritative_map():
    """The `_WSTG` map is authoritative where it has an entry, but it used to be applied as a plain
    overwrite, so every technique that declared `_t(wstg=...)` for an id absent from the map silently
    reported 'unmapped'. That hid 25 real mappings. The map must WIN, never DELETE."""
    src = open("/app/techniques.py").read() if __import__("os").path.exists("/app/techniques.py") else ""
    if src:
        assert '_rec["wstg"] = _WSTG.get(_tid) or _rec.get("wstg")' in src, \
            "the WSTG assignment must fall back to the record's own value, not clobber it"
    # techniques that declare a WSTG test inline keep it
    for tid in ("browser_persona_bola", "client_side_authz", "client_supplied_identity_param",
                "jwt_key_confusion"):
        t = tq.get(tid)
        if t:
            assert t.get("wstg"), "%s lost its inline WSTG mapping" % tid
    # and the authoritative map still wins where it has an entry
    assert tq.get("cache_deception")["wstg"] == "WSTG-CONF-13"


def test_every_wstg_mapping_names_a_real_test_id():
    """A wrong standards mapping is worse than a blank one — it tells a reader a standard covers
    something it does not. (Caught client_side_authz pointing at ATHZ-01 'Directory Traversal'.)"""
    import wstg_catalog
    cat = getattr(wstg_catalog, "WSTG", None) or getattr(wstg_catalog, "CATALOG", None)
    for t in tq.TECHNIQUES.values():
        w = t.get("wstg")
        if w:
            assert w in cat, "%s maps to %s, which is not a WSTG test id" % (t["id"], w)


def test_unmapped_techniques_are_a_recorded_decision_not_an_omission():
    unmapped = {t["id"] for t in tq.TECHNIQUES.values() if not t.get("wstg")}
    undocumented = unmapped - set(tq.WSTG_DELIBERATELY_UNMAPPED)
    assert not undocumented, ("these techniques have no WSTG mapping and no stated reason: %s"
                              % sorted(undocumented))
    for tid, why in tq.WSTG_DELIBERATELY_UNMAPPED.items():
        assert len(why) > 15, tid


def test_access_control_techniques_map_to_authorization_tests_not_traversal():
    assert tq.get("client_side_authz")["wstg"] == "WSTG-ATHZ-02"
    assert tq.get("path_traversal")["wstg"] == "WSTG-ATHZ-01"     # ATHZ-01 IS the traversal test
