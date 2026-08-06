"""Curated defensive-control mapping (Codex Tier-1 #3): families map to real controls + the attacker
capability they reduce; unknown families get NO fabricated control; provenance is honestly 'curated'."""
import defense_mapping as D


def test_sqli_maps_to_parameterized_and_structural_allowlist():
    ctrls = D.controls_for({"family": "sqli"})
    assert ctrls and ctrls[0]["control_id"] == "parameterized-queries"
    notes = " ".join(ctrls[0]["implementation_notes"]).lower()
    assert "parameter" in notes and "allowlist" in notes           # structural allowlist for ORDER BY etc.
    assert "database_read" in ctrls[0]["reduces"]


def test_idor_and_bola_map_to_object_level_authz():
    for fam in ("idor", "bola"):
        ctrls = D.controls_for(fam)
        assert ctrls[0]["control_id"] == "object-level-authorization"
        assert "cross_object_read" in ctrls[0]["reduces"]


def test_ssrf_maps_to_egress_allowlist_and_metadata_isolation():
    ctrls = D.controls_for({"family": "ssrf"})
    assert ctrls[0]["control_id"] == "egress-allowlist"
    notes = " ".join(ctrls[0]["implementation_notes"]).lower()
    assert "169.254.169.254" in notes or "metadata" in notes
    assert "cloud_metadata_theft" in ctrls[0]["reduces"]


def test_xss_maps_to_contextual_encoding_and_csp():
    ctrls = D.controls_for({"family": "xss"})
    ids = [c["control_id"] for c in ctrls]
    assert "contextual-output-encoding" in ids and "csp-hardening" in ids


def test_aliases_resolve_to_canonical_family():
    # real Apolaki family variants should still get the right control
    assert D.controls_for("dom_xss")[0]["control_id"] == "contextual-output-encoding"
    assert D.controls_for("backup_exposure")[0]["control_id"] == "no-sensitive-web-exposure"
    assert D.controls_for("access_control")[0]["control_id"] == "centralized-access-control"


def test_unknown_family_returns_no_fake_mapping():
    assert D.controls_for({"family": "totally_unknown_thing"}) == []
    assert D.controls_for("") == []
    assert D.reduces_for({"family": "nope"}) == []


def test_provenance_is_honestly_curated():
    for fam in D.families_covered():
        for c in D.controls_for(fam):
            assert c["scheme"] == "curated_defense" and c["confidence"] == "curated"
            assert c["provenance"] == "Apolaki local mapping"


def test_reduces_for_flattens_and_dedupes():
    caps = D.reduces_for({"family": "xss"})
    assert caps == list(dict.fromkeys(caps))            # de-duplicated, order preserved
    assert "session_theft" in caps
