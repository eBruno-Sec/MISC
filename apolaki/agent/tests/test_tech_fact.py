"""Q-021B - the TechnologyFact: a detected technology must survive with its version, its source and
an honest statement of how sure we are of that version.

Detection is NEVER a vulnerability. Every assertion here is about PERSISTENCE and HONESTY, not about
finding anything: a fact carries what was observed, and the ladder decides what may be done with it.

Shared module for the Q-021 family - Q-021C/D will add advisory/range cases beside these, and the
`cve_eligible` mutation guard below protects all of them at once.
"""
import dependency_intel as di


# ── the fact carries what the detector computed ────────────────────────────────────────────────
def test_tech_fact_persists_version_source_and_evidence():
    """The version is the whole point: it is computed and, before Q-021B, dropped one line later."""
    f = di.make_tech_fact("nginx", version="1.18.0", source="Server header",
                          detector="fingerprint.headers", category="server",
                          evidence="Server: nginx/1.18.0", location="http://box:3000/",
                          host="box:3000", now=1000.0)
    assert f["product"] == "nginx"
    assert f["version"] == "1.18.0"
    assert f["source"] == "Server header"
    assert f["detector"] == "fingerprint.headers"
    assert f["evidence"] == "Server: nginx/1.18.0"
    assert f["host"] == "box:3000"
    assert f["first_seen"] == 1000.0 and f["last_seen"] == 1000.0
    assert f["authenticated"] is False


def test_tech_fact_records_authentication_state():
    f = di.make_tech_fact("Drupal", version="", source="Set-Cookie", detector="fingerprint.cookies",
                          authenticated=True, now=1.0)
    assert f["authenticated"] is True


# ── the confidence ladder: dependency_intel's, not a second one ────────────────────────────────
def test_spoofable_server_banner_stays_low_and_is_never_cve_eligible():
    """CONTROL. A `Server:` banner is a CLAIM the target makes about itself - editable in one config
    line and rewritten by any proxy. It is the single largest false-positive source in this class, so
    it may never be strong enough to pull CVEs."""
    spoofed = di.make_tech_fact("Apache", version="1.3.9", source="Server header",
                                detector="fingerprint.headers",
                                evidence="Server: Apache/1.3.9", now=1.0)
    assert spoofed["version"] == "1.3.9", "the claimed version is still recorded - it is evidence"
    assert spoofed["version_confidence"] == di.LOW
    assert di.cve_eligible(spoofed) is False
    assert di.assess_component(spoofed) == []


def test_artifact_self_declared_version_is_confirmed():
    """A library file that states its own version is the artifact proving itself, not a claim."""
    f = di.make_tech_fact("jquery", version="3.4.1", source="js-content-banner",
                          detector="dependency_intel.js-content", now=1.0)
    assert f["version_confidence"] == di.CONFIRMED
    assert di.cve_eligible(f) is True


def test_filename_and_cdn_versions_are_high():
    for src in ("script-filename", "cdn-path", "script src"):
        f = di.make_tech_fact("jquery", version="3.4.1", source=src, now=1.0)
        assert f["version_confidence"] == di.HIGH, src
        assert di.cve_eligible(f) is True


def test_unknown_source_fails_closed_to_low():
    f = di.make_tech_fact("mystery", version="9.9", source="something-new", now=1.0)
    assert f["version_confidence"] == di.LOW
    assert di.cve_eligible(f) is False


# ── unknown version => POTENTIALLY_AFFECTED, never proven ──────────────────────────────────────
def test_versionless_detection_is_detected_only_and_potentially_affected():
    """CONTROL. `Server: nginx` with no version is a real observation and a legal fact - it just may
    never become a confirmed anything, however many CVEs a feed later returns for nginx."""
    f = di.make_tech_fact("nginx", version="", source="Server header",
                          detector="fingerprint.headers", now=1.0)
    assert f["version"] == ""
    assert f["version_confidence"] == di.LOW
    assert f["proof_state"] == di.DETECTED_TECHNOLOGY
    assert f["component_status"] == di.POTENTIALLY_AFFECTED
    assert di.cve_eligible(f) is False
    assert di.tech_component_status(f) == di.POTENTIALLY_AFFECTED


def test_versionless_fact_stays_potentially_affected_even_with_a_behaviour_proof():
    """A behaviour proof for a component whose version we do not know proves nothing ABOUT THIS
    component - `cve_eligible` is the enforcement point and it fails first."""
    f = di.make_tech_fact("nginx", version="", source="Server header", now=1.0)
    proof = {"cve": "CVE-2021-23017", "trigger": "t", "observed": "o",
             "control": "c", "control_observed": "different"}
    assert di.tech_component_status(f, proof, ["CVE-2021-23017"]) == di.POTENTIALLY_AFFECTED


def test_a_version_alone_is_only_suspected_never_confirmed():
    """The ladder tops out at VERSION_SUSPECTED in Q-021B. Nothing in this slice may claim an
    advisory match, an applicability verdict or an oracle - those are C/D/E."""
    f = di.make_tech_fact("jquery", version="3.4.1", source="js-content-banner", now=1.0)
    assert f["proof_state"] == di.VERSION_SUSPECTED
    assert f["component_status"] == di.POTENTIALLY_AFFECTED
    assert di.TECH_PROOF_LADDER.index(f["proof_state"]) < di.TECH_PROOF_LADDER.index(di.ADVISORY_MATCHED)


# ── dedupe is by IDENTITY, not by the version string ───────────────────────────────────────────
def test_same_version_on_two_products_never_merges():
    """CONTROL. nginx 1.18.0 and PHP 1.18.0 share a version string and nothing else. A dedupe keyed
    on the version - or on any key that omits the product - silently deletes one of two real facts."""
    facts = [di.make_tech_fact("nginx", version="1.18.0", source="Server header", host="h", now=1.0),
             di.make_tech_fact("PHP", version="1.18.0", source="X-Powered-By", host="h", now=1.0)]
    merged = di.merge_tech_facts(facts)
    assert len(merged) == 2
    assert {m["product"] for m in merged} == {"nginx", "php"}


def test_two_unmapped_products_sharing_a_version_never_merge():
    """The same control with the PRODUCT as the only discriminator. `_VENDOR` knows nginx and php, so
    the case above would also pass with a key that dropped the product entirely - measured: removing
    `product` from `tech_fact_key` left it green. Two products with no vendor mapping isolate it."""
    facts = [di.make_tech_fact("AlphaCMS", version="2.1.0", source="meta generator", host="h", now=1.0),
             di.make_tech_fact("BetaCMS", version="2.1.0", source="meta generator", host="h", now=1.0)]
    merged = di.merge_tech_facts(facts)
    assert [m["vendor"] for m in merged] == ["", ""], "neither product has a vendor hint"
    assert len(merged) == 2
    assert {m["product"] for m in merged} == {"alphacms", "betacms"}


def test_a_plugin_never_merges_into_its_host_product():
    """`component` carries a CMS plugin/theme/module. WordPress and WordPress+contact-form-7 are two
    different things to patch, so they are two facts even on one host at one version."""
    facts = [di.make_tech_fact("WordPress", version="6.4.2", source="meta generator", host="h", now=1.0),
             di.make_tech_fact("WordPress", version="6.4.2", source="meta generator", host="h",
                               component="contact-form-7", now=1.0)]
    assert len(di.merge_tech_facts(facts)) == 2


def test_same_product_on_two_hosts_never_merges():
    facts = [di.make_tech_fact("nginx", version="1.18.0", source="Server header", host="a", now=1.0),
             di.make_tech_fact("nginx", version="1.25.0", source="Server header", host="b", now=1.0)]
    assert len(di.merge_tech_facts(facts)) == 2


def test_repeat_observation_extends_last_seen_and_keeps_first_seen():
    a = di.make_tech_fact("nginx", version="1.18.0", source="Server header", host="h", now=100.0)
    b = di.make_tech_fact("nginx", version="1.18.0", source="Server header", host="h", now=500.0)
    merged = di.merge_tech_facts([a, b])
    assert len(merged) == 1
    assert merged[0]["first_seen"] == 100.0
    assert merged[0]["last_seen"] == 500.0


def test_stronger_evidence_wins_the_version():
    """The served file says 3.6.0; the filename still says 3.4.0 because an in-place upgrade never
    renames a path. Same reconciliation rule `reconcile_components` already applies to JS libraries."""
    weak = di.make_tech_fact("jquery", version="3.4.0", source="script-filename", host="h", now=1.0)
    strong = di.make_tech_fact("jquery", version="3.6.0", source="js-content-banner", host="h", now=2.0)
    merged = di.merge_tech_facts([weak, strong])
    assert len(merged) == 1
    assert merged[0]["version"] == "3.6.0"
    assert merged[0]["version_confidence"] == di.CONFIRMED


def test_a_versioned_observation_beats_a_versionless_one_at_the_same_rank():
    bare = di.make_tech_fact("nginx", version="", source="Server header", host="h", now=1.0)
    verd = di.make_tech_fact("nginx", version="1.18.0", source="Server header", host="h", now=2.0)
    merged = di.merge_tech_facts([bare, verd])
    assert len(merged) == 1 and merged[0]["version"] == "1.18.0"


def test_contradictory_equal_strength_versions_are_recorded_not_silently_dropped():
    """Two equally strong readings that disagree have no principled winner. Keeping one and saying
    nothing would be the invisible half of a false negative."""
    a = di.make_tech_fact("nginx", version="1.18.0", source="Server header", host="h", now=1.0)
    b = di.make_tech_fact("nginx", version="1.25.0", source="Server header", host="h", now=2.0)
    merged = di.merge_tech_facts([a, b])
    assert len(merged) == 1
    assert merged[0]["version"] == "1.18.0"
    assert "1.25.0" in merged[0]["version_conflicts"]


def test_authenticated_observation_marks_the_merged_fact():
    a = di.make_tech_fact("nginx", version="", source="Server header", host="h",
                          authenticated=False, now=1.0)
    b = di.make_tech_fact("nginx", version="", source="Server header", host="h",
                          authenticated=True, now=2.0)
    assert di.merge_tech_facts([a, b])[0]["authenticated"] is True


def test_merge_is_order_preserving_and_tolerates_junk():
    facts = [None, "nope", di.make_tech_fact("nginx", source="Server header", host="h", now=1.0),
             di.make_tech_fact("php", source="X-Powered-By", host="h", now=1.0)]
    merged = di.merge_tech_facts(facts)
    assert [m["product"] for m in merged] == ["nginx", "php"]


# ── the mutation guard the whole Q-021 family leans on ─────────────────────────────────────────
def test_cve_eligible_refuses_low_confidence_and_empty_versions():
    """MUTATION GUARD. Make `cve_eligible` return True for LOW and this fails - which is the whole
    defence between a spoofed banner and a report full of theoretical CVEs."""
    assert di.cve_eligible({"version": "1.0", "confidence": di.LOW}) is False
    assert di.cve_eligible({"version": "", "confidence": di.CONFIRMED}) is False
    assert di.cve_eligible({"version": "1.0", "confidence": di.CONFIRMED}) is True
    assert di.cve_eligible({"version": "1.0", "confidence": di.HIGH}) is True
    assert di.LOW not in di.CVE_ELIGIBLE


# ── the fact stays readable by every EXISTING dependency_intel consumer ─────────────────────────
def test_tech_fact_is_a_component_to_existing_readers():
    """`name`/`confidence`/`location` keep their meanings, so `cve_eligible`, `assess_component` and
    `reconcile_components` read a TechnologyFact without a second code path."""
    f = di.make_tech_fact("jQuery", version="3.4.0", source="script-filename",
                          location="http://h//h/jquery-3.4.0.js", now=1.0)
    assert f["name"] == "jquery" == f["product"]
    assert f["confidence"] == f["version_confidence"]
    assert f["location"] == "http://h/jquery-3.4.0.js", "canon_location still collapses doubled hosts"
    assert f["label"] == "jQuery", "display casing survives for the UI"
    assert [v["ids"] for v in di.assess_component(f)]
