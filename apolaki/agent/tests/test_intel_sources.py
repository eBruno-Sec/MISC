"""Trusted intel-source allowlist governance (#114): explicit allowlist, connectors OFF by default,
key-gated Tier-2, strict provenance, one-step lifecycle promotion, full request-log contract. Pure."""
import intel_sources as S


def test_allowlist_has_tiers_and_marks_live_feeds():
    t1 = {s["name"] for s in S.allowlist(1)}
    t2 = {s["name"] for s in S.allowlist(2)}
    assert {"cve_v5", "nvd", "cisa_kev", "epss", "ghsa", "nuclei_templates", "mitre_attack"} <= t1
    assert {"censys", "shodan", "virustotal", "ct_logs", "github_api"} <= t2
    assert S.get("cisa_kev")["live"] and S.get("mitre_capec")["live"] and S.get("mitre_attack")["live"]
    assert S.get("cve_v5")["live"] is False and S.get("shodan")["live"] is False


def test_connectors_are_all_disabled_by_default():
    assert S.enabled_sources(env={}) == []
    for n in S.SOURCES:
        assert S.is_enabled(n, env={}) is False


def test_tier1_master_switch_and_tier2_needs_key():
    env = {"INTEL_CONNECTORS": "1"}
    assert S.is_enabled("cisa_kev", env) and S.is_enabled("nvd", env)
    assert S.is_enabled("shodan", env) is False                          # tier2 ignores the tier1 master
    assert S.is_enabled("shodan", {"INTEL_SRC_SHODAN": "1"}) is False     # per-source still needs the key
    assert S.is_enabled("shodan", {"INTEL_SRC_SHODAN": "1", "SHODAN_API_KEY": "x"}) is True
    assert S.is_enabled("randomblog", {"INTEL_CONNECTORS": "1"}) is False  # non-allowlisted never enables


def test_all_tier2_require_a_key():
    for s in S.allowlist(2):
        assert s["requires_key"] is True


def test_provenance_record_is_strict_and_untrusted_by_default():
    r = S.provenance_record("nvd", cve="CVE-2024-1234", affected_product="acme",
                            affected_versions=["<1.2"], fixed_versions=["1.2"])
    for f in S.PROVENANCE_FIELDS:
        assert f in r
    assert r["validation_state"] == "candidate" and r["confidence"] <= 0.3
    assert r["source_type"] == "vuln_enrichment" and r["cve"] == "CVE-2024-1234" and r["allowlisted"] is True
    assert S.provenance_record("randomblog")["allowlisted"] is False


def test_lifecycle_promotion_is_one_step_no_skip_to_production():
    assert S.can_promote("candidate", "validating") and S.can_promote("validated", "fixture_backed")
    assert S.can_promote("candidate", "production") is False       # no jumping the queue
    assert S.can_promote("candidate", "rejected")                  # always allowed to reject
    assert S.can_promote("production", "candidate") is False


def test_request_log_entry_has_the_full_audit_contract():
    e = S.request_log_entry("cisa_kev", "https://x/kev.json", "vuln-intel", "self", 200,
                            rate_limit_state="ok", cache_status="hit")
    for f in S.REQUEST_LOG_FIELDS:
        assert f in e
    assert e["status"] == 200 and e["cache_status"] == "hit" and e["parser_version"] == "1"
