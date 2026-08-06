"""Governed intel connectors (#114): disabled sources do ZERO network I/O (default), enabled sources
run fetch->cache->rate-limit->log->normalize into strict-provenance CANDIDATE records. No network here —
the HTTP call is injected. Pure pipeline test."""
import intel_connectors as C


def _boom(url, headers=None):
    raise AssertionError("network was called for a disabled connector!")


_NVD = ('{"vulnerabilities":[{"cve":{"id":"CVE-2024-0001","published":"2024-01-01",'
        '"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8}}]},'
        '"weaknesses":[{"description":[{"value":"CWE-89"}]}],"references":[{"url":"http://x"}]}}]}')
_EPSS = '{"data":[{"cve":"CVE-2024-0001","epss":"0.97","percentile":"0.99","date":"2024-01-02"}]}'


def test_disabled_connector_makes_zero_network_calls():
    C.reset()
    r = C.fetch("nvd", env={}, http=_boom)          # nvd disabled by default; _boom must NOT be called
    assert r["status"] == "disabled" and r["records"] == [] and r["cache"] == "n/a"
    assert C.audit_log() == []                       # nothing logged, because nothing went out
    # a Tier-2 source with the enable flag but NO key is still disabled -> still no network
    assert C.fetch("shodan", env={"INTEL_SRC_SHODAN": "1"}, http=_boom)["status"] == "disabled"


def test_enabled_connector_fetches_normalizes_and_logs():
    C.reset()
    calls = []
    def http(url, headers=None):
        calls.append(url); return 200, _NVD
    r = C.fetch("nvd", env={"INTEL_SRC_NVD": "1"}, http=http, now=1000.0)
    assert r["status"] == "ok" and r["cache"] == "miss" and len(calls) == 1
    rec = r["records"][0]
    assert rec["source"] == "nvd" and rec["cve"] == "CVE-2024-0001" and rec["cwe"] == "CWE-89"
    assert rec["validation_state"] == "candidate" and rec["confidence"] <= 0.3   # untrusted until validated
    assert rec["cvss"] == 9.8
    # the mandatory audit record was written with the full contract
    log = C.audit_log()[-1]
    for f in ("source", "endpoint", "purpose", "target_scope", "timestamp", "status",
              "rate_limit_state", "cache_status", "parser_version"):
        assert f in log
    assert log["status"] == 200


def test_cache_serves_second_call_without_network():
    C.reset()
    calls = []
    def http(url, headers=None):
        calls.append(url); return 200, _EPSS
    C.fetch("epss", env={"INTEL_SRC_EPSS": "1"}, http=http, now=2000.0)
    r2 = C.fetch("epss", env={"INTEL_SRC_EPSS": "1"}, http=http, now=2000.5)  # within ttl
    assert r2["cache"] == "hit" and len(calls) == 1                          # served from cache, no 2nd call
    assert r2["records"][0]["epss"] == "0.97"


def test_rate_limit_blocks_a_burst():
    C.reset()
    assert C._rate_ok("x", 2, now=0.0) and C._rate_ok("x", 2, now=0.1)       # first 2 ok
    assert C._rate_ok("x", 2, now=0.2) is False                              # 3rd within the minute blocked
    assert C._rate_ok("x", 2, now=61.0) is True                             # window rolled over


def test_unknown_source_is_never_fetched():
    C.reset()
    assert C.fetch("randomblog", env={"INTEL_CONNECTORS": "1"}, http=_boom)["status"] == "unknown_source"


def test_kev_and_cve_v5_parsers_produce_candidates():
    kev = ('{"vulnerabilities":[{"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j",'
           '"dateAdded":"2021-12-10","dueDate":"2021-12-24"}]}')
    recs = C.normalize("cisa_kev", kev)
    assert recs and recs[0]["cve"] == "CVE-2021-44228" and recs[0]["known_exploited"] is True
    assert recs[0]["validation_state"] == "candidate"
    cve5 = ('{"cveMetadata":{"cveId":"CVE-2024-5555","datePublished":"2024-05-05"},'
            '"containers":{"cna":{"affected":[{"product":"acme","versions":[{"version":"1.0"}]}],'
            '"references":[{"url":"http://ref"}]}}}')
    r5 = C.normalize("cve_v5", cve5)
    assert r5 and r5[0]["cve"] == "CVE-2024-5555" and r5[0]["affected_product"] == "acme"
