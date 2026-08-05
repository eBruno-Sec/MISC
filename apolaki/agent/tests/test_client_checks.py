"""Reverse tabnabbing (CWE-1022) + permissive cross-domain policy (CWE-942) — deterministic content oracles
that closed the WSTG-CLNT-14 / CONF-08 coverage gaps. Confirm from HTML/XML content, no runtime, no writes."""
import blind_benchmark as bb
import client_checks_tool as cc
from report import cvss31_base_score


def test_reverse_tabnabbing_flags_external_blank_without_noopener():
    html = ('<a target="_blank" href="https://evil.example/x">bad</a>'
            '<a target="_blank" rel="noopener" href="https://evil.example/ok">safe</a>'
            '<a target="_blank" href="/local">same-origin</a>'
            '<a href="https://evil.example/no-blank">no blank</a>')
    hits = cc.reverse_tabnabbing(html, "https://site.test/page")
    assert hits == ["https://evil.example/x"]                    # only the unsafe cross-origin _blank link


def test_reverse_tabnabbing_ignores_noreferrer_and_schemes():
    html = ('<a target="_blank" rel="noreferrer" href="https://a.test/x">ok</a>'
            '<a target="_blank" href="javascript:void(0)">js</a>'
            '<a target="_blank" href="mailto:x@y.z">mail</a>')
    assert cc.reverse_tabnabbing(html, "https://site.test/") == []


def test_crossdomain_wildcard_detection():
    assert cc.crossdomain_wildcard('<cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>', "crossdomain.xml")
    assert not cc.crossdomain_wildcard('<cross-domain-policy><allow-access-from domain="trusted.com"/></cross-domain-policy>', "crossdomain.xml")
    assert cc.crossdomain_wildcard('<access-policy><cross-domain-access><policy><allow-from><domain uri="*"/></allow-from></policy></cross-domain-access></access-policy>', "clientaccesspolicy.xml")
    assert not cc.crossdomain_wildcard("<html>not a policy</html>", "crossdomain.xml")


def test_findings_are_proof_with_consistent_cvss():
    tf = cc.tabnabbing_finding("https://x/p", ["https://evil/x"])
    cf = cc.crossdomain_finding("https://x/crossdomain.xml", "crossdomain.xml")
    for f in (tf, cf):
        assert f["confidence"] == "confirmed" and bb._has_proof(f)
        # the stored score must match its vector (report integrity gate)
        assert abs(cvss31_base_score(f["cvss_vector"]) - f["cvss_score"]) < 0.05
    assert tf["cwe"] == "CWE-1022" and cf["cwe"] == "CWE-942"
