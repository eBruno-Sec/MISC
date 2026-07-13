"""Tests for core.nmap_parse — nmap XML parsing + NSE vuln/weak-TLS findings."""
from core.nmap_parse import parse_nmap_xml, extract_findings

SAMPLE = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.29"/>
        <script id="http-vuln-cve2017-5638" output="VULNERABLE: Apache Struts RCE. State: VULNERABLE IDs: CVE:CVE-2017-5638 CVSS: 10.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
        <script id="ssl-enum-ciphers" output="TLSv1.0: weak ciphers negotiated"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
    <os><osmatch name="Linux 4.15 - 5.8"/></os>
  </host>
</nmaprun>"""


def test_parse_hosts_ports_os():
    parsed = parse_nmap_xml(SAMPLE)
    assert "10.0.0.5" in parsed
    h = parsed["10.0.0.5"]
    assert h["os"].startswith("Linux")
    open_ports = {p["port"] for p in h["ports"]}
    assert open_ports == {80, 443}          # closed 22 excluded
    p80 = next(p for p in h["ports"] if p["port"] == 80)
    assert p80["product"] == "Apache httpd" and p80["version"] == "2.4.29"


def test_parse_bad_input_is_safe():
    assert parse_nmap_xml("") == {}
    assert parse_nmap_xml("not xml at all") == {}
    assert parse_nmap_xml("<nmaprun><host></host></nmaprun>") == {}   # no address


def test_extract_vuln_and_weak_tls_findings():
    findings = extract_findings(parse_nmap_xml(SAMPLE))
    titles = " | ".join(f["title"] for f in findings)
    assert "CVE-2017-5638" in titles
    vuln = next(f for f in findings if "cve2017-5638" in f["title"])
    assert vuln["severity"] == "critical"    # CVSS 10.0
    assert any("Weak TLS" in f["title"] and f["severity"] == "medium" for f in findings)


def test_no_findings_when_clean():
    clean = """<nmaprun><host><status state="up"/>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="80"><state state="open"/>
    <service name="http"/></port></ports></host></nmaprun>"""
    assert extract_findings(parse_nmap_xml(clean)) == []
