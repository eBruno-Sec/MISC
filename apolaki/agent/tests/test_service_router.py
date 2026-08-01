"""Service fingerprint -> technique-pack routing (pure). Beyond-web: a discovered service type
selects the matching technique pack, and web services defer to the existing web engine."""
from __future__ import annotations

import service_router as SR


def test_fingerprint_by_port():
    assert SR.fingerprint(port=53) == "dns"
    assert SR.fingerprint(port=21) == "ftp"
    assert SR.fingerprint(port=6379) == "redis"
    assert SR.fingerprint(port=8080) == "http"
    assert SR.fingerprint(port=9999) == "unknown"


def test_banner_overrides_port():
    # a banner is stronger evidence than the port number
    assert SR.fingerprint(port=8080, banner="SSH-2.0-OpenSSH_8.9") == "ssh"
    assert SR.fingerprint(port=12345, banner="220 mx1 ESMTP Postfix") == "smtp"
    assert SR.fingerprint(port=12345, banner="redis_version:7.0.0") == "redis"


def test_pack_declares_oracles_and_enables():
    dns = SR.pack_for("dns")
    ids = {c["id"] for c in dns["checks"]}
    assert "dns_zone_transfer" in ids
    ftp = SR.pack_for("ftp")
    anon = ftp["checks"][0]
    assert anon["cwe"] == "CWE-425" and "arbitrary_file_read" in anon["enables"]
    assert SR.pack_for("http") == {}          # web is handled by the web engine, not a pack
    assert SR.pack_for("unknown") == {}


def test_route_web_vs_pack():
    services = [
        {"host": "t", "port": 443},                       # web -> defer to web engine
        {"host": "t", "port": 21},                        # ftp -> ftp pack
        {"host": "t", "port": 25, "banner": "220 ESMTP"},  # smtp -> smtp pack
    ]
    routed = {r["service"]: r for r in SR.route(services)}
    assert routed["https"]["is_web"] is True and routed["https"]["checks"] == []
    assert routed["ftp"]["is_web"] is False and any(c["id"] == "ftp_anonymous" for c in routed["ftp"]["checks"])
    assert routed["smtp"]["checks"]


def test_known_services_listed():
    ks = SR.known_services()
    for s in ("dns", "ftp", "smtp", "ssh", "snmp", "smb", "redis"):
        assert s in ks
    assert "http" not in ks                    # not a pack — web engine owns it


def test_plan_gates_intrusive_to_full_mode():
    services = [{"host": "t", "port": 25, "banner": "220 ESMTP"}, {"host": "t", "port": 443}]
    active = SR.plan(services, full_mode=False)
    full = SR.plan(services, full_mode=True)
    assert not any(p["check"] == "smtp_open_relay" for p in active)   # intrusive -> Full only
    assert any(p["check"] == "smtp_open_relay" for p in full)
    assert any(p["check"] == "smtp_user_enum" for p in active)        # non-intrusive -> both
    assert all(p["service"] != "https" for p in full)                # web excluded from the plan


def test_no_check_brute_forces_credentials():
    # guardrail: no pack check should be a credential-guessing loop
    for svc in SR.known_services():
        for c in SR.pack_for(svc)["checks"]:
            oracle = c["oracle"].lower()
            assert "brute" not in oracle and "password list" not in oracle and "wordlist" not in oracle
