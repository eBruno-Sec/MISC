"""
Service fingerprint -> technique-pack routing (beyond web).

Apolaki routes testing by DISCOVERED SERVICE TYPE, not by running every scanner blindly. A
fingerprint (port + banner + transport) selects the matching technique PACK; the pack declares
which checks apply, what asset-graph node kind the service is, and what each check could UNLOCK.
Results feed the SAME canonical asset graph (asset_graph.py) + deterministic oracles — not a pile
of disconnected scanners.

Pure: fingerprinting + pack lookup only, unit-tested. The actual probes live in per-service drivers
that call route()/pack_for() to decide WHAT to run, then write findings/leads + graph nodes.
"""
from __future__ import annotations

import re

# well-known TCP/UDP port -> service type (the fallback when no banner is available)
_PORT_SVC = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 69: "tftp", 80: "http", 110: "pop3",
    111: "rpcbind", 135: "msrpc", 137: "netbios", 139: "netbios", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "smb", 465: "smtp", 512: "rexec", 513: "rlogin",
    514: "syslog", 587: "smtp", 623: "ipmi", 636: "ldap", 873: "rsync", 993: "imap",
    995: "pop3", 1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker", 2379: "etcd",
    3128: "proxy", 3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc", 5985: "winrm",
    6379: "redis", 8080: "http", 8443: "https", 9000: "http", 9200: "elasticsearch",
    9300: "elasticsearch", 10250: "kubelet", 11211: "memcached", 27017: "mongodb",
    502: "modbus",                                   # ICS/OT — Modbus/TCP (read-only audit)
    123: "ntp",                                       # NTP — monlist/amplification (read-only)
}

# banner signature -> service type (a banner OVERRIDES the port guess when present)
_BANNER_SVC = [
    (re.compile(r"^SSH-", re.I), "ssh"),
    (re.compile(r"ftp|vsftpd|proftpd|filezilla|pure-ftpd", re.I), "ftp"),
    (re.compile(r"(e?smtp|postfix|exim|sendmail)", re.I), "smtp"),
    (re.compile(r"redis_version|(-ERR|(\+PONG))", re.I), "redis"),
    (re.compile(r"mysql|mariadb", re.I), "mysql"),
    (re.compile(r"mongodb", re.I), "mongodb"),
    (re.compile(r"elasticsearch|\"cluster_name\"", re.I), "elasticsearch"),
    (re.compile(r"memcached|STAT pid", re.I), "memcached"),
    (re.compile(r"^220.*imap|dovecot", re.I), "imap"),
    (re.compile(r"HTTP/1\.[01]|Server:\s", re.I), "http"),
]

# a check declares its deterministic oracle + what a confirmation UNLOCKS (feeds the asset graph).
# intrusive checks are only run in Full mode by the driver. NONE brute-forces credentials.
_PACKS = {
    "dns": {"graph_kind": "service", "note": "DNS zone/record intelligence.", "checks": [
        {"id": "dns_zone_transfer", "cwe": "CWE-200", "intrusive": False,
         "oracle": "AXFR returns more than the SOA (a full zone) from a public resolver",
         "enables": ["subdomain_inventory"]},
        {"id": "dns_subdomain_takeover", "cwe": "CWE-350", "intrusive": False,
         "oracle": "a CNAME points to an unclaimed provider host (dangling delegation)", "enables": []},
    ]},
    "ftp": {"graph_kind": "service", "note": "FTP exposure / anonymous access.", "checks": [
        {"id": "ftp_anonymous", "cwe": "CWE-425", "intrusive": False,
         "oracle": "USER anonymous is accepted (230) — anonymous file access", "enables": ["arbitrary_file_read"]},
    ]},
    "smtp": {"graph_kind": "service", "note": "SMTP relay / user-enumeration / mail auth policy.", "checks": [
        {"id": "smtp_open_relay", "cwe": "CWE-269", "intrusive": True,
         "oracle": "MAIL FROM + RCPT TO for a foreign domain is accepted (relays third-party mail)", "enables": []},
        {"id": "smtp_user_enum", "cwe": "CWE-203", "intrusive": False,
         "oracle": "VRFY/EXPN/RCPT differentiates existing vs unknown users", "enables": ["user_enumeration"]},
        {"id": "smtp_spf_dmarc", "cwe": "CWE-290", "intrusive": False,
         "oracle": "no SPF/DMARC record for the sending domain (spoofable)", "enables": []},
    ]},
    "ssh": {"graph_kind": "service", "note": "SSH crypto/version audit (read-only handshake, no credential attack).", "checks": [
        {"id": "ssh_weak_crypto", "cwe": "CWE-326", "intrusive": False,
         "oracle": "the server's KEXINIT advertises weak KEX/cipher/MAC/host-key algorithms", "enables": []},
    ]},
    "snmp": {"graph_kind": "service", "note": "SNMP community/config exposure.", "checks": [
        {"id": "snmp_default_community", "cwe": "CWE-1188", "intrusive": False,
         "oracle": "a default community string (public/private) returns management data", "enables": ["config_read"]},
    ]},
    "smb": {"graph_kind": "service", "note": "SMB shares / signing / service intel.", "checks": [
        {"id": "smb_null_session", "cwe": "CWE-287", "intrusive": False,
         "oracle": "a null session lists shares", "enables": ["arbitrary_file_read"]},
        {"id": "smb_signing_disabled", "cwe": "CWE-347", "intrusive": False,
         "oracle": "message signing is not required (relay-able)", "enables": []},
    ]},
    "ldap": {"graph_kind": "service", "note": "LDAP/AD directory anonymous-read exposure.", "checks": [
        {"id": "ldap_anonymous_read", "cwe": "CWE-306", "intrusive": False,
         "oracle": "an anonymous bind can read directory entries from the naming context (not just RootDSE)",
         "enables": ["directory_read", "user_enumeration"]},
    ]},
    "modbus": {"graph_kind": "service", "note": "ICS/OT: unauthenticated Modbus/TCP device (READ-ONLY audit; never writes).", "checks": [
        {"id": "modbus_exposed", "cwe": "CWE-306", "intrusive": False,
         "oracle": "an unauthenticated Modbus device answers a read-only request (device-id / read-holding)",
         "enables": ["ot_read"]},
    ]},
    "vnc": {"graph_kind": "service", "note": "Remote desktop: unauthenticated VNC (READ-ONLY handshake).", "checks": [
        {"id": "vnc_no_auth", "cwe": "CWE-306", "intrusive": False,
         "oracle": "the RFB handshake advertises security type 'None' (no password required)",
         "enables": ["remote_control"]},
    ]},
    "rsync": {"graph_kind": "service", "note": "File sync: anonymous rsync module enumeration (READ-ONLY).", "checks": [
        {"id": "rsync_anon", "cwe": "CWE-306", "intrusive": False,
         "oracle": "an anonymous '#list' returns the daemon's module names", "enables": ["file_read"]},
    ]},
    "ntp": {"graph_kind": "service", "note": "Time: NTP monlist amplification/disclosure (READ-ONLY query).", "checks": [
        {"id": "ntp_monlist", "cwe": "CWE-406", "intrusive": False,
         "oracle": "the server answers the ntpdc monlist (mode 7) request (CVE-2013-5211)", "enables": []},
    ]},
    "redis": {"graph_kind": "service", "note": "Unauthenticated data store.", "checks": [
        {"id": "redis_no_auth", "cwe": "CWE-306", "intrusive": False,
         "oracle": "INFO/PING succeeds without AUTH (open data store)", "enables": ["database_read"]},
    ]},
    "mongodb": {"graph_kind": "service", "note": "Unauthenticated data store.", "checks": [
        {"id": "mongodb_no_auth", "cwe": "CWE-306", "intrusive": False,
         "oracle": "listDatabases succeeds without authentication", "enables": ["database_read"]},
    ]},
    "elasticsearch": {"graph_kind": "service", "note": "Open search cluster.", "checks": [
        {"id": "elastic_open", "cwe": "CWE-306", "intrusive": False,
         "oracle": "GET /_cat/indices returns indices without auth", "enables": ["database_read"]},
    ]},
    "memcached": {"graph_kind": "service", "note": "Unauthenticated cache (amplification risk).", "checks": [
        {"id": "memcached_open", "cwe": "CWE-306", "intrusive": False,
         "oracle": "stats returns without auth (also UDP-amplification exposure)", "enables": ["config_read"]},
    ]},
    "docker": {"graph_kind": "service", "note": "Exposed container control plane.", "checks": [
        {"id": "docker_api_open", "cwe": "CWE-306", "intrusive": False,
         "oracle": "GET /version + /containers/json succeed without auth", "enables": ["internal_request"]},
    ]},
    "kubelet": {"graph_kind": "service", "note": "Exposed kubelet API.", "checks": [
        {"id": "kubelet_open", "cwe": "CWE-306", "intrusive": False,
         "oracle": "GET /pods returns workload data without auth", "enables": ["internal_request"]},
    ]},
}

# service types that are actually web servers -> hand back to the existing web engine, not a pack.
_WEB = {"http", "https"}


def fingerprint(port: int = None, banner: str = "", transport: str = "tcp") -> str:
    """Classify a service. A banner wins over the port; falls back to the well-known port map;
    'unknown' when neither identifies it."""
    b = (banner or "").strip()
    if b:
        for rx, svc in _BANNER_SVC:
            if rx.search(b):
                return svc
    try:
        p = int(port) if port is not None else None
    except Exception:
        p = None
    if p in _PORT_SVC:
        return _PORT_SVC[p]
    return "unknown"


def is_web(service_type: str) -> bool:
    return service_type in _WEB


def pack_for(service_type: str) -> dict:
    """The technique pack for a service type (empty dict if none / web / unknown)."""
    return _PACKS.get(service_type, {})


def route(services: list) -> list:
    """Map discovered services -> routing decisions. Each input service is {host, port, banner?,
    transport?}. Returns [{host, port, service, is_web, pack, checks}] — the driver runs the pack's
    checks (non-web) or defers to the web engine (is_web)."""
    out = []
    for s in services or []:
        svc = fingerprint(s.get("port"), s.get("banner", ""), s.get("transport", "tcp"))
        pack = pack_for(svc)
        out.append({"host": s.get("host", ""), "port": s.get("port"), "service": svc,
                    "is_web": is_web(svc), "pack": pack, "checks": pack.get("checks", [])})
    return out


def plan(services: list, full_mode: bool = False) -> list:
    """Concrete ordered test plan from discovered services. Web services are excluded (the web engine
    owns them); intrusive checks are included ONLY in Full mode. Each item is ready for a per-service
    driver to execute and record against its oracle."""
    out = []
    for r in route(services):
        if r["is_web"] or r["service"] == "unknown":
            continue
        for c in r["checks"]:
            if c.get("intrusive") and not full_mode:
                continue
            out.append({"host": r["host"], "port": r["port"], "service": r["service"],
                        "check": c["id"], "cwe": c["cwe"], "oracle": c["oracle"],
                        "enables": c.get("enables", []), "intrusive": bool(c.get("intrusive"))})
    return out


_NMAP_RX = re.compile(r"\s*(\d+)/(tcp|udp)\s+open\s+(\S+)?\s*(.*)", re.I)

# nmap's own service NAME is authoritative — map it to our service types as a fallback.
_NMAP_NAME_MAP = {
    "http": "http", "https": "https", "ssl/http": "https", "http-proxy": "http", "domain": "dns",
    "microsoft-ds": "smb", "netbios-ssn": "smb", "ms-wbt-server": "rdp", "ms-sql-s": "mssql",
    "mysql": "mysql", "postgresql": "postgres", "redis": "redis", "ftp": "ftp", "ssh": "ssh",
    "smtp": "smtp", "snmp": "snmp", "imap": "imap", "pop3": "pop3", "telnet": "telnet",
    "mongodb": "mongodb", "docker": "docker", "rpcbind": "rpcbind", "ldap": "ldap",
    "elasticsearch": "elasticsearch", "memcached": "memcached",
}


def parse_nmap_ports(open_ports, host: str = "") -> list:
    """Parse nmap open-port lines ('6379/tcp open redis 7.0.0') into routed service dicts
    [{host, port, service, banner}] — the bridge from a port scan to service-pack execution.
    Uses banner > port > nmap's own service NAME (authoritative fallback)."""
    out = []
    for line in (open_ports or []):
        m = _NMAP_RX.match(str(line))
        if not m:
            continue
        port = int(m.group(1))
        name = (m.group(3) or "").lower()
        banner = (name + " " + (m.group(4) or "")).strip()
        svc = fingerprint(port, banner)
        if svc == "unknown":
            svc = _NMAP_NAME_MAP.get(name, "unknown")
        out.append({"host": host, "port": port, "service": svc, "banner": banner})
    return out


def known_services() -> list:
    """Service types Apolaki has a technique pack for (for the UI/report coverage view)."""
    return sorted(_PACKS.keys())
