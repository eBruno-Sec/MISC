"""
Parse nmap XML (-oX) into structured results and turn NSE script output into
findings — the difference between "nmap ran" and an nmap a professional reads.

Pure and deterministic (no I/O): Tyr runs nmap, this module extracts hosts,
ports/services/versions, OS guesses, and NSE script output, and promotes
vuln-script hits (VULNERABLE / CVE) and weak-TLS results to findings.
"""
import re
import xml.etree.ElementTree as ET

_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)
_CVSS_RE = re.compile(r"CVSS(?:v\d)?\s*[:=]?\s*(\d+(?:\.\d+)?)", re.I)
# ssl-enum-ciphers grades each cipher A–F and flags weak protocols.
_WEAK_TLS = ("sslv2", "sslv3", "tlsv1.0", "tlsv1.1")


def parse_nmap_xml(xml_text: str) -> dict:
    """Return {ip: {status, os, ports: [{port, proto, state, service, product,
    version, scripts: {id: output}}], hostscripts: {id: output}}}."""
    out = {}
    if not xml_text or "<" not in xml_text:
        return out
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out

    for host in root.findall("host"):
        addr = ""
        for a in host.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr") or ""
                break
        if not addr:
            continue
        st = host.find("status")
        status = st.get("state") if st is not None else ""

        os_guess = ""
        osel = host.find("os")
        if osel is not None:
            m = osel.find("osmatch")
            if m is not None:
                os_guess = m.get("name", "")

        ports = []
        portsel = host.find("ports")
        if portsel is not None:
            for p in portsel.findall("port"):
                pstate = p.find("state")
                if pstate is None or pstate.get("state") != "open":
                    continue
                svc = p.find("service")
                ports.append({
                    "port": int(p.get("portid", "0") or 0),
                    "proto": p.get("protocol", "tcp"),
                    "state": "open",
                    "service": (svc.get("name") if svc is not None else "") or "",
                    "product": (svc.get("product") if svc is not None else "") or "",
                    "version": (svc.get("version") if svc is not None else "") or "",
                    "scripts": {s.get("id"): (s.get("output") or "") for s in p.findall("script")},
                })

        hostscripts = {}
        hs = host.find("hostscript")
        if hs is not None:
            for s in hs.findall("script"):
                hostscripts[s.get("id")] = s.get("output") or ""

        out[addr] = {"status": status, "os": os_guess, "ports": ports, "hostscripts": hostscripts}
    return out


def _severity_from(output: str) -> tuple[str, float]:
    up = output.upper()
    m = _CVSS_RE.search(output)
    if m:
        try:
            score = float(m.group(1))
            if score >= 9.0:
                return "critical", score
            if score >= 7.0:
                return "high", score
            if score >= 4.0:
                return "medium", score
            return "low", score
        except ValueError:
            pass
    if "CRITICAL" in up:
        return "critical", 9.5
    return "high", 7.5


def extract_findings(parsed: dict) -> list:
    """Promote NSE vuln-script hits and weak-TLS results to finding dicts."""
    findings = []

    def add(host, port, sid, output):
        low = output.lower()
        is_vuln = ("vuln" in (sid or "").lower() and "VULNERABLE" in output) or _CVE_RE.search(output)
        if is_vuln:
            sev, cvss = _severity_from(output)
            cves = ", ".join(sorted(set(m.group(0).upper() for m in _CVE_RE.finditer(output))))
            where = f"{host}:{port}" if port else host
            findings.append({
                "host": host, "port": port, "script": sid,
                "title": f"nmap {sid}: vulnerable service on {where}" + (f" ({cves})" if cves else ""),
                "severity": sev, "cvss": cvss,
                "description": ("An nmap NSE vulnerability script flagged this service as vulnerable. "
                                "Confirm and prioritize against the referenced CVE(s)."),
                "evidence": output.strip()[:1200],
                "remediation": "Patch/upgrade the affected service to a fixed version and restrict its exposure.",
            })
        elif sid == "ssl-enum-ciphers" and any(w in low for w in _WEAK_TLS):
            proto = next((w.upper() for w in _WEAK_TLS if w in low), "legacy TLS")
            findings.append({
                "host": host, "port": port, "script": sid,
                "title": f"Weak TLS configuration on {host}:{port} ({proto})",
                "severity": "medium", "cvss": 5.3,
                "description": "The service negotiates a deprecated SSL/TLS protocol or weak cipher suite.",
                "evidence": output.strip()[:1000],
                "remediation": "Disable SSLv2/SSLv3/TLS1.0/1.1 and weak ciphers; require TLS 1.2+ with modern suites.",
            })

    for host, info in parsed.items():
        for p in info.get("ports", []):
            for sid, output in (p.get("scripts") or {}).items():
                add(host, p.get("port"), sid, output)
        for sid, output in (info.get("hostscripts") or {}).items():
            add(host, None, sid, output)
    return findings
