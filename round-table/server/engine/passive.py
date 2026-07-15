"""
Passive recon (Percival).

Public-data only: DNS-over-HTTPS, crt.sh certificate transparency, RDAP WHOIS,
HTTP HEAD, TLS certificate inspection, vendor fingerprinting. No packets that a
target would consider a scan.
"""
from pathlib import Path

import percival as P  # from knights/ (see engine.__init__ path setup)

from ..core.scope import split_host_port


def run_passive(target: str, run_dir: Path, log) -> dict:
    # Domain-oriented lookups use the host only; the HTTP probe keeps any port
    # so local apps like juice-shop:3000 are reachable.
    host, port = split_host_port(target)
    data: dict = {"target": target, "domain": host, "port": port}

    log("WHOIS via RDAP", phase="passive")
    data["whois"] = P.rdap_whois(host)
    w = data["whois"]
    if w:
        log(f"registrar={w.get('registrar','N/A')} expires={w.get('expires','N/A')}", "ok", "passive")

    log("DNS records (A/AAAA/MX/NS/TXT/CAA)", phase="passive")
    data["a_records"] = P.dns_query(host, "A")
    data["aaaa_records"] = P.dns_query(host, "AAAA")
    data["mx_records"] = P.dns_query(host, "MX")
    data["ns_records"] = P.dns_query(host, "NS")
    data["txt_records"] = P.dns_query(host, "TXT")
    data["caa_records"] = P.dns_query(host, "CAA")
    spf_raw = next((t for t in data["txt_records"] if "v=spf1" in t.lower()), None)
    data["spf_raw"] = spf_raw
    log(f"A={data['a_records']}  MX={len(data['mx_records'])}  NS={len(data['ns_records'])}  CAA={'yes' if data['caa_records'] else 'none'}", "ok", "passive")

    log("Email security (SPF/DMARC/DKIM/BIMI)", phase="passive")
    data["email"] = P.check_email_security(host, data["txt_records"])
    em = data["email"]
    log(f"SPF={'set' if em.get('spf') else 'MISSING'}  DMARC={'set' if em.get('dmarc') else 'MISSING'}  DKIM={len(em.get('dkim',[]))}", "ok", "passive")

    log("HTTP security headers", phase="passive")
    data["http"] = P.check_headers(target)  # keep host:port for the live app
    if data["http"].get("ok"):
        h = data["http"]["headers"]
        present = sum(1 for n, *_ in P.SECURITY_HEADERS if n in h)
        log(f"HTTP {data['http'].get('status')}  HTTPS={data['http'].get('is_https')}  headers {present}/{len(P.SECURITY_HEADERS)}", "ok", "passive")
    else:
        log(f"header inspection failed: {data['http'].get('error')}", "warn", "passive")

    log("TLS certificate", phase="passive")
    data["ssl"] = P.ssl_cert_info(host)
    if "error" not in data["ssl"]:
        log(f"issued_by={data['ssl'].get('issued_by','?')}  days_left={data['ssl'].get('days_left','?')}", "ok", "passive")

    log("Subdomains via crt.sh", phase="passive")
    subs, wildcards = P.crtsh_subdomains(host)
    data["subdomains"] = subs
    data["wildcards"] = wildcards
    data["sub_cats"] = {}
    for s in subs:
        cat, sev = P.classify_sub(s, host)
        data["sub_cats"].setdefault(cat, []).append({"name": s, "severity": sev})
    log(f"{len(subs)} subdomains, {len(wildcards)} wildcards", "ok", "passive")

    log("Vendor fingerprinting", phase="passive")
    data["vendors"] = P.fingerprint_vendors(data["txt_records"], spf_raw, data["mx_records"])
    hi = [v for v in data["vendors"] if v.get("rv") in ("CRITICAL", "HIGH")]
    log(f"{len(data['vendors'])} vendors ({len(hi)} high-value)", "ok", "passive")

    return data
