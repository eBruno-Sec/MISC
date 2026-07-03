"""
PERCIVAL  //  Phase 1 — Passive Recon
DNS, WHOIS, crt.sh subdomains, HTTP headers, email security,
SSL cert info, tech stack fingerprinting.
All passive. No packets sent to target.
"""

import json
import re
import ssl
import socket
import urllib.request
import urllib.parse
import urllib.error
import datetime
from pathlib import Path

R="\033[91m"; Y="\033[93m"; G="\033[92m"; C="\033[96m"; B="\033[94m"; BOLD="\033[1m"; RST="\033[0m"

def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)

def ok(m):  print(f"  {G}[+]{RST} {m}")
def info(m):print(f"  {C}[*]{RST} {m}")
def warn(m):print(f"  {Y}[!]{RST} {m}")
def err(m): print(f"  {R}[-]{RST} {m}")

# ─── HTTP HELPERS ──────────────────────────────────────────────────────────────
def http_get(url, timeout=8, retries=2):
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Mozilla/5.0 (RoundTable/1.0 passive-recon)")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.read().decode("utf-8", errors="ignore"), None
        except urllib.error.HTTPError as e:
            return None, f"http_{e.code}"
        except socket.timeout:
            continue
        except urllib.error.URLError as e:
            reason = str(e.reason).lower()
            if any(x in reason for x in ["nodename","no such host","name or service"]):
                return None, "dns"
            return None, "connection"
        except Exception:
            return None, "unknown"
    return None, "timeout"

def http_head(url, timeout=8, retries=2):
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, method="HEAD")
            req.add_header("User-Agent", "Mozilla/5.0 (RoundTable/1.0 passive-recon)")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return dict(r.headers), r.status, r.url, None
        except urllib.error.HTTPError as e:
            return dict(e.headers), e.code, url, None
        except socket.timeout:
            continue
        except Exception as e:
            return None, None, None, str(e)
    return None, None, None, "timeout"

# ─── DNS ───────────────────────────────────────────────────────────────────────
def dns_query(name, rtype, timeout=6):
    url = f"https://dns.google/resolve?name={urllib.parse.quote(name)}&type={rtype}"
    raw, _ = http_get(url, timeout=timeout)
    if not raw:
        return []
    try:
        data = json.loads(raw)
        return [r["data"] for r in data.get("Answer", [])]
    except:
        return []

# ─── WHOIS / RDAP ──────────────────────────────────────────────────────────────
def rdap_whois(domain):
    raw, _ = http_get(f"https://rdap.org/domain/{domain}")
    if not raw:
        return {}
    try:
        d = json.loads(raw)
        result = {}
        ent = next((e for e in d.get("entities",[]) if "registrar" in e.get("roles",[])), None)
        if ent:
            vcard = ent.get("vcardArray",[[],[]])[1]
            fn_entry = next((v for v in vcard if v[0]=="fn"), None)
            result["registrar"] = fn_entry[3] if fn_entry else ent.get("handle","N/A")
        else:
            result["registrar"] = "N/A"
        for event in d.get("events",[]):
            act = event.get("eventAction","")
            dt  = event.get("eventDate","N/A")[:10]
            if act == "registration": result["created"]  = dt
            if act == "expiration":   result["expires"]  = dt
            if act == "last changed": result["updated"]  = dt
        result["nameservers"] = [ns.get("ldhName","") for ns in d.get("nameservers",[])]
        result["status"]      = d.get("status",[])
        remarks = d.get("remarks",[])
        result["privacy_redacted"] = any(
            "redacted" in str(r).lower() or "privacy" in str(r).lower() for r in remarks
        )
        if not next((e for e in d.get("entities",[]) if "registrant" in e.get("roles",[])), None):
            result["privacy_redacted"] = True
        return result
    except:
        return {}

# ─── CERT TRANSPARENCY ─────────────────────────────────────────────────────────
def crtsh_subdomains(domain):
    raw, _ = http_get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=20)
    if not raw:
        return [], []
    try:
        data = json.loads(raw)
        names, wildcards = set(), set()
        for entry in data:
            for name in entry.get("name_value","").split("\n"):
                name = name.strip().lower()
                if not name.endswith(domain):
                    continue
                if name.startswith("*."):
                    wildcards.add(name)
                else:
                    names.add(name)
        return sorted(names), sorted(wildcards)
    except:
        return [], []

# ─── SSL CERT ──────────────────────────────────────────────────────────────────
def ssl_cert_info(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issued_to  = dict(x[0] for x in cert.get("subject",[]))
                issued_by  = dict(x[0] for x in cert.get("issuer",[]))
                not_after  = cert.get("notAfter","")
                not_before = cert.get("notBefore","")
                san = [v for t,v in cert.get("subjectAltName",[]) if t=="DNS"]
                try:
                    exp = datetime.datetime.strptime(not_after,"%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                    days_left = (exp - utcnow()).days
                except:
                    days_left = None
                return {
                    "issued_to":  issued_to.get("commonName","N/A"),
                    "issued_by":  issued_by.get("organizationName","N/A"),
                    "valid_from": not_before,
                    "valid_until":not_after,
                    "days_left":  days_left,
                    "san":        san[:15],
                }
    except ssl.SSLCertVerificationError as e:
        return {"error": f"SSL verification failed: {e}"}
    except Exception as e:
        return {"error": str(e)}

# ─── VENDOR FINGERPRINTING ─────────────────────────────────────────────────────
TXT_VENDORS = [
    ("paloaltonetworks-site-verification","Palo Alto Networks","Security","CRITICAL"),
    ("duo_sso_verification","Duo Security (MFA)","Security/Identity","CRITICAL"),
    ("bugcrowd-verification","Bugcrowd","Bug Bounty","CRITICAL"),
    ("hackerone-verification","HackerOne","Bug Bounty","CRITICAL"),
    ("intigriti-verification","Intigriti","Bug Bounty","CRITICAL"),
    ("synack-verification","Synack","Bug Bounty","CRITICAL"),
    ("safebreach-domain-verification","SafeBreach","Security","CRITICAL"),
    ("knowbe4","KnowBe4","Security Training","CRITICAL"),
    ("censys-domain-verification","Censys","Attack Surface Mgmt","CRITICAL"),
    ("cloudflare_dashboard_sso","Cloudflare","CDN/Identity","HIGH"),
    ("atlassian-domain-verification","Atlassian","Productivity","HIGH"),
    ("hcp-domain-verification","HashiCorp","Infrastructure","HIGH"),
    ("jamf-site-verification","Jamf MDM","Device Mgmt","HIGH"),
    ("docker-verification","Docker Hub","Infrastructure","HIGH"),
    ("Dynatrace-site-verification","Dynatrace APM","Monitoring","HIGH"),
    ("ms-domain-verification","Microsoft 365","Productivity","MEDIUM"),
    ("google-site-verification","Google Workspace","Productivity","MEDIUM"),
    ("notion-domain-verification","Notion","Productivity","MEDIUM"),
    ("teamviewer-sso-verification","TeamViewer","Remote Access","MEDIUM"),
    ("logmein-verification","LogMeIn","Remote Access","MEDIUM"),
    ("postman-domain-verification","Postman","Dev Tools","MEDIUM"),
    ("openai-domain-verification","OpenAI","AI","MEDIUM"),
    ("salesforce","Salesforce","CRM","LOW"),
    ("hubspotemail","HubSpot","CRM","LOW"),
    ("stripe-verification","Stripe","Payments","LOW"),
    ("docusign","DocuSign","Legal","LOW"),
    ("adobe-idp-site-verification","Adobe","Productivity","LOW"),
    ("facebook-domain-verification","Facebook","Social","LOW"),
]

SPF_VENDORS = [
    ("_spf.google.com","Google Workspace","Email","MEDIUM"),
    ("spf.protection.outlook.com","Microsoft 365","Email","MEDIUM"),
    ("ppe-hosted.com","Proofpoint","Email Security","HIGH"),
    ("pphosted.com","Proofpoint","Email Security","HIGH"),
    ("knowbe4.com","KnowBe4","Security Training","CRITICAL"),
    ("sendgrid.net","SendGrid","Email","LOW"),
    ("amazonses.com","Amazon SES","Email","LOW"),
    ("mailchimp.com","Mailchimp","Email","LOW"),
    ("salesforce.com","Salesforce","CRM","LOW"),
    ("hubspotemail.net","HubSpot","CRM","LOW"),
]

MX_VENDORS = [
    ("aspmx.l.google.com","Google Workspace","Email"),
    ("mail.protection.outlook.com","Microsoft 365","Email"),
    ("ppe-hosted.com","Proofpoint","Email Security"),
    ("pphosted.com","Proofpoint","Email Security"),
    ("mxlogin.com","Proofpoint Essentials","Email Security"),
    ("mx.zoho.com","Zoho Mail","Email"),
]

def fingerprint_vendors(txt_records, spf_raw, mx_records):
    vendors = {}
    all_txt = " ".join(txt_records).lower()
    for pat, name, cat, rv in TXT_VENDORS:
        if pat.lower() in all_txt:
            vendors[name] = {"name":name,"cat":cat,"rv":rv,"source":"TXT"}
    if spf_raw:
        spf_l = spf_raw.lower()
        for pat, name, cat, rv in SPF_VENDORS:
            if pat.lower() in spf_l:
                vendors[name] = {"name":name,"cat":cat,"rv":rv,"source":"SPF"}
    for mx in mx_records:
        mx_l = mx.lower()
        for pat, name, cat in MX_VENDORS:
            if pat in mx_l:
                vendors[name] = {"name":name,"cat":cat,"rv":"MEDIUM","source":"MX"}
    return list(vendors.values())

# ─── SECURITY HEADERS ──────────────────────────────────────────────────────────
SECURITY_HEADERS = [
    ("strict-transport-security","HSTS","HIGH","Enforce HTTPS. Without it SSL stripping is possible."),
    ("content-security-policy","CSP","HIGH","No CSP significantly increases XSS attack surface."),
    ("x-frame-options","X-Frame-Options","MEDIUM","Site may be embeddable in iframes (clickjacking risk)."),
    ("x-content-type-options","X-Content-Type-Options","MEDIUM","MIME sniffing may lead to XSS."),
    ("referrer-policy","Referrer-Policy","LOW","Referrer headers may leak URLs to third parties."),
    ("permissions-policy","Permissions-Policy","LOW","No browser feature restriction (camera, mic, geo)."),
]

def check_headers(domain):
    result = {"ok": False, "headers": {}, "status": None, "is_https": False, "error": None}
    hdrs, status, final_url, error = http_head(f"https://{domain}")
    if hdrs is None:
        hdrs, status, final_url, error = http_head(f"http://{domain}")
        result["error"] = error
    if hdrs:
        result["ok"]       = True
        result["status"]   = status
        result["is_https"] = bool(final_url and final_url.startswith("https://"))
        result["headers"]  = {k.lower(): v for k,v in hdrs.items()}
        result["final_url"]= final_url
    return result

# ─── EMAIL SECURITY ────────────────────────────────────────────────────────────
DKIM_SELECTORS = [
    "default","selector1","selector2","google","k1","k2","k3",
    "s1","s2","mx","smtp","mail","email","pm","postmark",
    "dkim","dkim1","dkim2","pic","scph0816","scph1220",
]

def check_email_security(domain, txt_records):
    spf    = [t for t in txt_records if "v=spf1" in t.lower()]
    dmarc  = dns_query(f"_dmarc.{domain}", "TXT")
    bimi   = dns_query(f"default._bimi.{domain}", "TXT")
    dkim_found = []
    for sel in DKIM_SELECTORS:
        r = dns_query(f"{sel}._domainkey.{domain}", "TXT")
        if r:
            dkim_found.append({"selector": sel, "value": r[0][:120]})
    return {
        "spf":    spf[0] if spf else None,
        "dmarc":  dmarc[0] if dmarc else None,
        "bimi":   bimi[0] if bimi else None,
        "dkim":   dkim_found,
        "selectors_checked": DKIM_SELECTORS,
    }

# ─── SUBDOMAIN CLASSIFICATION ──────────────────────────────────────────────────
SUB_CATS = [
    ("CI/CD & DevOps","CRITICAL",["jenkins","gitlab","drone","travis","circleci","teamcity","bamboo","buildkite","argocd","artifactory","nexus","sonar","harbor","devops"]),
    ("Security Infrastructure","CRITICAL",["vpn","sso","adfs","idp","iam","mfa","auth","saml","okta","ping","keycloak","clearpass","radius","pki"]),
    ("Admin & Management","HIGH",["admin","manage","mgmt","portal","cpanel","plesk","phpmyadmin","rancher","kibana","grafana","prometheus","tableau","splunk","jira","confluence"]),
    ("Exposed Dev/Test","MEDIUM",["dev","staging","test","qa","uat","sandbox","demo","beta","preview","preprod","canary","stage","stg","sit","lab"]),
    ("Data & Storage","MEDIUM",["db","database","sql","mongo","redis","elastic","backup","archive","ftp","sftp","storage","vault"]),
    ("Payment & Financial","HIGH",["payment","billing","pay","invoice","tokenizer","finance"]),
    ("Communication","LOW",["mail","webmail","smtp","imap","pop","autodiscover","lyncdiscover","sip","voip"]),
]

def classify_sub(name, domain):
    sub   = name.replace(f".{domain}","").lower()
    parts = sub.split(".")
    for cat, sev, patterns in SUB_CATS:
        for p in patterns:
            if any(pt == p or pt.startswith(p) or pt.endswith(p) for pt in parts):
                return cat, sev
    return "Other", "INFO"

# ─── MAIN ──────────────────────────────────────────────────────────────────────
def run_percival(domain, run_dir, cfg):
    run_dir = Path(run_dir)
    data    = {"domain": domain}

    # 1. WHOIS
    info("WHOIS via RDAP...")
    data["whois"] = rdap_whois(domain)
    if data["whois"]:
        ok(f"Registrar: {data['whois'].get('registrar','N/A')}  Expires: {data['whois'].get('expires','N/A')}")
    else:
        warn("WHOIS unavailable")

    # 2. DNS Records
    info("DNS records (A, AAAA, MX, NS, TXT, CAA)...")
    data["a_records"]    = dns_query(domain, "A")
    data["aaaa_records"] = dns_query(domain, "AAAA")
    data["mx_records"]   = dns_query(domain, "MX")
    data["ns_records"]   = dns_query(domain, "NS")
    data["txt_records"]  = dns_query(domain, "TXT")
    data["caa_records"]  = dns_query(domain, "CAA")
    spf_raw = next((t for t in data["txt_records"] if "v=spf1" in t.lower()), None)
    data["spf_raw"]      = spf_raw
    ok(f"A: {data['a_records']}  MX: {len(data['mx_records'])} records  NS: {len(data['ns_records'])} records")

    # 3. Email Security
    info("Email security (SPF, DMARC, DKIM, BIMI)...")
    data["email"] = check_email_security(domain, data["txt_records"])
    ok(f"SPF: {'found' if data['email']['spf'] else 'MISSING'}  DMARC: {'found' if data['email']['dmarc'] else 'MISSING'}  DKIM selectors found: {len(data['email']['dkim'])}")

    # 4. HTTP Headers
    info("HTTP security headers...")
    data["http"] = check_headers(domain)
    if data["http"]["ok"]:
        h = data["http"]["headers"]
        present = sum(1 for n,_,_,_ in SECURITY_HEADERS if n in h)
        ok(f"HTTP {data['http']['status']}  HTTPS: {data['http']['is_https']}  Security headers present: {present}/{len(SECURITY_HEADERS)}")
    else:
        warn(f"HTTP header inspection failed: {data['http']['error']}")

    # 5. SSL Cert
    info("SSL certificate...")
    data["ssl"] = ssl_cert_info(domain)
    if "error" not in data["ssl"]:
        ok(f"Issued by: {data['ssl']['issued_by']}  Expires in: {data['ssl'].get('days_left','?')} days")
    else:
        warn(f"SSL: {data['ssl']['error']}")

    # 6. Subdomains via crt.sh
    info("Subdomain enumeration via crt.sh...")
    subs, wildcards = crtsh_subdomains(domain)
    data["subdomains"]  = subs
    data["wildcards"]   = wildcards
    data["sub_cats"]    = {}
    for s in subs:
        cat, sev = classify_sub(s, domain)
        if cat not in data["sub_cats"]:
            data["sub_cats"][cat] = []
        data["sub_cats"][cat].append({"name": s, "severity": sev})
    ok(f"Found {len(subs)} subdomains, {len(wildcards)} wildcards")

    # 7. Tech Stack
    info("Tech stack fingerprinting...")
    data["vendors"] = fingerprint_vendors(data["txt_records"], spf_raw, data["mx_records"])
    ok(f"Vendors detected: {len(data['vendors'])}")
    for v in [x for x in data["vendors"] if x["rv"] in ("CRITICAL","HIGH")]:
        warn(f"  [{v['rv']}] {v['name']} ({v['cat']})")

    # Save raw JSON
    out = run_dir / "percival_raw.json"
    out.write_text(json.dumps(data, indent=2, default=str))
    ok(f"Percival raw data saved: {out}")

    # Save subdomain list for Galahad
    sub_file = run_dir / "subdomains.txt"
    sub_file.write_text("\n".join(subs))
    ok(f"Subdomain list saved: {sub_file} ({len(subs)} entries)")

    return data
