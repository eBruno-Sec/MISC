"""
Passive DNS intelligence + subdomain-takeover detection.

Uses DNS-over-HTTPS (dns.google) so no resolver binary is required. The parsing
and fingerprint-matching logic is pure and deterministic (unit-tested); only the
DoH fetch touches the network. Populates the recon context so the guidance
engine's email (SPF/DMARC), CAA, and takeover rules fire. Adapted from OLYMPUS
HERMES.
"""
from __future__ import annotations

import re
import sys as _sys                       # I-5: reach the orchestrator's swallow ledger without
                                         # importing it (tools imports dns_recon, never the reverse)

DOH_URL = "https://dns.google/resolve"
_RTYPE = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}


# ── deterministic parsers ────────────────────────────────────────
def _unquote_txt(data: str) -> str:
    return (data or "").strip().strip('"').replace('" "', "")


def parse_spf(txts: list) -> str:
    for t in txts:
        v = _unquote_txt(t)
        if v.lower().startswith("v=spf1"):
            return v
    return ""


def parse_dmarc(txts: list) -> str:
    for t in txts:
        v = _unquote_txt(t)
        if v.lower().startswith("v=dmarc1"):
            return v
    return ""


# vendor fingerprints keyed off TXT verification records
VENDOR_TXT_PATTERNS = {
    "stripe-verification": "Stripe",
    "google-site-verification": "Google Workspace",
    "atlassian-domain-verification": "Atlassian",
    "docusign": "DocuSign",
    "facebook-domain-verification": "Meta/Facebook",
    "MS=": "Microsoft 365",
    "adobe-idp-site-verification": "Adobe",
    "zoom-verify": "Zoom",
    "okta-verification": "Okta",
    "amazonses": "Amazon SES",
    "sendgrid": "SendGrid",
    "mailgun": "Mailgun",
}


def vendors_from_txt(txts: list) -> list:
    found = []
    for t in txts:
        v = _unquote_txt(t)
        for pat, name in VENDOR_TXT_PATTERNS.items():
            if pat.lower() in v.lower() and name not in found:
                found.append(name)
    return found


# ── subdomain takeover fingerprints (curated from can-i-take-over-xyz) ──
TAKEOVER_FINGERPRINTS = [
    {"service": "GitHub Pages", "cname": ("github.io", "githubusercontent"),
     "body": ("There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html"),
     "severity": "CRITICAL"},
    {"service": "Amazon S3", "cname": ("amazonaws.com", "s3.amazonaws"),
     "body": ("NoSuchBucket", "The specified bucket does not exist"), "severity": "CRITICAL"},
    {"service": "Heroku", "cname": ("herokuapp.com", "herokudns.com"),
     "body": ("No such app", "There's nothing here, yet.", "herokucdn.com/error-pages/no-such-app.html"),
     "severity": "CRITICAL"},
    {"service": "Fastly", "cname": ("fastly.net",),
     "body": ("Fastly error: unknown domain",), "severity": "CRITICAL"},
    {"service": "Shopify", "cname": ("myshopify.com",),
     "body": ("Sorry, this shop is currently unavailable", "Only one step left!"), "severity": "HIGH"},
    {"service": "Surge.sh", "cname": ("surge.sh",),
     "body": ("project not found",), "severity": "CRITICAL"},
    {"service": "Zendesk", "cname": ("zendesk.com",),
     "body": ("Help Center Closed",), "severity": "HIGH"},
    {"service": "Pantheon", "cname": ("pantheonsite.io",),
     "body": ("The gods are wise", "404 error unknown site"), "severity": "HIGH"},
    {"service": "Tumblr", "cname": ("domains.tumblr.com",),
     "body": ("Whatever you were looking for doesn't currently exist at this address",), "severity": "HIGH"},
    {"service": "Ghost", "cname": ("ghost.io",),
     "body": ("The thing you were looking for is no longer here",), "severity": "HIGH"},
    {"service": "Cargo", "cname": ("cargocollective.com",),
     "body": ("404 Not Found",), "severity": "MEDIUM"},
    {"service": "Netlify", "cname": ("netlify.app", "netlify.com"),
     "body": ("Not Found - Request ID",), "severity": "HIGH"},
]


def match_takeover(subdomain: str, cname: str, status: int, body: str) -> dict | None:
    """Return a takeover candidate if a dangling-CNAME provider fingerprint hits.

    A hit needs BOTH the CNAME pointing at a known provider AND the provider's
    'unclaimed' error signature in the response body (or a 404 with the provider
    CNAME). Pure and deterministic — the caller does the fetch."""
    cl = (cname or "").lower()
    bl = (body or "").lower()
    for fp in TAKEOVER_FINGERPRINTS:
        if not any(c in cl for c in fp["cname"]):
            continue
        body_hit = any(sig.lower() in bl for sig in fp["body"])
        if body_hit:
            return {"subdomain": subdomain, "service": fp["service"], "cname": cname,
                    "severity": fp["severity"],
                    "reason": f"CNAME -> {fp['service']} ({cname}); response shows unclaimed-resource signature"}
        if status == 404:
            return {"subdomain": subdomain, "service": fp["service"], "cname": cname,
                    "severity": "HIGH",
                    "reason": f"CNAME -> {fp['service']} ({cname}); 404 (possible dangling record, verify manually)"}
    return None


# ── async DoH fetch + aggregation ────────────────────────────────
async def doh(name: str, rtype: str, timeout: int = 12) -> list:
    """Query dns.google over HTTPS; return the list of answer `data` strings."""
    import httpx
    t = _RTYPE.get(rtype.upper(), 1)
    try:
        async with httpx.AsyncClient(verify=True, timeout=timeout,
                                     headers={"accept": "application/dns-json"}) as c:
            r = await c.get(DOH_URL, params={"name": name, "type": t})
            data = r.json()
    except Exception as _apolaki_exc:
        # I-5: [] is also "this name has no records of that type", which is precisely the
        # answer a subdomain-takeover or SPF/DMARC check reads as a healthy zone.  A DoH
        # transport failure must not be able to certify a domain as clean.
        _tools = _sys.modules.get("tools")
        if _tools is not None:
            _tools._swallow(_apolaki_exc, "dns_recon.doh", "%s/%s" % (name, rtype))
        return []
    return [a.get("data", "") for a in (data.get("Answer") or []) if a.get("type") == t]


def is_junk_host(host: str) -> bool:
    """True for hosts that are DNS/parsing ARTIFACTS, not real scan targets: an SOA RNAME
    (the zone's email contact, e.g. hostmaster.example.com) misread as a subdomain, or a name
    mangled by re-querying an RNAME as a host (hostmaster.hostmaster.hostmaster.example). These
    are never real web hosts — targeting them only burns budget and fills the ledger with scope
    blocks. Conservative on purpose: a plausible real subdomain (www / mail / mx1 / api / admin)
    is NEVER flagged; only self-repeating labels and the tight SOA-contact label set are."""
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return True
    labels = h.split(".")
    for i in range(len(labels) - 1):          # a repeated CONSECUTIVE label = a re-query artifact
        if labels[i] and labels[i] == labels[i + 1]:
            return True
    # a leftmost label that is a DNS SOA-RNAME contact convention (never a served web host)
    return labels[0] in ("hostmaster", "postmaster", "dnsadmin", "dnsmaster", "dns-admin")


async def gather_dns(domain: str) -> dict:
    """Collect A/NS/MX/TXT/CAA + SPF/DMARC + vendors for a registrable domain."""
    domain = (domain or "").lstrip("*.").split(":")[0]
    a = await doh(domain, "A")
    ns = await doh(domain, "NS")
    mx = await doh(domain, "MX")
    txt = await doh(domain, "TXT")
    caa = await doh(domain, "CAA")
    dmarc_txt = await doh("_dmarc." + domain, "TXT")
    return {
        "dns": {"a": a, "ns": ns, "mx": mx, "txt": txt},
        "email": {"spf": parse_spf(txt), "dmarc": parse_dmarc(dmarc_txt)},
        "caa_records": caa,
        "vendors": vendors_from_txt(txt),
    }


async def resolve_cname(host: str) -> str:
    ans = await doh(host, "CNAME")
    return (ans[0].rstrip(".") if ans else "")


# ── IP / ASN / NetRange (scope expansion, Ch 5) ──────────────────
def parse_cymru_asn(txt: str) -> dict:
    """Parse a Team Cymru origin TXT record: 'ASN | BGP prefix | CC | RIR | date'."""
    parts = [p.strip() for p in (txt or "").strip('"').split("|")]
    if len(parts) < 2:
        return {}
    return {"asn": parts[0], "prefix": parts[1],
            "country": parts[2] if len(parts) > 2 else "",
            "registry": parts[3] if len(parts) > 3 else ""}


def parse_cymru_asname(txt: str) -> str:
    """Parse 'ASN | CC | RIR | date | AS-NAME' -> the AS name."""
    parts = [p.strip() for p in (txt or "").strip('"').split("|")]
    return parts[-1] if parts else ""


async def asn_lookup(ip: str) -> dict:
    """IP -> ASN + BGP prefix (CIDR range) + AS name, via Team Cymru over DoH."""
    octets = ip.split(".")
    if len(octets) != 4:
        return {}
    rev = ".".join(reversed(octets)) + ".origin.asn.cymru.com"
    txt = await doh(rev, "TXT")
    info = parse_cymru_asn(txt[0]) if txt else {}
    if info.get("asn"):
        asn = info["asn"].split()[0]
        name_txt = await doh(f"AS{asn}.asn.cymru.com", "TXT")
        if name_txt:
            info["as_name"] = parse_cymru_asname(name_txt[0])
    return info


async def ip_intel(domain: str) -> dict:
    """Resolve a domain to its IP(s) and enrich the primary IP with ASN/range/org."""
    domain = (domain or "").lstrip("*.").split(":")[0]
    a = await doh(domain, "A")
    ips = [x for x in a if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", x)]
    out = {"domain": domain, "ips": ips, "asn": {}}
    if ips:
        out["asn"] = await asn_lookup(ips[0])
    return out
