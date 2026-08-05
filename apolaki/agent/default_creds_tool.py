"""Default-credentials analyzer (WAHH ch18, "Attacking the Application Server", CWE-1392 / CWE-521 / WSTG-ATHN-02).
A dropped-in admin interface (Tomcat Manager, JBoss jmx-console, ...) shipped with a documented DEFAULT login that
the operator never changed is one of the highest-impact real-world findings — Tomcat Manager with tomcat:tomcat is a
straight path to RCE (deploy a WAR). Apolaki fingerprints + discovers these interfaces but never checked the default.

NOT A BRUTE-FORCE. This is the explicitly-allowed 'single known value' case: for each RECOGNISED product interface we
try exactly ONE documented vendor-default pair — never a wordlist, never iteration against an account, never more than
one attempt per interface. The pair is bound to a specific product path + confirmed by a product-specific
authenticated marker, so a changed credential (401/403) or a different app yields nothing. The engine only engages a
URL that ALREADY issued an HTTP Basic challenge (401 WWW-Authenticate) — an open, no-auth interface is a *different*
finding (exposure), not default-creds. Pure logic here (match + confirm + finding); the caller performs the two GETs."""
from __future__ import annotations

# product -> exactly ONE documented default pair + the marker that proves an authenticated view was returned.
# Reference data (world knowledge, like a Nuclei default-login template), NOT target-specific hardcoding.
KNOWN_DEFAULTS = [
    {"product": "Apache Tomcat Manager", "paths": ["/manager/html"], "user": "tomcat", "pass": "tomcat",
     "markers": ["Tomcat Web Application Manager", "Application Manager"], "impact_rce": True},
    {"product": "Apache Tomcat Host Manager", "paths": ["/host-manager/html"], "user": "tomcat", "pass": "tomcat",
     "markers": ["Tomcat Virtual Host Manager", "Host Manager"], "impact_rce": True},
    {"product": "JBoss/WildFly jmx-console", "paths": ["/jmx-console/", "/jmx-console"], "user": "admin", "pass": "admin",
     "markers": ["JMX Agent View", "MBean", "jboss.system"], "impact_rce": True},
]


def match(path: str):
    """The KNOWN_DEFAULTS entry whose product interface this path is, else None (so we only ever try a default
    against the specific product it belongs to — never a generic guess)."""
    p = (path or "").rstrip("/").lower() or "/"
    for entry in KNOWN_DEFAULTS:
        for sig in entry["paths"]:
            if p == sig.rstrip("/").lower():
                return entry
    return None


def challenged(unauth_status: int, unauth_headers: dict) -> bool:
    """True only when the interface demanded HTTP Basic auth (401 + WWW-Authenticate: Basic) — the precondition
    for a default-creds test. A 200 (open) or a form login is out of scope for this Basic-auth engine."""
    if int(unauth_status or 0) != 401:
        return False
    www = " ".join(str(v) for k, v in (unauth_headers or {}).items() if k.lower() == "www-authenticate")
    return "basic" in www.lower()


def confirmed(authed_status: int, authed_body: str, entry: dict) -> bool:
    """The single default pair authenticated: a 200 whose body carries the product's authenticated-view marker.
    A 401/403 (credential changed) or a body without the marker is NOT confirmed."""
    if int(authed_status or 0) != 200:
        return False
    body = authed_body or ""
    return any(m.lower() in body.lower() for m in entry["markers"])


def finding(url: str, entry: dict) -> dict:
    rce = entry.get("impact_rce")
    return {
        "title": "Default administrative credentials on %s" % entry["product"],
        "severity": "critical" if rce else "high", "family": "default_credentials", "confidence": "confirmed",
        "target": url, "cwe": "CWE-1392",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if rce
                       else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "cvss_score": 9.8 if rce else 7.5,
        "evidence": ("%s at '%s' still accepts its documented default login. A single known vendor-default pair "
                     "authenticated and returned the product's admin view%s."
                     % (entry["product"], url, " — which permits remote code execution (e.g. WAR deploy)" if rce else "")),
        "success_oracle": "the default pair returned HTTP 200 with the '%s' admin marker" % entry["markers"][0],
        "reproduction_steps": [
            "Request %s with no credentials — the interface issues an HTTP Basic 401 challenge." % url,
            "Retry with the product's documented default credentials.",
            "The admin console loads (HTTP 200, '%s') — the default was never changed." % entry["markers"][0]],
        "impact": ("Full administrative control of %s%s." % (entry["product"],
                   "; on Tomcat/JBoss this is typically remote code execution via application deployment" if rce else "")),
        "remediation": ("Change or disable the default account immediately; restrict the management interface to "
                        "trusted networks and require strong, unique credentials."),
        "tags": ["default-credentials", "cwe-1392", "wstg-athn-02", entry["product"].split()[0].lower()],
    }
