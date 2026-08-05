"""Two deterministic, non-destructive client/config checks that close honest WSTG coverage gaps surfaced by
the coverage engine: reverse tabnabbing (WSTG-CLNT-14, CWE-1022) and a permissive cross-domain policy
(WSTG-CONF-08, CWE-942). Both confirm from CONTENT alone (page HTML / the policy file), so no runtime and no
side effects. Honest severity: modern browsers default rel=noopener and Flash/Silverlight are retired, so
these are LOW/MEDIUM and the remediation says so — but the misconfiguration is really present, so we report
it rather than hide it. Pure logic here; the HTTP fetches live in tools."""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

_A_TAG = re.compile(r"<a\b([^>]*)>", re.I)
_ATTR = lambda a, name: (re.search(r'%s\s*=\s*["\']?([^"\'>\s]+)' % name, a, re.I) or [None, ""])[1]


def _origin(u: str) -> str:
    p = urlparse(u)
    return "%s://%s" % (p.scheme, p.netloc)


def reverse_tabnabbing(html: str, base_url: str) -> list:
    """`<a target="_blank" href="EXTERNAL">` links that lack rel=noopener/noreferrer — the opened page can
    rewrite window.opener.location (phishing). Returns the offending external hrefs (deduped)."""
    base_origin = _origin(base_url)
    out, seen = [], set()
    for m in _A_TAG.finditer(html or ""):
        attrs = m.group(1)
        if (_ATTR(attrs, "target") or "").lower() != "_blank":
            continue
        href = _ATTR(attrs, "href")
        if not href or href.startswith(("#", "javascript:", "mailto:")):
            continue
        full = urljoin(base_url, href)
        if not full.startswith(("http://", "https://")) or _origin(full) == base_origin:
            continue                                    # only cross-origin targets can abuse window.opener
        rel = (_ATTR(attrs, "rel") or "").lower()
        if "noopener" in rel or "noreferrer" in rel:
            continue
        if full not in seen:
            seen.add(full)
            out.append(full)
    return out[:10]


def tabnabbing_finding(url: str, links: list) -> dict:
    return {
        "title": "Reverse tabnabbing — target=_blank link without rel=noopener",
        "severity": "low", "family": "reverse_tabnabbing", "confidence": "confirmed", "target": url,
        "cwe": "CWE-1022", "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N", "cvss_score": 3.4,
        "evidence": ("%d cross-origin link(s) open with target=\"_blank\" and no rel=\"noopener\"/\"noreferrer\" "
                     "(e.g. %s). The opened page receives a live window.opener and can navigate this tab to a "
                     "phishing clone." % (len(links), ", ".join(links[:3]))),
        "success_oracle": "a target=_blank link to a different origin lacks rel=noopener/noreferrer (deterministic in the page HTML)",
        "reproduction_steps": ["Open the page and locate the flagged external target=_blank link(s).",
                               "From an attacker-controlled destination, run `window.opener.location='https://phish'`.",
                               "The original tab silently navigates to the attacker page."],
        "impact": "An externally-linked page can redirect the user's original tab to a credential-phishing clone.",
        "remediation": ("Add rel=\"noopener noreferrer\" to every target=_blank link (or a global "
                        "Referrer-Policy + Cross-Origin-Opener-Policy). Modern browsers default noopener, so "
                        "the residual risk is older browsers and embedded webviews."),
        "tags": ["reverse-tabnabbing", "client-side", "cwe-1022"],
    }


_CROSSDOMAIN_WILDCARD = re.compile(r"<allow-access-from\b[^>]*\bdomain\s*=\s*[\"']\*[\"']", re.I)
_CAP_WILDCARD = re.compile(r"<domain\b[^>]*\buri\s*=\s*[\"']\*[\"']", re.I)


def crossdomain_wildcard(policy_xml: str, filename: str) -> bool:
    """True if a Flash crossdomain.xml (allow-access-from domain="*") or a Silverlight clientaccesspolicy.xml
    (<domain uri="*">) grants access to ANY origin — a permissive cross-domain policy."""
    body = policy_xml or ""
    if "clientaccesspolicy" in filename:
        return bool(_CAP_WILDCARD.search(body))
    return bool(_CROSSDOMAIN_WILDCARD.search(body))


def crossdomain_finding(url: str, filename: str) -> dict:
    return {
        "title": "Permissive cross-domain policy (%s allows any origin)" % filename,
        "severity": "medium", "family": "permissive_crossdomain", "confidence": "confirmed", "target": url,
        "cwe": "CWE-942", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N", "cvss_score": 5.8,
        "evidence": ("%s grants cross-origin access with a wildcard (domain=\"*\"), so any Flash/Silverlight "
                     "app on any site could make credentialed requests to this origin and read the responses." % filename),
        "success_oracle": "the served %s contains a wildcard allow-access rule (deterministic file content)" % filename,
        "reproduction_steps": ["GET /%s from the target." % filename,
                               "Observe the wildcard allow-access-from domain=\"*\" (or <domain uri=\"*\">).",
                               "A hosted Flash/Silverlight object on any origin could read authenticated responses."],
        "impact": ("Any origin's rich-internet-application code can read this site's authenticated responses "
                   "(cross-origin data theft) — the CORS-equivalent hole for the legacy Flash/Silverlight stack."),
        "remediation": ("Restrict allow-access-from to the specific trusted origins (never domain=\"*\"), or remove "
                        "the policy file entirely if no Flash/Silverlight client needs it (both are end-of-life)."),
        "tags": ["cross-domain-policy", "config", "cwe-942"],
    }
