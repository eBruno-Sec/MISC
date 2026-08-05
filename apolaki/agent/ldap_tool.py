"""LDAP injection engine (CWE-90), distilled from *Beginner Web Application Pentester* (Ali Abdollahi,
"Testing for LDAP injection"). Apps that authenticate or look users up against a directory build an LDAP
search filter by concatenating input, e.g. `(&(uid=USER)(userPassword=PASS))`. Unsanitised input lets an
attacker inject filter metacharacters ( ) * & | ! and break or subvert the filter.

CONFIRMATION IS LDAP-SPECIFIC — the same discipline as the XPath engine. A stray metacharacter breaks many
things (SQL, XPath, a generic 500), so a bare status change or boolean split does NOT prove LDAP and would
collide with SQLi/XPath. We confirm ONLY when the response leaks an LDAP DIRECTORY error signature
(javax.naming / JNDI / OpenLDAP / AD / ldap_* C-API) that an unbalanced filter provoked but the baseline did
not — content-based, like the SQLi DBMS-error and XPath-processor-error oracles. Precise over greedy.

Pure logic here (payloads + LDAP-error oracle + finding); the HTTP transport lives in tools.
"""
from __future__ import annotations

import re


def probes(orig: str) -> dict:
    """Filter-metacharacter breaks: an unbalanced parenthesis / stray operator makes the LDAP filter
    un-parseable, so a directory that concatenates input emits a filter/parse error."""
    o = orig or ""
    return {"paren": o + ")", "star_group": o + "*)(", "amp": o + "(", "pipe": o + "|("}


# Error signatures emitted by real LDAP stacks — present in a broken-filter response, absent from a normal
# one AND from SQL/XPath errors (which their own engines own). This is what makes the finding LDAP-SPECIFIC.
LDAP_ERRORS = [
    r"javax\.naming\.NamingException", r"javax\.naming\.directory", r"com\.sun\.jndi\.ldap",
    r"LDAPException", r"LDAP:\s*error code\s*\d+", r"error code 3\d\s*-\s*", r"Invalid DN syntax",
    r"Bad search filter", r"Protocol error", r"Object class violation", r"Invalid filter",
    r"ldap_search(?:_[a-z]+)?\(\)", r"ldap_(?:bind|modify|add|result)\(\)",
    r"supplied argument is not a valid ldap", r"AcceptSecurityContext error",
    r"System\.DirectoryServices", r"DirectoryServicesCOMException", r"OpenLDAP",
    r"IntStringPair", r"NDS error", r"Filter error", r"unbalanced parentheses",
]
_LDAP_RE = [re.compile(p, re.IGNORECASE) for p in LDAP_ERRORS]


def ldap_error(body: str) -> str:
    """The first LDAP-directory error signature in `body`, or '' — the confirming signal."""
    b = body or ""
    for rx in _LDAP_RE:
        m = rx.search(b)
        if m:
            return m.group(0)[:80]
    return ""


def evaluate(baseline_body: str, probe_body: str) -> dict:
    """Confirmed ONLY when a metacharacter break makes an LDAP-directory error appear that was NOT in the
    baseline. A generic 500 or a SQL/XPath error does NOT confirm (that would collide with those engines)."""
    sig = ldap_error(probe_body)
    if sig and not ldap_error(baseline_body):
        return {"confirmed": True, "oracle": "an LDAP directory error signature appeared after an unbalanced "
                "filter break ('%s') — the input is concatenated into an LDAP search filter" % sig}
    return {"confirmed": False, "oracle": ""}


def finding(url: str, param: str, where: str, oracle: str) -> dict:
    return {
        "title": "LDAP injection in %s '%s'" % (where, param),
        "severity": "high", "family": "ldap_injection", "confidence": "confirmed", "target": url,
        "cwe": "CWE-90", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "cvss_score": 8.2,
        "evidence": "The %s '%s' is concatenated into an LDAP search filter. %s" % (where, param, oracle),
        "success_oracle": oracle,
        "reproduction_steps": ["Send a request with an unbalanced filter metacharacter in '%s' (e.g. `)` or `*)(`)" % param,
                               "Observe an LDAP directory error in the response (the search filter broke)",
                               "Escalate on an LDAP-backed login with a filter tautology `*)(uid=*))(|(uid=*`"],
        "impact": ("LDAP injection lets an attacker subvert the directory query to bypass authentication (filter "
                   "tautology), enumerate directory objects, or read attributes they should not see."),
        "remediation": ("Escape LDAP filter metacharacters per RFC 4515 (use the platform's LDAP encoder), bind "
                        "with parameterised filters, and validate input against a strict allowlist."),
        "tags": ["ldap", "injection", "cwe-90"],
    }
