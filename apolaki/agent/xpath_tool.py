"""XPath injection engine (CWE-643) — distilled from *Beginner Web Application Pentester* (Ali Abdollahi,
"Testing for XPath injection"). Apps that authenticate/search against an XML document build an XPath query
by concatenating user input (e.g. //users/user[username/text()='USER' and password/text()='PASS']).

CONFIRMATION IS XPATH-SPECIFIC — this is the whole point. A stray quote breaks MANY things (SQL, LDAP, a
generic 500), so a bare status-class change or a boolean split does NOT prove XPath and would collide with
SQLi (mis-labelling a SQLi endpoint as XPath). We therefore confirm ONLY when the response leaks an XPath
PROCESSOR error signature (Saxon/libxml2/.NET/Jaxen/javax.xml.xpath ...) that a stray quote produced but
the baseline did not — content-based, the same discipline the SQLi engine uses for DBMS errors. Precise
over greedy: better to miss a silent XPath sink than to cry "XPath" on a SQLi bug.

Pure logic here (payloads + XPath-error oracle + finding); the HTTP transport lives in tools.
"""
from __future__ import annotations

import re

# quote-break probes (single- and double-quoted XPath string contexts) + an XPath-function break. Any of
# these, in a value concatenated into an XPath expression, provokes a parser error from the XPath engine.
def probes(orig: str) -> dict:
    o = orig or ""
    return {"sq": o + "'", "dq": o + '"', "fn": o + "']|//*['"}


# error signatures emitted by common XPath processors — present in a broken-XPath response, absent from a
# normal one and from a SQL error (which the SQLi engine owns). This is what makes the finding XPath-SPECIFIC.
XPATH_ERRORS = [
    r"XPathException", r"javax\.xml\.xpath", r"XPST\d{4}", r"XPTY\d{4}", r"FORG\d{4}", r"err:XP",
    r"xmlXPath(?:Eval|CompOpEval|Compile)", r"Invalid XPath", r"XPath syntax error", r"unclosed token",
    r"expression must evaluate to a node[- ]?set", r"System\.Xml\.XPath\.XPathException", r"org\.jaxen",
    r"net\.sf\.saxon", r"MS\.Internal\.Xml", r"A location step was expected",
    r"Expected token '.*' (?:in|at) XPath", r"SimpleXMLElement::xpath", r"DOMXPath::query",
    r"unterminated string literal.*xpath", r"XPathEvalError",
]
_XPATH_RE = [re.compile(p, re.IGNORECASE) for p in XPATH_ERRORS]


def xpath_error(body: str) -> str:
    """The first XPath-processor error signature found in `body`, or '' — the confirming signal."""
    b = body or ""
    for rx in _XPATH_RE:
        m = rx.search(b)
        if m:
            return m.group(0)[:80]
    return ""


def evaluate(baseline_body: str, probe_body: str) -> dict:
    """Confirmed ONLY when a quote/function break makes an XPath-processor error appear that was NOT in the
    baseline. A generic 500 or a SQL error does NOT confirm (that would collide with SQLi)."""
    sig = xpath_error(probe_body)
    if sig and not xpath_error(baseline_body):
        return {"confirmed": True, "oracle": "XPath-processor error signature appeared after a quote/function "
                "break ('%s') — the input is concatenated into an XPath expression" % sig}
    return {"confirmed": False, "oracle": ""}


def finding(url: str, param: str, where: str, oracle: str) -> dict:
    return {
        "title": "XPath injection in %s '%s'" % (where, param),
        "severity": "high", "family": "xpath_injection", "confidence": "confirmed", "target": url,
        "cwe": "CWE-643", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "cvss_score": 8.2,
        "evidence": "The %s '%s' is concatenated into an XPath query over an XML document. %s" % (where, param, oracle),
        "success_oracle": oracle,
        "reproduction_steps": ["Send a request with a stray quote in '%s'" % param,
                               "Observe an XPath-processor error in the response (the query broke)",
                               "Escalate with an XPath tautology (' or '1'='1) against an XML-backed login"],
        "impact": ("XPath injection lets an attacker read any part of the backing XML document (XPath has no "
                   "per-node ACLs) and, on XML-backed login forms, bypass authentication via a tautology."),
        "remediation": ("Never build XPath from string concatenation; use parameterized XPath / precompiled "
                        "expressions with variable binding, and validate/encode input."),
        "tags": ["xpath", "injection", "cwe-643"],
    }
