"""XPath injection engine (CWE-643) — distilled from *Beginner Web Application Pentester* (Ali Abdollahi,
"Testing for XPath injection"). Apps that authenticate/search against an XML document build an XPath query
by concatenating user input (e.g. //users/user[username/text()='USER' and password/text()='PASS']).

CONFIRMATION IS XPATH-SPECIFIC. An exposed processor error remains proof. A silent processor gets an
XPath-only `count(/*)=1` predicate and its otherwise identical contradiction `count(/*)=0`, accepted only
when application semantics change (authenticated state, protected controls, or a strict record-set
superset). Status, response size, and error text do not participate in that boolean decision.

Pure logic here (payloads + XPath-error oracle + finding); the HTTP transport lives in tools.
"""
from __future__ import annotations

import re

import semantic_differential as sd

# quote-break probes (single- and double-quoted XPath string contexts) + an XPath-function break. Any of
# these, in a value concatenated into an XPath expression, provokes a parser error from the XPath engine.
def probes(orig: str) -> dict:
    o = orig or ""
    return {"sq": o + "'", "dq": o + '"', "fn": o + "']|//*['"}


def boolean_pairs(orig: str) -> list:
    """XPath-specific truth/contradiction pairs for silent processors.

    Every XML document has exactly one document element, so count(/*)=1 is true and count(/*)=0 is a
    contradiction. The payload shape is otherwise identical, and the XPath-only count(/*) expression avoids
    claiming an ordinary SQL boolean split as XPath.
    """
    o = orig or "apolaki"
    return [
        {"name": "single_quote",
         "true": o + "' or count(/*)=1 or '1'='2",
         "false": o + "' or count(/*)=0 or '1'='2"},
        {"name": "double_quote",
         "true": o + '" or count(/*)=1 or "1"="2',
         "false": o + '" or count(/*)=0 or "1"="2'},
    ]


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


def evaluate_boolean(true_body: str, false_body: str, true_payload: str, false_payload: str) -> dict:
    ev = sd.evaluate(true_body, false_body, true_payload, false_payload)
    if not ev["confirmed"]:
        return {"confirmed": False, "oracle": ""}
    return {"confirmed": True,
            "oracle": ("an XPath-specific boolean differential split on count(/*)=1 versus the otherwise "
                       "identical contradiction count(/*)=0; %s" % ev["oracle"])}


def finding(url: str, param: str, where: str, oracle: str) -> dict:
    return {
        "title": "XPath injection in %s '%s'" % (where, param),
        "severity": "high", "family": "xpath_injection", "confidence": "confirmed", "target": url,
        "cwe": "CWE-643", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "cvss_score": 8.2,
        "evidence": "The %s '%s' is concatenated into an XPath query over an XML document. %s" % (where, param, oracle),
        "success_oracle": oracle,
        "reproduction_steps": ["Send the recorded XPath probe in '%s'" % param,
                               "Replay its structurally identical contradiction as a negative control",
                               "Confirm the recorded processor error or semantic auth/record-set split"],
        "impact": ("XPath injection lets an attacker read any part of the backing XML document (XPath has no "
                   "per-node ACLs) and, on XML-backed login forms, bypass authentication via a tautology."),
        "remediation": ("Never build XPath from string concatenation; use parameterized XPath / precompiled "
                        "expressions with variable binding, and validate/encode input."),
        "tags": ["xpath", "injection", "cwe-643"],
    }
