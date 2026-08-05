"""Reflected XSS through POST FORM fields (general): the GET-query XSS engine (xss_tool) misses a whole
class — a value submitted in a POST form that reflects into the response (e.g. a login form's username
echoed into `var username = '<HERE>'`). This module parses forms, builds a submit body that fills every
field (echoing hidden/CSRF tokens so the POST is accepted) with a canary/payload in ONE text field, and
reuses xss_tool's context+breakout analysis to decide exploitability. Browser confirmation (fill + submit +
alert) lives in tools; this module is pure (parse + body-build + candidate reasoning)."""
from __future__ import annotations

import re
from html import unescape
from urllib.parse import urljoin

import xss_tool as xt

# fields we never fuzz (submit buttons, file inputs, hidden CSRF tokens) / never treat as injection point
_SKIP_TYPES = ("submit", "button", "reset", "file", "image", "checkbox", "radio", "hidden")
# a plausible default so required fields (email/password) don't reject the submit before reflection
_DEFAULTS = {"email": "a@b.co", "password": "Aa1!aaaa", "tel": "1", "number": "1", "url": "http://a.co"}


def parse_forms(html: str, base_url: str) -> list:
    """Extract POST forms: {action, method, fields:{name:value}, text_fields:[names]}. Hidden inputs (CSRF
    tokens) are captured with their value so the submit is accepted; text-ish inputs are the fuzz targets."""
    forms = []
    for fm in re.finditer(r"<form\b([^>]*)>(.*?)</form>", html or "", re.S | re.I):
        attrs, inner = fm.group(1), fm.group(2)
        # attribute values may be quoted OR unquoted (real-world forms use both) — the [^"'\s>] class
        # captures an unquoted value up to whitespace/>, and the optional quotes handle the quoted case.
        method = (re.search(r'method\s*=\s*["\']?(\w+)', attrs, re.I) or [None, "get"])[1].lower()
        if method != "post":
            continue
        action = (re.search(r"""action\s*=\s*["']?([^"'\s>]*)""", attrs, re.I) or [None, ""])[1]
        fields, text_fields = {}, []
        for tag in re.finditer(r"<(input|textarea|select)\b([^>]*)>", inner, re.I):
            a = tag.group(2)
            name = (re.search(r"""name\s*=\s*["']?([^"'\s>]+)""", a, re.I) or [None, None])[1]
            if not name:
                continue
            itype = (re.search(r'type\s*=\s*["\']?([\w-]+)', a, re.I) or [None, "text"])[1].lower()
            val = (re.search(r"""value\s*=\s*["']?([^"'\s>]*)""", a, re.I) or [None, ""])[1]
            fields[name] = unescape(val)
            if itype in _SKIP_TYPES:
                continue
            if not fields[name]:
                fields[name] = _DEFAULTS.get(itype, "")
            text_fields.append(name)
        if text_fields:
            forms.append({"action": urljoin(base_url, action) if action else base_url,
                          "method": "post", "fields": fields, "text_fields": text_fields})
    return forms


def body_with(form: dict, field: str, value: str) -> dict:
    """A submit dict = every field filled (tokens echoed), with `field` set to `value`."""
    body = dict(form["fields"])
    body[field] = value
    return body


def reflection_context(resp_body: str, canary: str = xt.CANARY) -> str:
    """First HTML/JS context the canary reflects into (via xss_tool). '' if it does not reflect."""
    ctxs = xt.contexts_of(resp_body, canary)
    return ctxs[0] if ctxs else ""


def exploitable_breakout(resp_body: str, context: str) -> bool:
    """Reuse xss_tool: the context's breakout survives unescaped AND re-classifies to the same context."""
    return xt.reflected_exploitable(resp_body, context)


def finding(action: str, field: str, context: str, payload: str, evidence: str, confirmed_by_browser: bool) -> dict:
    label = "confirmed" if confirmed_by_browser else "candidate"
    sev = "high" if confirmed_by_browser else "medium"
    return {
        "title": "Reflected XSS via POST field '%s'" % field,
        "severity": sev, "family": "reflected_xss", "confidence": label, "target": action,
        "cwe": "CWE-79", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "cvss_score": 6.1,
        "evidence": evidence,
        "success_oracle": ("a payload submitted in the POST field '%s' executed in a real browser (alert fired)"
                           % field) if confirmed_by_browser else
                          ("the POST field '%s' reflects into a %s context with the structural characters "
                           "unescaped (breakout survived)" % (field, context)),
        "reproduction_steps": ["Submit the form at %s with '%s' set to the payload" % (action, field),
                               "Payload: %s" % payload,
                               "Observe it execute / reflect unescaped in the %s context" % context],
        "impact": "Execute script in victims' browsers: session/CSRF-token theft, account takeover.",
        "remediation": "Context-encode reflected values (HTML/JS/attribute); never emit user input inside a "
                       "JavaScript string without JS-encoding; add a strict Content-Security-Policy.",
        "tags": ["xss", "reflected", "post-form"],
    }
