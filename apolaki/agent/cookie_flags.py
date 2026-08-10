"""Session cookie sent without the Secure attribute (CWE-614).

Decided from the RAW `Set-Cookie` header and nothing else. Three tempting shortcuts are all wrong:

  - response prose. A page can say "the secure flag is false" while the header sets Secure, and the
    reverse. The body is marketing; the header is the contract.
  - the browser cookie jar. By the time a jar has normalised things, per-field identity is gone and a
    cookie rejected for unrelated reasons looks the same as one never set.
  - whether the request used HTTPS. Secure is a property of the cookie, not of the connection that
    happened to deliver it.

Splitting matters too. `Set-Cookie` values legally contain commas inside `Expires=Wed, 09 Jun 2027 …`,
so naive comma-splitting invents cookies that were never sent. Where the transport preserves separate
header fields we use them; where it has already joined them we split only at a comma that is followed by
a real `name=` pair.

Scope is deliberately narrow: this reports CWE-614 only. HttpOnly, SameSite and Domain breadth are
separate weaknesses with their own findings, and folding them in here would make the verdict unreadable.
"""
from __future__ import annotations

import re

# A comma that begins a new cookie: followed by a token, '=', and no space before the '='. Anything else
# (notably a date inside Expires) stays part of the current cookie.
_SPLIT = re.compile(r",\s*(?=[A-Za-z0-9!#$%&'*+\-.^_`|~]+=)")
_ATTR_ONLY = {"secure", "httponly", "partitioned"}
# Session-ish names. A tracking or preference cookie without Secure is untidy; a SESSION cookie without
# it is the actual finding, because that is the one worth stealing off the wire.
_SESSIONISH = re.compile(r"(sess|sid|token|auth|login|remember|jwt|csrf|xsrf|jsessionid|phpsessid|"
                         r"asp\.net|connect\.sid)", re.I)


def split_set_cookie(raw) -> list:
    """Individual Set-Cookie field values. Accepts a list (preferred) or an already-joined string."""
    if raw is None:
        return []
    items = list(raw) if isinstance(raw, (list, tuple)) else _SPLIT.split(str(raw))
    return [s.strip() for s in items if s and s.strip()]


def parse_cookie(field: str) -> dict:
    """One Set-Cookie field -> {name, value, attrs{}, secure: bool}. Attribute names are lowercased.

    `secure` is read ONLY from the attribute list, never from the cookie's value -- a cookie whose value
    happens to contain the word "secure" is not a secure cookie.
    """
    parts = [p.strip() for p in str(field or "").split(";") if p.strip()]
    if not parts or "=" not in parts[0]:
        return {}
    name, _, value = parts[0].partition("=")
    attrs = {}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        attrs[k.strip().lower()] = v.strip()
    return {"name": name.strip(), "value": value.strip(), "attrs": attrs,
            "secure": "secure" in attrs}


def evaluate(raw) -> dict:
    """Cookies set WITHOUT Secure. Empty/unparseable input yields nothing -- never a default finding."""
    fields = split_set_cookie(raw)
    if not fields:
        return {"confirmed": False, "cookies": [], "oracle": ""}
    missing, parsed_any = [], False
    for f in fields:
        ck = parse_cookie(f)
        if not ck:
            continue                     # a field we cannot parse is INCONCLUSIVE, not vulnerable
        parsed_any = True
        if not ck["secure"]:
            missing.append(ck)
    if not parsed_any or not missing:
        return {"confirmed": False, "cookies": [], "oracle": ""}
    names = [c["name"] for c in missing]
    session = [n for n in names if _SESSIONISH.search(n)]
    return {
        "confirmed": True, "cookies": names, "session_cookies": session,
        "oracle": ("the raw Set-Cookie header sets %s without the Secure attribute "
                   "(attributes present: %s). Read from the header field itself, not from the response "
                   "body and not from a browser cookie jar."
                   % (", ".join("'%s'" % n for n in names[:4]),
                      ", ".join(sorted(set(k for c in missing for k in c["attrs"])) or ["none"])))}


def finding(url: str, names, oracle: str, session: bool = False) -> dict:
    label = ", ".join(names[:3]) if isinstance(names, (list, tuple)) else str(names)
    return {
        "title": "Cookie set without the Secure attribute (%s)" % label,
        "severity": "medium" if session else "low",
        "family": "insecure_cookie", "confidence": "confirmed", "target": url,
        "cwe": "CWE-614", "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss_score": 5.9,
        "evidence": oracle,
        "success_oracle": oracle,
        "reproduction_steps": [
            "Request %s and read the raw Set-Cookie response header." % url,
            "The cookie is set without the Secure attribute.",
            "A plaintext request to the same host therefore transmits it, so anyone on the network path "
            "can read it -- no TLS downgrade of the main site is required, only one http:// request.",
        ],
        "impact": ("Without Secure, the browser also sends this cookie over plain HTTP. A network "
                   "attacker who can induce a single http:// request to the domain captures it. Where "
                   "the cookie carries a session, that is account takeover."),
        "remediation": ("Set the Secure attribute on every cookie carrying a session or other sensitive "
                        "value, and serve the site over HTTPS with HSTS so no plaintext request is made."),
        "tags": ["cwe-614", "cookie", "session"],
    }
