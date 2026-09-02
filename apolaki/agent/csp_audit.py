"""Granular Content-Security-Policy analysis -- seven Burp Scanner checks in one passive engine.

MINED FROM Burp's published issue catalog (portswigger.net/burp/documentation/scanner/
vulnerabilities-list), which lists these as distinct issues:

    Content security policy: allows untrusted script execution
    Content security policy: allows untrusted style execution
    Content security policy: allows clickjacking
    Content security policy: allows form hijacking
    Content security policy: allowlisted script resources
    Content security policy: malformed syntax
    Content security policy: not enforced

Apolaki previously answered only "is there a CSP header". Present-but-useless is the common case on a
real target -- `script-src *` is a header that passes a presence check and stops nothing.

PURE. No network, no state. Takes the header value; returns findings. Every rule below is checkable
by hand against a header you can write yourself, which is the point: a detection whose ground truth
you cannot construct is a detection you cannot calibrate.

THE CSP SEMANTICS THAT MAKE THIS AN ORACLE RATHER THAN A GREP -- each one is a false positive this
would otherwise emit, and they are why "look for unsafe-inline" is not good enough:

  * A NONCE OR HASH NEUTRALISES 'unsafe-inline'. CSP2+ browsers IGNORE 'unsafe-inline' when a nonce
    or hash source is present in the same directive. Flagging it there accuses a site that did the
    RIGHT thing -- the modern, recommended pattern.
  * `frame-ancestors` and `form-action` DO NOT FALL BACK to `default-src`. Their absence is a real
    gap even when default-src is restrictive, and treating default-src as covering them would miss
    both. Conversely `script-src`/`style-src` DO fall back, so their absence is only a finding when
    default-src is also permissive.
  * `'none'` in a directive is restrictive; a bare `*`, `http:`, `https:` or `data:` is not.
  * REPORT-ONLY ENFORCES NOTHING. `Content-Security-Policy-Report-Only` is monitoring, so a site
    with only that has no policy at all, however good the policy reads.
"""
from __future__ import annotations

import re

#: Sources that permit script from anywhere. `data:` is included deliberately -- `script-src data:`
#: lets an attacker who controls any script URL inline a whole payload.
_WILDCARD_SOURCES = frozenset({"*", "http:", "https:", "data:", "http://*", "https://*"})

#: Directives that DO fall back to `default-src` when absent (CSP spec). Anything not listed here --
#: notably `frame-ancestors`, `form-action`, `base-uri` -- does NOT, which is the distinction that
#: makes two of these checks correct.
_FALLBACK_TO_DEFAULT = frozenset({"script-src", "style-src", "img-src", "connect-src", "font-src",
                                  "media-src", "object-src", "frame-src", "worker-src"})

#: Hosts whose presence in `script-src` historically permits CSP bypass, because they serve
#: attacker-controllable JS (JSONP endpoints, user content, arbitrary module hosting). Burp reports
#: this as "allowlisted script resources". Conservative: only entries with a documented bypass.
_BYPASSABLE_SCRIPT_HOSTS = (
    "*.googleapis.com", "ajax.googleapis.com", "www.google.com", "translate.google.com",
    "*.cloudflare.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com",
    "*.amazonaws.com", "s3.amazonaws.com", "*.firebaseio.com", "*.blogspot.com",
)

_NONCE_OR_HASH = re.compile(r"'(?:nonce-[^']+|sha(?:256|384|512)-[^']+)'", re.I)
_DIRECTIVE_NAME = re.compile(r"^[a-zA-Z][a-zA-Z0-9-]*$")


def parse_csp(header_value: str) -> dict:
    """`{directive: [sources]}`, lower-cased directive names, original-case sources.

    Sources keep their case because a nonce is case-sensitive; directive names do not because CSP
    matches them case-insensitively.
    """
    out: dict = {}
    for chunk in str(header_value or "").split(";"):
        parts = chunk.strip().split()
        if not parts:
            continue
        name = parts[0].lower()
        if name not in out:                      # first occurrence wins, per spec
            out[name] = parts[1:]
    return out


def _sources_for(policy: dict, directive: str) -> list | None:
    """Effective sources for a directive, honouring `default-src` fallback ONLY where the spec says.

    Returns None when the directive is genuinely unset AND has no fallback -- which is a different
    fact from "set to something permissive" and is reported differently.
    """
    if directive in policy:
        return policy[directive]
    if directive in _FALLBACK_TO_DEFAULT and "default-src" in policy:
        return policy["default-src"]
    return None


def _permits_untrusted(sources: list) -> str:
    """Why this source list allows untrusted code, or "" when it does not."""
    lowered = [s.lower() for s in sources]
    if "'none'" in lowered:
        return ""
    joined = " ".join(sources)
    has_nonce_or_hash = bool(_NONCE_OR_HASH.search(joined))
    # CSP2+: a nonce or hash makes the browser IGNORE 'unsafe-inline'. Flagging it here would accuse
    # a site of the exact pattern the spec recommends.
    if "'unsafe-inline'" in lowered and not has_nonce_or_hash:
        return "'unsafe-inline' with no nonce or hash, so any injected inline script executes"
    if "'unsafe-eval'" in lowered:
        return "'unsafe-eval' permits string-to-code execution (eval, setTimeout(string), Function)"
    for src in lowered:
        if src in _WILDCARD_SOURCES:
            return "%s allows script from any origin" % src
    return ""


def analyze_csp(enforced: str = "", report_only: str = "") -> list:
    """Every CSP weakness in one pass. Returns finding-shaped dicts, most severe first.

    `enforced` is `Content-Security-Policy`; `report_only` is `Content-Security-Policy-Report-Only`.
    Both are passed so "report-only only" can be told apart from "no policy at all" -- the first is a
    site that wrote a policy and did not turn it on, which is a different message to its owner.
    """
    out = []
    if not str(enforced or "").strip():
        if str(report_only or "").strip():
            out.append({"check": "csp_not_enforced", "severity": "low",
                        "detail": "a Content-Security-Policy exists but ONLY as Report-Only, which "
                                  "enforces nothing -- the policy is monitoring, not protection"})
        return out                    # no enforced policy: nothing else here is measurable

    policy = parse_csp(enforced)
    if not policy:
        return [{"check": "csp_malformed", "severity": "low",
                 "detail": "the Content-Security-Policy header is present but parses to no "
                           "directives, so the browser enforces nothing"}]

    bad_names = [d for d in policy if not _DIRECTIVE_NAME.match(d)]
    if bad_names:
        out.append({"check": "csp_malformed", "severity": "low",
                    "detail": "unparseable directive name(s) %s -- a malformed directive is ignored "
                              "by the browser, so the protection it was meant to provide is absent"
                              % ", ".join(sorted(bad_names)[:4])})

    script = _sources_for(policy, "script-src")
    if script is None:
        out.append({"check": "csp_untrusted_script", "severity": "medium",
                    "detail": "neither script-src nor default-src is set, so the policy places no "
                              "restriction on script execution at all"})
    else:
        why = _permits_untrusted(script)
        if why:
            out.append({"check": "csp_untrusted_script", "severity": "medium",
                        "detail": "script-src permits untrusted execution: %s" % why})
        listed = {s.lower() for s in script}
        risky = sorted(h for h in _BYPASSABLE_SCRIPT_HOSTS if h in listed)
        if risky:
            out.append({"check": "csp_allowlisted_script_resources", "severity": "low",
                        "detail": "script-src allowlists host(s) with known CSP-bypass paths (%s); "
                                  "an attacker who can reach a JSONP or user-content endpoint there "
                                  "executes script under this origin's policy"
                                  % ", ".join(risky[:4])})

    style = _sources_for(policy, "style-src")
    if style is not None and _permits_untrusted(style):
        out.append({"check": "csp_untrusted_style", "severity": "low",
                    "detail": "style-src permits untrusted style: %s -- CSS injection can exfiltrate "
                              "data through attribute selectors" % _permits_untrusted(style)})

    # frame-ancestors and form-action DO NOT fall back to default-src. Their absence is a real gap
    # even under a restrictive default-src, and this is where a naive checker gets it wrong.
    if "frame-ancestors" not in policy:
        out.append({"check": "csp_allows_clickjacking", "severity": "low",
                    "detail": "frame-ancestors is not set and does NOT inherit from default-src, so "
                              "this policy does not prevent framing"})
    elif _permits_untrusted(policy["frame-ancestors"]):
        out.append({"check": "csp_allows_clickjacking", "severity": "low",
                    "detail": "frame-ancestors permits any origin to frame this page"})

    if "form-action" not in policy:
        out.append({"check": "csp_allows_form_hijacking", "severity": "low",
                    "detail": "form-action is not set and does NOT inherit from default-src, so an "
                              "injected or rewritten form can post credentials to an attacker host"})
    elif _permits_untrusted(policy["form-action"]):
        out.append({"check": "csp_allows_form_hijacking", "severity": "low",
                    "detail": "form-action permits submission to any origin"})

    order = {"medium": 0, "low": 1, "informational": 2}
    out.sort(key=lambda f: order.get(f["severity"], 3))
    return out
