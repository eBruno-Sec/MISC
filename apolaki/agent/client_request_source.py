"""Client-side request TARGETS built from a DOM-read source (CWE-1104-adjacent, PortSwigger's
"client-side request URL override"). Pure static analysis of JavaScript — no network, never raises.

WHY THIS IS A LEAD AND NOT A CONFIRMATION. When a page builds a request like

    fetch(this.getAttribute("action"), {...})          // target read from the DOM
    xhr.open(m, el.dataset.endpoint)                   // target read from a data attribute

the request target is not a constant in the code: it is whatever the DOM says at call time. That is a
real weakness — DOM clobbering, an HTML-injection sink, or a prototype-pollution gadget can redirect the
request, and its Content-Type or body may come from the same place. But whether it is EXPLOITABLE depends
on whether some other defect lets an attacker reach that DOM node, which this analysis cannot know.

Apolaki's rule is that a finding is confirmed by a runtime oracle or it is not confirmed. `dom_trace`
already confirms the runtime case: injecting into a client-side source and observing a fetch to the
attacker host. What it cannot see is the case where the source is a server-rendered attribute that no
URL parameter controls — there is nothing to inject into, so the render proves nothing and the class
would be reported as absent. Static reading is the only way to SEE it; a lead is the only honest way to
REPORT it. The two views compose and neither pretends to be the other.

Deliberately narrow, because a broad "fetch with a variable" rule would fire on almost every SPA: the
target expression must read from the DOM or from the URL, and a same-file constant or a template literal
rooted at a literal path is not reported.
"""
from __future__ import annotations

import re

# Expressions that read a request target out of the page rather than out of the code.
_DOM_READ = (
    (r"\.getAttribute\(\s*['\"](?:action|href|src|formaction|data-[\w-]+)['\"]\s*\)", "a DOM attribute"),
    (r"\.dataset\.\w+", "a data-* attribute"),
    (r"\.(?:action|formAction)\b", "a form action property"),
    (r"\bdocument\.(?:baseURI|URL|documentURI)\b", "the document URL"),
    (r"\blocation\.(?:href|search|hash|pathname)\b", "the page URL"),
    (r"\bdocument\.referrer\b", "the referrer"),
)

# The request calls whose FIRST url-bearing argument we inspect.
_CALLS = (
    (r"\bfetch\s*\(", "fetch()"),
    (r"\.open\s*\(\s*[^,)]+,", "XMLHttpRequest.open()"),
    (r"\bnavigator\.sendBeacon\s*\(", "navigator.sendBeacon()"),
    (r"\bimportScripts\s*\(", "importScripts()"),
)

_IDENT = re.compile(r"[A-Za-z_$][\w$]*")

# Function parameter lists, matched with BOUNDED quantifiers so malformed input cannot cause runaway
# backtracking. `function f(a, b)` and `(a, b) =>`.
_PARAM_LIST_RX = (
    re.compile(r"function\s+[\w$]*\s*\(([^()]{0,200})\)"),
    re.compile(r"\(([^()]{0,200})\)\s*=>"),
)

# Hard input bound: a scanner reads scripts the TARGET serves, so a multi-megabyte bundle (or a
# deliberately hostile one) must not decide how long the scan takes.
_MAX_JS = 400_000
_MAX_CALLS = 200


def _arg_slice(js: str, start: int, span: int = 220) -> str:
    """The text just after a call's opening paren — enough to see the target expression. Pure."""
    return js[start:start + span]


def _target_expr(chunk: str) -> str:
    """The first argument of the call, up to the first top-level comma. Pure, bracket-aware."""
    depth, out = 0, []
    for ch in chunk:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif ch == "," and depth == 0:
            break
        out.append(ch)
    return "".join(out).strip()


def _resolves_to_dom(js: str, expr: str) -> tuple:
    """(reason, evidence) when `expr` reads from the DOM/URL, directly or via a local variable assigned
    from one in the same file. ("", "") otherwise. Pure — one hop, deliberately not a full dataflow."""
    for rx, why in _DOM_READ:
        if re.search(rx, expr):
            return why, expr[:120]
    # one hop: `const path = el.getAttribute("action")` … `fetch(path)`
    name = _IDENT.match(expr.strip())
    if name:
        ident = re.escape(name.group(0))
        for rx, why in _DOM_READ:
            m = re.search(r"(?:const|let|var)\s+%s\s*=\s*([^;\n]{0,160})" % ident, js)
            if m and re.search(rx, m.group(1)):
                return why, "%s = %s" % (name.group(0), m.group(1).strip()[:100])
        # a function PARAMETER named like a path, where the file also reads a request target from the DOM.
        # BOUNDED QUANTIFIERS ONLY. The obvious pattern here — `\w+\s*\(\s*[^)]*\bident\b[^)]*\)\s*{` —
        # backtracks catastrophically on unbalanced input: a body of 500 bare `fetch(` tokens took this
        # scan from milliseconds to minutes. A scanner reads JavaScript served BY THE TARGET, so a hostile
        # or merely malformed script must never be able to stall it.
        for rx in _PARAM_LIST_RX:
            for pm in rx.finditer(js):
                params = pm.group(1)
                if len(params) > 200:
                    continue
                if re.search(r"\b%s\b" % ident, params):
                    for drx, why in _DOM_READ:
                        if re.search(drx, js):
                            return why, "%s (parameter; the caller supplies a DOM-read value)" % name.group(0)
    return "", ""


def scan(js: str, url: str = "") -> list:
    """Every request whose TARGET is read from the page. Pure; never raises."""
    out, seen = [], set()
    try:
        s = str(js or "")[:_MAX_JS]
        if not s.strip():
            return []
        budget = _MAX_CALLS
        for call_rx, call_name in _CALLS:
            for m in re.finditer(call_rx, s):
                budget -= 1
                if budget < 0:
                    return out
                expr = _target_expr(_arg_slice(s, m.end()))
                if not expr or expr.startswith(("'", '"', "`/", "`http")):
                    continue                       # a literal target is not attacker-influenced
                why, ev = _resolves_to_dom(s, expr)
                if not why:
                    continue
                key = (call_name, expr[:60])
                if key in seen:
                    continue
                seen.add(key)
                out.append({"call": call_name, "expression": expr[:120], "source": why,
                            "evidence": ev, "script": url})
    except Exception:
        return out
    return out


def lead(hit: dict, page_url: str) -> dict:
    """An operator LEAD, never a confirmed finding — the runtime reachability is unproven by design."""
    return {
        "title": "Client-side request URL is read from the page (%s)" % hit.get("source", "the DOM"),
        "severity": "low", "confidence": "lead", "family": "request_url_override",
        "cwe": "CWE-441", "target": page_url,
        "vuln_class": "client_side",
        "evidence": "%s in %s builds its request target from %s: %s"
                    % (hit.get("call"), hit.get("script") or "page script", hit.get("source"),
                       hit.get("evidence") or hit.get("expression")),
        "description": ("The page issues a request whose TARGET is taken from the DOM or the URL rather "
                        "than from a constant in the code. Anything that can influence that DOM node — "
                        "an HTML-injection sink, DOM clobbering, or a prototype-pollution gadget — "
                        "redirects the request, and the body or Content-Type is often read from the same "
                        "place."),
        "impact": ("If the source node is reachable, the request (and any credentials or data it "
                   "carries) can be redirected to an attacker-controlled host."),
        "oracle": ("STATIC ONLY. Reported as a lead: the request target is demonstrably not a constant, "
                   "but whether an attacker can reach that DOM node is not proven here. dom_trace "
                   "confirms the runtime case separately by injecting a client-side source and observing "
                   "a fetch to the attacker host."),
        "remediation": ("Build request targets from constants in the code, or validate the value against "
                        "an allowlist of same-origin paths before issuing the request."),
        "tags": ["client_side", "request_url_override", "static", "lead"],
    }
