"""
DOM audit — dynamic client-side source->sink confirmation (a mini DOM-Invader).

The static js_review flags dangerous sinks (innerHTML, location, __proto__, deparam,
AngularJS) as LEADS. This module turns the confirmable ones into CONFIRMED findings
by driving a real headless browser: inject a unique marker into a DOM SOURCE
(location.hash / a query param), load the page, and observe whether a SINK actually
fired — proof, not suspicion. Four classes are confirmable with no false positives
because each check keys on a unique canary that cannot occur naturally:

  - Prototype pollution: `?__proto__[KEY]=VAL` (or via the hash) => after load,
    Object.prototype[KEY] === VAL globally.
  - DOM-based XSS: an auto-firing payload in the hash/param => alert() fires with
    our marker (execution, not mere reflection).
  - DOM-based open redirect: a URL source pointed at an attacker host => the page
    navigates to that host.
  - Client-side template injection: `{{7*7}}MARKER` in a reflected param => the DOM
    renders `49MARKER` (the expression evaluated), only where a template engine runs.

Pure/deterministic here (probe URLs + result interpretation + finding builders); the
browser transport lives in tools._run_dom_audit.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

MARK = "bbhdom8842"          # unique canary (execution / render marker)
PP_KEY = "bbhpp8842"         # prototype-pollution property name (must be unique)
EVIL = "bbh-evil.example"    # attacker host for open-redirect confirmation

EXEC_PAYLOADS = (
    f'<img src=x onerror=alert("{MARK}")>',
    f'<svg onload=alert("{MARK}")>',
)
# Query params that commonly feed a client-side redirect or a template.
REDIRECT_PARAMS = ("returnUrl", "redirect", "url", "next", "return", "dest", "redir", "goto")
TEMPLATE_PARAMS = ("search", "q", "query", "searchTerm", "message", "name", "s")

# ── prototype-pollution GADGET discovery ─────────────────────────────────────────
# Confirming pollution (Object.prototype[x] set) proves the SOURCE; a real DOM-XSS/redirect needs a
# GADGET — a property the app reads from a config/options object and passes to a dangerous sink
# (script.src, innerHTML, location, eval). This wordlist is framework-level and PUBLICLY documented
# (PortSwigger prototype-pollution gadget research + common libs), i.e. a TECHNIQUE wordlist, not any
# lab's answer key. It is UNIONED with property names harvested from the TARGET's own JS (target-derived
# fixtures), so app-specific gadgets are reached without hardcoding a lab.
GADGET_PROPS = (
    "transport_url", "src", "url", "href", "action", "srcdoc", "data", "html", "template",
    "content", "value", "callback", "hitCallback", "sequence", "type", "integrity", "nonce",
    "baseURI", "background", "poster", "cite", "code", "codebase", "manifest", "sanitize",
    "allowedTags", "target", "method", "script", "source", "path", "endpoint", "api", "redirect",
)

# property names that are common JS/DOM builtins or methods, NOT app config gadgets — excluded from the
# harvest so we spend the bounded browser budget on plausible gadget properties only.
_HARVEST_STOP = frozenset((
    "length", "push", "pop", "shift", "unshift", "slice", "splice", "concat", "join", "indexof",
    "foreach", "map", "filter", "reduce", "find", "includes", "keys", "values", "entries", "call",
    "apply", "bind", "tostring", "valueof", "hasownproperty", "prototype", "constructor", "__proto__",
    "then", "catch", "finally", "resolve", "reject", "addeventlistener", "removeeventlistener",
    "getelementbyid", "queryselector", "queryselectorall", "createelement", "appendchild",
    "getattribute", "setattribute", "textcontent", "parentnode", "childnodes", "style", "classname",
    "innerhtml", "outerhtml", "attributes", "dataset", "children", "firstchild", "nextsibling",
    "log", "warn", "error", "info", "assign", "keys", "stringify", "parse", "test", "exec", "match",
    "replace", "split", "trim", "charat", "substring", "substr", "tolowercase", "touppercase",
))

_SINK_HINTS = ("src", "script", "innerhtml", "outerhtml", "eval", "settimeout", "setinterval",
               "location", "href", "insertadjacent", "document.write", "createcontextualfragment")


def harvest_gadget_props(js_text: str, cap: int = 12) -> list:
    """Extract candidate gadget property names from a page's JS (target-derived). Collect `.prop` and
    `['prop']` reads, drop builtins, and RANK properties that appear near a dangerous sink first — those
    are the likeliest gadgets. Pure + bounded."""
    import re
    js = js_text or ""
    props = {}
    for m in re.finditer(r"\.([A-Za-z_]\w{1,29})\b", js):
        props[m.group(1)] = props.get(m.group(1), 0)
    for m in re.finditer(r"""\[\s*['"]([A-Za-z_]\w{1,29})['"]\s*\]""", js):
        props[m.group(1)] = props.get(m.group(1), 0)
    low = js.lower()
    ranked = []
    for name in props:
        if name.lower() in _HARVEST_STOP:
            continue
        score = 0
        # proximity to a sink keyword: scan windows around each occurrence of the property
        for mm in re.finditer(r"\b" + re.escape(name) + r"\b", js):
            w = low[max(0, mm.start() - 60): mm.start() + 60]
            if any(h in w for h in _SINK_HINTS):
                score += 2
        if name in GADGET_PROPS:
            score += 1
        ranked.append((score, name))
    ranked.sort(key=lambda x: (-x[0], x[1]))
    return [n for _, n in ranked][:cap]


def _set_fragment(url: str, value: str) -> str:
    return urlunparse(urlparse(url)._replace(fragment=value))


def _add_query(url: str, name: str, value: str) -> str:
    p = urlparse(url)
    pairs = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k != name]
    pairs.append((name, value))
    return urlunparse(p._replace(query=urlencode(pairs)))


def build_probes(url: str, extra_params=None) -> list:
    """Bounded set of DOM probes for one page. Each item:
    {"class", "nav" (URL to load), "src" (source), "expect"}. `extra_params` = parameters DISCOVERED for
    this page (client-JS reads + reflected-wordlist probe) that no crawl edge linked — feeding them here is
    what catches CSTI/redirect on an app-specific, unlinked param like /catalog?category."""
    probes = []
    # the page's OWN query params — the reflected ones most likely to reach a template or
    # a client-side redirect sink (e.g. /catalog?category, /blog?search). Testing these —
    # not just a fixed name list — is what catches CSTI on app-specific params like category.
    own_params = [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True) if k]
    disc = [p for p in (extra_params or []) if p][:6]   # bound so proto/xss probes stay within the cap
    csti_params = list(dict.fromkeys(own_params + disc + list(TEMPLATE_PARAMS)))
    redir_params = list(dict.fromkeys(own_params + disc + list(REDIRECT_PARAMS)))
    # ── CSTI first (highest value): reflected template expression into own + common params ──
    for pn in csti_params:
        probes.append({"class": "csti", "nav": _add_query(url, pn, "{{7*7}}" + MARK), "src": pn})
    # …and from the FRAGMENT. proto/redirect/xss below already probe the hash; CSTI did not, which left a
    # gap for the common SPA shape where a hash-router segment is interpolated into a template. The hash
    # is never sent to the server, so no reflected-parameter probe can reach this sink. One probe.
    probes.append({"class": "csti", "nav": _set_fragment(url, "{{7*7}}" + MARK), "src": "hash"})
    # ── prototype pollution: hash (deparam/hash routers) + query ──
    for src, nav in (("hash", _set_fragment(url, f"__proto__[{PP_KEY}]={MARK}")),
                     ("query", _add_query(url, f"__proto__[{PP_KEY}]", MARK)),
                     ("hash", _set_fragment(url, f"constructor[prototype][{PP_KEY}]={MARK}"))):
        probes.append({"class": "proto", "nav": nav, "src": src})
    # ── DOM XSS: hash execution (covers hashchange/render sinks) ──
    # ORDERED BEFORE the redirect fan-out, and that ordering is load-bearing rather than cosmetic. The
    # list is truncated to a fixed cap below, and the redirect block grows with every discovered
    # parameter while the XSS block is a fixed 2. Left last, a page with enough parameters would push
    # script-execution testing off the end — silently trading the highest-severity check for another
    # redirect probe. Whatever the cap cuts should be the least valuable thing, not the most.
    for pl in EXEC_PAYLOADS:
        probes.append({"class": "xss", "nav": _set_fragment(url, pl), "src": "hash"})
    # ── DOM open redirect: hash + redirect-ish + own params ──
    probes.append({"class": "redirect", "nav": _set_fragment(url, f"https://{EVIL}/"), "src": "hash"})
    for pn in redir_params:
        probes.append({"class": "redirect", "nav": _add_query(url, pn, f"https://{EVIL}/"), "src": pn})
    # de-dup by nav URL, keep order (CSTI-on-own-params prioritised), cap for a bounded pass
    seen, out = set(), []
    for p in probes:
        if p["nav"] not in seen:
            seen.add(p["nav"])
            out.append(p)
    return out[:24]


# ── interpret one probe's browser result ─────────────────────────
def confirmed_proto(pp_value) -> bool:
    return pp_value == MARK


def confirmed_redirect(nav_targets) -> bool:
    # A real DOM open redirect NAVIGATES the top document to a URL whose HOST is
    # the attacker host. A substring test on the raw nav URL is wrong and yields a
    # false positive: our probe URL carries EVIL in its own fragment/query
    # (e.g. http://target/#https://bbh-evil.example/), so the initial same-origin
    # load — reported by page.on("framenavigated") — trivially "contains" EVIL even
    # though the browser never left the target. Compare the parsed HOST instead, so
    # only a genuine navigation whose host IS the attacker host confirms.
    for t in (nav_targets or []):
        try:
            host = (urlparse((t or "").strip()).hostname or "").lower()
        except ValueError:
            continue
        if host == EVIL or host.endswith("." + EVIL):
            return True
    return False


def confirmed_xss(dialog_msg) -> bool:
    return bool(dialog_msg) and MARK in str(dialog_msg)


def confirmed_csti(body: str) -> bool:
    # {{7*7}} rendered to 49 with the marker intact => the engine evaluated it.
    return bool(body) and (f"49{MARK}" in body) and (f"{{{{7*7}}}}{MARK}" not in body)


# per-family CVSS v3.1 base (defensible vectors) + the browser oracle each class confirms on.
_DOM_CVSS = {
    "xss":                 ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "dom_xss":             ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "csti":                ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "prototype_pollution": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L", 6.3),
    "open_redirect":       ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N", 4.7),
}


# ── finding builders (all CONFIRMED, with evidence) ──────────────
def _sev_from_score(score, fallback):
    if not isinstance(score, (int, float)):
        return fallback
    return ("critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4
            else "low" if score > 0 else "info")


def _base(url, title, sev, desc, evidence, family, cwe, tags, steps, impact=None, oracle=None):
    vec, score = _DOM_CVSS.get(family, ("", None))
    # Severity ALWAYS agrees with the CVSS band (reflected XSS/CSTI = 6.1 → Medium, not an inflated
    # High). Truth-first: the label can never contradict the score the report prints beside it
    # (CHAD final-audit defect #6 — caught by report.report_integrity_check).
    sev = _sev_from_score(score, sev)
    return {"title": title, "severity": sev, "target": url, "description": desc,
            "impact": impact or "Client-side code execution / manipulation in victims' browsers.",
            "evidence": evidence, "reproduction_steps": steps, "cwe": cwe, "family": family,
            "tags": tags, "confidence": "confirmed",
            "cvss_vector": vec, "cvss_score": score,
            "success_oracle": oracle or "a unique browser canary fired at runtime (see Evidence)"}


def proto_finding(url, nav, src):
    return _base(url, f"Client-side prototype pollution (DOM, via {src})", "high",
                 (f"Injecting a property through the {src} polluted Object.prototype globally "
                  "(a client-side prototype-pollution gadget processed attacker input)."),
                 f"Loaded {nav} → Object.prototype.{PP_KEY} === \"{MARK}\" after load.",
                 "prototype_pollution", "CWE-1321", ["prototype-pollution", "dom"],
                 [f"Load {nav}", f"In the console, read Object.prototype.{PP_KEY}",
                  "Observe the attacker-controlled value is now global (pollution confirmed)"],
                 impact=("A client-side prototype-pollution gadget lets attacker input set properties on "
                         "Object.prototype for every object in the victim's page, which can corrupt app logic "
                         "and, where a downstream sink trusts a polluted property, escalate to DOM XSS. Impact is "
                         "client-side (victim browser), not server compromise."),
                 oracle=f"after loading the crafted URL, Object.prototype.{PP_KEY} === the unique marker \"{MARK}\"")


def redirect_finding(url, nav, src):
    return _base(url, f"DOM-based open redirection (via {src})", "medium",
                 (f"A URL taken from the {src} is used to navigate the browser without validation, so "
                  "the page can be made to send visitors to an attacker-chosen site."),
                 f"Loaded {nav} → the page navigated to https://{EVIL}/.",
                 "open_redirect", "CWE-601", ["open-redirect", "dom"],
                 [f"Load {nav}", f"Observe the browser navigate to https://{EVIL}/"],
                 impact=("An attacker-chosen URL in the %s drives the browser to an external site, enabling "
                         "convincing phishing and OAuth/token-forwarding abuse from the trusted origin." % src),
                 oracle=f"the page issues a top-level navigation to the attacker-controlled host {EVIL}")


def xss_finding(url, nav, src):
    return _base(url, f"DOM-based XSS (via {src})", "high",
                 (f"A payload delivered through the {src} reached a DOM sink and EXECUTED in a real "
                  "browser (alert fired) — attacker script runs in the victim's session."),
                 f"Loaded {nav} → alert(\"{MARK}\") executed.",
                 "xss", "CWE-79", ["xss", "dom"],
                 [f"Load {nav}", "Observe alert() fire (script executed from the DOM source)"],
                 impact=("Attacker JavaScript runs in the victim's authenticated session from the trusted origin: "
                         "session/cookie theft, account actions as the victim, keylogging, and phishing. Client-side, "
                         "not server compromise."),
                 oracle=f"alert() executed in a real browser carrying the unique marker \"{MARK}\"")


def csti_finding(url, nav, src):
    f = _base(url, f"Client-side template injection (CSTI, via {src})", "high",
              (f"Input in '{src}' is evaluated by the page's CLIENT-SIDE template engine (AngularJS) in the "
               "victim's browser: the expression {{7*7}} rendered as 49. This is client-side code execution "
               "(an AngularJS sandbox escape to JavaScript) — NOT server-side template injection, and it does "
               "NOT give server RCE or server compromise."),
              (f"Headless Chromium loaded {nav}; after the AngularJS digest the rendered DOM contained "
               f"\"49{MARK}\" — the expression 7*7 was evaluated in-browser (browser-confirmed, not reflection)."),
              "csti", "CWE-79", ["csti", "dom-xss", "client-side"],
              [f"Open {nav} in a browser running the AngularJS app",
               "Let the AngularJS digest cycle run",
               "Observe 49 rendered in place of {{7*7}} in the live DOM — the expression executed client-side"])
    f["capec"] = "CAPEC-588: DOM-Based Cross-Site Scripting"
    f["success_oracle"] = (f"after the AngularJS digest, the live DOM contains \"49{MARK}\" (the expression "
                           "7*7 evaluated in-browser) while the literal {{7*7}} does not remain")
    f["impact"] = ("Attacker-controlled AngularJS expressions execute as JavaScript in the victim's browser "
                   "(client-side code execution / DOM XSS). Realistic impact: session-cookie theft, account "
                   "takeover, keylogging of form input, and convincing phishing served from the trusted domain. "
                   "This does not compromise the server itself.")
    return f


# ── gadget probes: pollute a candidate gadget property, watch for a sink firing ──
# flavor -> the polluted value + the runtime signal that confirms the gadget reached a sink:
#   "exec":     an img/onerror payload -> if a gadget writes it to innerHTML/eval it EXECUTES (dialog canary) => DOM XSS
#   "resource": an attacker-host URL   -> if a gadget assigns it to a <script>/fetch src the browser REQUESTS
#                                         the attacker host (non-navigation) => DOM XSS (attacker controls loaded code)
#   "nav":      an attacker-host URL   -> if a gadget assigns it to location the page NAVIGATES to it => open redirect
# `data:` in a <script src> is blocked by Chromium, so the script-gadget is detected by the outbound REQUEST to
# the attacker host, not by execution — reliable and needs no code to actually load. The exec payload's alert arg
# is a quote-free regex literal /MARK/ (String(/MARK/) carries MARK) so quote-escaping can't neuter it.
_GADGET_VALUE = {
    "exec":     "<img src=x onerror=alert(/%s/)>" % MARK,
    "resource": "https://%s/%s.js" % (EVIL, MARK),
    "nav":      "https://%s/" % EVIL,
}


def gadget_probes(url: str, extra_props=None, cap: int = 12) -> list:
    """Bounded prototype-pollution GADGET probes for one page. Pollutes each candidate property (harvested
    from the target's JS first, then the framework wordlist) via the hash AND query, across the sink flavors.
    Each item: {class:'gadget', prop, flavor, nav, src, base}."""
    props, seen = [], set()
    for p in list(extra_props or []) + list(GADGET_PROPS):
        if p and p not in seen:
            seen.add(p); props.append(p)
        if len(props) >= cap:
            break
    out = []
    for prop in props:
        for flavor, val in _GADGET_VALUE.items():
            for src, nav in (("hash", _set_fragment(url, "__proto__[%s]=%s" % (prop, val))),
                             ("query", _add_query(url, "__proto__[%s]" % prop, val))):
                out.append({"class": "gadget", "prop": prop, "flavor": flavor, "nav": nav, "src": src, "base": url})
    return out


def is_evil_req(u: str) -> bool:
    """A request whose HOST is the attacker host (host-parse discipline, no substring false positive)."""
    try:
        h = (urlparse((u or "").strip()).hostname or "").lower()
    except ValueError:
        return False
    return h == EVIL or h.endswith("." + EVIL)


def gadget_family(flavor, *, dialog_msg=None, navs=None, evil_reqs=None) -> str:
    """Which family a gadget probe CONFIRMED from the runtime signals, or '' if it did not fire."""
    if flavor == "exec" and confirmed_xss(dialog_msg):
        return "dom_xss"
    if flavor == "resource" and any(is_evil_req(u) for u in (evil_reqs or [])):
        return "dom_xss"
    if flavor == "nav" and confirmed_redirect(navs):
        return "open_redirect"
    return ""


def gadget_finding(url, prop, nav, family):
    if family == "dom_xss":
        f = _base(url, "DOM XSS via prototype-pollution gadget ('%s')" % prop, "high",
                  ("A prototype-pollution gadget reads the property '%s' and passes it to a script/innerHTML sink; "
                   "polluting Object.prototype['%s'] made the browser run attacker-controlled code from the "
                   "trusted origin." % (prop, prop)),
                  "Loaded %s → after Object.prototype['%s'] was polluted the gadget drove a script/DOM sink "
                  "(alert executed, or the page loaded attacker script from %s)." % (nav, prop, EVIL),
                  "dom_xss", "CWE-1321", ["prototype-pollution", "dom-xss", "gadget"],
                  [f"Load {nav}", f"Object.prototype['{prop}'] is polluted; the gadget feeds it to a script/innerHTML sink",
                   "Observe attacker script run (alert fires, or an attacker-host script request is issued)"],
                  impact=("Prototype pollution plus this gadget yields DOM XSS: attacker script runs in the victim's "
                          "authenticated session from the trusted origin (session/token theft, account takeover)."),
                  oracle=f"after polluting Object.prototype['{prop}'], the gadget drove a browser sink at runtime "
                         f"(alert carrying \"{MARK}\", or an outbound script request to the attacker host {EVIL})")
        f["capec"] = "CAPEC-77: Manipulating User-Controlled Variables"
        return f
    return _base(url, "DOM open redirect via prototype-pollution gadget ('%s')" % prop, "medium",
                 ("A prototype-pollution gadget reads the property '%s' as a navigation target; polluting "
                  "Object.prototype['%s'] drove the browser to an attacker host." % (prop, prop)),
                 "Loaded %s → the page navigated to https://%s/ after Object.prototype['%s'] was polluted." % (nav, EVIL, prop),
                 "open_redirect", "CWE-601", ["prototype-pollution", "open-redirect", "gadget"],
                 [f"Load {nav}", f"Observe the browser navigate to https://{EVIL}/ (gadget used the polluted '{prop}')"],
                 impact=("A polluted navigation gadget redirects victims to an attacker site from the trusted origin "
                         "(phishing, OAuth/token forwarding)."),
                 oracle=f"after polluting Object.prototype['{prop}'], the page navigated to the attacker host {EVIL}")


def build_finding(probe: dict, *, pp_value=None, nav_targets=None, dialog_msg=None, body=None, evil_reqs=None):
    """Return a CONFIRMED finding for a probe whose browser result proves the class,
    else None. One place so the transport never has to guess."""
    cls, url, nav, src = probe["class"], probe.get("base", probe["nav"]), probe["nav"], probe["src"]
    if cls == "proto" and confirmed_proto(pp_value):
        return proto_finding(url, nav, src)
    if cls == "redirect" and confirmed_redirect(nav_targets):
        return redirect_finding(url, nav, src)
    if cls == "xss" and confirmed_xss(dialog_msg):
        return xss_finding(url, nav, src)
    if cls == "csti" and confirmed_csti(body):
        return csti_finding(url, nav, src)
    if cls == "gadget":
        fam = gadget_family(probe.get("flavor"), dialog_msg=dialog_msg, navs=nav_targets, evil_reqs=evil_reqs)
        if fam:
            return gadget_finding(url, probe["prop"], nav, fam)
    return None


# ===============================================================================================
# Q-003 -- `postMessage` as a DOM source (CWE-346 -> CWE-79), WSTG-CLNT-11
#
# A page that registers `window.addEventListener("message", h)` and lets `event.data` reach a
# dangerous sink is exploitable by ANY page that can obtain a handle to it (an iframe it embeds, or
# a `window.open` popup it holds). The classic aggravator is a handler that never checks
# `event.origin`.
#
# THE LADDER, and why each rung exists:
#   1. DETECT   - a static match on `addEventListener("message")` is a LEAD, never a finding. This
#                 project's whole claim is that what it reports is proven.
#   2. GRADE    - a handler comparing `event.origin` against an allowlist is materially different
#                 from one that does not, and from one that does `origin.indexOf("target.com")`
#                 (bypassable by `https://evil.example/?x=https://target.com`). Reporting the three
#                 identically is the noise that makes a report worthless.
#   3. CONFIRM  - post the canary from a context we control and observe the SINK FIRE. That is the
#                 difference between a finding and a guess; the transport lives in
#                 `tools._wm_audit`, which drives a real Chromium exactly as `_run_dom_audit` does.
#
# THE STATIC GRADE IS A PREDICTION; THE RUNTIME IS THE VERDICT. A handler this module grades
# `strict` that nevertheless fires on our cross-origin post is CONFIRMED and the grade was wrong --
# disagreements are resolved in favour of what the browser actually did, in both directions.
#
# REAL FIXTURE, COPIED FROM A LIVE TARGET (Juice Shop `main.js`, the only `onmessage` in the whole
# bundle): `this.ws.onmessage=function(e){a.onData(e.data)}` -- socket.io's WebSocket transport, NOT
# a window handler. A regex on `onmessage` alone reports a web-message vulnerability on Juice Shop
# that does not exist, so the RECEIVER is checked, not just the event name.
# ===============================================================================================

WM_MARK = "bbhwm8842"          # web-message canary, DISTINCT from MARK so a hash-sourced XSS
                               # confirmation can never be mis-attributed to the message source.

#: Receivers on which a `message` listener really is a WINDOW web-message handler. A bare
#: `addEventListener("message", ...)` (no receiver) is window's in a normal script, so it counts.
#: Everything else -- `ws`, `socket`, `worker`, `port`, `es`, `channel` -- is a different transport
#: whose `message` event is not attacker-reachable via `postMessage` to the page.
_WM_WINDOW_RECEIVERS = frozenset({"window", "self", "globalThis", "top", "parent", "this.window"})

_WM_ADD_RE = re.compile(
    r"""(?:(?P<recv>[\w$][\w$.]{0,40})\s*\.\s*)?addEventListener\s*\(\s*(?P<q>['"])message(?P=q)\s*,""")
#: THE WRAPPER FORM, and it is not a hypothetical. `iframe-resizer` 4.3.9 -- a library on millions of
#: pages -- defines its own `addEventListener(el, evt, func)` helper and registers with
#: `addEventListener(window, 'message', iFrameListener)`. MEASURED against the real jsDelivr build:
#: with only the receiver-dot form above, `find_message_listeners` returned 0 listeners AND
#: `wm_scan_hint` returned False, so the page would never even have been loaded in a browser. The
#: receiver is still checked -- `addEventListener(port, 'message', f)` is rejected -- so widening the
#: shape does not widen what counts as a window handler.
_WM_ADD_ARG_RE = re.compile(
    r"""addEventListener\s*\(\s*(?P<recv>[\w$][\w$.]{0,40})\s*,\s*(?P<q>['"])message(?P=q)\s*,""")
_WM_ON_RE = re.compile(
    r"""(?:(?P<recv>[\w$][\w$.]{0,40})\s*\.\s*)?onmessage\s*=""")

#: sink name -> the pattern that shows `event.data` can reach it. Checked INSIDE the handler body
#: only, so an unrelated `innerHTML` elsewhere in the bundle cannot manufacture a lead.
_WM_SINK_PATTERNS = (
    ("innerHTML",          r"\.\s*innerHTML\s*="),
    ("outerHTML",          r"\.\s*outerHTML\s*="),
    ("insertAdjacentHTML", r"\.\s*insertAdjacentHTML\s*\("),
    ("srcdoc",             r"\.\s*srcdoc\s*="),
    ("document.write",     r"document\s*\.\s*write(?:ln)?\s*\("),
    ("eval",               r"\beval\s*\("),
    ("Function",           r"\bnew\s+Function\s*\("),
    ("setTimeout",         r"\bset(?:Timeout|Interval)\s*\("),
    ("location",           r"\blocation\s*\.\s*(?:href|replace|assign)\s*[=(]|\blocation\s*=[^=]"),
    ("element.src",        r"\.\s*src\s*="),
    ("jQuery.html",        r"\.\s*(?:html|append|prepend|after|before|replaceWith)\s*\("),
)
_WM_SINKS = tuple((name, re.compile(pat)) for name, pat in _WM_SINK_PATTERNS)

#: the handler must actually READ the event payload, or there is no source->sink flow to report.
_WM_READS_DATA = re.compile(r"\.\s*data\b|\{\s*data\s*[,}]")

# -- origin validation grading -------------------------------------------------------------------
# STRICT: `e.origin === "https://x"` (either operand order), or exact membership in an allowlist
#         (`ALLOWED.includes(e.origin)` / `.indexOf(e.origin)` / `.has(e.origin)`), i.e. the ORIGIN
#         is the ARGUMENT.
# WEAK:   a substring/prefix/regex test performed ON the origin (`e.origin.indexOf("target.com")`),
#         the classic bypass. `.origin` referenced but never compared grades weak too: silence about
#         how a value is used is not evidence that it gates anything.
_WM_ORIGIN_REF = re.compile(r"[\w$]+\s*\.\s*origin\b")
_WM_ORIGIN_STRICT = re.compile(
    r"[\w$]+\s*\.\s*origin\s*(?:===|!==|==|!=)"
    r"|(?:===|!==|==|!=)\s*[\w$]+\s*\.\s*origin\b"
    r"|\.\s*(?:includes|indexOf|has|contains|lastIndexOf)\s*\(\s*[\w$]+\s*\.\s*origin\s*[,)]")
_WM_ORIGIN_WEAK = re.compile(
    r"[\w$]+\s*\.\s*origin\s*\.\s*"
    r"(?:indexOf|lastIndexOf|startsWith|endsWith|includes|search|match|replace|slice|substr|substring)\s*\(")

#: `X.<key> === "<literal>"` inside the handler: a routing gate the payload must satisfy or the
#: handler returns early. Target-derived -- the literal is read off the target, never guessed.
_WM_GATE_RE = re.compile(
    r"""[\w$]+\s*\.\s*([A-Za-z_$][\w$]{0,29})\s*(?:===|==)\s*(['"])([^'"]{1,40})\2"""
    r"""|(['"])([^'"]{1,40})\4\s*(?:===|==)\s*[\w$]+\s*\.\s*([A-Za-z_$][\w$]{0,29})""")

#: THE SAME GATE WRITTEN AS A SWITCH, which is how real message routers are written. The equality
#: form above found NOTHING on the canonical JSON.parse shape (`switch(d.type){case "load-channel":`)
#: -- a real handler shape whose gate is a `case` label, not an `==`. A payload that misses the gate
#: is dropped by the handler's default branch and the engine reports clean on a vulnerable page,
#: which is exactly the "probe with an invented value" failure. `case` labels are collected in SOURCE
#: ORDER and the discriminant property is taken from the nearest preceding `switch`.
_WM_SWITCH_RE = re.compile(r"switch\s*\(\s*[\w$]+\s*\.\s*([A-Za-z_$][\w$]{0,29})\s*\)")
_WM_CASE_RE = re.compile(r"""\bcase\s+(['"])([^'"]{1,40})\1\s*:""")

#: THE PROPERTY ON THE RIGHT OF THE ASSIGNMENT -- the one that actually flows INTO the sink.
#: MEASURED on the canonical JSON.parse shape (`ACMEplayer.element.src = d.url`): ranking by
#: sink-proximity alone put `src` -- the SINK's own property name -- ahead of `url`, the only
#: property that carries attacker data. Probing `{"type":"load-channel","src":...}` sets a property
#: the handler never reads, so the engine reports clean on a page it is looking straight at.
_WM_SINK_FED_RE = re.compile(
    r"""\.\s*(?:innerHTML|outerHTML|srcdoc|src|href|action|text|value)\s*=\s*"""
    r"""[\w$]+(?:\s*\.\s*[\w$]+)*\s*\.\s*([A-Za-z_$][\w$]{0,29})"""
    r"""|\b(?:eval|write|writeln|setTimeout|setInterval|html|assign|replace|insertAdjacentHTML)"""
    r"""\s*\(\s*[\w$]+(?:\s*\.\s*[\w$]+)*\s*\.\s*([A-Za-z_$][\w$]{0,29})""")

_WM_PARSES_JSON = re.compile(r"JSON\s*\.\s*parse\s*\(")

#: properties read off the event payload: `e.data.url`, `e.data["url"]`, `JSON.parse(e.data).url`.
_WM_DATA_PROP_RE = re.compile(
    r"""\.\s*data\s*\.\s*([A-Za-z_$][\w$]{0,29})"""
    r"""|\.\s*data\s*\[\s*(['"])([A-Za-z_$][\w$]{0,29})\2\s*\]"""
    r"""|JSON\s*\.\s*parse\s*\([^()]{0,80}\)\s*\.\s*([A-Za-z_$][\w$]{0,29})""")

_WM_BODY_CAP = 4000        # a handler longer than this is minified app soup; grade what we can see


def _wm_brace_body(text: str, start: int, cap: int = _WM_BODY_CAP) -> str:
    """The `{...}` block beginning at/after `start`, brace-matched with minimal string awareness.

    Quotes are tracked (with escapes) so a `{` inside a string literal cannot unbalance the scan;
    regex literals are NOT tracked, which is a known and bounded imprecision -- it can only truncate
    a body early, i.e. UNDER-report sinks, never invent one.
    """
    n = len(text)
    i = text.find("{", start)
    if i < 0 or i - start > 200:
        return ""
    depth, j, quote, esc = 0, i, "", False
    while j < n and j - i < cap:
        c = text[j]
        if quote:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == quote:
                quote = ""
        elif c in "'\"`":
            quote = c
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
        j += 1
    return text[i:min(n, i + cap)]


def _wm_resolve_handler(js: str, after: int) -> str:
    """The handler source for a listener whose registration ends at `after`.

    Inline `function(e){...}` / `(e)=>{...}` / `e=>{...}` are brace-matched in place. A NAMED
    reference (`addEventListener("message", handleMsg)`) is resolved by finding its declaration
    elsewhere in the same file. An unresolvable handler returns "" -- which downgrades the record
    rather than inventing an analysis of code we never read.
    """
    tail = js[after:after + 400]
    stripped = tail.lstrip()
    lead = len(tail) - len(stripped)
    if stripped.startswith(("function", "async function", "(", "async (")) or re.match(
            r"^(?:async\s+)?[\w$]+\s*=>", stripped):
        body = _wm_brace_body(js, after + lead)
        if body:
            return body
    m = re.match(r"^([\w$]{1,60})\s*[,)]", stripped)
    if not m:
        return ""
    name = m.group(1)
    for pat in (r"function\s+%s\s*\(" % re.escape(name),
                r"\b%s\s*=\s*(?:async\s+)?function\b" % re.escape(name),
                r"\b%s\s*=\s*(?:async\s+)?\(?[\w$,\s]*\)?\s*=>" % re.escape(name),
                r"\b%s\s*\([^)]{0,80}\)\s*\{" % re.escape(name)):
        d = re.search(pat, js)
        if d:
            body = _wm_brace_body(js, d.end() - 1)
            if body:
                return body
    return ""


def wm_origin_grade(handler_src: str) -> str:
    """`strict` | `weak` | `none` -- how the handler validates `event.origin`.

    A PREDICTION about exploitability, not a verdict: `tools._wm_audit` posts from a genuinely
    foreign origin and the browser's own delivery decision overrules this in both directions.
    """
    h = handler_src or ""
    if _WM_ORIGIN_STRICT.search(h):
        return "strict"
    if _WM_ORIGIN_WEAK.search(h) or _WM_ORIGIN_REF.search(h):
        return "weak"
    return "none"


def _wm_switch_gates(handler_src: str) -> list:
    """[(discriminant_property, case_literal)] for switch cases whose BODY reaches a sink.

    Only sink-reaching cases are returned. A `switch(d.type)` typically routes half a dozen benign
    messages and one dangerous one; posting the benign literal makes the handler take a harmless
    branch and the engine reports clean on a page that is genuinely vulnerable.
    """
    h, out = handler_src or "", []
    for sw in _WM_SWITCH_RE.finditer(h):
        prop = sw.group(1)
        region = h[sw.end():sw.end() + _WM_BODY_CAP]
        cases = list(_WM_CASE_RE.finditer(region))
        for i, c in enumerate(cases):
            end = cases[i + 1].start() if i + 1 < len(cases) else len(region)
            body = region[c.end():end]
            if any(rx.search(body) for _, rx in _WM_SINKS):
                pair = (prop, c.group(2))
                if pair not in out:
                    out.append(pair)
    return out


def wm_handler_facts(handler_src: str) -> dict:
    """Everything the handler SOURCE says about itself: which sinks it reaches, whether it reads the
    event payload at all, how it grades `event.origin`, which payload properties it consumes, and
    which literal gates a payload has to satisfy. Used unchanged on both the statically-scraped
    handler and the one read back off the live page over CDP -- one analyser, two inputs."""
    h = handler_src or ""
    sinks = [name for name, rx in _WM_SINKS if rx.search(h)]
    gates, props = {}, []
    for m in _WM_GATE_RE.finditer(h):
        key, val = (m.group(1), m.group(3)) if m.group(1) else (m.group(6), m.group(5))
        if key and val and key.lower() not in ("origin", "source") and key not in gates:
            gates[key] = val
        if len(gates) >= 2:
            break
    # STRONGEST FIRST: a property assigned into (or passed to) a sink is the one carrying attacker
    # data; an explicit `e.data.X` read is next; the sink-proximity harvest only backfills.
    for m in _WM_SINK_FED_RE.finditer(h):
        p = m.group(1) or m.group(2)
        if p and p not in props:
            props.append(p)
    for m in _WM_DATA_PROP_RE.finditer(h):
        p = m.group(1) or m.group(3) or m.group(4)
        if p and p not in props:
            props.append(p)
    # backfill with sink-adjacent property names read off the handler itself (target-derived, the
    # same ranking `harvest_gadget_props` already applies to prototype-pollution gadgets)
    # a switch-based router contributes ALTERNATIVE gate sets, one per sink-reaching case, because
    # only one branch of the switch usually reaches the sink and we do not know which in advance
    alts = []
    for prop, lit in _wm_switch_gates(h)[:3]:
        g = dict(gates)
        g[prop] = lit
        if g not in alts:
            alts.append(g)
    if alts:
        gates = alts[0]
    for p in harvest_gadget_props(h, cap=6):
        if p not in props and p not in gates:
            props.append(p)
    return {"sinks": sinks, "reads_data": bool(_WM_READS_DATA.search(h)),
            "origin_check": wm_origin_grade(h), "props": props[:6], "gates": gates,
            "gate_alts": alts or [gates], "parses_json": bool(_WM_PARSES_JSON.search(h)),
            "resolved": bool(h.strip())}


def find_message_listeners(js_text: str, *, source: str = "") -> list:
    """Every WINDOW `message` listener in one script, with its handler analysed. STATIC => LEADS.

    The receiver is checked, not just the event name: `this.ws.onmessage = ...` (socket.io's
    WebSocket transport, and the ONLY `onmessage` in Juice Shop's live bundle) is a different
    transport and is rejected here. `postMessage` cannot reach it, so reporting it would be a false
    positive on a real target -- measured, not hypothesised.
    """
    js, out = js_text or "", []
    for rx in (_WM_ADD_RE, _WM_ADD_ARG_RE, _WM_ON_RE):
        for m in rx.finditer(js):
            recv = (m.group("recv") or "").strip()
            if recv and recv not in _WM_WINDOW_RECEIVERS:
                continue                       # ws/socket/worker/port/EventSource: not a web message
            # `onmessage` is a PROPERTY ASSIGNMENT, so the handler begins at the `=`, not after it;
            # every other form ends its match on the comma that precedes the handler.
            handler = _wm_resolve_handler(js, m.end() - (1 if rx is _WM_ON_RE else 0))
            rec = {"receiver": recv or "window",
                   "registration": "onmessage" if rx is _WM_ON_RE else "addEventListener",
                   "source": source, "handler": handler[:_WM_BODY_CAP]}
            rec.update(wm_handler_facts(handler))
            out.append(rec)
    return out


def wm_reportable(rec: dict) -> bool:
    """A listener worth spending browser budget on / worth reporting as a lead: it reaches a sink AND
    reads the event payload. A handler that never touches `event.data` has no source->sink flow, and
    a handler with no sink cannot become XSS -- reporting either is the lint-rule noise this ticket
    exists to avoid."""
    return bool(rec.get("sinks")) and bool(rec.get("reads_data"))


def wm_scan_hint(text: str) -> bool:
    """LOOSE, CHEAP gate over raw page/script text: is it worth loading this page in a browser to
    enumerate its real listeners? Deliberately over-inclusive -- it fires on Juice Shop's
    `ws.onmessage` -- because the authoritative decision is the CDP listener enumeration, and a loose
    cheap gate in front of an authoritative expensive check wastes a page load, whereas a tight one
    would silently lose every `window`-aliased minified bundle.

    The `addEventListener` half deliberately allows arguments BEFORE the event name: the first
    version of this gate required the string literal immediately after the paren and MEASURED False
    on the real iframe-resizer build, which registers `addEventListener(window, 'message', fn)`.
    """
    t = text or ""
    return bool(re.search(r"onmessage\s*=|addEventListener\s*\([^)]{0,60}['\"]message['\"]", t))


# -- payloads: what we post, and why each shape exists -------------------------------------------
_WM_EXEC_HTML = '<img src=x onerror=alert("%s")>' % WM_MARK   # innerHTML / document.write / srcdoc
_WM_EXEC_JS = 'alert("%s")' % WM_MARK                         # eval / setTimeout / new Function
_WM_JS_URL = 'javascript:alert("%s")' % WM_MARK               # location / element.src
_WM_NAV_URL = "https://%s/%s" % (EVIL, WM_MARK)               # location -> open redirect


def wm_payloads(rec: dict, cap: int = 10) -> list:
    """Bounded payloads to post at one handler. Each item:
    {"kind": "string"|"json"|"object", "value", "flavor": "exec"|"nav", "label"}.

    Shapes are chosen from what the HANDLER ITSELF does -- the sinks it reaches pick the exec vs nav
    flavour, and the JSON/object shapes are built from properties and literal gates read off the
    target's own handler. Nothing here is a guessed property name from a wordlist: a handler that
    early-returns unless `d.type === "load-channel"` is satisfied with the literal it was MEASURED
    to require.

    ORDER IS LOAD-BEARING, NOT COSMETIC -- the same rule `build_probes` already records: whatever the
    cap cuts must be the least valuable thing, not the most. A handler that does
    `try { d = JSON.parse(e.data) } catch(e) { return }` DISCARDS every plain-string payload, so for a
    structured handler the strings are the waste and the gate-satisfying object is the whole point.
    MEASURED before this fix on the canonical JSON.parse shape: the one payload that reproduces the
    documented exploit sat at index 10 of a list capped at 10.
    """
    sinks = set(rec.get("sinks") or ())
    strings, structured = [], []
    markup = sinks & {"innerHTML", "outerHTML", "insertAdjacentHTML", "srcdoc",
                      "document.write", "jQuery.html"}
    code = sinks & {"eval", "Function", "setTimeout"}
    urlish = sinks & {"location", "element.src"}
    if markup or not sinks:
        strings.append({"kind": "string", "value": _WM_EXEC_HTML, "flavor": "exec", "label": "html"})
    if code or not sinks:
        strings.append({"kind": "string", "value": _WM_EXEC_JS, "flavor": "exec", "label": "js"})
    if urlish or not sinks:
        strings.append({"kind": "string", "value": _WM_JS_URL, "flavor": "exec", "label": "js-url"})
        strings.append({"kind": "string", "value": _WM_NAV_URL, "flavor": "nav", "label": "nav-url"})
    out = structured
    for gates in (rec.get("gate_alts") or [dict(rec.get("gates") or {})])[:3]:
        for prop in (rec.get("props") or [])[:3]:
            if prop in gates:
                continue                       # never overwrite the literal the gate demands
            for val, flavor, label in ((_WM_EXEC_HTML, "exec", "html"),
                                       (_WM_JS_URL, "exec", "js-url"),
                                       (_WM_NAV_URL, "nav", "nav-url")):
                if flavor == "nav" and not urlish:
                    continue
                body = dict(gates)
                body[prop] = val
                out.append({"kind": "json", "value": body, "flavor": flavor,
                            "label": "json:%s=%s" % (prop, label)})
                out.append({"kind": "object", "value": body, "flavor": flavor,
                            "label": "object:%s=%s" % (prop, label)})
    # A handler that parses JSON, or gates on a literal, drops raw strings on the floor -- put the
    # structured payloads in front of the cap for it, and behind the cap for everyone else.
    ordered = (structured + strings) if (rec.get("parses_json") or rec.get("gates")) \
        else (strings + structured)
    seen, uniq = set(), []
    for p in ordered:
        key = (p["kind"], repr(p["value"]))
        if key not in seen:
            seen.add(key)
            uniq.append(p)
    return uniq[:cap]


def confirmed_wm(dialog_msg) -> bool:
    """Execution, not reflection: an alert carrying the web-message canary actually fired."""
    return bool(dialog_msg) and WM_MARK in str(dialog_msg)


def wm_family(flavor, *, dialog_msg=None, navs=None) -> str:
    """Which family the runtime signals CONFIRM for one posted payload, or '' if nothing fired."""
    if confirmed_wm(dialog_msg):
        return "dom_xss"
    if flavor == "nav" and confirmed_redirect(navs):
        return "open_redirect"
    return ""


_DOM_CVSS["web_message"] = ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4)


def _wm_origin_sentence(grade: str) -> str:
    return {
        "none": "The handler performs NO check on event.origin, so any page that can obtain a "
                "handle to this one (by framing it, or by window.open) can drive the sink.",
        "weak": "The handler's event.origin check is a substring/prefix test rather than an equality "
                "or allowlist-membership test, so an attacker origin such as "
                "https://evil.example/?x=<expected-origin> or <expected-origin>.evil.example "
                "satisfies it.",
        "strict": "The handler compares event.origin for equality or allowlist membership.",
    }.get(grade, "The handler's origin validation could not be determined from its source.")


def wm_lead_finding(url: str, rec: dict) -> dict:
    """A LEAD -- a `message` handler whose source reaches a sink, NOT driven to execution.

    Deliberately NOT built through `_base`: that builder stamps `confidence: "confirmed"` on
    everything it touches, and a static match graded confirmed is the most expensive defect class in
    this platform. A lead carries no proof burden (`proof_schema.UNPROVEN_CONFIDENCE`) precisely
    because it makes no proof claim.
    """
    vec, score = _DOM_CVSS["web_message"]
    grade = rec.get("origin_check") or "none"
    sinks = ", ".join(rec.get("sinks") or []) or "an unidentified sink"
    where = rec.get("source") or url
    return {
        "title": "Web-message (postMessage) handler reaches a DOM sink (origin check: %s)" % grade,
        "severity": _sev_from_score(score, "medium"), "target": url,
        "description": (
            "This page registers a window '%s' handler (%s) that reads event.data and passes it to "
            "%s. %s Any page able to obtain a handle to this document can post to that handler."
            % (rec.get("registration") or "message", rec.get("receiver") or "window", sinks,
               _wm_origin_sentence(grade))),
        "impact": ("If the payload reaches the sink unfiltered, attacker script runs in the victim's "
                   "authenticated session from this trusted origin (session/token theft, actions as "
                   "the victim). Client-side; not server compromise."),
        "evidence": ("Static analysis of %s found a window message listener registered via %s whose "
                     "handler reads event.data and reaches: %s. Origin validation graded '%s'. "
                     "NOT DRIVEN TO EXECUTION -- this is a lead, not a proof."
                     % (where, rec.get("registration") or "addEventListener", sinks, grade)),
        "reproduction_steps": [
            "Open %s" % url,
            "In DevTools, inspect the window 'message' listener (Elements > Event Listeners, or "
            "getEventListeners(window).message)",
            "From a page you control, frame this document (or window.open it) and call "
            "targetWindow.postMessage(<payload>, '*')",
            "Observe whether the payload reaches %s" % sinks],
        "cwe": "CWE-346", "family": "web_message",
        "tags": ["postmessage", "web-message", "dom", "cwe-346", "wstg-clnt-11"],
        "confidence": "lead",
        "cvss_vector": vec, "cvss_score": score,
        "success_oracle": ("UNPROVEN at this confidence. To confirm: post a unique canary from a "
                           "foreign origin and observe the sink fire at runtime."),
        "capec": "CAPEC-588: DOM-Based Cross-Site Scripting",
    }


def wm_finding(url: str, rec: dict, payload: dict, family: str, *, control: str = "",
               origin: str = "") -> dict:
    """A CONFIRMED web-message finding: the canary was posted from a FOREIGN origin and the sink
    fired in a real browser. `control` records the mismatched-`targetOrigin` negative control that
    had to stay silent for this to be reported at all.

    `origin` IS THE ORIGIN THAT ACTUALLY POSTED, and it is a parameter rather than a constant because
    hardcoding one made the evidence FALSE. This function printed "from the foreign origin
    https://bbh-evil.example/" while `tools._wm_confirm` was posting from a loopback harness on an
    ephemeral port -- a true finding described by a sentence that never happened. Evidence naming the
    wrong actor is not a cosmetic defect: it is the part a human re-runs to check the claim.
    """
    grade = rec.get("origin_check") or "none"
    label = payload.get("label") or payload.get("kind")
    posted = payload.get("value")
    evidence = ("Framed %s from the foreign origin %s and called "
                "postMessage(%r, \"*\"); %s. %s"
                % (url, origin or "an origin under our control", posted,
                   ("alert(\"%s\") EXECUTED in the page" % WM_MARK) if family == "dom_xss"
                   else ("the page navigated to https://%s/" % EVIL),
                   control or ""))
    if family == "dom_xss":
        f = _base(url, "DOM XSS via postMessage web message (%s)" % label, "high",
                  ("A window 'message' handler on this page passes event.data to a DOM sink. A "
                   "message posted from an origin we control reached that sink and EXECUTED script "
                   "in the page's own origin. Origin validation was graded '%s' from the handler "
                   "source and the runtime confirms it does not stop a foreign sender." % grade),
                  evidence, "dom_xss", "CWE-79",
                  ["postmessage", "web-message", "dom-xss", "cwe-346", "wstg-clnt-11"],
                  ["From a page on an origin you control, embed %s in an iframe (or open it with "
                   "window.open)" % url,
                   "Wait for it to load, then call frame.contentWindow.postMessage(%r, \"*\")" % posted,
                   "Observe alert(\"%s\") fire -- attacker script executing in the target's origin"
                   % WM_MARK],
                  impact=("Any page that can frame or open this one runs arbitrary JavaScript in the "
                          "victim's authenticated session on this origin: session/token theft, "
                          "account actions as the victim, keylogging, phishing from the trusted "
                          "domain."),
                  oracle=("a message posted from a foreign origin caused alert() carrying the unique "
                          "canary \"%s\" to execute, while the same payload sent with a mismatched "
                          "targetOrigin did not" % WM_MARK))
        f["capec"] = "CAPEC-588: DOM-Based Cross-Site Scripting"
        return f
    f = _base(url, "DOM open redirect via postMessage web message (%s)" % label, "medium",
              ("A window 'message' handler uses event.data as a navigation target without validating "
               "event.origin (graded '%s'), so any page that can obtain a handle to this document "
               "can send visitors to an attacker-chosen site." % grade),
              evidence, "open_redirect", "CWE-601",
              ["postmessage", "web-message", "open-redirect", "cwe-346", "wstg-clnt-11"],
              ["From an origin you control, frame %s" % url,
               "Call frame.contentWindow.postMessage(%r, \"*\")" % posted,
               "Observe the browser navigate to https://%s/" % EVIL],
              impact=("An attacker page drives the victim's browser from this trusted origin to a "
                      "site of its choosing, enabling phishing and OAuth/token forwarding."),
              oracle=("a message posted from a foreign origin caused a top-level navigation to the "
                      "attacker host %s, while the same payload sent with a mismatched targetOrigin "
                      "did not" % EVIL))
    return f
