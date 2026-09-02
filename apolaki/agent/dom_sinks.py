"""Client-side sink families beyond `dom_trace`'s four (Q-147). PURE: signals in, findings out.

`dom_trace` proves four families (dom_xss, open_redirect, request_url_override, dom_link/data
manipulation). Burp's catalogue lists roughly twenty client-side sink classes; this module adds the
ones Apolaki could not see, in EXACTLY the same shape: `classify(...)` maps a dict of collected
runtime signals to hit dicts, `finding(hit)` builds the confirmed finding. No network, no browser,
no state - the render collects, this decides.

Two JS constants (`DOM_SINK_HOOKS_JS`, `DOM_SINK_SCAN_JS`) are DATA, not behaviour: the hooks are
installed as a page init script before any application script runs, and the scan reads the recorded
buffer back. They live here rather than in `dom_trace.DOM_SCAN_JS` so this engine's wiring is one
added call and `dom_trace` keeps its own contract.


THE TWO RULES THIS MODULE INHERITS
──────────────────────────────────
Q-128, PRESENCE IN THE DOM IS NOT A DOM FLOW. A stock WordPress produced 314 of 322 findings from
the canary merely BEING in an `href` - the SERVER echoed the request URI into its comment-reply
link and the oracle called it "DOM link manipulation" at CWE-79. `server_reflected` exists for that.

Q-129, A PAGE THAT NEVER LOADED IS NOT A PAGE. A navigation to a dead port still renders the
BROWSER'S OWN ERROR PAGE and Chrome puts the requested URL in it, so the canary was "found" on a
host that answered nothing. `navigated` exists for that; absent means LOADED, deliberately.

BEHAVIOURS ARE NEVER GATED. A dialog that fired, a socket that opened, a header that went out, an
expression that threw - those are things the browser DID. `dom_trace` leaves `dom_xss`,
`open_redirect` and `request_url_override` ungated on both flags for exactly this reason, and every
behaviour family here follows it. `navigated` is set only after `goto` returns, so a slow page that
timed out mid-load can still have fired a real behaviour; suppressing it would trade a
false-positive flood for a missed real bug, which is the wrong trade.

The governing principle, stated once:

    A presence signal is gated on `server_reflected` when the finding's CLAIM is "client-side code
    did this". It is not gated when the claim is STRUCTURAL and true no matter who wrote the value -
    but then the finding must not claim a DOM flow, and must name the real mechanism (reflected /
    stored / DOM) from `server_reflected` instead.

Exactly one family takes the second branch (`form_action_hijack`); see its block for why, and
`tests/test_dom_sinks.py` for the two assertions that pin both halves.
"""
from __future__ import annotations

import dom_trace as dt


# ── structural probe markers ───────────────────────────────────────────────────────────────────
# Each of these turns a substring question ("is the canary in there?") into a STRUCTURAL one ("did
# the canary become its own query key / its own object key / break the expression?"). Substring
# oracles for a structural claim are how four false HIGHs reached a live bug-bounty target.
HPP_MARKER = "apolakihpp"       # probe value: <canary>&apolakihpp=<canary>
JSON_MARKER = "apolakijson"     # probe value: <canary>","apolakijson":"<canary>
XPATH_BREAKER = "'"             # probe value: <canary>'  -> an unbalanced XPath string literal

#: Request headers the BROWSER controls. `Referer` carries the full probe URL - including the canary
#: - on every sub-resource request, so a naive "canary in a header" test reports Ajax header
#: manipulation on every page that loads one image. This list is the difference between the two.
BROWSER_HEADERS = frozenset({
    "referer", "referrer", "origin", "host", "cookie", "user-agent", "accept", "accept-encoding",
    "accept-language", "connection", "content-length", "sec-fetch-site", "sec-fetch-mode",
    "sec-fetch-dest", "sec-fetch-user", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "upgrade-insecure-requests", "cache-control", "pragma", "range", "if-none-match",
    "if-modified-since", "te", "priority",
})

#: Sinks whose arrival means script ran or markup was parsed, in descending danger.
DANGEROUS_SINKS = ("eval", "Function", "setTimeout", "setInterval", "document.write",
                   "document.writeln", "innerHTML", "outerHTML", "insertAdjacentHTML")


# ── pure string helpers (no urlparse, no try/except: these cannot raise) ────────────────────────

def _host_of(u: str) -> str:
    """Authority host of a URL, lower-cased, port and userinfo stripped. Pure and total."""
    s = str(u or "").strip()
    i = s.find("://")
    if i >= 0:
        s = s[i + 3:]
    s = s.split("/")[0].split("?")[0].split("#")[0]
    if "@" in s:
        s = s.rpartition("@")[2]
    if s.startswith("["):                      # IPv6 literal keeps its brackets
        return (s[:s.find("]") + 1] if "]" in s else s).lower()
    return s.split(":")[0].lower()


def _scheme_of(u: str) -> str:
    """Lower-cased URL scheme, or "" when there is none. Pure and total."""
    s = str(u or "").strip()
    i = s.find(":")
    if i <= 0:
        return ""
    head = s[:i]
    return head.lower() if head.replace("+", "").replace("-", "").replace(".", "").isalnum() else ""


def _authority_host(u: str) -> str:
    """The HOST of a URL, with scheme, userinfo, port, path and query removed.

    BREAKER FINDING. `websocket_url_poisoning` claimed "the socket endpoint is chosen by the
    payload" while testing `canary in ws_url` -- a substring anywhere in the URL. An application
    that opens its OWN socket as `wss://app/live?room=<canary>` satisfied that and was reported as
    attacker-controlled routing. The canary REACHING the URL is ordinary data flow; the canary
    being the AUTHORITY is control. Checks 3 and 4 in this file are already structural and say so.

    Userinfo is stripped deliberately: `wss://user:<canary>@app/` still connects to `app`, so a
    canary there controls nothing. Pure string work, consistent with this file's no-urlparse rule.
    """
    rest = u.split("://", 1)[-1]
    for sep in ("/", "?", "#"):
        rest = rest.split(sep, 1)[0]
    rest = rest.rsplit("@", 1)[-1]          # drop userinfo, keep the real destination
    return rest.rsplit(":", 1)[0] if rest.count(":") == 1 else rest


def _query_pairs(u: str) -> list:
    """(key, value) pairs of a URL's query, split STRUCTURALLY on the raw separators. Pure.

    Deliberately NOT `parse_qsl`: no unquoting. A percent-encoded `%26apolakihpp%3D` inside one
    parameter's VALUE must stay one parameter, because that is exactly the shape of our own probe
    URL - unquoting first would make the probe look like the pollution it is testing for."""
    s = str(u or "")
    i = s.find("?")
    if i < 0:
        return []
    q = s[i + 1:].split("#")[0]
    out = []
    for part in q.split("&"):
        if not part:
            continue
        k, _, v = part.partition("=")
        out.append((k, v))
    return out


def _s(sig: dict, key: str) -> str:
    """A signal read as a stripped string. Absent/None/non-string all collapse to ""."""
    v = (sig or {}).get(key)
    return v.strip() if isinstance(v, str) else ("" if v is None else str(v).strip())


def _list(sig: dict, key: str) -> list:
    v = (sig or {}).get(key)
    return list(v) if isinstance(v, (list, tuple)) else []


def _int(sig: dict, key: str) -> int:
    v = (sig or {}).get(key)
    return v if isinstance(v, int) and not isinstance(v, bool) else 0


def source_phrase(source: str, param: str) -> str:
    """Human wording for the injection point, extending `dom_trace`'s vocabulary. Pure."""
    if source == "web_message":
        return "a cross-origin web message (postMessage)"
    if source == "page":
        return "the page as served"
    return dt.source_phrase(source, param)


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# PARAMETER-SCOPED CLASSIFIER
# ═══════════════════════════════════════════════════════════════════════════════════════════════

def classify(url: str, param: str, canary: str, sig: dict, source: str = "query") -> list:
    """PURE: signals collected for ONE source/parameter -> the confirmed hits, most severe first.

    Same signature and same hit shape as `dom_trace.classify`, so the wiring is one added line and
    the caller's dedup key `(family, param)` keeps working unchanged."""
    hits, s = [], sig or {}
    here = dt.probe_url(url, param, canary, source)
    where = source_phrase(source, param)
    # Q-129. Absent means LOADED: every existing caller omits the key, and defaulting the other way
    # silently disables the presence families everywhere they were not threaded through.
    loaded = s.get("navigated", True)

    def _add(family, evidence, target=None, **extra):
        hit = {"family": family, "param": param, "source": source, "canary": canary,
               "target": target or here, "evidence": evidence}
        hit.update(extra)
        hits.append(hit)

    # ── BEHAVIOURS (ungated) ────────────────────────────────────────────────────────────────────

    # 1. document.domain manipulation. The canary must be INSIDE the written value: a page that
    #    legitimately does `document.domain = "example.com"` writes the setter on every load, and
    #    reporting the write itself would fire on every such page forever.
    dd = _s(s, "doc_domain_write")
    if dd and canary in dd:
        _add("document_domain_manipulation",
             "%s reaches a runtime `document.domain` assignment: document.domain -> %r. The value "
             "the page writes is attacker-controlled, so the payload chooses the document's origin "
             "for same-origin-policy purposes." % (where, dd[:120]),
             target=s.get("docdomain_target"))

    # 2. WebSocket URL poisoning. Attacker-controlled means the canary reached the URL, or the URL
    #    IS the attacker host we injected - a bare `ws_url` is just the application's own socket.
    wu = _s(s, "ws_url")
    if wu and (canary in _authority_host(wu) or dt.is_evil_host(wu)):
        opened = bool(s.get("ws_opened"))
        _add("websocket_url_poisoning",
             "%s controls the target of a WebSocket handshake request the page opened: %s%s. The "
             "socket endpoint is chosen by the payload, not by the application." % (
                 where, wu[:140],
                 " (the connection reached OPEN)" if opened else " (constructed; OPEN not observed)"),
             target=s.get("ws_target"))

    # 3. Client-side HTTP parameter pollution. STRUCTURAL: the marker must be its OWN query key in a
    #    request the page built, carrying our canary as its value. A substring test here would fire
    #    on our own probe URL, which contains the marker percent-encoded inside one parameter.
    for cand in _list(s, "hpp_request_urls"):
        cu = str(cand or "")
        if not cu or cu == here:        # never the navigation we ourselves sent
            continue
        polluted = [v for k, v in _query_pairs(cu) if k == HPP_MARKER]
        if polluted and canary in polluted[0]:
            _add("client_side_hpp",
                 "%s injects a parameter separator into a URL the page builds at runtime: the "
                 "request %s carries `%s` as a SEPARATE query parameter, not as part of the value "
                 "the application intended. Client-side HTTP parameter pollution." % (
                     where, cu[:140], HPP_MARKER),
                 target=s.get("hpp_target"))
            break

    # 4. Client-side JSON injection. STRUCTURAL: the marker became a KEY of the parsed object, which
    #    can only happen if the payload broke out of the JSON string literal it was concatenated
    #    into. The canary appearing as a VALUE is ordinary data flow and is not reported.
    if JSON_MARKER in [str(k) for k in _list(s, "json_keys")]:
        _add("client_json_injection",
             "%s breaks out of a JSON string literal the page concatenates and parses at runtime: "
             "the payload added `%s` as a top-level KEY of the object `JSON.parse` returned, so the "
             "attacker controls the parsed structure, not just one value." % (where, JSON_MARKER),
             target=s.get("json_target"))

    # 5. Client-side XPath injection. A three-fact differential, not a substring: the parameter
    #    reaches an expression, an unbalanced quote makes `document.evaluate` throw, and the SAME
    #    render without the quote does not. Any two of the three alone are not injection.
    xexpr = next((str(e) for e in _list(s, "xpath_exprs") if canary in str(e)), "")
    if xexpr and s.get("xpath_error") and not s.get("xpath_baseline_error"):
        _add("client_xpath_injection",
             "%s is concatenated into a client-side XPath expression evaluated at runtime "
             "(`%s`); the payload `%s%s` made `document.evaluate` throw a syntax error while the "
             "identical render without the quote did not. The parameter changes the expression's "
             "STRUCTURE, not only its data." % (where, xexpr[:120], canary, XPATH_BREAKER),
             target=s.get("xpath_target"))

    # 6. Ajax request header manipulation. The Referer trap: the browser puts the full probe URL -
    #    canary included - in `Referer` on every sub-resource request, so an unfiltered "canary in a
    #    header" test reports this family on every page that loads one image. Only headers the PAGE
    #    set count, and controlling the header NAME is a materially worse bug than its value.
    for pair in _list(s, "ajax_headers"):
        if not (isinstance(pair, (list, tuple)) and len(pair) >= 2):
            continue
        name, value = str(pair[0]), str(pair[1])
        if name.strip().lower() in BROWSER_HEADERS:
            continue
        if canary in name:
            _add("ajax_header_manipulation",
                 "%s controls the NAME of a request header the page sets at runtime: `%s: %s`. An "
                 "attacker-chosen header name lets the payload introduce headers the application "
                 "never intended to send." % (where, name[:80], value[:60]),
                 target=s.get("ajaxhdr_target"), cwe="CWE-113",
                 cvss=("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4))
            break
        if canary in value:
            _add("ajax_header_manipulation",
                 "%s controls the VALUE of the request header `%s` that the page sets at runtime "
                 "(`%s`). The payload is placed in an outbound header by client-side code." % (
                     where, name[:80], value[:100]),
                 target=s.get("ajaxhdr_target"), cwe="CWE-20",
                 cvss=("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1))
            break

    # 7. DOM-based denial of service. A REPEATED differential or nothing. One hung render is a flaky
    #    lab, a slow container or a rate limiter; this is the noisiest signal in the module and the
    #    only defensible form of it is "every probe render hung and no baseline render did".
    dos_r, dos_h, dos_b = _int(s, "dos_renders"), _int(s, "dos_hangs"), _int(s, "dos_baseline_hangs")
    if dos_r >= 2 and dos_h == dos_r and dos_b == 0:
        _add("client_side_dos",
             "%s makes the page stop responding: %d of %d probe renders exceeded the load budget "
             "with the payload present and 0 of the baseline renders did. The payload reaches a "
             "client-side construct that consumes the render thread." % (where, dos_h, dos_r),
             target=s.get("dos_target"),
             cvss=("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L", 4.3))

    # 8. Persistent DOM XSS via web storage. The payload arrives in the URL, client-side code writes
    #    it to localStorage/sessionStorage, and it EXECUTES on a later load whose URL is clean.
    #    Execution is a behaviour, so this half is ungated - but the write and the replay are still
    #    required, or this is just `dom_xss` reported twice.
    st_write = next((w for w in _list(s, "storage_writes")
                     if isinstance(w, dict) and canary in str(w.get("value", ""))), None)
    replay_clean = (not s.get("storage_replay_server_reflected")) and s.get("storage_replay_navigated", True)
    if st_write and s.get("storage_replay_executed"):
        # The execution is REAL and never gated -- a dialog fired. But when the replay render was
        # ALSO server-reflected there were two possible carriers for the value, and the mechanism
        # claim ("it came back out of storage") is then only one of them. Saying so keeps the
        # finding honest without downgrading a behaviour the browser actually performed: the Q-128
        # rule applied to evidence rather than to severity.
        _also = ("" if replay_clean else
                 " NOTE: the replay response also carried the canary, so the server stored it too "
                 "and storage is one of two possible carriers -- the execution is confirmed, the "
                 "storage path is not exclusive.")
        _add("dom_storage_xss",
             "%s is written to %s['%s'] by client-side code and EXECUTES on a subsequent load whose "
             "URL contains no payload at all: the browser fired the canary dialog from the stored "
             "value. A crafted link plants the payload once and it runs on every later visit.%s" % (
                 where, st_write.get("store", "localStorage"), str(st_write.get("key", ""))[:60],
                 _also),
             target=s.get("storage_target"))

    # ── PRESENCE, GATED (Q-128 + Q-129) ─────────────────────────────────────────────────────────

    # 9. HTML5 storage manipulation without execution. The replay render is the whole oracle: its
    #    URL carries no canary, so a canary in ITS raw response means the SERVER stored the value -
    #    that is server-side stored input, owned by another engine, and calling it "web storage
    #    manipulation" would be a false claim about the mechanism. Same rule as Q-128, one render
    #    later.
    if st_write and s.get("storage_replayed") and replay_clean and not s.get("storage_replay_executed"):
        sink = _s(s, "storage_replay_sink")
        _add("dom_storage_manipulation",
             "%s is persisted to %s['%s'] by client-side code and read back into the page on a "
             "subsequent load whose URL contains no payload%s. The application trusts web-storage "
             "content it wrote from an attacker-controlled source." % (
                 where, st_write.get("store", "localStorage"), str(st_write.get("key", ""))[:60],
                 (" (it reached the `%s` sink)" % sink) if sink else ""),
             target=s.get("storage_target"))

    # 10. Local file path manipulation. Gated presence, and the STRUCTURE carries the claim: the
    #     canary must be inside a `file:` URL, not merely somewhere in an href. The reflected
    #     variant of this class is server-side path handling, which other engines own; what is
    #     claimed here is specifically a client-side local file reference, so the Q-128 gate applies
    #     in full.
    if loaded and not s.get("server_reflected"):
        fu = next((str(u) for u in _list(s, "file_urls")
                   if canary in str(u) and _scheme_of(str(u)) == "file"), "")
        if fu:
            _add("local_file_path_manipulation",
                 "%s controls a local file reference the page resolves at runtime: %s -> `%s`. The "
                 "payload chooses a path on the client's own filesystem." % (where, param, fu[:140]))

    # ── PRESENCE, STRUCTURAL, DELIBERATELY NOT GATED ON `server_reflected` ──────────────────────
    #
    # 11. Form action hijacking. Gating this on `server_reflected` would delete the variant Burp
    #     calls "Form action hijacking (reflected)", which is a real credential-theft bug and which
    #     Q-147 explicitly asks for: the server echoes `?next=https://evil/` into
    #     `<form action="https://evil/">` and the victim's password is posted to the attacker. The
    #     server put it there. That IS the bug.
    #
    #     So the discriminator is not WHO wrote the value, it is WHAT the value controls: the
    #     resolved action's AUTHORITY must be the attacker host we injected, parsed - never a
    #     substring. A canary that merely appears in the action's query string is NOT a finding,
    #     and that is precisely the WordPress shape that produced the 314 false positives.
    #
    #     `server_reflected` still decides the WORDING, so this module never claims a DOM flow for a
    #     server echo. Q-129 still applies: a page that never loaded proves nothing.
    fa = _s(s, "form_action")
    if loaded and fa and dt.is_evil_host(fa):
        mech = "the server reflected it into the form's action attribute (reflected form action " \
               "hijacking)" if s.get("server_reflected") else \
               "client-side code wrote the form's action at runtime (DOM-based form action hijacking)"
        pw = bool(s.get("form_password"))
        _add("form_action_hijack",
             "%s sets the submission target of a form on this page to the attacker host `%s` "
             "(resolved action: %s); %s. Submitting the form sends %s to a host the application "
             "does not control." % (
                 where, _host_of(fa), fa[:140], mech,
                 "the victim's credentials - the form carries a password field" if pw
                 else "every field the victim typed"),
             target=s.get("form_target"), form_password=pw,
             cvss=("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1) if pw
             else ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N", 4.7))

    hits.sort(key=_severity_key, reverse=True)
    return hits


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# PAGE-SCOPED CLASSIFIER  (sinks with no URL parameter as their source)
# ═══════════════════════════════════════════════════════════════════════════════════════════════

def classify_page(url: str, sig: dict) -> list:
    """PURE: page-level client-side sinks - web messages and PRSSI. Most severe first.

    These have no injected parameter: the source of a web message is the message, and PRSSI is a
    property of how the page as served resolves its own stylesheet references."""
    hits, s = [], sig or {}
    loaded = s.get("navigated", True)

    def _add(family, param, source, evidence, **extra):
        hit = {"family": family, "param": param, "source": source, "canary": _s(s, "pm_canary"),
               "target": url, "evidence": evidence}
        hit.update(extra)
        hits.append(hit)

    # WEB MESSAGES ARE NOT CLASSIFIED HERE. `_run_dom_audit` already delivers them from a real
    # bound harness origin and applies a targeted-origin control, and this module reaching the same
    # verdict from its own hooks would put two rows for one fact in the report, drifting apart on
    # every edit. The families this file still owns are the ones with no other producer.

    # ── 3. Path-relative style sheet import ─────────────────────────────────────────────────────
    #
    # A three-signal CONJUNCTION, because any one of them alone is ordinary. The server must accept
    # extra path segments and still return this page, the page must import a stylesheet by a
    # path-relative reference (so the import resolves against the padded path), AND the document
    # must render in quirks mode (so the browser accepts the response as CSS whatever its type).
    # No canary is involved, so `server_reflected` has nothing to gate; `navigated` still does.
    css = _s(s, "prssi_relative_css")
    if loaded and css and s.get("prssi_path_tolerant") and s.get("prssi_quirks"):
        _add("prssi", "(page)", "page",
             "Path-relative style sheet import: the server returns this same page's response for a "
             "padded path (extra segments appended), the document imports `%s` by a path-relative "
             "reference that therefore resolves under the attacker-chosen path, and the document "
             "renders in quirks mode (`compatMode=BackCompat`) so the browser will accept the "
             "response body as a style sheet regardless of its Content-Type." % css[:120],
             target=_s(s, "prssi_target") or url)

    hits.sort(key=_severity_key, reverse=True)
    return hits


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# FINDING SHAPE
# ═══════════════════════════════════════════════════════════════════════════════════════════════
# CVSS vectors and their scores are paired from the standard v3.1 calculator; every score here is
# one of the five vectors already in use by `dom_trace` or computed from the same base equation, so
# a vector and its number can never disagree.
_V_61 = ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1)
_V_54 = ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", 5.4)
_V_47 = ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N", 4.7)
_V_43 = ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", 4.3)
_V_31 = ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1)

_CVSS = {
    "document_domain_manipulation": _V_47,
    "websocket_url_poisoning": _V_54,
    "form_action_hijack": _V_47,
    "dom_storage_xss": _V_61,
    "dom_storage_manipulation": _V_43,
    "ajax_header_manipulation": _V_31,
    "client_side_hpp": _V_43,
    "client_json_injection": _V_54,
    "client_xpath_injection": _V_54,
    "client_side_dos": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L", 4.3),
    "local_file_path_manipulation": _V_43,
    "prssi": _V_31,
}

_CWE = {
    "document_domain_manipulation": "CWE-346",
    "websocket_url_poisoning": "CWE-918",           # attacker chooses the request target
    "form_action_hijack": "CWE-601",
    "dom_storage_xss": "CWE-79",
    "dom_storage_manipulation": "CWE-345",          # Insufficient Verification of Data Authenticity
    "ajax_header_manipulation": "CWE-20",
    "client_side_hpp": "CWE-235",                   # Improper Handling of Extra Parameters
    "client_json_injection": "CWE-74",
    "client_xpath_injection": "CWE-643",
    "client_side_dos": "CWE-400",
    "local_file_path_manipulation": "CWE-73",       # External Control of File Name or Path
    "prssi": "CWE-706",                             # Use of Incorrectly-Resolved Name or Reference
}

_TITLE = {
    "document_domain_manipulation": "Document domain manipulation",
    "websocket_url_poisoning": "WebSocket URL poisoning",
    "form_action_hijack": "Form action hijacking",
    "dom_storage_xss": "Persistent DOM XSS via HTML5 web storage",
    "dom_storage_manipulation": "HTML5 web storage manipulation",
    "ajax_header_manipulation": "Ajax request header manipulation",
    "client_side_hpp": "Client-side HTTP parameter pollution",
    "client_json_injection": "Client-side JSON injection",
    "client_xpath_injection": "Client-side XPath injection",
    "client_side_dos": "DOM-based denial of service",
    "local_file_path_manipulation": "Local file path manipulation",
    "prssi": "Path-relative style sheet import",
}

_IMPACT = {
    "document_domain_manipulation":
        "The payload chooses the document's effective origin, collapsing the same-origin boundary "
        "with sibling subdomains: one XSS anywhere under the parent domain then reaches this page's "
        "DOM, cookies and session.",
    "websocket_url_poisoning":
        "The attacker chooses the WebSocket endpoint the page connects to, so the whole duplex "
        "channel - the data the page sends and everything it renders from the replies - belongs to "
        "the attacker.",
    "form_action_hijack":
        "The form submits to an attacker-controlled host, so everything the victim typed - "
        "credentials included where the form has a password field - is delivered to the attacker "
        "when they click submit on the application's own page.",
    "dom_storage_xss":
        "A single crafted link plants a payload in the victim's web storage that executes on every "
        "later visit to the application, with no attacker involvement after the first click.",
    "dom_storage_manipulation":
        "Attacker-chosen content persists in the victim's browser and is re-read as trusted input "
        "by the application on later visits.",
    "ajax_header_manipulation":
        "The payload controls headers the page sends, allowing headers the application never "
        "intended - authorization, routing or cache-key headers - to be introduced from a link.",
    "client_side_hpp":
        "The payload adds parameters to requests the page builds, overriding values the application "
        "chose and reaching functionality the intended request never exposed.",
    "client_json_injection":
        "The payload controls the STRUCTURE of an object the page parses and then trusts, letting "
        "it introduce or override properties the application relies on for its client-side "
        "decisions.",
    "client_xpath_injection":
        "The payload changes the XPath expression the page evaluates, so it can select nodes the "
        "query was written to exclude.",
    "client_side_dos":
        "A crafted link makes the application's own page unusable in the victim's browser.",
    "local_file_path_manipulation":
        "The payload chooses a path on the client's filesystem that the application then reads or "
        "references.",
    "prssi":
        "A crafted URL makes the page import its own response body as a style sheet, which in a "
        "browser that evaluates style-sheet expressions yields script execution and in any browser "
        "allows the page's rendering to be controlled from a link.",
}


def _cvss_of(hit: dict) -> tuple:
    """The hit's own CVSS override (severity varies WITHIN a family for two of these) else the
    family default. One place, so a vector and its score can never be paired by hand twice."""
    c = (hit or {}).get("cvss")
    if isinstance(c, (list, tuple)) and len(c) == 2:
        return c[0], c[1]
    return _CVSS.get((hit or {}).get("family", ""), ("", None))


def _severity_key(hit: dict) -> float:
    return float(_cvss_of(hit)[1] or 0.0)


def severity_of(score) -> str:
    sc = float(score or 0.0)
    return "high" if sc >= 7.0 else ("medium" if sc >= 4.0 else "low")


def finding(hit: dict) -> dict:
    """Build a CONFIRMED finding from a hit. Same shape as `dom_trace.finding`."""
    fam = hit["family"]
    vec, score = _cvss_of(hit)
    src = hit.get("source") or "query"
    where = {"query": "", "fragment": " (via the URL fragment)",
             "fragment_raw": " (via the URL fragment)",
             "web_message": "", "page": ""}.get(src, "")
    named = fam not in ("web_message_xss", "web_message_manipulation", "prssi")
    title = "%s in '%s'%s" % (_TITLE.get(fam, fam), hit["param"], where) if named \
        else _TITLE.get(fam, fam)
    steps = ["Load %s in a browser" % hit["target"]]
    if src == "web_message":
        steps = ["Load %s in a browser" % hit["target"],
                 "From a page on a DIFFERENT origin, open this URL and post a message to the "
                 "window: `w.postMessage(payload, '*')`",
                 "Observe the message data reach the client-side sink named in the evidence"]
    elif fam in ("dom_storage_xss", "dom_storage_manipulation"):
        steps = ["Load %s in a browser (this plants the payload in web storage)" % hit["target"],
                 "Navigate to the same page with NO payload in the URL",
                 "Observe the stored value come back out of web storage into the page"]
    elif fam == "prssi":
        steps = ["Request %s with extra path segments appended" % hit["target"],
                 "Observe the server return the same page and the page import its own response "
                 "body as a style sheet"]
    else:
        steps.append("Observe the attacker-controlled payload reach the client-side sink named in "
                     "the evidence")
    if src in ("fragment", "fragment_raw"):
        steps.append("NOTE: the payload is in the URL FRAGMENT, which the browser never sends to "
                     "the server - this cannot be reproduced from a server-side request log or by "
                     "replaying the request.")
    return {
        "title": title,
        "severity": severity_of(score),
        "family": fam,
        "confidence": "confirmed",
        "target": hit["target"],
        "source": src,
        "cwe": hit.get("cwe") or _CWE.get(fam, "CWE-79"),
        "cvss_vector": vec,
        "cvss_score": score,
        "evidence": hit["evidence"],
        "success_oracle": "a client-side sink was observed receiving attacker-controlled data at "
                          "runtime in a real browser, with the structural discriminator for this "
                          "family satisfied (not a substring match) and the server-reflection and "
                          "page-loaded controls applied.",
        "reproduction_steps": steps,
        "impact": _IMPACT.get(fam, ""),
        "tags": ["dom", "client-side", "runtime-canary", fam],
    }


# ═══════════════════════════════════════════════════════════════════════════════════════════════
# THE IN-PAGE COLLECTORS  (data, not behaviour - the driver installs and reads these)
# ═══════════════════════════════════════════════════════════════════════════════════════════════
#
# DOM_SINK_HOOKS_JS is an INIT SCRIPT: it must run before any application script, so it is installed
# with `page.add_init_script(...)`, never `page.evaluate(...)`. Evaluating it after load would wrap
# functions the application already captured references to, and every hook would silently record
# nothing - the same shape of failure as the missing `DOM_SCAN_JS` constant, which looked present
# and collected nothing for every render.
DOM_SINK_HOOKS_JS = r"""
(() => {
  if (window.__apolaki_sinks) return;
  const B = { sink_hits: [], json_keys: [], xpath_exprs: [], xpath_error: false,
              storage_writes: [], doc_domain_write: "", ws_urls: [], ws_opened: false,
              ajax_headers: [] };
  window.__apolaki_sinks = B;

  // RESTORED. Deleting the web-message hooks took `cap` out with them, because it sat between
  // them and this line. Every recorder in this file calls it, each inside `try { } catch (e) {}`,
  // so the ReferenceError was swallowed 100% of the time and EVERY sink went silently unrecorded:
  // ws_urls, json_keys, xpath_exprs, storage_writes, and sink_hits via `rec`. The unit suite
  // stayed green because it feeds `classify` a signal dict directly and never runs this JS. The
  // liveness gate caught it in one run -- and I had already SEEN `storage_writes: []` on a page
  // that writes to localStorage and read past it.
  const cap = (a, v) => { if (a.length < 40) a.push(v); };
  const MINE = /__apolaki/;
  const rec = (name, v) => { try { if (typeof v === "string" && v && !MINE.test(v))
      cap(B.sink_hits, { sink: name, value: v.slice(0, 400) }); } catch (e) {} };

  // script-executing / markup-parsing sinks
  const wrapFn = (obj, name, label) => { try {
      const o = obj[name]; if (typeof o !== "function") return;
      obj[name] = function () { rec(label, arguments[0]); return o.apply(this, arguments); };
    } catch (e) {} };
  wrapFn(window, "eval", "eval");
  wrapFn(window, "setTimeout", "setTimeout");
  wrapFn(window, "setInterval", "setInterval");
  wrapFn(document, "write", "document.write");
  wrapFn(document, "writeln", "document.writeln");
  try { const F = window.Function;
    window.Function = function () { rec("Function", arguments[arguments.length - 1]);
                                    return F.apply(this, arguments); }; } catch (e) {}
  for (const [proto, prop, label] of [[Element.prototype, "innerHTML", "innerHTML"],
                                      [Element.prototype, "outerHTML", "outerHTML"]]) {
    try { const d = Object.getOwnPropertyDescriptor(proto, prop); if (!d || !d.set) continue;
      Object.defineProperty(proto, prop, Object.assign({}, d, {
        set: function (v) { rec(label, v); return d.set.call(this, v); } })); } catch (e) {}
  }
  wrapFn(Element.prototype, "insertAdjacentHTML", "insertAdjacentHTML");

  // document.domain: record what the page WRITES, not what it reads
  try { const d = Object.getOwnPropertyDescriptor(Document.prototype, "domain");
    if (d && d.set) Object.defineProperty(Document.prototype, "domain", Object.assign({}, d, {
      set: function (v) { try { B.doc_domain_write = String(v).slice(0, 200); } catch (e) {}
                          return d.set.call(this, v); } })); } catch (e) {}

  // Ajax request headers. `classify` has read `ajax_headers` since the module was written and
  // NOTHING EVER PRODUCED IT, so the family could not fire -- reachable code, unreachable verdict.
  // Only headers the PAGE sets are recorded: the browser puts the full probe URL, canary included,
  // in `Referer` on every sub-resource request, so an unfiltered "canary in a header" test reports
  // this family on every page that loads one image. `classify` drops BROWSER_HEADERS for the same
  // reason; recording only what the page set is the other half of that guard.
  try { const XS = XMLHttpRequest.prototype.setRequestHeader;
    XMLHttpRequest.prototype.setRequestHeader = function (n, v) {
      try { cap(B.ajax_headers, [String(n), String(v)]); } catch (e) {}
      return XS.apply(this, arguments); }; } catch (e) {}
  try { const F = window.fetch;
    window.fetch = function (input, init) {
      try {
        const h = (init && init.headers) || (input && input.headers) || null;
        if (h) {
          if (typeof h.forEach === "function") { h.forEach((v, k) => cap(B.ajax_headers, [String(k), String(v)])); }
          else if (Array.isArray(h)) { for (const kv of h) cap(B.ajax_headers, [String(kv[0]), String(kv[1])]); }
          else { for (const k of Object.keys(h)) cap(B.ajax_headers, [String(k), String(h[k])]); }
        }
      } catch (e) {}
      return F.apply(this, arguments); }; } catch (e) {}

  // WebSocket construction (belt-and-braces: the driver's page.on("websocket") is the primary)
  try { const W = window.WebSocket;
    const P = function (u, p) { try { cap(B.ws_urls, String(u).slice(0, 300)); } catch (e) {}
      const s = p === undefined ? new W(u) : new W(u, p);
      try { s.addEventListener("open", () => { B.ws_opened = true; }); } catch (e) {}
      return s; };
    P.prototype = W.prototype; for (const k of ["CONNECTING", "OPEN", "CLOSING", "CLOSED"]) P[k] = W[k];
    window.WebSocket = P; } catch (e) {}

  // JSON.parse: the KEYS of the object that came back are the structural evidence
  try { const J = JSON.parse;
    JSON.parse = function (t) { const r = J.apply(this, arguments);
      try { if (r && typeof r === "object" && !Array.isArray(r))
              for (const k of Object.keys(r)) cap(B.json_keys, String(k).slice(0, 80)); } catch (e) {}
      return r; }; } catch (e) {}

  // document.evaluate: the expression, and whether an unbalanced quote made it throw
  try { const E = document.evaluate;
    document.evaluate = function (expr) { try { cap(B.xpath_exprs, String(expr).slice(0, 300)); } catch (e) {}
      try { return E.apply(this, arguments); }
      catch (err) { B.xpath_error = true; throw err; } }; } catch (e) {}

  // web storage writes
  try { const S = Storage.prototype.setItem;
    Storage.prototype.setItem = function (k, v) {
      try { cap(B.storage_writes, { store: (this === window.sessionStorage ? "sessionStorage"
                                                                           : "localStorage"),
                                    key: String(k).slice(0, 120), value: String(v).slice(0, 400) });
      } catch (e) {}
      return S.apply(this, arguments); }; } catch (e) {}
})();
"""

#: Read the hook buffer back AND collect the pure-DOM signals this engine needs, in one evaluate.
#: Takes the canary, like `dom_trace.DOM_SCAN_JS`, and returns keys that merge straight into `sig`.
DOM_SINK_SCAN_JS = r"""(c) => {
  const B = window.__apolaki_sinks || {};
  const o = { ajax_headers: B.ajax_headers || [], sink_hits: B.sink_hits || [], json_keys: B.json_keys || [],
              xpath_exprs: B.xpath_exprs || [], xpath_error: !!B.xpath_error,
              storage_writes: B.storage_writes || [], doc_domain_write: B.doc_domain_write || "",
              ws_url: "", ws_opened: !!B.ws_opened, form_action: "", form_password: false,
              file_urls: [], prssi_quirks: false, prssi_relative_css: "" };
  try { o.ws_url = (B.ws_urls || []).find(u => u.indexOf(c) >= 0) || (B.ws_urls || [])[0] || ""; } catch (e) {}
  try {
    for (const f of document.querySelectorAll("form")) {
      const a = f.action || "";
      if (!a) continue;
      if (a.indexOf(c) >= 0 || /^https?:\/\/evilc[0-9a-z]+\.example/i.test(a)) {
        o.form_action = a.slice(0, 300);
        o.form_password = !!f.querySelector("input[type=password]");
        break;
      }
    }
  } catch (e) {}
  try {
    for (const e2 of document.querySelectorAll("[href],[src]")) {
      const v = e2.getAttribute("href") || e2.getAttribute("src") || "";
      if (v.slice(0, 5).toLowerCase() === "file:" && v.indexOf(c) >= 0) {
        o.file_urls.push(v.slice(0, 300)); if (o.file_urls.length > 5) break; }
    }
  } catch (e) {}
  try { o.prssi_quirks = (document.compatMode === "BackCompat"); } catch (e) {}
  try {
    for (const l of document.querySelectorAll("link[rel~=stylesheet i][href]")) {
      const h = l.getAttribute("href") || "";
      if (h && h[0] !== "/" && h.indexOf("://") < 0 && h.slice(0, 5) !== "data:") {
        o.prssi_relative_css = h.slice(0, 200); break; }
    }
  } catch (e) {}
  return o;
}"""


