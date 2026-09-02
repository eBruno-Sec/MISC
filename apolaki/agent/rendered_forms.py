"""
Rendered-form probing: injection through the controls a SINGLE-PAGE APP actually renders.

WHY THIS IS NOT `form_xss.parse_forms` WITH A BROWSER BOLTED ON
--------------------------------------------------------------
`parse_forms` answers "what forms does this DOCUMENT declare?" by regex-scraping `<form>` out of
the served bytes. On an SPA the served bytes are a shell, so the answer is "none" -- and that
answer is CORRECT. The question is what is wrong.

MEASURED (juice-shop:3000, Q-158): served HTML = 0 forms / 0 inputs; after render, `#/login`
carries `form#login-form` with `action=null` and `method=null`, and `#/contact` carries
`form#feedback-form` whose controls have no `name=` at all (`id=comment`, `id=captchaControl`).
`parse_forms` drops both before reading a field: it requires `method="post"`, requires an
`action`, and reads `name=`. Feeding it rendered HTML produces a form that cannot be submitted --
a different way to find nothing.

So this module asks a different question, the one that HAS an answer on an SPA:

    "what request does this application send when a human fills its controls?"

The endpoint, the verb, the encoding and the PARAMETER NAMES are not parsed out of attributes;
they are OBSERVED, by filling each rendered control with its own unique marker, letting the
application's own JavaScript build and send the request, and reading back where each marker
landed in the body it sent. `wire_form()` is that observation, and it is the artifact that
replaces `parse_forms`'s output.

That the app's own request is used rather than one we compose is not a purity preference, it is
load-bearing. MEASURED: `POST /rest/user/login` with a broken quote answers a hand-rolled
urllib request with a bare HTML stacktrace carrying no DBMS text, and answers the APPLICATION's
own XHR with `{"error":{"message":"SQLITE_ERROR: unrecognized token: ..."}}`. Same endpoint, same
payload; only the app's request gets the answer that proves the injection.

SHAPE (the house convention -- see `bie.py`): the ORACLE IS PURE and the DRIVER IS DUMB.
Everything above the `live: playwright driver` banner is pure and unit-tested with no browser:
descriptor -> probe plan, wire body -> parameter path, response pair -> verdict. The driver
below it only navigates, clears obstructions, fills, clicks and records.

ORACLES ARE REUSED, NOT RE-INVENTED (`sqli_tool.error_signatures`,
`sqli_tool.auth_bypass_confirmed`, `xss_tool.contexts_of` / `reflected_exploitable` /
`markup_executable`). This module contributes the CARRIER -- a control the application really
submits -- not a fourth opinion about what an injection looks like.
"""
from __future__ import annotations

import json
import re
import time
from urllib.parse import parse_qsl, urlparse

import sqli_tool
import xss_tool as xt

MAX_BODY = 4000                     # response bytes retained per exchange (evidence, not a corpus)

#: One definition, imported rather than copied. 429/503 mean the edge answered, not the
#: application -- `quote_break_recovers`'s docstring records the live bug-bounty false HIGH that
#: came from treating "not a 5xx" as "the application answered". The same rule binds here: no
#: verdict is ever formed from a pair in which either side never reached the app.
_INFRA_STATUSES = sqli_tool._INFRA_STATUSES

#: Controls that cannot carry a text payload. A `range`/`checkbox`/`file` is still part of the
#: form (it is recorded in the descriptor, because the app may require it) but it is never a
#: fuzz target and never gets a marker.
NON_FILLABLE_TYPES = frozenset({
    "checkbox", "radio", "file", "image", "submit", "button", "reset", "range", "color", "hidden",
})

#: Attributes that identify a control, best first. On an SPA the winner is usually NOT `name`:
#: juice-shop's feedback form identifies its comment box only by `id`, and Angular reactive forms
#: identify controls by `formcontrolname`. The provenance is kept (see `field_identity`) because a
#: placeholder-derived label is a weaker claim than a `name`, and evidence should say which it is.
IDENTITY_ATTRS = ("name", "formcontrolname", "data-testid", "id", "aria-label", "placeholder")

_IDENTITY_QUALITY = {"name": "strong", "formcontrolname": "strong", "data-testid": "strong",
                     "id": "medium", "aria-label": "weak", "placeholder": "weak", "": "none"}

#: Hint -> value shape. A default has ONE job: get past the client-side validator so the
#: application actually sends the request. MEASURED: juice-shop's `#loginButton` stays
#: `disabled` (and the click times out) until every required control holds a value its validator
#: accepts, so a form filled with "x" everywhere is a form that never submits and never tests
#: anything. Each shape embeds the marker so the wire mapping survives the shaping.
_SHAPES = (
    (("email", "e-mail", "mail"), "%s@example.test"),
    (("password", "passwort", "passwd", "pwd"), "Aa1!%s"),
    (("phone", "tel", "mobile"), "5550%s"),
    (("url", "website", "link", "homepage"), "http://example.test/%s"),
    (("zip", "postal"), "10001"),
    (("date", "dob", "birth"), "2000-01-01"),
)
_NUMERIC_TYPES = frozenset({"number", "range", "tel"})

MARKER_PREFIX = "apolakirf"


def marker(tag: str, index: int = 0) -> str:
    """A per-control marker. Lowercase and alphanumeric so it survives an input that lowercases or
    strips punctuation, and distinctive enough that finding it in a request body is not a
    coincidence. Pure."""
    return "%s%sf%d" % (MARKER_PREFIX, re.sub(r"[^a-z0-9]", "", str(tag).lower())[:12], int(index))


# ─────────────────────────────────────────────────────────────── pure: the rendered descriptor
def field_identity(field: dict) -> tuple:
    """(label, source_attribute) for a rendered control, best identity first. ("", "") when the
    control is anonymous -- which is not fatal, because the WIRE name is learned from where the
    marker lands, not from the DOM. Pure."""
    f = field or {}
    for attr in IDENTITY_ATTRS:
        val = str(f.get(attr.replace("-", "_")) or f.get(attr) or "").strip()
        if val:
            return val, attr
    return "", ""


def identity_quality(source: str) -> str:
    """How load-bearing an identity is. Ranking/labelling only -- never proof. Pure."""
    return _IDENTITY_QUALITY.get(str(source or ""), "none")


def is_fillable(field: dict) -> bool:
    """Can this control carry a text payload? Pure."""
    f = field or {}
    if str(f.get("type") or "").lower() in NON_FILLABLE_TYPES:
        return False
    return str(f.get("tag") or "").lower() in ("input", "textarea", "select") and bool(f.get("selector"))


def fillable_fields(descriptor: dict) -> list:
    """The controls of a descriptor that can carry a payload, in DOM order. Pure."""
    return [f for f in ((descriptor or {}).get("fields") or []) if is_fillable(f)]


def shaped_value(field: dict, payload: str) -> str:
    """`payload`, shaped so the client-side validator accepts it.

    The shape is chosen from the control's identity + type, NOT from its `type=` alone: an SPA
    routinely renders an e-mail control as `type=text` with only an `aria-label` to say what it is
    (MEASURED on juice-shop's registration form: `#emailControl`, `type=text`,
    `aria-label="Email address field"`). Pure."""
    f = field or {}
    label, _src = field_identity(f)
    blob = " ".join(str(f.get(k) or "") for k in
                    ("type", "name", "formcontrolname", "id", "aria_label", "aria-label",
                     "placeholder", "label")).lower() + " " + str(label).lower()
    itype = str(f.get("type") or "").lower()
    if itype in _NUMERIC_TYPES or "number" in blob:
        digits = re.sub(r"\D", "", payload)
        return digits or "1"
    for hints, shape in _SHAPES:
        if itype in hints or any(h in blob for h in hints):
            return shape % payload if "%s" in shape else shape
    return payload


def baseline_plan(descriptor: dict, *, tag: str) -> dict:
    """Fill EVERY fillable control with its OWN marker, in one submission.

    This is the whole discovery step: one request, and the application itself tells us its
    endpoint, its verb, its encoding and the parameter name behind every control -- the four
    things `parse_forms` reads out of attributes an SPA does not have. Pure.

    Returns {"values": {selector: value}, "markers": {selector: marker}, "fields": {selector: label}}"""
    values, markers, labels = {}, {}, {}
    for i, f in enumerate(fillable_fields(descriptor)):
        sel = f["selector"]
        mk = marker(tag, i)
        values[sel] = shaped_value(f, mk)
        markers[sel] = mk
        labels[sel] = field_identity(f)[0] or sel
    return {"values": values, "markers": markers, "fields": labels}


# ───────────────────────────────────────────────────────────── pure: reading the app's request
def _walk_json(node, marker_text: str, path: str = ""):
    if isinstance(node, dict):
        for k, v in node.items():
            hit = _walk_json(v, marker_text, "%s.%s" % (path, k) if path else str(k))
            if hit:
                return hit
    elif isinstance(node, list):
        for i, v in enumerate(node):
            hit = _walk_json(v, marker_text, "%s[%d]" % (path, i))
            if hit:
                return hit
    elif isinstance(node, str) and marker_text in node:
        return path or "(root)"
    return ""


def locate_marker(body: str, content_type: str, marker_text: str) -> dict:
    """Where a marker landed in the request the application sent.

    {"found": bool, "carrier": "json"|"form"|"query"|"raw"|"", "path": "email" | "user.email" |
     "items[0].name"}. This is the replacement for reading `name=` off an `<input>`: the parameter
    name is whatever the app's own serialiser called it. Pure."""
    text, ct = str(body or ""), str(content_type or "").lower()
    if not marker_text or marker_text not in text:
        return {"found": False, "carrier": "", "path": ""}
    if "json" in ct or text.lstrip()[:1] in ("{", "["):
        try:
            path = _walk_json(json.loads(text), marker_text)
        except Exception:
            path = ""
        if path:
            return {"found": True, "carrier": "json", "path": path}
    if "form-urlencoded" in ct or ("=" in text and "&" in text and "\n" not in text):
        for k, v in parse_qsl(text, keep_blank_values=True):
            if marker_text in v:
                return {"found": True, "carrier": "form", "path": k}
    return {"found": True, "carrier": "raw", "path": ""}


def locate_marker_in_url(url: str, marker_text: str) -> dict:
    """A GET form delivers its values in the query string; same question, other carrier. Pure."""
    if not marker_text or marker_text not in str(url or ""):
        return {"found": False, "carrier": "", "path": ""}
    for k, v in parse_qsl(urlparse(str(url)).query, keep_blank_values=True):
        if marker_text in v:
            return {"found": True, "carrier": "query", "path": k}
    return {"found": True, "carrier": "raw", "path": ""}


def wire_form(submission: dict, plan: dict) -> dict:
    """The OBSERVED form: what `parse_forms` would have produced if the DOM had told the truth.

    {"observed", "url", "method", "content_type", "carrier", "params": {selector: path},
     "unmapped": [selector], "note"}

    `unmapped` is not a failure to hide -- a control whose value never appears in the request is a
    control the app transformed, dropped or did not send, and saying so is the difference between
    "we probed that field" and "we thought we did". Pure."""
    sub, pl = submission or {}, plan or {}
    if not sub.get("observed"):
        return {"observed": False, "url": "", "method": "", "content_type": "", "carrier": "",
                "params": {}, "unmapped": sorted((pl.get("markers") or {}).keys()),
                "note": str(sub.get("reason") or "no submission observed")}
    body, ct, url = sub.get("request_body") or "", sub.get("content_type") or "", sub.get("url") or ""
    params, unmapped, carriers = {}, [], []
    for sel, mk in (pl.get("markers") or {}).items():
        hit = locate_marker(body, ct, mk)
        if not hit["found"]:
            hit = locate_marker_in_url(url, mk)
        if hit["found"] and hit["path"]:
            params[sel] = hit["path"]
            carriers.append(hit["carrier"])
        else:
            unmapped.append(sel)
    return {"observed": True, "url": url, "method": str(sub.get("method") or "").upper(),
            "content_type": ct, "carrier": (carriers or [""])[0], "params": params,
            "unmapped": sorted(unmapped),
            "note": "" if params else "no rendered control's value appeared in the request the app sent"}


# ───────────────────────────────────────────────────────────────────── pure: the probe plans
#: A quote breaks a string literal; this is the classic error-based carrier and it is appended to
#: a value the validator already accepted, so the request still leaves the browser.
QUOTE_PROBE = "'"
#: Doubling the quote ESCAPES it. If the single quote broke a SQL statement, the doubled one must
#: not -- a probe whose "recovery" control also errors was never talking to a SQL parser.
QUOTE_CONTROL = "''"

#: One shot has to carry every breakout the reflection oracle can confirm on, because a rendered
#: form is expensive to submit (navigate + fill + wait for the app's request) and the context is
#: not known until the response comes back. These are exactly `xt.EXECUTABLE_ON_REFLECTION` --
#: contexts where a surviving breakout is proof by itself, so no second browser pass is owed.
XSS_BREAKOUT = "".join(xt.BREAKOUTS[c] for c in ("html", "attr_dq", "attr_sq"))


def probe_plans(descriptor: dict, wire: dict, base_plan: dict, *, tag: str, max_fields: int = 4) -> list:
    """Stage two: what to send now that the application has told us where its parameters are.

    Deliberately a SECOND stage. The auth-bypass payload is only planned for an endpoint the app
    actually posts credentials to, and the reflection payload only for a response a browser would
    parse as markup -- neither is knowable before the baseline submission, and guessing either is
    how a probe becomes noise. Pure.

    Every plan carries the baseline's values for the other controls, so the only thing that
    changes between baseline and probe is the one field under test."""
    plans = []
    if not (wire or {}).get("observed"):
        return plans
    base_values = dict((base_plan or {}).get("values") or {})
    mapped = (wire or {}).get("params") or {}
    is_login = sqli_tool.looks_like_login((wire or {}).get("url") or "")
    for i, f in enumerate(fillable_fields(descriptor)):
        sel = f.get("selector")
        if sel not in mapped or len(plans) >= max_fields * 3:
            continue                          # never claim to have probed a field we cannot deliver to
        label = field_identity(f)[0] or sel
        base_val = base_values.get(sel, "")

        def _mk(kind, payload, family, oracle):
            vals = dict(base_values)
            vals[sel] = payload
            return {"kind": kind, "field": sel, "field_label": label, "param": mapped[sel],
                    "family": family, "oracle": oracle, "payload": payload, "values": vals}

        plans.append(_mk("probe", base_val + QUOTE_PROBE, "sqli", "error-based"))
        plans.append(_mk("control", base_val + QUOTE_CONTROL, "sqli", "error-based"))
        if is_login:
            plans.append(_mk("probe", sqli_tool.AUTH_BYPASS_PAYLOADS[0], "auth_bypass", "auth-bypass"))
        canary = "%s%sx%d" % (MARKER_PREFIX, re.sub(r"[^a-z0-9]", "", str(tag).lower())[:12], i)
        plans.append(_mk("probe", shaped_value(f, canary) + XSS_BREAKOUT, "xss", "reflection"))
    return plans


# ─────────────────────────────────────────────────────────────────────────── pure: the oracles
def _comparable(baseline: dict, probe: dict) -> str:
    """"" when the pair may be judged, otherwise WHY it may not.

    Refusing here is the whole point: a verdict formed from a submission that never happened, or
    from a pair the edge answered, is a false accusation dressed as a differential."""
    b, p = baseline or {}, probe or {}
    for name, ex in (("baseline", b), ("probe", p)):
        if not ex.get("observed"):
            return "%s submission was not observed (%s)" % (name, ex.get("reason") or "no request captured")
        if int(ex.get("status") or 0) in _INFRA_STATUSES:
            return "%s answered HTTP %s -- the edge, not the application" % (name, ex.get("status"))
        if int(ex.get("status") or 0) <= 0:
            return "%s has no HTTP status" % name
    if not _same_endpoint(b.get("url"), p.get("url")):
        return "baseline and probe went to different endpoints (%s vs %s)" % (b.get("url"), p.get("url"))
    return ""


def _same_endpoint(a, b) -> bool:
    pa, pb = urlparse(str(a or "")), urlparse(str(b or ""))
    return (pa.netloc, pa.path.rstrip("/")) == (pb.netloc, pb.path.rstrip("/"))


def judge_error(baseline: dict, probe: dict, control: dict = None) -> dict:
    """Error-based: a DBMS error signature the baseline did not carry.

    `control` is the DOUBLED-quote submission through the SAME control. A doubled quote is an
    ESCAPED quote: if the single quote really broke a SQL string literal, the doubled one must
    repair it. When the control errors too, the 500 was not about our quote and this refuses."""
    why = _comparable(baseline, probe)
    if why:
        return {"confirmed": False, "oracle": "error-based", "reason": why}
    hits = sqli_tool.error_signatures(baseline.get("body") or "", probe.get("body") or "")
    if not hits:
        return {"confirmed": False, "oracle": "error-based",
                "reason": "no DBMS error signature appeared that the baseline lacked"}
    controls = [{"kind": "benign-baseline-signature-absence",
                 "result": "the same form, same control, benign value: none of the matched "
                           "signatures were present"}]
    if control is not None:
        if not control.get("observed"):
            return {"confirmed": False, "oracle": "error-based",
                    "reason": "the escaped-quote control was not delivered, so the signature is unexplained"}
        if sqli_tool.error_signatures(baseline.get("body") or "", control.get("body") or ""):
            return {"confirmed": False, "oracle": "error-based",
                    "reason": "the ESCAPED-quote control produced the same error, so the single "
                              "quote is not what broke the statement"}
        controls.append({"kind": "escaped-quote-recovery", "payload_suffix": QUOTE_CONTROL,
                         "status": control.get("status"),
                         "result": "doubling the quote removed the DBMS error"})
    return {"confirmed": True, "oracle": "error-based", "hits": hits, "negative_controls": controls}


def judge_auth_bypass(baseline: dict, probe: dict) -> dict:
    """Authentication bypass through a rendered credential control."""
    why = _comparable(baseline, probe)
    if why:
        return {"confirmed": False, "oracle": "auth-bypass", "reason": why}
    if not sqli_tool.looks_like_login(probe.get("url") or ""):
        return {"confirmed": False, "oracle": "auth-bypass",
                "reason": "the observed endpoint is not a credential-checking endpoint"}
    sig = sqli_tool.auth_bypass_confirmed(int(baseline.get("status") or 0), baseline.get("body") or "",
                                          int(probe.get("status") or 0), probe.get("body") or "")
    if not sig:
        return {"confirmed": False, "oracle": "auth-bypass",
                "reason": "no session was issued that the benign invalid credential did not also get"}
    return {"confirmed": True, "oracle": "auth-bypass", "signal": sig["signal"], "how": sig["how"],
            "negative_controls": [{
                "kind": "benign-invalid-credential",
                "status": baseline.get("status"),
                "result": "the same form submitted with a benign invalid credential did not "
                          "receive a session"}]}


def judge_reflection(baseline: dict, probe: dict, canary: str) -> dict:
    """Reflected XSS through a rendered control -- the class `run_form_xss` was meant to cover.

    Two refusals matter. A canary echoed into a JSON body is not markup (Q-160,
    `xt.markup_executable`), and a canary whose breakout characters came back ENCODED is a
    correctly-encoded field, which must stay silent -- that is the mandatory negative control."""
    why = _comparable(baseline, probe)
    if why:
        return {"confirmed": False, "oracle": "reflection", "reason": why}
    body = probe.get("body") or ""
    if canary not in body:
        return {"confirmed": False, "oracle": "reflection", "reason": "the value does not reflect"}
    hdrs = {str(k).lower(): str(v).lower() for k, v in (probe.get("response_headers") or {}).items()}
    if not xt.markup_executable(probe.get("response_content_type") or "",
                                nosniff="nosniff" in hdrs.get("x-content-type-options", "")):
        return {"confirmed": False, "oracle": "reflection",
                "reason": "reflected into a %s response, which a browser does not parse as markup"
                          % (probe.get("response_content_type") or "typeless")}
    ctxs = xt.contexts_of(body, canary)
    if not ctxs:
        return {"confirmed": False, "oracle": "reflection", "reason": "no injectable context"}
    for ctx in ctxs:
        if xt.reflected_exploitable(body, ctx):
            return {"confirmed": True, "oracle": "reflection", "context": ctx,
                    "negative_controls": [{
                        "kind": "encoded-output",
                        "result": "the breakout characters survived unencoded in the %s context; an "
                                  "encoded reflection does not reach this branch" % ctx}]}
    return {"confirmed": False, "oracle": "reflection",
            "reason": "the value reflects but its breakout characters came back encoded"}


def judge_probe(baseline: dict, probe: dict, plan: dict, control: dict = None) -> dict:
    """Route one probe to the oracle its family names. Pure; never guesses a family."""
    fam = str((plan or {}).get("family") or "")
    if fam == "auth_bypass":
        return judge_auth_bypass(baseline, probe)
    if fam == "xss":
        payload = str((plan or {}).get("payload") or "")
        canary = (re.search(r"%s[a-z0-9]+" % MARKER_PREFIX, payload) or [payload])[0]
        return judge_reflection(baseline, probe, canary)
    return judge_error(baseline, probe, control)


# ────────────────────────────────────────────────────────────────────────── pure: the findings
def _provenance(route: str, plan: dict, wire: dict, probe: dict) -> dict:
    return {"route": route, "control": plan.get("field"), "control_label": plan.get("field_label"),
            "observed_endpoint": wire.get("url"), "observed_method": wire.get("method"),
            "observed_parameter": plan.get("param"), "carrier": wire.get("carrier"),
            "submitted_by": probe.get("submitted_by"), "settle": probe.get("settle"),
            "discovery": "rendered-control submission (no action/method attribute required)"}


def finding(route: str, plan: dict, wire: dict, baseline: dict, probe: dict, verdict: dict) -> dict:
    """Build the finding its oracle earned, reusing the existing family builders.

    The rendered-form provenance is ADDED to those findings, never substituted for their proof:
    the claim is still "this parameter is concatenated into a statement", and what this module
    contributes is that the value got there through a control the application itself submitted."""
    param = plan.get("param") or plan.get("field_label") or plan.get("field")
    url = wire.get("url") or ""
    if verdict.get("oracle") == "auth-bypass":
        f = sqli_tool.auth_bypass_finding(url, param, plan.get("payload") or "", verdict.get("signal") or "")
    elif verdict.get("oracle") == "reflection":
        f = _reflection_finding(url, param, plan, verdict, probe)
    else:
        f = sqli_tool.error_finding(url, param, QUOTE_PROBE, verdict.get("hits") or [])
    f["rendered_form"] = _provenance(route, plan, wire, probe)
    f["evidence"] = ("%s  |  rendered control %r on %s -> %s %s (%s param %r); baseline HTTP %s -> "
                     "probe HTTP %s" % (f.get("evidence") or "", plan.get("field_label"), route,
                                        wire.get("method"), url, wire.get("carrier"), param,
                                        baseline.get("status"), probe.get("status")))
    f.setdefault("reproduction_steps", [])
    f["reproduction_steps"] = ["Open %s and fill the rendered control %r (%s)"
                               % (route, plan.get("field_label"), plan.get("field")),
                               "Payload: %s" % (plan.get("payload") or ""),
                               "Submit the form; the app sends %s %s with %s=%s"
                               % (wire.get("method"), url, param, plan.get("payload") or "")
                               ] + list(f["reproduction_steps"])
    ncs = list(f.get("negative_controls") or []) + list(verdict.get("negative_controls") or [])
    f["negative_controls"] = ncs
    f["tags"] = sorted(set(list(f.get("tags") or []) + ["rendered-form", "spa"]))
    return f


def _reflection_finding(url: str, param: str, plan: dict, verdict: dict, probe: dict) -> dict:
    ctx = verdict.get("context") or "html"
    return {
        "title": "Reflected XSS via rendered form control '%s'" % (plan.get("field_label") or param),
        "param": param, "severity": "high", "family": "xss", "confidence": "confirmed",
        "target": url, "cwe": "CWE-79",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "cvss_score": 6.1,
        "description": ("A payload typed into the rendered control %r was submitted by the "
                        "application itself and reflected into a %s context with its breakout "
                        "characters unencoded." % (plan.get("field_label"), ctx)),
        "evidence": "payload reflected unencoded in the %s context (HTTP %s)" % (ctx, probe.get("status")),
        "impact": "Execute script in victims' browsers: session/CSRF-token theft, account takeover.",
        "reproduction_steps": [],
        "remediation": "Context-encode reflected values; add a strict Content-Security-Policy.",
        "tags": ["xss", "reflected"],
        "negative_controls": [],
    }


# ══════════════════════════════════════════════════ live: playwright driver (thin, never judges)
#: Enumerate the control groups a rendered page actually shows.
#:
#: A group is a `<form>`/dialog when there is one, otherwise the nearest ancestor that owns a
#: button -- but NEVER an ancestor that also contains the site chrome. Without that last clause
#: the group degenerates to `<body>` and swallows the navbar: MEASURED on juice-shop, the naive
#: version returned a "form" whose fields were the header search box and whose submit buttons were
#: `menu`, `search` and `Your Basket`.
FORM_SCAN_JS = r"""() => {
  const CHROME = 'nav,header,footer,[role=banner],[role=navigation],[role=contentinfo],mat-toolbar';
  const esc = (s) => (window.CSS && CSS.escape) ? CSS.escape(s) : String(s).replace(/[^\w-]/g, '\\$&');
  const attr = (el, a) => el.getAttribute(a) || '';
  const sel = (el) => {
    if (el.id) return '#' + esc(el.id);
    const t = el.tagName.toLowerCase();
    for (const a of ['name', 'formcontrolname', 'data-testid', 'aria-label', 'placeholder']) {
      const v = attr(el, a);
      if (v) return t + '[' + a + '="' + v.replace(/["\\]/g, '\\$&') + '"]';
    }
    return '';
  };
  const shown = (el) => {
    let cs = {};
    try { cs = getComputedStyle(el); } catch (e) { return false; }
    const r = el.getBoundingClientRect();
    return cs.display !== 'none' && cs.visibility !== 'hidden' && Number(cs.opacity || 1) > 0
           && r.width > 0 && r.height > 0 && !el.hasAttribute('hidden');
  };
  const container = (el) => {
    const f = el.closest('form,[role=form],dialog,[role=dialog],[aria-modal="true"]');
    if (f) return f;
    let n = el.parentElement, d = 0;
    while (n && d < 8) {
      if (n.querySelector('button,input[type=submit]') && !n.querySelector(CHROME)) return n;
      n = n.parentElement; d++;
    }
    return null;
  };
  const groups = new Map();
  for (const el of document.querySelectorAll('input,textarea,select')) {
    if (!shown(el)) continue;
    const own = container(el);
    if (!own) continue;
    if (!groups.has(own)) groups.set(own, []);
    if (groups.get(own).length >= 30) continue;
    groups.get(own).push({
      tag: el.tagName.toLowerCase(),
      type: (attr(el, 'type') || el.type || 'text').toLowerCase(),
      name: attr(el, 'name'), formcontrolname: attr(el, 'formcontrolname'),
      id: el.id || '', 'data-testid': attr(el, 'data-testid'),
      'aria-label': attr(el, 'aria-label'), aria_label: attr(el, 'aria-label'),
      placeholder: attr(el, 'placeholder'),
      required: el.required === true || attr(el, 'aria-required') === 'true',
      selector: sel(el)
    });
  }
  const SUBMITISH = /(submit|send|log ?in|sign ?in|sign ?up|register|save|post|search|continue|apply|go)\b/i;
  const out = [];
  for (const [own, fields] of groups) {
    if (out.length >= 8) break;
    const subs = [];
    for (const b of own.querySelectorAll('button,input[type=submit],[role=button]')) {
      if (!shown(b)) continue;
      const text = (b.innerText || b.value || attr(b, 'aria-label') || '').trim().slice(0, 60);
      const type = (attr(b, 'type') || '').toLowerCase();
      subs.push({text: text, id: b.id || '', type: type, disabled: b.disabled === true,
                 rank: type === 'submit' ? 0 : (SUBMITISH.test(text) ? 1 : 2), selector: sel(b)});
    }
    subs.sort((a, b) => a.rank - b.rank);
    out.push({
      container: own.tagName.toLowerCase() + (own.id ? '#' + own.id : ''),
      is_form: own.tagName.toLowerCase() === 'form',
      action: own.getAttribute ? own.getAttribute('action') : null,
      method: own.getAttribute ? own.getAttribute('method') : null,
      fields: fields, submits: subs.filter((s) => s.selector).slice(0, 4)
    });
  }
  return out;
}"""

#: Is the element at `selector` actually clickable, or is something on top of it? Cookie banners
#: and welcome modals are not an edge case: MEASURED on juice-shop, `app-welcome-banner` inside a
#: `mat-dialog` covers `#loginButton` on a cold boot, and a fixed `z-index: 9999` cookie bar sits
#: over the page. A driver that does not clear them reports "the form never submitted" about a
#: perfectly submittable form.
COVERED_JS = r"""(sel) => {
  const el = document.querySelector(sel);
  if (!el) return {found: false, covered: false, layer: ''};
  const r = el.getBoundingClientRect();
  const top = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
  const covered = !(top === el || el.contains(top) || (top && top.contains(el)));
  let layer = '';
  if (covered && top) {
    let n = top, d = 0;
    while (n && d < 8) {
      const cs = getComputedStyle(n);
      if (cs.position === 'fixed' || cs.position === 'absolute' || n.getAttribute('role') === 'dialog'
          || n.getAttribute('aria-modal') === 'true') {
        layer = n.tagName.toLowerCase() + (n.id ? '#' + n.id : '');
        break;
      }
      n = n.parentElement; d++;
    }
  }
  return {found: true, covered: covered, layer: layer || (covered ? 'unknown-layer' : '')};
}"""

#: Generic dismissal vocabulary for a consent/welcome layer. Deliberately generic web wording --
#: a target-specific button label here would be a benchmark signature, which this project refuses.
_DISMISS_WORDS = ("dismiss", "close", "accept", "agree", "allow", "got it", "ok", "okay",
                  "no thanks", "continue", "understood", "i agree", "consent")


def available() -> tuple:
    """(usable, note). Delegates to bie so there is ONE answer about whether a browser exists."""
    import bie
    return bie.available()


def read_forms(page, errors: list = None) -> list:
    """The rendered control groups, or [] with the failure RECORDED.

    `except Exception: return []` would make a page that crashed the evaluate byte-identical to a
    page that genuinely renders no form -- the exact shape Q-016 keeps finding in this codebase."""
    try:
        return list(page.evaluate(FORM_SCAN_JS) or [])
    except Exception as exc:
        if errors is not None and len(errors) < 20:
            errors.append("read_forms: %s: %s" % (type(exc).__name__, str(exc)[:160]))
        return []


def clear_obstruction(page, selector: str, *, budget_ms: int = 4000, errors: list = None) -> str:
    """Uncover `selector`, waiting for the CONDITION (nothing on top of it) and never for a duration.

    Bounded by a deadline, and each pass re-reads `COVERED_JS` rather than assuming the previous
    action worked. Returns what happened, so evidence records how the click became possible."""
    deadline = time.monotonic() + max(0, budget_ms) / 1000.0
    actions = []
    while True:
        try:
            state = page.evaluate(COVERED_JS, selector)
        except Exception as exc:
            if errors is not None:
                errors.append("clear_obstruction: %s" % str(exc)[:120])
            return "probe-failed"
        if not state.get("found"):
            return "control-absent"
        if not state.get("covered"):
            return "clear" if not actions else "cleared by " + ", ".join(actions)
        if time.monotonic() >= deadline:
            return "still covered by %s after %s" % (state.get("layer"), ", ".join(actions) or "no action")
        if "escape" not in actions:
            try:
                page.keyboard.press("Escape")
                actions.append("escape")
                continue
            except Exception:
                pass
        clicked = False
        for word in _DISMISS_WORDS:
            try:
                btn = page.get_by_role("button", name=re.compile(re.escape(word), re.I)).first
                if btn.is_visible(timeout=250):
                    btn.click(timeout=800)
                    actions.append("dismiss:%s" % word)
                    clicked = True
                    break
            except Exception:
                continue
        if not clicked:
            actions.append("no-dismissable-layer")
            return "still covered by %s (%s)" % (state.get("layer"), ", ".join(actions))


def _record_response(resp, out: dict):
    try:
        req = resp.request
        out.update({
            "observed": True, "url": resp.url, "method": (req.method or "").upper(),
            "status": resp.status, "request_body": req.post_data or "",
            "content_type": (req.headers or {}).get("content-type", ""),
            "response_content_type": (resp.headers or {}).get("content-type", ""),
            "response_headers": dict(resp.headers or {}),
            "body": (resp.text() or "")[:MAX_BODY],
        })
    except Exception as exc:
        out.setdefault("observed", False)
        out["reason"] = "response unreadable: %s" % str(exc)[:120]


def fill_and_submit(page, descriptor: dict, values: dict, needles, *,
                    timeout_ms: int = 9000, errors: list = None) -> dict:
    """Fill the rendered controls, let the APPLICATION send its own request, and record it.

    `needles` are the strings that identify OUR submission on the wire; the response expectation is
    registered BEFORE the click so a fast answer cannot be missed (the `bie._goto_awaiting_object`
    pattern). Nothing here decides anything -- an unsubmittable form returns `observed: False` with
    a reason, and the pure oracle refuses to judge it."""
    out = {"observed": False, "reason": "", "filled": [], "submitted_by": "",
           "settle": "expect-response(payload-on-the-wire)"}
    for sel, val in (values or {}).items():
        try:
            page.fill(sel, val, timeout=min(3000, timeout_ms))
            out["filled"].append(sel)
        except Exception as exc:
            if errors is not None and len(errors) < 20:
                errors.append("fill %s: %s" % (sel, str(exc)[:100]))
    if not out["filled"]:
        out["reason"] = "no rendered control accepted a value"
        return out

    def _match(resp):
        try:
            req = resp.request
            if (req.method or "").upper() == "OPTIONS":
                return False
            blob = (req.post_data or "") + " " + (resp.url or "")
            return any(n and n in blob for n in needles)
        except Exception:
            return False

    # Only a control that LOOKS like a submit is worth a click budget. MEASURED: juice-shop's login
    # form also contains a "Button to display the password" toggle, and clicking it costs a full
    # timeout (6s) for a control that can never submit anything. rank 0/1 = type=submit / submit-ish
    # text; anything else is tried only when the form offers nothing better.
    submits = [s for s in (descriptor.get("submits") or []) if s.get("selector")]
    ranked = [s for s in submits if int(s.get("rank", 2)) <= 1] or submits[:1]
    last_field = (out["filled"] or [""])[-1]
    attempts = []
    for sub in ranked[:2]:
        attempts.append(("click", sub["selector"]))
    attempts.append(("enter", last_field))       # many SPA forms submit on Enter and have no button
    for how, target in attempts:
        if not target:
            continue
        out["obstruction"] = clear_obstruction(page, target, errors=errors) if how == "click" else "n/a"
        try:
            with page.expect_response(_match, timeout=timeout_ms) as info:
                if how == "click":
                    page.click(target, timeout=timeout_ms)
                else:
                    page.press(target, "Enter", timeout=min(3000, timeout_ms))
            _record_response(info.value, out)
            if out.get("observed"):
                out["submitted_by"] = "%s:%s" % (how, target)
                return out
        except Exception as exc:
            out["reason"] = "%s on %s did not produce a request carrying our value (%s)" % (
                how, target, str(exc).splitlines()[0][:90])
    return out


def _open_route(page, base: str, route: str, descriptor: dict = None, *, timeout_ms: int = 25000) -> str:
    """Navigate and wait for the FORM to exist -- the condition, bounded. Returns the settle note."""
    import bie
    url = route if "://" in str(route) else "%s/%s" % (str(base).rstrip("/"), str(route).lstrip("/"))
    try:
        import browser_engine
        browser_engine.rate_limited_goto_sync(page, url, wait_until="domcontentloaded", timeout=timeout_ms)
    except Exception as exc:
        return "navigation-failed: %s" % str(exc).splitlines()[0][:90]
    wait_for = ""
    if descriptor:
        wait_for = next((f.get("selector") for f in fillable_fields(descriptor) if f.get("selector")), "")
    try:
        page.wait_for_selector(wait_for or "input,textarea,select", timeout=min(9000, timeout_ms),
                               state="visible")
        note = "form-visible"
    except Exception:
        note = "no-visible-control"
    return note + "+" + bie.settle(page, min(8000, timeout_ms))


def probe_form(page, base: str, route: str, descriptor: dict, *, tag: str, timeout_ms: int = 25000,
               max_fields: int = 3, errors: list = None) -> dict:
    """One rendered form, end to end: learn its wire shape, then probe each mapped control.

    Every submission is a fresh load of the route -- an SPA form keeps state (and often navigates)
    after a submit, so re-using the page would probe a form that is no longer the one described."""
    base_plan = baseline_plan(descriptor, tag=tag)
    if not base_plan["values"]:
        return {"route": route, "wire": {"observed": False, "note": "no fillable control"},
                "probes": [], "findings": []}
    _open_route(page, base, route, descriptor, timeout_ms=timeout_ms)
    baseline = fill_and_submit(page, descriptor, base_plan["values"],
                               list(base_plan["markers"].values()), errors=errors)
    baseline["settle"] = "expect-response"
    wire = wire_form(baseline, base_plan)
    result = {"route": route, "container": descriptor.get("container"),
              "action": descriptor.get("action"), "method_attr": descriptor.get("method"),
              "wire": wire, "baseline": _clip(baseline), "probes": [], "findings": [],
              "exchanges": [exchange_row(baseline, "baseline")]}
    if not wire.get("observed") or not wire.get("params"):
        return result

    plans = probe_plans(descriptor, wire, base_plan, tag=tag, max_fields=max_fields)
    controls = {}
    for plan in plans:
        if plan["kind"] == "control":
            continue
        _open_route(page, base, route, descriptor, timeout_ms=timeout_ms)
        needles = [plan["payload"]] + [v for v in base_plan["markers"].values()]
        probe = fill_and_submit(page, descriptor, plan["values"], needles, errors=errors)
        control = None
        if plan["family"] == "sqli":
            key = (plan["field"], "control")
            if key not in controls:
                cplan = next((p for p in plans if p["kind"] == "control" and p["field"] == plan["field"]), None)
                if cplan:
                    _open_route(page, base, route, descriptor, timeout_ms=timeout_ms)
                    controls[key] = fill_and_submit(page, descriptor, cplan["values"],
                                                    [cplan["payload"]] + needles, errors=errors)
                    result["exchanges"].append(
                        exchange_row(controls[key], "escaped-quote control for %s" % plan["field"]))
            control = controls.get(key)
        result["exchanges"].append(
            exchange_row(probe, "%s probe on %s" % (plan["family"], plan["field"])))
        verdict = judge_probe(baseline, probe, plan, control)
        result["probes"].append({"field": plan["field"], "field_label": plan["field_label"],
                                 "param": plan.get("param"), "family": plan["family"],
                                 "payload": plan["payload"], "status": probe.get("status"),
                                 "observed": bool(probe.get("observed")),
                                 "verdict": verdict.get("confirmed"),
                                 "reason": verdict.get("reason", "")})
        if verdict.get("confirmed"):
            result["findings"].append(finding(route, plan, wire, baseline, probe, verdict))
    return result


def exchange_row(ex: dict, note: str = "") -> dict:
    """One submission, in the shape the engagement's ONE traffic ledger stores.

    NO ISLAND: every request this engine causes the application to send is a real request against
    the target and belongs in the same capture as every other engine's, tagged with its own
    provenance. An engine whose traffic is invisible to the ledger is a second, private history."""
    return {"method": str(ex.get("method") or "POST").upper(), "url": ex.get("url") or "",
            "status": int(ex.get("status") or 0), "len": len(str(ex.get("body") or "")),
            "resp_ct": ex.get("response_content_type") or "", "engine": "rendered-forms",
            "note": note, "observed": bool(ex.get("observed"))}


def _clip(ex: dict) -> dict:
    keep = ("observed", "status", "url", "method", "content_type", "response_content_type",
            "request_body", "reason", "submitted_by", "obstruction")
    out = {k: ex.get(k) for k in keep if k in ex}
    out["body_head"] = str(ex.get("body") or "")[:240]
    return out


def run(base: str, routes=None, *, headers: dict = None, storage: dict = None, timeout_ms: int = 25000,
        max_forms: int = 3, max_fields: int = 3, tag: str = "q158", scope_ok=None) -> dict:
    """Drive every rendered form on `routes` and return findings + the observed wire shapes.

    Read-only: the probes fill and submit forms the application already exposes. Never raises."""
    import bie
    usable, note = available()
    out = {"base": base, "browser": bool(usable), "ran": False, "note": note, "forms": [],
           "findings": [], "exchanges": [], "errors": []}
    if not usable:
        return out
    ok = scope_ok or (lambda _u: True)
    base = str(base or "").rstrip("/")
    if not base or not ok(base):
        out["note"] = "no in-scope base url"
        return out
    routes = list(routes or ["/"])
    from playwright.sync_api import sync_playwright
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            try:
                ctx, page, _cdp, _seeded = bie._new_persona(browser, base, headers or {},
                                                            timeout_ms=timeout_ms, wire=[],
                                                            role="rendered-forms", storage=storage)
                out["ran"] = True
                seen = 0
                for route in routes:
                    url = route if "://" in str(route) else "%s/%s" % (base, str(route).lstrip("/"))
                    if not ok(url):
                        continue
                    _open_route(page, base, route, None, timeout_ms=timeout_ms)
                    for desc in read_forms(page, out["errors"]):
                        if seen >= max_forms:
                            break
                        if not fillable_fields(desc):
                            continue
                        seen += 1
                        res = probe_form(page, base, route, desc, tag="%s%d" % (tag, seen),
                                         timeout_ms=timeout_ms, max_fields=max_fields,
                                         errors=out["errors"])
                        out["forms"].append(res)
                        out["findings"].extend(res.get("findings") or [])
                        out["exchanges"].extend(res.get("exchanges") or [])
                try:
                    ctx.close()
                except Exception:
                    pass
            finally:
                try:
                    browser.close()
                except Exception:
                    pass
    except Exception as exc:
        out["note"] = "browser runtime unavailable: %s" % str(exc)[:140]
        return out
    out["counts"] = {"forms": len(out["forms"]),
                     "wire_observed": sum(1 for f in out["forms"] if (f.get("wire") or {}).get("observed")),
                     "probes": sum(len(f.get("probes") or []) for f in out["forms"]),
                     "submissions": len(out["exchanges"]),
                     "findings": len(out["findings"])}
    return out
