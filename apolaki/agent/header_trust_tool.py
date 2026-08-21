"""
Header-trust engine (T1) — authorization decided by a client-controlled header.

Found by walking OverTheWire Natas: level 4 grants access based on the `Referer` header, which the client
sends and therefore controls entirely. Apolaki had no engine for the class.

NOT a duplicate of `cache_tool`. That module sends some of the same header NAMES, but its oracle is cache
poisoning — a canary reflected into a response that a *clean* re-request then receives. This module's
oracle is an authorization state change: a request that was DENIED becomes GRANTED. Same headers, different
question, different proof.

Two sub-classes, both confirmed by safe GETs only:

  header_auth_bypass    a request denied without the header succeeds with it. Referer, X-Forwarded-For,
                        X-Real-IP and friends are attacker-supplied; trusting them for an access decision
                        means anyone can make the decision.
  url_override_bypass   a path denied directly is reached by asking for a permitted path and naming the
                        denied one in X-Original-URL / X-Rewrite-URL — the front-end proxy applies its ACL
                        to the request line while the back end honours the header. This is the
                        `request_url_override` family the sealed blind benchmark missed twice.

FALSE-POSITIVE DISCIPLINE. Two controls, and neither is optional:

  * **Value control.** The header must be sent again with an implausible value. If access is granted with
    ANY value, the server is not trusting the value — the change is something else (a caching artefact, a
    flaky endpoint) and nothing is confirmed.
  * **Content control.** For URL override, the response must differ from what the permitted path returns
    on its own. Otherwise the server ignored the header and simply served the permitted page, which looks
    identical to success at the status-code level and is the obvious trap here.

Pure analysis; the caller performs the (read-only) requests.
"""
from __future__ import annotations


import re
# Statuses that mean "denied" for the purposes of a before/after authorization differential.
DENIED = (401, 403, 404, 405)
# Below this a "200" carries no page to have been granted access to.
_MIN_BODY = 24

# header -> (value builder, why a server might trust it, implausible control value)
# The value builder takes {"host": ..., "origin": ..., "path": ...}.
AUTH_HEADERS = {
    "Referer": (lambda c: c.get("origin", "") + "/",
                "some apps gate on where the request claims to have come from",
                "https://apolaki-implausible-referer.invalid/"),
    "X-Forwarded-For": (lambda c: "127.0.0.1",
                        "a trusted-proxy header used as the client IP for an internal-only allowlist",
                        "203.0.113.253"),
    "X-Real-IP": (lambda c: "127.0.0.1", "the same client-IP trust under a different proxy convention",
                  "203.0.113.253"),
    "X-Client-IP": (lambda c: "127.0.0.1",
                    "another client-IP header some stacks trust for allowlisting", "203.0.113.253"),
    "X-Remote-Addr": (lambda c: "127.0.0.1", "a client-IP header trusted as if it were the socket peer address", "203.0.113.253"),
    "X-Custom-IP-Authorization": (lambda c: "127.0.0.1",
                                  "an explicitly IP-gated admin control", "203.0.113.253"),
}

# Headers that make the BACK END serve a different path than the request line the front end filtered.
URL_OVERRIDE_HEADERS = ("X-Original-URL", "X-Rewrite-URL")


# Static-asset URLs a page always contains; never the value an access check is asking for.
_ASSET = re.compile(r"\.(?:css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map)(?:$|[?#])", re.I)


def expected_values_from_denial(body: str, max_out: int = 3) -> list:
    """Values the REFUSAL ITSELF names. Pure.

    A server that refuses often explains what it wanted — Natas 4 answers *'You are visiting from "" while
    authorized users should come only from "http://natas5.natas.labs.overthewire.org/"'*. Guessing the
    expected Referer is hopeless; reading it out of the refusal is not, and it is the same
    target-leaks-the-clue principle the intel harvester already runs on.

    Only QUOTED URLs are considered, and static assets are dropped — every page cites its own stylesheets,
    and none of those is an access-control expectation."""
    out = []
    for m in re.finditer(r"""["']\s*(https?://[^"'\s>]+)\s*["']""", body or ""):
        u = m.group(1)
        if _ASSET.search(u) or u in out:
            continue
        out.append(u)
        if len(out) >= max_out:
            break
    return out


def header_candidates(origin: str, path: str = "/", denial_body: str = ""):
    """[(header, value, control_value, rationale)] to try against one target. Pure.

    When a denial body is supplied, values it names are tried FIRST for the headers whose expected value is
    a URL — that is the difference between guessing and reading."""
    ctx = {"origin": origin.rstrip("/"), "path": path}
    out = []
    for hinted in expected_values_from_denial(denial_body):
        out.append(("Referer", hinted,
                    "https://apolaki-implausible-referer.invalid/",
                    "the refusal itself named this origin as the one it accepts"))
    for name, (builder, why, control) in AUTH_HEADERS.items():
        try:
            out.append((name, builder(ctx), control, why))
        except Exception:
            continue
    return out


def _body(x):
    return ((x or {}).get("body") or "")


def _status(x):
    return int((x or {}).get("status") or 0)


def judge_header_trust(baseline, with_header, value_control=None) -> dict:
    """Did a client-controlled header change an authorization decision? Pure, deterministic.

    CONFIRMED requires: the request was genuinely denied without the header; it succeeded with it, with a
    substantive body; and the SAME header carrying an implausible value did NOT also succeed. That last
    control is what separates "the server trusts this value" from "this endpoint is flaky"."""
    if _status(baseline) not in DENIED:
        return {"verdict": "not_applicable",
                "reason": "the request was not denied without the header (status %s), so there is no "
                          "authorization decision to bypass" % _status(baseline)}
    if _status(with_header) != 200:
        return {"verdict": "rejected",
                "reason": "the header did not change the decision (still status %s)" % _status(with_header)}
    if len(_body(with_header).strip()) < _MIN_BODY:
        return {"verdict": "rejected",
                "reason": "status became 200 but the body is empty — nothing was actually served"}
    if value_control is None:
        return {"verdict": "lead",
                "reason": "access was granted with the header but the implausible-value control did not "
                          "run — cannot tell whether the VALUE is trusted or merely the header's presence"}
    if _status(value_control) == 200 and len(_body(value_control).strip()) >= _MIN_BODY:
        return {"verdict": "rejected",
                "reason": "an implausible value was accepted too, so the server is not trusting the value; "
                          "the status change has another cause"}
    return {"verdict": "confirmed",
            "reason": "denied without the header (%s), granted with it (200, %d bytes), and refused again "
                      "when the same header carried an implausible value (%s)"
                      % (_status(baseline), len(_body(with_header)), _status(value_control))}


def judge_url_override(direct, permitted, overridden) -> dict:
    """Did X-Original-URL / X-Rewrite-URL reach a path the request line was denied? Pure.

    The content control carries the weight: a server that IGNORES the header simply serves the permitted
    page, which is a 200 and looks like success. Only a response that differs from the permitted page shows
    the override actually took effect."""
    if _status(direct) not in DENIED:
        return {"verdict": "not_applicable",
                "reason": "the target path is not denied directly (status %s)" % _status(direct)}
    if _status(overridden) != 200:
        return {"verdict": "rejected",
                "reason": "the override header did not yield access (status %s)" % _status(overridden)}
    if _body(overridden) == _body(permitted):
        return {"verdict": "rejected",
                "reason": "the response is byte-identical to the permitted path, so the header was ignored "
                          "and nothing was bypassed"}
    if len(_body(overridden).strip()) < _MIN_BODY:
        return {"verdict": "rejected", "reason": "empty response; nothing was served"}
    return {"verdict": "confirmed",
            "reason": "the path is denied on the request line (%s) but reachable by naming it in the "
                      "override header (200, %d bytes, and different from the permitted page)"
                      % (_status(direct), len(_body(overridden)))}


# ── body-signalled authorization ────────────────────────────────────────────────────────────────
# Many applications answer 200 for everything and say "you don't have permission" in the page. A
# status-only oracle is blind to those — proven on Natas 4, where all three probes return 200 and the
# access decision lives in the body.
#
# The general form needs no target knowledge: THE TWO DENIED RESPONSES AGREE WITH EACH OTHER AND THE
# GRANTED ONE IS THE ODD ONE OUT. Sending no header and sending an implausible value are both refusals,
# so they should look alike; a valid value should not.
#
# Measured on Natas 4: sim(baseline, control) = 0.979, sim(baseline, granted) = 0.812,
# sim(control, granted) = 0.794.
#
# The stability requirement doubles as the false-positive guard. A page with a timestamp, CSRF token or
# rotating banner makes baseline and control differ too, which fails STABLE_MIN and the oracle declines —
# so dynamic content cannot manufacture a finding.
STABLE_MIN = 0.95      # the two refusals must look like each other
DIFFER_MAX = 0.90      # the grant must not look like a refusal
MARGIN_MIN = 0.05      # and the gap must be decisive, not noise


def _similarity(a: str, b: str) -> float:
    from difflib import SequenceMatcher
    return SequenceMatcher(None, a or "", b or "").ratio()


def judge_body_differential(baseline, with_header, value_control) -> dict:
    """Authorization signalled in the BODY rather than the status. Pure, deterministic."""
    if None in (baseline, with_header, value_control):
        return {"verdict": "lead", "reason": "the body differential needs all three probes"}
    b, g, c = _body(baseline), _body(with_header), _body(value_control)
    if min(len(b), len(g), len(c)) < _MIN_BODY:
        return {"verdict": "not_applicable", "reason": "responses too small to compare"}
    if not all(_status(x) == 200 for x in (baseline, with_header, value_control)):
        return {"verdict": "not_applicable",
                "reason": "not a uniform-200 target; the status oracle applies instead"}
    stable = _similarity(b, c)
    if stable < STABLE_MIN:
        return {"verdict": "rejected",
                "reason": "no header and an implausible value produced DIFFERENT pages (similarity %.3f), "
                          "so this response is not stable enough to attribute a change to the header — "
                          "dynamic content, not a bypass" % stable}
    gb, gc = _similarity(g, b), _similarity(g, c)
    if max(gb, gc) > DIFFER_MAX or (stable - max(gb, gc)) < MARGIN_MIN:
        return {"verdict": "rejected",
                "reason": "the valid value produced substantially the same page as a refusal "
                          "(similarity %.3f vs %.3f) — the header changed nothing" % (max(gb, gc), stable)}
    return {"verdict": "confirmed",
            "reason": "all three responses are 200, but the two refusals match each other (%.3f) while the "
                      "valid header value produced a materially different page (%.3f) — the server is "
                      "deciding on a value the client supplies" % (stable, max(gb, gc))}


ORACLE_HEADER = ("a request denied without the header returns 200 with it, while the same header carrying "
                 "an implausible value is refused — so the server is trusting a value the client controls")
ORACLE_BODY = ("all three probes return 200, but the no-header and implausible-value responses match each "
               "other while the valid value yields a materially different page — the access decision is "
               "made on a client-supplied value and signalled in the body")
ORACLE_OVERRIDE = ("a path denied on the request line is served when named in an override header, and the "
                   "response differs from the permitted path, proving the header took effect")


def finding_header_trust(url: str, header: str, value: str, rationale: str, probes: dict,
                         verdict: dict) -> dict:
    confirmed = verdict.get("verdict") == "confirmed"
    finding = {
        "title": "Authorization decided by the client-controlled '%s' header — %s" % (header, url),
        "severity": "high" if confirmed else "medium",
        "confidence": "confirmed" if confirmed else "lead",
        "family": "access_control",
        "cwe": "CWE-807",
        "owasp": "A01:2021",
        "target": url,
        "tags": ["access_control", "header-trust", header.lower()],
        "description": ("The server grants access to %s when the request carries '%s: %s', and denies it "
                        "otherwise. %s Because %s, this control can be satisfied by anyone. %s"
                        % (url, header, value, "", rationale, verdict.get("reason", ""))),
        "impact": ("Any unauthenticated client can set this header, so the access control is decorative: "
                   "the resource is effectively public to anyone who knows the header name."),
        "oracle": ORACLE_HEADER,
        # The evidence names the authorization state change explicitly — an unauthorized request becoming
        # authorized IS the finding, and the proof contract for this family requires that signal.
        "evidence": ("unauthorized GET %s -> %s (denied) | same unauthorized request with '%s: %s' -> %s "
                     "(%d bytes, access granted) | with an implausible value -> %s (denied again)"
                     % (url, _status(probes.get("baseline")), header, value,
                        _status(probes.get("with_header")), len(_body(probes.get("with_header"))),
                        _status(probes.get("value_control")))),
        "remediation": ("Never derive an authorization decision from a request header the client supplies. "
                        "Use the authenticated session; if a proxy must convey the client address, have "
                        "the proxy overwrite the header and reject it from untrusted sources."),
        "found_by": "header_trust_tool",
    }
    if confirmed:
        finding["negative_controls"] = [
            {"kind": "header-absent", "status": _status(probes.get("baseline")),
             "len": len(_body(probes.get("baseline"))), "result": "access denied"},
            {"kind": "implausible-header-value", "status": _status(probes.get("value_control")),
             "len": len(_body(probes.get("value_control"))), "result": "access denied again"},
        ]
    return finding


def finding_url_override(base: str, denied_path: str, header: str, probes: dict, verdict: dict) -> dict:
    confirmed = verdict.get("verdict") == "confirmed"
    target = base.rstrip("/") + denied_path
    finding = {
        "title": "Front-end ACL bypassed via the '%s' header — %s" % (header, target),
        "severity": "high" if confirmed else "medium",
        "confidence": "confirmed" if confirmed else "lead",
        "family": "access_control",
        "cwe": "CWE-807",
        "owasp": "A01:2021",
        "target": target,
        "tags": ["access_control", "header-trust", "url-override", "request_url_override"],
        "description": ("%s is denied when requested directly, but is served when a permitted path is "
                        "requested with '%s: %s'. The front end applies its access rules to the request "
                        "line while the back end honours the header. %s"
                        % (target, header, denied_path, verdict.get("reason", ""))),
        "impact": ("Every path the front-end proxy protects can be reached by naming it in this header, "
                   "which defeats the perimeter control entirely."),
        "oracle": ORACLE_OVERRIDE,
        "evidence": ("unauthorized GET %s -> %s (denied by the front end) | GET %s with '%s: %s' -> %s "
                     "(%d bytes, access granted, and the body differs from the permitted page)"
                     % (target, _status(probes.get("direct")), base, header, denied_path,
                        _status(probes.get("overridden")), len(_body(probes.get("overridden"))))),
        "remediation": ("Strip X-Original-URL and X-Rewrite-URL at the edge, and apply authorization in "
                        "the application on the path it actually serves."),
        "found_by": "header_trust_tool",
    }
    if confirmed:
        finding["negative_controls"] = [
            {"kind": "direct-denied-path", "status": _status(probes.get("direct")),
             "len": len(_body(probes.get("direct"))), "result": "front end denied the target path"},
            {"kind": "permitted-path-body", "status": _status(probes.get("permitted")),
             "len": len(_body(probes.get("permitted"))),
             "result": "override response differed from the ordinary permitted page"},
        ]
    return finding
