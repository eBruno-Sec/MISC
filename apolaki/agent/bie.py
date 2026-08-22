"""
Browser Intelligence Engine (BIE) -- Apolaki's RUNTIME viewpoint (#124).

Apolaki reasons over assets, requests and graph facts: static/HTTP truth. What it lacked was the
runtime truth a real user's browser sees AFTER JavaScript executes -- SPA state, per-persona storage,
the requests the app itself decides to make. BIE adds that viewpoint with **Playwright** for control
and **raw CDP** underneath for wire-level instrumentation (Network domain: exact method/url/headers/
post-data/status/mime/remote-ip/security-state).

The capability that matters is NOT "we can drive Chrome". It is the **persona-swap cross-user proof**:

    persona A's browser opens /rest/basket/1  ->  BIE captures the EXACT runtime request
    persona B's browser context replays it, changing ONLY the id
    three negative controls run (anonymous / implausible-id / B's own object)
    the ORACLE -- not the browser -- decides whether that is a vulnerability

That last line is the crown-jewel invariant: the browser performs the *attempt*; a deterministic
oracle with negative controls decides truth. "The browser did something weird" is never a finding.

NO ISLAND: runtime requests land in the shared CaptureStore (engine="browser", so they are in the one
engagement HAR), runtime observations feed the same planner vocabulary as HTTP recon, confirmed
findings carry an evidence-derived PoC bundle (screenshots + exact/mutated request + every control +
a replay script) frozen from the actual run, and the artery records the proof it fired.

Degrades cleanly: with no Playwright/Chromium available every entry point returns a clearly-labelled
empty result. Nothing is faked, nothing raises.
"""
from __future__ import annotations

import browser_engine
import re

# Response bodies are compared by the oracle and embedded in evidence -- bound both.
_MAX_BODY = 6000
# Below this a "200" carries no object to prove ownership of (empty shells, `{}`, `[]`).
_MIN_BODY = 12
# Header values that must never leave this module.
_SECRET_HDRS = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "token",
                "proxy-authorization", "x-csrf-token"}
# An id an application is overwhelmingly unlikely to own -- the "not object-specific" control.
_IMPLAUSIBLE_ID = "99999901"

# Terminal path segment that looks like an object id: numeric, uuid, or long hex/objectid.
_ID_SEG = re.compile(r"^(?:\d{1,12}|[0-9a-fA-F]{24}|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})$")


# ─────────────────────────────────────────────────────────── pure: redaction + shaping
def redact_headers(h) -> dict:
    """Header names are evidence; secret header VALUES never are. Pure."""
    try:
        return {str(k): ("<redacted>" if str(k).lower() in _SECRET_HDRS else str(v))
                for k, v in dict(h or {}).items()}
    except Exception:
        return {}


def storage_from_login(resp_json, max_keys: int = 12) -> dict:
    """The app-issued session STATE a single-page app keeps in browser storage, taken from the
    application's OWN login response. Target-agnostic: flatten the response's scalar fields (Juice Shop's
    {authentication:{token,bid,umail}} -> token/bid/umail; {data:{access_token,user_id}} -> the same idea).

    Why this matters: injecting only an Authorization header gives a real session to the TRANSPORT, but the
    SPA still does not know WHO it is, so it never renders the pages that fetch the user's objects. Seeding
    what the app's own login response returned is what makes the browser behave like a logged-in user.
    Pure; nothing is invented -- only fields the server actually sent."""
    out = {}

    def walk(o, depth=0):
        if depth > 3 or len(out) >= max_keys:
            return
        if isinstance(o, dict):
            for k, v in o.items():
                if len(out) >= max_keys:
                    return
                if isinstance(v, (str, int, float, bool)) and not isinstance(v, bool):
                    s = str(v)
                    if 0 < len(s) <= 512:
                        out.setdefault(str(k), s)
                elif isinstance(v, (dict, list)):
                    walk(v, depth + 1)
        elif isinstance(o, list):
            for v in o[:5]:
                walk(v, depth + 1)

    try:
        walk(resp_json)
    except Exception:
        return {}
    return out


def _clip(s) -> str:
    s = "" if s is None else str(s)
    return s[:_MAX_BODY]


def exchange(url: str, status: int, body: str = "", headers=None, method: str = "GET",
             persona: str = "", ms: float = 0.0) -> dict:
    """One runtime request/response the oracle can reason about. Pure."""
    return {"url": url, "method": str(method).upper(), "status": int(status or 0),
            "body": _clip(body), "len": len(body or ""), "headers": redact_headers(headers),
            "persona": persona, "ms": round(float(ms or 0), 1)}


# ─────────────────────────────────────────────────────────── pure: runtime hypothesis forming
def object_template(url: str):
    """(template, id) for a URL whose LAST path segment is an object id, else (None, None).
    `/rest/basket/1?x=2` -> (`/rest/basket/{id}`, `1`). Pure."""
    try:
        from urllib.parse import urlsplit
        parts = urlsplit(str(url))
        segs = [s for s in parts.path.split("/")]
        if len(segs) < 2 or not segs[-1]:
            return None, None
        if not _ID_SEG.match(segs[-1]):
            return None, None
        oid = segs[-1]
        tmpl = parts.scheme + "://" + parts.netloc + "/".join(segs[:-1] + ["{id}"])
        return tmpl, oid
    except Exception:
        return None, None


def swap_url(url: str, new_id: str):
    """Replace ONLY the terminal object id -- the single-variable mutation. Pure."""
    tmpl, oid = object_template(url)
    if not tmpl:
        return None
    return tmpl.replace("{id}", str(new_id))


def _split_path(url: str):
    """(scheme, netloc, [segments], query) or None. Pure."""
    try:
        from urllib.parse import urlsplit
        p = urlsplit(str(url))
        segs = [s for s in p.path.split("/") if s != ""]
        if not p.netloc or not segs:
            return None
        return p.scheme, p.netloc, segs, p.query
    except Exception:
        return None


def swap_segment(url: str, index: int, value: str):
    """Replace the path segment at `index` and nothing else. Pure."""
    parts = _split_path(url)
    if not parts:
        return None
    scheme, netloc, segs, query = parts
    if not (0 <= index < len(segs)):
        return None
    segs = list(segs)
    segs[index] = str(value)
    return scheme + "://" + netloc + "/" + "/".join(segs) + (("?" + query) if query else "")


def differing_segment(url_a: str, url_b: str):
    """The single path position where two structurally identical URLs differ, else None.

    This is how an object key is IDENTIFIED without guessing its shape: a numeric id, a uuid, a username
    and a slug all look different, but "the one segment that changed between two personas' requests to the
    same endpoint" is the same signal in every case. Pure."""
    a, b = _split_path(url_a), _split_path(url_b)
    if not a or not b:
        return None
    if (a[0], a[1]) != (b[0], b[1]) or len(a[2]) != len(b[2]):
        return None
    diff = [i for i, (x, y) in enumerate(zip(a[2], b[2])) if x != y]
    if len(diff) != 1:
        return None
    i = diff[0]
    va, vb = a[2][i], b[2][i]
    if not va or not vb or len(va) > 64 or len(vb) > 64:
        return None
    if "." in va and "." in vb:            # both look like filenames -> a static asset, not an object key
        return None
    return i


def segment_template(url: str, index: int) -> str:
    """The URL with the object position marked, e.g. http://t/rest/basket/{id}. Pure."""
    parts = _split_path(url)
    if not parts:
        return str(url)
    scheme, netloc, segs, _q = parts
    segs = list(segs)
    if 0 <= index < len(segs):
        segs[index] = "{id}"
    return scheme + "://" + netloc + "/" + "/".join(segs)


def _no_query(url: str) -> str:
    return str(url).split("?", 1)[0].rstrip("/")


def object_candidates(owner_urls, attacker_urls, max_n: int = 4) -> list:
    """Runtime-observed cross-user hypotheses: an endpoint both personas' browsers requested, differing in
    exactly ONE path segment. Pure.

    The object key is identified by OBSERVATION, not by its shape — a numeric id, a uuid, a username and a
    slug are indistinguishable to a regex but identical to this test, which is why username-keyed APIs
    (`/users/v1/{name}`) are covered as naturally as `/basket/{n}`.

    The discriminator that keeps it honest: the attacker's URL must be one the OWNER never requested (and
    vice versa). If both personas fetched it, the differing segment is a route difference — `/api/users/1`
    vs `/api/orders/1` — not a per-user key, and pairing them would manufacture nonsense.

    Returns [{template, owner_url, owner_id, attacker_url, attacker_id, index}]."""
    o_urls = [str(u) for u in (owner_urls or [])][:300]
    a_urls = [str(u) for u in (attacker_urls or [])][:300]
    o_seen, a_seen = {_no_query(u) for u in o_urls}, {_no_query(u) for u in a_urls}
    out, templates = [], set()
    for ou in o_urls:
        if _no_query(ou) in a_seen:          # both personas fetched this exact object -> nothing to prove
            continue
        for au in a_urls:
            if _no_query(au) in o_seen:      # the "attacker's" url is the owner's too -> route difference
                continue
            idx = differing_segment(ou, au)
            if idx is None:
                continue
            tmpl = segment_template(ou, idx)
            if tmpl in templates:
                continue
            templates.add(tmpl)
            oa, ab = _split_path(ou), _split_path(au)
            out.append({"template": tmpl, "owner_url": ou, "owner_id": oa[2][idx],
                        "attacker_url": au, "attacker_id": ab[2][idx], "index": idx})
            break
        if len(out) >= max_n:
            break
    return out


# ─────────────────────────────────────────────────────────── pure: THE ORACLE
def judge(baseline, mutation, *, anon=None, nonexistent=None, control=None) -> dict:
    """Decide whether a persona-swap attempt proved a cross-user object read. Pure, deterministic.

    CONFIRMED requires ALL of:
      1. the owner's own request really returned a substantive object          (there is something to steal)
      2. the attacker's swapped request returned 200                            (not denied)
      3. the attacker's body is byte-identical to the owner's                   (B literally received A's object)
      4. the anonymous control did NOT return that same body                    (the resource is not public)
      5. the implausible-id control did NOT return that same body               (the route is object-specific,
                                                                                 not an SPA shell / catch-all)
      6. the attacker's OWN object differs from the owner's                     (the objects are distinguishable)

    Controls 4 and 5 are MANDATORY: without them the result is a `lead`, never a confirmation. A missing
    control is missing evidence, and missing evidence never becomes proof."""
    def _b(x):
        return ((x or {}).get("body") or "")

    def _s(x):
        return int((x or {}).get("status") or 0)

    def _ran(x):
        """Did this control actually reach the server?

        `is None` was the only liveness test, but the live producer NEVER returns None on failure --
        _FETCH_JS catches its own exception and returns {status: 0, body: '', error: '...'}. That dict
        satisfies `is not None`, so an ERRORED control passed as a SATISFIED control and the oracle
        walked straight to `confirmed`. The anonymous control is the most fragile of the three (empty
        headers, a persona that may be sitting on about:blank, a WAF dropping unauthenticated
        requests) -- so the common failure was: anon control dies, public resource is reported as a
        confirmed cross-user read. A false positive produced by a control that never ran.
        """
        if not isinstance(x, dict):
            return False
        return _s(x) != 0 and not x.get("error")

    base_b = _b(baseline)
    if _s(baseline) != 200 or len(base_b.strip()) < _MIN_BODY:
        return {"verdict": "not_applicable",
                "reason": "the owner's own request did not return a substantive object (status %s, %d bytes)"
                          % (_s(baseline), len(base_b))}
    if _s(mutation) != 200:
        return {"verdict": "rejected", "reason": "authorization enforced: the attacker persona received "
                                                 "status %s for the owner's object" % _s(mutation)}
    if _b(mutation) != base_b:
        return {"verdict": "rejected", "reason": "the attacker's response is not the owner's object "
                                                 "(%d vs %d bytes)" % (len(_b(mutation)), len(base_b))}
    missing = [n for n, c in (("anonymous", anon), ("implausible-id", nonexistent)) if not _ran(c)]
    if missing:
        return {"verdict": "lead", "reason": "cross-user read observed but the %s negative control did not "
                                             "run -- not provable" % " and ".join(missing)}
    if _s(anon) == 200 and _b(anon) == base_b:
        return {"verdict": "rejected", "reason": "the resource is PUBLIC -- an unauthenticated request "
                                                 "returns the identical body, so no authorization was bypassed"}
    if _s(nonexistent) == 200 and _b(nonexistent) == base_b:
        return {"verdict": "rejected", "reason": "the route is not object-specific -- an implausible id "
                                                 "returns the identical body (SPA shell / catch-all)"}
    # THE THIRD CONTROL HAD THE SAME HOLE, and the first fix missed it. An ERRORED control fails
    # `_s(control) == 200` exactly like a control that legitimately differs, so the indistinguishable-
    # objects rejection never fired and the verdict fell through to `confirmed`. Reproduced with two
    # personas holding byte-identical objects: control alive -> rejected, control errored -> confirmed.
    #
    # `control is None` is a different thing and stays permitted: it means no second object existed to
    # compare, which is a known limit of the setup. An errored control means we TRIED and failed, and
    # that cannot rule out indistinguishability -- so it is a lead, not a confirmation.
    if control is not None and not _control_ran(control):
        return {"verdict": "lead", "reason": "the owner's object was returned, but the attacker's-own-object "
                                             "control did not run, so two byte-identical objects cannot be "
                                             "ruled out -- not provable"}
    if control is not None and _s(control) == 200 and _b(control) == base_b:
        return {"verdict": "rejected", "reason": "the attacker's own object is byte-identical to the "
                                                 "owner's -- the objects are not distinguishable"}
    return {"verdict": "confirmed",
            "reason": "the attacker persona's browser received the owner's object verbatim (200, %d bytes) "
                      "while anonymous=%s and implausible-id=%s did not"
                      % (len(base_b), _s(anon), _s(nonexistent))}


ORACLE = ("runtime persona swap: the same browser request replayed in a second authenticated browser "
          "context with ONLY the object id changed returns the owner's object byte-for-byte, while the "
          "anonymous and implausible-id negative controls do not")


# ─────────────────────────────────────────────────────────── pure: evidence + finding
def replay_script(cand: dict, owner: str = "owner", attacker: str = "attacker") -> str:
    """A literally-runnable replay of the confirmed run (no secrets: the operator supplies the tokens
    the vault holds). Deterministic replay > pretty report language. Pure."""
    return "\n".join([
        "#!/bin/sh",
        "# Apolaki BIE replay -- cross-user object read via persona swap.",
        "# Supply each persona's own auth material; Apolaki never exports session secrets.",
        "OWNER_AUTH=\"$1\"     # e.g. 'Bearer <%s token>'" % owner,
        "ATTACKER_AUTH=\"$2\"  # e.g. 'Bearer <%s token>'" % attacker,
        "",
        "echo '1. baseline  -- %s reads its OWN object (expect 200 + the object)'" % owner,
        "curl -sk -o /dev/null -w '   %%{http_code} %%{size_download}B\\n' -H \"Authorization: $OWNER_AUTH\" '%s'"
        % cand.get("owner_url", ""),
        "echo '2. mutation  -- %s reads the SAME url (only the id differs from its own): the bug'" % attacker,
        "curl -sk -o /dev/null -w '   %%{http_code} %%{size_download}B\\n' -H \"Authorization: $ATTACKER_AUTH\" '%s'"
        % cand.get("owner_url", ""),
        "echo '3. control   -- anonymous (expect NOT the object; proves it is not public)'",
        "curl -sk -o /dev/null -w '   %%{http_code} %%{size_download}B\\n' '%s'" % cand.get("owner_url", ""),
        "echo '4. control   -- implausible id (expect NOT the object; proves the route is object-specific)'",
        "curl -sk -o /dev/null -w '   %%{http_code} %%{size_download}B\\n' -H \"Authorization: $ATTACKER_AUTH\" '%s'"
        % (_implausible_url(cand) or ""),
    ])


def _implausible_url(cand: dict):
    """The negative-control URL: the same request with an id no application should own. Pure."""
    u = cand.get("owner_url", "")
    idx = cand.get("index")
    if idx is not None:
        return swap_segment(u, idx, _IMPLAUSIBLE_ID)
    return swap_url(u, _IMPLAUSIBLE_ID)


def browser_evidence(cand: dict, probes: dict, verdict: dict, *, owner: str = "owner",
                     attacker: str = "attacker", screenshots=None) -> dict:
    """The evidence-derived PoC section: frozen FROM THE ACTUAL RUN, not reconstructed afterwards.
    Bodies are clipped, headers redacted. Pure."""
    steps = [
        "1. Authenticate as persona '%s' in an isolated browser context." % owner,
        "2. Observe the application request %s at runtime (captured via CDP Network)." % cand.get("owner_url", ""),
        "3. Authenticate as persona '%s' in a SEPARATE browser context." % attacker,
        "4. From that context issue the identical request, changing ONLY the object id "
        "(%s -> %s)." % (cand.get("attacker_id"), cand.get("owner_id")),
        "5. Observe that persona '%s' receives persona '%s''s object verbatim." % (attacker, owner),
        "6. Negative controls: the same request anonymously, and with an implausible id, do NOT return it.",
    ]
    return {
        "schema": "apolaki.bie-evidence/1",
        "engine": "browser-intelligence-engine",
        "instrumentation": "playwright + raw CDP (Network domain)",
        "reproduction_steps": steps,
        "template": cand.get("template"),
        "exact_request": probes.get("baseline"),
        "mutated_request": probes.get("mutation"),
        "negative_controls": {k: probes.get(k) for k in ("anon", "nonexistent", "control")
                              if probes.get(k) is not None},
        "verdict": verdict,
        "personas": {"owner": owner, "attacker": attacker, "secrets": "[REDACTED -- held server-side]"},
        "screenshots": screenshots or {},
        "replay_script": replay_script(cand, owner, attacker),
    }


def finding(cand: dict, probes: dict, verdict: dict, *, owner: str = "owner", attacker: str = "attacker",
            screenshots=None) -> dict:
    """A confirmed (or lead) cross-user read, shaped for the findings gate."""
    confirmed = verdict.get("verdict") == "confirmed"
    url = cand.get("owner_url", "")
    return {
        "title": "Cross-user object read confirmed in the browser runtime (%s)" % (cand.get("template") or url),
        "severity": "high" if confirmed else "medium",
        "confidence": "confirmed" if confirmed else "lead",
        "family": "bola",
        "cwe": "CWE-639",
        "owasp": "API1:2023",
        "target": url,
        "tags": ["bola", "idor", "browser", "runtime", "persona-swap", "access_control"],
        "description": ("Persona '%s' retrieved persona '%s''s object through a real browser session by "
                        "changing only the object id in a request the application itself makes at runtime. "
                        "%s" % (attacker, owner, verdict.get("reason", ""))),
        # The access-control proof contract (proof_schema) requires a stated impact on any CONFIRMED
        # finding — a cross-user read is only meaningful once the consequence is named.
        "impact": ("Any authenticated user can read other users' objects at %s by changing the id, so the "
                   "whole collection is enumerable: every record it holds can be harvested by one "
                   "ordinary account." % (cand.get("template") or url)),
        "oracle": ORACLE,
        "evidence": ("owner %s -> %s %dB | attacker (swapped) -> %s %dB (identical) | anonymous -> %s | "
                     "implausible id -> %s"
                     % (url, (probes.get("baseline") or {}).get("status"),
                        (probes.get("baseline") or {}).get("len", 0),
                        (probes.get("mutation") or {}).get("status"),
                        (probes.get("mutation") or {}).get("len", 0),
                        (probes.get("anon") or {}).get("status"),
                        (probes.get("nonexistent") or {}).get("status"))),
        "remediation": ("Enforce object-level authorization on the server for every object read: resolve the "
                        "requested id and verify it belongs to the authenticated principal before returning "
                        "it. Client-side scoping and unguessable ids are not authorization."),
        "browser_evidence": browser_evidence(cand, probes, verdict, owner=owner, attacker=attacker,
                                             screenshots=screenshots),
        "found_by": "bie",
    }


# ──────────────────────────────────────── pure: USER-FLOW RECORDING -> REPRODUCIBLE ATTACK PATH
def user_flow(settle, wire, probe, *, owner: str = "owner", attacker: str = "attacker") -> dict:
    """Turn the run into an ordered, reproducible path: authenticate -> navigate -> the app fetches an
    object -> the swap -> the result. Pure.

    This is the Page-Object idea applied to evidence rather than to test code: the value is not a class
    hierarchy, it is that a confirmed finding can state the ROUTE a human takes to reach it, derived from
    what actually happened rather than narrated afterwards.

    Deliberately built only from navigation and observation. Driving a flow by CLICKING is state-changing
    and stays operator-gated, so it is not done here — and a flow recorder that could never fire would be
    exactly the island the doctrine forbids."""
    steps, n = [], 0
    n += 1
    steps.append({"n": n, "actor": owner, "action": "authenticate",
                  "detail": "open an isolated browser context and restore the persona's own session"})
    seen = set()
    for s in (settle or []):
        u = (s or {}).get("url")
        if not u or u in seen:
            continue
        seen.add(u)
        n += 1
        steps.append({"n": n, "actor": owner, "action": "navigate", "url": u,
                      "detail": "synchronised on %s" % (s.get("reason") or "load")})
    obj_urls = [w.get("url") for w in (wire or []) if w.get("url") and _split_path(w["url"])]
    cand = (probe or {}).get("candidate") or {}
    if cand.get("owner_url"):
        n += 1
        steps.append({"n": n, "actor": owner, "action": "observe_request", "url": cand["owner_url"],
                      "detail": "the application itself requests this object at runtime"})
        n += 1
        steps.append({"n": n, "actor": attacker, "action": "replay_with_one_change",
                      "url": cand["owner_url"],
                      "detail": "same request from the second persona's browser, changing only %s"
                                % ("the object key '%s' -> '%s'" % (cand.get("attacker_id"),
                                                                    cand.get("owner_id"))
                                   if cand.get("index") is not None or cand.get("owner_id")
                                   else "one identity parameter")})
    v = (probe or {}).get("verdict") or {}
    if v:
        n += 1
        steps.append({"n": n, "actor": "oracle", "action": "decide",
                      "detail": "%s — %s" % (str(v.get("verdict", "")).upper(), v.get("reason", ""))})
    return {"schema": "apolaki.bie-flow/1", "personas": {"owner": owner, "attacker": attacker},
            "steps": steps, "objects_seen": len(set(obj_urls)),
            "narrative": " -> ".join("%s %s" % (s["actor"], s["action"]) for s in steps)}


# ──────────────────────────────────────────────────────── pure: LOCATOR FALLBACK CHAIN
# Selenium Ch.4 catalogues why a single locator breaks: attributes churn between deploys, the element is
# created only after an event, it is not visible yet, or the page and the script are out of sync. The fix
# is not a cleverer selector — it is ORDERED FALLBACK plus a wait. Strategies are ordered most-stable
# first, so a run degrades to a weaker locator instead of failing outright, and records WHICH one worked
# (a finding reproduced via a brittle selector deserves to say so).
_LOCATOR_ORDER = ("test_id", "id", "name", "role", "label", "placeholder", "text", "css", "xpath")

# How stable each strategy is against ordinary front-end churn — reported with the resolution so evidence
# never implies more reproducibility than the locator actually has.
_LOCATOR_STABILITY = {"test_id": "high", "id": "high", "name": "high", "role": "high", "label": "medium",
                      "placeholder": "medium", "text": "medium", "css": "low", "xpath": "low"}


def locator_chain(descriptor: dict) -> list:
    """Ordered [(strategy, value)] to try for one element. Pure — no browser needed, so the ordering
    policy itself is testable."""
    d = descriptor or {}
    out = []
    for strat in _LOCATOR_ORDER:
        v = d.get(strat)
        if v:
            out.append((strat, str(v)))
    return out


def locator_quality(strategy: str) -> str:
    return _LOCATOR_STABILITY.get(str(strategy), "unknown")


def resolve_locator(page, descriptor: dict, *, timeout_ms: int = 5000) -> dict:
    """Walk the fallback chain until one strategy resolves to exactly one visible element.

    Returns {resolved, strategy, stability, tried, failure}. Never raises, never clicks — resolution is
    read-only. Ambiguity is a FAILURE, not a coin flip: a chain that matches several elements has not
    identified anything, and silently taking the first is how automation acts on the wrong control."""
    chain = locator_chain(descriptor)
    if not chain:
        return {"resolved": False, "strategy": "", "tried": [],
                "failure": classify_failure("no such element: empty locator descriptor")}
    tried, last = [], None
    for strat, val in chain:
        try:
            if strat == "test_id":
                loc = page.get_by_test_id(val)
            elif strat == "role":
                loc = page.get_by_role(val)
            elif strat == "label":
                loc = page.get_by_label(val)
            elif strat == "placeholder":
                loc = page.get_by_placeholder(val)
            elif strat == "text":
                loc = page.get_by_text(val)
            elif strat == "id":
                loc = page.locator("#" + val)
            elif strat == "name":
                loc = page.locator("[name=%s]" % _css_quote(val))
            elif strat == "xpath":
                loc = page.locator("xpath=" + val)
            else:
                loc = page.locator(val)
            n = loc.count()
            if n == 1:
                loc.wait_for(state="visible", timeout=timeout_ms)
                tried.append({"strategy": strat, "matches": 1, "ok": True})
                return {"resolved": True, "strategy": strat, "stability": locator_quality(strat),
                        "locator": loc, "tried": tried, "failure": classify_failure("")}
            tried.append({"strategy": strat, "matches": n, "ok": False,
                          "why": "ambiguous" if n > 1 else "no match"})
        except Exception as e:
            last = e
            tried.append({"strategy": strat, "ok": False, "why": classify_failure(e)["code"]})
    return {"resolved": False, "strategy": "", "tried": tried,
            "failure": classify_failure(last or "no such element: no strategy in the chain resolved")}


def _css_quote(v: str) -> str:
    return '"%s"' % str(v).replace("\\", "\\\\").replace('"', '\\"')


# ──────────────────────────────────────────── pure: RETEST FROM FROZEN BROWSER EVIDENCE
def _sha(s: str) -> str:
    import hashlib
    return hashlib.sha256((s or "").encode("utf8", "replace")).hexdigest()[:32]


def har_response_for(har_json, url: str) -> dict:
    """The recorded response for a URL inside a HAR document. Pure.

    WHAT A HAR CAN AND CANNOT DO — the distinction matters and is easy to get wrong: replaying a HAR as the
    network layer reproduces the RECORDING, so it can never prove a bug still exists. It is a demonstration
    (show a client the exploit without touching production) and a FROZEN BASELINE (what the vulnerable
    response looked like), never a verification. Only a live re-send can decide OPEN or CLOSED."""
    try:
        entries = ((har_json or {}).get("log") or {}).get("entries") or []
    except Exception:
        return {}
    for e in entries:
        try:
            if same_endpoint((e.get("request") or {}).get("url", ""), url):
                r = e.get("response") or {}
                c = r.get("content") or {}
                return {"url": (e.get("request") or {}).get("url"), "status": int(r.get("status") or 0),
                        "len": int(c.get("size") or r.get("bodySize") or 0),
                        "mime": c.get("mimeType") or "", "source": "har"}
        except Exception:
            continue
    return {}


def retest_recipe(finding: dict) -> dict:
    """The replayable recipe frozen from a confirmed BIE run. Pure.

    A generic BOLA finding carries a URL and prose, which is why the retest loop can only call it
    INCONCLUSIVE. A BIE finding carries the exact request, the persona roles, and the response that proved
    the bug — enough for the oracle to decide honestly on a re-send."""
    be = (finding or {}).get("browser_evidence") or {}
    base = be.get("exact_request") or {}
    mut = be.get("mutated_request") or {}
    if not (base.get("url") or mut.get("url")):
        return {}
    body = mut.get("body") or base.get("body") or ""
    return {
        "schema": "apolaki.bie-retest/1",
        "url": mut.get("url") or base.get("url"),
        "method": (mut.get("method") or base.get("method") or "GET").upper(),
        "as_persona": (be.get("personas") or {}).get("attacker") or "attacker",
        "vulnerable_status": int(mut.get("status") or base.get("status") or 0),
        "vulnerable_len": int(mut.get("len") or base.get("len") or 0),
        "vulnerable_body_sha": _sha(body),
        "oracle": finding.get("oracle") or "",
        "note": "re-send this as the same persona; the frozen response below is what the bug looked like",
    }


# Statuses that mean the server now REFUSES the access the finding proved.
_REFUSED = (401, 403, 404, 405, 410)


def retest_verdict(recipe: dict, live) -> dict:
    """OPEN / CLOSED / INCONCLUSIVE for a re-sent BIE recipe. Pure, deterministic.

    Deliberately conservative in one direction: a 200 whose body merely CHANGED is INCONCLUSIVE, not
    CLOSED, because ordinary data churn looks exactly like that and a false 'closed' is the worst outcome
    a retest can produce. Only an explicit refusal, or an empty response where substantive data used to
    be, closes a finding."""
    r, l = recipe or {}, live or {}
    if not r.get("url"):
        return {"state": "INCONCLUSIVE", "reason": "no replayable recipe was frozen for this finding"}
    st = int(l.get("status") or 0)
    body = l.get("body") or ""
    if st == 0:
        return {"state": "INCONCLUSIVE", "reason": "the re-send did not complete"}
    if st in _REFUSED:
        return {"state": "CLOSED", "reason": "the server now refuses the request (status %d) that "
                                             "previously returned the other user's object" % st}
    if st == 200 and _sha(body) == r.get("vulnerable_body_sha"):
        return {"state": "OPEN", "reason": "the same request still returns the identical object "
                                           "(%d bytes) — the fix is not in place" % len(body)}
    if st == 200 and len(body.strip()) < _MIN_BODY:
        return {"state": "CLOSED", "reason": "the request now returns an empty response where the other "
                                             "user's object used to be"}
    if st == 200:
        return {"state": "INCONCLUSIVE", "reason": "still 200 but the body changed — this is what ordinary "
                                                   "data churn looks like, so it is not proof of a fix; "
                                                   "operator retest required"}
    return {"state": "INCONCLUSIVE", "reason": "unexpected status %d — operator retest required" % st}


# ──────────────────────────────────────────────── pure: BROWSER-DRIVING FAILURE TAXONOMY
# Selenium's exception catalogue (Ch.9) is really a catalogue of the ways a browser can fail to do what a
# test asked. Apolaki needs it for a different reason: a flow that could not be driven must say WHY, or
# "we found nothing" silently becomes indistinguishable from "we could not look". Each entry maps a raw
# driver error to a stable reason code, a human explanation, and whether it is worth retrying.
_FAILURE_SIGNATURES = (
    # (matcher substrings, code, meaning, retryable, security_signal)
    (("element click intercepted", "intercepts pointer events", "is not clickable at point"),
     "click_intercepted",
     "another element covers the control, so the click landed on the overlay instead",
     True, "overlay_over_control"),
    (("stale element", "element is not attached", "node is detached"),
     "stale_element",
     "the page re-rendered and the element reference became invalid",
     True, ""),
    (("element not interactable", "not visible", "element is not visible", "not enabled",
      "element is disabled"),
     "not_interactable",
     "the control is present but cannot be interacted with (hidden or disabled)",
     False, ""),
    (("unexpected alert", "javascript dialog", "dialog is open"),
     "unexpected_dialog",
     "a JavaScript dialog interrupted the flow and must be handled first",
     True, ""),
    (("err_cert", "insecure certificate", "ssl error", "certificate verify"),
     "insecure_certificate",
     "the target presented a certificate the browser refuses",
     False, "tls_certificate_rejected"),
    (("no such element", "waiting for selector", "unable to find element", "locator resolved to 0"),
     "element_not_found",
     "no element matched the locator within the wait window",
     True, ""),
    (("timeout", "timed out", "exceeded"),
     "timeout",
     "the condition never became true within the wait window",
     True, ""),
    (("net::err_", "connection refused", "econnrefused", "unreachable", "name_not_resolved"),
     "unreachable",
     "the browser could not reach the target at all",
     False, ""),
    (("navigation", "frame was detached", "target closed", "browser has been closed"),
     "navigation_lost",
     "the page or browser went away mid-operation",
     True, ""),
)


def classify_failure(err) -> dict:
    """Turn a raw browser error into an honest, stable outcome. Pure.

    `security_signal` is the interesting part: `click_intercepted` means something was drawn ON TOP of a
    control, which is the same condition a clickjacking overlay creates. It is reported as a SIGNAL for the
    planner, never as a finding — an app's own modal does this legitimately every day."""
    s = str(err or "").lower()
    if not s.strip():
        return {"code": "none", "meaning": "no error", "retryable": False, "security_signal": "",
                "raw": ""}
    for tokens, code, meaning, retryable, signal in _FAILURE_SIGNATURES:
        if any(t in s for t in tokens):
            return {"code": code, "meaning": meaning, "retryable": retryable,
                    "security_signal": signal, "raw": str(err)[:200]}
    return {"code": "unknown", "meaning": "the browser failed for a reason Apolaki does not classify",
            "retryable": False, "security_signal": "", "raw": str(err)[:200]}


def drive_report(attempts) -> dict:
    """Aggregate what the browser could and could not do, so coverage is stated rather than implied. An
    engagement that says 'no findings' while every navigation timed out is lying by omission. Pure."""
    att = list(attempts or [])
    failed = [a for a in att if a.get("failure", {}).get("code") not in ("none", None)]
    by_code, signals = {}, {}
    for a in failed:
        f = a.get("failure") or {}
        by_code[f.get("code")] = by_code.get(f.get("code"), 0) + 1
        if f.get("security_signal"):
            signals[f["security_signal"]] = signals.get(f["security_signal"], 0) + 1
    return {"attempted": len(att), "succeeded": len(att) - len(failed), "failed": len(failed),
            "by_code": by_code, "security_signals": signals,
            "complete": len(failed) == 0,
            "note": ("every browser action completed" if not failed else
                     "%d of %d browser actions failed — coverage is INCOMPLETE for those paths"
                     % (len(failed), len(att)))}


# ────────────────────────────── pure: CLIENT-SUPPLIED IDENTITY PARAMETERS (route-interception tampering)
# Parameter names that carry WHO the request is about. When a server derives identity from one of these
# instead of from the session, changing it is an authorization bypass. Ranking only — never proof.
_IDENTITY_PARAM_HINTS = ("userid", "user_id", "uid", "accountid", "account_id", "customerid", "customer_id",
                         "clientid", "client_id", "memberid", "profileid", "profile_id", "ownerid",
                         "owner_id", "tenant", "tenantid", "tenant_id", "orgid", "org_id", "companyid",
                         "basketid", "basket_id", "cartid", "cart_id", "orderid", "order_id", "email",
                         "username", "user", "owner", "account")


def identity_params(url: str) -> list:
    """Query parameters that name WHO the request concerns, with their observed values. Pure."""
    try:
        from urllib.parse import urlsplit, parse_qsl
    except Exception:
        return []
    out = []
    try:
        for k, v in parse_qsl(urlsplit(str(url)).query, keep_blank_values=False):
            kl = k.lower().replace("-", "_")
            if not v:
                continue
            if kl in _IDENTITY_PARAM_HINTS or any(h == kl or kl.endswith(h) for h in _IDENTITY_PARAM_HINTS):
                out.append((k, v))
    except Exception:
        return []
    return out


def mutate_param(url: str, name: str, value: str) -> str:
    """Replace exactly ONE query parameter's value, preserving everything else. Pure."""
    try:
        from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
        p = urlsplit(str(url))
        q = [(k, (str(value) if k == name else v)) for k, v in parse_qsl(p.query, keep_blank_values=True)]
        return urlunsplit((p.scheme, p.netloc, p.path, urlencode(q), p.fragment))
    except Exception:
        return str(url)


def same_endpoint(a: str, b: str) -> bool:
    """Same scheme/host/path, ignoring the query — 'the same request, different variable'. Pure."""
    try:
        from urllib.parse import urlsplit
        x, y = urlsplit(str(a)), urlsplit(str(b))
        return (x.scheme, x.netloc, x.path) == (y.scheme, y.netloc, y.path)
    except Exception:
        return False


def param_candidates(owner_urls, attacker_urls, max_n: int = 3) -> list:
    """Identity parameters BOTH personas' browsers sent on the same endpoint with DIFFERENT values. That
    difference is the evidence the parameter is identity-scoped — derived from observing two real sessions,
    never from a guess about naming. Pure."""
    atk = {}
    for u in (attacker_urls or []):
        for k, v in identity_params(u):
            atk.setdefault((_path_key(u), k.lower()), (u, v))
    out, seen = [], set()
    for u in (owner_urls or []):
        for k, v in identity_params(u):
            key = (_path_key(u), k.lower())
            if key in seen or key not in atk:
                continue
            au, av = atk[key]
            if str(av) == str(v):
                continue                       # both personas send the same value -> not identity-scoped
            seen.add(key)
            out.append({"template": _path_key(u), "param": k, "owner_url": u, "owner_value": v,
                        "attacker_url": au, "attacker_value": av})
            if len(out) >= max_n:
                return out
    return out


def _path_key(url: str) -> str:
    try:
        from urllib.parse import urlsplit
        p = urlsplit(str(url))
        return p.scheme + "://" + p.netloc + p.path
    except Exception:
        return str(url)


def _control_ran(x):
    """Shared liveness test for a negative control. A control that ERRORED is not a control that PASSED.
    _FETCH_JS returns {status: 0, body: "", error: ...} on failure, so every `is not None` guard in this
    module silently accepted a dead probe as a satisfied one."""
    if not isinstance(x, dict):
        return False
    return int(x.get("status") or 0) != 0 and not x.get("error")


def judge_param_swap(self_baseline, other_baseline, mutation, anon=None) -> dict:
    """Decide whether the server derived identity from a CLIENT-SUPPLIED parameter. Pure, deterministic.

    The secure behaviour has a specific, recognisable signature — the server ignores the parameter and
    keeps answering about the session's own user — and it is explicitly REJECTED here rather than being
    mistaken for a weak signal. A confirmation requires the response to become, byte-for-byte, the OTHER
    persona's own view of that endpoint."""
    def _b(x):
        return ((x or {}).get("body") or "")

    def _s(x):
        return int((x or {}).get("status") or 0)

    if _s(self_baseline) != 200 or len(_b(self_baseline).strip()) < _MIN_BODY:
        return {"verdict": "not_applicable", "reason": "the persona's own request returned nothing "
                                                       "substantive to compare against"}
    if _s(other_baseline) != 200 or len(_b(other_baseline).strip()) < _MIN_BODY:
        return {"verdict": "not_applicable", "reason": "the second persona has no comparable view of this "
                                                       "endpoint"}
    if _b(other_baseline) == _b(self_baseline):
        return {"verdict": "not_applicable", "reason": "both personas already see identical content — the "
                                                       "endpoint is not user-specific, so nothing can be proven"}
    if _s(mutation) != 200:
        return {"verdict": "rejected", "reason": "the tampered parameter was refused (status %s)" % _s(mutation)}
    if _b(mutation) == _b(self_baseline):
        return {"verdict": "rejected", "reason": "SECURE: the server ignored the client-supplied parameter "
                                                 "and answered about the session's own user"}
    if _b(mutation) == _b(other_baseline):
        if _control_ran(anon) and _s(anon) == 200 and _b(anon) == _b(other_baseline):
            return {"verdict": "rejected", "reason": "the content is PUBLIC — anonymous receives it too"}
        # Same trap as judge_client_side_authz: an errored anon control already failed the 200 test, so
        # it never fired the PUBLIC rejection and fell straight through to `confirmed`. Public has to be
        # ruled OUT by a control that ran, not left unexamined.
        if not _control_ran(anon):
            return {"verdict": "lead", "reason": "the other persona's data was returned, but the anonymous "
                                                 "control did not run, so PUBLIC content cannot be ruled "
                                                 "out -- not provable"}
        return {"verdict": "confirmed",
                "reason": "the server derived identity from the client-supplied '%s' parameter: changing "
                          "only that value returned the other persona's data verbatim (%d bytes)"
                          % (str((mutation or {}).get("param") or "parameter"), len(_b(mutation)))}
    return {"verdict": "lead", "reason": "the response changed but matched neither persona's baseline — "
                                         "the parameter influences the answer without a proven cross-user read"}


PARAM_ORACLE = ("two personas' browsers sent the same endpoint with different identity-parameter values; "
                "rewriting ONLY that value in the owner's own outgoing request returns the other persona's "
                "baseline byte-for-byte, while a server that ignores the parameter is explicitly rejected")


def finding_param_swap(cand: dict, probes: dict, verdict: dict, *, owner: str = "owner",
                       attacker: str = "attacker", mutation_method: str = "") -> dict:
    """Server trusts a client-supplied identity parameter — proven by mutating the app's own request."""
    confirmed = verdict.get("verdict") == "confirmed"
    url = cand.get("owner_url", "")
    return {
        "title": "Server trusts a client-supplied identity parameter '%s' (%s)"
                 % (cand.get("param"), cand.get("template") or url),
        "severity": "high" if confirmed else "medium",
        "confidence": "confirmed" if confirmed else "lead",
        "family": "bola",
        "cwe": "CWE-639",
        "owasp": "API1:2023",
        "target": url,
        "tags": ["bola", "idor", "browser", "runtime", "parameter-tampering", "access_control"],
        "description": ("The application's own request carries '%s' to say which user it concerns. Rewriting "
                        "only that value in the outgoing request — as persona '%s', targeting persona '%s''s "
                        "value — returned the other user's data. %s"
                        % (cand.get("param"), owner, attacker, verdict.get("reason", ""))),
        "impact": ("Identity is taken from a value the client controls, so any authenticated user can read "
                   "any other user's data at %s by editing one parameter; the entire user base is "
                   "enumerable." % (cand.get("template") or url)),
        "oracle": PARAM_ORACLE,
        "evidence": ("owner %s -> %s %dB | same request with %s rewritten to the other persona's value -> "
                     "%s %dB, identical to that persona's own baseline | anonymous -> %s"
                     % (url, (probes.get("self_baseline") or {}).get("status"),
                        (probes.get("self_baseline") or {}).get("len", 0), cand.get("param"),
                        (probes.get("mutation") or {}).get("status"),
                        (probes.get("mutation") or {}).get("len", 0),
                        (probes.get("anon") or {}).get("status"))),
        "remediation": ("Derive the subject of the request from the authenticated session, not from a "
                        "request parameter. If the parameter must exist, verify it matches the session's "
                        "principal and reject it otherwise."),
        "browser_evidence": {
            "schema": "apolaki.bie-evidence/1",
            "engine": "browser-intelligence-engine",
            "instrumentation": "playwright route interception (%s)" % (mutation_method or "unknown"),
            "reproduction_steps": [
                "1. Authenticate as persona '%s' in a browser." % owner,
                "2. Observe the application send %s at runtime." % url,
                "3. Intercept that outgoing request and change ONLY '%s' from '%s' to '%s'."
                % (cand.get("param"), cand.get("owner_value"), cand.get("attacker_value")),
                "4. Observe the response is persona '%s''s data, byte-for-byte." % attacker,
                "5. Negative controls: a server that ignores the parameter, and anonymous access, both "
                "fail to produce this result.",
            ],
            "mutated_variable": {"param": cand.get("param"), "from": cand.get("owner_value"),
                                 "to": cand.get("attacker_value"), "method": mutation_method},
            "exact_request": probes.get("self_baseline"),
            "mutated_request": probes.get("mutation"),
            "negative_controls": {k: probes.get(k) for k in ("anon", "other_baseline")
                                  if probes.get(k) is not None},
            "verdict": verdict,
            "personas": {"owner": owner, "attacker": attacker, "secrets": "[REDACTED -- held server-side]"},
            "replay_script": "\n".join([
                "#!/bin/sh",
                "# Apolaki BIE replay -- server trusts a client-supplied identity parameter.",
                "AUTH=\"$1\"   # persona '%s' auth material" % owner,
                "echo '1. baseline -- own value:'",
                "curl -sk -o /dev/null -w '   %%{http_code} %%{size_download}B\\n' -H \"Authorization: $AUTH\" '%s'" % url,
                "echo '2. mutation -- only %s changed:'" % cand.get("param"),
                "curl -sk -o /dev/null -w '   %%{http_code} %%{size_download}B\\n' -H \"Authorization: $AUTH\" '%s'"
                % mutate_param(url, cand.get("param", ""), cand.get("attacker_value", "")),
            ]),
        },
        "found_by": "bie",
    }


# ─────────────────────────────────────────── pure: the CLIENT-SIDE CONTROL SURFACE (CWE-602)
# Words that mark a control as reaching privileged/state-changing functionality. Used only to RANK which
# hidden controls are worth a safe probe -- never to assert a finding.
_PRIV_HINTS = ("admin", "manage", "moderat", "approve", "audit", "config", "setting", "role", "permission",
               "user", "delete", "remove", "ban", "suspend", "impersonat", "export", "billing", "invoice",
               "refund", "payout", "internal", "debug", "console", "backup", "owner", "grant")

# Selenium's visibility_of contract (Ch.10): an element is visible only when it is DISPLAYED *and* has
# height and width greater than zero. Anything else is hidden from the user -- which is precisely the
# state the client-side-authorization question turns on.
CONTROL_SURFACE_JS = """() => {
  const out = [];
  const sel = 'a[href],button,input[type=submit],input[type=button],[role=button],[routerlink]';
  // A control inside a COLLAPSED CONTAINER (closed nav drawer, accordion, inactive tab, closed dialog) is
  // not withheld from the user -- they open the menu and it is there. Only a control the application
  // suppressed in its own right is a candidate for "the UI withheld this". Distinguishing the two is the
  // difference between a real CWE-602 finding and flagging every item in a hamburger menu.
  const CONTAINERISH = /(nav|menu|drawer|sidenav|sidebar|accordion|collapse|dropdown|tab-|panel|dialog|modal|offcanvas)/i;
  const hiddenBy = (el) => {
    let node = el.parentElement, depth = 0;
    while (node && depth < 12) {
      let s = {};
      try { s = getComputedStyle(node); } catch (e) {}
      if (s.display === 'none' || s.visibility === 'hidden' || node.hasAttribute('hidden')) {
        const sig = (node.tagName + ' ' + (node.className || '') + ' ' + (node.getAttribute('role') || ''));
        return CONTAINERISH.test(sig) ? 'collapsed-container' : 'ancestor';
      }
      node = node.parentElement; depth++;
    }
    return 'self';
  };
  for (const el of document.querySelectorAll(sel)) {
    if (out.length >= 300) break;
    let cs = {};
    try { cs = getComputedStyle(el); } catch (e) {}
    const r = el.getBoundingClientRect();
    const displayed = cs.display !== 'none' && cs.visibility !== 'hidden' && Number(cs.opacity || 1) > 0;
    const visible = displayed && r.width > 0 && r.height > 0 && !el.hasAttribute('hidden');
    const disabled = el.disabled === true || el.getAttribute('aria-disabled') === 'true' ||
                     el.classList.contains('disabled');
    const by = visible ? '' : hiddenBy(el);
    out.push({
      tag: el.tagName.toLowerCase(),
      text: (el.innerText || el.value || el.getAttribute('aria-label') || '').trim().slice(0, 80),
      href: el.getAttribute('href') || '',
      resolved: (el.tagName.toLowerCase() === 'a' && el.href) ? el.href : '',
      routerlink: el.getAttribute('routerlink') || '',
      id: el.id || '', name: el.getAttribute('name') || '',
      visible: visible, disabled: !!disabled, hidden_by: by,
      reason: !displayed ? 'not-displayed' : (r.width <= 0 || r.height <= 0) ? 'zero-size'
              : el.hasAttribute('hidden') ? 'hidden-attr' : (disabled ? 'disabled' : '')
    });
  }
  return out;
}"""


# HONEST LIMITATION: a framework that REMOVES a control from the DOM (Angular *ngIf, React conditional
# render) leaves nothing to enumerate — this phase then correctly reports zero rather than guessing. Routes
# that exist only inside the JS bundle are the static collectors' job (codereview/js-review already harvest
# them into has_sensitive_route); the two views compose, and neither pretends to be the other.
def privilege_hint(control: dict) -> str:
    """Which privileged-word a control's text/href/id suggests, or "". Ranking only, never proof. Pure."""
    blob = " ".join(str(control.get(k) or "") for k in ("text", "href", "routerlink", "id", "name")).lower()
    for w in _PRIV_HINTS:
        if w in blob:
            return w
    return ""


def dedupe_controls(controls) -> list:
    """One entry per distinct control across every rendered route. A control seen VISIBLE anywhere is not
    withheld — the persona can reach it, so it must not be reported as hidden just because some other route
    did not render it. Pure."""
    by_key, order = {}, []
    for c in (controls or []):
        k = (c.get("tag"), c.get("text"), c.get("href") or c.get("routerlink"), c.get("id"))
        if k not in by_key:
            by_key[k] = dict(c)
            order.append(k)
        elif c.get("visible") and not c.get("disabled"):
            by_key[k] = dict(c)              # the most PERMISSIVE observation wins
    return [by_key[k] for k in order]


def classify_controls(controls) -> dict:
    """Split the rendered control surface three ways. A withheld control is the interesting one — the
    application decided this user may not have it. A control sitting in a COLLAPSED CONTAINER (closed nav
    drawer, accordion, inactive tab) is NOT withheld: the user opens the menu and it is there, so treating
    it as withheld would flag every hamburger-menu item as a potential authorization bug. Pure."""
    offered, withheld, collapsed = [], [], []
    for c in (controls or []):
        if c.get("visible") and not c.get("disabled"):
            offered.append(c)
        elif c.get("hidden_by") == "collapsed-container" and not c.get("disabled"):
            collapsed.append(c)
        else:
            withheld.append(c)
    priv = [c for c in withheld if privilege_hint(c)]
    return {"total": len(controls or []), "offered": offered, "withheld": withheld,
            "collapsed": collapsed, "withheld_privileged": priv,
            "counts": {"total": len(controls or []), "offered": len(offered), "withheld": len(withheld),
                       "collapsed": len(collapsed), "withheld_privileged": len(priv)}}


def probe_targets(classified: dict, base: str, max_n: int = 6) -> list:
    """Withheld controls whose target is a REAL server resource, so a SAFE GET actually asks the server the
    question. Client-side-only routes (#/…, routerLink, javascript:, #) and anything that would require a
    state-changing submit are deliberately excluded here -- those become operator leads, never auto-fired.
    Pure."""
    from urllib.parse import urljoin
    out, seen = [], set()
    for c in (classified or {}).get("withheld_privileged", []):
        href = str(c.get("resolved") or c.get("href") or "")
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            continue
        u = urljoin(base.rstrip("/") + "/", href)
        if "#" in u.split("://")[-1].split("/", 1)[-1][:1]:
            continue
        if u in seen:
            continue
        seen.add(u)
        out.append({**c, "probe_url": u, "hint": privilege_hint(c)})
        if len(out) >= max_n:
            break
    return out


def judge_client_side_authz(control: dict, persona, anon=None, shell=None) -> dict:
    """Decide whether a control the UI WITHHELD is nevertheless served by the server to this persona --
    i.e. the access control lives only in the browser (CWE-602). Pure, deterministic.

    CONFIRMED requires: the control really was withheld in the rendered DOM; the server serves it to this
    persona (200 + substantive body); the ANONYMOUS control does not get the same body (otherwise it is
    simply public content, not an authorization boundary); and the SPA-shell control differs (otherwise we
    only received index.html and learned nothing)."""
    def _b(x):
        return ((x or {}).get("body") or "")

    def _s(x):
        return int((x or {}).get("status") or 0)

    if control.get("visible") and not control.get("disabled"):
        return {"verdict": "not_applicable", "reason": "the UI offers this control to the persona"}
    if _s(persona) != 200 or len(_b(persona).strip()) < _MIN_BODY:
        return {"verdict": "rejected", "reason": "the server also refuses it (status %s) -- the control is "
                                                 "hidden AND enforced" % _s(persona)}
    if not _control_ran(shell):
        return {"verdict": "lead", "reason": "server served the withheld control but the SPA-shell control "
                                             "did not run -- not provable"}
    if _b(shell) == _b(persona):
        return {"verdict": "rejected", "reason": "the response is the application shell (an unknown path "
                                                 "returns the same body) -- nothing privileged was served"}
    if _control_ran(anon) and _s(anon) == 200 and _b(anon) == _b(persona):
        return {"verdict": "rejected", "reason": "the resource is PUBLIC -- anonymous receives the same "
                                                 "body, so no authorization boundary exists"}
    # A DEAD anonymous control cannot clear a resource of being public. Tightening the condition above
    # is not enough on its own: an errored control already failed `_s(anon) == 200`, so it never fired
    # the rejection and fell through to `confirmed` anyway. The public-resource question has to be
    # ANSWERED, not merely not-answered-negatively.
    if not _control_ran(anon):
        return {"verdict": "lead", "reason": "server served the withheld control, but the anonymous "
                                             "control did not run, so PUBLIC cannot be ruled out -- "
                                             "not provable"}
    return {"verdict": "confirmed",
            "reason": "the interface withheld this control (%s) yet the server served it to the same "
                      "persona (200, %d bytes): the restriction is enforced only in the browser"
                      % (control.get("reason") or "hidden", len(_b(persona)))}


CLIENT_AUTHZ_ORACLE = ("the control is withheld in the rendered DOM (Selenium visibility contract: not "
                       "displayed, or zero-size, or disabled) while a SAFE GET as the same persona is "
                       "served a substantive body that is neither the SPA shell nor public content")


def finding_client_side_authz(control: dict, probes: dict, verdict: dict, persona: str = "user") -> dict:
    """A control the browser hid but the server still serves — access control implemented in the UI only."""
    confirmed = verdict.get("verdict") == "confirmed"
    url = control.get("probe_url", "")
    label = control.get("text") or control.get("id") or control.get("href") or "(unlabelled control)"
    return {
        "title": "Access control enforced only in the browser: withheld control \"%s\" is served by the "
                 "server" % str(label)[:60],
        "severity": "high" if confirmed else "medium",
        "confidence": "confirmed" if confirmed else "lead",
        "family": "access_control",
        "cwe": "CWE-602",
        "owasp": "A01:2021",
        "target": url,
        "tags": ["access_control", "client_side", "browser", "runtime", "hidden_ui"],
        "description": ("The application's own interface withheld this control from persona '%s' (%s), "
                        "which means the application itself considers it out of bounds for this user. The "
                        "server nevertheless serves it to that same session. %s"
                        % (persona, control.get("reason") or "hidden", verdict.get("reason", ""))),
        "impact": ("A user the application intends to exclude can reach %s directly — the restriction is "
                   "cosmetic, so anyone who opens developer tools or requests the URL gets the "
                   "privileged function." % url),
        "oracle": CLIENT_AUTHZ_ORACLE,
        "evidence": ("withheld control %s (%s) -> persona GET %s = %s (%dB) | anonymous = %s | "
                     "unknown-path shell control = %s"
                     % (str(label)[:40], control.get("reason"), url,
                        (probes.get("persona") or {}).get("status"),
                        (probes.get("persona") or {}).get("len", 0),
                        (probes.get("anon") or {}).get("status"),
                        (probes.get("shell") or {}).get("status"))),
        "remediation": ("Enforce the authorization decision on the server for this route, not by hiding the "
                        "control. Hiding or disabling UI affordances is a usability measure; any client can "
                        "request the underlying resource directly."),
        "browser_evidence": {
            "schema": "apolaki.bie-evidence/1",
            "engine": "browser-intelligence-engine",
            "instrumentation": "playwright + raw CDP (DOM/Runtime)",
            "reproduction_steps": [
                "1. Authenticate as persona '%s' in a browser." % persona,
                "2. Observe that the control \"%s\" is present in the DOM but withheld (%s)."
                % (str(label)[:60], control.get("reason") or "hidden"),
                "3. Request its target directly: GET %s with the same session." % url,
                "4. Observe the server returns it anyway (the UI was the only thing stopping you).",
                "5. Negative controls: an unknown path returns the app shell, and anonymous does not "
                "receive this content.",
            ],
            "control": {k: control.get(k) for k in ("tag", "text", "href", "id", "visible", "disabled",
                                                    "reason", "hint")},
            "exact_request": probes.get("persona"),
            "negative_controls": {k: probes.get(k) for k in ("anon", "shell") if probes.get(k) is not None},
            "verdict": verdict,
            "personas": {"persona": persona, "secrets": "[REDACTED -- held server-side]"},
            "replay_script": "\n".join([
                "#!/bin/sh",
                "# Apolaki BIE replay -- UI-only access control (CWE-602).",
                "AUTH=\"$1\"   # the persona's own auth material",
                "echo '1. the UI withheld this control (%s); ask the server directly:'" % (control.get("reason") or "hidden"),
                "curl -sk -o /dev/null -w '   %%{http_code} %%{size_download}B\\n' -H \"Authorization: $AUTH\" '%s'" % url,
                "echo '2. control -- anonymous (expect denied or different):'",
                "curl -sk -o /dev/null -w '   %%{http_code} %%{size_download}B\\n' '%s'" % url,
            ]),
        },
        "found_by": "bie",
    }


# ─────────────────────────────────────────────────────────── pure: runtime -> planner vocabulary
def to_observations(runtime) -> set:
    """Map a runtime capture onto the SAME deterministic observation vocabulary HTTP recon uses, so the
    browser's runtime truth reaches the existing planner instead of forming a second brain. Pure."""
    out = set()
    r = runtime or {}
    if not r or r.get("browser") is False:
        return out
    urls = [str(u).lower() for u in (r.get("requests") or [])]
    joined = " ".join(urls)
    if any(u.endswith(".js") or ".js?" in u for u in urls):
        out.add("serves_js")
    if "/api/" in joined or "/rest/" in joined or "/graphql" in joined or "/v1/" in joined:
        out.add("has_api")
    if any(w in joined for w in ("login", "signin", "authenticate", "/session")):
        out.add("has_login")
    if any(object_template(u)[0] for u in urls):
        out.add("has_object_id")
    if r.get("storage_keys") or r.get("has_auth_material"):
        out.add("authenticated")
    if any(w in joined for w in ("/admin", "/manage", "/internal", "/console")):
        out.add("has_sensitive_route")
    return out


# ─────────────────────────────────────────────────────────── live: Playwright + raw CDP
def available() -> tuple:
    """(usable, note). Never raises."""
    try:
        import playwright  # noqa: F401
    except Exception:
        return False, "playwright is not installed in this image"
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except Exception:
        return False, "playwright sync API unavailable"
    return True, "playwright + chromium"


def _empty(base: str, note: str) -> dict:
    return {"base": base, "browser": False, "ran": False, "note": note,
            "requests": [], "candidates": [], "probes": [], "findings": [], "exchanges": []}


_FETCH_JS = """async ([u, h]) => {
  const t0 = performance.now();
  try {
    const r = await fetch(u, { headers: h || {}, credentials: 'include', redirect: 'follow' });
    const body = await r.text();
    const hd = {}; r.headers.forEach((v, k) => { hd[k] = v; });
    return { status: r.status, body: body, headers: hd, ms: performance.now() - t0 };
  } catch (e) {
    return { status: 0, body: '', headers: {}, ms: performance.now() - t0, error: String(e).slice(0, 160) };
  }
}"""


def _seed_auth(page, headers: dict, storage: dict = None) -> bool:
    """Give the browser context the persona's session the way the APPLICATION does: the bearer token into
    localStorage/sessionStorage + a `token` cookie, plus every field the app's own login response returned
    (see storage_from_login). SPAs read identity from storage, not from a header the operator injected.
    Best-effort; returns whether any material was seeded."""
    tok = ""
    for k, v in (headers or {}).items():
        if str(k).lower() == "authorization":
            tok = str(v).split(" ", 1)[-1].strip()
    seed = dict(storage or {})
    if tok:
        seed.setdefault("token", tok)
    if not seed:
        return bool(headers)
    try:
        page.evaluate("""(s) => { try { for (const k in s) { localStorage.setItem(k, s[k]);
                                                             sessionStorage.setItem(k, s[k]); }
                                        if (s.token) document.cookie = 'token=' + s.token + '; path=/';
                                  } catch (e) {} }""", seed)
        return True
    except Exception:
        return bool(headers)


def _attach_cdp(context, page, sink: list, role: str = ""):
    """Raw CDP Network domain -- the wire-level view Playwright's high-level events do not expose
    (post data, mime type, remote address, security state). Best-effort; None when unavailable."""
    try:
        cdp = context.new_cdp_session(page)
        cdp.send("Network.enable")
        pending = {}

        def _req(ev):
            try:
                r = ev.get("request") or {}
                pending[ev.get("requestId")] = {"url": r.get("url"), "method": r.get("method"),
                                                "post_data": bool(r.get("postData"))}
            except Exception:
                pass

        def _resp(ev):
            try:
                r = ev.get("response") or {}
                q = pending.pop(ev.get("requestId"), {})
                sink.append({"url": r.get("url") or q.get("url"), "method": q.get("method") or "GET",
                             "status": r.get("status"), "mime": r.get("mimeType"),
                             "remote_ip": r.get("remoteIPAddress"),
                             "security": r.get("securityState"),
                             "resp_len": int(r.get("encodedDataLength") or 0),
                             "post_data": bool(q.get("post_data")), "persona": role})
            except Exception:
                pass

        cdp.on("Network.requestWillBeSent", _req)
        cdp.on("Network.responseReceived", _resp)
        return cdp
    except Exception:
        return None


def settle(page, timeout_ms: int, expect_object: bool = False) -> str:
    """DETERMINISM, not sleeping. A fixed `wait_for_timeout` is an anti-pattern: it is simultaneously too
    slow on a fast app and too short on a slow one, which is exactly how browser evidence turns flaky.
    Instead wait for the CONDITION that matters — the network going idle, and (when the point of the
    navigation is to observe an object fetch) an actual response whose URL carries an object id.

    Returns the settle reason, so the evidence records HOW the run was synchronised rather than hiding a
    magic number. Never raises."""
    reason = "load"
    try:
        page.wait_for_load_state("networkidle", timeout=timeout_ms)
        reason = "networkidle"
    except Exception:
        reason = "networkidle-timeout"
    if expect_object:
        try:
            page.wait_for_event("response", predicate=lambda r: bool(object_template(r.url)[0]),
                                timeout=min(4000, timeout_ms))
            reason += "+object-response"
        except Exception:
            reason += "+no-object-response"
    return reason


def _goto_awaiting_object(page, url: str, timeout_ms: int, attempts: list = None) -> str:
    """Navigate and wait for the app's OWN object request, registering the expectation BEFORE the
    navigation so a fast response cannot be missed. Deterministic; never raises.

    A navigation that fails is RECORDED (see classify_failure) rather than swallowed — silent failure is
    how a scan comes to report 'nothing found' about a page it never actually loaded."""
    def _record(err=None):
        if attempts is not None:
            attempts.append({"action": "navigate", "url": url, "failure": classify_failure(err)})

    try:
        with page.expect_response(lambda r: bool(_split_path(r.url)), timeout=timeout_ms):
            browser_engine.rate_limited_goto_sync(
                page, url, wait_until="domcontentloaded", timeout=timeout_ms)
        _record()
        return settle(page, timeout_ms) + "+object-response"
    except Exception:
        try:
            browser_engine.rate_limited_goto_sync(
                page, url, wait_until="domcontentloaded", timeout=timeout_ms)
        except Exception as e:
            _record(e)
            return "navigation-failed: %s" % classify_failure(e)["code"]
        _record()
        return settle(page, timeout_ms)


def _artifact_dir(har_dir: str = "") -> str:
    """Where run artifacts (HAR, trace) are written. Defaults under the agent's data volume so they
    survive the mission and can be attached to the bundle. Never raises."""
    import os
    d = har_dir or os.environ.get("BIE_ARTIFACT_DIR") or "/app/data/bie"
    try:
        os.makedirs(d, exist_ok=True)
        return d
    except Exception:
        return ""


def start_trace(context, name: str) -> bool:
    """Begin a Playwright trace: every action, DOM snapshot, console line and network call of the run,
    scrubable afterwards in the trace viewer. Best-effort; a browser without tracing must not fail a
    scan."""
    try:
        context.tracing.start(name=str(name)[:60], screenshots=True, snapshots=True, sources=False)
        return True
    except Exception:
        return False


def stop_trace(context, path: str) -> str:
    """Finish the trace and return the artifact path (empty when tracing was unavailable). Never raises."""
    if not path:
        try:
            context.tracing.stop()
        except Exception:
            pass
        return ""
    try:
        context.tracing.stop(path=path)
        import os
        return path if os.path.exists(path) else ""
    except Exception:
        return ""


def session_fingerprint(context) -> dict:
    """A REDACTED description of the persona's real browser session — cookie names, origins and storage
    keys, never values. Proves the two contexts were genuinely distinct logged-in sessions without
    exporting a single secret. Never raises."""
    try:
        st = context.storage_state()
    except Exception:
        return {}
    try:
        cookies = sorted({str(c.get("name")) for c in (st.get("cookies") or [])})
        origins = []
        for o in (st.get("origins") or []):
            origins.append({"origin": o.get("origin"),
                            "storage_keys": sorted(str(i.get("name")) for i in (o.get("localStorage") or []))})
        return {"cookie_names": cookies, "origins": origins,
                "note": "values redacted — session secrets never leave the engine"}
    except Exception as _apolaki_exc:
        # I-5: {} is also what a persona with no cookies and no storage returns, so the
        # persona-swap proof would read a crashed fingerprint as "the two contexts were
        # identical" -- the exact claim this function exists to be able to refuse.
        # `import` rather than `sys.modules.get`: `deadcode_gate.scan_qualified`
        # resolves a caller only through a RESOLVED import, and a module fetched
        # dynamically resolves to nothing -- which is how this recorder read as dead
        # while three live call sites pointed straight at it.  Safe as a statement in
        # an except handler: every path that reaches here runs inside a ToolRegistry
        # dispatch, so `tools` is already in sys.modules and this is a dict lookup.
        import tools as _tools
        _tools._swallow(_apolaki_exc, "bie.session_fingerprint", "")
        return {}


def _new_persona(browser, base: str, headers: dict, *, timeout_ms: int, wire: list, role: str = "",
                 storage: dict = None, har_dir: str = ""):
    """An isolated browser context per persona -- separate cookie jar, storage and session. This is what
    makes the swap honest: two REAL logged-in browsers, not one browser with two header sets.

    Each persona gets its OWN wire sink: which persona's browser made which request is the whole basis of
    the cross-user hypothesis, so a shared sink would destroy the attribution."""
    kw = {"ignore_https_errors": True,
          "extra_http_headers": {k: v for k, v in (headers or {}).items()}}
    if har_dir:                             # record the real run as a HAR — a standard, replayable artifact
        import os as _os
        kw["record_har_path"] = _os.path.join(har_dir, "bie-%s.har" % (role or "persona"))
        kw["record_har_content"] = "omit"   # bodies live in the evidence exchanges (clipped + redacted)
    ctx = browser.new_context(**kw)
    page = ctx.new_page()
    cdp = _attach_cdp(ctx, page, wire, role=role)
    try:
        browser_engine.rate_limited_goto_sync(
            page, base, wait_until="domcontentloaded", timeout=timeout_ms)
    except Exception:
        pass
    seeded = _seed_auth(page, headers, storage)
    try:                                    # reload so the SPA boots WITH the persona's session
        browser_engine.rate_limited_goto_sync(
            page, base, wait_until="domcontentloaded", timeout=timeout_ms)
    except Exception:
        pass
    settle(page, timeout_ms)
    return ctx, page, cdp, seeded


def route_mutate(context, page, target_url: str, param: str, new_value: str, *, persona: str,
                 trigger_url: str = "", timeout_ms: int = 25000) -> tuple:
    """Change ONE variable in the application's OWN outgoing request, before it leaves the browser.

    This is the real thing the spec asks for: not a replayed fetch we composed, but the request the app
    itself decided to make, intercepted and rewritten in flight. Returns (exchange, method) where method
    records HONESTLY how the mutation was achieved — "route-interception" when the app re-issued the
    request and we rewrote it, or "in-page-fetch" when it did not and we had to issue the mutated request
    from inside the persona's page instead. Never raises; read-only (safe methods only)."""
    mutated = mutate_param(target_url, param, new_value)
    captured, method = {}, "route-interception"

    def _handler(route):
        try:
            req = route.request
            if req.method.upper() in ("GET", "HEAD") and same_endpoint(req.url, target_url):
                route.continue_(url=mutate_param(req.url, param, new_value))
                return
        except Exception:
            pass
        try:
            route.continue_()
        except Exception:
            pass

    def _on_response(resp):
        try:
            if not captured and same_endpoint(resp.url, target_url) and param + "=" in resp.url:
                captured.update({"status": resp.status, "body": (resp.text() or "")[:_MAX_BODY]})
        except Exception:
            pass

    try:
        context.route("**/*", _handler)
        page.on("response", _on_response)
    except Exception:
        return _fetch(page, mutated, {}, persona), "in-page-fetch"
    try:
        nav = trigger_url or page.url or target_url
        browser_engine.rate_limited_goto_sync(
            page, nav, wait_until="domcontentloaded", timeout=timeout_ms)
        settle(page, timeout_ms)
    except Exception:
        pass
    try:
        context.unroute("**/*", _handler)
        page.remove_listener("response", _on_response)
    except Exception:
        pass
    if not captured:
        # The app did not re-issue that request on this navigation. Say so, and fall back to issuing the
        # mutated request from inside the persona's own page — still a real browser request in a real
        # session, but a weaker provenance claim, so the evidence records which one happened.
        return _fetch(page, mutated, {}, persona), "in-page-fetch"
    return exchange(mutated, captured.get("status"), captured.get("body", ""), persona=persona), method


def _read_controls(page, errors: list = None) -> list:
    """Enumerate the rendered control surface of whatever page the persona is currently on.

    Never raises -- an unreadable page must not abort the phase -- but the failure is RECORDED rather
    than dissolved (Q-016). `except Exception: return []` made a `page.evaluate` that threw
    byte-identical to a page that genuinely renders no controls: `classify_controls([])` gives
    `counts.total = 0`, phase 2 emits zero probes and zero findings, and the report prints
    `control_surface.counts.total: 0` -- a confident statement that the application has no control
    surface, produced by a crash.

    Fourth instance of this shape in the codebase (DOM_SCAN_JS, the traversal import, the service
    sweep), which is why the fix is a recorded diagnostic and not a bare `raise`: the caller decides
    what a degraded read means, and it can only decide if it is told.
    """
    try:
        return list(page.evaluate(CONTROL_SURFACE_JS) or [])
    except Exception as exc:
        if errors is not None and len(errors) < 20:
            errors.append("%s: %s" % (type(exc).__name__, str(exc)[:160]))
        return []


def _fetch(page, url: str, headers: dict, persona: str) -> dict:
    """Issue the request FROM INSIDE the persona's page -- same origin, same cookies, same service
    workers as the application's own traffic."""
    try:
        res = page.evaluate(_FETCH_JS, [url, {k: v for k, v in (headers or {}).items()}])
    except Exception as e:
        return exchange(url, 0, "", {}, persona=persona) | {"error": str(e)[:160]}
    return exchange(url, res.get("status"), res.get("body") or "", res.get("headers"),
                    persona=persona, ms=res.get("ms"))


def run_persona_swap(base: str, *, owner_headers: dict, attacker_headers: dict, owner: str = "owner",
                     attacker: str = "attacker", seed_paths=None, extra_owner_urls=None,
                     owner_storage: dict = None, attacker_storage: dict = None, har_dir: str = "",
                     timeout_ms: int = 25000, max_candidates: int = 3, screenshots: bool = True,
                     scope_ok=None) -> dict:
    """THE runtime cross-user proof. Opens one isolated browser context per persona (owner / attacker /
    anonymous), lets each application boot for real, harvests the object requests the app itself makes,
    forms the swap hypotheses, executes each swap plus three negative controls from inside the attacker's
    own page, and hands every result to the deterministic oracle.

    scope_ok(url) -> bool is the caller's scope gate; every URL touched passes through it. Read-only:
    only GETs are issued. Never raises -- returns a labelled empty result on any failure."""
    usable, note = available()
    if not usable:
        return _empty(base, note)
    base = (base or "").rstrip("/")
    if not base:
        return _empty(base, "no base url")
    ok = scope_ok or (lambda _u: True)
    if not ok(base):
        return _empty(base, "base url is out of scope")

    from playwright.sync_api import sync_playwright
    o_wire, a_wire, n_wire = [], [], []
    out = _empty(base, "")
    out.update({"browser": True, "ran": True, "note": ""})
    art_dir = _artifact_dir(har_dir)
    har_dir = har_dir or art_dir
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            try:
                o_ctx, o_page, _oc, o_seed = _new_persona(browser, base, owner_headers, role=owner,
                                                          timeout_ms=timeout_ms, wire=o_wire,
                                                          storage=owner_storage, har_dir=har_dir)
                a_ctx, a_page, _ac, a_seed = _new_persona(browser, base, attacker_headers, role=attacker,
                                                          timeout_ms=timeout_ms, wire=a_wire,
                                                          storage=attacker_storage, har_dir=har_dir)
                n_ctx, n_page, _nc, _ = _new_persona(browser, base, {}, role="anonymous",
                                                     timeout_ms=timeout_ms, wire=n_wire, har_dir=har_dir)
                # Trace the ATTACKER context: it is the one that performs every exploit attempt, so its
                # trace is the scrubable recording a client can replay against a confirmed finding.
                traced = start_trace(a_ctx, "apolaki-bie-%s" % attacker)

                obs_start = (len(o_wire), len(a_wire))
                # The control surface must be read while the personas are still ON the application's own
                # pages — a later navigation to a raw API URL would present an empty DOM and silently
                # report "no controls". Accumulate across every rendered route.
                ctl_errors = out.setdefault("control_read_errors", [])
                raw_controls, app_page_url = _read_controls(a_page, ctl_errors), base
                attempts = out.setdefault("_attempts", [])
                for path in (seed_paths or [])[:6]:      # let each app render the pages that fetch objects
                    u = path if "://" in str(path) else base + str(path)
                    if not ok(u):
                        continue
                    for pg in (o_page, a_page):
                        out.setdefault("settle", []).append(
                            {"url": u, "reason": _goto_awaiting_object(pg, u, timeout_ms, attempts)})
                    raw_controls += _read_controls(a_page, ctl_errors)
                    app_page_url = u                     # the last APP page that actually drove requests
                # OBSERVED cross-user hypotheses: the object URLs each persona's OWN browser requested.
                owner_urls = [w["url"] for w in o_wire[obs_start[0]:] if w.get("url")]
                attacker_urls = [w["url"] for w in a_wire[obs_start[1]:] if w.get("url")]
                owner_urls += [str(u) for u in (extra_owner_urls or [])]
                cands = object_candidates(owner_urls, attacker_urls, max_n=max_candidates)
                # When both personas hit the SAME ids (shared/public data), fall back to the explicit
                # owner objects the caller supplies -- the artery knows which ids the owner owns.
                if not cands:
                    # Caller-supplied owner objects: the caller (the artery) already established ownership,
                    # so the terminal segment IS the key — no id-shape guess needed, which is what lets a
                    # username-keyed object through where a regex would refuse it.
                    for u in (extra_owner_urls or [])[:max_candidates]:
                        parts = _split_path(str(u))
                        if not parts or not ok(str(u)):
                            continue
                        idx = len(parts[2]) - 1
                        cands.append({"template": segment_template(str(u), idx), "owner_url": str(u),
                                      "owner_id": parts[2][idx], "attacker_url": None,
                                      "attacker_id": None, "index": idx})
                out["candidates"] = cands

                for cand in cands:
                    ourl = cand["owner_url"]
                    if not ok(ourl):
                        continue
                    nonexistent_url = (swap_segment(ourl, cand["index"], _IMPLAUSIBLE_ID)
                                       if cand.get("index") is not None else swap_url(ourl, _IMPLAUSIBLE_ID))
                    probes = {
                        "baseline": _fetch(o_page, ourl, owner_headers, owner),
                        "mutation": _fetch(a_page, ourl, attacker_headers, attacker),
                        "anon": _fetch(n_page, ourl, {}, "anonymous"),
                        "nonexistent": (_fetch(a_page, nonexistent_url, attacker_headers, attacker)
                                        if nonexistent_url and ok(nonexistent_url) else None),
                        "control": (_fetch(a_page, cand["attacker_url"], attacker_headers, attacker)
                                    if cand.get("attacker_url") and ok(cand["attacker_url"]) else None),
                    }
                    verdict = judge(probes["baseline"], probes["mutation"], anon=probes["anon"],
                                    nonexistent=probes["nonexistent"], control=probes["control"])
                    shots = {}
                    if screenshots and verdict.get("verdict") == "confirmed":
                        shots = _capture_shots(o_page, a_page, ourl, timeout_ms)
                    out["probes"].append({"candidate": cand, "verdict": verdict,
                                          "exchanges": {k: v for k, v in probes.items() if v}})
                    out["exchanges"].extend([v for v in probes.values() if v])
                    if verdict.get("verdict") in ("confirmed", "lead"):
                        f = finding(cand, probes, verdict, owner=owner, attacker=attacker,
                                    screenshots=shots)
                        # the route a human takes to reach this, derived from what actually happened
                        f["browser_evidence"]["flow"] = user_flow(
                            out.get("settle") or [], o_wire,
                            {"candidate": cand, "verdict": verdict}, owner=owner, attacker=attacker)
                        out["findings"].append(f)
                # PHASE 3 — CLIENT-SUPPLIED IDENTITY PARAMETERS, mutated by route interception. Where
                # phase 1 changes an id in a path, this changes one identity VARIABLE inside the request
                # the application itself emits, in flight. Safe methods only.
                for pc in param_candidates(owner_urls, attacker_urls):
                    if not ok(pc["owner_url"]) or not ok(pc["attacker_url"]):
                        continue
                    # Re-drive an APP page (phase 1's screenshots may have parked the page on a raw API
                    # URL), so the application genuinely re-issues the request we intend to intercept.
                    mut, how = route_mutate(o_ctx, o_page, pc["owner_url"], pc["param"],
                                            pc["attacker_value"], persona=owner, timeout_ms=timeout_ms,
                                            trigger_url=app_page_url)
                    pprobes = {"self_baseline": _fetch(o_page, pc["owner_url"], owner_headers, owner),
                               "other_baseline": _fetch(a_page, pc["attacker_url"], attacker_headers,
                                                        attacker),
                               "mutation": {**mut, "param": pc["param"]},
                               "anon": _fetch(n_page, pc["attacker_url"], {}, "anonymous")}
                    pver = judge_param_swap(pprobes["self_baseline"], pprobes["other_baseline"],
                                            pprobes["mutation"], anon=pprobes["anon"])
                    out["probes"].append({"candidate": pc, "verdict": pver, "mutation_method": how,
                                          "exchanges": {k: v for k, v in pprobes.items() if v}})
                    out["exchanges"].extend([v for v in pprobes.values() if v])
                    if pver.get("verdict") in ("confirmed", "lead"):
                        out["findings"].append(finding_param_swap(pc, pprobes, pver, owner=owner,
                                                                  attacker=attacker, mutation_method=how))

                # PHASE 2 — the client-side CONTROL SURFACE (CWE-602). What did the interface WITHHOLD from
                # this persona, and does the server withhold it too? Only safe GETs on real server
                # resources are fired; state-changing controls become operator leads, never auto-clicks.
                classified = classify_controls(dedupe_controls(raw_controls))
                out["control_surface"] = {k: classified[k] for k in ("counts", "withheld_privileged")}
                # Q-016: a zero that came from a CRASH is not the same claim as a zero that came from
                # a page. `degraded` is set only when the read failed AND nothing was read, which is
                # exactly the case a reader would otherwise mistake for "this app has no controls".
                if ctl_errors:
                    out["control_surface"]["read_errors"] = list(ctl_errors)
                    out["control_surface"]["degraded"] = not raw_controls
                for ctl in probe_targets(classified, base):
                    u = ctl["probe_url"]
                    if not ok(u):
                        continue
                    shell_url = base + "/apolaki-unknown-path-%s" % _IMPLAUSIBLE_ID
                    cprobes = {"persona": _fetch(a_page, u, attacker_headers, attacker),
                               "anon": _fetch(n_page, u, {}, "anonymous"),
                               "shell": (_fetch(a_page, shell_url, attacker_headers, attacker)
                                         if ok(shell_url) else None)}
                    cver = judge_client_side_authz(ctl, cprobes["persona"], anon=cprobes["anon"],
                                                   shell=cprobes["shell"])
                    out["probes"].append({"candidate": ctl, "verdict": cver,
                                          "exchanges": {k: v for k, v in cprobes.items() if v}})
                    out["exchanges"].extend([v for v in cprobes.values() if v])
                    if cver.get("verdict") in ("confirmed", "lead"):
                        out["findings"].append(finding_client_side_authz(ctl, cprobes, cver,
                                                                        persona=attacker))

                out["personas"] = {
                    "owner": {"role": owner, "auth_seeded": bool(o_seed),
                              "session": session_fingerprint(o_ctx)},
                    "attacker": {"role": attacker, "auth_seeded": bool(a_seed),
                                 "session": session_fingerprint(a_ctx)},
                    "anonymous": {"role": "anonymous", "auth_seeded": False,
                                  "session": session_fingerprint(n_ctx)}}
                # Freeze the trace only when something was actually CONFIRMED — a scrubable recording of a
                # run that proved nothing is noise, and traces are large.
                import os as _os
                if traced:
                    want = any(f.get("confidence") == "confirmed" for f in out["findings"])
                    tpath = (_os.path.join(art_dir, "bie-trace-%s.zip" % attacker)
                             if (want and art_dir) else "")
                    saved = stop_trace(a_ctx, tpath)
                    if saved:
                        out["trace"] = {"path": saved, "persona": attacker,
                                        "bytes": (_os.path.getsize(saved) if _os.path.exists(saved) else 0),
                                        "viewer": "npx playwright show-trace <file>",
                                        "contains": "every action, DOM snapshot, console line and network "
                                                    "call of the confirmed run"}
                        for f in out["findings"]:
                            if f.get("confidence") == "confirmed":
                                f.setdefault("browser_evidence", {})["trace"] = out["trace"]
                for c in (o_ctx, a_ctx, n_ctx):
                    try:
                        c.close()
                    except Exception:
                        pass
            finally:
                try:
                    browser.close()
                except Exception:
                    pass
    except Exception as e:
        return _empty(base, "browser runtime unavailable: %s" % str(e)[:120])
    wire = o_wire + a_wire + n_wire
    # Coverage honesty: state what the browser could and could not do, so "no findings" is never confused
    # with "we could not look".
    out["drive"] = drive_report(out.pop("_attempts", []))
    out["requests"] = sorted({w["url"] for w in wire if w.get("url")})
    out["wire"] = wire[:400]
    out["observations"] = sorted(to_observations({"browser": True, "requests": out["requests"],
                                                  "has_auth_material": True}))
    out["counts"] = {"requests": len(out["requests"]), "candidates": len(out["candidates"]),
                     "probes": len(out["probes"]), "findings": len(out["findings"]),
                     "confirmed": sum(1 for f in out["findings"] if f.get("confidence") == "confirmed"),
                     "by_persona": {owner: len(o_wire), attacker: len(a_wire), "anonymous": len(n_wire)}}
    return out


def _capture_shots(owner_page, attacker_page, url: str, timeout_ms: int) -> dict:
    """Before/after screenshots frozen from the confirmed run: the owner viewing its own object, and the
    attacker's browser showing the SAME object it should never see. Best-effort."""
    import base64
    shots = {}
    for label, pg in (("owner_view", owner_page), ("attacker_view", attacker_page)):
        try:
            browser_engine.rate_limited_goto_sync(
                pg, url, wait_until="domcontentloaded", timeout=timeout_ms)
            settle(pg, timeout_ms)
            shots[label] = {"png_b64": base64.b64encode(pg.screenshot()).decode(), "url": url}
        except Exception:
            pass
    return shots


def observe(base: str, *, headers: dict = None, seed_paths=None, timeout_ms: int = 25000,
            scope_ok=None) -> dict:
    """Browser-as-sensor with the raw-CDP wire view: boot the app for real (optionally authenticated) and
    return every request it makes, plus the runtime observations for the planner. Read-only."""
    usable, note = available()
    if not usable:
        return _empty(base, note)
    base = (base or "").rstrip("/")
    ok = scope_ok or (lambda _u: True)
    if not base or not ok(base):
        return _empty(base, "no in-scope base url")
    from playwright.sync_api import sync_playwright
    wire = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
            try:
                ctx, page, _c, seeded = _new_persona(browser, base, headers or {},
                                                     timeout_ms=timeout_ms, wire=wire)
                for path in (seed_paths or [])[:6]:
                    u = path if "://" in str(path) else base + str(path)
                    if not ok(u):
                        continue
                    _goto_awaiting_object(page, u, timeout_ms)
                try:
                    storage = page.evaluate("() => Object.keys(localStorage || {})")
                except Exception:
                    storage = []
                try:
                    ctx.close()
                except Exception:
                    pass
            finally:
                try:
                    browser.close()
                except Exception:
                    pass
    except Exception as e:
        return _empty(base, "browser runtime unavailable: %s" % str(e)[:120])
    urls = sorted({w["url"] for w in wire if w.get("url")})
    res = {"base": base, "browser": True, "ran": True, "note": "", "requests": urls, "wire": wire[:400],
           "storage_keys": list(storage or []), "has_auth_material": bool(headers),
           "candidates": [], "probes": [], "findings": [], "exchanges": [],
           "counts": {"requests": len(urls), "object_urls": sum(1 for u in urls if object_template(u)[0])}}
    res["observations"] = sorted(to_observations(res))
    return res
