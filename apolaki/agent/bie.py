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


def object_candidates(owner_urls, attacker_urls, max_n: int = 4) -> list:
    """Runtime-observed cross-user hypotheses: URLs the OWNER's browser actually requested that share a
    path template with something the ATTACKER's browser requested, but with a DIFFERENT id. That pairing
    is what makes the swap meaningful (both personas legitimately use the endpoint; only the id differs),
    and it is derived from observation -- not from spraying ids. Pure.

    Returns [{template, owner_url, owner_id, attacker_url, attacker_id}] ordered by observation order."""
    atk = {}
    for u in (attacker_urls or []):
        t, i = object_template(u)
        if t:
            atk.setdefault(t, (u, i))
    out, seen = [], set()
    for u in (owner_urls or []):
        t, i = object_template(u)
        if not t or t in seen or t not in atk:
            continue
        au, ai = atk[t]
        if str(ai) == str(i):
            continue                      # same object -> nothing to prove
        seen.add(t)
        out.append({"template": t, "owner_url": u, "owner_id": i,
                    "attacker_url": au, "attacker_id": ai})
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
    missing = [n for n, c in (("anonymous", anon), ("implausible-id", nonexistent)) if c is None]
    if missing:
        return {"verdict": "lead", "reason": "cross-user read observed but the %s negative control did not "
                                             "run -- not provable" % " and ".join(missing)}
    if _s(anon) == 200 and _b(anon) == base_b:
        return {"verdict": "rejected", "reason": "the resource is PUBLIC -- an unauthenticated request "
                                                 "returns the identical body, so no authorization was bypassed"}
    if _s(nonexistent) == 200 and _b(nonexistent) == base_b:
        return {"verdict": "rejected", "reason": "the route is not object-specific -- an implausible id "
                                                 "returns the identical body (SPA shell / catch-all)"}
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
        % (swap_url(cand.get("owner_url", ""), _IMPLAUSIBLE_ID) or ""),
    ])


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
        if anon is not None and _s(anon) == 200 and _b(anon) == _b(other_baseline):
            return {"verdict": "rejected", "reason": "the content is PUBLIC — anonymous receives it too"}
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
    if shell is None:
        return {"verdict": "lead", "reason": "server served the withheld control but the SPA-shell control "
                                             "did not run -- not provable"}
    if _b(shell) == _b(persona):
        return {"verdict": "rejected", "reason": "the response is the application shell (an unknown path "
                                                 "returns the same body) -- nothing privileged was served"}
    if anon is not None and _s(anon) == 200 and _b(anon) == _b(persona):
        return {"verdict": "rejected", "reason": "the resource is PUBLIC -- anonymous receives the same "
                                                 "body, so no authorization boundary exists"}
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


def _goto_awaiting_object(page, url: str, timeout_ms: int) -> str:
    """Navigate and wait for the app's OWN object request, registering the expectation BEFORE the
    navigation so a fast response cannot be missed. Deterministic; never raises."""
    try:
        with page.expect_response(lambda r: bool(object_template(r.url)[0]), timeout=timeout_ms):
            page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        return settle(page, timeout_ms) + "+object-response"
    except Exception:
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        except Exception:
            return "navigation-failed"
        return settle(page, timeout_ms)


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
    except Exception:
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
        page.goto(base, wait_until="domcontentloaded", timeout=timeout_ms)
    except Exception:
        pass
    seeded = _seed_auth(page, headers, storage)
    try:                                    # reload so the SPA boots WITH the persona's session
        page.goto(base, wait_until="domcontentloaded", timeout=timeout_ms)
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
        page.goto(nav, wait_until="domcontentloaded", timeout=timeout_ms)
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


def _read_controls(page) -> list:
    """Enumerate the rendered control surface of whatever page the persona is currently on. Never raises."""
    try:
        return list(page.evaluate(CONTROL_SURFACE_JS) or [])
    except Exception:
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

                obs_start = (len(o_wire), len(a_wire))
                # The control surface must be read while the personas are still ON the application's own
                # pages — a later navigation to a raw API URL would present an empty DOM and silently
                # report "no controls". Accumulate across every rendered route.
                raw_controls, app_page_url = _read_controls(a_page), base
                for path in (seed_paths or [])[:6]:      # let each app render the pages that fetch objects
                    u = path if "://" in str(path) else base + str(path)
                    if not ok(u):
                        continue
                    for pg in (o_page, a_page):
                        out.setdefault("settle", []).append(
                            {"url": u, "reason": _goto_awaiting_object(pg, u, timeout_ms)})
                    raw_controls += _read_controls(a_page)
                    app_page_url = u                     # the last APP page that actually drove requests
                # OBSERVED cross-user hypotheses: the object URLs each persona's OWN browser requested.
                owner_urls = [w["url"] for w in o_wire[obs_start[0]:] if w.get("url")]
                attacker_urls = [w["url"] for w in a_wire[obs_start[1]:] if w.get("url")]
                owner_urls += [str(u) for u in (extra_owner_urls or [])]
                cands = object_candidates(owner_urls, attacker_urls, max_n=max_candidates)
                # When both personas hit the SAME ids (shared/public data), fall back to the explicit
                # owner objects the caller supplies -- the artery knows which ids the owner owns.
                if not cands:
                    for u in (extra_owner_urls or [])[:max_candidates]:
                        t, i = object_template(str(u))
                        if t and ok(str(u)):
                            cands.append({"template": t, "owner_url": str(u), "owner_id": i,
                                          "attacker_url": None, "attacker_id": None})
                out["candidates"] = cands

                for cand in cands:
                    ourl = cand["owner_url"]
                    if not ok(ourl):
                        continue
                    nonexistent_url = swap_url(ourl, _IMPLAUSIBLE_ID)
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
                        out["findings"].append(finding(cand, probes, verdict, owner=owner,
                                                       attacker=attacker, screenshots=shots))
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
            pg.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
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
