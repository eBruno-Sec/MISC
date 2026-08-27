"""
Transport + web posture engines (#103, distilled from WAHH ch.12/13 and the transport-posture family).

The classes here are not "scanner nags". Each one is a property that is DIRECTLY OBSERVABLE at the wire
and has a crisp, deterministic oracle, which is what separates a posture finding worth reporting from a
checklist item:

  tls_posture             a deprecated protocol version is SUPPORTED only if a handshake pinned to that
                          version actually COMPLETES. Not inferred from a banner, not guessed from a
                          cipher list -- negotiated or not.
  cookie_scope_posture    a session cookie either carries Secure/HttpOnly/SameSite or it does not. The
                          Set-Cookie header is the evidence; there is nothing to infer.
  http_security_headers   a protective header is present or absent in the response. Graded honestly:
                          missing HSTS on HTTPS is a real transport weakness; a missing Permissions-Policy
                          is hygiene, and is reported as such rather than inflated.
  http_methods_audit      TRACE is confirmed only when the response ECHOES the exact marker we sent
                          (Cross-Site Tracing). Dangerous write methods are read from the Allow header --
                          Apolaki never sends a PUT or DELETE to find out.

Everything in the pure layer is offline and testable. The live layer opens read-only TLS handshakes and
sends safe methods only. No DoS: a handful of connections per host, no retries in a loop.
"""
from __future__ import annotations

import datetime
import re

# Protocol versions that are deprecated for any modern deployment (RFC 8996 deprecates TLS 1.0/1.1).
_DEPRECATED_PROTOCOLS = ("SSLv3", "TLSv1", "TLSv1.1")
_MODERN_PROTOCOLS = ("TLSv1.2", "TLSv1.3")

# Cipher properties that are broken regardless of protocol version.
_WEAK_CIPHER_TOKENS = ("NULL", "EXPORT", "ANON", "ADH", "AECDH", "RC4", "DES-CBC3", "3DES", "DES",
                       "MD5", "IDEA", "SEED", "CAMELLIA128", "RC2")

# Cookie names that indicate a SESSION credential rather than a preference. Attribute gaps only matter
# on these -- flagging `theme=dark` for missing HttpOnly is noise.
_SESSION_COOKIE_HINTS = ("sess", "session", "sid", "auth", "token", "jwt", "login", "remember",
                         "csrf", "xsrf", "phpsessid", "jsessionid", "asp.net_sessionid", "connect.sid")

# Q-101. A key size means nothing without the ALGORITHM it belongs to. 256 bits is catastrophic for
# RSA and entirely healthy for an elliptic curve -- ECDSA P-256 is roughly RSA-3072 equivalent, and it
# is what most of the modern web serves. The old single `_MIN_RSA_BITS = 2048`, applied to every key
# regardless of type, reported three HIGH "weak key" findings against live Shopify hosts fronted by
# Cloudflare on TLSv1.3. The constant was named for RSA and used for everything, so the name was the
# only thing carrying the discriminator and names do not run.
#
# UNKNOWN IS NOT WEAK. An algorithm this map has no entry for is left alone: a finding is a claim, and
# "I could not identify this key" is not evidence of anything. Adding a permissive default here would
# reintroduce the bug for the next algorithm nobody anticipated.
_MIN_KEY_BITS = {
    "rsa": 2048,
    "dsa": 2048,
    "dh": 2048,
    "ec": 256,          # P-256 and up; P-192 and below are genuinely weak and still caught
    "ed25519": 0,       # fixed-size modern curve -- a size comparison does not apply
    "ed448": 0,
}


# ─────────────────────────────────────────────────────────────── pure: certificates
def _parse_cert_time(s):
    """OpenSSL's 'Jun  1 12:00:00 2027 GMT' -> datetime (UTC). None when unparseable. Pure."""
    if not s:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            return datetime.datetime.strptime(str(s).strip(), fmt).replace(
                tzinfo=datetime.timezone.utc)
        except Exception:
            continue
    return None


def _rdn(seq) -> dict:
    """Python's nested RDN tuples -> a flat dict. Pure."""
    out = {}
    try:
        for rdn in (seq or ()):
            for k, v in rdn:
                out[str(k)] = str(v)
    except Exception:
        pass
    return out


def cert_names(cert: dict) -> list:
    """Every hostname the certificate is valid for (CN + subjectAltName DNS entries). Pure."""
    names = []
    try:
        cn = _rdn((cert or {}).get("subject")).get("commonName")
        if cn:
            names.append(cn)
        for typ, val in ((cert or {}).get("subjectAltName") or ()):
            if str(typ).lower() == "dns" and val:
                names.append(str(val))
    except Exception:
        pass
    return list(dict.fromkeys(names))


def hostname_matches(hostname: str, names) -> bool:
    """RFC 6125 style match including a single leftmost wildcard label. Pure."""
    h = str(hostname or "").lower().rstrip(".")
    for n in (names or []):
        n = str(n).lower().rstrip(".")
        if not n:
            continue
        if n == h:
            return True
        if n.startswith("*."):
            suffix = n[1:]                       # ".example.com"
            if h.endswith(suffix) and h[: -len(suffix)].count(".") == 0 and h != suffix.lstrip("."):
                return True
    return False


def analyze_certificate(cert: dict, hostname: str, *, now=None, key_bits: int = 0,
                        key_algo: str = "") -> list:
    """Certificate defects a client would actually reject or warn on. Pure; returns issue dicts.

    Q-101: `key_algo` is REQUIRED to judge `key_bits`. It defaults to "" rather than "rsa" so that a
    caller which has not been taught to pass it yet reports NOTHING about key size, instead of
    silently judging every curve against an RSA threshold -- which is the bug this parameter exists
    to close, and a falsy default that guesses would rebuild it."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    issues = []
    if not cert:
        return issues
    subject, issuer = _rdn(cert.get("subject")), _rdn(cert.get("issuer"))
    not_after = _parse_cert_time(cert.get("notAfter"))
    not_before = _parse_cert_time(cert.get("notBefore"))
    if not_after and not_after < now:
        issues.append({"id": "cert_expired", "severity": "high",
                       "detail": "the certificate expired on %s" % cert.get("notAfter")})
    elif not_after and (not_after - now).days <= 30:
        issues.append({"id": "cert_expiring", "severity": "low",
                       "detail": "the certificate expires in %d day(s), on %s"
                                 % ((not_after - now).days, cert.get("notAfter"))})
    if not_before and not_before > now:
        issues.append({"id": "cert_not_yet_valid", "severity": "medium",
                       "detail": "the certificate is not valid until %s" % cert.get("notBefore")})
    if subject and issuer and subject == issuer:
        issues.append({"id": "cert_self_signed", "severity": "medium",
                       "detail": "the certificate is self-signed (subject equals issuer), so it proves "
                                 "no identity to a client"})
    names = cert_names(cert)
    if hostname and names and not hostname_matches(hostname, names):
        issues.append({"id": "cert_hostname_mismatch", "severity": "high",
                       "detail": "the certificate is valid for %s, not for %s"
                                 % (", ".join(names[:5]), hostname)})
    minimum = _MIN_KEY_BITS.get((key_algo or "").lower())
    if key_bits and minimum and key_bits < minimum:
        # The algorithm is NAMED in the detail. A reader who disagrees with the threshold can see
        # which one was applied, instead of having to guess that "256 bits" was measured against RSA.
        issues.append({"id": "cert_weak_key", "severity": "high",
                       "detail": "the %s public key is %d bits, below the %d-bit minimum for %s"
                                 % (key_algo.upper(), key_bits, minimum, key_algo.upper())})
    return issues


# ─────────────────────────────────────────────────────────────── pure: protocols + ciphers
def weak_cipher(cipher_name: str) -> str:
    """The broken property in a negotiated cipher suite, or "". Pure."""
    n = str(cipher_name or "").upper()
    for tok in _WEAK_CIPHER_TOKENS:
        if tok in n:
            return tok
    return ""


def analyze_protocols(supported: dict) -> dict:
    """Grade the handshake results. `supported` maps a protocol name -> bool (a handshake pinned to that
    version completed) or None (could not be tested from this client). Pure.

    Honest about its own blind spot: a version the local OpenSSL refuses to speak is `None`, which is
    'unknown', never 'not supported'."""
    sup = supported or {}
    deprecated = [p for p in _DEPRECATED_PROTOCOLS if sup.get(p) is True]
    untestable = [p for p in _DEPRECATED_PROTOCOLS if sup.get(p) is None]
    modern = [p for p in _MODERN_PROTOCOLS if sup.get(p) is True]
    # A server that appears to accept EVERY pinned version, including ones it should not, means the probe
    # is not discriminating -- refuse to report rather than emit nonsense.
    tested = [p for p in sup if sup.get(p) is not None]
    trustworthy = not (tested and all(sup.get(p) for p in tested) and len(tested) >= 4)
    return {"deprecated_supported": deprecated, "modern_supported": modern,
            "untestable": untestable, "discriminating": trustworthy,
            "no_modern_support": bool(tested) and not modern}


# ─────────────────────────────────────────────────────────────── pure: cookies
def parse_set_cookie(header_value: str) -> dict:
    """One Set-Cookie header -> {name, value_len, secure, httponly, samesite, domain, path}. Pure."""
    parts = [p.strip() for p in str(header_value or "").split(";") if p.strip()]
    if not parts:
        return {}
    name, _, val = parts[0].partition("=")
    out = {"name": name.strip(), "value_len": len(val), "secure": False, "httponly": False,
           "samesite": "", "domain": "", "path": ""}
    for p in parts[1:]:
        k, _, v = p.partition("=")
        k = k.strip().lower()
        if k == "secure":
            out["secure"] = True
        elif k == "httponly":
            out["httponly"] = True
        elif k == "samesite":
            out["samesite"] = v.strip().lower()
        elif k in ("domain", "path"):
            out[k] = v.strip()
    return out


def is_session_cookie(name: str) -> bool:
    n = str(name or "").lower()
    return any(h in n for h in _SESSION_COOKIE_HINTS)


def _registrable_suffix(host: str) -> str:
    """The last two labels of a host — a crude eTLD+1 that is deliberately conservative. Pure."""
    parts = [p for p in str(host or "").lower().strip(".").split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else ""


def analyze_cookie_scope(set_cookie_headers, *, host: str = "") -> list:
    """How WIDELY a session cookie is scoped — a different question from which attributes it carries.

    *Web Browser Engineering §10.5* makes the incongruity explicit: the same-origin policy compares scheme,
    host and port, while cookies *"don't care about scheme or port… an oversight or incongruity left over
    from the messy early web."* So a cookie is reachable from places SOP would treat as separate origins,
    and the only lever an application has over that is Domain, Path and Secure.

    Reports breadth, not attributes (`analyze_cookies` owns those). Pure."""
    issues = []
    reg = _registrable_suffix(host)
    for raw in (set_cookie_headers or []):
        c = parse_set_cookie(raw)
        if not c or not c.get("name") or not is_session_cookie(c["name"]):
            continue
        dom = (c.get("domain") or "").lstrip(".").lower()
        if dom and host and dom != str(host).lower():
            sev = "medium"
            detail = ("session cookie '%s' is scoped to Domain=%s rather than the issuing host %s, so it "
                      "is sent to every subdomain of %s — one weak or attacker-controlled subdomain is "
                      "enough to receive it" % (c["name"], dom, host, dom))
            if reg and dom == reg:
                sev = "high"
                detail += "; that is the registrable domain, the widest scope available"
            issues.append({"id": "cookie_domain_too_broad", "severity": sev, "cookie": c["name"],
                           "detail": detail})
        if not c.get("secure"):
            issues.append({"id": "cookie_reachable_over_plaintext", "severity": "medium",
                           "cookie": c["name"],
                           "detail": ("session cookie '%s' has no Secure attribute, and cookies ignore "
                                      "scheme, so the browser will attach it to a plaintext http:// "
                                      "request to the same host even when the site is served over HTTPS"
                                      % c["name"])})
        path = c.get("path") or "/"
        if path == "/" and dom:
            issues.append({"id": "cookie_scope_widest", "severity": "low", "cookie": c["name"],
                           "detail": ("session cookie '%s' combines Domain=%s with Path=/, the broadest "
                                      "reach a cookie can have" % (c["name"], dom))})
    return issues


def analyze_cookies(set_cookie_headers, *, is_https: bool) -> list:
    """Attribute gaps on SESSION cookies only. Pure. Directly observable — no inference, so no FPs."""
    issues = []
    for raw in (set_cookie_headers or []):
        c = parse_set_cookie(raw)
        if not c or not c.get("name") or not is_session_cookie(c["name"]):
            continue
        miss = []
        if is_https and not c["secure"]:
            miss.append(("secure", "high", "it can be sent over plaintext HTTP and captured in transit"))
        if not c["httponly"]:
            miss.append(("httponly", "medium", "script in the page can read it, so any XSS becomes "
                                               "session theft"))
        if not c["samesite"] or c["samesite"] == "none":
            miss.append(("samesite", "low" if not c["samesite"] else "medium",
                         "it is attached to cross-site requests, enabling CSRF against this session"))
        for attr, sev, why in miss:
            issues.append({"id": "cookie_missing_" + attr, "severity": sev, "cookie": c["name"],
                           "detail": "session cookie '%s' does not set %s: %s"
                                     % (c["name"], attr.capitalize(), why)})
    return issues


# ─────────────────────────────────────────────────────────────── pure: protective headers
# header -> (severity when absent, why it matters). Graded honestly: transport + framing defects are real
# findings; the rest is hygiene and is reported at info so a report is not padded with severity.
_HEADER_RULES = {
    "strict-transport-security": ("medium", "without HSTS a browser will still make the first request "
                                            "over plaintext HTTP, which is where session cookies leak"),
    "x-content-type-options": ("info", "browsers may MIME-sniff a response into a different type"),
    "referrer-policy": ("info", "full URLs (including tokens in query strings) leak to third parties"),
    "permissions-policy": ("info", "powerful browser features are not explicitly restricted"),
}


def analyze_security_headers(headers: dict, *, is_https: bool) -> list:
    """Missing protective headers, honestly graded. Pure."""
    low = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    issues = []
    csp = low.get("content-security-policy", "")
    xfo = low.get("x-frame-options", "")
    # clickjacking: EITHER control is sufficient, so only flag when BOTH are absent
    if not xfo and "frame-ancestors" not in csp.lower():
        issues.append({"id": "header_missing_framing_control", "severity": "medium",
                       "detail": "neither X-Frame-Options nor a CSP frame-ancestors directive is set, so "
                                 "the page can be framed by any origin (clickjacking)"})
    if not csp:
        issues.append({"id": "header_missing_csp", "severity": "low",
                       "detail": "no Content-Security-Policy, so an injected script has no second line "
                                 "of defence"})
    for h, (sev, why) in _HEADER_RULES.items():
        if h == "strict-transport-security" and not is_https:
            continue                       # HSTS is meaningless on a plaintext origin
        if h not in low:
            issues.append({"id": "header_missing_" + h.replace("-", "_"), "severity": sev,
                           "detail": "no %s: %s" % (h, why)})
    return issues


# ─────────────────────────────────────────────────────────────── pure: HTTP methods
_DANGEROUS_METHODS = ("PUT", "DELETE", "PATCH", "TRACE", "TRACK", "CONNECT",
                      "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK")


def analyze_methods(allow_header: str, *, trace_status: int = 0, trace_body: str = "",
                    trace_marker: str = "") -> list:
    """Advertised dangerous methods, plus a CONFIRMED Cross-Site Tracing check. Pure.

    The distinction is deliberate: `Allow` is what the server CLAIMS, so it is a lead. TRACE echoing the
    exact marker we sent is proof, because nothing else produces that string."""
    issues = []
    advertised = [m.strip().upper() for m in str(allow_header or "").split(",") if m.strip()]
    risky = [m for m in advertised if m in _DANGEROUS_METHODS]
    if risky:
        issues.append({"id": "methods_dangerous_advertised", "severity": "low", "confidence": "lead",
                       "detail": "the server advertises %s in its Allow header; whether they are actually "
                                 "permitted was NOT tested (Apolaki does not send write methods to find out)"
                                 % ", ".join(sorted(set(risky)))})
    if trace_marker and int(trace_status or 0) == 200 and trace_marker in str(trace_body or ""):
        issues.append({"id": "methods_trace_enabled", "severity": "medium", "confidence": "confirmed",
                       "detail": "TRACE is enabled and echoed the exact marker sent (Cross-Site Tracing): "
                                 "the response reflects request headers back to the client"})
    return issues


# ─────────────────────────────────────────────────────────────── pure: findings
_FINDING_META = {
    "cert_expired": ("CWE-295", "Expired TLS certificate", "high"),
    "cert_expiring": ("CWE-295", "TLS certificate expiring soon", "low"),
    "cert_not_yet_valid": ("CWE-295", "TLS certificate not yet valid", "medium"),
    "cert_self_signed": ("CWE-295", "Self-signed TLS certificate", "medium"),
    "cert_hostname_mismatch": ("CWE-297", "TLS certificate does not match the hostname", "high"),
    "cert_weak_key": ("CWE-326", "Weak TLS certificate key", "high"),
    "tls_deprecated_protocol": ("CWE-327", "Deprecated TLS protocol accepted", "medium"),
    "tls_weak_cipher": ("CWE-327", "Weak TLS cipher negotiated", "medium"),
    "tls_no_modern_protocol": ("CWE-326", "No modern TLS version supported", "high"),
    "cookie_missing_secure": ("CWE-614", "Session cookie without the Secure attribute", "high"),
    "cookie_missing_httponly": ("CWE-1004", "Session cookie without HttpOnly", "medium"),
    "cookie_missing_samesite": ("CWE-1275", "Session cookie without a restrictive SameSite", "low"),
    "cookie_domain_too_broad": ("CWE-565", "Session cookie scoped to a broader domain than its issuer", "medium"),
    "cookie_reachable_over_plaintext": ("CWE-614", "Session cookie reachable over plaintext (cookies ignore scheme)", "medium"),
    "cookie_scope_widest": ("CWE-565", "Session cookie at the broadest possible scope", "low"),
    "header_missing_framing_control": ("CWE-1021", "Page can be framed by any origin", "medium"),
    "header_missing_csp": ("CWE-693", "No Content-Security-Policy", "low"),
    "header_missing_strict_transport_security": ("CWE-319", "HSTS not enabled on an HTTPS origin", "medium"),
    "header_missing_x_content_type_options": ("CWE-693", "MIME sniffing not disabled", "info"),
    "header_missing_referrer_policy": ("CWE-200", "No Referrer-Policy", "info"),
    "header_missing_permissions_policy": ("CWE-693", "No Permissions-Policy", "info"),
    "methods_dangerous_advertised": ("CWE-650", "Server advertises dangerous HTTP methods", "low"),
    "methods_trace_enabled": ("CWE-693", "HTTP TRACE enabled (Cross-Site Tracing)", "medium"),
}

_REMEDIATION = {
    "tls_deprecated_protocol": "Disable SSLv3/TLS 1.0/1.1 and serve TLS 1.2 as the minimum (RFC 8996).",
    "tls_weak_cipher": "Remove NULL/EXPORT/anonymous/RC4/3DES/MD5 suites; prefer AEAD suites.",
    "tls_no_modern_protocol": "Enable TLS 1.2 and 1.3.",
    "cookie_missing_secure": "Set the Secure attribute on every session cookie.",
    "cookie_missing_httponly": "Set HttpOnly so page script cannot read the session cookie.",
    "cookie_missing_samesite": "Set SameSite=Lax (or Strict) on session cookies.",
    "header_missing_framing_control": "Send X-Frame-Options: DENY, or CSP frame-ancestors 'none'.",
    "header_missing_strict_transport_security": "Send Strict-Transport-Security with a long max-age.",
    "methods_trace_enabled": "Disable the TRACE and TRACK methods at the web server.",
}

# How each class was observed — used to make the evidence string replayable.
_PROBE_VERB = {"tls": "TLS handshake to", "cert": "TLS handshake to", "cookie": "GET",
               "header": "GET", "methods": "OPTIONS/TRACE"}

_ORACLES = {
    "tls": "a protocol version is reported as supported only when a handshake PINNED to that version "
           "actually completed against the live host; an untestable version is reported as unknown",
    "cert": "the certificate presented by the live host, parsed and checked against the hostname "
            "requested and the current time",
    "cookie": "the Set-Cookie header the server sent, read directly — the attribute is present or it "
              "is not",
    "header": "the response headers the server sent, read directly",
    "methods": "TRACE is confirmed only when the response echoes the exact random marker sent in the "
               "request; advertised methods are reported as an untested lead",
}


def finding(issue: dict, target: str, *, kind: str, evidence: str = "") -> dict:
    """Shape one posture issue as a finding. Pure."""
    iid = issue.get("id", "")
    cwe, title, default_sev = _FINDING_META.get(iid, ("CWE-693", iid.replace("_", " ").title(), "info"))
    sev = issue.get("severity") or default_sev
    conf = issue.get("confidence") or "confirmed"
    # Evidence must be REPLAYABLE, not a sentence: state the observation against the concrete target so a
    # reviewer can re-derive it. (The platform's proof_schema enforces exactly this, and rightly rejected
    # the prose-only first version.)
    #
    # That composition used to apply ONLY when no explicit evidence was passed, so the two callers that DO
    # pass it -- tls_deprecated_protocol ("handshake pinned to TLSv1 completed") and tls_weak_cipher
    # ("negotiated cipher: ...") -- shipped a bare fragment carrying no verb, no target and no arrow.
    # MEASURED at clean HEAD, both then FAILED proof_schema.validate_confirmed with
    # ['reproduction_or_request_response', 'evidence_signal:->'] while claiming confidence "confirmed":
    # a confirmed finding failing its own proof contract. The observation is unchanged and no less
    # specific -- it is now stated against the target it was made on, which is what makes it replayable.
    ev = evidence or issue.get("evidence") or issue.get("detail", "")
    ev = "%s %s -> %s" % (_PROBE_VERB.get(kind, "GET"), target, ev)
    return {
        "title": title + " — " + target,
        "severity": sev,
        "confidence": conf,
        "family": "transport_posture" if kind in ("tls", "cert") else "security_misconfig",
        "cwe": cwe,
        "owasp": "A02:2021" if kind in ("tls", "cert") else "A05:2021",
        "target": target,
        "tags": ["posture", kind, iid],
        "description": issue.get("detail", ""),
        "impact": issue.get("impact") or _impact_for(iid, target),
        "oracle": _ORACLES.get(kind, ""),
        "evidence": ev,
        "remediation": _REMEDIATION.get(iid, "Apply the platform's hardening guidance for this control."),
        "found_by": "transport_posture",
    }


def _impact_for(iid: str, target: str) -> str:
    if iid.startswith("cert_") or iid.startswith("tls_"):
        return ("Traffic to %s can be downgraded, decrypted or impersonated by an attacker positioned on "
                "the network path, exposing session credentials and any data in transit." % target)
    if iid.startswith("cookie_"):
        return ("The session cookie for %s is reachable in a way it should not be, turning a network "
                "position or a script injection into full account takeover." % target)
    if iid == "methods_trace_enabled":
        return ("Request headers, including cookies sent by a victim's browser, are reflected back and "
                "can be read by an attacker who can make the victim issue the request.")
    return ("A defence-in-depth control is absent on %s, so another defect in the application has one "
            "fewer barrier to exploitation." % target)


def findings_for(target: str, *, protocols=None, cipher: str = "", cert: dict = None, hostname: str = "",
                 key_bits: int = 0, key_algo: str = "", set_cookies=None, headers: dict = None, is_https: bool = False,
                 allow_header: str = "", trace_status: int = 0, trace_body: str = "",
                 trace_marker: str = "", http_observed: bool = True, now=None) -> list:
    """Every posture finding for one target, from already-collected observations. Pure.

    Q-097: `http_observed` is the caller stating whether an HTTP response was ACTUALLY RECEIVED.
    `headers={}` means "a response arrived and carried no protective headers" and must still be
    reported; `http_observed=False` means no response arrived at all, and an absence cannot be
    observed in something that never existed. Those two were the same value here, which is how a
    field mission emitted 18 missing-header findings against a host it never reached. Defaults True
    so every existing caller keeps its meaning; only a caller that KNOWS its request died says False.
    """
    out = []
    pg = analyze_protocols(protocols or {})
    if pg["discriminating"]:
        for p in pg["deprecated_supported"]:
            out.append(finding({"id": "tls_deprecated_protocol", "severity": "medium",
                                "detail": "the host completed a handshake pinned to %s, a protocol "
                                          "deprecated by RFC 8996" % p}, target, kind="tls",
                               evidence="handshake pinned to %s completed" % p))
        if pg["no_modern_support"]:
            out.append(finding({"id": "tls_no_modern_protocol", "severity": "high",
                                "detail": "no handshake succeeded at TLS 1.2 or 1.3"}, target, kind="tls"))
    wc = weak_cipher(cipher)
    if wc:
        out.append(finding({"id": "tls_weak_cipher", "severity": "medium",
                            "detail": "the negotiated cipher suite %s uses %s" % (cipher, wc)},
                           target, kind="tls", evidence="negotiated cipher: %s" % cipher))
    for iss in analyze_certificate(cert or {}, hostname, now=now, key_bits=key_bits, key_algo=key_algo):
        out.append(finding(iss, target, kind="cert"))
    # Everything below this line is read off ONE HTTP response. With no response there is no
    # observation to grade, and `analyze_security_headers({})` would otherwise report all six
    # protective headers absent from a socket that never opened.
    if http_observed:
        for iss in analyze_cookies(set_cookies or [], is_https=is_https):
            out.append(finding(iss, target, kind="cookie"))
        for iss in analyze_cookie_scope(set_cookies or [], host=hostname):
            out.append(finding(iss, target, kind="cookie"))
        for iss in analyze_security_headers(headers or {}, is_https=is_https):
            out.append(finding(iss, target, kind="header"))
    for iss in analyze_methods(allow_header, trace_status=trace_status, trace_body=trace_body,
                               trace_marker=trace_marker):
        out.append(finding(iss, target, kind="methods"))
    return out


# ─────────────────────────────────────────────────────────────── live: TLS handshakes
_PIN = {"SSLv3": "SSLv3", "TLSv1": "TLSv1", "TLSv1.1": "TLSv1_1", "TLSv1.2": "TLSv1_2",
        "TLSv1.3": "TLSv1_3"}


def _ctx_for(version: str):
    """A client context pinned to exactly one protocol version, with the OpenSSL security level lowered
    so a LEGACY handshake is actually attempted rather than refused locally (refusing locally would make
    an insecure server look secure). Returns None when this OpenSSL cannot speak that version at all."""
    import ssl
    name = _PIN.get(version)
    if not name or not hasattr(ssl.TLSVersion, name):
        return None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        v = getattr(ssl.TLSVersion, name)
        ctx.minimum_version = v
        ctx.maximum_version = v
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except Exception:
            pass
        return ctx
    except Exception:
        return None


def probe_tls(host: str, port: int = 443, timeout: float = 6.0) -> dict:
    """Read-only TLS introspection: which pinned protocol versions complete a handshake, what gets
    negotiated by default, and the certificate presented. One short connection per version — never a
    loop, never a retry storm. Never raises."""
    import socket
    import ssl
    out = {"host": host, "port": int(port), "reachable": False, "protocols": {}, "cipher": "",
           "protocol": "", "cert": {}, "key_bits": 0, "key_algo": "", "note": ""}
    if not host:
        return {**out, "note": "no host"}
    # default negotiation first: what a normal client actually gets
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                out["reachable"] = True
                out["protocol"] = ss.version() or ""
                out["cipher"] = (ss.cipher() or ("", "", 0))[0]
                try:
                    out["cert"] = ss.getpeercert() or {}
                except Exception:
                    out["cert"] = {}
                try:
                    der = ss.getpeercert(binary_form=True)
                    out["key_bits"], out["key_algo"] = _key_bits(der)
                    if not out["cert"]:      # CERT_NONE leaves the parsed dict empty — parse the DER
                        out["cert"] = cert_from_der(der)
                except Exception:
                    pass
    except Exception as e:
        return {**out, "note": "TLS not available on %s:%s (%s)" % (host, port, str(e)[:80])}
    # then each version, pinned
    for ver in ("SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"):
        c = _ctx_for(ver)
        if c is None:
            out["protocols"][ver] = None          # this client cannot test it -> unknown, not "absent"
            continue
        try:
            with socket.create_connection((host, int(port)), timeout=timeout) as sock:
                with c.wrap_socket(sock, server_hostname=host) as ss:
                    out["protocols"][ver] = bool(ss.version())
        except Exception:
            out["protocols"][ver] = False
    return out


def cert_from_der(der_bytes) -> dict:
    """Parse a DER certificate into the same shape ssl.getpeercert() produces.

    Necessary, not merely convenient: the probe must use verify_mode=CERT_NONE, because refusing the
    handshake on a bad certificate would make it impossible to REPORT the bad certificate. Under
    CERT_NONE, Python returns an empty dict from getpeercert(), so without this the engine would silently
    find no certificate defects at all — which is exactly what the first live run against a known-bad
    server showed. Best-effort; returns {} when the parser is unavailable."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID, ExtensionOID
    except Exception:
        return {}
    try:
        c = x509.load_der_x509_certificate(der_bytes)
    except Exception:
        return {}

    def _name(n):
        out = []
        for attr in n:
            try:
                key = {NameOID.COMMON_NAME: "commonName",
                       NameOID.ORGANIZATION_NAME: "organizationName",
                       NameOID.COUNTRY_NAME: "countryName"}.get(attr.oid, attr.oid._name)
                out.append(((str(key), str(attr.value)),))
            except Exception:
                continue
        return tuple(out)

    sans = []
    try:
        ext = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = [("DNS", d) for d in ext.value.get_values_for_type(x509.DNSName)]
    except Exception:
        pass
    fmt = "%b %d %H:%M:%S %Y GMT"
    try:
        na = c.not_valid_after_utc.strftime(fmt)
        nb = c.not_valid_before_utc.strftime(fmt)
    except Exception:
        na = c.not_valid_after.strftime(fmt)
        nb = c.not_valid_before.strftime(fmt)
    return {"subject": _name(c.subject), "issuer": _name(c.issuer),
            "notAfter": na, "notBefore": nb, "subjectAltName": tuple(sans)}


def _key_bits(der_bytes):
    r"""`(size, algorithm)` for a DER certificate, best-effort without a crypto dependency.

    Q-101: this function ALREADY branched on RSA vs EC and then returned a bare int, so the caller
    compared an elliptic-curve size against an RSA threshold and called a healthy P-256 certificate a
    HIGH weak key. The discriminator was measured here and dropped on the way out -- the same defect
    as `_cmd` discarding `proc.returncode` and `_http` discarding `status`. It is returned now.

    `("", 0)` on any failure, and an unrecognised key type yields its size with an EMPTY algorithm,
    which the threshold map deliberately has no entry for. Unknown is not weak."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        c = x509.load_der_x509_certificate(der_bytes)
        k = c.public_key()
        if isinstance(k, rsa.RSAPublicKey):
            return k.key_size, "rsa"
        if isinstance(k, ec.EllipticCurvePublicKey):
            return k.curve.key_size, "ec"
        name = type(k).__name__.lower()
        for algo in ("ed25519", "ed448", "dsa", "dh"):
            if algo in name:
                return getattr(k, "key_size", 0) or 0, algo
        return (getattr(k, "key_size", 0) or 0), ""
    except Exception:
        return 0, ""


def trace_marker() -> str:
    """A random marker that can only appear in a response by being echoed. Pure-ish (random)."""
    import uuid
    return "Apolaki-Trace-" + uuid.uuid4().hex[:16]
