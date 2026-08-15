"""Cross-Site WebSocket Hijacking -- CWE-1385 / CWE-346, WSTG-CLNT-10.

A WebSocket handshake is an ordinary HTTP/1.1 request, so the browser attaches the target's cookies
to it -- and the same-origin policy does NOT apply. If the server upgrades the connection without
checking `Origin`, any page the victim visits can open an authenticated socket to the application
and read whatever that socket pushes. That is the whole bug: CSRF with a full-duplex channel on the
end of it.

WHAT THIS MODULE REFUSES TO CALL A FINDING, and why each guard exists:

  * **A 101 is not the vulnerability.** Plenty of servers complete the upgrade and then reject at
    the application layer, and plenty of sockets carry nothing but public data. Reporting the
    upgrade alone would flag every socket.io deployment in existence. So `evaluate` demands the
    handshake AND an authenticated marker in the pushed frame.

  * **A 101 is not even proof of an upgrade.** The status line is trivially forged by a proxy, a
    captive portal or a catch-all route. RFC 6455 makes the server prove it understood the
    handshake: it must return base64(sha1(our key + the GUID)). `handshake_accepted` computes that
    from the key WE sent and compares. Checking for "101" alone was the shortcut this module was
    written not to take.

  * **The marker appearing without the cookie kills the finding.** If the cookie-stripped control
    receives the same marker, the socket is public and there is nothing to hijack. `evaluate`
    returns `clean` for that shape. Measured on OWASP Juice Shop, whose socket.io endpoint upgrades
    happily from `Origin: http://evil.example` and pushes an identical Engine.IO handshake frame
    with and without credentials -- a lead, never a confirm. See docs/handoff/realtime.md.

  * **A Bearer token is not a hijackable credential.** The attack works because the BROWSER attaches
    the cookie by itself. `Authorization` is set by JavaScript, and attacker-origin JavaScript
    cannot set it for another origin, so a token-only session is not exploitable cross-site however
    permissive the handshake is. `evaluate` caps a cookie-less session at a lead.

  * **The marker is an OBSERVED identity, never an invented string.** Same rule as
    `session_lifecycle_tool.build_discriminator`. A made-up marker cannot appear in either frame, so
    the engine would report clean on a vulnerable endpoint and never know.

Pure logic only -- byte assembly, byte parsing, and the verdict. The socket lives in
`tools.ToolRegistry._run_ws_hijack`, which is the only thing here that touches the network.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
from urllib.parse import urlparse, urlunparse

# RFC 6455 section 1.3. The server proves it spoke WebSocket by hashing our key with this.
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# The attacker origin we present. A constant so the evidence is reproducible by hand, and obviously
# foreign to any target -- a real deployment's allowlist can never legitimately contain it.
EVIL_ORIGIN = "http://apolaki-cswsh.invalid"

# Endpoint paths worth trying when the page advertises no explicit ws:// URL. Deliberately short:
# these are the framework defaults, not a fuzzing wordlist. Discovery from content is preferred.
COMMON_WS_PATHS = (
    "/socket.io/?EIO=4&transport=websocket",
    "/ws",
    "/websocket",
    "/wss",
    "/cable",
)

# ws:// or wss:// literals in HTML/JS. Bounded so a huge bundle cannot blow up the scan.
_WS_LITERAL = re.compile(r"""["'`](wss?://[^"'`\s\\]{3,300})["'`]""", re.I)
# `new WebSocket("/path")` / `new WebSocket('...')` with a relative or absolute-path argument.
_WS_RELATIVE = re.compile(r"""new\s+WebSocket\s*\(\s*["'`](/[^"'`\s\\]{0,300})["'`]""", re.I)


# -- RFC 6455 handshake -------------------------------------------------------------------------

def accept_for(key: str) -> str:
    """The `Sec-WebSocket-Accept` value RFC 6455 requires for `key`: base64(sha1(key + GUID)).

    Pure. Computed from the key WE sent, so a server that echoes a canned header, a proxy that
    fabricates a 101, or a replayed capture all fail the comparison in `handshake_accepted`.
    """
    return base64.b64encode(hashlib.sha1((str(key or "") + GUID).encode()).digest()).decode()


def new_key() -> str:
    """A fresh 16-byte base64 `Sec-WebSocket-Key` (RFC 6455 requires 16 random bytes).

    Random per handshake ON PURPOSE: it makes `accept_for` a real challenge-response. A fixed key
    would let a cached or replayed response satisfy the check forever.
    """
    return base64.b64encode(os.urandom(16)).decode()


def build_handshake(host: str, path: str, key: str, origin: str = EVIL_ORIGIN,
                    cookie: str = "", port: int = 0, extra_headers: dict = None) -> bytes:
    """The raw HTTP/1.1 Upgrade request bytes. Pure.

    `origin` and `cookie` are both meaningful when EMPTY -- an empty cookie is the negative control
    and an empty origin is a same-origin-ish request -- so neither gets an `or DEFAULT` fallback.
    An empty string omits the header entirely; that is the caller's explicit choice, not a default.
    """
    hostport = host if not port or port in (80, 443) else "%s:%d" % (host, port)
    lines = [
        "GET %s HTTP/1.1" % (path or "/"),
        "Host: %s" % hostport,
        "Upgrade: websocket",
        "Connection: Upgrade",
        "Sec-WebSocket-Key: %s" % (key or ""),
        "Sec-WebSocket-Version: 13",
    ]
    if origin:
        lines.append("Origin: %s" % origin)
    if cookie:
        lines.append("Cookie: %s" % cookie)
    for k, v in (extra_headers or {}).items():
        if k and v:
            lines.append("%s: %s" % (k, v))
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace")


def parse_handshake(raw) -> dict:
    """Split a raw response head into {status, headers, accept, upgrade}. Pure.

    Header names are lower-cased; values keep their case. A malformed or empty head yields
    status 0 and empty fields rather than raising -- the caller decides what that means.
    """
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode("latin-1", "replace")
    text = str(raw or "")
    head = text.split("\r\n\r\n", 1)[0].split("\n\n", 1)[0]
    lines = [ln for ln in head.replace("\r\n", "\n").split("\n") if ln.strip()]
    status = 0
    if lines:
        parts = lines[0].split()
        if len(parts) >= 2 and parts[0].upper().startswith("HTTP/"):
            try:
                status = int(parts[1])
            except ValueError:
                status = 0
    headers = {}
    for ln in lines[1:]:
        if ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        headers[k.strip().lower()] = v.strip()
    return {"status": status, "headers": headers,
            "accept": headers.get("sec-websocket-accept", ""),
            "upgrade": headers.get("upgrade", "")}


def handshake_accepted(parsed: dict, key: str) -> bool:
    """True only for a REAL RFC 6455 upgrade of the handshake we sent. Pure.

    All three must hold: status 101, `Upgrade: websocket`, and an accept header equal to
    base64(sha1(key + GUID)). Checking the status alone is the shortcut this function exists to
    refuse -- see the module docstring.

    An empty key or an empty accept header returns False rather than comparing two empty strings
    into a pass. That is the `x or DEFAULT` trap in its exact local form: with `key=""` and a server
    that sends no accept header, a naive `accept_for(key) == parsed["accept"]` is comparing a real
    hash against "" and is safe, but the reverse -- trusting a missing header -- is not, so both
    are rejected explicitly.
    """
    if not isinstance(parsed, dict) or not key:
        return False
    if int(parsed.get("status") or 0) != 101:
        return False
    if str(parsed.get("upgrade") or "").strip().lower() != "websocket":
        return False
    got = str(parsed.get("accept") or "").strip()
    if not got:
        return False
    return got == accept_for(key)


# -- RFC 6455 framing ---------------------------------------------------------------------------

OPCODE_TEXT, OPCODE_BINARY, OPCODE_CLOSE, OPCODE_PING, OPCODE_PONG = 0x1, 0x2, 0x8, 0x9, 0xA


def decode_frames(buf, limit: int = 8) -> list:
    """Decode server->client frames into [{opcode, text, length}]. Pure.

    Server frames are unmasked per RFC 6455 section 5.1, but a mask bit is honoured anyway rather
    than trusted -- a non-conforming server would otherwise hand back scrambled payload that
    silently fails every marker match, which is an invisible false negative.

    Stops cleanly on a truncated frame (returns what it decoded) and is bounded by `limit`, so a
    hostile or chatty endpoint cannot spin here.
    """
    if isinstance(buf, str):
        buf = buf.encode("latin-1", "replace")
    buf = bytes(buf or b"")
    out, i = [], 0
    while i + 2 <= len(buf) and len(out) < limit:
        b0, b1 = buf[i], buf[i + 1]
        opcode = b0 & 0x0F
        masked, ln = b1 >> 7, b1 & 0x7F
        i += 2
        if ln == 126:
            if i + 2 > len(buf):
                break
            ln = int.from_bytes(buf[i:i + 2], "big")
            i += 2
        elif ln == 127:
            if i + 8 > len(buf):
                break
            ln = int.from_bytes(buf[i:i + 8], "big")
            i += 8
        mask = b""
        if masked:
            if i + 4 > len(buf):
                break
            mask = buf[i:i + 4]
            i += 4
        if i + ln > len(buf):
            break                                    # truncated payload: keep what we have, stop
        payload = buf[i:i + ln]
        i += ln
        if mask:
            payload = bytes(p ^ mask[j % 4] for j, p in enumerate(payload))
        out.append({"opcode": opcode, "length": ln,
                    "text": payload.decode("utf-8", "replace")})
    return out


def frames_text(frames) -> str:
    """The concatenated payload text of data frames (text/binary), for marker matching. Pure.
    Control frames (close/ping/pong) carry no application data and are excluded, so a close reason
    string can never be mistaken for pushed application data."""
    return "\n".join(f.get("text", "") for f in (frames or [])
                     if f.get("opcode") in (OPCODE_TEXT, OPCODE_BINARY))


# -- discovery ----------------------------------------------------------------------------------

def _ws_scheme(http_scheme: str) -> str:
    return "wss" if str(http_scheme or "").lower() == "https" else "ws"


def discover_ws_urls(content: str, base_url: str, limit: int = 5) -> list:
    """WebSocket endpoints advertised by the page/JS text, absolute-ised against `base_url`. Pure.

    Two shapes: a `ws://`/`wss://` literal, and `new WebSocket("/relative")`. Deduped, order
    preserved, bounded. Returns [] for empty content -- an empty page is a real input and yields no
    endpoints, never a guessed default.
    """
    if not base_url:
        return []
    pr = urlparse(base_url)
    if not pr.netloc:
        return []
    out, seen = [], set()
    for m in _WS_LITERAL.finditer(content or ""):
        u = m.group(1)
        if u not in seen:
            seen.add(u)
            out.append(u)
            if len(out) >= limit:
                return out
    ws_base = "%s://%s" % (_ws_scheme(pr.scheme), pr.netloc)
    for m in _WS_RELATIVE.finditer(content or ""):
        u = ws_base + m.group(1)
        if u not in seen:
            seen.add(u)
            out.append(u)
            if len(out) >= limit:
                break
    return out


def default_ws_urls(base_url: str) -> list:
    """The framework-default endpoints to try when the content advertised none. Pure."""
    pr = urlparse(base_url or "")
    if not pr.netloc:
        return []
    ws_base = "%s://%s" % (_ws_scheme(pr.scheme), pr.netloc)
    return [ws_base + p for p in COMMON_WS_PATHS]


def split_ws_url(ws_url: str) -> tuple:
    """(host, port, path_with_query) for a ws:// or wss:// URL. Pure. Port defaults to the scheme's
    (80/443) only when the URL states none -- a stated port always wins, including port 80 on wss."""
    pr = urlparse(ws_url or "")
    host = pr.hostname or ""
    port = pr.port or (443 if pr.scheme.lower() == "wss" else 80)
    path = urlunparse(("", "", pr.path or "/", "", pr.query, "")) or "/"
    return host, port, path


def http_origin_of(ws_url: str) -> str:
    """The http(s) origin a browser would report for a socket to `ws_url`. Pure."""
    pr = urlparse(ws_url or "")
    if not pr.netloc:
        return ""
    return "%s://%s" % ("https" if pr.scheme.lower() == "wss" else "http", pr.netloc)


# -- the oracle ---------------------------------------------------------------------------------

CONFIRMED, LEAD, CLEAN = "confirmed", "lead", "clean"


def _looks_like_a_random_token(value: str) -> bool:
    """True for a high-entropy opaque token (session id, socket id, nonce, CSRF value). Pure.

    The shape: >=16 characters, alphanumeric-with-separators only, mixing upper AND lower AND
    digits. Real account identifiers do not look like that -- an email carries an `@` and a dot, and
    a human username is either shorter or not case-and-digit mixed across 16+ characters.
    """
    v = str(value or "")
    if len(v) < 16:
        return False
    if not all(c.isalnum() or c in "-_=+/" for c in v):
        return False
    return (any(c.isupper() for c in v) and any(c.islower() for c in v)
            and any(c.isdigit() for c in v))


def identity_markers(candidates) -> list:
    """Filter caller-supplied markers down to values that can actually WITNESS a session. Pure.

    THIS IS A REAL GUARD, not tidying, and a test that fails without it. The oracle asks "did the
    control receive this same marker?", so any value that CHANGES between connections trivially
    passes -- the control cannot echo a nonce that was minted for the authed connection. Feed it a
    socket id and it manufactures a confirm on a completely public endpoint. Measured: Juice Shop's
    Engine.IO handshake pushes `{"sid":"fOcfpqZA9zEc6crMAAAA"}` to the authed connection and
    `{"sid":"s3UsPOoUjURjjUUYAAAB"}` to the cookie-stripped control -- different strings, same
    public message.

    So a marker must be an account identity (the thing the HTTP session PROVED), not an opaque
    token. Values under 4 characters go too: a 1-3 char marker matches almost any JSON by accident.

    This filter cannot be replaced by comparing frame SHAPES instead. `{"user":"alice1234"}` versus
    `{"user":"anonymous"}` normalises to the same shape and is a genuine confirm, so a shape rule
    would trade this false positive for a false negative. Rejecting nonce-shaped markers is the
    guard that costs nothing real.
    """
    out = []
    for c in (candidates or []):
        c = str(c or "").strip()
        if len(c) < 4 or _looks_like_a_random_token(c):
            continue
        if c not in out:
            out.append(c)
    return out


def first_marker(text: str, markers) -> str:
    """The first usable identity marker present in `text`, or "". Pure.
    Runs `identity_markers` first, so a nonce can never be matched here."""
    low = str(text or "").lower()
    if not low:
        return ""
    for m in identity_markers(markers):
        if m.lower() in low:
            return m
    return ""


def evaluate(authed: dict, control: dict, markers=None, had_cookie: bool = False) -> dict:
    """The CSWSH verdict. Pure, and the only place the two halves are combined.

    `authed`  -- {"accepted": bool, "frames": [...]} from the handshake carrying the session cookie
                 plus the attacker Origin.
    `control` -- the SAME handshake with the cookie stripped. Mandatory.
    `markers` -- OBSERVED identity values the HTTP session already proved (never invented).
    `had_cookie` -- whether the session we replayed actually carried a Cookie.

    CONFIRMED requires all four:
      (a) a real RFC 6455 upgrade from the attacker Origin (accept verified against our key), AND
      (b) an observed authenticated marker in the pushed frames, AND
      (c) the cookie-stripped control does NOT carry that marker -- the data is genuinely gated, AND
      (d) the replayed credential was a Cookie, because that is the only thing a browser attaches
          cross-origin by itself.

    Everything weaker degrades explicitly:
      * (a) without (b)         -> LEAD  ("a socket exists and upgrades cross-origin")
      * (a)+(b) but not (c)     -> CLEAN (the marker is public; the control proves it)
      * (a)+(b)+(c) but not (d) -> LEAD  (a token-only session is not hijackable cross-site)
      * no (a)                  -> CLEAN (nothing upgraded; there is no socket to hijack)
    """
    authed = authed if isinstance(authed, dict) else {}
    control = control if isinstance(control, dict) else {}
    a_ok = bool(authed.get("accepted"))
    c_ok = bool(control.get("accepted"))
    a_text = frames_text(authed.get("frames"))
    c_text = frames_text(control.get("frames"))
    base = {"verdict": CLEAN, "marker": "", "accepted": a_ok, "control_accepted": c_ok,
            "authed_frame": a_text[:400], "control_frame": c_text[:400], "reason": ""}

    if not a_ok:
        base["reason"] = ("the cross-origin handshake did not produce a verified RFC 6455 upgrade "
                          "(no 101 with an accept derived from the key we sent)")
        return base

    # An empty marker list is a real input: we hold no observed identity to test half (b) against,
    # so half (b) is UNTESTED, not failed. That is a lead -- never a confirm, never a silent clean.
    # A list that contained ONLY nonce-shaped values is the same situation, by the same reasoning.
    if not identity_markers(markers):
        base.update(verdict=LEAD, reason=(
            "the endpoint completed a cross-origin WebSocket upgrade, but no observed identity "
            "marker was available to test whether the pushed frames are authenticated"))
        return base

    a_hit = first_marker(a_text, markers)
    if not a_hit:
        base.update(verdict=LEAD, reason=(
            "the endpoint completed a cross-origin WebSocket upgrade, but the pushed frames "
            "carried no authenticated data, so nothing was hijacked"))
        return base

    c_hit = first_marker(c_text, markers)
    if c_hit:
        base.update(verdict=CLEAN, marker=a_hit, reason=(
            "the pushed data is PUBLIC: the cookie-stripped control received the same marker "
            "(%s), so the socket is not authenticated and there is nothing to hijack" % c_hit))
        return base

    if not had_cookie:
        base.update(verdict=LEAD, marker=a_hit, reason=(
            "authenticated data was pushed to a cross-origin handshake, but the session credential "
            "is not a cookie -- a browser does not attach an Authorization header to a cross-origin "
            "WebSocket, so this is not exploitable cross-site"))
        return base

    base.update(verdict=CONFIRMED, marker=a_hit, reason=(
        "a cross-origin handshake carrying only the victim's cookie was upgraded and pushed "
        "authenticated data (%s); the identical cookie-stripped handshake did not" % a_hit))
    return base


# -- findings -----------------------------------------------------------------------------------

# CVSS v3.1: network, low complexity, no privileges, user must visit the attacker page (UI:R),
# scope unchanged. C:H because the socket streams the victim's authenticated data. I:N ON PURPOSE --
# this engine reads ONE inbound frame and never sends an application frame, so write impact is not
# proven and must not be scored. `report.report_integrity_check` recomputes this from the vector and
# rejects a disagreement over 0.5, so vector and score are kept together here.
_CVSS_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
_CVSS_SCORE = 6.5

_BASE_TAGS = ["websocket", "cswsh", "origin-validation", "wstg-clnt-10"]

_REMEDIATION = (
    "Validate the `Origin` header on the WebSocket handshake against an explicit allowlist and "
    "reject the upgrade when it does not match -- the same-origin policy does not protect a "
    "WebSocket, so the browser will happily open one cross-site with the victim's cookies. Do not "
    "rely on the session cookie alone to authorise the socket: require a per-session CSRF token in "
    "the handshake query or the first client frame, and set SameSite=Strict/Lax on the session "
    "cookie so it is not attached to a cross-site upgrade in the first place."
)


def cswsh_finding(ws_url: str, verdict: dict, origin: str, control_evidence: str,
                  marker_source: str = "") -> dict:
    """A CONFIRMED cross-site WebSocket hijack.

    `control_evidence` is the recorded artifact of the cookie-stripped handshake that ACTUALLY RAN.
    It is written to `negative_controls` -- one of `proof_schema.CONTROL_KEYS` -- so
    `report.control_ran` reads a real artifact rather than a claim. This engine never prints a
    control sentence it cannot back with that field.
    """
    marker = verdict.get("marker", "")
    ev = ("Cross-Site WebSocket Hijacking at %s. A raw HTTP/1.1 Upgrade carrying ONLY the session "
          "cookie and a foreign `Origin: %s` was accepted: HTTP 101 with a `Sec-WebSocket-Accept` "
          "that verifies against the `Sec-WebSocket-Key` we sent (RFC 6455 "
          "base64(sha1(key+GUID))), so the upgrade is real and not a forged status line. The first "
          "server-pushed frame carried the authenticated marker %r%s: %s. "
          "NEGATIVE CONTROL -- the byte-identical handshake with the Cookie header removed %s."
          % (ws_url, origin, marker,
             (" (observed from %s)" % marker_source) if marker_source else "",
             (verdict.get("authed_frame") or "")[:200], control_evidence))
    return {
        "title": "Cross-Site WebSocket Hijacking -- the handshake ignores Origin and streams the "
                 "victim's authenticated data",
        "severity": "high", "family": "cswsh", "confidence": "confirmed",
        "target": ws_url, "cwe": "CWE-1385",
        "cvss_vector": _CVSS_VECTOR, "cvss_score": _CVSS_SCORE,
        "evidence": ev,
        "success_oracle": ("a cross-origin handshake carrying only the victim's cookie is upgraded "
                           "(RFC 6455 accept verified) AND pushes an observed identity marker that "
                           "the cookie-stripped control does not receive"),
        "negative_controls": [{
            "kind": "cookie-stripped handshake",
            "description": "the identical Upgrade request with the Cookie header removed",
            "result": control_evidence,
            "rules_out": "a public socket that pushes the same data to anyone",
        }],
        "reproduction_steps": [
            "Log in to the application and capture the session cookie.",
            "Open a raw TCP connection to the WebSocket host and send an HTTP/1.1 GET for %s with "
            "`Upgrade: websocket`, `Sec-WebSocket-Version: 13`, a random `Sec-WebSocket-Key`, the "
            "captured Cookie, and `Origin: %s`." % (ws_url, origin),
            "Verify the response is 101 and that `Sec-WebSocket-Accept` equals "
            "base64(sha1(your key + 258EAFA5-E914-47DA-95CA-C5AB0DC85B11)).",
            "Read the first server-pushed frame: it contains %r." % marker,
            "Repeat the identical handshake with the Cookie header removed -- it does not return "
            "that data. The data is therefore session-gated, and the Origin check is missing.",
        ],
        "impact": ("Any page the victim visits while logged in can open an authenticated WebSocket "
                   "to this application and read the data it streams -- the same-origin policy does "
                   "not apply to WebSockets, so no XSS on the target is needed. The attacker's page "
                   "receives the victim's session data directly."),
        "remediation": _REMEDIATION,
        "tags": list(_BASE_TAGS) + ["cwe-1385", "cwe-346"],
        "wstg": "WSTG-CLNT-10",
    }


def upgrade_lead(ws_url: str, verdict: dict, origin: str, control_evidence: str) -> dict:
    """A LEAD: the handshake upgrades cross-origin, but the authenticated-data half was not proven.

    This is deliberately not a finding. Half (a) alone is the normal state of most WebSocket
    deployments -- measured on Juice Shop, which upgrades from any Origin and pushes only a public
    Engine.IO handshake frame. Emitting it as `confirmed` would flag every socket.io app alive.
    """
    return {
        "title": "WebSocket handshake accepts a foreign Origin (no authenticated data observed)",
        "severity": "info", "family": "cswsh", "confidence": "lead",
        "target": ws_url, "cwe": "CWE-346",
        "evidence": ("%s upgraded a raw HTTP/1.1 handshake presenting a foreign `Origin: %s` "
                     "(HTTP 101, RFC 6455 accept verified against the key we sent), so the "
                     "handshake performs no Origin validation. NOT CONFIRMED as CSWSH: %s. "
                     "NEGATIVE CONTROL -- the cookie-stripped handshake %s. Pushed frame: %s"
                     % (ws_url, origin, verdict.get("reason", ""), control_evidence,
                        (verdict.get("authed_frame") or "")[:200] or "(none)")),
        "success_oracle": ("cross-origin upgrade confirmed; authenticated-data half NOT proven, so "
                           "this is reported as a lead and never as a confirmed finding"),
        "negative_controls": [{
            "kind": "cookie-stripped handshake",
            "description": "the identical Upgrade request with the Cookie header removed",
            "result": control_evidence,
            "rules_out": "an endpoint that only serves authenticated sockets",
        }],
        "impact": ("A missing Origin check on the handshake is exploitable ONLY if the socket "
                   "carries session-gated data. Apolaki did not observe any, so this is recorded "
                   "as a lead for manual review, not as a vulnerability."),
        "remediation": _REMEDIATION,
        "tags": list(_BASE_TAGS) + ["cwe-346", "unconfirmed"],
        "wstg": "WSTG-CLNT-10",
    }
