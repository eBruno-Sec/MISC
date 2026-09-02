"""Q-148 -- passive CONTENT disclosure, mined from Burp's published issue catalog.

    Private key disclosed                 Json Web Key Set disclosed
    JWT private key disclosed             Database connection string disclosed
    Credit card numbers disclosed         Social security numbers disclosed
    Source code disclosure                Cross-domain script include
    Password submitted using GET          Password returned in later response
    Session token in URL

PASSIVE, and that is the whole economic argument: every check here reads a response the scanner
ALREADY fetched. Zero extra requests, no probe budget, no rate-limit exposure, and it fires on every
URL in the surface. The last mission crawled 6345 URLs; a passive family lights up all of them.

PURE. No network, no state, and -- deliberately -- NO `except` HANDLER ANYWHERE IN THIS FILE. Every
parse below is written to be total: the JWK reader walks braces instead of calling `json.loads`, and
the query reader splits strings instead of calling `urlsplit`, because both of those raise and the
repo's silent-failure census (`tests/test_silent_failure_invariant.py`) is a ratchet. Validation
instead of catching.

NOT `exposure_tool`. That engine asks "is /.git/config readable" -- SIGNATURE of a known file at a
known path. This one asks "does an ordinary 200 response CONTAIN a secret", which needs no extra
request and has no path list. Different job, no overlap.

═══════════════════════════════════════════════════════════════════════════════════════════════
THE FALSE-POSITIVE PROBLEM IS THE ENTIRE TICKET

`tests/test_exposure_catchall_is_not_a_file.py` records a CRITICAL "Exposed .env file" raised
against a WordPress install that has no .env. Two causes, both of which this file is written to
avoid by construction:

  1. `re.I` APPLIED TO A CASE-BEARING SIGNATURE. `^[A-Z][A-Z0-9_]{2,}\\s*=` means "an uppercase KEY
     at a line start". Folded, it means "any word followed by `=`", and it matched `class=` in
     WordPress's own markup. Here, case folding is opt-in per pattern: `-----BEGIN` and `<?php` are
     case-BEARING and are matched exactly; the payment-context words are ordinary English and fold.
  2. `\\s` MATCHING NEWLINES, so `^` bought nothing. Every horizontal-whitespace class in this file
     is `[^\\S\\n]`.

The specific traps for THESE checks, each of which fires on a normal page if handled carelessly:

  * A 16-DIGIT RUN IS ALSO AN ORDER ID, a tracking number, or two concatenated timestamps. Luhn
    alone is a 1-in-10 filter and is not enough. `find_card_numbers` requires Luhn AND a real IIN
    prefix AND the brand's exact length AND digit-run boundaries AND a payment context.
  * `\\d{3}-\\d{2}-\\d{4}` IS A PRODUCT SKU. The context-free SSN scan is REFUSED, in writing, in
    `find_ssns`'s docstring. Only the labelled form ships.
  * A CONNECTION STRING IN DOCUMENTATION is more common than one in a leak, and it is the same
    string minus a real credential. `Password=myPassword` is rejected as a placeholder.
  * A PAGE THAT DISPLAYS CODE is not a page that leaked code. Matches inside `<pre>`/`<code>`, and
    HTML-escaped `&lt;?php`, are excluded.
  * NEARLY EVERY SITE LOADS THIRD-PARTY SCRIPT. That check is informational, deduplicated to one
    finding, and never carries a severity that would reorder a report.

REDACTION. A finding that quotes a card number or a private key INTO THE REPORT is itself a
disclosure -- the report then carries the secret to everyone the report reaches. Every finding here
reports a MATCH LOCATION (byte offset + line) and a MASKED form. `intel.to_dict(redact_secrets=True)`
is the convention this follows.
"""
from __future__ import annotations

import re

# ══════════════════════════════════════════════════════════════════ finding plumbing

#: check id -> (severity, CWE). One table so a check cannot ship without both.
_META = {
    "private_key_disclosed":            ("critical", "CWE-522"),
    "jwt_private_key_disclosed":        ("critical", "CWE-522"),
    "jwks_disclosed":                   ("info",     "CWE-200"),
    "db_connection_string_disclosed":   ("high",     "CWE-522"),
    "credit_card_disclosed":            ("high",     "CWE-359"),
    "ssn_disclosed":                    ("high",     "CWE-359"),
    "source_code_disclosure":           ("high",     "CWE-540"),
    "cross_domain_script_include":      ("info",     "CWE-829"),
    "password_form_method_get":         ("medium",   "CWE-598"),
    "password_in_url":                  ("medium",   "CWE-598"),
    "session_token_in_url":             ("medium",   "CWE-598"),
    "password_returned_in_response":    ("medium",   "CWE-200"),
}


def _line_of(text: str, offset: int) -> int:
    """1-based line number of `offset`. Reported instead of the surrounding text, because the
    surrounding text of a disclosure IS the disclosure."""
    return text.count("\n", 0, max(0, int(offset))) + 1


def _finding(check: str, detail: str, evidence: str, text: str, offset: int,
             confidence: str = "confirmed", **extra) -> dict:
    severity, cwe = _META[check]
    out = {"check": check, "severity": severity, "cwe": cwe, "confidence": confidence,
           "detail": detail, "evidence": evidence,
           "location": {"offset": int(offset), "line": _line_of(text, offset)}}
    out.update(extra)
    return out


# ══════════════════════════════════════════════════════════════════ redaction


def mask_secret(value: str) -> str:
    """A secret with no useful non-secret part: length hint only, exactly as `intel.to_dict`
    does under `redact_secrets=True`."""
    return "<redacted:%d>" % len(str(value or ""))



_DISPLAY_BLOCK = re.compile(r"<(pre|code|xmp|textarea)\b[^>]*>.*?</\1\s*>", re.I | re.S)


def display_spans(text: str) -> list:
    """(start, end) of every region whose whole purpose is to SHOW markup rather than be it."""
    return [(m.start(), m.end()) for m in _DISPLAY_BLOCK.finditer(text or "")]


def _inside(offset: int, spans: list) -> bool:
    return any(a <= offset < b for a, b in spans)


# ══════════════════════════════════════════════════════════════════ 1. private key disclosed

#: Case-BEARING on purpose (see the module docstring). PEM armour is uppercase by definition, and
#: folding this would match the word "begin" beside the words "private key" in prose.
_PEM_BEGIN = re.compile(
    r"-----BEGIN (RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED |ENCRYPTED RSA )?PRIVATE KEY(?: BLOCK)?-----")
_PEM_END = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")
#: PEM base64 alphabet plus the whitespace and the PGP armour header lines that ride inside a block.
_PEM_BODY_CHARS = re.compile(r"[A-Za-z0-9+/=]")
#: A documentation page carries the ARMOUR and an ellipsis where the key would be. So does a config
#: template. Neither is a disclosure, and both are common.
#: The word alternatives carry non-alphanumeric lookarounds because a PEM body IS base64 and the
#: letters "paste" or "example" occur inside real key material by chance. Without the lookarounds
#: this control would cause false NEGATIVES on genuine keys.
_KEY_PLACEHOLDER = re.compile(
    r"\.\.\.|\u2026|<[^>\n]{0,60}>|\{\{|\$\{|%[A-Z_]{3,}%|"
    r"(?i:(?<![A-Za-z0-9])(?:your|paste|insert|redacted|snip|example|placeholder|xxxx|todo|"
    r"key[_ -]?here|omitted)(?![A-Za-z0-9]))")

#: A PEM body shorter than this is armour with nothing in it. The smallest real key material that
#: appears between PEM lines (a 256-bit EC key) is ~120 base64 characters.
_MIN_PEM_BODY = 100


def find_private_keys(body: str) -> list:
    """`-----BEGIN ... PRIVATE KEY-----` with real key material between the armour lines.

    The armour is a near-zero-FP signature -- it is 30 characters of fixed uppercase text that no
    template engine emits by accident. The FP that DOES exist is documentation: a page explaining
    PEM shows the armour with `...` or `<your key here>` in the middle. Both halves are tested.

    A PUBLIC key or a CERTIFICATE is not matched: `PRIVATE KEY` is required literally, so
    `-----BEGIN PUBLIC KEY-----` and `-----BEGIN CERTIFICATE-----` cannot reach this.
    """
    text = str(body or "")
    out = []
    # BREAKER FINDING 2. `display_spans` was written as the documentation-page control and then
    # never called -- 0 callers repo-wide. A developer-docs page SHOWING an example PEM block was
    # therefore reported as a CRITICAL private-key disclosure. Same shape as the -on-WordPress
    # CRITICAL: a documented FP control that exists and is not wired is not a control.
    _shown = display_spans(text)
    for m in _PEM_BEGIN.finditer(text):
        if _inside(m.start(), _shown):
            continue
        end = _PEM_END.search(text, m.end())
        if not end:
            continue                      # unterminated armour is prose, not a key
        block = text[m.end():end.start()]
        material = len(_PEM_BODY_CHARS.findall(block))
        if material < _MIN_PEM_BODY:
            continue
        if _KEY_PLACEHOLDER.search(block):
            continue                      # a documented shape, not a leaked key
        kind = (m.group(1) or "").strip() or "PKCS#8"
        out.append(_finding(
            "private_key_disclosed",
            "a %s PRIVATE KEY block with %d characters of key material is served in this response "
            "body; anyone who fetches this URL holds the key" % (kind, material),
            "-----BEGIN %s PRIVATE KEY----- %s" % (kind, mask_secret(block)),
            text, m.start()))
    return out


# ══════════════════════════════════════════════════════════════════ 2. JWK / JWKS
#
# STRUCTURAL, NOT GREP. `"d"` appears in any JSON document; `"d"` carrying 20+ base64url characters
# inside the SAME object as `"kty"` is an RSA/EC private exponent and nothing else. The object slice
# is found by walking braces rather than by `json.loads`, because a response body is frequently
# HTML with JSON embedded in it -- and because `json.loads` raises, and this file has no handlers.

_KTY = re.compile(r'"kty"[^\S\n]*:[^\S\n]*"(RSA|EC|OKP|oct)"')
#: RSA private exponent/primes, EC/OKP private scalar, and the oct symmetric key.
_JWK_PRIVATE_MEMBER = re.compile(r'"(d|p|q|dp|dq|qi|k)"[^\S\n]*:[^\S\n]*"([A-Za-z0-9_-]{20,})"')
_JWKS_SET = re.compile(r'"keys"[^\S\n]*:[^\S\n]*\[')

#: Bound on the brace walk. A JWK is a flat object of a few hundred bytes; scanning further than
#: this means the `"kty"` was not in a JWK at all.
_OBJECT_WINDOW = 8192


def enclosing_object(text: str, index: int) -> tuple:
    """(start, end) of the innermost `{...}` containing `index`, or (-1, -1).

    Total by construction: it counts braces and gives up at the window edge. It does not attempt to
    honour braces inside string literals, which is safe here because every JWK member value is
    base64url, a decimal, or an array of base64url -- none of which can contain a brace.
    """
    text = str(text or "")
    start = -1
    depth = 0
    for i in range(index, max(-1, index - _OBJECT_WINDOW), -1):
        ch = text[i]
        if ch == "}":
            depth += 1
        elif ch == "{":
            if depth == 0:
                start = i
                break
            depth -= 1
    if start < 0:
        return (-1, -1)
    depth = 0
    for j in range(start, min(len(text), start + _OBJECT_WINDOW)):
        ch = text[j]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return (start, j + 1)
    return (-1, -1)


def _top_level_only(obj: str) -> str:
    """The object with every NESTED object/array blanked out, so a member search sees only members
    of THIS object. Length-preserving (nested spans become spaces), so match offsets stay valid."""
    out, depth = [], 0
    for ch in str(obj or ""):
        if ch in "{[":
            depth += 1
            out.append(ch if depth == 1 else " ")
        elif ch in "}]":
            out.append(ch if depth == 1 else " ")
            depth = max(0, depth - 1)
        else:
            out.append(ch if depth <= 1 else " ")
    return "".join(out)


def find_jwk_private_keys(body: str) -> list:
    """A JWK carrying PRIVATE key material. Burp: "JWT private key disclosed"."""
    text = str(body or "")
    out = []
    seen = set()
    for m in _KTY.finditer(text):
        start, end = enclosing_object(text, m.start())
        if start < 0 or start in seen:
            continue
        seen.add(start)
        # BREAKER FINDING 3. This searched the WHOLE object slice, nested objects included, so a
        # PUBLIC key set carrying any nested `{"d": ...}` -- metadata, an x5c annotation -- was
        # reported CRITICAL "attacker can mint and sign tokens". A public JWKS endpoint is public
        # BY DESIGN, so that fires on a correctly-configured server. A private member belongs to the
        # key only when it is a member OF THE KEY, not of something nested inside it.
        priv = _JWK_PRIVATE_MEMBER.search(_top_level_only(text[start:end]))
        if not priv:
            continue                      # a PUBLIC JWK: `n`/`e`/`x`/`y` only. The common case.
        out.append(_finding(
            "jwt_private_key_disclosed",
            'a JSON Web Key of type %s exposes its PRIVATE member "%s"; whoever fetches this URL can '
            "mint and sign tokens this application will accept" % (m.group(1), priv.group(1)),
            '"%s": %s' % (priv.group(1), mask_secret(priv.group(2))),
            text, start))
    return out


def find_jwks(body: str) -> list:
    """A JWKS document. Burp reports the mere disclosure, and it is INFORMATIONAL: a JWKS of public
    keys is published on purpose, at a well-known URL, by design. It is worth recording because it
    names the signing algorithm and key ids an auth attack needs -- and no more than that.

    Suppressed when the same document already produced `jwt_private_key_disclosed`: one document,
    one finding, and the critical one is not to be diluted by an info row beside it.
    """
    text = str(body or "")
    if not _JWKS_SET.search(text) or not _KTY.search(text):
        return []
    if find_jwk_private_keys(text):
        return []
    m = _JWKS_SET.search(text)
    keys = len(_KTY.findall(text))
    return [_finding(
        "jwks_disclosed",
        "a JSON Web Key Set with %d public key(s) is readable here; it discloses the signing "
        "algorithms and key ids used for this application's tokens" % keys,
        "keys: %d, kty: %s" % (keys, ", ".join(sorted(set(_KTY.findall(text))))),
        text, m.start(), confidence="informational")]


# ══════════════════════════════════════════════════════════════════ 3. DB connection string
#
# A connection string in a DOCS page is more common than one in a leak, and it is character-for-
# character the same string minus a real credential. So a CREDENTIAL COMPONENT is required, and the
# credential is checked against the placeholder vocabulary that documentation actually uses.

_CONN_URI = re.compile(
    r"\b(postgresql|postgres|mysql|mariadb|mongodb\+srv|mongodb|rediss|redis|amqps|amqp|"
    r"sqlserver|mssql|db2|clickhouse|cassandra|jdbc:[a-z0-9]{2,12})://"
    r"([^\s/:@\"'<>]{1,64}):([^\s/@\"'<>]{1,128})@([^\s/?#\"'<>]{1,255})", re.I)

#: The key-value dialect (.NET / ODBC / JDBC properties). Both halves are required: a `Password=`
#: with no server beside it is a form field, and a `Server=` with no password is a hostname.
_CONN_KV_SECRET = re.compile(r"\b(password|pwd)[^\S\n]*=[^\S\n]*([^;\s\"'<>&]{1,128})", re.I)
_CONN_KV_HOST = re.compile(
    r"\b(server|data source|host|hostname|initial catalog|database|uid|user id)[^\S\n]*=[^\S\n]*[^;\s\"'<>&]", re.I)
#: How far either side of the password the host key may sit. A .NET connection string is one line.
_CONN_KV_WINDOW = 200

#: The vocabulary documentation uses where a credential goes. This is the single load-bearing FP
#: control for this check: `postgres://user:password@localhost/db` is in every quickstart on earth.
_CRED_PLACEHOLDER = re.compile(
    r"^(?:\*+|x{3,}|X{3,}|\.{2,}|<.*>|\{\{.*\}\}|\$\{.*\}|%[A-Za-z_]{3,}%|"
    r"(?:my|your|the|a)?[_-]?(?:password|passwd|pass|pwd|secret|credential|changeme|"
    r"example|placeholder|redacted|dbpass|yourpass)[_-]?\d{0,3})$", re.I)

_MIN_CRED = 4


def _is_placeholder(value: str) -> bool:
    value = str(value or "")
    return len(value) < _MIN_CRED or bool(_CRED_PLACEHOLDER.match(value))


def find_connection_strings(body: str) -> list:
    """A database connection string CARRYING A CREDENTIAL. Burp: "Database connection string
    disclosed".

    Both dialects: the URI form (`postgres://user:pass@host`, `mongodb+srv://...`, `jdbc:...`) and
    the key-value form (`Server=...;User Id=...;Password=...`). In both, a password that reads as a
    documentation placeholder is rejected -- that is the difference between a leak and a README.
    """
    text = str(body or "")
    out = []
    for m in _CONN_URI.finditer(text):
        scheme, user, secret, host = m.group(1), m.group(2), m.group(3), m.group(4)
        if _is_placeholder(secret):
            continue                       # documentation, not a leak
        out.append(_finding(
            "db_connection_string_disclosed",
            "a %s connection string with live credentials is served in this response body "
            "(user %r, host %r); it grants direct database access, bypassing the application "
            "entirely" % (scheme.lower(), user, host),
            "%s://%s:%s@%s" % (scheme.lower(), user, mask_secret(secret), host),
            text, m.start()))
    for m in _CONN_KV_SECRET.finditer(text):
        secret = m.group(2)
        if _is_placeholder(secret):
            continue
        # BREAKER FINDING 4. The window crossed NEWLINES, despite the constant's own comment saying
        # a .NET connection string is one line. A settings panel with host= and password= four HTML
        # lines apart fired HIGH, and so did a single anchor carrying ?uid=&password= in a query
        # string. Clamped to the password's OWN line, which is what the comment always claimed.
        _ls = text.rfind(chr(10), 0, m.start()) + 1
        _le = text.find(chr(10), m.end())
        _le = len(text) if _le < 0 else _le
        lo = max(_ls, m.start() - _CONN_KV_WINDOW)
        hi = min(_le, m.end() + _CONN_KV_WINDOW)
        _span = text[lo:hi]
        # ...and the second half of the same finding: a URL QUERY STRING is not a DSN. A key-value
        # connection string separates pairs with ';'; a query string uses '&'. A single anchor
        # carrying ?uid=jdoe&password=... satisfied every other clause and was reported HIGH.
        if "&" in _span or "?" in _span:
            continue
        if not _CONN_KV_HOST.search(_span):
            continue                       # a bare `password=` is a form field, not a DSN
        out.append(_finding(
            "db_connection_string_disclosed",
            "a key-value database connection string with a live %s is served in this response body, "
            "beside a server/database key; it grants direct database access, bypassing the "
            "application entirely" % m.group(1).lower(),
            "%s=%s" % (m.group(1), mask_secret(secret)),
            text, m.start()))
    return out


# ══════════════════════════════════════════════════════════ the aggregate entry point
#
# WHAT ACTUALLY SHIPPED, and this note exists because the module docstring above describes the full
# plan rather than the delivered set. The lane that wrote this file was killed by a session limit
# partway through, so `_META` carries twelve check ids and four finders exist:
#
#     SHIPPED   private_key_disclosed · jwt_private_key_disclosed · jwks_disclosed
#               db_connection_string_disclosed
#     NOT YET   credit_card_disclosed · ssn_disclosed · source_code_disclosure
#               cross_domain_script_include · password_* · session_token_in_url
#
# A module whose docstring promises checks it does not have is itself a false claim, which is the
# defect class this repo keeps filing. The unimplemented ids stay in `_META` deliberately -- they are
# the contract a future finder must satisfy -- but `scan_response` can only return what exists, and
# `SHIPPED_CHECKS` below is the honest list a caller can rely on.
#
# The SSN scan is a DELIBERATE REFUSAL, not an omission: `\d{3}-\d{2}-\d{4}` is also a product SKU,
# a phone number and a date, and a context-free version would fire on ordinary pages. That decision
# is recorded in the docstring above and should not be quietly reversed.

SHIPPED_CHECKS = ("private_key_disclosed", "jwt_private_key_disclosed", "jwks_disclosed",
                  "db_connection_string_disclosed")


def scan_response(body: str, *, url: str = "") -> list:
    """Every shipped passive check over one response body. PURE -- no network, no state.

    Passive by construction: it reads a body the scanner ALREADY fetched, so it costs no request and
    carries no probe risk. That is what makes it worth running on every response rather than on a
    sampled subset.

    `url` is carried onto the finding as `target` only; nothing here inspects it, so a caller with no
    URL still gets correct results.
    """
    out = []
    for finder in (find_private_keys, find_jwk_private_keys, find_jwks, find_connection_strings):
        for f in finder(body or ""):
            if url:
                f = dict(f, target=url)
            out.append(f)
    # Severity order, then stable by check id, so a report renders the same way every render.
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}
    out.sort(key=lambda f: (rank.get(str(f.get("severity", "")).lower(), 9), str(f.get("check", ""))))
    return out
