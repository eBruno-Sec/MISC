"""
Deterministic web-security primitives (scope decisions, probe generation,
response comparison, sensitive-path validation).

No network I/O. The tool layer owns transport, approval, logging, and finding
creation; this module owns scope decisions, probe generation, response
comparison, and wordlist shaping. Ported/adapted from Yggdrasil
core/web_security.py.
"""
from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
import html as _html
import os
import posixpath
import re
from urllib.parse import parse_qsl, unquote_plus, urlencode, urlparse, urlunparse

TRAVERSAL_PARAM_HINTS = {
    "file", "filepath", "filename", "path", "dir", "folder", "template",
    "page", "include", "view", "download", "document", "doc", "asset",
    "resource", "locale", "lang", "theme", "skin", "image", "img", "url",
}

IDOR_PARAM_HINTS = {
    "id", "uid", "user", "user_id", "userid", "account", "account_id",
    "customer", "customer_id", "tenant", "tenant_id", "org", "org_id",
    "project", "project_id", "order", "order_id", "invoice", "invoice_id",
    "profile", "profile_id", "record", "record_id", "object", "object_id",
}

TRAVERSAL_SAFE_PAYLOADS = (
    "../bbh-canary.txt",
    "..%2fbbh-canary.txt",
    "%2e%2e%2fbbh-canary.txt",
    "....//bbh-canary.txt",
    "..\\bbh-canary.txt",
    # advanced filter/WAF bypasses (WAHH ch10): double-URL-encode + overlong-UTF-8 beat filters that
    # decode once (WAF) but let the backend decode again, or that only match ASCII `../`.
    "%252e%252e%252fbbh-canary.txt",
    "..%c0%afbbh-canary.txt",
)

TRAVERSAL_LAB_PAYLOADS = (
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    # advanced bypasses (WAHH ch10) — the ones a naive `../` filter and a single-decode WAF miss:
    "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",  # double URL-encode
    "..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",                             # overlong UTF-8
    "..%252f..%252f..%252f..%252fetc%252fpasswd",                                  # double-encoded slash
)

DEFAULT_DISCOVERY_WORDS = (
    "admin", "administrator", "login", "logout", "dashboard", "console",
    "manager", "management", "portal", "control", "account", "accounts",
    "users", "user", "api", "api/v1", "api/v2", "graphql", "graphiql",
    "swagger", "swagger-ui", "swagger.json", "openapi.json", "docs",
    "redoc", "actuator", "actuator/health", "actuator/env", "metrics",
    "debug", "server-status", "status", "health", "version", "config",
    "configuration", ".env", ".git/HEAD", ".git/config", ".svn/entries",
    "backup", "backups", "bak", "old", "tmp", "temp", "logs", "log",
    "error.log", "access.log", "uploads", "upload", "files", "download",
    "downloads", "private", "internal", "dev", "test", "stage", "staging",
    "qa", "beta", "sandbox", "robots.txt", "sitemap.xml", ".well-known",
    ".well-known/security.txt", "phpinfo.php", "info.php", "wp-login.php",
    "wp-admin", "wp-json/wp/v2/users", "wp-content/debug.log",
)

SENSITIVE_RESPONSE_WORDS = re.compile(
    r"(?i)(email|username|user_id|userid|account|tenant|invoice|order|"
    r"customer|address|phone|ssn|token|secret|api[_-]?key|role|admin)"
)

TRAVERSAL_RESPONSE_HINTS = (
    "root:x:0:0", "[extensions]", "[fonts]", "boot loader",
    "no such file or directory", "failed to open stream",
    "permission denied", "directory traversal", "path traversal",
    "invalid path", "not allowed to load local resource",
)

# Content the PARAMETER CANNOT HAVE SUPPLIED. This is the only single-response evidence that a file
# was actually read: the body carries the interior of a known system file, and no probe value contains
# it. Each is checked two-sided (present in the probe response, absent from the baseline) so a page
# that always displays such text is not mistaken for a traversal.
FILE_CONTENT_SIGNATURES = (
    ("root:x:0:0", "/etc/passwd content returned (root:x:0:0)"),
    ("[boot loader]", "win.ini content returned ([boot loader])"),
    ("; for 16-bit app support", "win.ini content returned (16-bit app support stanza)"),
    ("[mci extensions]", "win.ini content returned ([mci extensions])"),
    ("[extensions]", "win.ini content returned ([extensions])"),
    ("[fonts]", "win.ini content returned ([fonts])"),
    ("root:*:0:0", "/etc/passwd content returned (BSD root entry)"),
    ("daemon:x:1:1", "/etc/passwd content returned (daemon entry)"),
)

# Confidences the product does NOT report as a real vulnerability. Mirrors
# proof_schema.UNPROVEN_CONFIDENCE; duplicated rather than imported to keep this module dependency-free
# (it is the pure primitives layer). test_traversal_oracle pins the two together.
UNPROVEN_TRAVERSAL_CONFIDENCE = frozenset(
    {"lead", "candidate", "unconfirmed", "informational", "info", "tentative"})

# The file that must EXIST on the far side of the traversal, per platform, plus the separator its
# encodings rewrite. The absent twin is generated from this model so both payloads have identical
# length, identical separator positions and identical punctuation — see _absent_tail.
_TWIN_MODELS = (
    ("posix", "etc/passwd", "/"),
    ("windows", "windows\\win.ini", "\\"),
)


@dataclass(frozen=True)
class WebProbe:
    url: str
    parameter: str
    original_value: str
    payload: str
    family: str


def _host_matches_rule(host: str, rule: dict) -> bool:
    ident = (rule.get("identifier") or "").lower().strip()
    if not ident:
        return False
    if _is_path_rule(rule):
        return False
    if ident.startswith(("http://", "https://")):
        ident = urlparse(ident).netloc
    ident = ident.split("/")[0].split(":")[0].lstrip("*.").lower()
    clean_host = host.split(":")[0].lstrip("*.").lower()
    return clean_host == ident or clean_host.endswith("." + ident)


def _looks_like_host_identifier(identifier: str) -> bool:
    ident = (identifier or "").strip().lower()
    if not ident:
        return False
    if ident.startswith(("http://", "https://")):
        ident = urlparse(ident).netloc
    ident = ident.split("/")[0].split(":")[0].lstrip("*.")
    if not ident:
        return False
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ident):
        return True
    return "." in ident and " " not in ident and "\t" not in ident


def _is_path_rule(rule: dict) -> bool:
    ident = (rule.get("identifier") or "").strip()
    rule_type = (rule.get("type") or "").lower().strip()
    return rule_type in ("path", "url_path") or (ident.startswith("/") and not ident.startswith("//"))


def _is_host_rule(rule: dict) -> bool:
    if _is_path_rule(rule):
        return False
    ident = (rule.get("identifier") or "").strip()
    rule_type = (rule.get("type") or "").lower().strip()
    if rule_type in ("url", "ip", "domain"):
        return _looks_like_host_identifier(ident)
    return ident.startswith(("http://", "https://")) or _looks_like_host_identifier(ident)


def _path_matches_rule(path: str, rule: dict) -> bool:
    ident = (rule.get("identifier") or "").strip()
    if ident.startswith(("http://", "https://")):
        ident = urlparse(ident).path or "/"
    if not ident.startswith("/"):
        return False
    clean_rule = posixpath.normpath("/" + ident.lstrip("/"))
    clean_path = posixpath.normpath("/" + (path or "/").lstrip("/"))
    if clean_rule in ("", ".", "/"):
        return True
    return clean_path == clean_rule or clean_path.startswith(clean_rule.rstrip("/") + "/")


def _rule_matches_url(url: str, base_url: str, rule: dict) -> bool:
    parsed = urlparse(url)
    base = urlparse(base_url)
    if _is_path_rule(rule):
        return (parsed.hostname or "").lower() == (base.hostname or "").lower() and _path_matches_rule(parsed.path, rule)
    ident = (rule.get("identifier") or "").strip()
    if ident.startswith(("http://", "https://")):
        r = urlparse(ident)
        if r.hostname and not _host_matches_rule(parsed.hostname or "", {"identifier": r.hostname}):
            return False
        return _path_matches_rule(parsed.path, {"identifier": r.path or "/"})
    return _host_matches_rule(parsed.hostname or "", rule)


def is_url_in_scope(url: str, base_url: str, scope_rules: dict | None = None) -> bool:
    parsed = urlparse(url)
    base = urlparse(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return False
    host = parsed.hostname or ""
    base_host = base.hostname or ""

    rules = scope_rules or {}
    out_rules = rules.get("out_of_scope") or []
    in_rules = rules.get("in_scope") or []
    if any(_rule_matches_url(url, base_url, rule) for rule in out_rules):
        return False

    host_rules = [rule for rule in in_rules if _is_host_rule(rule)]
    path_rules = [rule for rule in in_rules if _is_path_rule(rule)]

    if host_rules:
        host_allowed = any(_host_matches_rule(host, rule) for rule in host_rules)
    else:
        host_allowed = host.lower() == base_host.lower()
    if not host_allowed:
        return False

    if path_rules:
        return any(_path_matches_rule(parsed.path, rule) for rule in path_rules)
    if in_rules:
        return any(_rule_matches_url(url, base_url, rule) for rule in in_rules)
    return True


def _replace_query_value(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    new_pairs = [(k, value if k == name else v) for k, v in pairs]
    return urlunparse(parsed._replace(query=urlencode(new_pairs, doseq=True)))


def looks_pathlike(name: str, value: str) -> bool:
    lname = name.lower()
    v = (value or "").lower()
    if lname in TRAVERSAL_PARAM_HINTS:
        return True
    if any(h in lname for h in ("file", "path", "dir", "page", "template", "download")):
        return True
    if "/" in v or "\\" in v or "%2f" in v or "%5c" in v:
        return True
    return bool(re.search(r"\.(txt|csv|pdf|docx?|xlsx?|xml|json|yml|yaml|conf|ini|log|png|jpe?g|gif)$", v))


def build_traversal_probes(url: str, *, lab_mode: bool = False, max_probes: int = 12) -> list:
    payloads = list(TRAVERSAL_SAFE_PAYLOADS)
    if lab_mode:
        payloads.extend(TRAVERSAL_LAB_PAYLOADS)
    probes: list = []
    pairs = parse_qsl(urlparse(url).query, keep_blank_values=True)
    # looks_pathlike ORDERS the work, it does not gate it. As a filter it silently skipped every
    # parameter with an opaque name -- `?id=SafeText` reaching a file read is still a file read, and the
    # heuristic only ever existed to stop probe blowup on a wide query string. max_probes already bounds
    # that, so path-like parameters go first and the rest still get tested with whatever budget is left.
    # On a narrow query string, which is the common case, every parameter is now reached.
    ordered = ([pv for pv in pairs if looks_pathlike(pv[0], pv[1])]
               + [pv for pv in pairs if not looks_pathlike(pv[0], pv[1])])
    for name, value in ordered:
        for payload in payloads:
            probes.append(WebProbe(
                url=_replace_query_value(url, name, payload),
                parameter=name, original_value=value, payload=payload,
                family="path_traversal"))
            if len(probes) >= max_probes:
                return probes
    return probes


def with_param(url: str, name: str, value: str) -> str:
    """Public form of the query rewrite the probe builders use, so a caller driving its own payload
    sequence (the traversal differential) does not have to reach for a private helper."""
    return _replace_query_value(url, name, value)


def traversal_parameters(url: str, *, limit: int = 3) -> list:
    """Query parameter names worth a traversal experiment, path-like ones first.

    Same ordering rule as build_traversal_probes: the heuristic ORDERS the work, it never gates it —
    an opaque parameter name reaching a file read is still a file read."""
    pairs = parse_qsl(urlparse(url).query, keep_blank_values=True)
    ordered = ([n for n, v in pairs if looks_pathlike(n, v)]
               + [n for n, v in pairs if not looks_pathlike(n, v)])
    seen, out = set(), []
    for name in ordered:
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out[:limit]


def build_idor_probes(url: str, max_probes: int = 8) -> list:
    probes: list = []
    parsed = urlparse(url)
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        lname = name.lower()
        if lname in IDOR_PARAM_HINTS or lname.endswith("_id") or lname.endswith("id"):
            if value.isdigit():
                n = int(value)
                for candidate in {n + 1, max(1, n - 1)}:
                    if candidate != n:
                        probes.append(WebProbe(
                            url=_replace_query_value(url, name, str(candidate)),
                            parameter=name, original_value=value, payload=str(candidate),
                            family="idor_query"))
    path_parts = parsed.path.split("/")
    for i, part in enumerate(path_parts):
        if not part.isdigit():
            continue
        n = int(part)
        for candidate in {n + 1, max(1, n - 1)}:
            if candidate == n:
                continue
            new_parts = list(path_parts)
            new_parts[i] = str(candidate)
            probes.append(WebProbe(
                url=urlunparse(parsed._replace(path="/".join(new_parts))),
                parameter=f"path[{i}]", original_value=part, payload=str(candidate),
                family="idor_path"))
            if len(probes) >= max_probes:
                return probes
    return probes[:max_probes]


def text_from_response(response) -> str:
    if isinstance(response, dict):
        return response.get("body") or ""
    text = getattr(response, "text", "")
    if text:
        return text
    content = getattr(response, "content", b"")
    if isinstance(content, bytes):
        return content.decode("utf-8", errors="replace")
    return str(content or "")


def _status_of(response) -> int:
    if isinstance(response, dict):
        return response.get("status") or response.get("status_code") or 0
    return getattr(response, "status_code", 0) or 0


def _body_similarity(a: str, b: str) -> float:
    a = re.sub(r"\s+", " ", a or "")[:12000]
    b = re.sub(r"\s+", " ", b or "")[:12000]
    if not a and not b:
        return 1.0
    return SequenceMatcher(None, a, b).ratio()


@dataclass(frozen=True)
class TraversalTwin:
    """A shape-identical pair of traversal payloads: one that resolves to a file which MUST exist on
    the far side of the escape, and two that resolve to files which cannot. Same length, same segment
    count, same separators, same encoding — so any response that is a function of the parameter's
    SHAPE is identical for all three, and only the target's existence on disk can separate them."""
    label: str
    encoding: str
    exists: str
    absent_a: str
    absent_b: str
    target: str


def _absent_tail(model: str, nonce: str) -> str:
    """A tail of the same length as `model` with its separators and dots in the same places."""
    out, k = [], 0
    for ch in model:
        if ch in "/\\.":
            out.append(ch)
        else:
            out.append(nonce[k % len(nonce)])
            k += 1
    return "".join(out)


def _encode_seps(text: str, sep: str, encoded: str) -> str:
    return text.replace(sep, encoded) if encoded else text


def build_traversal_twins(*, depth: int = 6, nonces=None, max_twins: int = 3) -> list:
    """Shape-identical exists/absent payload triples, one per platform × encoding.

    The absent targets are random per call: a fixed absent name would eventually exist somewhere, and
    a target that learned the name could answer "exists" to both halves and defeat the oracle."""
    if not nonces:
        nonces = [os.urandom(10).hex(), os.urandom(10).hex()]
    na, nb = (list(nonces) + list(nonces))[:2]
    # (encoding label, encoded form of the separator; None = literal)
    encodings = (("raw", None), ("url", "%2f"))
    twins = []
    for label, model, sep in _TWIN_MODELS:
        for enc_label, enc in encodings:
            if enc and sep != "/":
                continue                      # %2f only rewrites a forward slash
            prefix = (".." + _encode_seps(sep, sep, enc)) * depth
            twins.append(TraversalTwin(
                label=label, encoding=enc_label, target=model,
                exists=prefix + _encode_seps(model, sep, enc),
                absent_a=prefix + _encode_seps(_absent_tail(model, na), sep, enc),
                absent_b=prefix + _encode_seps(_absent_tail(model, nb), sep, enc)))
    return twins[:max_twins]


def _decode_echo(text: str) -> str:
    """Undo the two transports an application uses when it echoes a path back: HTML entity escaping
    (the OWASP Benchmark writes `/` as `&#x2f;`) and percent-encoding."""
    try:
        text = _html.unescape(text or "")
    except Exception:
        pass
    try:
        text = unquote_plus(text)
    except Exception:
        pass
    return text


def redact_payload_echo(body: str, payloads) -> str:
    """`body` with every trace of the probe values removed.

    This is what makes the differential sound. Two responses to two different payloads always differ —
    by the payloads. Strip the payload, its decoded form, its individual path segments and the path
    punctuation left behind, and whatever still differs is text the APPLICATION produced, not text we
    supplied. On a pure-echo endpoint the redacted responses are identical."""
    text = _decode_echo(body or "")
    variants, tokens = set(), set()
    for p in payloads or []:
        if not p:
            continue
        d = _decode_echo(p)
        variants.update({p, d, d.replace("/", "\\"), d.replace("\\", "/")})
        for tok in re.split(r"[^A-Za-z0-9_\-]+", d):
            tok = tok.strip(".")
            if len(tok) >= 2:
                tokens.add(tok)
    for v in sorted(variants, key=len, reverse=True):
        text = re.sub(re.escape(v), " ", text, flags=re.I)
    # ...then the segments on their own, so an app that echoes the RESOLVED path (`/etc/passwd`
    # after normalising the `../`) is still recognised as echo rather than as evidence.
    for tok in sorted(tokens, key=len, reverse=True):
        text = re.sub(r"(?<![A-Za-z0-9])%s(?![A-Za-z0-9])" % re.escape(tok), " ", text, flags=re.I)
    text = re.sub(r"[\\/.]+", " ", text)
    return " ".join(text.split())


def _redacted(text: str, payloads) -> str:
    """The comparable form of a response: its body with every echoed payload removed.

    Exists so the two CONTROLS can ask for equality while `unexplained_divergence` keeps its
    `min_chars` floor for the job that floor is for — naming EVIDENCE a human will read. One function
    was serving both purposes, and the threshold that stops a 1-character diff being quoted as proof
    is the same threshold that let a nondeterministic page pass as deterministic (fp42).
    """
    return redact_payload_echo(text or "", payloads)


def unexplained_divergence(text_a: str, text_b: str, payloads, *, min_chars: int = 3):
    """The first difference between two responses that the echoed payloads CANNOT account for.

    Returns the evidence snippet, or None when every difference is echo. This is the whole point of
    the rewritten oracle: reflection is not evidence, so any difference explained by reflection is
    discarded before the responses are compared."""
    a = redact_payload_echo(text_a, payloads)
    b = redact_payload_echo(text_b, payloads)
    if a == b:
        return None
    for tag, i1, i2, j1, j2 in SequenceMatcher(None, a, b).get_opcodes():
        if tag == "equal":
            continue
        for chunk in (b[j1:j2], a[i1:i2]):
            if len(re.sub(r"[^A-Za-z0-9]+", "", chunk)) >= min_chars:
                return chunk.strip()[:200]
    return None


def _content_signature(probe_text: str, base_text: str):
    """A known system file's interior, present in the probe response and absent from the baseline."""
    low = (probe_text or "").lower()
    base_low = (base_text or "").lower()
    for needle, reason in FILE_CONTENT_SIGNATURES:
        if needle in low and needle not in base_low:
            return reason
    return None


def analyze_traversal_pair(baseline, probe, payload: str, *, lab_mode: bool = False):
    """A SINGLE request can confirm traversal only when the response carries content the parameter
    could not have supplied.

    HISTORY, and the reason this is written the way it is: this function used to return
    `confirmed` whenever the probe value appeared in the response — so an application that echoes its
    input produced a confirmed path traversal for a payload with no `../` in it, and for a string that
    was not a filename at all. 22 clean OWASP Benchmark cases carried one, and the whole pathtraver
    score rested on it (docs/LEDGERS.md, RETRACTION 2026-08-10). Reflection now yields a LEAD:
    the parameter reaches the page, which is worth the follow-up differential
    (`analyze_traversal_differential`), and is not by itself evidence that any file was read."""
    base_text = text_from_response(baseline)
    probe_text = text_from_response(probe)
    low = probe_text.lower()
    status = _status_of(probe)
    base_status = _status_of(baseline)
    similarity = _body_similarity(base_text, probe_text)

    signature = _content_signature(probe_text, base_text)
    if signature:
        return {"severity": "high", "confidence": "confirmed", "oracle": "file-content-signature",
                "reason": signature, "similarity": similarity}

    if "bbh-canary" in low or "yggdrasil-canary" in low or "olympus-canary" in low:
        return {"severity": "info", "confidence": "lead", "oracle": "reflection",
                "reason": "probe value reflected — the parameter reaches the response, but nothing "
                          "shows a file was read; needs the exists/absent differential",
                "similarity": similarity}

    weak = [hint for hint in TRAVERSAL_RESPONSE_HINTS
            if hint in low and hint not in base_text.lower()]
    if weak and status >= 400 and similarity < 0.98:
        return {"severity": "low", "confidence": "lead", "oracle": "file-error",
                "reason": f"file/path error after traversal probe: {weak[0]} — proves a file sink, "
                          f"not a successful escape", "similarity": similarity}
    if status != base_status and status in (200, 206, 400, 403, 404, 500) and similarity < 0.80:
        return {"severity": "info", "confidence": "lead", "oracle": "response-differential",
                "reason": f"status/body changed from {base_status} to {status}", "similarity": similarity}
    return None


def analyze_traversal_differential(exists_resp, absent_a_resp, absent_b_resp, twin,
                                   *, baseline=None, exists_repeat=None):
    """CONFIRM path traversal from a three-request, two-sided experiment.

    Requests, all with the same parameter and shape-identical payloads:
      exists   -> `../../../../etc/passwd`      (must exist on the far side of the escape)
      absent_a -> `../../../../q7x/a1b2c3`      (cannot exist)
      absent_b -> `../../../../z3k/d4e5f6`      (cannot exist, different name)

    Confirmation requires all of:
      1. the two ABSENT responses agree once the echo is redacted — otherwise the endpoint is
         nondeterministic (a request id, a timestamp) and any difference is noise, not a file system;
      2. the EXISTS response diverges from them in a way the echoed payload cannot explain;
    and the shortcut of (0) the response simply containing the file's contents.

    A reflecting endpoint fails (2) by construction: redaction removes the only thing that differed.

    (3) THE ORDER CONTROL, added 2026-08-14 after a MEASURED false positive. The two checks above
    control for echo and for noise; neither controls for the request ORDER. On a stateful endpoint the
    first request differs from every later one, and whichever payload happens to go first inherits
    that difference. Reproduced against the live lab on `weakrand-00/BenchmarkTest00187`, a case
    vulnerable to nothing:

        order [exists, absent_a, absent_b]  -> exists   'has been remembered with cookie: ...'
                                              absent_a  'Welcome back: ...'
                                              absent_b  'Welcome back: ...'   => CONFIRMED
        order [absent_a, exists, absent_b]  => None      (the divergence moved to absent_a)
        order [absent_a, absent_b, exists]  => None

    The absent pair agreed, the exists response diverged, and the difference was not the echoed
    payload -- every stated requirement was met by a session cookie. So `exists` is now REPEATED, and
    a divergence counts only if it survives the repeat: a file system answers the same way twice,
    while a first-request artifact (session establishment, cache miss, connection warm-up) does not.
    Same discipline as Q-040 -- the reference must REPRODUCE, not merely resemble.

    Without `exists_repeat` the caller has run no such control, so the strongest verdict available is
    a LEAD. Silently confirming without it is what this function did on 2026-08-14."""
    e_text = text_from_response(exists_resp)
    a_text = text_from_response(absent_a_resp)
    b_text = text_from_response(absent_b_resp)
    base_text = text_from_response(baseline) if baseline is not None else ""
    e_st, a_st, b_st = (_status_of(exists_resp), _status_of(absent_a_resp), _status_of(absent_b_resp))
    payloads = [twin.exists, twin.absent_a, twin.absent_b]

    signature = _content_signature(e_text, base_text)
    if signature:
        return {"severity": "high", "confidence": "confirmed", "oracle": "file-content-signature",
                "reason": signature, "payload": twin.exists, "twin": twin.label}

    # (1) determinism control — the negative control that keeps a noisy page from confirming.
    #
    # STRICT EQUALITY, not "no nameable divergence" (fp42). This asked
    # `unexplained_divergence(a_text, b_text)`, which returns a snippet only when some diff chunk holds
    # >= 3 alphanumerics. SequenceMatcher chops two random 9-10 digit integers into 1-2 character
    # chunks, so MEASURED over 5000 draws from a pool of 300 real responses, a page whose 300/300
    # responses were DISTINCT was certified deterministic 3.38% of the time and confirmed traversal
    # 2.98% of the time. Masking the random integer dropped that to 0/5000 — the integer was the whole
    # cause. The docstring already said the absent pair must "agree once the echo is redacted"; that is
    # equality, and the code was asking a weaker question than the sentence describing it.
    if a_st != b_st or _redacted(a_text, payloads) != _redacted(b_text, payloads):
        return None

    # (3) the ORDER control. Judged before any verdict is built, so every path below inherits it.
    #     `graded()` is the single place that decides confirmed-vs-lead, because two call sites
    #     deciding it independently is how one of them ends up not deciding it at all.
    r_text = text_from_response(exists_repeat) if exists_repeat is not None else None
    r_st = _status_of(exists_repeat) if exists_repeat is not None else None

    def graded(verdict: dict, *, holds: bool) -> dict:
        if exists_repeat is None:
            verdict.update(confidence="lead", severity="medium",
                           reason=verdict["reason"] + " — NOT REPEATED: without a second `exists` "
                                  "request this cannot be told apart from a first-request artifact "
                                  "(session establishment, cache miss), so it is reported as a lead")
            return verdict
        # The repeat must REPRODUCE the original exists, not merely still differ from the absent pair
        # (fp42). Q-047's repeat was aimed at a FIRST-REQUEST artifact: the first response differs, the
        # repeat does not, the divergence dies. It cannot catch the complementary EVERY-REQUEST
        # artifact, because a per-request random value makes the repeat diverge from the absents
        # exactly as the original did — `holds` is satisfied and the reason even gains the words "it
        # REPRODUCED". Requiring the repeat to be IDENTICAL to the first `exists` after echo redaction
        # closes both: a file system serves the same bytes twice, a random page does not. Same rule as
        # Q-040 — the reference must REPRODUCE, not merely resemble.
        if not holds or _redacted(r_text, payloads) != _redacted(e_text, payloads):
            return None
        verdict["reason"] += " — and it REPRODUCED on a repeat of the same request"
        verdict["repeat_control"] = ("the exists response was byte-identical on a repeat, after echo "
                                     "redaction, and still diverged from both absent twins")
        return verdict

    # (2) the present/absent divergence. A status code cannot be echoed, so it counts on its own.
    if e_st != a_st:
        return graded({"severity": "high", "confidence": "confirmed",
                       "oracle": "existence-differential",
                       "reason": f"'{twin.target}' answered {e_st} where an absent file of identical "
                                 f"shape answered {a_st} twice — the path was resolved against the "
                                 f"file system outside the application directory",
                       "payload": twin.exists, "twin": twin.label},
                      holds=(r_st == e_st and r_st != a_st))
    evidence = unexplained_divergence(e_text, a_text, payloads)
    if evidence and unexplained_divergence(e_text, b_text, payloads):
        return graded({"severity": "high", "confidence": "confirmed",
                       "oracle": "existence-differential",
                       "reason": f"'{twin.target}' produced a response an absent file of identical "
                                 f"shape did not, twice over, and the difference is not the echoed "
                                 f"payload: {evidence!r}",
                       "payload": twin.exists, "twin": twin.label, "evidence": evidence},
                      holds=bool(r_text is not None
                                 and unexplained_divergence(r_text, a_text, payloads)
                                 and unexplained_divergence(r_text, b_text, payloads)))
    return None


def analyze_idor_pair(baseline, replay, *, cross_role: bool):
    base_text = text_from_response(baseline)
    replay_text = text_from_response(replay)
    base_status = _status_of(baseline)
    replay_status = _status_of(replay)
    if replay_status not in range(200, 300):
        return None
    if len(replay_text) < 40:
        return None
    similarity = _body_similarity(base_text, replay_text)
    sensitive = bool(SENSITIVE_RESPONSE_WORDS.search(replay_text))
    if cross_role and similarity > 0.88:
        return {"severity": "high" if sensitive else "medium", "confidence": "probable",
                "reason": "alternate auth profile received near-identical object response",
                "similarity": similarity}
    if not cross_role and base_status in range(200, 300) and 0.15 < similarity < 0.95 and sensitive:
        return {"severity": "low", "confidence": "possible",
                "reason": "neighboring object ID returned sensitive-looking object data",
                "similarity": similarity}
    return None


def generate_discovery_words(base_url: str, urls: list | None = None) -> list:
    words = set(DEFAULT_DISCOVERY_WORDS)
    parsed = urlparse(base_url)
    host_root = (parsed.hostname or "").split(".")[0]
    if host_root:
        words.update({host_root, f"{host_root}-admin", f"{host_root}-api", f"{host_root}.bak"})
    for raw in urls or []:
        p = urlparse(raw)
        for part in p.path.split("/"):
            part = part.strip()
            if 2 < len(part) < 50 and not part.startswith("{"):
                words.add(part)
                words.add(part + ".bak")
                words.add(part + ".old")
                words.add(part + "~")
        for name, _ in parse_qsl(p.query, keep_blank_values=True):
            if 2 < len(name) < 50:
                words.add(name)
    normalized = []
    for word in sorted(words):
        clean = word.strip().lstrip("/")
        if clean and ".." not in clean:
            normalized.append(clean)
    return normalized


def normalize_discovered_url(base_url: str, word: str) -> str:
    parsed = urlparse(base_url)
    clean_path = posixpath.normpath("/" + word.lstrip("/"))
    if clean_path == "/.":
        clean_path = "/"
    return urlunparse(parsed._replace(path=clean_path, query="", fragment=""))


# ── Reflection-based injection probes (CORS / redirect / host-hdr / SSTI) ──
REDIRECT_PARAM_HINTS = {
    "next", "url", "target", "redirect", "redir", "redirect_uri", "redirecturi",
    "redirect_url", "redirecturl", "redirect_to", "return", "returnurl", "return_url",
    "returnto", "ret", "dest", "destination", "continue", "goto", "out", "view",
    "to", "u", "n", "r", "uri", "link", "forward", "forwardurl", "forward_url",
    "relaystate", "callback", "checkout_url", "image_url", "go", "login_url",
}
SSTI_PARAM_HINTS = {
    "name", "search", "q", "query", "message", "email", "template",
    "greeting", "title", "subject", "comment", "text", "content",
}
_EVIL_HOST = "bbh-evil.example"
# Open-redirect payloads incl. filter-bypass forms from Bug Bounty Bootcamp Ch 7
# (scheme autocorrect, backslash, @-userinfo, whitespace, encoded slash). All
# resolve to bbh-evil.example so the analyzer's host match fires on a hit.
_REDIRECT_PAYLOADS = (
    "https://bbh-evil.example",          # plain absolute
    "//bbh-evil.example",                # scheme-relative
    "/\\bbh-evil.example",               # backslash autocorrect
    "https:/\\bbh-evil.example",         # mangled scheme
    "https:bbh-evil.example",            # scheme autocorrect (no //)
    "https://legit.example@bbh-evil.example",   # @ userinfo trick
    "https://bbh-evil.example%2f@legit.example",  # encoded-slash + @ confusion
    "/%2f%2fbbh-evil.example",           # encoded scheme-relative
    "https://bbh-evil.example/%2e%2e",   # path-normalization noise
)
_SSTI_PAYLOAD = "{{7*7}}${7*7}"     # detect 49 from either engine
_SSTI_MARKER = "49"


def analyze_cors(origin: str, resp_headers: dict) -> dict | None:
    """Flag a CORS misconfig: the request Origin is reflected in ACAO, worst when
    Access-Control-Allow-Credentials is also true."""
    h = {str(k).lower(): str(v) for k, v in (resp_headers or {}).items()}
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower() == "true"
    if acao == origin:
        sev = "HIGH" if acac else "MEDIUM"
        detail = "reflected arbitrary Origin" + (" WITH credentials" if acac else "")
        return {"severity": sev, "detail": detail, "acao": acao, "credentials": acac}
    if acao == "*" and acac:
        return {"severity": "HIGH", "detail": "wildcard ACAO with credentials", "acao": "*", "credentials": True}
    return None


def analyze_open_redirect(status: int, location: str, final_url: str) -> dict | None:
    """Flag an open redirect: a 3xx Location (or followed final URL) lands on the
    attacker host we injected."""
    target = (location or final_url or "")
    tl = target.lower()
    if _EVIL_HOST in tl and (300 <= (status or 0) < 400 or _EVIL_HOST in (final_url or "").lower()):
        return {"severity": "MEDIUM", "detail": f"redirect follows attacker host: {target[:120]}",
                "location": target}
    return None


#: Response headers that prove a SHARED cache handled this response. A poisoned redirect is only
#: dangerous if something stores it and serves it to somebody else.
_CACHE_EVIDENCE = ("age", "x-cache", "cf-cache-status", "via", "x-served-by", "x-cache-hits",
                   "x-varnish", "fastly-debug-digest")


def host_header_sinks(resp_headers=None, xfh_location=None) -> list:
    """Which sink, if any, could turn a Host-reflecting redirect into an actual attack.

    Q-114. Returns the sinks found, `[]` when the caller probed and found none. Callers that did NOT
    probe pass nothing and must not read `[]` as evidence of absence -- `analyze_host_header` keeps
    that distinction, following Q-103's rule that "not supplied" and "supplied and empty" are
    different facts.
    """
    sinks = []
    hdrs = {str(k).lower(): str(v) for k, v in (resp_headers or {}).items()}
    if any(h in hdrs for h in _CACHE_EVIDENCE):
        sinks.append("shared cache (%s)" % ", ".join(sorted(h for h in _CACHE_EVIDENCE if h in hdrs)))
    cc = hdrs.get("cache-control", "").lower()
    if "s-maxage" in cc or ("public" in cc and "no-store" not in cc):
        sinks.append("Cache-Control permits shared storage (%s)" % cc[:60])
    if xfh_location:
        try:
            if (urlparse(xfh_location).hostname or "").lower() == _EVIL_HOST:
                sinks.append("X-Forwarded-Host is honoured (reverse-proxy route into the same primitive)")
        except Exception:
            pass
    return sinks


def analyze_host_header(body: str, location: str, resp_headers=None, xfh_location=None) -> dict | None:
    """Flag host-header injection: the spoofed Host BECAME the redirect target's host.

    Q-106b -- the same defect shape as the CRLF oracle, found by auditing its neighbours after that
    one reported a false HIGH on a live target. `_EVIL_HOST in location` is a SUBSTRING test, so it
    fires on a Location that merely CONTAINS the string anywhere:

        Location: https://legit.example/login?next=https%3A%2F%2Fbbh-evil.example
        Location: https://legit.example/?ref=bbh-evil.example

    Neither is host-header injection. The first is an open-redirect parameter (a different finding,
    with its own engine) and the second is a query echo. The claim this oracle makes -- "the app
    trusts the Host header" -- is only supported when the spoofed host is the AUTHORITY the victim
    would actually be sent to.

    So the test is structural: parse the Location and require `hostname == _EVIL_HOST`. A relative
    Location cannot carry a host at all and is now correctly silent, where the substring test would
    have matched `/redir?to=bbh-evil.example`.

    The BODY branch stays a substring test on purpose. It is already LOW, it claims only reflection
    rather than a redirect primitive, and a host string in HTML has no structure to parse.

    Q-114 -- THE GRADE IS NOW MEASURED, NOT ASSERTED. The Shopify engagement raised 8 of these on
    linkpop.com and the operator reproduced one by hand:

        curl -is https://linkpop.com/054470-ee -H 'Host: bbh-evil.example'
        HTTP/1.1 301 Moved Permanently
        Location: https://bbh-evil.example/054470-ee/index.html?s=1
        Server: UploadServer

    The behaviour is REAL and this oracle was right to fire. The MEDIUM was not earned: he probed
    both sinks and neither existed -- no cache headers at all (no Age / X-Cache / CF-Cache-Status /
    Via) so nothing stores the poisoned redirect for a second visitor, and X-Forwarded-Host was
    ignored so the reverse-proxy route into the same primitive is absent too. `Server: UploadServer`
    is a Google Cloud Storage bucket website, where building the redirect from the supplied Host is
    stock platform behaviour rather than an application defect. The right output was INFORMATIONAL.

    That is the Q-106 lesson moved one layer, from the oracle to the grade: detection was sound and
    severity was asserted. A MEDIUM sent to a mature program on this evidence is closed N/A, and N/A
    closures cost the reporter signal.

    `resp_headers`/`xfh_location` OMITTED means the caller did not probe, and the grade is unchanged
    -- absence of evidence is not evidence of absence, and a caller that cannot probe must not be
    silently credited with a negative result.
    """
    loc = (location or "").strip()
    if loc:
        try:
            host = (urlparse(loc).hostname or "").lower()
        except Exception:
            host = ""
        if host == _EVIL_HOST:
            probed = resp_headers is not None or xfh_location is not None
            sinks = host_header_sinks(resp_headers, xfh_location) if probed else []
            if not probed:
                return {"severity": "MEDIUM",
                        "detail": f"spoofed Host became the redirect target: {loc[:120]}"}
            if sinks:
                return {"severity": "MEDIUM", "sinks": sinks,
                        "detail": f"spoofed Host became the redirect target: {loc[:120]} "
                                  f"-- exploitable through {'; '.join(sinks)}"}
            return {"severity": "INFORMATIONAL", "sinks": [],
                    "detail": f"spoofed Host became the redirect target: {loc[:120]} -- but NO sink "
                              "was found: the response carries no shared-cache indicator "
                              "(Age/X-Cache/CF-Cache-Status/Via) and X-Forwarded-Host is not "
                              "honoured, so the poisoned redirect reaches nobody but the requester. "
                              "Reportable only if a cache or a proxy route is demonstrated"}
    if _EVIL_HOST in (body or "").lower():
        return {"severity": "LOW", "detail": "spoofed Host reflected in response body"}
    return None


def analyze_ssti(baseline_body: str, probe_body: str) -> dict | None:
    """Flag SSTI/CSTI: the arithmetic marker 49 appears only after injection."""
    if _SSTI_MARKER in (probe_body or "") and _SSTI_MARKER not in (baseline_body or ""):
        return {"severity": "HIGH", "detail": "template expression {{7*7}}/${7*7} evaluated to 49"}
    return None


# ── CRLF / response-header injection ─────────────────────────────
CRLF_MARKER = "bbhcrlf"


def build_crlf_probes(url: str, max_probes: int = 6) -> list:
    """One probe per query param: append an encoded CRLF + a marker header. If the
    app writes the value into a response header (e.g. Set-Cookie) unescaped, the
    header block splits and our marker header appears in the response."""
    inj = f"\r\nX-{CRLF_MARKER}: {CRLF_MARKER}pwned"
    probes = []
    for name, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
        probes.append(WebProbe(url=_replace_query_value(url, name, (value or "1") + inj),
                               parameter=name, original_value=value, payload=inj, family="crlf"))
        if len(probes) >= max_probes:
            break
    return probes


def analyze_crlf(resp_headers: dict, resp_status: int = 0) -> dict | None:
    """Confirmed ONLY when our injected marker became its OWN HEADER NAME.

    Q-106 / Q-106c. This reported a false HIGH against a live bug-bounty target TWICE.

    Round one: the test was `marker in header_name OR "bbhcrlfpwned" in header_value`, justified by
    "the marker cannot occur naturally". Our payload is in the request URL, so any app echoing that
    URL into a header hands it back. `linkpop.com` returned it inside `Location` with `%0D%0A` still
    encoded. I tightened the VALUE branch to reject a still-encoded CRLF and kept it.

    Round two proved that was the wrong repair. `partners.shopify.com` returned:

        location: .../organizations?redirect_to=...itcat%3Dpartner_blog%250D%250AX-bbhcrlf%253A%2Bbbhcrlfpwned

    **`%250D%250A` -- DOUBLE-encoded.** The server URL-encoded our input into a `redirect_to`
    parameter, so my single-encoding check missed it. Chasing encodings is unwinnable: there is
    always another layer.

    THE VALUE BRANCH HAS NO LEGITIMATE CASE, which is why it is gone rather than tightened. A real
    response split is parsed BY THE HTTP CLIENT as a separate header, so the marker arrives as a
    KEY -- including the Set-Cookie sink, where `Set-Cookie: a=b
X-bbhcrlf: pwned` reaches us as
    two parsed headers, not one value. If the marker only ever appears inside a value, nothing split
    and we are reading our own request back.

    Two field false positives, zero true positives, and no mechanism by which a value-only match
    could be real. The key test is the whole oracle.
    """
    for k in (resp_headers or {}):
        if CRLF_MARKER in str(k).lower():
            return {"severity": "HIGH",
                    "detail": f"injected header surfaced in the response ({k}) — response-splitting/"
                              "header-injection primitive (cache poisoning, cookie/redirect injection)"}
    return None


def build_redirect_probes(url: str, max_probes: int = 6) -> list:
    probes = []
    for name, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
        if name.lower() in REDIRECT_PARAM_HINTS:
            for pl in _REDIRECT_PAYLOADS:
                probes.append(WebProbe(url=_replace_query_value(url, name, pl),
                                       parameter=name, original_value=value, payload=pl,
                                       family="open_redirect"))
                if len(probes) >= max_probes:
                    return probes
    return probes


def build_ssti_probes(url: str, max_probes: int = 6) -> list:
    probes = []
    for name, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
        if name.lower() in SSTI_PARAM_HINTS or (value and value.isalpha()):
            probes.append(WebProbe(url=_replace_query_value(url, name, _SSTI_PAYLOAD),
                                   parameter=name, original_value=value, payload=_SSTI_PAYLOAD,
                                   family="ssti"))
            if len(probes) >= max_probes:
                return probes
    return probes


# ── Sensitive-path body validation ────────────────────────────────
_ENV_KV_RE = re.compile(r"^[A-Z_][A-Z0-9_]{2,}\s*=\s*\S+", re.MULTILINE)
_SECRET_KEYWORDS_RE = re.compile(
    r"(API[_-]?KEY|SECRET[_-]?KEY|SECRET|PASSWORD|DB_PASS|ACCESS_TOKEN|PRIVATE_KEY|AWS_(?:ACCESS|SECRET))",
    re.IGNORECASE)
_GIT_HEAD_RE = re.compile(r"^ref:\s*refs/|^[0-9a-f]{40}\s*$", re.MULTILINE)
_GIT_CONFIG_RE = re.compile(r"\[core\]|repositoryformatversion", re.IGNORECASE)
_ACTUATOR_ENV_RE = re.compile(r'"propertySources"|"activeProfiles"', re.IGNORECASE)
_ACTUATOR_HEALTH_RE = re.compile(r'"status"\s*:\s*"(UP|DOWN)"', re.IGNORECASE)
_API_SCHEMA_RE = re.compile(r'"(swagger|openapi)"\s*:|("paths"\s*:.*"info"\s*:)', re.IGNORECASE | re.DOTALL)
_APACHE_STATUS_RE = re.compile(r"apache server status|scoreboard", re.IGNORECASE)
_PROMETHEUS_METRICS_RE = re.compile(r"^# (HELP|TYPE) ", re.MULTILINE)
_SECURITY_TXT_RE = re.compile(r"^Contact:", re.MULTILINE | re.IGNORECASE)
_PHP_CONFIG_RE = re.compile(r"<\?php|define\s*\(|\$config\b", re.IGNORECASE)
_GENERIC_HTML_RE = re.compile(r"<div id=[\"'](root|app|__next|___gatsby)[\"']", re.IGNORECASE)
# A response leaking multiple credential/secret VALUES in a data structure — e.g. an
# unauthenticated debug endpoint dumping user records with passwords. Matches a JSON
# key/value like "password":"pass1"; requiring >=2 avoids a lone login form/doc.
_CREDS_DUMP_RE = re.compile(
    r'"(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|'
    r'private[_-]?key|client[_-]?secret|session[_-]?token)"\s*:\s*"[^"]{1,}"', re.IGNORECASE)
_DIR_LISTING_RE = re.compile(r"Index of /|<title>Index of", re.IGNORECASE)
_ARCHIVE_CT_RE = re.compile(r"zip|x-tar|gzip|octet-stream|x-7z|x-rar", re.IGNORECASE)


def _sensitive_hit(title, severity, cvss, description, remediation, evidence="", confidence="confirmed"):
    # A specific body-signature match (real .env content, a git ref, an actuator JSON,
    # a credentials dump) IS evidence-backed confirmation, so it defaults to confirmed.
    # The generic "endpoint reachable" fallback passes confidence="candidate" (a Lead).
    return {"title": title, "severity": severity, "cvss": cvss,
            "description": description, "remediation": remediation, "evidence": evidence,
            "confidence": confidence, "family": "exposure"}


def classify_sensitive_path_hit(path: str, status_code: int, body: str,
                                 content_type: str = "", baseline_body: str = ""):
    """Validate a candidate sensitive-path hit's BODY before treating it as a real
    exposure. HTTP 200 alone proves nothing — a catch-all SPA returns the same
    shell for every path. Returns a finding-shape dict for a validated hit, or
    None to suppress."""
    if status_code != 200:
        return None
    body = body or ""
    content_type = (content_type or "").lower()
    low_path = (path or "").lower()

    if baseline_body and len(baseline_body) > 40 and _body_similarity(body, baseline_body) >= 0.92:
        return None

    if low_path.endswith(".env"):
        if _ENV_KV_RE.search(body) or _SECRET_KEYWORDS_RE.search(body):
            return _sensitive_hit("Environment file exposed", "high", 8.6,
                "The .env file returned real KEY=VALUE configuration/secret-shaped content.",
                "Move secrets out of the webroot; block dotfiles at the edge; rotate any leaked credentials.",
                "Body matched environment-variable / secret-keyword pattern.")
        return None
    if low_path.endswith("/.git/head") or low_path.endswith(".git/head"):
        if _GIT_HEAD_RE.search(body):
            return _sensitive_hit("Git repository exposed (.git/HEAD)", "high", 7.5,
                ".git/HEAD returned a real git ref, confirming the .git directory is web-accessible.",
                "Block /.git/ at the edge and remove repository metadata from the webroot.",
                "Body matched a git ref / commit-hash pattern.")
        return None
    if low_path.endswith("/.git/config") or low_path.endswith(".git/config"):
        if _GIT_CONFIG_RE.search(body):
            return _sensitive_hit("Git config exposed", "high", 7.5,
                ".git/config returned real git configuration content.",
                "Block /.git/ at the edge and remove repository metadata from the webroot.",
                "Body matched [core] / repositoryformatversion.")
        return None
    if "actuator/env" in low_path:
        if _ACTUATOR_ENV_RE.search(body):
            return _sensitive_hit("Spring actuator environment exposed", "high", 8.1,
                "The actuator env endpoint returned real Spring property-source data.",
                "Disable or authenticate actuator env endpoints.",
                "Body matched Spring Boot actuator env JSON shape.")
        return None
    if "actuator/health" in low_path:
        if _ACTUATOR_HEALTH_RE.search(body):
            return _sensitive_hit("Spring actuator health exposed", "medium", 5.3,
                "The actuator health endpoint returned a real UP/DOWN status payload.",
                "Restrict actuator endpoints to trusted networks.",
                "Body matched actuator health status JSON.")
        return None
    if "swagger" in low_path or "openapi" in low_path:
        if _API_SCHEMA_RE.search(body):
            return _sensitive_hit("API schema exposed", "medium", 5.3,
                "The endpoint returned a real OpenAPI/Swagger schema document.",
                "Restrict API documentation in production if it reveals sensitive operations.",
                "Body matched swagger/openapi schema shape.")
        return None
    if "server-status" in low_path:
        if _APACHE_STATUS_RE.search(body):
            return _sensitive_hit("Apache server-status exposed", "medium", 5.3,
                "mod_status returned real scoreboard/server-status content.",
                "Disable or restrict server-status to trusted networks.",
                "Body matched Apache Server Status page markers.")
        return None
    if "metrics" in low_path:
        if _PROMETHEUS_METRICS_RE.search(body):
            return _sensitive_hit("Metrics endpoint exposed", "medium", 5.3,
                "The endpoint returned real Prometheus-format metrics.",
                "Restrict metrics endpoints to trusted networks.",
                "Body matched Prometheus exposition format (# HELP/# TYPE).")
        return None
    if "security.txt" in low_path:
        if _SECURITY_TXT_RE.search(body):
            return _sensitive_hit("security.txt present", "info", 0.0,
                "A well-known security.txt was found (informational, not a vulnerability).",
                "No action required; this is expected disclosure-policy metadata.",
                "Body matched RFC 9116 Contact: field.")
        return None
    if "config" in low_path and not any(s in low_path for s in ("actuator", "swagger", "openapi")):
        if _PHP_CONFIG_RE.search(body) and not _GENERIC_HTML_RE.search(body):
            return _sensitive_hit("Configuration file exposed", "high", 7.5,
                "The path returned real configuration-file content (PHP tags / config directives), not a generic page.",
                "Move configuration files out of the webroot; restrict access at the edge.",
                "Body matched PHP config markers and did not match a generic HTML shell.")
        return None
    if "backup" in low_path or low_path.endswith((".bak", ".zip", ".tar", ".tar.gz", ".sql", ".old")):
        if not _GENERIC_HTML_RE.search(body) and (
            _ARCHIVE_CT_RE.search(content_type) or _DIR_LISTING_RE.search(body)
            or re.search(r"backup|dump", body, re.IGNORECASE)):
            return _sensitive_hit("Backup/archive exposed", "high", 7.5,
                "The path returned archive/backup-shaped content, not a generic page.",
                "Remove backup/archive files from the webroot; restrict access at the edge.",
                "Body/content-type matched a backup or directory-listing signature.")
        return None

    # Credentials / secrets DUMP anywhere: a body leaking multiple secret VALUES
    # (e.g. an unauthenticated /_debug returning users with passwords). Checked here
    # so any path qualifies; >=2 matches keeps a single login form/doc from tripping it.
    if not _GENERIC_HTML_RE.search(body):
        n_creds = len(_CREDS_DUMP_RE.findall(body or ""))
        if n_creds >= 2:
            return _sensitive_hit("Sensitive data / credentials exposed", "critical", 9.1,
                "The endpoint returned a data body leaking multiple credential/secret values "
                "(e.g. user records with passwords) without authentication.",
                "Remove or authenticate the endpoint; treat every exposed credential as compromised "
                "and rotate it.",
                f"Response body contained {n_creds} credential/secret value(s) in a data response.")

    if _GENERIC_HTML_RE.search(body):
        return None
    return _sensitive_hit(f"Endpoint reachable: {path}", "low", 3.1,
        f"{path} returned HTTP 200 with content that does not look like the site's generic page. "
        "Manual review recommended to determine sensitivity.",
        "Review whether this endpoint should be publicly reachable; restrict if not intended.",
        "No specific sensitive-content signature matched; recorded as a low-confidence candidate.",
        confidence="candidate")   # unvalidated -> stays a Lead, never a confirmed finding
