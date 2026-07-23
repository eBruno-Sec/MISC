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
import posixpath
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

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
)

TRAVERSAL_LAB_PAYLOADS = (
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
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
    for name, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
        if not looks_pathlike(name, value):
            continue
        for payload in payloads:
            probes.append(WebProbe(
                url=_replace_query_value(url, name, payload),
                parameter=name, original_value=value, payload=payload,
                family="path_traversal"))
            if len(probes) >= max_probes:
                return probes
    return probes


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


def analyze_traversal_pair(baseline, probe, payload: str, *, lab_mode: bool = False):
    base_text = text_from_response(baseline)
    probe_text = text_from_response(probe)
    low = probe_text.lower()
    status = _status_of(probe)
    base_status = _status_of(baseline)
    similarity = _body_similarity(base_text, probe_text)

    strong = []
    if "root:x:0:0" in low or "[extensions]" in low or "[fonts]" in low:
        strong.append("sensitive file signature returned")
    if "bbh-canary" in low or "yggdrasil-canary" in low or "olympus-canary" in low:
        strong.append("canary filename reflected through file handling path")

    weak = [hint for hint in TRAVERSAL_RESPONSE_HINTS if hint in low]
    if strong:
        return {"severity": "high" if lab_mode else "medium",
                "confidence": "confirmed" if lab_mode else "probable",
                "reason": ", ".join(strong), "similarity": similarity}
    if weak and status >= 400 and similarity < 0.98:
        return {"severity": "medium", "confidence": "possible",
                "reason": f"file/path error after traversal probe: {weak[0]}", "similarity": similarity}
    if status != base_status and status in (200, 206, 400, 403, 404, 500) and similarity < 0.80:
        return {"severity": "low", "confidence": "possible",
                "reason": f"status/body changed from {base_status} to {status}", "similarity": similarity}
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


def analyze_host_header(body: str, location: str) -> dict | None:
    """Flag host-header injection: the spoofed Host is reflected into the response
    body or a redirect Location (link/cache/reset-poisoning primitive)."""
    if _EVIL_HOST in (location or "").lower():
        return {"severity": "MEDIUM", "detail": f"spoofed Host reflected in Location: {location[:120]}"}
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
    """Confirmed when our injected marker made it into the RESPONSE header block —
    either as its own header name or a value split into an existing header
    (Set-Cookie is the classic sink). Header-key/value match = a real split, so
    no baseline is needed (the marker cannot occur naturally)."""
    for k, v in (resp_headers or {}).items():
        kl, vl = str(k).lower(), str(v).lower()
        if CRLF_MARKER in kl or f"{CRLF_MARKER}pwned" in vl:
            where = k if CRLF_MARKER in kl else f"{k} (value split)"
            return {"severity": "HIGH",
                    "detail": f"injected header surfaced in the response ({where}) — response-splitting/"
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
