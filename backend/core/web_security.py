"""
Deterministic web-security primitives for Yggdrasil.

These helpers do not perform network I/O. Tyr owns transport, approval,
logging, and finding creation; this module owns scope decisions, probe
generation, response comparison, and wordlist shaping.
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
    "../yggdrasil-canary.txt",
    "..%2fyggdrasil-canary.txt",
    "%2e%2e%2fyggdrasil-canary.txt",
    "....//yggdrasil-canary.txt",
    "..\\yggdrasil-canary.txt",
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

HIGH_VALUE_EXPOSURE_PATHS = {
    "/.env": ("Environment file exposed", "high", "Move secrets out of webroot and block dotfiles at the edge."),
    "/.git/config": ("Git config exposed", "high", "Block .git paths and remove repository metadata from webroot."),
    "/.git/HEAD": ("Git repository exposed", "high", "Block .git paths and remove repository metadata from webroot."),
    "/actuator/env": ("Spring actuator environment exposed", "high", "Disable or authenticate actuator env endpoints."),
    "/actuator/health": ("Spring actuator health exposed", "medium", "Restrict actuator endpoints to trusted networks."),
    "/swagger.json": ("API schema exposed", "medium", "Restrict API documentation in production if it reveals sensitive operations."),
    "/openapi.json": ("OpenAPI schema exposed", "medium", "Restrict API documentation in production if it reveals sensitive operations."),
    "/graphql": ("GraphQL endpoint discovered", "medium", "Review introspection, authorization, and query complexity controls."),
    "/metrics": ("Metrics endpoint exposed", "medium", "Restrict metrics endpoints to trusted networks."),
    "/server-status": ("Server status endpoint exposed", "medium", "Disable or restrict server-status."),
}

SENSITIVE_RESPONSE_WORDS = re.compile(
    r"(?i)(email|username|user_id|userid|account|tenant|invoice|order|"
    r"customer|address|phone|ssn|token|secret|api[_-]?key|role|admin)"
)

TRAVERSAL_RESPONSE_HINTS = (
    "root:x:0:0",
    "[extensions]",
    "[fonts]",
    "boot loader",
    "no such file or directory",
    "failed to open stream",
    "permission denied",
    "directory traversal",
    "path traversal",
    "invalid path",
    "not allowed to load local resource",
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
    # Treat real hostnames/domains as host rules. Ignore prose accidentally
    # parsed from scope notes, such as "SQL injection" or "JavaScript".
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
    if rule_type in ("url", "ip"):
        return _looks_like_host_identifier(ident)
    if rule_type == "domain":
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


def build_traversal_probes(url: str, *, lab_mode: bool = False, max_probes: int = 12) -> list[WebProbe]:
    payloads = list(TRAVERSAL_SAFE_PAYLOADS)
    if lab_mode:
        payloads.extend(TRAVERSAL_LAB_PAYLOADS)

    probes: list[WebProbe] = []
    for name, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
        if not looks_pathlike(name, value):
            continue
        for payload in payloads:
            probes.append(WebProbe(
                url=_replace_query_value(url, name, payload),
                parameter=name,
                original_value=value,
                payload=payload,
                family="path_traversal",
            ))
            if len(probes) >= max_probes:
                return probes
    return probes


def build_idor_probes(url: str, max_probes: int = 8) -> list[WebProbe]:
    probes: list[WebProbe] = []
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
                            parameter=name,
                            original_value=value,
                            payload=str(candidate),
                            family="idor_query",
                        ))

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
                parameter=f"path[{i}]",
                original_value=part,
                payload=str(candidate),
                family="idor_path",
            ))
            if len(probes) >= max_probes:
                return probes
    return probes[:max_probes]


def text_from_response(response) -> str:
    text = getattr(response, "text", "")
    if text:
        return text
    content = getattr(response, "content", b"")
    if isinstance(content, bytes):
        return content.decode("utf-8", errors="replace")
    return str(content or "")


def _body_similarity(a: str, b: str) -> float:
    a = re.sub(r"\s+", " ", a or "")[:12000]
    b = re.sub(r"\s+", " ", b or "")[:12000]
    if not a and not b:
        return 1.0
    return SequenceMatcher(None, a, b).ratio()


def analyze_traversal_pair(baseline, probe, payload: str, *, lab_mode: bool = False) -> dict | None:
    base_text = text_from_response(baseline)
    probe_text = text_from_response(probe)
    low = probe_text.lower()
    status = getattr(probe, "status_code", 0)
    base_status = getattr(baseline, "status_code", 0)
    similarity = _body_similarity(base_text, probe_text)

    strong = []
    if "root:x:0:0" in low or "[extensions]" in low or "[fonts]" in low:
        strong.append("sensitive file signature returned")
    if "yggdrasil-canary" in low or "olympus-canary" in low:
        strong.append("canary filename reflected through file handling path")

    weak = [hint for hint in TRAVERSAL_RESPONSE_HINTS if hint in low]
    if strong:
        return {
            "severity": "high" if lab_mode else "medium",
            "confidence": "confirmed" if lab_mode else "probable",
            "reason": ", ".join(strong),
            "similarity": similarity,
        }
    if weak and status >= 400 and similarity < 0.98:
        return {
            "severity": "medium",
            "confidence": "possible",
            "reason": f"file/path error after traversal probe: {weak[0]}",
            "similarity": similarity,
        }
    if status != base_status and status in (200, 206, 400, 403, 404, 500) and similarity < 0.80:
        return {
            "severity": "low",
            "confidence": "possible",
            "reason": f"status/body changed from {base_status} to {status}",
            "similarity": similarity,
        }
    return None


def analyze_idor_pair(baseline, replay, *, cross_role: bool) -> dict | None:
    base_text = text_from_response(baseline)
    replay_text = text_from_response(replay)
    base_status = getattr(baseline, "status_code", 0)
    replay_status = getattr(replay, "status_code", 0)
    if replay_status not in range(200, 300):
        return None
    if len(replay_text) < 40:
        return None

    similarity = _body_similarity(base_text, replay_text)
    sensitive = bool(SENSITIVE_RESPONSE_WORDS.search(replay_text))
    if cross_role and similarity > 0.88:
        return {
            "severity": "high" if sensitive else "medium",
            "confidence": "probable",
            "reason": "alternate auth profile received near-identical object response",
            "similarity": similarity,
        }
    if not cross_role and base_status in range(200, 300) and 0.15 < similarity < 0.95 and sensitive:
        return {
            "severity": "low",
            "confidence": "possible",
            "reason": "neighboring object ID returned sensitive-looking object data",
            "similarity": similarity,
        }
    return None


def generate_discovery_words(base_url: str, urls: list[str] | None = None) -> list[str]:
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
