"""
Wordlist catalog + target-specific generation.

Curated seed lists for content discovery, plus deterministic generation of
target-specific candidate paths/params/credentials from the discovered surface.
Inspired by OLYMPUS core/wordlists.py + HEPHAESTUS. Pure and deterministic.
"""
import os
from urllib.parse import urlparse

# ── SecLists integration (optional, graceful) ────────────────────
# If a SecLists checkout is present on disk we expose a curated slice of its high-value
# lists through the SAME catalog/get_words API, so content-discovery / ffuf / fuzzing can
# use them. Absent SecLists, everything falls back to the native curated lists below with
# no error. Path is configurable via SECLISTS_PATH; a few conventional roots are tried.
_SECLISTS_ROOTS = [
    os.environ.get("SECLISTS_PATH", ""),
    "/usr/share/seclists", "/usr/share/wordlists/seclists", "/usr/share/wordlists/SecLists",
    "/opt/SecLists", "/opt/seclists",
]
# id -> (relative path under the SecLists root, label, description)
_SECLISTS_INDEX = {
    "seclists:web-common": ("Discovery/Web-Content/common.txt", "SecLists common web content", "Directory/file brute-force (common)."),
    "seclists:raft-dirs": ("Discovery/Web-Content/raft-medium-directories.txt", "SecLists raft directories", "raft-medium directories."),
    "seclists:raft-files": ("Discovery/Web-Content/raft-medium-files.txt", "SecLists raft files", "raft-medium files."),
    "seclists:api-endpoints": ("Discovery/Web-Content/api/api-endpoints.txt", "SecLists API endpoints", "Common REST/API endpoint names."),
    "seclists:subdomains": ("Discovery/DNS/subdomains-top1million-5000.txt", "SecLists subdomains (5k)", "Top 5000 subdomain labels."),
    "seclists:passwords-10k": ("Passwords/Common-Credentials/10-million-password-list-top-10000.txt", "SecLists top 10k passwords", "Offline/authorized password lists only."),
    "seclists:usernames": ("Usernames/top-usernames-shortlist.txt", "SecLists usernames", "Common usernames."),
    "seclists:lfi": ("Fuzzing/LFI/LFI-Jhaddix.txt", "SecLists LFI payloads", "Path traversal / LFI payloads."),
}
_SECLISTS_MAXLINES = 20000   # bound any single list so a huge file never blows memory


def _seclists_root():
    for r in _SECLISTS_ROOTS:
        if r and os.path.isdir(r):
            return r
    return None


def _seclists_file(rel: str):
    root = _seclists_root()
    if not root:
        return None
    p = os.path.normpath(os.path.join(root, rel))
    # containment guard: never escape the SecLists root via a crafted relative path
    if not p.startswith(os.path.normpath(root) + os.sep):
        return None
    return p if os.path.isfile(p) else None


def _read_wordfile(path: str) -> list:
    words = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh):
                if i >= _SECLISTS_MAXLINES:
                    break
                w = line.strip()
                if w and not w.startswith("#"):
                    words.append(w)
    except OSError:
        return []
    return words


def seclists_available() -> bool:
    return _seclists_root() is not None


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
    """List available seed wordlists with size + preview. Native curated lists always
    appear; SecLists entries are appended only when the file actually exists on disk
    (graceful — absent SecLists changes nothing)."""
    out = []
    for wid, entry in CATALOG.items():
        out.append({
            "id": wid,
            "label": entry["label"],
            "description": entry["description"],
            "count": len(entry["words"]),
            "preview": entry["words"][:8],
        })
    for wid, (rel, label, desc) in _SECLISTS_INDEX.items():
        path = _seclists_file(rel)
        if not path:
            continue
        words = _read_wordfile(path)
        if not words:
            continue
        out.append({"id": wid, "label": label, "description": desc,
                    "count": len(words), "preview": words[:8], "source": "seclists"})
    return out


def get_words(wordlist_id: str) -> list:
    """Words for a catalog id. `seclists:*` ids read the on-disk SecLists file (bounded);
    an unknown or unavailable id returns []."""
    if (wordlist_id or "").startswith("seclists:"):
        spec = _SECLISTS_INDEX.get(wordlist_id)
        if not spec:
            return []
        path = _seclists_file(spec[0])
        return _read_wordfile(path) if path else []
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
