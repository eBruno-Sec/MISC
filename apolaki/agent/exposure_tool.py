"""
Information-disclosure / exposed-file detection.

From Bug Bounty Bootcamp (Li, Ch 21). Probes a curated set of high-value files
that leak source, secrets, or internal detail — version-control directories
(.git/.svn), environment/config files (.env, wp-config backups, .aws/credentials),
server diagnostics (phpinfo, server-status), credential stores (.htpasswd), and
database dumps.

The point of difference from generic content discovery: each check has a strong
CONTENT validator (a signature that genuinely-exposed file carries), so a
catch-all SPA that answers 200 for everything cannot produce a false positive —
the signature (`[core]` for a git config, `KEY=value` for a dotenv, `Bud1` for a
.DS_Store) has to actually be in the body. A confirmed .git/HEAD or .git/config
additionally yields a "source recoverable" escalation, since the whole repo can
be dumped from a browsable .git.

Pure/deterministic; unit-tested. tools._run_exposure does the transport.
"""
from __future__ import annotations

import re

# family -> CWE for the finding
_CWE = {"git_exposure": "CWE-527", "config_exposure": "CWE-538", "info_disclosure": "CWE-200",
        "credential_exposure": "CWE-538", "backup_exposure": "CWE-530"}

# Each check: path, human name, severity, family, and content signatures (the
# body must match at least one). Signatures are chosen to be absent from normal
# HTML/JSON pages so a 200 catch-all cannot trip them.
EXPOSURE_CHECKS = [
    {"path": ".git/HEAD", "name": "Exposed .git/HEAD", "severity": "high", "family": "git_exposure",
     "sig": [r"^\s*ref:\s*refs/(?:heads|tags)/"]},
    {"path": ".git/config", "name": "Exposed .git/config", "severity": "high", "family": "git_exposure",
     "sig": [r"\[core\]", r"\[remote\s", r"\[branch\s"]},
    {"path": ".git/logs/HEAD", "name": "Exposed .git/logs/HEAD", "severity": "high", "family": "git_exposure",
     "sig": [r"[0-9a-f]{40}\s+[0-9a-f]{40}\s"]},
    {"path": ".svn/entries", "name": "Exposed .svn/entries", "severity": "high", "family": "git_exposure",
     "sig": [r"svn://", r"has-props", r"^\d+\s*\ndir"]},
    {"path": ".env", "name": "Exposed .env file", "severity": "critical", "family": "config_exposure",
     "sig": [r"(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*=", r"APP_KEY\s*=", r"DB_PASSWORD\s*=", r"SECRET"]},
    {"path": "wp-config.php.bak", "name": "Exposed wp-config backup", "severity": "critical", "family": "backup_exposure",
     "sig": [r"DB_PASSWORD", r"DB_NAME", r"AUTH_KEY", r"\$table_prefix"]},
    {"path": "config.php.bak", "name": "Exposed PHP config backup", "severity": "high", "family": "backup_exposure",
     "sig": [r"<\?php", r"password", r"mysqli?_connect"]},
    {"path": ".aws/credentials", "name": "Exposed AWS credentials", "severity": "critical", "family": "credential_exposure",
     "sig": [r"aws_access_key_id", r"aws_secret_access_key"]},
    {"path": ".htpasswd", "name": "Exposed .htpasswd", "severity": "high", "family": "credential_exposure",
     "sig": [r":\$apr1\$", r":\$2[aby]\$", r":\{SHA\}", r":\$6\$"]},
    {"path": "phpinfo.php", "name": "Exposed phpinfo()", "severity": "medium", "family": "info_disclosure",
     "sig": [r"phpinfo\(\)", r">PHP Version\s*<", r"php\.ini"]},
    {"path": "server-status", "name": "Exposed Apache server-status", "severity": "medium", "family": "info_disclosure",
     "sig": [r"Apache Server Status", r"Server uptime", r"requests/sec"]},
    {"path": "backup.sql", "name": "Exposed SQL dump", "severity": "high", "family": "backup_exposure",
     "sig": [r"INSERT INTO", r"CREATE TABLE", r"-- MySQL dump", r"DROP TABLE IF EXISTS"]},
    {"path": ".DS_Store", "name": "Exposed .DS_Store", "severity": "low", "family": "info_disclosure",
     "sig": [r"Bud1"]},
    {"path": "docker-compose.yml", "name": "Exposed docker-compose.yml", "severity": "low", "family": "info_disclosure",
     "sig": [r"(?m)^services:", r"(?m)^\s+image:\s", r"(?m)^version:\s"]},
    {"path": ".git/index", "name": "Exposed .git/index", "severity": "high", "family": "git_exposure",
     "sig": [r"^DIRC"]},
]


def paths() -> list:
    return [c["path"] for c in EXPOSURE_CHECKS]


def _matches(sigs: list, body: str) -> str:
    for s in sigs:
        if re.search(s, body or "", re.I | re.M):
            return s
    return ""


def classify(check: dict, status: int, body: str, content_type: str = "",
             baseline_body: str = "") -> dict | None:
    """Return a finding when a check's file is genuinely exposed.

    Requires a 2xx status, a signature match in the body, and — as a guard
    against catch-all 200 pages — a body that differs from the not-found
    baseline."""
    if not (200 <= (status or 0) < 300):
        return None
    if baseline_body and (body or "") == baseline_body:
        return None
    matched = _matches(check["sig"], body or "")
    if not matched:
        return None
    finding = exposure_finding(check, matched)
    if baseline_body:
        finding["negative_controls"] = [{
            "kind": "not-found-baseline",
            "response_length": len(baseline_body),
            "result": "the same host's randomized not-found response differed and lacked the file signature",
        }]
    return finding


def exposure_finding(check: dict, matched: str) -> dict:
    fam = check["family"]
    return {
        "title": check["name"], "severity": check["severity"],
        "target": check["path"],   # tools fills the absolute URL
        "description": (f"{check['name']} is publicly readable and its content matches the expected signature "
                        f"(/{check['path']}). This leaks {'source and history' if fam == 'git_exposure' else 'sensitive configuration/credentials' if fam in ('config_exposure', 'credential_exposure', 'backup_exposure') else 'internal information'}."),
        "impact": ("Recover application source and secrets" if fam in ("git_exposure", "backup_exposure")
                   else "Disclose credentials / secret keys enabling further compromise" if fam in ("config_exposure", "credential_exposure")
                   else "Leak internal configuration/version detail useful for further attacks"),
        "reproduction_steps": [f"Request /{check['path']}",
                               f"Observe the exposed content (signature '{matched}' present)"],
        "evidence": f"signature: {matched}", "cwe": _CWE.get(fam, "CWE-200"),
        "family": fam, "tags": ["information-disclosure", fam.replace("_", "-")], "confidence": "confirmed",
    }


def git_reconstruct_finding(confirmed_git: list) -> dict:
    files = ", ".join(sorted({c for c in confirmed_git}))
    return {
        "title": "Exposed .git repository — full source recoverable", "severity": "high",
        "target": ".git/",
        "description": (f"A browsable .git directory is exposed ({files}). With .git/config/HEAD/index readable, the "
                        "entire repository — source code, history, and any committed secrets — can be reconstructed "
                        "with git-dumper or by walking the object store."),
        "impact": "Full source-code and commit-history disclosure, including secrets ever committed.",
        "reproduction_steps": ["Confirm /.git/HEAD and /.git/config are readable",
                               "Run git-dumper (or fetch .git/index + objects) to reconstruct the repo",
                               "grep the history for credentials/keys"],
        "evidence": f"exposed: {files}", "cwe": "CWE-527", "family": "git_exposure",
        "tags": ["information-disclosure", "git-exposure", "source-disclosure"], "confidence": "confirmed",
    }


# ── Exposed-directory harvest + poison-null-byte bypass (general) ────────────────
# Many apps expose a browsable file directory (an FTP/uploads/backup folder served as an
# HTML index). Harvesting the linked files discloses confidential docs, source backups and
# keys. Files whose extension is blocked (403) are commonly reachable via a poison null
# byte that tricks the extension allowlist (`file.bak%2500.md`). All well-known techniques;
# every access here is scope-guarded and only reported when the content is genuinely
# sensitive (truth-first).
DIR_CANDIDATES = ["ftp", "uploads", "upload", "files", "file", "backup", "backups",
                  "download", "downloads", "data", "public", "static", "encryptionkeys",
                  "attachments", "documents", "media"]

# Extensions that usually indicate a raw/backup/secret file worth harvesting.
_HARVEST_EXT = (".bak", ".old", ".backup", ".zip", ".tar", ".gz", ".sql", ".db", ".sqlite",
                ".kdbx", ".pyc", ".key", ".pem", ".p12", ".pfx", ".yml", ".yaml", ".md",
                ".conf", ".config", ".ini", ".env", ".json", ".log", ".gg", ".txt", ".csv")
# Allowlisted "safe" extensions a null-byte payload appends to slip past the filter.
_NULLBYTE_APPEND = (".md", ".txt", ".pdf")
_HREF = re.compile(r'href=["\']([^"\']+)["\']', re.I)


def looks_like_listing(html: str) -> bool:
    """Heuristic: does this HTML look like a browsable directory index (file links)?"""
    if not html:
        return False
    if re.search(r"index of\s*/|directory listing", html, re.I):
        return True
    files = [h for h in _HREF.findall(html) if "." in h.rsplit("/", 1)[-1]]
    return len(files) >= 3


def parse_listing(html: str) -> list:
    """Extract file paths (with extensions) from a directory-index page."""
    out, seen = [], set()
    for h in _HREF.findall(html or ""):
        h = h.strip()
        if h.startswith(("http://", "https://", "mailto:", "#", "?", "..")):
            continue
        leaf = h.rsplit("/", 1)[-1]
        if "." not in leaf or leaf in (".", ".."):
            continue
        p = h.lstrip("/")
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out[:100]


def nullbyte_variants(path: str) -> list:
    """Poison-null-byte bypass candidates for a blocked file: append an allowlisted
    extension after an encoded null byte so the filter sees `.md` but the OS opens the
    real file. Tries the double-encoded (%2500) and single (%00) forms."""
    out = []
    for enc in ("%2500", "%00"):
        for ext in _NULLBYTE_APPEND:
            out.append(path + enc + ext)
    return out


def is_harvestable(path: str) -> bool:
    leaf = path.rsplit("/", 1)[-1].lower()
    return leaf.endswith(_HARVEST_EXT)


_SENSITIVE_SIG = re.compile(
    r"confidential|do not distribute|BEGIN (?:RSA|EC|OPENSSH|PRIVATE)|password|passwd|"
    r"secret|api[_-]?key|\"name\":\s*\"|coupon|salary|acquisition|kdbx|private key|"
    r"aws_access_key|-----BEGIN", re.I)


def harvest_finding(url: str, path: str, via_nullbyte: bool, snippet: str,
                    *, negative_control: dict = None) -> dict:
    how = "a poison-null-byte extension bypass" if via_nullbyte else "direct request"
    finding = {
        "title": f"Exposed sensitive file: {path.rsplit('/', 1)[-1]}"
                 + (" (null-byte bypass)" if via_nullbyte else ""),
        "severity": "high", "target": url, "family": "backup_exposure",
        "description": (f"A sensitive file in a browsable directory was retrieved via {how}. "
                        "Exposed backup/source/key/document files leak confidential data and "
                        "often credentials or source history."),
        "impact": "Disclosure of confidential documents, source backups, or secret keys.",
        "reproduction_steps": [f"Request {url}",
                               "Observe the sensitive file content is served"]
                              + (["(the plain path is blocked; the null byte defeats the extension allowlist)"]
                                 if via_nullbyte else []),
        "evidence": (snippet or "")[:300], "cwe": "CWE-552",
        "family": "backup_exposure", "tags": ["information-disclosure", "exposed-file"]
                  + (["poison-null-byte"] if via_nullbyte else []),
        "confidence": "confirmed",
    }
    if negative_control:
        finding["negative_controls"] = [dict(negative_control)]
    elif via_nullbyte:
        finding["negative_controls"] = [{
            "kind": "plain-path-refusal",
            "path": path,
            "result": "the unmodified path returned 401/403 before the encoded-null twin returned content",
        }]
    return finding
