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
     # Q-127, the SECOND defect in the same finding. This was
     #   r"(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*="
     # and `\s` MATCHES NEWLINES, so `^` bought nothing: the match could begin at any line start,
     # consume every following newline and tab, and land on an uppercase token deep inside indented
     # HTML. MEASURED against WordPress's own tab-indented markup -- it matched.
     #
     # `[^\S\n]*` is horizontal whitespace only, so the KEY must genuinely start its own line, and a
     # value is now required after the `=`: a dotenv line is `KEY=value`, never a bare `KEY=`. Bare
     # `SECRET` is gone for the same reason -- it matched the word anywhere on any page.
     "sig": [r"(?m)^[^\S\n]*[A-Z][A-Z0-9_]{2,}[^\S\n]*=[^\S\n]*\S",
             r"(?m)^[^\S\n]*APP_KEY[^\S\n]*=", r"(?m)^[^\S\n]*DB_PASSWORD[^\S\n]*=",
             r"(?m)^[^\S\n]*[A-Z_]*SECRET[A-Z_]*[^\S\n]*=[^\S\n]*\S"]},
    {"path": "wp-config.php.bak", "name": "Exposed wp-config backup", "severity": "critical", "family": "backup_exposure",
     "sig": [r"DB_PASSWORD", r"DB_NAME", r"AUTH_KEY", r"\$table_prefix"]},
    {"path": "config.php.bak", "name": "Exposed PHP config backup", "severity": "high", "family": "backup_exposure",
     "sig": [r"<\?php", r"password", r"mysqli?_connect"]},
    {"path": ".aws/credentials", "name": "Exposed AWS credentials", "severity": "critical", "family": "credential_exposure",
     "sig": [r"(?i)aws_access_key_id", r"(?i)aws_secret_access_key"]},
    {"path": ".htpasswd", "name": "Exposed .htpasswd", "severity": "high", "family": "credential_exposure",
     "sig": [r":\$apr1\$", r":\$2[aby]\$", r":\{SHA\}", r":\$6\$"]},
    {"path": "phpinfo.php", "name": "Exposed phpinfo()", "severity": "medium", "family": "info_disclosure",
     "sig": [r"phpinfo\(\)", r">PHP Version\s*<", r"php\.ini"]},
    {"path": "server-status", "name": "Exposed Apache server-status", "severity": "medium", "family": "info_disclosure",
     "sig": [r"(?i)Apache Server Status", r"(?i)Server uptime", r"(?i)requests/sec"]},
    {"path": "backup.sql", "name": "Exposed SQL dump", "severity": "high", "family": "backup_exposure",
     "sig": [r"(?i)INSERT INTO", r"(?i)CREATE TABLE", r"(?i)-- MySQL dump", r"(?i)DROP TABLE IF EXISTS"]},
    {"path": ".DS_Store", "name": "Exposed .DS_Store", "severity": "low", "family": "info_disclosure",
     "sig": [r"Bud1"]},
    {"path": "docker-compose.yml", "name": "Exposed docker-compose.yml", "severity": "low", "family": "info_disclosure",
     "sig": [r"(?m)^services:", r"(?m)^\s+image:\s", r"(?m)^version:\s"]},
    {"path": ".git/index", "name": "Exposed .git/index", "severity": "high", "family": "git_exposure",
     "sig": [r"^DIRC"]},
]


def _matches(sigs: list, body: str) -> str:
    r"""First signature that matches, or "".

    Q-127. `re.I` USED TO BE APPLIED TO EVERY SIGNATURE, and that is what actually broke the dotenv
    check. `^[A-Z][A-Z0-9_]{2,}\s*=` reads as "an uppercase KEY at the start of a line" -- which is
    what a dotenv line is -- but under IGNORECASE it means "any word followed by `=`", and every
    tab-indented HTML attribute in existence is exactly that. MEASURED: it matched `class=` in
    WordPress's own markup, which is how a CRITICAL "Exposed .env file" was raised against a site
    that has no .env.

    Case sensitivity is now the DEFAULT and a signature that genuinely wants folding says so with an
    inline `(?i)`. That keeps the decision next to the pattern whose author knows whether case
    carries meaning: `DIRC`, `Bud1`, `ref: refs/`, `$apr1$` and an uppercase dotenv KEY are all
    case-BEARING, and folding them was never intended -- it was inherited from one flag at the call
    site.
    """
    for s in sigs:
        if re.search(s, body or "", re.M):
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
    # Q-127. THE CATCH-ALL GUARD WAS EXACT EQUALITY, AND EXACT EQUALITY IS NOT "THE SAME PAGE".
    # MEASURED on a stock WordPress lab -- `/.env` and a randomised not-found path:
    #
    #     /.env body                 82506 chars
    #     randomised 404 baseline    82534 chars
    #     body == baseline_body      False        <- the guard passed
    #     _body_similarity           1.0          <- they are the same page
    #
    # 28 bytes of difference: the requested path echoed into the title and the search form. Any
    # dynamic byte -- a nonce, a timestamp, a CSRF token, the path itself -- defeats `==`, and an
    # application that answers 200 to everything then matches a signature somewhere in its own
    # markup. That produced a **CRITICAL "Exposed .env file"** against a WordPress install that has
    # no .env at all.
    #
    # `validate_sensitive_body` in web_security.py already had this right, at the same threshold.
    # The correct tool existed in the codebase and this call site used the wrong one.
    if baseline_body and len(baseline_body) > 40:
        from web_security import _body_similarity
        if _body_similarity(body or "", baseline_body) >= 0.92:
            return None
    elif baseline_body and (body or "") == baseline_body:
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


def observed_directories(observed_urls, origin: str = "") -> list:
    """Directory paths that the engagement has ALREADY WALKED, newest-evidence-first.

    Q-173. DIR_CANDIDATES is a list of GUESSES -- 16 names somebody typed. Every directory
    derived here is a FACT: the crawler fetched a URL underneath it, so the directory exists
    on this host. A directory listing we already fetched is a list of real files, and the
    harvester never got to see one.

    MEASURED on mission bed9ffcd (target mutillidae): the mission fetched
    `http://mutillidae/passwords/?C=N;O=D` three times -- three rows in its own `exchanges`
    table -- and `looks_like_listing` / `parse_listing` / `is_harvestable` all say YES when
    handed that body by hand. Nothing downstream was broken. The directory simply never
    reached the engine, because `passwords` is not one of the 16 guessed names, and a
    published, working 23-account credential file went unreported.

    The rule is deliberately about SHAPE, not names: a URL ending in `/` names a directory,
    and every parent segment of any observed URL names a directory. A trailing segment
    without a `/` is NOT assumed to be a directory (that would turn `.git/logs/HEAD` into a
    `HEAD/` request), so this generates strictly fewer bogus requests than the guess list it
    supplements.
    """
    out, seen = [], set()
    host = ""
    m = re.match(r"https?://([^/]+)", origin or "")
    if m:
        host = m.group(1).lower()
    for raw in (observed_urls or []):
        u = str(raw or "").strip()
        if not u:
            continue
        um = re.match(r"https?://([^/]+)(/[^?#]*)?", u)
        if um:
            if host and um.group(1).lower() != host:
                continue          # a directory on another host is not this host's surface
            path = um.group(2) or "/"
        elif u.startswith("/"):
            path = u.split("?", 1)[0].split("#", 1)[0]
        else:
            continue
        # A path ending in "/" IS a directory; otherwise only its parents are.
        segs = [s for s in path.split("/") if s and s not in (".", "..")]
        if not path.endswith("/") and segs:
            segs = segs[:-1]
        for i in range(1, len(segs) + 1):
            d = "/".join(segs[:i])
            if len(d) > 200:
                break
            if d not in seen:
                seen.add(d)
                out.append(d)
    return out


def directory_candidates(origin: str = "", observed_urls=None, limit: int = 40) -> list:
    """Directories to check for a browsable index: OBSERVED FACTS FIRST, then guesses.

    Pure and side-effect free -- the caller passes whatever URL surface it has (in
    `tools.py` that is `self.urls`). Passing nothing degrades to exactly the old
    behaviour, so this can never make an existing run worse.
    """
    # Q-184. ROUND-ROBIN BY TOP-LEVEL SEGMENT, so one deep tree cannot eat the budget.
    #
    # MEASURED on a real mission's 549-URL surface: this returned 40 candidates of which 21 were
    # `.git` internals -- `.git/objects/09`, `.git/objects/15`, `.git/refs/tags` and so on -- which
    # hold binary blobs and nothing harvestable. They sort early, so `passwords` was not merely
    # ranked low, it was ABSENT from the list, and `/passwords/accounts.txt` (23 working logins)
    # went unharvested on a mission that had already fetched that very listing.
    #
    # One exposed `.git` tree crowded out the entire rest of the application. Taking breadth first
    # is the general answer: every distinct top-level area contributes one directory before any
    # area contributes a second, so depth costs a tree its own slots rather than everyone else's.
    # Order WITHIN an area is preserved, and observed facts still precede guesses.
    def _area(d):
        return (d.strip("/").split("/", 1)[0] or "").lower()

    groups, order = {}, []
    for d in list(observed_directories(observed_urls, origin)) + list(DIR_CANDIDATES):
        k = d.strip("/")
        if not k:
            continue
        a = _area(k)
        if a not in groups:
            groups[a] = []
            order.append(a)
        groups[a].append(k)

    out, seen = [], set()
    depth = 0
    while len(out) < max(1, limit):
        added = False
        for a in order:
            if depth >= len(groups[a]):
                continue
            d = groups[a][depth]
            added = True
            if d.lower() in seen:
                continue
            seen.add(d.lower())
            out.append(d)
            if len(out) >= max(1, limit):
                break
        if not added:
            break
        depth += 1
    return out

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


def parse_listing(html: str, base_url: str = "") -> list:
    """Extract root-relative file paths from a directory-index page.

    Q-173. `base_url` is new and it fixes a defect that made this engine structurally unable
    to read the most common directory listing on the internet.

    A listing's hrefs are RELATIVE TO THE PAGE THEY ARE ON, and the two common listing styles
    differ in exactly that respect:

        http://juice-shop:3000/ftp   -> href="ftp/acquisitions.md"   (resolves to /ftp/...)
        http://mutillidae/passwords/ -> href="accounts.txt"          (resolves to /passwords/...)

    The old signature could not tell them apart, so it returned the raw href and the caller
    joined it to the ORIGIN. MEASURED, that is right for one style and wrong for the other:

        caller joins to     : http://juice-shop:3000/ftp/acquisitions.md -> 200
        caller joins to     : http://mutillidae/accounts.txt            -> 404
        correct URL would be: http://mutillidae/passwords/accounts.txt  -> 200

    Apache `mod_autoindex` emits bare file names, so EVERY Apache autoindex harvested by this
    engine has been requesting files from the web root and getting 404s. It appeared to work
    only because juice-shop's listing happens to emit root-relative hrefs. Resolving against
    the page's own URL handles both styles by construction.

    `base_url` should be the FINAL response URL (after redirects), because `/passwords` and
    `/passwords/` resolve relative hrefs differently. Omitting it preserves the old behaviour
    exactly, so no existing caller changes meaning.
    """
    from urllib.parse import urljoin, urlsplit
    out, seen = [], set()
    origin = ""
    if base_url:
        sp = urlsplit(base_url)
        origin = "%s://%s" % (sp.scheme, sp.netloc)
    for h in _HREF.findall(html or ""):
        h = h.strip()
        if h.startswith(("http://", "https://", "mailto:", "#", "?", "..")):
            continue
        leaf = h.split("?", 1)[0].split("#", 1)[0].rsplit("/", 1)[-1]
        if "." not in leaf or leaf in (".", ".."):
            continue
        if base_url:
            resolved = urljoin(base_url, h)
            sp = urlsplit(resolved)
            if "%s://%s" % (sp.scheme, sp.netloc) != origin:
                continue            # a listing may link offsite; that is not this host's surface
            p = sp.path.lstrip("/")
        else:
            p = h.lstrip("/")
        if p and p not in seen:
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


# ── Is this file's CONTENT sensitive? (Q-173: judged on structure, never on its name) ──
#
# The old oracle here was one substring regex whose alternatives included a bare `password`,
# `passwd` and `secret`. MEASURED, it is unsound in BOTH directions:
#
#   mutillidae/passwords/accounts.txt   SENSITIVE=True  match='password'
#   mutillidae/robots.txt               SENSITIVE=True  match='password'   <- FALSE POSITIVE
#   bwapp/robots.txt                    SENSITIVE=True  match='password'   <- FALSE POSITIVE
#   dvwa/robots.txt                     SENSITIVE=False
#
# Both robots files match only because they say `Disallow: /passwords/`. And the one TRUE
# positive is luck: `accounts.txt` matches only because ten of its rows use the literal
# password "password" (`4,jeremy,password,d1373 1337 speak,Admin`). A credential dump whose
# passwords were real secrets contains the substring nowhere and would be dropped in silence.
#
# So the bare secret WORDS now require an ASSIGNMENT (`password=v`, `"api_key": "v"`), which
# is what a leaked config actually looks like and what a robots directive never is, and three
# STRUCTURAL detectors are added below. MEASURED against juice-shop's /ftp harvest before
# changing anything: no existing true positive there depends on a bare secret word
# (`acquisitions.md` fires on `confidential` / `do not distribute` / `acquisition`), so this
# tightening regresses nothing observed.

# Documentary markers: a human deliberately labelled the file. Low FP, kept as-is.
_DOC_SENSITIVE = re.compile(
    r"confidential|do not distribute|private key|kdbx|coupon|salary|acquisition|"
    r"\"name\":\s*\"", re.I)

# Unambiguous secret MATERIAL. Every one of these is a structural artefact -- an armoured key
# block, a vendor-formatted key id, a crypt hash in a passwd row, or an inline-credential URI.
# Compiled SEPARATELY on purpose: case sensitivity carries meaning per pattern (`AKIA` and
# `-----BEGIN` are case-BEARING; the AWS config key is not), and Python rejects an inline
# `(?i)`/`(?m)` that is not at the start of the expression.
_KEY_MATERIAL_PATTERNS = [
    re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"),
    re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|PGP|DSA)"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"^[^:\s]{1,64}:\$(?:apr1|2[aby]|1|5|6)\$", re.M),
    re.compile(r"\b[a-z][a-z0-9+.\-]{1,20}://[^/\s:@]{1,64}:[^/\s:@]{1,128}@"),
    re.compile(r"aws_secret_access_key\s*[=:]\s*\S", re.I),
]


def _key_material(body: str):
    for p in _KEY_MATERIAL_PATTERNS:
        m = p.search(body or "")
        if m:
            return m
    return None

# A secret WORD only counts when something is assigned to it.
#
# The value charset excludes ` and * deliberately. MEASURED on dvwa's own README.md, which
# reported as an "Exposed configuration secret" on the line
#     **Default password = `password`**
# That is the application's published documentation describing its default login, formatted
# as markdown emphasis around a code span -- not a leaked config value. A config assignment's
# value is a BARE token; a documentation example's value is wrapped in formatting. Excluding
# the two markdown delimiters separates them without needing to know the file is a README.
# The leading `[A-Za-z0-9_.-]*` matters: `\bpassword` cannot match inside `DB_PASSWORD`, because
# `_` is a word character and there is no boundary before `PASSWORD`. The single most common
# shape of a leaked config key was therefore invisible to this pattern.
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?:^|[^A-Za-z0-9])[A-Za-z0-9_.\-]*"
    r"(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\b"
    r"\s*[:=]\s*[\"']?[^\s\"',;<>`*]{3,}")

# A database dump states its own structure.
_DB_DUMP = re.compile(r"(?i)\bCREATE\s+TABLE\b")
_DB_ROWS = re.compile(r"(?i)\bINSERT\s+INTO\b")

_IDENT_FIELD = re.compile(r"[A-Za-z0-9._@+-]{1,64}")
# A single field: no whitespace, any length. The minimum used to be 3 characters and that
# ALONE suppressed the whole mutillidae credential dump -- one of its 23 accounts has the
# two-character password `42`, so the column failed an all()-quantified length test and the
# file classified as not-sensitive. A per-VALUE length floor is the wrong instrument: real
# passwords can be short, and it is the COLUMN that has to look like secrets. The median
# length check in credential_table() describes the column instead of vetoing on one outlier.
_TOKEN_FIELD = re.compile(r"\S{1,128}")
# Column shapes that are emphatically NOT secrets. If EVERY value in the candidate secret
# column is one of these, the table is a directory/log/inventory, not a credential store.
_NOT_SECRET = re.compile(
    r"^(?:[^@\s]+@[^@\s]+\.[A-Za-z]{2,}"          # email
    r"|https?://\S+"                               # url
    r"|\d{1,4}[-/]\d{1,2}[-/]\d{1,4}"              # date
    r"|\d{1,3}(?:\.\d{1,3}){3}"                    # ipv4
    r"|[+-]?\d+(?:\.\d+)?"                         # bare number
    r"|true|false|null|none|yes|no|n/a|-)$", re.I)
_MARKUP = re.compile(r"<(?:!doctype|html|head|body|div|table|script|a\s)", re.I)


def credential_table(body: str) -> dict | None:
    """Does this body READ AS a table of login records? Structural, name-free.

    A credential store has a shape no prose has: many rows, one consistent delimiter, a
    near-unique identifier column, and an adjacent opaque token column with no whitespace.
    The near-uniqueness requirement is what separates a login table (usernames are unique)
    from a robots.txt (`Disallow` repeats on every row) -- MEASURED, that single ratio is
    what rejects robots.txt on all three labs while accepting a real 23-account dump.
    """
    if not body or _MARKUP.search(body[:4000]):
        return None
    lines = [ln.strip() for ln in body.splitlines()[:2000]]
    lines = [ln for ln in lines if ln and not ln.startswith(("#", "//", ";", "--"))]
    if len(lines) < 3:
        return None
    for delim in (",", ":", ";", "\t", "|"):
        rows = [[f.strip() for f in ln.split(delim)] for ln in lines]
        rows = [r for r in rows if len(r) >= 2]
        if len(rows) < 3:
            continue
        counts = {}
        for r in rows:
            counts[len(r)] = counts.get(len(r), 0) + 1
        width, n = max(counts.items(), key=lambda kv: kv[1])
        if n < 3 or n < 0.8 * len(rows):
            continue                       # ragged: prose, not a table
        rows = [r for r in rows if len(r) == width]
        for i in range(width - 1):
            ident = [r[i] for r in rows]
            secret = [r[i + 1] for r in rows]
            if not all(_IDENT_FIELD.fullmatch(v or "") for v in ident):
                continue
            if all(re.fullmatch(r"[+-]?\d+", v or "") for v in ident):
                continue                   # a row number is not a username
            if not all(_TOKEN_FIELD.fullmatch(v or "") for v in secret):
                continue
            if all(_NOT_SECRET.match(v or "") for v in secret):
                continue                   # an email/date/number column is not a secret column
            uniq = len({v.lower() for v in ident}) / float(len(ident))
            if uniq < 0.7:
                continue                   # a repeated key ("Disallow") is a directive, not a login
            if len({v for v in secret}) < 2:
                continue                   # a constant column is a flag, not a secret
            lens = sorted(len(v) for v in secret)
            if lens[len(lens) // 2] < 3:
                continue                   # a column of 1-2 char values is a code, not a secret
            # A SECRET COLUMN LOOKS DIFFERENT FROM A NAME COLUMN. Without this, the plain CSV
            #     id,name,city / 1,alice,Boston / 2,bob,Denver
            # satisfies every other rule -- unique ids, adjacent whitespace-free tokens -- and
            # classifies as a credential store. That is the flood failure mode: an inventory,
            # a contact export or a log would each raise a HIGH. Secrets carry a digit or a
            # symbol, or they are long; dictionary words in title case are a name column.
            secretish = sum(1 for v in secret
                            if len(v) >= 8 or re.search(r"\d|[^A-Za-z0-9]", v))
            if secretish < 0.5 * len(secret):
                continue
            if sum(1 for a, b in zip(ident, secret) if a == b) > len(rows) / 2:
                continue
            sample = ", ".join(sorted({v for v in ident})[:3])
            return {"rows": len(rows), "delimiter": delim, "ident_col": i,
                    "secret_col": i + 1, "identifiers": sample, "distinct_ratio": round(uniq, 3)}
    return None


def classify_content(body: str, content_type: str = "") -> dict | None:
    """What KIND of sensitive thing is this, judged only on what the bytes contain?

    Returns None for anything not shown to be sensitive. Ordered strongest-evidence-first so
    the reported claim is the one actually proven.
    """
    b = body or ""
    if len(b.strip()) < 8:
        return None
    m = _key_material(b)
    if m:
        return {"kind": "key_material", "family": "credential_exposure", "severity": "high",
                "cwe": "CWE-522",
                "evidence": "armoured key material / vendor key id present (value redacted)",
                "detail": "the file contains structural secret material (%s)" % _redact(m.group(0))}
    if _DB_DUMP.search(b) and _DB_ROWS.search(b):
        return {"kind": "db_dump", "family": "backup_exposure", "severity": "high",
                "cwe": "CWE-530",
                "evidence": "SQL dump: CREATE TABLE + INSERT INTO both present",
                "detail": "the file is a database dump (schema and row data)"}
    # A DIRECTORY INDEX IS A TABLE OF CONTENTS, NOT CONTENT. MEASURED: juice-shop's /ftp
    # listing classified as a sensitive document purely because it prints the file name
    # `acquisitions.md`. That is the same "judge it by its name" error this whole change
    # exists to remove -- an index naming a sensitive file is not itself a sensitive file.
    # Placed after the two unambiguous material checks, which no index page can satisfy.
    if looks_like_listing(b):
        return None
    t = credential_table(b)
    if t:
        return {"kind": "credential_table", "family": "credential_exposure", "severity": "high",
                "cwe": "CWE-522",
                "evidence": ("credential-table shape: %d rows, %r-delimited, column %d is a "
                             "near-unique identifier (distinct ratio %s) and column %d an adjacent "
                             "whitespace-free token; identifiers include %s (secrets redacted)"
                             % (t["rows"], t["delimiter"], t["ident_col"], t["distinct_ratio"],
                                t["secret_col"], t["identifiers"])),
                "detail": "the file is structurally a table of login records", "table": t}
    m = _SECRET_ASSIGNMENT.search(b)
    if m:
        return {"kind": "secret_assignment", "family": "config_exposure", "severity": "high",
                "cwe": "CWE-538",
                "evidence": "a secret is assigned a value (%s)" % _redact(m.group(0)),
                "detail": "the file assigns a value to a secret-bearing key"}
    m = _DOC_SENSITIVE.search(b)
    if m:
        return {"kind": "sensitive_document", "family": "backup_exposure", "severity": "high",
                "cwe": "CWE-552", "evidence": "sensitive-document marker: %r" % m.group(0),
                "detail": "the file carries a documentary sensitivity marker"}
    return None


def _redact(s: str) -> str:
    """Keep the SHAPE of a secret, never its value.

    U+FFFD is stripped: it is emitted only by a decoder that hit bytes it could not decode, so
    it is an artefact of our own reading, never content. MEASURED on a real harvested file --
    a doc whose `--user=root --password=samurai` is mis-decoded -- the evidence string came out
    as "�password: <redacted>". This project has already shipped one finding titled
    `Exposed application credentials for 'root�'`; a decode artefact must never reach a
    report as if it were observed text.
    """
    s = (s or "").replace("�", "").strip()
    head = re.split(r"[:=]", s, 1)[0].strip()
    return (head[:40] + ": <redacted>") if len(s) > len(head) else (s[:24] + "<redacted>")


class _SensitiveContent:
    """Duck-typed stand-in for the old `_SENSITIVE_SIG` regex.

    `tools.py::_run_dir_harvest` calls `exp._SENSITIVE_SIG.search(body)` and only tests the
    result for truthiness. Keeping that exact surface lets the corrected, structural judgement
    reach the live harvest path without editing a file this lane does not own.
    """

    def search(self, body, *_a, **_kw):
        c = classify_content(body or "")
        return _SensitiveHit(c) if c else None


class _SensitiveHit:
    def __init__(self, c):
        self.classification = c

    def group(self, *_a):
        return self.classification.get("evidence", "")

    def __bool__(self):
        return True


_SENSITIVE_SIG = _SensitiveContent()


def harvest_finding(url: str, path: str, via_nullbyte: bool, snippet: str,
                    *, negative_control: dict = None) -> dict:
    how = "a poison-null-byte extension bypass" if via_nullbyte else "direct request"
    leaf = path.rsplit("/", 1)[-1]
    # Q-173. The grade and the evidence now come from WHAT THE BYTES ARE, not from the fact
    # that a request succeeded. Two things this fixes:
    #   1. the claim matches the observation -- a credential table is reported as a credential
    #      table (CWE-522), not as a generic "backup_exposure" (CWE-552);
    #   2. the raw body no longer becomes the evidence string. It used to be `snippet[:300]`,
    #      which for a published credential dump means the plaintext passwords are copied into
    #      the finding, the report and the database. Evidence is now a redacted description of
    #      the STRUCTURE, which is what the claim rests on anyway.
    c = classify_content(snippet or "") or {}
    kind = c.get("kind", "")
    title = {
        "credential_table": f"Exposed credential store: {leaf}",
        "key_material": f"Exposed secret key material: {leaf}",
        "db_dump": f"Exposed database dump: {leaf}",
        "secret_assignment": f"Exposed configuration secret: {leaf}",
    }.get(kind, f"Exposed sensitive file: {leaf}")
    fam = c.get("family", "backup_exposure")
    finding = {
        "title": title + (" (null-byte bypass)" if via_nullbyte else ""),
        "severity": c.get("severity", "high"), "target": url, "family": fam,
        "description": (f"A sensitive file in a browsable directory was retrieved via {how}: "
                        + c.get("detail", "the file carries sensitive content") + ". "
                        + ("The directory index that names this file was itself fetched during this "
                           "engagement, so the file is discovered surface, not a guess.")),
        "impact": ("Anyone who can read this file obtains working logins for the listed accounts, "
                   "with no guessing or brute force." if kind == "credential_table" else
                   "Disclosure of secret key material usable to impersonate or decrypt." if kind == "key_material" else
                   "Disclosure of stored application data, including any secrets held in it." if kind == "db_dump" else
                   "Disclosure of confidential documents, source backups, or secret keys."),
        "reproduction_steps": [f"Request {url}",
                               "Observe the sensitive file content is served"]
                              + (["(the plain path is blocked; the null byte defeats the extension allowlist)"]
                                 if via_nullbyte else []),
        "evidence": c.get("evidence") or "content matched a sensitive-content classifier",
        "cwe": c.get("cwe", "CWE-552"),
        "tags": ["information-disclosure", "exposed-file"]
                + ([kind.replace("_", "-")] if kind else [])
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
