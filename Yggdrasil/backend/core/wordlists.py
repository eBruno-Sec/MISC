"""
Yggdrasil wordlist engine.

Two sources of wordlists:

  1. CURATED  - a hand-picked subset of SecLists / Assetnote fetched into
                /opt/wordlists at build time (see Dockerfile). Fast to pull,
                covers the lists that actually matter for content discovery,
                DNS, and injection fuzzing. No 1GB full-SecLists clone.

  2. GENERATED - target-specific lists built DETERMINISTICALLY from HERMES
                recon output (subdomain labels, vendor names, tech stack,
                discovered paths). No LLM involved: this is pure string
                permutation, so it is free, instant, and reproducible.

Generated lists are written into settings.wordlists_dir and show up in the
catalog alongside the curated sets, selectable per mission.
"""
import os
import re
from core.timeutil import utcnow

from core.config import settings

CURATED_DIR = "/opt/wordlists"

# id -> metadata. `file` is the basename inside CURATED_DIR.
CURATED = [
    {"id": "raft-dirs", "file": "raft-medium-directories.txt",
     "name": "RAFT Medium Directories", "category": "content",
     "source": "SecLists", "desc": "Primary directory discovery list."},
    {"id": "raft-files", "file": "raft-medium-files.txt",
     "name": "RAFT Medium Files", "category": "content",
     "source": "SecLists", "desc": "Filenames and extensions for content discovery."},
    {"id": "common", "file": "common.txt",
     "name": "Common Web Content", "category": "content",
     "source": "SecLists", "desc": "Fast, high-signal common paths."},
    {"id": "api", "file": "api-endpoints.txt",
     "name": "API Endpoints", "category": "api",
     "source": "SecLists", "desc": "REST/API route names."},
    {"id": "dns-20k", "file": "subdomains-top20000.txt",
     "name": "DNS Subdomains Top 20k", "category": "dns",
     "source": "SecLists", "desc": "Subdomain brute-force list."},
    {"id": "lfi", "file": "lfi.txt",
     "name": "LFI / Path Traversal", "category": "fuzz",
     "source": "SecLists", "desc": "Local file inclusion payloads."},
    {"id": "sqli", "file": "sqli.txt",
     "name": "Generic SQLi", "category": "fuzz",
     "source": "built-in", "desc": "SQL injection fuzzing strings."},
    {"id": "xss", "file": "xss.txt",
     "name": "XSS Payloads", "category": "fuzz",
     "source": "built-in", "desc": "Cross-site scripting payloads."},
    {"id": "users", "file": "usernames.txt",
     "name": "Usernames Shortlist", "category": "auth",
     "source": "SecLists", "desc": "Common usernames for auth testing."},
    {"id": "passwords", "file": "passwords-common.txt",
     "name": "Common Passwords", "category": "auth",
     "source": "built-in", "desc": "Most common passwords for spraying."},
]

# Default lists used for content discovery when a mission selects none.
DEFAULT_CONTENT_IDS = ["raft-dirs", "common"]

_SLUG_RE = re.compile(r"[^a-zA-Z0-9._-]+")


def wl_dir() -> str:
    os.makedirs(settings.wordlists_dir, exist_ok=True)
    return settings.wordlists_dir


def _stats(path: str):
    """Return (line_count, size_bytes). Cheap line count, no full read into memory."""
    if not os.path.exists(path):
        return 0, 0
    size = os.path.getsize(path)
    count = 0
    try:
        with open(path, "rb") as f:
            for _ in f:
                count += 1
    except OSError:
        count = 0
    return count, size


def _curated_path(entry: dict) -> str:
    return os.path.join(CURATED_DIR, entry["file"])


def curated_catalog() -> list:
    out = []
    for e in CURATED:
        p = _curated_path(e)
        count, size = _stats(p)
        out.append({
            "id": e["id"], "name": e["name"], "category": e["category"],
            "source": e["source"], "desc": e["desc"], "kind": "curated",
            "path": p, "exists": os.path.exists(p), "count": count, "size": size,
        })
    return out


def generated_catalog() -> list:
    out = []
    d = wl_dir()
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".txt"):
            continue
        p = os.path.join(d, fn)
        count, size = _stats(p)
        out.append({
            "id": f"gen:{fn[:-4]}", "name": fn[:-4], "category": "generated",
            "source": "YGGDRASIL", "desc": "Target-specific, built from recon.",
            "kind": "generated", "path": p, "exists": True,
            "count": count, "size": size,
        })
    return out


def catalog() -> list:
    return curated_catalog() + generated_catalog()


def path_for_id(wid: str) -> str | None:
    if wid.startswith("gen:"):
        base = os.path.realpath(wl_dir())
        # A generated id is a bare slug. Re-slugify to strip any path separators
        # or traversal (../, %2f) an attacker could sneak through the URL, then
        # confirm the resolved path stays inside the wordlists dir.
        name = slugify(wid[4:])
        p = os.path.realpath(os.path.join(base, name + ".txt"))
        if os.path.dirname(p) != base:
            return None
        return p if os.path.exists(p) else None
    for e in CURATED:
        if e["id"] == wid:
            p = _curated_path(e)
            return p if os.path.exists(p) else None
    return None


def resolve_ids(ids: list) -> list:
    """Map a list of wordlist ids to existing file paths, preserving order, skipping missing."""
    paths = []
    for wid in ids or []:
        p = path_for_id(wid)
        if p and p not in paths:
            paths.append(p)
    return paths


def primary_content_list() -> str | None:
    """Best single existing curated content list, for tools that take one wordlist."""
    for wid in DEFAULT_CONTENT_IDS + ["raft-files", "api"]:
        p = path_for_id(wid)
        if p:
            return p
    # last resort: first existing curated of any kind
    for e in curated_catalog():
        if e["exists"]:
            return e["path"]
    return None


# ── Deterministic target-specific generation ─────────────────────────────

_BASE_ACTIONS = [
    "admin", "api", "app", "apps", "auth", "backup", "backups", "beta",
    "config", "console", "dashboard", "data", "db", "debug", "dev", "docs",
    "files", "graphql", "health", "internal", "login", "logout", "manage",
    "metrics", "old", "portal", "private", "prod", "secret", "staging",
    "static", "status", "swagger", "test", "tmp", "upload", "uploads",
    "user", "users", "v1", "v2", "web", ".git", ".env",
]

_SUFFIXES = ["", "s", "-api", "-admin", "-dev", "-staging", "-internal",
             "-portal", "-v1", "-v2", "-old", "-bak", "-test", "-prod",
             "2024", "2025", "_v1", "_v2"]

_FILE_EXTS = [".bak", ".old", ".zip", ".tar.gz", ".txt", ".json", ".config",
              ".conf", ".yml", ".yaml", ".sql", ".log", ".env.bak"]

_STOP = {"com", "net", "org", "io", "co", "www", "gov", "edu", "app", "dev",
         "cloud", "aws", "amazonaws", "cloudfront", "azure", "google"}


def _tokens_from_hermes(hermes: dict) -> set:
    toks = set()
    domain = (hermes or {}).get("domain", "") or ""
    # apex company label
    parts = [p for p in domain.split(".") if p]
    if parts:
        toks.add(parts[0].lower())

    # subdomain labels
    for sub in (hermes or {}).get("subdomains", []) or []:
        name = sub if isinstance(sub, str) else sub.get("host", "")
        for label in re.split(r"[.\-_]", name.lower()):
            if len(label) > 1 and label not in _STOP and not label.isdigit():
                toks.add(label)

    # vendor product names
    for v in (hermes or {}).get("vendors", []) or []:
        vendor = v.get("vendor", "") if isinstance(v, dict) else str(v)
        first = re.split(r"[\s.\-_]", vendor.lower())
        if first and len(first[0]) > 1:
            toks.add(first[0])

    # technologies
    techs = (hermes or {}).get("technologies", {}) or {}
    for tech_list in techs.values():
        for t in tech_list or []:
            clean = _SLUG_RE.sub("", str(t).lower())
            if len(clean) > 2 and clean not in _STOP:
                toks.add(clean)

    toks.discard("")
    return toks


def generate_target_wordlist(hermes: dict, extra_paths: list = None, cap: int = 6000) -> list:
    """Build a deterministic content-discovery wordlist from recon signal. No AI."""
    words = set(_BASE_ACTIONS)
    seeds = _tokens_from_hermes(hermes)

    for seed in seeds:
        for suf in _SUFFIXES:
            words.add(f"{seed}{suf}")
        for act in ("admin", "api", "dev", "internal", "portal", "old"):
            words.add(f"{seed}-{act}")
            words.add(f"{act}-{seed}")
            words.add(f"{seed}/{act}")
        for ext in _FILE_EXTS:
            words.add(f"{seed}{ext}")

    # discovered paths from a prior crawl, normalized to path segments
    for u in extra_paths or []:
        seg = u.split("?")[0].strip("/").split("/")
        for s in seg:
            s = _SLUG_RE.sub("", s)
            if 1 < len(s) < 40:
                words.add(s)
                words.add(f"{s}.bak")
                words.add(f"{s}.old")

    words.discard("")
    return sorted(words)[:cap]


def slugify(name: str) -> str:
    s = _SLUG_RE.sub("-", name.strip().lower()).strip("-")
    return s or "target"


def write_list(name: str, words: list) -> dict:
    """Write a wordlist into the wordlists dir. Returns a catalog-style entry."""
    slug = slugify(name)
    path = os.path.join(wl_dir(), f"{slug}.txt")
    with open(path, "w") as f:
        f.write("\n".join(words) + "\n")
    count, size = _stats(path)
    return {
        "id": f"gen:{slug}", "name": slug, "category": "generated",
        "source": "YGGDRASIL", "desc": "Target-specific, built from recon.",
        "kind": "generated", "path": path, "exists": True,
        "count": count, "size": size, "created": utcnow().isoformat(),
    }


def build_target_list(mission_id: str, hermes: dict, extra_paths: list = None) -> dict:
    """Generate and persist the per-mission target list. Returns catalog entry."""
    domain = (hermes or {}).get("domain") or mission_id[:8]
    words = generate_target_wordlist(hermes, extra_paths)
    return write_list(f"target-{slugify(domain)}", words)


def content_wordlists_for(mission_id: str, hermes: dict = None, selected_ids: list = None) -> list:
    """
    Ordered list of existing file paths for content discovery:
    generated target list first (if present/creatable), then selected curated
    (or the defaults). Deduplicated, missing files skipped.
    """
    paths = []
    slug = slugify((hermes or {}).get("domain", "")) if hermes else ""
    gen = os.path.join(wl_dir(), f"target-{slug}.txt")
    if slug and os.path.exists(gen):
        paths.append(gen)

    ids = selected_ids if selected_ids else DEFAULT_CONTENT_IDS
    for p in resolve_ids(ids):
        if p not in paths:
            paths.append(p)

    if not paths:
        pc = primary_content_list()
        if pc:
            paths.append(pc)
    return paths
