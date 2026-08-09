"""
Natas ladder benchmark (#33) — how far do Apolaki's GENERAL engines climb, honestly?

OverTheWire's Natas is 34 levels of real web vulnerability classes. Each level's page hides the NEXT
level's password, so the ladder is inherently sequential and self-verifying: a recovered value either
authenticates to level N+1 or it does not. That makes the oracle unusually good — no judgement call, no
partial credit, no "looks like a finding".

THREE DISCIPLINES, or the number is worthless:

1. **General engines only.** A level counts as solved when an engine that exists to find a CLASS of bug
   surfaces the credential. A level solved by logic written for that level is not a capability, it is a
   lookup table, and it inflates every future claim. Same rule as the GinAndJuice blind run. This module
   holds NO per-level exploit logic, and `test_natas_ladder.py` asserts that structurally.

2. **Passwords never reach the repository.** Thirty-four levels produce thirty-four live credentials.
   They are held in memory and written only to a gitignored path. A natas0 password already leaked into
   git history once this project; the temptation here is 34x larger.

3. **An honest ceiling.** The useful output is
   `solved-generally / needs-operator-step / out-of-scope-for-a-scanner`, not a padded total. Several
   late levels (hash-extension forgery, `preg_replace /e`) are genuinely CTF-shaped, and reporting them
   as failures of a scanner would be as dishonest as claiming them as wins.

Pure functions here; the network lives in `run_ladder`, which the caller drives.
"""
from __future__ import annotations

import base64
import re

BASE = "natas%d.natas.labs.overthewire.org"
FIRST_LEVEL, LAST_LEVEL = 0, 34

# A Natas password is 32 alphanumeric characters. Deliberately anchored on word boundaries so a longer
# base64 blob or a hex digest does not read as one.
PASSWORD_RE = re.compile(r"(?<![A-Za-z0-9])([A-Za-z0-9]{32})(?![A-Za-z0-9])")


def level_url(level: int) -> str:
    """Pure."""
    return "http://" + BASE % level + "/"


def auth_header(level: int, password: str) -> dict:
    """HTTP Basic for natas<level>. Pure."""
    token = base64.b64encode(("natas%d:%s" % (level, password)).encode()).decode()
    return {"Authorization": "Basic " + token}


def candidate_passwords(text: str, exclude=()) -> list:
    """Every 32-char alphanumeric token in `text`, minus ones already known. Pure.

    Deliberately dumb: this does NOT know where a level hides its secret. It is the general shape of the
    thing being looked for, and everything that narrows it down comes from Apolaki's own engines."""
    out, seen = [], set(exclude or ())
    for m in PASSWORD_RE.finditer(text or ""):
        v = m.group(1)
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def classify(level: int) -> str:
    """What KIND of level this is, so the score can be read honestly. Pure.

    This is not a hint about how to solve one — it is the reporting bucket. A scanner failing a level
    that requires forging a hash-extension is not the same kind of failure as missing a SQL injection,
    and a single number that merges them tells the reader nothing."""
    if level in (0, 1, 2, 3, 4, 5, 6, 7):
        return "surface"          # comments, robots.txt, headers, LFI, trivially reachable state
    if level in (8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18):
        return "injection"        # command, SQL (incl. blind), upload, weak crypto/session
    if level in (19, 20, 21, 22, 23, 24, 25, 26):
        return "session_logic"    # session handling, type juggling, LFI-to-session, deserialization
    return "specialist"           # 27-34: hash extension, preg_replace /e, XXE, timing


def summarise(results: list) -> dict:
    """Roll per-level outcomes into the honest three-bucket score. Pure.

    `solved` counts ONLY levels where a general engine produced a credential that then authenticated.
    Anything else is separated by reason rather than folded into a failure count."""
    by = {"solved": [], "not_solved": [], "blocked": []}
    for r in results or []:
        if r.get("solved"):
            by["solved"].append(r["level"])
        elif r.get("blocked"):
            by["blocked"].append(r["level"])
        else:
            by["not_solved"].append(r["level"])
    kinds = {}
    for r in results or []:
        k = classify(r["level"])
        kinds.setdefault(k, {"solved": 0, "total": 0})
        kinds[k]["total"] += 1
        if r.get("solved"):
            kinds[k]["solved"] += 1
    attempted = len(results or [])
    return {"attempted": attempted, "solved": len(by["solved"]),
            "not_solved": len(by["not_solved"]), "blocked": len(by["blocked"]),
            "solved_levels": by["solved"], "unsolved_levels": by["not_solved"],
            "by_class": kinds,
            "rate": round(100.0 * len(by["solved"]) / attempted, 1) if attempted else 0.0}


def report_line(summary: dict) -> str:
    """One honest sentence. Names the ceiling rather than implying the rate is the capability."""
    parts = ", ".join("%s %d/%d" % (k, v["solved"], v["total"])
                      for k, v in sorted(summary.get("by_class", {}).items()))
    return ("Natas ladder: %d/%d levels solved by general engines (%.1f%%) — %s. Unsolved levels are "
            "reported by class, not merged into one number: a scanner missing a hash-extension forgery "
            "is a different fact from a scanner missing a SQL injection."
            % (summary.get("solved", 0), summary.get("attempted", 0), summary.get("rate", 0.0), parts))


def engines_for(html: str, url: str) -> list:
    """Run Apolaki's GENERAL passive analyzers over one page and return everything they surfaced.

    This is the honest core of the benchmark: the only things consulted are engines that exist to find a
    CLASS of bug on any target. No level is named, no level-specific path is tried. If a level falls, it
    falls because a general engine did the work.

    Returns [{engine, value}] so the report can say WHICH engine earned each level rather than just
    counting."""
    out = []
    try:
        import codereview as cr
        for hit in (cr.scan_comment_secrets(html) or []):
            out.append({"engine": "scan_comment_secrets", "value": str(hit.get("value", ""))})
        for hit in (cr.scan_secrets(html) or []):
            out.append({"engine": "scan_secrets", "value": str(hit.get("value", hit))})
    except Exception:
        pass
    try:
        import codereview as cr
        for c in (cr.scan_comments(html) or []):
            out.append({"engine": "scan_comments", "value": str(c.get("text", c))})
    except Exception:
        pass
    return out


# Ordinary recon paths every web assessment checks. These are NOT level hints — robots.txt and a
# directory index are what any scanner looks at on any target. The line that must not be crossed is a
# path that only matters on one Natas level; test_natas_ladder.py asserts none appear here.
GENERAL_RECON_PATHS = ("robots.txt", ".git/config", "sitemap.xml", ".well-known/security.txt")

_HREF_RE = re.compile(r"""(?:href|src)\s*=\s*["']([^"'>\s]+)["']""", re.I)
_DISALLOW_RE = re.compile(r"(?im)^\s*(?:dis)?allow\s*:\s*(\S+)")


def same_origin_refs(html: str) -> list:
    """Relative resources the page itself references. Pure — ordinary crawling, not a level hint."""
    out = []
    for ref in _HREF_RE.findall(html or ""):
        if ref.startswith(("http://", "https://", "//", "#", "mailto:", "javascript:", "data:")):
            continue
        out.append(ref.lstrip("/"))
    return list(dict.fromkeys(out))


def directories_of(refs) -> list:
    """Parent directories of referenced resources — the classic exposed-index check. Pure.

    A page that references `files/pixel.png` implies `files/`. Looking there is generic recon (Apolaki's
    `exposed_files_harvest` does the same) and is how a directory listing gets found on ANY target."""
    out = []
    for r in refs or []:
        if "/" in r:
            d = r.rsplit("/", 1)[0] + "/"
            if d not in out:
                out.append(d)
    return out


def robots_paths(text: str) -> list:
    """Paths named by robots.txt — which exists to name them. Pure."""
    return list(dict.fromkeys(p.lstrip("/") for p in _DISALLOW_RE.findall(text or "")
                              if p not in ("/", "*")))


def recon_targets(html: str, robots_text: str = "") -> list:
    """Everything ordinary recon would fetch next, in priority order. Pure."""
    refs = same_origin_refs(html)
    return list(dict.fromkeys(list(GENERAL_RECON_PATHS) + robots_paths(robots_text)
                              + directories_of(refs) + refs))


# A client-controlled boolean set to 0 — `loggedin=0`, `admin=0`. Word-anchored so `x_0` or a longer
# token does not match. Defined here rather than inline: this pattern was once corrupted by a literal
# backspace character that grep rendered invisibly, and the probe silently matched nothing.
_BOOL_ZERO_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,20})\s*=\s*0\b")


def retry_variants(html: str, origin: str, path: str = "/", headers_text: str = "") -> list:
    """[(label, headers)] — request variants Apolaki's GENERAL engines say are worth retrying.

    Sourced from `header_trust_tool`, which exists to test the class "authorization decided by a
    client-controlled header" on any target. Notably `expected_values_from_denial` reads the values the
    REFUSAL ITSELF names — a denial saying "authorized users come only from X" has handed over X, and
    harvesting that is general behaviour, not a level hint."""
    out = []
    try:
        import header_trust_tool as ht
        for header, value, _control, _why in ht.header_candidates(origin, path, html or "")[:6]:
            out.append(("%s: %s" % (header, value[:40]), {header: value}))
    except Exception:
        pass
    # Client-controlled boolean cookies: flip 0 -> 1. Generic client-side-trust probe.
    #
    # RESPONSE HEADERS ARE SEARCHED TOO, not just the body. A Set-Cookie header is the ordinary place a
    # server hands the client an authorization input, and reading only the body missed every one of them
    # — a probe that could see just half of its own input surface.
    for source in (html or "", headers_text or ""):
        for m in _BOOL_ZERO_RE.finditer(source):
            label = "cookie %s=1" % m.group(1)
            if label not in [o[0] for o in out]:
                out.append((label, {"Cookie": "%s=1" % m.group(1)}))
    return out[:12]


def solve_level(level: int, password: str, fetch, budget: int = 45) -> dict:
    """Attempt ONE level with general engines. THE single implementation — the /benchmark/natas endpoint
    calls this rather than repeating it, because two copies of a solver drift and then disagree about
    what the benchmark measured.

    `fetch(url, headers) -> (status, body, headers_text)` is injected so this is testable with no network.

    The oracle is the ladder itself: a candidate counts only when it actually AUTHENTICATES to the next
    level. No similarity heuristic, no "looks like a password"."""
    from urllib.parse import urljoin
    base = level_url(level)
    auth = auth_header(level, password)
    try:
        st, body, hdrs = fetch(base, auth)
    except Exception as e:
        return {"level": level, "solved": False, "blocked": True, "class": classify(level),
                "reason": "fetch failed: %s" % type(e).__name__}
    if st != 200:
        return {"level": level, "solved": False, "blocked": True, "class": classify(level),
                "reason": "HTTP %s" % st}

    pages, fetches = {base: body}, 1
    rst, rtxt, _ = fetch(base + "robots.txt", auth)
    fetches += 1
    frontier = [urljoin(base, p) for p in recon_targets(body, rtxt if rst == 200 else "")]
    for _hop in range(2):                       # depth 2: a directory index is one hop from its files
        nxt = []
        for u in frontier:
            if fetches >= budget or u in pages:
                continue
            s, b, _ = fetch(u, auth)
            fetches += 1
            if s == 200:
                pages[u] = b
                nxt += [urljoin(u, r) for r in same_origin_refs(b)]
        frontier = nxt

    for label, extra in retry_variants(body, base.rstrip("/"), "/", hdrs):
        if fetches >= budget:
            break
        merged = dict(auth)
        merged.update(extra)
        s, b, _ = fetch(base, merged)
        fetches += 1
        if s == 200 and b != body:
            pages["%s [%s]" % (base, label)] = b

    pool = []
    for u, b in pages.items():
        for e in engines_for(b, u):
            pool += [(v, "engine:" + e["engine"]) for v in candidate_passwords(e["value"], exclude=[password])]
        pool += [(v, "recon@" + (u.replace(base, "") or "root"))
                 for v in candidate_passwords(b, exclude=[password])]

    seen = set()
    for value, origin in pool:
        if value in seen:
            continue
        seen.add(value)
        try:
            s3, _b, _h = fetch(level_url(level + 1), auth_header(level + 1, value))
        except Exception:
            continue
        if s3 == 200:
            return {"level": level, "solved": True, "next_password": value, "origin": origin,
                    "class": classify(level), "fetches": fetches}
    return {"level": level, "solved": False, "blocked": False, "class": classify(level),
            "fetches": fetches, "candidates_tried": len(seen),
            "origin": "no general engine surfaced a credential"}
