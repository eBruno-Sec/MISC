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
    vuln_found = sorted(r["level"] for r in (results or [])
                        if not r.get("solved") and r.get("vulnerability_confirmed"))
    return {"vulnerability_confirmed_only": vuln_found,
            "attempted": attempted, "solved": len(by["solved"]),
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


_CONTENT_PATH_RE = re.compile(r"[A-Za-z0-9_\-./]{2,60}\.[A-Za-z0-9]{2,6}\b")
_SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".css", ".woff", ".woff2", ".svg", ".map")


def content_paths(text: str) -> list:
    """Path-like strings appearing as TEXT in served content. Pure.

    Mirrors what Apolaki already does in `agent.py` when it mines a served blob for paths, and what
    `codeintel` does to served JS: a file that discloses source, a stack trace, a config dump or a
    comment often names a path that is not linked anywhere. `same_origin_refs` only sees href/src, so a
    path revealed as prose is invisible to it — which is a general blind spot, not a Natas one.

    Static assets are skipped: they are noise, and fetching them proves nothing."""
    out = []
    src = text or ""
    for m in _CONTENT_PATH_RE.finditer(src):
        # An absolute URL must be judged by what PRECEDES the match, not by the match itself: the
        # character class excludes ':', so `http://cdn.test/x.js` matches only as `cdn.test/x.js` and a
        # `startswith("http")` test sees nothing wrong. Left unfixed, offsite hosts enter the crawl
        # frontier disguised as relative paths.
        before = src[max(0, m.start() - 3):m.start()]
        if "//" in before or before.endswith(("@", ":")):
            continue
        p = m.group(0).strip(".").lstrip("/")
        if not p or p.lower().endswith(_SKIP_EXT) or p.startswith(("http", "www.")):
            continue
        if "/" not in p and "." not in p:
            continue
        if p not in out:
            out.append(p)
    return out[:20]


def robots_paths(text: str) -> list:
    """Paths named by robots.txt — which exists to name them. Pure."""
    return list(dict.fromkeys(p.lstrip("/") for p in _DISALLOW_RE.findall(text or "")
                              if p not in ("/", "*")))


def recon_targets(html: str, robots_text: str = "") -> list:
    """Everything ordinary recon would fetch next, in priority order. Pure."""
    refs = same_origin_refs(html)
    return list(dict.fromkeys(list(GENERAL_RECON_PATHS) + robots_paths(robots_text)
                              + directories_of(refs) + refs + content_paths(html)))


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


_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
_ACTION_RE = re.compile(r"""\baction\s*=\s*["']([^"']*)["']""", re.I)
_METHOD_RE = re.compile(r"""\bmethod\s*=\s*["']?(get|post)""", re.I)
_INPUT_RE = re.compile(r"<(?:input|textarea|select)\b[^>]*>", re.I)
_NAME_RE = re.compile(r"""\bname\s*=\s*["']?([A-Za-z0-9_\-\[\]]+)""", re.I)
_VALUE_RE = re.compile(r"""\bvalue\s*=\s*["']([^"']*)["']""", re.I)
_TYPE_RE = re.compile(r"""\btype\s*=\s*["']?([a-z]+)""", re.I)


def forms_in(html: str) -> list:
    """[{action, method, fields}] for every form on the page. Pure, no network.

    Observation gets you to a page; a great many findings need the page ACTED ON. Hidden inputs are
    carried through unchanged (they are usually state the server expects back), and the interesting
    fields — the ones a tester varies — are returned separately so a caller can substitute values it
    discovered elsewhere."""
    out = []
    for m in _FORM_RE.finditer(html or ""):
        block, tag = m.group(1), m.group(0)[:m.group(0).find(">") + 1]
        fields, interesting = {}, []
        for inp in _INPUT_RE.finditer(block):
            raw = inp.group(0)
            nm = _NAME_RE.search(raw)
            if not nm:
                continue
            name = nm.group(1)
            typ = (_TYPE_RE.search(raw).group(1).lower() if _TYPE_RE.search(raw) else "text")
            if typ == "reset":
                continue
            val = _VALUE_RE.search(raw)
            fields[name] = val.group(1) if val else ""
            # A SUBMIT BUTTON IS PART OF THE PAYLOAD. Server handlers routinely gate on it
            # (`array_key_exists("submit", $_POST)`, `if isset($_POST['save'])`), so dropping it means
            # the request is silently rejected no matter how right the other values are — the form was
            # submitted and nothing happened, which reads as "the value was wrong".
            # It is carried, never VARIED: it is not an input a tester controls the meaning of.
            if typ not in ("hidden", "submit", "button", "image"):
                interesting.append(name)
        if fields:
            out.append({"action": (_ACTION_RE.search(tag).group(1) if _ACTION_RE.search(tag) else ""),
                        "method": (_METHOD_RE.search(tag).group(1).lower()
                                   if _METHOD_RE.search(tag) else "get"),
                        "fields": fields, "interesting": interesting})
    return out


def form_submissions(html: str, discovered) -> list:
    """[(label, form, payload)] — each form filled with a value the scan already DISCOVERED. Pure.

    This is the step that turns observation into interaction, and it is general: a value recovered from
    one part of a target is exactly what a tester feeds back into a form on another part. Nothing here
    knows what any particular form is for.

    Every discovered value is tried in every non-hidden field, one field at a time, so a success is
    attributable to a single substitution rather than a lucky combination."""
    out = []
    for form in forms_in(html):
        # 14, not 6. A decoded value necessarily sits behind the raw tokens it was derived from, so a
        # tight budget silently excludes exactly the candidates that cost the most to produce — the
        # decode chain ran, found the answer, and nothing ever submitted it.
        for value in list(discovered or [])[:14]:
            for field in form["interesting"][:3]:
                payload = dict(form["fields"])
                payload[field] = value
                out.append(("form %s=%s..." % (field, str(value)[:8]), form, payload))
    return out[:30]


_ABS_PATH_RE = re.compile(r"(/(?:etc|var|opt|home|usr|srv|tmp|proc)/[A-Za-z0-9_\-./]{2,80})")


def absolute_paths(text: str) -> list:
    """Filesystem paths named in content — the target telling you where something lives. Pure.

    A hint, a stack trace, an error page or a config dump routinely names an absolute path. Combined with
    a parameter that loads files, that is the whole of a local-file-read: the target supplies both the
    vulnerability and the address. General to any application, not a property of one."""
    out = []
    for m in _ABS_PATH_RE.finditer(text or ""):
        p = m.group(1).rstrip(".,;:)\"'")
        if p not in out:
            out.append(p)
    return out[:12]


def param_substitutions(urls, values) -> list:
    """[(label, url)] — each observed URL parameter replaced with each discovered path. Pure.

    This is the local-file-read probe in its general form: a parameter that names a resource is a
    parameter that may name ANY resource. One parameter is varied at a time so a success attributes to a
    single substitution, the same discipline the form prober uses."""
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
    out = []
    for u in list(urls or [])[:6]:
        parts = urlsplit(str(u))
        qs = parse_qsl(parts.query)
        if not qs:
            continue
        for i, (k, _v) in enumerate(qs):
            for val in list(values or [])[:6]:
                new = list(qs)
                new[i] = (k, val)
                out.append(("param %s=%s" % (k, str(val)[:34]),
                            urlunsplit((parts.scheme, parts.netloc, parts.path,
                                        urlencode(new), parts.fragment))))
    return out[:24]


# Tokens worth feeding back into a form: long-ish opaque strings. A secret read out of a disclosed file
# looks like this, and so does a session id or a hash. Deliberately wider than PASSWORD_RE, because the
# value a form wants is often NOT the 32-char answer — it is an intermediate the server checks.
_INTERESTING_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])([A-Za-z0-9+/=_\-]{8,64})(?![A-Za-z0-9])")


def solve_level(level: int, password: str, fetch, budget: int = 70, post=None) -> dict:
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
                # Links AND paths named in the content. A source-disclosure page, stack trace or config
                # dump names files that are linked from nowhere; href/src extraction cannot see them.
                nxt += [urljoin(u, r) for r in same_origin_refs(b)]
                nxt += [urljoin(u, r) for r in content_paths(b)]
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

    # INTERACTION. Everything above is observation; a great many findings need the page acted on. Values
    # the scan already discovered anywhere are fed back into every form field, one substitution at a
    # time so a success is attributable. `post` is optional so a caller without it degrades to
    # observation-only rather than crashing — and the result then says the class went untested.
    # RANK BY RARITY. A secret appears in ONE place; boilerplate (framework names, nav labels, the level's
    # own hostname) appears in every page fetched. Taking the first tokens found meant the landing page's
    # furniture crowded out the value dug out of a disclosed file — the engines had already recovered it
    # and the harness never tried it. Rarity is a general signal, not a hint about any particular target.
    freq, first_seen = {}, {}
    for url, b in pages.items():
        for tok in set(_INTERESTING_TOKEN_RE.findall(b)):
            if tok == password:
                continue
            freq[tok] = freq.get(tok, 0) + 1
            first_seen.setdefault(tok, url)
    # rarest first; among equals prefer what was found by DIGGING (not the landing page)
    discovered = sorted(freq, key=lambda t: (freq[t], first_seen[t] == base, -len(t)))

    # DECODE what was discovered. An application that stores a check-value obfuscated —
    # `base64(strrev(bin2hex(x)))` is ordinary — hands over the answer in a form no single decode step
    # recovers. `intel.decode_chains` walks stacked encodings, so the plaintext joins the candidate pool
    # ahead of the encoded form it came from.
    try:
        import intel as _intel
        decoded = []
        for tok in discovered[:8]:
            for value, recipe in _intel.decode_chains(tok, depth=4):
                if 6 <= len(value) <= 64 and value not in decoded and value not in freq:
                    decoded.append(value)
        # Order matters and a first attempt got it wrong: prepending decoded values pushed the rarest
        # RAW token out of the candidate budget and broke a level that had been passing. The rarest few
        # originals keep their place; decoded values slot in behind them.
        discovered = discovered[:3] + decoded + discovered[3:]
    except Exception:
        pass
    # LOCAL-FILE READ. A parameter that names a resource may name any resource, and targets routinely
    # disclose absolute paths in hints, errors and config dumps. Both halves come from the target.
    paths = []
    for b in pages.values():
        for p in absolute_paths(b):
            if p not in paths:
                paths.append(p)
    if paths:
        for label, url in param_substitutions(list(pages), paths):
            if fetches >= budget:
                break
            try:
                s, b, _ = fetch(url, auth)
            except Exception:
                continue
            fetches += 1
            if s == 200 and b != body:
                pages["%s [%s]" % (base, label)] = b

    # COMMAND INJECTION reading a disclosed path. Both halves come from the target: it names an absolute
    # path AND executes injected input. `cmdi_tool` supplies the separator shapes so this benchmark does
    # not invent its own payload vocabulary.
    inject_values = []
    if paths:
        try:
            import cmdi_tool as _cmdi
            for p in paths[:3]:
                inject_values += [d["payload"] for d in _cmdi.read_file_payloads("", p)]
        except Exception:
            pass

    if post and (discovered or inject_values):
        for label, form, payload in form_submissions(body, inject_values + discovered):
            if fetches >= budget:
                break
            action = urljoin(base, form["action"] or "")
            try:
                if form["method"] == "post":
                    s, b, _ = post(action, auth, payload)
                else:
                    from urllib.parse import urlencode
                    sep = "&" if "?" in action else "?"
                    s, b, _ = fetch(action + sep + urlencode(payload), auth)
            except Exception:
                continue
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
    # FOUND THE BUG vs CAPTURED THE FLAG are different claims, and merging them understates the tool.
    # natas9 is the case that forced the distinction: the general cmdi engine CONFIRMS the injection with
    # its own FP-safe oracle (a computed product, never an echo), but the target discloses nowhere the
    # password lives — and inferring `/etc/natas_webpass/natasN` is Natas knowledge, not a capability.
    # A scanner's job is finding the vulnerability; knowing where the prize sits is the operator's.
    vuln = confirm_vulnerability(base, auth, body, fetch)
    return {"level": level, "solved": False, "blocked": False, "class": classify(level),
            "fetches": fetches, "candidates_tried": len(seen),
            "vulnerability_confirmed": vuln,
            "origin": ("vulnerability CONFIRMED (%s) but the flag's location is not disclosed — "
                       "operator knowledge, not a scanner gap" % vuln) if vuln else
                      "no general engine surfaced a credential"}


def confirm_vulnerability(base: str, auth: dict, html: str, fetch) -> str:
    """Name the vulnerability class a general engine can PROVE here, or "". Pure apart from `fetch`.

    Separate from flag capture on purpose. Reporting only "unsolved" for a level whose bug was found and
    proven would understate the tool and mislead the reader about where the ceiling actually is."""
    from urllib.parse import urlencode
    try:
        import cmdi_tool
    except Exception:
        return ""
    for form in forms_in(html)[:2]:
        for field in form["interesting"][:2]:
            base_payload = dict(form["fields"])
            base_payload[field] = "apolaki"
            try:
                _s, baseline, _h = fetch(base + "?" + urlencode(base_payload), auth)
            except Exception:
                continue
            for item in cmdi_tool.output_payloads("apolaki")[:5]:
                probe_payload = dict(form["fields"])
                probe_payload[field] = item["payload"]
                try:
                    _s2, probe, _h2 = fetch(base + "?" + urlencode(probe_payload), auth)
                except Exception:
                    continue
                if cmdi_tool.analyze_output(baseline, probe):
                    return "command_injection"
    return ""
