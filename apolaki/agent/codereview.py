"""
Static source review (SAST-lite) + JS secret/endpoint mining.

From Bug Bounty Bootcamp (Li, Ch 22). Black-box hunters routinely pull JS bundles
and leaked source; this turns that into signal: dangerous sinks (RCE / injection
/ XSS / deserialization), hardcoded secrets, weak crypto, revealing developer
comments, debug endpoints, and API endpoints/paths that seed the attack surface.

All analyzers are pure and operate on text — unit-tested here; tools._run_js_review
fetches in-scope JS (or takes pasted source) and runs them.
"""
from __future__ import annotations

import math
import re

# ── Hardcoded secrets ────────────────────────────────────────────
_SECRET_PATTERNS = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    ("AWS secret access key", re.compile(r"(?i)aws.{0,20}?(secret|key).{0,5}['\"]([A-Za-z0-9/+=]{40})['\"]"), "critical"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "high"),
    ("Google OAuth token", re.compile(r"\bya29\.[0-9A-Za-z\-_]{20,}"), "high"),
    ("GitHub token", re.compile(r"\bgh[posru]_[0-9A-Za-z]{36,}\b"), "critical"),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "high"),
    ("Stripe live secret key", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b"), "critical"),
    ("Twilio API key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "high"),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "critical"),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "medium"),
    ("GitHub legacy token (40-hex)", re.compile(r"(?i)(?:github|gh|token|access[_-]?token).{0,20}?\b([a-f0-9]{40})\b"), "high"),
]
# generic KEY = "value" assignments
_ASSIGN = re.compile(
    r"(?i)\b(api[_-]?key|secret[_-]?key|secret|password|passwd|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\b"
    r"\s*[:=]\s*['\"]([^'\"]{8,})['\"]")
_PLACEHOLDER = re.compile(r"(?i)(your|example|changeme|placeholder|xxxx|<[^>]+>|\{\{|\}\}|test|dummy|sample|redacted|\.\.\.)")


def _redact(s: str) -> str:
    return s if len(s) <= 8 else f"{s[:4]}…{s[-4:]}"


def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1


def scan_secrets(text: str) -> list:
    out, seen = [], set()
    for name, rx, sev in _SECRET_PATTERNS:
        for m in rx.finditer(text or ""):
            val = m.group(len(m.groups())) if m.groups() else m.group(0)
            key = (name, val)
            if key in seen:
                continue
            seen.add(key)
            out.append({"type": name, "severity": sev, "match": _redact(val),
                        "line": _line_of(text, m.start())})
    for m in _ASSIGN.finditer(text or ""):
        keyname, val = m.group(1), m.group(2)
        if _PLACEHOLDER.search(val) or val.isdigit():
            continue
        key = ("assignment:" + keyname.lower(), val)
        if key in seen:
            continue
        seen.add(key)
        out.append({"type": f"Hardcoded {keyname}", "severity": "high",
                    "match": _redact(val), "line": _line_of(text, m.start())})
    return out


# ── Dangerous sinks (RCE / injection / XSS / deserialization) ────
_SINKS = [
    (re.compile(r"\beval\s*\("), "eval()", "code injection / RCE", "high"),
    (re.compile(r"\bnew\s+Function\s*\("), "new Function()", "code injection", "medium"),
    (re.compile(r"\bdocument\.write(?:ln)?\s*\("), "document.write()", "DOM XSS", "medium"),
    (re.compile(r"\.innerHTML\s*="), "innerHTML =", "DOM XSS", "medium"),
    (re.compile(r"\.outerHTML\s*="), "outerHTML =", "DOM XSS", "medium"),
    (re.compile(r"\.insertAdjacentHTML\s*\("), "insertAdjacentHTML()", "DOM XSS", "medium"),
    (re.compile(r"\$\([^)]*\)\.html\s*\("), "jQuery .html()", "DOM XSS", "medium"),
    (re.compile(r"\bset(?:Timeout|Interval)\s*\(\s*['\"]"), "setTimeout/Interval(string)", "code injection", "low"),
    (re.compile(r"\b(?:location|document\.location)\s*(?:\.href|\.assign\s*\(|\.replace\s*\()?\s*[=(][^;\n]*(?:hash|search|location|referrer|\bname\b)"),
     "location <- URL source", "DOM open redirect / DOM XSS", "medium"),
    # client-side prototype pollution — the deparam gadget + unsafe deep-merge/
    # __proto__ writes (ginandjuice's /blog vector is deparam.js).
    (re.compile(r"\bdeparam\s*\("), "deparam()", "client-side prototype pollution (deparam gadget)", "medium"),
    (re.compile(r"(?:\$|jQuery)\.extend\s*\(\s*true\b"), "$.extend(true, ...)", "client-side prototype pollution", "medium"),
    (re.compile(r"__proto__|constructor\s*\[\s*['\"]prototype|\bprototype\s*\[\s*[^\]]+\]\s*="), "__proto__ / prototype write", "client-side prototype pollution", "medium"),
    # client-side template injection surface (AngularJS evaluates {{ }} in the DOM)
    (re.compile(r"\bng-app\b|angular\.bootstrap\s*\(|\[ng-app\]"), "AngularJS ng-app", "client-side template injection (CSTI)", "medium"),
    (re.compile(r"child_process|\.execSync?\s*\(|\.spawn\s*\("), "child_process/exec()", "command injection / RCE", "high"),
    (re.compile(r"\bunserialize\s*\("), "unserialize()", "insecure deserialization", "high"),
    (re.compile(r"\b(?:system|shell_exec|passthru|popen|assert)\s*\("), "PHP system/shell_exec()", "RCE", "high"),
    (re.compile(r"\bpickle\.loads?\s*\(|\byaml\.load\s*\((?![^)]*Safe)"), "pickle/yaml.load()", "insecure deserialization", "high"),
    (re.compile(r"\bos\.system\s*\(|\bsubprocess\.(?:call|Popen|run)\s*\([^)]*shell\s*=\s*True"), "os.system/shell=True", "command injection", "high"),
    (re.compile(r"\bMarshal\.load\s*\("), "Marshal.load()", "insecure deserialization", "high"),
]


def scan_sinks(text: str) -> list:
    out = []
    for rx, name, vuln, sev in _SINKS:
        m = rx.search(text or "")
        if m:
            out.append({"sink": name, "vuln": vuln, "severity": sev, "line": _line_of(text, m.start())})
    return out


# ── Weak crypto ──────────────────────────────────────────────────
_WEAK = [
    (re.compile(r"(?i)\bMD5\b|createHash\(['\"]md5"), "MD5"),
    (re.compile(r"(?i)\bMD4\b"), "MD4"),
    (re.compile(r"(?i)\bSHA-?1\b|createHash\(['\"]sha1"), "SHA-1"),
    (re.compile(r"(?i)\bDES\b(?!C)"), "DES"),
    (re.compile(r"(?i)\bRC4\b"), "RC4"),
    (re.compile(r"(?i)\bECB\b|['\"]aes-\d+-ecb"), "ECB mode"),
    (re.compile(r"Math\.random\s*\("), "Math.random() (non-crypto)"),
]


def scan_weak_crypto(text: str) -> list:
    out = []
    for rx, name in _WEAK:
        m = rx.search(text or "")
        if m:
            out.append({"algorithm": name, "line": _line_of(text, m.start())})
    return out


# ── Revealing developer comments ─────────────────────────────────
_COMMENT = re.compile(r"(?m)(?://|#|/\*|<!--)\s*(.*?(?:todo|fixme|hack|xxx|bug|insecure|not secure|"
                      r"vuln|hardcoded|backdoor|do not ship|remove this|temporary|debug|csrf|"
                      r"disable|bypass).*)$", re.I)


def scan_comments(text: str) -> list:
    out = []
    for m in _COMMENT.finditer(text or ""):
        out.append({"comment": m.group(1).strip()[:160], "line": _line_of(text, m.start())})
    return out[:25]


# Any comment, not just a suspicious-keyword one — comments are where credentials get parked.
# The `//` branch must NOT fire inside a URL: without the lookbehind, `href="http://host/..."` reads as a
# line comment and the whole rest of the line becomes a "comment body". That produced a false positive on
# the very first live page this was tested against.
_ANY_COMMENT = re.compile(
    r"(?s)(?:<!--(.*?)-->"          # HTML
    r"|/\*(.*?)\*/"                 # block
    r"|(?m:(?<![:/])//[ \t]*(.*)$)"  # line comment, not the // in a scheme
    r"|(?m:^[ \t]*\#[ \t]*(.*)$))")  # shell/python comment at line start only

# Credential-shaped text a developer leaves in prose, which the structured _SECRET_PATTERNS miss because
# it has no vendor prefix: "the password for X is <32 hex-ish chars>", "password: hunter2".
_COMMENT_CRED = [
    ("credential in comment", re.compile(
        r"(?i)\b(?:pass(?:word|wd)?|pwd|secret|api[_-]?key|token|credential)s?\b[^A-Za-z0-9\r\n]{0,20}"
        r"(?:for\s+\S{1,32}\s+)?(?:is|=|:)?[^A-Za-z0-9\r\n]{0,6}([A-Za-z0-9!@#$%^&*_\-+.]{8,64})"),
     "high"),
]

# Words that make a "credential" a placeholder rather than a secret.
_PLACEHOLDER_WORD = re.compile(
    r"(?i)^(your|my|the|a|an|some|example|sample|changeme|change|placeholder|xxx+|todo|fixme|none|null|"
    r"true|false|password|passwd|pwd|secret|token|apikey|key|value|string|here|goes|redacted|hidden|"
    r"insert|enter|set|put|real|actual|test|dummy|foo|bar|baz)$")


def _is_placeholder(val: str) -> bool:
    """A documentation placeholder, not a leak. Token-aware, because the common form is hyphen-joined
    prose — `your-password-here` is three placeholder words, while `my-production-secret-42` is not
    (production and 42 carry real information)."""
    v = val.strip()
    if not v or re.fullmatch(r"[*.\-_x]+", v, re.I):        # masks
        return True
    if re.fullmatch(r"<.*>|\{.*\}|\[.*\]|\$\{.*\}", v):     # template slots
        return True
    tokens = [t for t in re.split(r"[-_.\s]+", v) if t]
    return bool(tokens) and all(_PLACEHOLDER_WORD.match(t) for t in tokens)


def scan_comment_secrets(text: str) -> list:
    """Credentials parked in COMMENTS — the class `scan_secrets` cannot see.

    Two blind spots meet here and neither alone catches it. `scan_secrets` matches vendor-shaped tokens
    (AKIA…, AIza…) and a password written in prose has no such shape. `scan_comments` only surfaces
    comments containing todo/fixme/hack, and a comment that simply states a password contains none of
    those words.

    Proven live on OverTheWire Natas level 0, whose served HTML carries
    `<!--The password for natas1 is scfWG6qNEIdzqVyfRwEGXyNUfFZkZeQ7 -->`. Apolaki read that page, ran
    both scanners, and reported nothing.

    Placeholders are filtered, because `<!-- password: your-password-here -->` is documentation, not a
    leak. Pure."""
    out, seen = [], set()
    for m in _ANY_COMMENT.finditer(text or ""):
        body = next((g for g in m.groups() if g), "") or ""
        if not body.strip():
            continue
        for name, rx, sev in _COMMENT_CRED:
            for cm in rx.finditer(body):
                val = cm.group(1).strip()
                if len(val) < 8 or _is_placeholder(val) or val in seen:
                    continue
                # a run of identical characters is a mask, not a credential
                if len(set(val)) <= 2:
                    continue
                seen.add(val)
                out.append({"kind": name, "severity": sev, "value": val,
                            "comment": body.strip()[:160], "line": _line_of(text, m.start())})
    return out[:15]


# ── Endpoint / path extraction (seed the surface) ────────────────
_FULL_URL = re.compile(r"https?://[^\s'\"<>()\\]{4,}")
_PATH = re.compile(r"['\"](/[A-Za-z0-9_\-/.]{2,}(?:\?[^'\"]*)?)['\"]")
_FETCH = re.compile(r"(?:fetch|axios(?:\.\w+)?|\.open)\s*\(\s*['\"]([^'\"]+)['\"]")
# Modern SPA bundles write API routes as TEMPLATE LITERALS with ${...} interpolation:
#   `${this.hostServer}/rest/basket/${e}`   this.hostServer+"/api/BasketItems"
# _PATH only matches a single/double-quoted literal that is ENTIRELY a leading-slash
# path, so every interpolated REST route (basket, ftp, Users, SecurityQuestions,
# reviews, 2fa, …) is invisible and never gets probed — the single biggest attack-surface
# gap on Angular/React targets. Match a known API subtree wherever it occurs (allowing
# ${...} path segments), plus well-known standalone sensitive paths, and normalise the
# interpolations to {id} so the endpoint seeds the access-control / exposure probes.
_API_TREE = re.compile(
    r"/(?:rest|api|graphql|socket\.io|b2b)(?:/(?:[A-Za-z0-9_\-.]+|\$\{[^}]*\}))+", re.I)
_API_STD = re.compile(
    r"/(?:ftp|metrics|snippets|encryptionkeys|redirect|support|profile|swagger|"
    r"video|dataerasure|\.well-known)(?:/[A-Za-z0-9_\-.]*)?", re.I)


def _norm_tmpl(p: str) -> str:
    # ${expr} -> {id}; collapse a trailing partial segment left by an interpolation
    # (e.g. /ftp/order_{id}.pdf stays, /ftp/order_ -> /ftp/) so it is fetchable.
    p = re.sub(r"\$\{[^}]*\}", "{id}", p)
    p = re.sub(r"/[A-Za-z0-9_\-.]*_$", "/", p)
    return p


def extract_endpoints(text: str) -> list:
    found = []
    for m in _FULL_URL.finditer(text or ""):
        found.append(m.group(0).rstrip(".,;"))
    for m in _FETCH.finditer(text or ""):
        found.append(m.group(1))
    for m in _PATH.finditer(text or ""):
        p = m.group(1)
        if "/api" in p or re.search(r"\.(json|php|aspx?|jsp|do|action)$", p) or p.count("/") >= 2:
            found.append(p)
    for rx in (_API_TREE, _API_STD):
        for m in rx.finditer(text or ""):
            found.append(_norm_tmpl(m.group(0)))
    return list(dict.fromkeys(found))[:400]


# ── High-entropy scan (TruffleHog-style, catches unformatted secrets) ──
def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


_TOKEN = re.compile(r"[A-Za-z0-9/+_=\-]{20,}")


def scan_entropy(text: str, threshold: float = 4.3) -> list:
    out, seen = [], set()
    for m in _TOKEN.finditer(text or ""):
        tok = m.group(0)
        if tok in seen or _PLACEHOLDER.search(tok):
            continue
        if _shannon(tok) >= threshold:
            seen.add(tok)
            out.append({"match": _redact(tok), "entropy": round(_shannon(tok), 2),
                        "line": _line_of(text, m.start())})
    return out[:20]


# ── Assemble findings for one source ─────────────────────────────
def review(text: str, source: str) -> dict:
    findings = []
    for s in scan_secrets(text):
        findings.append({
            "title": f"Hardcoded secret in JS/source: {s['type']}", "severity": s["severity"],
            "target": source, "description": f"{s['type']} found in {source} (line {s['line']}): {s['match']}",
            "impact": "Leaked credentials allow direct access to the associated service/account.",
            "reproduction_steps": [f"Open {source}", f"See {s['type']} at line {s['line']}"],
            "evidence": f"line {s['line']}: {s['match']}", "cwe": "CWE-798",
            "family": "code-review", "tags": ["secrets", "disclosure"], "confidence": "candidate"})
    for s in scan_sinks(text):
        findings.append({
            "title": f"Security-sensitive sink: {s['sink']} ({s['vuln']})", "severity": s["severity"],
            "target": source, "description": f"{s['sink']} at line {s['line']} in {source} — potential {s['vuln']} "
                                             "if it reaches user-controlled input.",
            "impact": f"Possible {s['vuln']}.", "reproduction_steps": [f"Review {source} line {s['line']}",
                                                                       "Trace whether user input reaches this sink"],
            "cwe": "CWE-94", "family": "code-review", "tags": ["sink", s["vuln"].split("/")[0].strip()],
            "confidence": "candidate"})
    for w in scan_weak_crypto(text):
        findings.append({
            "title": f"Weak cryptography: {w['algorithm']}", "severity": "low", "target": source,
            "description": f"{w['algorithm']} referenced at line {w['line']} in {source}.",
            "impact": "Weak/insecure algorithm; impact depends on where it protects data.",
            "reproduction_steps": [f"Review {source} line {w['line']}"], "cwe": "CWE-327",
            "family": "code-review", "tags": ["crypto"], "confidence": "candidate"})
    # Credentials parked in comments — a distinct class from "revealing comments" (no todo/fixme keyword)
    # and from scan_secrets (no vendor-shaped token). Confirmed live on Natas level 0.
    for cs in scan_comment_secrets(text):
        findings.append({
            "title": "Credential exposed in a source comment",
            "severity": cs["severity"], "target": source, "confidence": "confirmed",
            "family": "sensitive_exposure", "cwe": "CWE-615",
            "description": ("A comment in %s states a credential in plain text: %r. Comments are served "
                            "to every client; this is readable by anyone who views the source."
                            % (source, cs["comment"])),
            "impact": "The credential is disclosed to anyone who fetches the page or file.",
            "evidence": "GET %s -> comment at line %s contains a credential-shaped value"
                        % (source, cs["line"]),
            "oracle": ("a comment body matches a credential statement and the value is not a placeholder "
                       "or mask"),
            "remediation": "Remove the credential from the source and rotate it.",
            "tags": ["secrets", "comment", "source-disclosure"],
        })

    comments = scan_comments(text)
    if comments:
        joined = "; ".join(f"L{c['line']}: {c['comment']}" for c in comments[:6])
        findings.append({
            "title": f"Revealing developer comments ({len(comments)})", "severity": "info", "target": source,
            "description": f"Comments in {source} hint at gaps/TODOs: {joined}",
            "impact": "May reveal incomplete controls (e.g. missing CSRF), debug hooks, or hidden endpoints.",
            "reproduction_steps": [f"Grep {source} for TODO/FIXME/CSRF/debug"], "cwe": "CWE-615",
            "family": "code-review", "tags": ["disclosure"], "confidence": "candidate"})
    return {"findings": findings, "endpoints": extract_endpoints(text),
            "entropy_hits": scan_entropy(text)}
