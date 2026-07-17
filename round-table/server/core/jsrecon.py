"""
JavaScript bundle recon.

Big SPAs ship large JS bundles that leak internal API endpoints and sometimes
credentials. This module downloads the served bundles (read-only GET) and pulls:
  - API endpoints / routes  -> a manual-testing worklist, also fed to the
    injection + intuition engines so they probe real app params.
  - secret-looking strings  -> findings, classified honestly by how sensitive
    the pattern is. Many keys in client JS are PUBLIC by design (Firebase apiKey,
    Stripe publishable, Google Maps key); those are flagged INFO with a "verify"
    note, never screamed as critical. Secrets are reported for the human to
    verify, never used.

Bounded (script count, size, time). Auth-aware.
"""
from __future__ import annotations

import re
import ssl
import urllib.request
from urllib.parse import urljoin, urlparse

from .detectors import _finding

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE
UA = "RoundTable/2 jsrecon"

MAX_SCRIPTS = 25
MAX_BYTES = 3_000_000
FETCH_TIMEOUT = 12

# ── endpoint extraction ─────────────────────────────────────────────────────
_EP_PATTERNS = [
    re.compile(r"""["'`](/(?:api|rest|graphql|gql|v\d+|internal|admin|users?|accounts?|oauth|auth|login|logout|session|token|gateway|services?|upload|files?|payments?|orders?|cart|checkout|webhooks?|notify|search|config|settings|profile|billing|invoice|seller|merchant|ads?|campaign)[A-Za-z0-9_\-/.:{}$]*)["'`]"""),
    re.compile(r"""(?:fetch|\.get|\.post|\.put|\.patch|\.delete|\.request|axios|\.ajax)\(\s*["'`]([^"'`\s?]+)["'`]"""),
    re.compile(r"""["'`](https?://[a-z0-9.\-]+/[A-Za-z0-9_\-/.]{2,})["'`]"""),
]

# ── secret patterns: (name, regex, severity, note) ──────────────────────────
# HIGH/MEDIUM = worth reporting once verified. INFO = usually public by design.
_SECRETS = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "HIGH",
     "AWS access key id. If a matching secret is nearby it is live-usable. Verify it authenticates and is not a canary before reporting."),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "HIGH",
     "A private key embedded in client-side code."),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "HIGH", "Slack token."),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), "HIGH", "GitHub access token."),
    ("Stripe secret key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), "HIGH",
     "Stripe SECRET key (not the publishable pk_). High impact if live."),
    ("Google OAuth client secret", re.compile(r"\bGOCSPX-[0-9A-Za-z_\-]{28}\b"), "HIGH", "Google OAuth client secret."),
    ("SendGrid API key", re.compile(r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b"), "HIGH", "SendGrid API key."),
    ("Generic JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{6,}"), "MEDIUM",
     "A JWT in client code. Decode it: a live session/service token is a finding, a hard-coded sample is not."),
    ("Generic secret assignment", re.compile(r"""(?i)(?:client_?secret|api[_-]?secret|secret_?key|access[_-]?token|auth[_-]?token|private[_-]?key)["'`]?\s*[:=]\s*["'`]([0-9A-Za-z_\-+/]{16,})["'`]"""), "MEDIUM",
     "A secret-looking assignment. Some are build-time public config; verify it is actually sensitive and live before reporting."),
    # likely-public by design -> INFO + verify note
    ("Google API key (often public)", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "INFO",
     "Google API key. Maps/Places keys are meant to be public, but an UNRESTRICTED key allows quota theft. Test for missing HTTP-referer / API restrictions."),
    ("Stripe publishable key (public)", re.compile(r"\bpk_live_[0-9a-zA-Z]{24,}\b"), "INFO",
     "Stripe publishable key. Public by design. Not a finding on its own."),
]


def _fetch(url, headers, cap=MAX_BYTES):
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT, context=_CTX) as r:
            return r.status, r.read(cap).decode("utf-8", "ignore")
    except Exception:
        return None, ""


def _same_site(u: str, host: str) -> bool:
    h = (urlparse(u).hostname or "").lower()
    if not h:
        return True  # relative
    reg = ".".join(host.split(".")[-2:])
    return h == host or h.endswith("." + reg)


def _script_urls(base: str, html: str) -> list[str]:
    out, seen = [], set()
    for src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
        u = urljoin(base + "/", src)
        if u.lower().split("?")[0].endswith(".js") and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def mine_js(base: str, log=None, auth: dict = None) -> dict:
    base = base.rstrip("/")
    host = (urlparse(base).hostname or "").lower()
    headers = {"User-Agent": UA}
    if auth:
        headers.update(auth)

    st, html = _fetch(base, headers)
    if not html:
        return {"endpoints": [], "findings": []}
    scripts = _script_urls(base, html)[:MAX_SCRIPTS]
    if log:
        log(f"jsrecon: {len(scripts)} JS bundle(s) on {host}", "info", "detect")

    endpoints: set[str] = set()
    secrets: dict[str, dict] = {}   # name -> {sev, note, sample, count}
    blob_seen = 0

    for su in scripts:
        _, js = _fetch(su, headers)
        if not js:
            continue
        blob_seen += 1
        for pat in _EP_PATTERNS:
            for m in pat.findall(js):
                ep = m if isinstance(m, str) else m[0]
                ep = ep.strip().split("#")[0]
                if not ep or len(ep) > 180:
                    continue
                if ep.startswith("http"):
                    if not _same_site(ep, host):
                        continue
                elif not ep.startswith("/"):
                    continue
                endpoints.add(ep)
        for name, pat, sev, note in _SECRETS:
            m = pat.search(js)
            if m:
                val = (m.group(1) if m.groups() else m.group(0))
                rec = secrets.setdefault(name, {"sev": sev, "note": note, "sample": val[:6] + "…", "count": 0, "url": su})
                rec["count"] += 1

    endpoints = sorted(e for e in endpoints if e not in ("/", ""))
    findings: list[dict] = []

    # secret findings (one per type, honest severity)
    for name, r in secrets.items():
        conf = 78 if r["sev"] == "HIGH" else (60 if r["sev"] == "MEDIUM" else 40)
        findings.append(_finding(
            key=f"js-secret-{re.sub(r'[^a-z]+', '-', name.lower())}",
            title=f"Secret-looking string in JS bundle: {name}",
            category="Secrets", severity=r["sev"], surface=r["url"], confidence=conf,
            evidence=f"Pattern '{name}' matched in a served JS bundle (sample prefix {r['sample']}, {r['count']} hit(s)). {r['note']}",
            what="A credential-shaped string is exposed in client-side JavaScript. Verify whether it is live and sensitive before reporting (many client keys are public by design).",
            how=["Extract the full value from the bundle (view-source / curl the .js).",
                 "Determine the key type and whether it is meant to be public (Firebase/Stripe-publishable/Maps are public).",
                 "If it looks sensitive, test it read-only against its service to confirm it authenticates.",
                 "Report only a key that is both live and grants access it should not."],
            tools=["curl", "trufflehog", "jwt_tool"],
            curl_steps=[{"desc": "Pull the bundle and grep the pattern", "cmd": f"curl -sS -k {r['url']} | grep -aoE '\\S*{re.escape(r['sample'][:4])}\\S*' | head"}],
            references=[{"title": "OWASP: Sensitive data in client code", "url": "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"}],
            remediation={"summary": "Move secrets server-side; rotate any leaked credential; restrict public keys (referer/IP/scopes).", "fixes": []},
            tags=["secret", "js", "disclosure"],
        ))

    # endpoint worklist (one advisory finding; also fed to recon.js_endpoints)
    if endpoints:
        show = endpoints[:60]
        findings.append(_finding(
            key="js-endpoints", title=f"API endpoints mined from JS ({len(endpoints)})",
            category="Attack Surface", severity="LOW", surface=base, confidence=55,
            evidence="Endpoints referenced in the served JS bundles (often unlinked in the UI): "
                     + ", ".join(show) + ("  …" if len(endpoints) > len(show) else ""),
            what="These are real routes the app calls. Many are auth-gated API endpoints where the actual "
                 "bounty-grade bugs live (IDOR/BOLA, broken access control, injection, mass assignment). "
                 "This is a manual worklist, not a vuln by itself.",
            how=["Authenticate, then hit each endpoint and diff responses across your roles / other users' object ids (IDOR/BOLA).",
                 "Look for object ids, GraphQL, upload, and payment routes first.",
                 "Fuzz parameters on the interesting ones (the injection playbooks apply here).",
                 "Check whether privileged endpoints are reachable unauthenticated (forced browsing)."],
            tools=["curl", "browser devtools", "ffuf"],
            curl_steps=[{"desc": "List the mined endpoints from the bundle",
                         "cmd": f"curl -sS -k {base}/ | grep -oE 'src=\"[^\"]+\\.js\"'  # then curl each and grep for /api /rest /graphql"}],
            references=[{"title": "OWASP API Security Top 10", "url": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/"}],
            tags=["js", "endpoints", "api", "attack-surface"],
        ))

    if log:
        secret_n = len(secrets)
        log(f"jsrecon: {len(endpoints)} endpoint(s), {secret_n} secret-pattern type(s) from {blob_seen} bundle(s)",
            "ok" if (endpoints or secret_n) else "info", "detect")
    return {"endpoints": endpoints, "findings": findings}
