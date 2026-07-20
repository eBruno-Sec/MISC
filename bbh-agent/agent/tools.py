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
    "run_whatweb": PermissionLevel.ACTIVE,
    "run_fingerprint": PermissionLevel.ACTIVE,
    "run_nmap": PermissionLevel.ACTIVE,
    "run_nuclei": PermissionLevel.ACTIVE,
    "http_probe": PermissionLevel.ACTIVE,
    "fetch_openapi": PermissionLevel.ACTIVE,
    "run_katana": PermissionLevel.ACTIVE,
    "check_takeover": PermissionLevel.ACTIVE,
    "run_graphql": PermissionLevel.ACTIVE,
    "run_jwt": PermissionLevel.ACTIVE,
    "run_oauth": PermissionLevel.ACTIVE,
    "run_xss": PermissionLevel.ACTIVE,
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
    "run_zap": PermissionLevel.INTRUSIVE,
    "run_dalfox": PermissionLevel.INTRUSIVE,
    "run_sqlmap": PermissionLevel.INTRUSIVE,
}

_UA = "Mozilla/5.0 (compatible; BBH-Agent/2.0; +authorized-testing)"


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
     "description": "INTRUSIVE: SQL-injection confirmation on a URL (requires sqlmap; skips gracefully if unavailable).",
     "input_schema": {"type": "object", "properties": {
         "url": {"type": "string"}, "data": {"type": "string", "default": ""}}, "required": ["url"]}},
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
]


class ToolRegistry:
    def __init__(self, scope: ScopeEngine, mission_id: str = None, lab_mode: bool = False,
                 session_headers: dict = None):
        self.scope = scope
        self.mission_id = mission_id
        self.lab_mode = lab_mode
        # Authenticated scanning: headers (Cookie/Authorization) shared with every
        # HTTP request the tools make, so scans reach the post-login surface.
        self.session_headers = session_headers or {}
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

    # ── helpers ──────────────────────────────────────────────────
    async def _cmd(self, cmd: list, timeout: int = 180) -> tuple:
        if not shutil.which(cmd[0]):
            return "", f"__MISSING__{cmd[0]}"
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return out.decode(errors="replace"), err.decode(errors="replace")
        except asyncio.TimeoutError:
            return "", "Command timed out"
        except Exception as e:
            return "", str(e)

    def _add_urls(self, urls) -> None:
        for u in urls:
            if u and u not in self.urls and self.scope.validate(u)[0]:
                self.urls.append(u)

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
        except Exception as e:
            return {"error": str(e), "status": 0, "headers": {}, "body": "", "length": 0, "final_url": url}

        if capture and self.mission_id:
            db.add_exchange(self.mission_id, {
                "url": url, "method": method.upper(), "request_headers": req_headers,
                "request_body": body, "status_code": resp["status"],
                "response_headers": resp["headers"], "response_body": text[:4000]},
                finding_id=finding_id)
        return resp

    # ── PASSIVE ──────────────────────────────────────────────────
    async def _run_subfinder(self, inp: dict) -> ToolResult:
        domain = inp["domain"]
        out, err = await self._cmd(["subfinder", "-d", domain, "-silent", "-json"], timeout=120)
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
        note = " (rate-limited, partial)" if rate_limited else ""
        return ToolResult("github_recon", domain, True,
                          f"{len(dorks)} dorks, {hits_total} hits, {len(findings)} secret/lead finding(s){note}",
                          findings)

    # ── ACTIVE ───────────────────────────────────────────────────
    async def _run_httpx(self, inp: dict) -> ToolResult:
        targets = inp["targets"]
        ports = inp.get("ports", "80,443,8080,8443,3000,8000,9000")
        tmp = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                for t in targets[:400]:
                    f.write(t + "\n")
                tmp = f.name
            out, err = await self._cmd(
                ["httpx", "-l", tmp, "-ports", ports, "-status-code", "-title",
                 "-tech-detect", "-silent", "-json"], timeout=300)
        finally:
            if tmp and os.path.exists(tmp):
                os.unlink(tmp)
        if err.startswith("__MISSING__"):
            return ToolResult("httpx", "", False, "", [], "httpx not installed")
        hosts = []
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
        self.recon["live_hosts"].extend(hosts)
        self._add_urls([h["url"] for h in hosts if h.get("url")])
        return ToolResult("httpx", f"{len(targets)} probed", True, f"{len(hosts)} live hosts", hosts)

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

    async def _run_nuclei(self, inp: dict) -> ToolResult:
        target = inp["target"]
        tags = inp.get("tags", "tech,misconfig,exposed-panels")
        severity = inp.get("severity", "low,medium,high,critical")
        out, err = await self._cmd(
            ["nuclei", "-u", target, "-tags", tags, "-severity", severity,
             "-silent", "-json", "-no-interactsh"], timeout=360)
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
                findings.append(rec)
                self.recon["nuclei"].append(rec)
            except Exception:
                pass
        return ToolResult("nuclei", target, True, f"{len(findings)} findings", findings)

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
        out, err = await self._cmd(["katana", "-u", url, "-silent", "-jc", "-d", "2"], timeout=180)
        if err.startswith("__MISSING__"):
            return ToolResult("katana", url, False, "", [], "katana not installed (use http_probe / run_wayback instead)")
        urls = [u.strip() for u in out.splitlines() if u.strip().startswith("http")]
        urls = [u for u in urls if self.scope.validate(u)[0]]
        self._add_urls(urls)
        return ToolResult("katana", url, True, f"{len(urls)} crawled URLs", [{"url": u} for u in urls[:50]])

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
                    if xt.reflected_exploitable(rb.text, ctx):
                        reflected.append((p, xt.reflection_finding(url, p, ctx)))
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
                        findings.append(xt.execution_finding(url, p, pl, where))
                        done.add((where, p))
                await browser.close()
        except Exception:
            return findings
        return findings

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

        findings, endpoints = [], []
        for label, text in sources:
            res = cr.review(text, label)
            findings += res["findings"]
            endpoints += res["endpoints"]

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

        async def probe(word):
            url = ws.normalize_discovered_url(base_url, word)
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

        await asyncio.gather(*[probe(w) for w in words])
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
        params = [p for p in params][:8]
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
                        findings.append(ssrf.reflection_finding(url, p, payload, hit["cloud"], hit["matched"]))
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
                    findings.append(ssrf.blind_finding(url, p, open_pl, closed_pl, sig))
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
                    findings.append(collab.oob_finding(url, p, purl, inter) if inter
                                    else ssrf.oob_finding(url, p, purl))
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
        if self.mission_id and findings:
            await self._http(url, "POST", {"Content-Type": ctype}, body=sample or "<root/>", capture=True)
        conf = sum(1 for f in findings if f.get("confidence") == "confirmed")
        return ToolResult("xxe", url, True, f"{len(findings)} XXE signal(s), {conf} confirmed", findings)

    async def _run_sqli(self, inp: dict) -> ToolResult:
        import time
        import httpx
        import sqli_tool as sqli
        from urllib.parse import parse_qsl
        url = inp["url"]
        params = (inp.get("params") or xt.params_of(url))[:8]
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
            for p in params:
                orig = qvals.get(p, "1")
                confirmed = False
                # 1) error-based
                for probe in sqli.ERROR_PROBES[:3]:
                    r, _ = await get(c, xt.set_param(url, p, orig + probe))
                    if r is None:
                        continue
                    hits = sqli.error_signatures(base_body, r.text)
                    if hits:
                        findings.append(sqli.error_finding(url, p, probe, hits))
                        ev.append(xt.set_param(url, p, orig + probe)); confirmed = True
                        break
                if confirmed:
                    continue
                # 2) boolean-based blind
                for pair in sqli.boolean_payloads(orig):
                    rt, _ = await get(c, xt.set_param(url, p, pair["true"]))
                    rf, _ = await get(c, xt.set_param(url, p, pair["false"]))
                    if rt is None or rf is None:
                        continue
                    if sqli.analyze_boolean(base_body, rt.text, rf.text):
                        findings.append(sqli.boolean_finding(url, p, pair))
                        ev.append(xt.set_param(url, p, pair["false"])); confirmed = True
                        break
                if confirmed:
                    continue
                # 3) time-based blind (only when quieter oracles found nothing)
                for item in sqli.time_payloads(orig, seconds):
                    _, ctl = await get(c, xt.set_param(url, p, item["control"]))
                    _, slp = await get(c, xt.set_param(url, p, item["payload"]))
                    if sqli.analyze_time(ctl, slp, seconds):
                        findings.append(sqli.time_finding(url, p, item, ctl, slp, seconds))
                        ev.append(xt.set_param(url, p, item["payload"]))
                        break

        if self.mission_id and ev:
            await self._http(ev[0], "GET", capture=True)
        return ToolResult("sqli", url, True,
                          f"tested {len(params)} param(s), {len(findings)} confirmed SQLi", findings)

    async def _run_zap(self, inp: dict) -> ToolResult:
        import zap_client as zc
        url = inp["url"]
        if not zc.configured():
            return ToolResult("zap", url, True,
                              "ZAP not configured — enable with: docker compose --profile zap up -d "
                              "and set ZAP_ADDR=http://zap:8090", [])
        zap = zc.ZapClient()
        try:
            await zap.version()
        except Exception as e:
            return ToolResult("zap", url, False, "", [], f"ZAP daemon unreachable at ZAP_ADDR: {e}")

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
            # spider -> ajax spider (SPA) -> active scan, all scope-fenced
            sid = await zap.spider(url, context=name)
            if sid is not None:
                await zap.wait_int(lambda: zap.spider_status(sid),
                                   cap=int(inp.get("spider_seconds", 180)), stop_event=self.stop_event)
            try:
                await zap.ajax_start(url, context=name)
                await zap.wait_str(lambda: zap.ajax_status(), cap=120, stop_event=self.stop_event)
            except Exception:
                pass
            # tune the active scan: identify our traffic + widen input vectors
            # (POST/JSON/headers/cookie) so API bodies get fuzzed. Best-effort.
            setups = [zap.add_scan_header(), zap.set_injectable()]
            # enable out-of-band detection (blind SSRF/XXE/RCE) if an OAST
            # service is configured (env ZAP_OAST_SERVICE or the tool param).
            oast = inp.get("oast_service") or os.getenv("ZAP_OAST_SERVICE", "")
            if oast:
                setups.append(zap.set_oast_service(oast))
            for setup in setups:
                try:
                    await setup
                except Exception:
                    pass
            asid = await zap.ascan(url, context_id=ctx_id, policy=inp.get("scan_policy") or None)
            if asid is not None:
                await zap.wait_int(lambda: zap.ascan_status(asid),
                                   cap=int(inp.get("scan_seconds", 600)), stop_event=self.stop_event)
            raw = zc.dedup_alerts(await zap.alerts(baseurl=f"{base.scheme}://{base.netloc}"))
        except Exception as e:
            return ToolResult("zap", url, False, "", [], f"ZAP scan error: {e}")

        findings = [zc.alert_to_finding(a) for a in raw]
        findings = [f for f in findings if f["severity"] in ("critical", "high", "medium", "low")]
        self.recon.setdefault("zap", []).extend(findings)
        return ToolResult("zap", url, True,
                          f"{len(findings)} ZAP alert(s) (from {len(raw)} raw)", findings)

    async def _run_dalfox(self, inp: dict) -> ToolResult:
        url = inp["url"]
        out, err = await self._cmd(["dalfox", "url", url, "--silence", "--format", "json"], timeout=240)
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
        cmd = ["sqlmap", "-u", url, "--batch", "--level", "1", "--risk", "1", "--flush-session"]
        if data:
            cmd += ["--data", data]
        out, err = await self._cmd(cmd, timeout=420)
        if err.startswith("__MISSING__"):
            return ToolResult("sqlmap", url, False, "", [], "sqlmap not installed")
        vuln = "is vulnerable" in out or "sqlmap identified" in out
        return ToolResult("sqlmap", url, True,
                          "SQLi indicated" if vuln else "No SQLi confirmed",
                          [{"vulnerable": vuln, "log_tail": out[-800:]}])

    # ── PASSIVE advisory: playbook + storage ─────────────────────
    async def _generate_playbook(self, inp: dict) -> ToolResult:
        recon = dict(self.recon)
        recon["urls"] = self.urls
        guide = guidance_mod.build_guidance(recon)
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

    async def _store_finding(self, inp: dict) -> ToolResult:
        if self.mission_id:
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
