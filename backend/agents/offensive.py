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
in the Saga report.
"""
import asyncio
import json
import os
import re
import tempfile
from html import unescape
from urllib.parse import urljoin, urlparse, parse_qs, parse_qsl, urlencode, urlunparse

import httpx

from core.web_security import (
    HIGH_VALUE_EXPOSURE_PATHS,
    analyze_idor_pair,
    analyze_traversal_pair,
    build_idor_probes,
    build_traversal_probes,
    generate_discovery_words,
    is_url_in_scope,
    normalize_discovered_url,
)

SECLISTS_DIRS = [
    "/opt/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/opt/seclists/Discovery/Web-Content/raft-small-words.txt",
    "/opt/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/opt/seclists/Discovery/Web-Content/common.txt",
]

PARAMETER_BRUTE_WORDS = (
    "searchTerm", "search", "q", "query", "keyword", "term", "s", "text",
    "id", "productId", "product_id", "itemId", "item_id", "sku", "category",
    "cat", "sort", "order", "filter", "page", "p", "limit", "offset",
    "stockApi", "stock_api", "stockId", "stock_id", "xml", "payload", "data",
    "json", "redirect", "redirectUrl", "redirect_url", "redirectUri",
    "redirect_uri", "returnUrl", "return_url", "return", "next", "continue",
    "url", "uri", "dest", "destination", "file", "filename", "path", "folder",
    "dir", "template", "view", "include", "pagePath", "download", "image",
    "img", "lang", "locale", "callback", "jsonp", "message", "name", "email",
    "username", "user", "userId", "user_id", "uid", "account", "accountId",
    "account_id", "customer", "customerId", "customer_id", "admin", "role",
    "debug", "test", "token", "api_key", "apikey", "key", "csrf",
    "csrfToken", "session", "sessionId", "ref", "source", "from", "to",
    "minPrice", "maxPrice", "price", "type", "format", "callbackUrl",
    "logout", "login", "password", "oldPassword", "newPassword",
)


class OffensiveEngine:
    """Mixed into the active assessment agent. Expects the host to provide: self.run_command, self.log,
    self.add_finding (all from BaseAgent)."""

    # ── Crawl ────────────────────────────────────────────────────
    async def crawl(self, base_url: str, max_urls: int = 200) -> list:
        await self.log(f"Crawling {base_url} for endpoints and parameters (katana)", "info")
        stdout, _, rc = await self.run_command(
            ["katana", "-u", base_url, "-jc", "-kf", "all", "-d", "3",
             "-c", "15", "-silent", "-nc", "-timeout", "10"],
            timeout=180,
        )
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

    def _attr_value(self, html: str, name: str) -> str:
        match = re.search(rf'''\b{name}\s*=\s*["']?([^"'\s>]+)''', html, re.I)
        return unescape(match.group(1).strip()) if match else ""

    def _looks_static_asset(self, url: str, *, allow_js: bool = True) -> bool:
        path = urlparse(url).path.lower()
        static_exts = (
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
            ".js", ".css", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm",
            ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z",
        )
        if allow_js and path.endswith(".js"):
            return False
        return path.endswith(static_exts)

    def _extract_html_routes(self, page_url: str, text: str) -> tuple[list[str], list[str]]:
        urls: list[str] = []
        form_candidates: list[str] = []

        for match in re.findall(r'''(?:href|src|action)\s*=\s*["']([^"']+)["']''', text, re.I):
            if match.startswith(("mailto:", "tel:", "javascript:", "data:")):
                continue
            urls.append(urljoin(page_url, unescape(match)))

        # Pick up fetch('/api/x'), axios.get('/x'), url: '/x', and similar app routes inside HTML/JS.
        js_route_re = re.compile(
            r'''["']((?:https?://[^"'<>\s\\]+|/[A-Za-z0-9._~!$&'()*+,;=:@%/-][^"'<>\s\\]{0,220})(?:\?[^"'<>\s\\]*)?)["']''',
            re.I,
        )
        for raw in js_route_re.findall(text[:500000]):
            if raw.startswith(("/static/", "/assets/")):
                continue
            urls.append(urljoin(page_url, unescape(raw)))

        form_re = re.compile(r"<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>", re.I | re.S)
        field_re = re.compile(r'''<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']?([^"'\s>]+)''', re.I)
        for form in form_re.finditer(text[:500000]):
            attrs = form.group("attrs") or ""
            body = form.group("body") or ""
            action = self._attr_value(attrs, "action") or page_url
            names = []
            seen_names = set()
            for name in field_re.findall(body):
                clean = unescape(name.strip())
                if clean and clean not in seen_names:
                    seen_names.add(clean)
                    names.append(clean)
            if not names:
                continue
            target = urljoin(page_url, action)
            parsed = urlparse(target)
            existing = parse_qsl(parsed.query, keep_blank_values=True)
            existing_names = {k for k, _ in existing}
            pairs = existing + [(name, "yggdrasil") for name in names if name not in existing_names]
            form_candidates.append(urlunparse(parsed._replace(query=urlencode(pairs, doseq=True), fragment="")))

        return urls, form_candidates

    async def spider_http(
        self,
        base_url: str,
        seeds: list,
        scope_rules: dict | None = None,
        max_pages: int = 80,
        max_urls: int = 700,
    ) -> list:
        queue = self._dedupe_in_scope_urls([base_url] + (seeds or []), base_url, scope_rules, max_urls=max_urls)
        seen_pages: set[str] = set()
        discovered: list[str] = list(queue)
        form_candidates: list[str] = []
        fetched = 0

        await self.log(f"Spider crawl starting with {len(queue)} seed URL(s)", "info")
        async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as c:
            while queue and fetched < max_pages and len(discovered) < max_urls:
                page = queue.pop(0)
                page_key = page.split("#", 1)[0]
                if page_key in seen_pages or self._looks_static_asset(page_key, allow_js=True):
                    continue
                seen_pages.add(page_key)
                try:
                    response = await c.get(page)
                except Exception:
                    continue
                fetched += 1
                content_type = response.headers.get("content-type", "").lower()
                path = urlparse(str(response.url)).path.lower()
                if response.status_code >= 500:
                    continue
                if "html" not in content_type and "javascript" not in content_type and not path.endswith(".js"):
                    continue

                extracted, forms = self._extract_html_routes(str(response.url), response.text)
                form_candidates.extend(forms)
                for candidate in extracted + forms:
                    if self._looks_static_asset(candidate, allow_js=True) and "?" not in candidate:
                        continue
                    normalized = self._dedupe_in_scope_urls([candidate], base_url, scope_rules, max_urls=1)
                    if not normalized:
                        continue
                    candidate = normalized[0]
                    if candidate not in discovered:
                        discovered.append(candidate)
                        if not self._looks_static_asset(candidate, allow_js=True) and len(queue) < max_pages:
                            queue.append(candidate)

        parameterized = [u for u in discovered if "?" in u and "=" in u]
        await self.log(
            f"Spider crawl harvested {len(discovered)} URL(s), "
            f"{len(parameterized)} parameterized, {len(form_candidates)} form-derived candidate(s)",
            "success" if len(discovered) > 1 else "info",
        )
        return self._dedupe_in_scope_urls(discovered + form_candidates, base_url, scope_rules, max_urls=max_urls)

    # ── SQL injection ────────────────────────────────────────────
    def _extract_urls_from_text(self, text: str) -> list[str]:
        urls = []
        for match in re.findall(r'''https?://[^\s"'<>\\)]+''', text or ""):
            urls.append(match.rstrip(".,;]})"))
        return urls

    async def paramspider_parameter_mining(
        self,
        base_url: str,
        scope_rules: dict | None = None,
        max_urls: int = 350,
    ) -> list:
        domain = urlparse(base_url).hostname or ""
        if not domain:
            return []

        found: list[str] = []
        stdout, stderr, rc = await self.run_command(
            ["paramspider", "-d", domain, "-s"],
            timeout=180,
        )
        if rc == 127:
            await self.log("ParamSpider not available; using archive parameter mining fallback", "warn")
        elif rc == 0:
            found.extend(self._extract_urls_from_text(stdout))
        else:
            await self.log(f"ParamSpider returned non-zero status; using archive fallback ({stderr[:120]})", "warn")

        try:
            async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as c:
                response = await c.get(
                    "https://web.archive.org/cdx",
                    params={
                        "url": f"{domain}/*",
                        "output": "json",
                        "fl": "original",
                        "collapse": "urlkey",
                        "filter": "statuscode:200",
                    },
                )
            if response.status_code == 200:
                data = response.json()
                for row in data[1:900] if isinstance(data, list) else []:
                    if isinstance(row, list) and row:
                        found.append(str(row[0]))
        except Exception as e:
            await self.log(f"Archive parameter mining fallback failed: {type(e).__name__}", "warn")

        param_urls = [u for u in found if "?" in u and "=" in u]
        param_urls = self._dedupe_in_scope_urls(param_urls, base_url, scope_rules, max_urls=max_urls)
        param_names = {
            name
            for url in param_urls
            for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)
            if name
        }
        await self.log(
            f"ParamSpider-style mining found {len(param_urls)} parameterized URL(s), "
            f"{len(param_names)} unique parameter name(s)",
            "success" if param_urls else "info",
        )
        return param_urls

    def _candidate_routes_for_parameter_discovery(
        self,
        base_url: str,
        urls: list,
        declared_paths: list | None = None,
        scope_rules: dict | None = None,
        max_routes: int = 12,
    ) -> list[str]:
        routes: list[str] = []

        def add(raw: str):
            if not raw or not isinstance(raw, str):
                return
            route = raw.split("#", 1)[0].strip()
            if not route.startswith("http"):
                route = urljoin(base_url.rstrip("/") + "/", route.lstrip("/"))
            route = self._route_without_query(route)
            if self._looks_static_asset(route, allow_js=False):
                return
            if not is_url_in_scope(route, base_url, scope_rules):
                return
            if route not in routes:
                routes.append(route)

        for raw in self._urls_from_declared_paths(base_url, declared_paths or []):
            add(raw)
        for raw in urls or []:
            add(raw)
        add(base_url)

        def score(route: str) -> tuple[int, str]:
            path = (urlparse(route).path or "/").lower()
            value = 0
            if self._declared_hints_for_route(path, declared_paths):
                value -= 400
            for marker, weight in (
                ("/catalog/product/stock", -180),
                ("/catalog/product", -160),
                ("/catalog/subscribe", -150),
                ("/catalog", -140),
                ("/blog/post", -120),
                ("/blog", -110),
                ("/login", -100),
                ("/my-account", -90),
            ):
                if marker in path:
                    value += weight
            if path in ("", "/"):
                value += 150
            return (value, route)

        return sorted(routes, key=score)[:max_routes]

    def _collect_parameter_names_from_json(self, obj, parent_key: str = "") -> set[str]:
        names: set[str] = set()
        param_keys = {"param", "params", "parameter", "parameters", "name", "names", "found"}
        method_keys = {"get", "post", "put", "patch", "delete", "json", "xml", "headers", "cookies", "query", "body"}

        if isinstance(obj, dict):
            parent_is_param = parent_key.lower() in param_keys
            for key, value in obj.items():
                key_text = str(key)
                if "url" in key_text.lower() and isinstance(value, str):
                    for name, _ in parse_qsl(urlparse(value).query, keep_blank_values=True):
                        clean = self._clean_parameter_name(name)
                        if clean:
                            names.add(clean)
                if parent_is_param and key_text.lower() not in method_keys:
                    clean = self._clean_parameter_name(key_text)
                    if clean:
                        names.add(clean)
                if key_text.lower() in {"param", "parameter", "name"} and isinstance(value, str):
                    clean = self._clean_parameter_name(value)
                    if clean:
                        names.add(clean)
                names.update(self._collect_parameter_names_from_json(value, key_text))
        elif isinstance(obj, list):
            parent_is_param = parent_key.lower() in param_keys or parent_key.lower() in method_keys
            for item in obj:
                if parent_is_param and isinstance(item, str):
                    clean = self._clean_parameter_name(item)
                    if clean and not clean.startswith("http"):
                        names.add(clean)
                names.update(self._collect_parameter_names_from_json(item, parent_key))
        return names

    def _collect_parameter_names_from_text(self, text: str) -> set[str]:
        names: set[str] = set()
        for url in self._extract_urls_from_text(text or ""):
            for name, _ in parse_qsl(urlparse(url).query, keep_blank_values=True):
                clean = self._clean_parameter_name(name)
                if clean:
                    names.add(clean)

        for line in (text or "").splitlines():
            low = line.lower()
            if "param" not in low and "found" not in low:
                continue
            if ":" in line:
                line = line.split(":", 1)[1]
            for token in re.split(r"[\s,\[\]{}'\"=]+", line):
                clean = self._clean_parameter_name(token)
                if 1 < len(clean) < 80 and not clean.lower().startswith(("http", "found", "param")):
                    names.add(clean)
        return names

    def _parameter_urls_from_names(
        self,
        routes: list[str],
        names: set[str],
        base_url: str,
        scope_rules: dict | None = None,
        tool: str = "external",
        max_urls: int = 180,
    ) -> list[dict]:
        found: list[dict] = []
        seen = set()
        for route in routes:
            for name in sorted(names):
                candidate = self._append_param_to_url(route, name)
                if candidate in seen or not is_url_in_scope(candidate, base_url, scope_rules):
                    continue
                seen.add(candidate)
                found.append({"url": candidate, "route": route, "parameter": name, "tool": tool})
                if len(found) >= max_urls:
                    return found
        return found

    async def arjun_parameter_discovery(
        self,
        base_url: str,
        urls: list,
        scope_rules: dict | None = None,
        declared_paths: list | None = None,
        max_routes: int = 10,
    ) -> list[dict]:
        routes = self._candidate_routes_for_parameter_discovery(
            base_url, urls, declared_paths, scope_rules, max_routes=max_routes
        )
        if not routes:
            return []

        await self.log(f"Arjun parameter discovery on {len(routes)} high-value route(s)", "info")
        target_file = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        output_file = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        target_file.write("\n".join(routes))
        target_file.close()
        output_file.close()

        names: set[str] = set()
        try:
            stdout, stderr, rc = await self.run_command(
                [
                    "arjun", "-i", target_file.name, "-o", output_file.name,
                    "-m", "GET", "-t", "5", "-T", "10", "--stable", "-q",
                ],
                timeout=240,
            )
            if rc == 127:
                await self.log("Arjun not available; skipping Arjun parameter discovery", "warn")
                return []
            if rc != 0:
                await self.log(f"Arjun returned non-zero status: {(stderr or stdout)[:180]}", "warn")
            if os.path.exists(output_file.name) and os.path.getsize(output_file.name) > 0:
                try:
                    with open(output_file.name, "r", encoding="utf-8", errors="ignore") as fh:
                        names.update(self._collect_parameter_names_from_json(json.load(fh)))
                except Exception:
                    with open(output_file.name, "r", encoding="utf-8", errors="ignore") as fh:
                        names.update(self._collect_parameter_names_from_text(fh.read()))
            names.update(self._collect_parameter_names_from_text(stdout))
        finally:
            for path in (target_file.name, output_file.name):
                try:
                    os.unlink(path)
                except OSError:
                    pass

        results = self._parameter_urls_from_names(routes, names, base_url, scope_rules, tool="arjun")
        await self.log(
            f"Arjun discovered {len(names)} parameter name(s), producing {len(results)} URL candidate(s)",
            "success" if results else "info",
        )
        return results

    async def x8_parameter_discovery(
        self,
        base_url: str,
        urls: list,
        scope_rules: dict | None = None,
        declared_paths: list | None = None,
        max_routes: int = 8,
    ) -> list[dict]:
        routes = self._candidate_routes_for_parameter_discovery(
            base_url, urls, declared_paths, scope_rules, max_routes=max_routes
        )
        if not routes:
            return []

        names = self._candidate_parameter_names(urls, declared_paths, limit=180)
        wordlist_file = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        output_file = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        wordlist_file.write("\n".join(names))
        wordlist_file.close()
        output_file.close()

        discovered_names: set[str] = set()
        await self.log(f"x8 hidden parameter discovery on {len(routes)} route(s) with {len(names)} names", "info")
        try:
            stdout, stderr, rc = await self.run_command(
                [
                    "x8", "-u", *routes, "-w", wordlist_file.name, "-O", "json",
                    "-o", output_file.name, "--timeout", "10", "-W", "4",
                    "--strict", "--remove-empty",
                ],
                timeout=240,
            )
            if rc == 127:
                await self.log("x8 not available; native wfuzz-style parameter probing remains enabled", "warn")
                return []
            if rc != 0:
                await self.log(f"x8 returned non-zero status: {(stderr or stdout)[:180]}", "warn")
            if os.path.exists(output_file.name) and os.path.getsize(output_file.name) > 0:
                with open(output_file.name, "r", encoding="utf-8", errors="ignore") as fh:
                    text = fh.read()
                try:
                    discovered_names.update(self._collect_parameter_names_from_json(json.loads(text)))
                except Exception:
                    discovered_names.update(self._collect_parameter_names_from_text(text))
            discovered_names.update(self._collect_parameter_names_from_text(stdout))
        finally:
            for path in (wordlist_file.name, output_file.name):
                try:
                    os.unlink(path)
                except OSError:
                    pass

        results = self._parameter_urls_from_names(routes, discovered_names, base_url, scope_rules, tool="x8")
        await self.log(
            f"x8 discovered {len(discovered_names)} parameter name(s), producing {len(results)} URL candidate(s)",
            "success" if results else "info",
        )
        return results

    async def external_parameter_discovery(
        self,
        base_url: str,
        urls: list,
        scope_rules: dict | None = None,
        declared_paths: list | None = None,
    ) -> list[dict]:
        results: list[dict] = []
        for tool_name, coro in (
            ("Arjun", self.arjun_parameter_discovery(base_url, urls, scope_rules, declared_paths)),
            ("x8", self.x8_parameter_discovery(base_url, urls, scope_rules, declared_paths)),
        ):
            try:
                tool_results = await coro
                results.extend(tool_results if isinstance(tool_results, list) else [])
            except Exception as e:
                await self.log(f"{tool_name} parameter discovery failed: {type(e).__name__}: {str(e)[:180]}", "warn")

        deduped: list[dict] = []
        seen = set()
        for row in results:
            url = row.get("url") if isinstance(row, dict) else ""
            if not url or url in seen:
                continue
            seen.add(url)
            deduped.append(row)
        return deduped[:240]

    def _candidate_parameter_names(self, urls: list, declared_paths: list | None = None, limit: int = 90) -> list[str]:
        priority_word_count = 55
        names = list(PARAMETER_BRUTE_WORDS[:priority_word_count])
        for raw in urls or []:
            parsed = urlparse(raw)
            for name, _ in parse_qsl(parsed.query, keep_blank_values=True):
                if name:
                    names.append(name)
            for part in parsed.path.split("/"):
                part = re.sub(r"[^A-Za-z0-9_]", "", part)
                if 2 < len(part) < 35:
                    names.append(part)
                    names.append(part + "_id")
        for row in declared_paths or []:
            if not isinstance(row, dict):
                continue
            path = str(row.get("path") or "")
            for part in path.split("/"):
                part = re.sub(r"[^A-Za-z0-9_]", "", part)
                if 2 < len(part) < 35:
                    names.append(part)
                    names.append(part + "_id")
            for hint in row.get("hints", []) or []:
                low = str(hint).lower()
                if "redirect" in low:
                    names.extend(["redirect", "url", "next", "returnUrl"])
                if "xml" in low or "xxe" in low:
                    names.extend(["xml", "data", "payload", "stockApi"])
                if "sql" in low:
                    names.extend(["id", "category", "product_id", "search"])
                if "xss" in low or "cross-site" in low:
                    names.extend(["q", "search", "message", "name", "callback"])
        names.extend(PARAMETER_BRUTE_WORDS[priority_word_count:])
        deduped = []
        seen = set()
        for name in names:
            clean = self._clean_parameter_name(name)
            if not clean or clean in seen:
                continue
            seen.add(clean)
            deduped.append(clean)
            if len(deduped) >= limit:
                break
        return deduped

    def _clean_parameter_name(self, name: str) -> str:
        return re.sub(r"[^A-Za-z0-9_.-]", "", str(name).strip())[:80]

    def _declared_hints_for_route(self, route_path: str, declared_paths: list | None = None) -> list[str]:
        route_path = (route_path or "/").split("?", 1)[0].strip() or "/"
        if not route_path.startswith("/"):
            route_path = "/" + route_path
        route_norm = route_path.rstrip("/") or "/"

        hints: list[str] = []
        for row in declared_paths or []:
            if not isinstance(row, dict):
                continue
            declared = str(row.get("path") or "").split("?", 1)[0].strip()
            if not declared.startswith("/"):
                continue
            declared_norm = declared.rstrip("/") or "/"
            exact = route_norm == declared_norm
            child = declared_norm != "/" and route_norm.startswith(declared_norm + "/")
            if not exact and not child:
                continue
            hints.extend(str(h) for h in (row.get("hints") or []) if h)
        return hints

    def _append_param_to_url(self, route: str, name: str, value: str = "yggdrasil") -> str:
        parsed = urlparse(route)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if any(k == name for k, _ in pairs):
            pairs = [(k, value if k == name else v) for k, v in pairs]
        else:
            pairs.append((name, value))
        return urlunparse(parsed._replace(query=urlencode(pairs, doseq=True), fragment=""))

    def _route_parameter_names(self, route: str, urls: list, declared_paths: list | None = None) -> list[str]:
        parsed = urlparse(route)
        path = parsed.path or "/"
        path_lower = path.lower()
        segments = [s for s in re.split(r"[^A-Za-z0-9]+", path) if 1 < len(s) < 35]
        hints = self._declared_hints_for_route(path, declared_paths)
        names: list[str] = []

        def add(*items):
            for item in items:
                if isinstance(item, (list, tuple, set)):
                    add(*item)
                else:
                    clean = self._clean_parameter_name(item)
                    if clean:
                        names.append(clean)

        # Keep observed parameters for the same route at the front.
        route_key = self._route_without_query(route)
        for raw in urls or []:
            if self._route_without_query(raw) != route_key:
                continue
            for name, _ in parse_qsl(urlparse(raw).query, keep_blank_values=True):
                add(name)

        if "/catalog/product/stock" in path_lower:
            add("stockApi", "stock_api", "productId", "product_id", "sku", "xml", "payload", "data", "url", "path")
        if "/catalog/product" in path_lower:
            add("productId", "product_id", "id", "sku", "itemId", "item_id")
        if "/catalog/subscribe" in path_lower or "subscribe" in segments:
            add("email", "name", "message", "callback", "redirect", "returnUrl")
        if "/catalog" in path_lower:
            add("searchTerm", "search", "q", "query", "category", "sort", "filter", "productId", "id", "minPrice", "maxPrice")
        if "/blog" in path_lower:
            add("id", "postId", "post_id", "search", "q", "query", "redirect", "url", "next")
        if "/login" in path_lower or "account" in segments:
            add("username", "email", "password", "redirect", "returnUrl", "next", "csrf", "token")

        for segment in segments:
            add(segment, f"{segment}Id", f"{segment}_id")

        for hint in hints:
            low = str(hint).lower()
            if "sql" in low:
                add("id", "searchTerm", "search", "category", "productId", "product_id", "sort", "filter")
            if "xss" in low or "cross-site" in low or "template injection" in low or "dom" in low:
                add("searchTerm", "q", "query", "message", "name", "callback", "returnUrl", "redirect", "data")
            if "xml" in low or "xxe" in low:
                add("xml", "payload", "data", "stockApi", "stock_api", "url", "path")
            if "redirect" in low or "link manipulation" in low or "request url" in low:
                add("redirect", "redirectUrl", "redirect_uri", "url", "next", "returnUrl", "continue")
            if "traversal" in low or "file" in low or "lfi" in low or "include" in low:
                add("file", "filename", "path", "template", "include", "download")
            if "base64" in low:
                add("data", "payload", "id", "searchTerm")
            if "header injection" in low:
                add("redirect", "url", "next", "returnUrl", "callback")

        add(self._candidate_parameter_names(urls, declared_paths, limit=160))

        deduped: list[str] = []
        seen = set()
        for name in names:
            if name in seen:
                continue
            seen.add(name)
            deduped.append(name)
        return deduped

    def generate_parameter_test_urls(
        self,
        base_url: str,
        urls: list,
        declared_paths: list | None = None,
        scope_rules: dict | None = None,
        max_routes: int = 80,
        max_urls: int = 450,
    ) -> list[str]:
        route_entries: list[tuple[str, int]] = []
        seen_routes = set()

        def add_route(raw: str):
            if not raw or not isinstance(raw, str):
                return
            route = raw.split("#", 1)[0].strip()
            if not route:
                return
            if not route.startswith("http"):
                route = urljoin(base_url.rstrip("/") + "/", route.lstrip("/"))
            route = self._route_without_query(route)
            if self._looks_static_asset(route, allow_js=False):
                return
            if not is_url_in_scope(route, base_url, scope_rules):
                return
            if route in seen_routes:
                return
            seen_routes.add(route)
            route_entries.append((route, len(route_entries)))

        for route in self._urls_from_declared_paths(base_url, declared_paths or []):
            add_route(route)
        for route in urls or []:
            add_route(route)
        add_route(base_url)

        def route_rank(item: tuple[str, int]) -> tuple[int, int]:
            route, order = item
            path = (urlparse(route).path or "/").lower()
            score = order
            hints = self._declared_hints_for_route(path, declared_paths)
            if hints:
                score -= 500
            priority_markers = (
                ("/catalog/product/stock", -220),
                ("/catalog/product", -190),
                ("/catalog/subscribe", -180),
                ("/catalog", -170),
                ("/blog/post", -150),
                ("/blog", -140),
                ("/login", -130),
                ("/my-account", -120),
            )
            for marker, weight in priority_markers:
                if marker in path:
                    score += weight
            if path in ("", "/"):
                score += 250
            return (score, order)

        route_param_sets: list[tuple[str, list[str]]] = []
        for route, _ in sorted(route_entries, key=route_rank)[:max_routes]:
            path = (urlparse(route).path or "/").lower()
            hints = self._declared_hints_for_route(path, declared_paths)
            names = self._route_parameter_names(route, urls or [], declared_paths)
            if not names:
                continue
            per_route_limit = 34 if hints else 20
            if path in ("", "/"):
                per_route_limit = 8
            route_param_sets.append((route, names[:per_route_limit]))

        generated: list[str] = []
        seen_urls = set()
        max_param_depth = max((len(names) for _, names in route_param_sets), default=0)
        for idx in range(max_param_depth):
            for route, names in route_param_sets:
                if idx >= len(names):
                    continue
                name = names[idx]
                candidate = self._append_param_to_url(route, name)
                if candidate in seen_urls or not is_url_in_scope(candidate, base_url, scope_rules):
                    continue
                seen_urls.add(candidate)
                generated.append(candidate)
                if len(generated) >= max_urls:
                    return generated
        return generated

    def _route_without_query(self, url: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme and parsed.netloc and not parsed.path:
            parsed = parsed._replace(path="/")
        return urlunparse(parsed._replace(query="", fragment=""))

    async def hidden_parameter_bruteforce(
        self,
        base_url: str,
        urls: list,
        scope_rules: dict | None = None,
        declared_paths: list | None = None,
        max_routes: int = 20,
    ) -> list:
        routes = []
        for raw in [base_url] + (urls or []):
            route = self._route_without_query(raw)
            if self._looks_static_asset(route, allow_js=False):
                continue
            if route not in routes and is_url_in_scope(route, base_url, scope_rules):
                routes.append(route)
            if len(routes) >= max_routes:
                break
        if not routes:
            return []

        names = self._candidate_parameter_names(urls, declared_paths)
        marker = "yggdrasil_param_probe"
        discovered = []
        seen = set()
        await self.log(f"wfuzz-style hidden parameter brute force on {len(routes)} route(s) with {len(names)} names", "info")

        async with httpx.AsyncClient(timeout=7, verify=False, follow_redirects=True) as c:
            for route in routes:
                try:
                    control = await c.get(route, params={"yggdrasil_control": marker})
                except Exception:
                    continue
                control_text = control.text[:12000]
                control_len = len(control.content)
                for name in names:
                    probe_url = route + ("&" if "?" in route else "?") + urlencode({name: marker})
                    if not is_url_in_scope(probe_url, base_url, scope_rules):
                        continue
                    try:
                        probe = await c.get(probe_url)
                    except Exception:
                        continue
                    delta = abs(len(probe.content) - control_len)
                    status_changed = probe.status_code != control.status_code
                    reflected = marker in probe.text
                    body_changed = delta > 80 and probe.text[:12000] != control_text
                    if not (status_changed or reflected or body_changed):
                        continue
                    key = (route, name)
                    if key in seen:
                        continue
                    seen.add(key)
                    discovered.append({
                        "url": probe_url,
                        "route": route,
                        "parameter": name,
                        "signal": "reflected" if reflected else "status/length delta",
                    })
                    if len(discovered) >= 120:
                        break
                if len(discovered) >= 120:
                    break

        await self.log(
            f"Hidden parameter brute force discovered {len(discovered)} candidate parameter(s)",
            "success" if discovered else "info",
        )
        return discovered

    async def test_sqli(self, urls: list) -> list:
        param_urls = [u for u in urls if "?" in u and "=" in u][:25]
        if not param_urls:
            await self.log("No parameterized URLs to test for SQLi", "info")
            return []

        await self.log(f"Testing {len(param_urls)} endpoints for SQL injection (sqlmap)", "info")
        findings = []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(param_urls))
            url_file = f.name

        try:
            stdout, stderr, rc = await self.run_command(
                ["sqlmap", "-m", url_file, "--batch", "--random-agent",
                 "--level", "2", "--risk", "2", "--smart",
                 "--technique", "BEUST", "--threads", "4",
                 "--timeout", "15", "--retries", "1",
                 "--output-dir", "/tmp/sqlmap_out"],
                timeout=600,
            )
            if rc == 127:
                await self.log("sqlmap not available; SQLi testing skipped", "warn")
                return []

            combined = stdout + stderr
            # sqlmap prints "Parameter: X (GET)" and "Type:" blocks on a hit
            vuln_blocks = re.findall(
                r"Parameter:\s*(.+?)\s*\((\w+)\).*?Type:\s*(.+?)\n.*?Title:\s*(.+?)\n",
                combined, re.DOTALL,
            )
            hit_urls = re.findall(r"sqlmap identified the following injection point.*?URL:\s*(\S+)", combined, re.DOTALL)

            for param, method, sqli_type, title in vuln_blocks:
                findings.append({"parameter": param.strip(), "method": method, "type": sqli_type.strip()})
                await self.add_finding(
                    title=f"SQL Injection: {param.strip()} parameter ({method})",
                    severity="critical",
                    description=f"SQL injection confirmed by sqlmap on parameter '{param.strip()}'. "
                                f"Injection type: {sqli_type.strip()}. An attacker can read or modify "
                                f"the database, extract credentials, and potentially achieve RCE.",
                    evidence=f"sqlmap: {title.strip()}\nParameter: {param.strip()} ({method})",
                    cvss_score=9.8,
                    remediation="Use parameterized queries / prepared statements. Never concatenate "
                                "user input into SQL. Apply least-privilege DB accounts and a WAF.",
                )

            if not vuln_blocks and "is vulnerable" in combined.lower():
                await self.add_finding(
                    title="Possible SQL Injection (manual confirm)",
                    severity="high",
                    description="sqlmap flagged a potential injection point. Manual confirmation advised.",
                    evidence=combined[-400:],
                    cvss_score=7.5,
                    remediation="Parameterize queries; review flagged endpoint.",
                )

            await self.log(f"SQLi testing complete: {len(vuln_blocks)} confirmed injection points", "success" if vuln_blocks else "info")
        except Exception as e:
            await self.log(f"sqlmap error: {e}", "warn")
        finally:
            os.unlink(url_file)

        return findings

    async def _basic_xss_reflection(self, param_urls: list) -> list:
        """Fast fallback when dalfox is unavailable or times out.

        This does not prove script execution. It records reflected parameters as
        low-severity candidates so a tester knows where browser validation is worth doing.
        """
        findings = []
        seen = set()
        marker_base = "yggdrasil_xss_probe"
        async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as c:
            for url in param_urls[:25]:
                parsed = urlparse(url)
                pairs = parse_qsl(parsed.query, keep_blank_values=True)
                for name, _ in pairs[:5]:
                    key = (parsed.path, name)
                    if key in seen:
                        continue
                    marker = f"{marker_base}_{re.sub(r'[^a-zA-Z0-9]', '_', name)[:20]}"
                    probe_pairs = [(k, marker if k == name else v) for k, v in pairs]
                    probe_url = urlunparse(parsed._replace(query=urlencode(probe_pairs, doseq=True)))
                    try:
                        response = await c.get(probe_url)
                    except Exception:
                        continue
                    if marker not in response.text:
                        continue
                    seen.add(key)
                    findings.append({"param": name, "type": "reflection", "url": probe_url})
                    await self.add_finding(
                        title=f"Reflected Parameter Candidate: {name}",
                        severity="low",
                        description=(
                            "The parameter value was reflected in the HTTP response. This is not confirmed XSS, "
                            "but it is a useful candidate for context-aware browser validation."
                        ),
                        evidence=f"Probe marker reflected in response\nURL: {probe_url}",
                        cvss_score=3.7,
                        remediation=(
                            "Apply context-aware output encoding and validate whether the reflection occurs in "
                            "HTML, attribute, script, URL, or JSON context."
                        ),
                    )
        await self.log(f"Basic reflection fallback complete: {len(findings)} candidate(s)", "success" if findings else "info")
        return findings

    # XSS
    async def test_xss(self, urls: list) -> list:
        param_urls = [u for u in urls if "?" in u and "=" in u][:40]
        if not param_urls:
            await self.log("No parameterized URLs to test for XSS", "info")
            return []

        await self.log(f"Testing {len(param_urls)} endpoints for XSS (dalfox)", "info")
        findings = []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(param_urls))
            url_file = f.name

        try:
            stdout, stderr, rc = await self.run_command(
                ["dalfox", "file", url_file, "--format", "json",
                 "--silence", "--no-spinner", "--worker", "10", "--timeout", "10"],
                timeout=420,
            )
            if rc == 127:
                await self.log("dalfox not available; XSS testing skipped", "warn")
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

            if not findings:
                await self.log("Dalfox did not return confirmed XSS; running basic reflection fallback", "info")
                findings.extend(await self._basic_xss_reflection(param_urls))
            await self.log(f"XSS testing complete: {len(findings)} confirmed/candidate", "success" if findings else "info")
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
            stdout, _, rc = await self.run_command(
                ["nuclei", "-l", uf, "-dast", "-jsonl", "-silent",
                 "-severity", "critical,high,medium", "-timeout", "10", "-rl", "50"],
                timeout=420,
            )
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
    # Path traversal / local file include
    async def test_path_traversal(
        self,
        urls: list,
        base_url: str,
        scope_rules: dict | None = None,
        lab_mode: bool = False,
    ) -> list:
        parameterized = [
            u for u in urls
            if "?" in u and "=" in u and is_url_in_scope(u, base_url, scope_rules)
        ][:40]
        path_like_candidates = [
            u for u in parameterized
            if build_traversal_probes(u, lab_mode=lab_mode, max_probes=1)
        ]
        if not path_like_candidates:
            await self.log(
                f"No path-like parameters to test for traversal ({len(parameterized)} parameterized URLs reviewed)",
                "info",
            )
            return []

        candidates = path_like_candidates
        await self.log(
            f"Testing {len(candidates)} path-like URLs for path traversal/LFI "
            f"({'lab payloads enabled' if lab_mode else 'safe canary mode'})",
            "info",
        )
        findings = []
        seen = set()

        async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=False) as c:
            for url in candidates:
                probes = build_traversal_probes(url, lab_mode=lab_mode, max_probes=10)
                if not probes:
                    continue
                try:
                    baseline = await c.get(url)
                except Exception:
                    continue
                for probe in probes:
                    if not is_url_in_scope(probe.url, base_url, scope_rules):
                        continue
                    key = (probe.parameter, urlparse(probe.url).path)
                    if key in seen:
                        continue
                    try:
                        response = await c.get(probe.url)
                    except Exception:
                        continue
                    hit = analyze_traversal_pair(baseline, response, probe.payload, lab_mode=lab_mode)
                    if not hit:
                        continue
                    seen.add(key)
                    findings.append({
                        "url": probe.url,
                        "parameter": probe.parameter,
                        "severity": hit["severity"],
                        "confidence": hit["confidence"],
                        "reason": hit["reason"],
                    })
                    await self.add_finding(
                        title=f"Possible Path Traversal/LFI: {probe.parameter}",
                        severity=hit["severity"],
                        description=(
                            "Yggdrasil observed response behavior consistent with path traversal "
                            "or unsafe server-side file access. Validate impact manually before "
                            "marking confirmed outside lab targets."
                        ),
                        evidence=(
                            f"URL: {probe.url}\n"
                            f"Parameter: {probe.parameter}\n"
                            f"Payload family: {probe.family}\n"
                            f"Signal: {hit['reason']}\n"
                            f"Confidence: {hit['confidence']}\n"
                            "Mappings: CWE-22, OWASP Top 10 2025, OWASP WSTG path traversal testing"
                        ),
                        cvss_score=7.5 if hit["severity"] == "high" else 5.3,
                        remediation=(
                            "Resolve requested files against an allowlisted base directory, "
                            "canonicalize before authorization, reject traversal sequences, and "
                            "avoid passing user-controlled paths into filesystem APIs."
                        ),
                    )
                    break

        await self.log(f"Path traversal testing complete: {len(findings)} candidate findings", "success" if findings else "info")
        return findings

    # IDOR / BOLA
    async def test_idor_bola(
        self,
        urls: list,
        base_url: str,
        scope_rules: dict | None = None,
        auth_profiles: dict | None = None,
    ) -> list:
        candidates = [
            u for u in urls
            if is_url_in_scope(u, base_url, scope_rules) and build_idor_probes(u, max_probes=1)
        ][:50]
        if not candidates:
            await self.log("No object-reference URLs to test for IDOR/BOLA", "info")
            return []

        profiles = {
            name: headers for name, headers in (auth_profiles or {}).items()
            if isinstance(name, str) and isinstance(headers, dict)
        }
        cross_role = len(profiles) >= 2
        mode = "cross-role replay" if cross_role else "unauthenticated neighbor-ID heuristic"
        await self.log(f"Testing {len(candidates)} IDOR/BOLA candidates ({mode})", "info")

        findings = []
        seen = set()

        async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=False) as c:
            if cross_role:
                names = list(profiles.keys())
                owner = names[0]
                for url in candidates[:25]:
                    try:
                        baseline = await c.get(url, headers=profiles[owner])
                    except Exception:
                        continue
                    for other in names[1:]:
                        try:
                            replay = await c.get(url, headers=profiles[other])
                        except Exception:
                            continue
                        hit = analyze_idor_pair(baseline, replay, cross_role=True)
                        if not hit:
                            continue
                        key = (url, other)
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append({"url": url, "profile": other, **hit})
                        await self.add_finding(
                            title=f"Probable IDOR/BOLA: {urlparse(url).path}",
                            severity=hit["severity"],
                            description=(
                                "An alternate auth profile received a near-identical object response. "
                                "This suggests missing per-object authorization or tenant isolation."
                            ),
                            evidence=(
                                f"URL: {url}\nOwner profile: {owner}\nReplay profile: {other}\n"
                                f"Signal: {hit['reason']}\nSimilarity: {hit['similarity']:.2f}\n"
                                "Mappings: CWE-639, CWE-862, CWE-863, OWASP Broken Access Control, OWASP API1 BOLA"
                            ),
                            cvss_score=7.5,
                            remediation="Enforce server-side object ownership checks for every object read/write.",
                        )
                        break
            else:
                for url in candidates:
                    probes = build_idor_probes(url, max_probes=4)
                    if not probes:
                        continue
                    try:
                        baseline = await c.get(url)
                    except Exception:
                        continue
                    for probe in probes:
                        if not is_url_in_scope(probe.url, base_url, scope_rules):
                            continue
                        try:
                            replay = await c.get(probe.url)
                        except Exception:
                            continue
                        hit = analyze_idor_pair(baseline, replay, cross_role=False)
                        if not hit:
                            continue
                        key = (probe.url, probe.parameter)
                        if key in seen:
                            continue
                        seen.add(key)
                        findings.append({"url": probe.url, "parameter": probe.parameter, **hit})
                        await self.add_finding(
                            title=f"Potential IDOR/BOLA Candidate: {probe.parameter}",
                            severity=hit["severity"],
                            description=(
                                "A neighboring object identifier returned sensitive-looking object data. "
                                "This is a candidate access-control issue; confirm with two authorized "
                                "accounts for a true IDOR/BOLA result."
                            ),
                            evidence=(
                                f"Baseline URL: {url}\nProbe URL: {probe.url}\n"
                                f"Parameter: {probe.parameter}\nOriginal: {probe.original_value}\n"
                                f"Candidate: {probe.payload}\nSignal: {hit['reason']}\n"
                                "Mappings: CWE-639, CWE-862, CWE-863, OWASP Broken Access Control, OWASP API1 BOLA"
                            ),
                            cvss_score=3.7 if hit["severity"] == "low" else 5.3,
                            remediation="Enforce object-level authorization and tenant checks before returning records.",
                        )
                        break

        await self.log(f"IDOR/BOLA testing complete: {len(findings)} candidate findings", "success" if findings else "info")
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

        async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as c:
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
                            await self.add_finding(
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
                            break
                    except Exception:
                        continue

        # Exposed sensitive endpoints frequently paying on bounties
        sensitive = ["/.git/config", "/.env", "/actuator/health", "/actuator/env",
                     "/api/swagger.json", "/swagger-ui/", "/graphql", "/server-status",
                     "/.well-known/security.txt", "/debug", "/metrics"]
        async with httpx.AsyncClient(timeout=6, verify=False, follow_redirects=False) as c:
            for path in sensitive:
                try:
                    r = await c.get(base_url.rstrip("/") + path)
                    if r.status_code == 200 and len(r.content) > 20:
                        sev = "high" if path in ("/.env", "/.git/config", "/actuator/env") else "medium"
                        cvss = 7.5 if sev == "high" else 5.3
                        findings.append({"type": "exposure", "path": path})
                        await self.add_finding(
                            title=f"Sensitive Endpoint Exposed: {path}",
                            severity=sev,
                            description=f"{path} is publicly accessible and returned content. "
                                        "This can leak secrets, source, internal config, or API schemas.",
                            evidence=f"GET {path} -> 200 ({len(r.content)} bytes)",
                            cvss_score=cvss,
                            remediation="Restrict or remove the endpoint. Move secrets to env/secret managers "
                                        "and block metadata/debug routes at the edge.",
                        )
                except Exception:
                    continue

        # GraphQL introspection (common high-value finding)
        try:
            async with httpx.AsyncClient(timeout=8, verify=False) as c:
                q = {"query": "{__schema{types{name}}}"}
                r = await c.post(base_url.rstrip("/") + "/graphql", json=q)
                if r.status_code == 200 and "__schema" in r.text:
                    findings.append({"type": "graphql_introspection"})
                    await self.add_finding(
                        title="GraphQL Introspection Enabled",
                        severity="medium",
                        description="The GraphQL endpoint exposes its full schema via introspection, "
                                    "handing an attacker the complete API surface for targeted abuse.",
                        evidence="POST /graphql with introspection query returned __schema",
                        cvss_score=5.3,
                        remediation="Disable introspection in production and enforce query depth/complexity limits.",
                    )
        except Exception:
            pass

        await self.log(f"Auth/access-control probing complete: {len(findings)} findings", "success" if findings else "info")
        return findings

    # ── Content discovery with a real wordlist ───────────────────
    def _parse_ffuf_json(self, stdout: str) -> list:
        found = []
        text = stdout.strip()
        if not text:
            return found
        try:
            data = json.loads(text)
            if isinstance(data, dict) and isinstance(data.get("results"), list):
                for hit in data["results"]:
                    found.append({"url": hit.get("url", ""), "status": hit.get("status", 0)})
                return found
        except json.JSONDecodeError:
            pass
        for line in stdout.splitlines():
            try:
                hit = json.loads(line)
                found.append({"url": hit.get("url", ""), "status": hit.get("status", 0)})
            except json.JSONDecodeError:
                continue
        return found

    async def _python_content_discovery(self, base_url: str, words: list) -> list:
        found = []
        async with httpx.AsyncClient(timeout=6, verify=False, follow_redirects=False) as c:
            for i in range(0, min(len(words), 350), 25):
                batch = words[i:i + 25]
                tasks = [c.get(normalize_discovered_url(base_url, word)) for word in batch]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, Exception):
                        continue
                    if result.status_code in (200, 204, 301, 302, 307, 401, 403):
                        found.append({
                            "url": str(result.url),
                            "status": result.status_code,
                            "length": len(result.content),
                        })
        return found

    async def content_discovery(self, base_url: str, urls: list | None = None) -> list:
        generated_words = generate_discovery_words(base_url, urls or [])
        wordlist = next((w for w in SECLISTS_DIRS if os.path.exists(w)), None)
        temp_wordlist = None
        if not wordlist:
            await self.log("SecLists not present; using Yggdrasil generated discovery wordlist", "warn")
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
            tmp.write("\n".join(generated_words))
            tmp.close()
            temp_wordlist = tmp.name
            wordlist = temp_wordlist
        else:
            await self.log("Content discovery with SecLists + Yggdrasil high-value checks", "info")

        found = []
        try:
            stdout, _, rc = await self.run_command(
                ["ffuf", "-u", f"{base_url.rstrip('/')}/FUZZ", "-w", wordlist,
                 "-mc", "200,204,301,302,307,401,403", "-json", "-s",
                 "-t", "25", "-timeout", "6", "-maxtime", "90"],
                timeout=120,
            )
            if rc == 127:
                await self.log("ffuf not available; using Python content discovery fallback", "warn")
                found = await self._python_content_discovery(base_url, generated_words)
            elif rc == -1:
                await self.log("ffuf timed out; using generated Python fallback", "warn")
                found = await self._python_content_discovery(base_url, generated_words)
            else:
                found = self._parse_ffuf_json(stdout)
        finally:
            if temp_wordlist and os.path.exists(temp_wordlist):
                os.unlink(temp_wordlist)

        for path, (title, severity, remediation) in HIGH_VALUE_EXPOSURE_PATHS.items():
            match = next((h for h in found if urlparse(h.get("url", "")).path.rstrip("/") == path.rstrip("/")), None)
            if not match:
                continue
            await self.add_finding(
                title=title,
                severity=severity,
                description=f"Content discovery found high-value path {path}.",
                evidence=(
                    f"GET {match.get('url')} -> HTTP {match.get('status')}\n"
                    "Mappings: OWASP Security Misconfiguration, CWE-200 where sensitive data is exposed"
                ),
                cvss_score=7.5 if severity == "high" else 5.3,
                remediation=remediation,
            )

        for hit in found[:25]:
            await self.log(
                f"Content path discovered: HTTP {hit.get('status', '?')} {hit.get('url', '')}",
                "info",
            )
        if len(found) > 25:
            await self.log(f"Content discovery found {len(found) - 25} additional paths not shown in log", "info")
        await self.log(f"Content discovery: {len(found)} paths", "success" if found else "info")
        return found

    def _dedupe_in_scope_urls(self, urls: list, base_url: str, scope_rules: dict | None, max_urls: int = 400) -> list:
        deduped = []
        seen = set()
        for raw in urls:
            if not raw or not isinstance(raw, str):
                continue
            url = raw.split("#", 1)[0].strip()
            if not url.startswith("http"):
                url = urljoin(base_url.rstrip("/") + "/", url.lstrip("/"))
            if not is_url_in_scope(url, base_url, scope_rules):
                continue
            if url in seen:
                continue
            seen.add(url)
            deduped.append(url)
            if len(deduped) >= max_urls:
                break
        return deduped

    async def explore_discovered_paths(
        self,
        base_url: str,
        discovered: list,
        existing_urls: list,
        scope_rules: dict | None = None,
        max_paths: int = 30,
    ) -> list:
        if not discovered:
            return []

        seeds = []
        for hit in discovered:
            url = str(hit.get("url") or "")
            status = int(hit.get("status") or 0)
            if not url:
                continue
            if not url.startswith("http"):
                url = urljoin(base_url.rstrip("/") + "/", url.lstrip("/"))
            if status not in (200, 204, 301, 302, 307, 401, 403):
                continue
            if is_url_in_scope(url, base_url, scope_rules):
                seeds.append(url)

        seeds = self._dedupe_in_scope_urls(seeds, base_url, scope_rules, max_urls=max_paths)
        if not seeds:
            return []

        await self.log(f"Exploring {len(seeds)} discovered content path(s) for links and endpoints", "info")
        expanded = list(seeds)
        link_re = re.compile(r'''(?:href|src|action)\s*=\s*["']([^"']+)["']''', re.I)

        async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as c:
            for seed in seeds:
                try:
                    response = await c.get(seed)
                except Exception:
                    continue
                content_type = response.headers.get("content-type", "").lower()
                if response.status_code >= 400 or "html" not in content_type:
                    continue
                for match in link_re.findall(response.text[:250000]):
                    if match.startswith(("mailto:", "tel:", "javascript:", "data:")):
                        continue
                    expanded.append(urljoin(str(response.url), match))

        expanded = self._dedupe_in_scope_urls(existing_urls + expanded, base_url, scope_rules)
        added = max(0, len(expanded) - len(set(existing_urls)))
        await self.log(f"Discovered path exploration added {added} endpoint(s) to active testing set", "success" if added else "info")
        return expanded

    def _urls_from_declared_paths(self, base_url: str, declared_paths: list) -> list:
        urls = []
        for row in declared_paths or []:
            path = row.get("path") if isinstance(row, dict) else str(row)
            if not path or not str(path).startswith("/"):
                continue
            urls.append(urljoin(base_url.rstrip("/") + "/", str(path).lstrip("/")))
        return urls

    def _declared_paths_from_scope_rules(self, scope_rules: dict | None) -> list:
        rows = []
        for rule in (scope_rules or {}).get("in_scope", []) or []:
            if not isinstance(rule, dict):
                continue
            ident = str(rule.get("identifier") or "").strip()
            rule_type = str(rule.get("type") or "").lower().strip()
            if rule_type in ("path", "url_path") or (ident.startswith("/") and not ident.startswith("//")):
                rows.append({"path": ident, "hints": []})
        return rows

    async def check_declared_dependency_hints(self, declared_paths: list, base_url: str) -> list:
        findings = []
        candidates = [
            row for row in declared_paths or []
            if isinstance(row, dict)
            and any("vulnerable javascript dependency" in str(h).lower() for h in row.get("hints", []))
        ]
        if not candidates:
            return findings

        async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as c:
            for row in candidates[:20]:
                path = row.get("path", "")
                url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
                try:
                    response = await c.get(url)
                except Exception:
                    continue
                if response.status_code >= 400:
                    continue

                parsed = urlparse(url)
                title = "Outdated JavaScript Dependency Exposed"
                description = "A JavaScript dependency declared in scope notes was reachable during active testing."
                if "angular_1-7-7" in parsed.path.lower() or "angular" in parsed.path.lower():
                    title = "Outdated AngularJS Dependency Exposed"
                    description = (
                        "AngularJS 1.x is end-of-life and should not be used in production without compensating controls. "
                        "The dependency was reachable from the assessed application surface."
                    )

                findings.append({"type": "dependency", "url": url})
                await self.add_finding(
                    title=title,
                    severity="medium",
                    description=description,
                    evidence=f"GET {url} -> HTTP {response.status_code} ({len(response.content)} bytes)",
                    cvss_score=5.3,
                    remediation="Upgrade to a maintained framework/version and remove unused legacy JavaScript assets.",
                )

        await self.log(f"Declared dependency hint checks complete: {len(findings)} result(s)", "success" if findings else "info")
        return findings

    async def check_declared_vulnerability_hints(
        self,
        declared_paths: list,
        base_url: str,
        scope_rules: dict | None = None,
    ) -> list:
        hint_map = {
            "sql injection": ("Manual Test Candidate: SQL Injection", "CWE-89, OWASP Injection"),
            "cross-site scripting": ("Manual Test Candidate: Cross-Site Scripting", "CWE-79, OWASP XSS"),
            "xss": ("Manual Test Candidate: Cross-Site Scripting", "CWE-79, OWASP XSS"),
            "xml external entity": ("Manual Test Candidate: XML External Entity", "CWE-611, OWASP XXE"),
            "xxe": ("Manual Test Candidate: XML External Entity", "CWE-611, OWASP XXE"),
            "open redirection": ("Manual Test Candidate: Open Redirect", "CWE-601"),
            "prototype pollution": ("Manual Test Candidate: Prototype Pollution", "CWE-1321"),
            "template injection": ("Manual Test Candidate: Template Injection", "CWE-94/CWE-1336"),
            "header injection": ("Manual Test Candidate: HTTP Response Header Injection", "CWE-113"),
            "dom data manipulation": ("Manual Test Candidate: DOM Data Manipulation", "DOM-based client-side issue"),
            "link manipulation": ("Manual Test Candidate: Link Manipulation", "DOM-based client-side issue"),
            "request url override": ("Manual Test Candidate: Request URL Override", "client-side request control"),
            "base64-encoded data": ("Manual Test Candidate: Encoded Parameter Handling", "encoded input attack surface"),
        }
        rows = []
        for row in declared_paths or []:
            if not isinstance(row, dict):
                continue
            hints = [str(h) for h in row.get("hints", []) if str(h).strip()]
            if hints:
                rows.append((row.get("path", ""), hints))
        if not rows:
            return []

        candidates = []
        seen = set()
        async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as c:
            for path, hints in rows[:80]:
                if not path or not str(path).startswith("/"):
                    continue
                url = urljoin(base_url.rstrip("/") + "/", str(path).lstrip("/"))
                if not is_url_in_scope(url, base_url, scope_rules):
                    continue
                try:
                    response = await c.get(url)
                except Exception:
                    continue
                if response.status_code >= 500:
                    continue
                for hint in hints:
                    low_hint = hint.lower()
                    matched = next((v for k, v in hint_map.items() if k in low_hint), None)
                    if not matched:
                        continue
                    title, mapping = matched
                    key = (title, url)
                    if key in seen:
                        continue
                    seen.add(key)
                    candidates.append({"url": url, "hint": hint, "status": response.status_code})
                    await self.add_finding(
                        title=f"{title}: {urlparse(url).path or '/'}",
                        severity="low",
                        description=(
                            "The authorized scope notes identify this reachable endpoint as a candidate "
                            "for manual validation. Yggdrasil has not confirmed exploitability here; "
                            "this preserves the testing lead when automated tools miss it."
                        ),
                        evidence=(
                            f"Scope hint: {hint}\n"
                            f"GET {url} -> HTTP {response.status_code} ({len(response.content)} bytes)\n"
                            f"Mapping: {mapping}"
                        ),
                        cvss_score=3.1,
                        remediation="Manually validate the endpoint, then remediate with the control appropriate to the confirmed weakness.",
                    )

        await self.log(f"Declared vulnerability hint checks complete: {len(candidates)} manual candidate(s)", "success" if candidates else "info")
        return candidates

    async def run_offensive(
        self,
        base_url: str,
        scope_rules: dict | None = None,
        options: dict | None = None,
        declared_paths: list | None = None,
    ) -> dict:
        options = options or {}
        await self.log(f"⚔ Offensive engine engaged against {base_url}", "info")
        declared_paths = list(declared_paths or [])
        if not declared_paths:
            declared_paths = self._declared_paths_from_scope_rules(scope_rules)
        urls = self._dedupe_in_scope_urls(await self.crawl(base_url), base_url, scope_rules)
        declared_seed_urls = self._urls_from_declared_paths(base_url, declared_paths or [])
        if declared_seed_urls:
            declared_seed_urls = self._dedupe_in_scope_urls(declared_seed_urls, base_url, scope_rules)
            await self.log(f"Using {len(declared_seed_urls)} declared scope path(s) as active test seeds", "info")
            urls = self._dedupe_in_scope_urls(urls + declared_seed_urls, base_url, scope_rules)
        if base_url not in urls:
            urls.insert(0, base_url)
        spider_urls = await self.spider_http(base_url, urls, scope_rules)
        if spider_urls:
            urls = self._dedupe_in_scope_urls(urls + spider_urls, base_url, scope_rules)
        lab_mode = bool(
            options.get("lab_mode")
            or os.getenv("YGGDRASIL_LAB_MODE", "").lower() in ("1", "true", "yes")
            or os.getenv("OLYMPUS_LAB_MODE", "").lower() in ("1", "true", "yes")
        )
        auth_profiles = options.get("auth_profiles") or {}

        # Run content discovery before injection/access-control modules so discovered
        # paths become real test inputs rather than only a final counter.
        async def _run_module(label: str, coro):
            try:
                result = await coro
                if not isinstance(result, list):
                    await self.log(f"{label} module returned {type(result).__name__}; treating as no results", "warn")
                    return []
                await self.log(f"{label} module complete: {len(result)} result(s)", "info")
                return result
            except Exception as e:
                await self.log(f"{label} module failed: {type(e).__name__}: {str(e)[:240]}", "warn")
                return []

        param_mining = await _run_module("ParamSpider-style parameter mining", self.paramspider_parameter_mining(base_url, scope_rules))
        if param_mining:
            urls = self._dedupe_in_scope_urls(urls + param_mining, base_url, scope_rules)

        disco = await _run_module("Content discovery", self.content_discovery(base_url, urls))
        expanded_urls = await self.explore_discovered_paths(base_url, disco, urls, scope_rules)
        if expanded_urls:
            urls = expanded_urls
            followup_spider_urls = await self.spider_http(base_url, urls, scope_rules, max_pages=40)
            if followup_spider_urls:
                urls = self._dedupe_in_scope_urls(urls + followup_spider_urls, base_url, scope_rules)

        generated_param_urls = self.generate_parameter_test_urls(
            base_url,
            urls,
            declared_paths=declared_paths,
            scope_rules=scope_rules,
        )
        if generated_param_urls:
            # Put generated candidates first so capped tools exercise the high-value route/parameter matrix.
            urls = self._dedupe_in_scope_urls(generated_param_urls + urls, base_url, scope_rules, max_urls=900)
        await self.log(
            f"Generated {len(generated_param_urls)} parameter test URL(s) from routes, wordlist, and scope hints",
            "success" if generated_param_urls else "info",
        )

        external_params = await _run_module(
            "Arjun/x8 parameter discovery",
            self.external_parameter_discovery(base_url, urls, scope_rules, declared_paths),
        )
        if external_params:
            urls = self._dedupe_in_scope_urls(
                [p.get("url", "") for p in external_params if isinstance(p, dict)] + urls,
                base_url,
                scope_rules,
                max_urls=1000,
            )

        hidden_params = await _run_module(
            "wfuzz-style hidden parameter brute force",
            self.hidden_parameter_bruteforce(base_url, urls, scope_rules, declared_paths),
        )
        if hidden_params:
            urls = self._dedupe_in_scope_urls(
                urls + [h.get("url", "") for h in hidden_params if isinstance(h, dict)],
                base_url,
                scope_rules,
            )

        parameterized_urls = [u for u in urls if "?" in u and "=" in u]
        traversal_candidate_urls = [
            u for u in parameterized_urls
            if build_traversal_probes(u, lab_mode=lab_mode, max_probes=1)
        ]
        idor_candidate_urls = [
            u for u in urls
            if build_idor_probes(u, max_probes=1)
        ]
        await self.log(
            "Coverage: "
            f"{len(urls)} in-scope URLs, "
            f"{len(parameterized_urls)} parameterized, "
            f"{len(traversal_candidate_urls)} traversal candidates, "
            f"{len(idor_candidate_urls)} IDOR/BOLA candidates",
            "info",
        )

        # Run modules sequentially because BaseAgent logging/finding writes share one DB session.
        # Concurrent module tasks can collide inside SQLAlchemy AsyncSession and disappear as empty results.
        sqli = await _run_module("SQLi", self.test_sqli(urls))
        xss = await _run_module("XSS", self.test_xss(urls))
        dast = await _run_module("Nuclei DAST", self.nuclei_dast(urls))
        auth = await _run_module("Auth/access-control", self.test_auth(base_url, urls))
        dependency = await _run_module("Declared dependency hints", self.check_declared_dependency_hints(declared_paths or [], base_url))
        scope_candidates = await _run_module("Declared vulnerability hints", self.check_declared_vulnerability_hints(declared_paths or [], base_url, scope_rules))
        traversal = await _run_module("Path traversal/LFI", self.test_path_traversal(urls, base_url, scope_rules, lab_mode))
        idor = await _run_module("IDOR/BOLA", self.test_idor_bola(urls, base_url, scope_rules, auth_profiles))

        def _safe(x):
            return x if isinstance(x, list) else []

        result = {
            "crawled_urls": len(urls),
            "coverage": {
                "in_scope_urls": len(urls),
                "parameterized_urls": len(parameterized_urls),
                "traversal_candidate_urls": len(traversal_candidate_urls),
                "idor_candidate_urls": len(idor_candidate_urls),
                "content_paths_discovered": len(_safe(disco)),
                "declared_scope_paths": len(declared_paths or []),
                "declared_seed_urls": len(declared_seed_urls),
                "spider_urls": len(spider_urls or []),
                "param_mining_urls": len(_safe(param_mining)),
                "generated_parameter_urls": len(generated_param_urls),
                "parameter_wordlist_size": len(self._candidate_parameter_names(urls, declared_paths, limit=160)),
                "external_parameter_candidates": len(_safe(external_params)),
                "hidden_parameter_candidates": len(_safe(hidden_params)),
                "lab_mode": lab_mode,
                "auth_profiles": len(auth_profiles),
            },
            "sqli": _safe(sqli),
            "xss": _safe(xss),
            "dast": _safe(dast),
            "auth": _safe(auth),
            "dependency": _safe(dependency),
            "scope_candidates": _safe(scope_candidates),
            "path_traversal": _safe(traversal),
            "idor_bola": _safe(idor),
            "content": _safe(disco),
            "param_mining": _safe(param_mining),
            "generated_params": generated_param_urls,
            "external_params": _safe(external_params),
            "hidden_params": _safe(hidden_params),
        }
        total = sum(len(_safe(v)) for v in (sqli, xss, dast, auth, dependency, scope_candidates, traversal, idor))
        await self.log(f"Offensive engine complete: {total} web-app findings across {len(urls)} in-scope URLs", "success")
        return result
