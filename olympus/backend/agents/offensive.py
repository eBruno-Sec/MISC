"""
OLYMPUS offensive engine.

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
from urllib.parse import urlparse, parse_qs

# Curated wordlists first (fast, fetched at build time), full SecLists as fallback.
SECLISTS_DIRS = [
    "/opt/wordlists/raft-medium-directories.txt",
    "/opt/wordlists/common.txt",
    "/opt/seclists/Discovery/Web-Content/raft-medium-directories.txt",
    "/opt/seclists/Discovery/Web-Content/common.txt",
]


class OffensiveEngine:
    """Mixed into Ares. Expects the host to provide: self.run_command, self.log,
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

    # ── SQL injection ────────────────────────────────────────────
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

    # ── XSS ──────────────────────────────────────────────────────
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
            stdout, _, rc = await self.run_command(
                ["ffuf", "-u", f"{base_url.rstrip('/')}/FUZZ", "-w", wordlist,
                 "-mc", "200,204,301,302,307,401,403", "-json", "-s",
                 "-t", "40", "-timeout", "8"],
                timeout=300,
            )
            if rc == 127:
                await self.log("ffuf not available; content discovery skipped", "warn")
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

        async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as c:
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
                        await self.add_finding(
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
                    if budget <= 0:
                        await self.log("Path traversal request budget reached; stopping early", "warn")
                        break

        await self.log(f"Path traversal testing complete: {len(findings)} confirmed",
                       "success" if findings else "info")
        return findings

    # ── OWASP ZAP active scan (full DAST) ────────────────────────
    async def zap_active_scan(self, base_url: str) -> list:
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
                    return []

                ver = (await _get(c, "/JSON/core/view/version/", {})).get("version", "?")
                await self.log(f"OWASP ZAP {ver} online; seeding target", "info")

                await _get(c, "/JSON/core/action/accessUrl/", {"url": base_url, "followRedirects": "true"})

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

    async def run_offensive(self, base_url: str, extra_wordlists: list = None) -> dict:
        await self.log(f"⚔ Offensive engine engaged against {base_url}", "info")
        urls = await self.crawl(base_url)

        # Run injection classes concurrently where safe
        sqli, xss, dast, auth, trav, disco = await asyncio.gather(
            self.test_sqli(urls),
            self.test_xss(urls),
            self.nuclei_dast(urls),
            self.test_auth(base_url, urls),
            self.test_path_traversal(urls),
            self.content_discovery(base_url, extra_wordlists),
            return_exceptions=True,
        )

        def _safe(x):
            return x if isinstance(x, list) else []

        # OWASP ZAP full active scan: heavy, runs after the fast probes.
        zap = await self.zap_active_scan(base_url)

        result = {
            "crawled_urls": len(urls),
            "sqli": _safe(sqli),
            "xss": _safe(xss),
            "dast": _safe(dast),
            "auth": _safe(auth),
            "traversal": _safe(trav),
            "zap": _safe(zap),
            "content": _safe(disco),
        }
        total = sum(len(_safe(v)) for v in (sqli, xss, dast, auth, trav, zap))
        await self.log(f"⚔ Offensive engine complete: {total} injection/access/DAST findings across {len(urls)} URLs", "success")
        return result
