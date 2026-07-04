import asyncio
import json
import re
from .base import BaseAgent

SEVERITY_MAP = {
    "critical": ("critical", 9.5),
    "high": ("high", 7.5),
    "medium": ("medium", 5.0),
    "low": ("low", 3.0),
    "info": ("info", 0.0),
    "unknown": ("info", 0.0),
}


class Ares(BaseAgent):
    name = "ares"
    symbol = "⚔"
    display_name = "ARES"
    role = "Active Scanning & Vuln Assessment"


    def _scope_filter(self, hosts: list, scope_rules: dict) -> list:
        in_rules = scope_rules.get("in_scope", [])
        out_rules = scope_rules.get("out_of_scope", [])

        def matches(host: str, rules: list) -> bool:
            h = host.lower()
            for rule in rules:
                rid = rule.get("identifier", "").lower().lstrip("*.")
                if not rid:
                    continue
                if h == rid or h.endswith("." + rid):
                    return True
            return False

        result = []
        for h in hosts:
            host = h if isinstance(h, str) else h.get("host", "")
            if out_rules and matches(host, out_rules):
                continue
            if in_rules and not matches(host, in_rules):
                continue
            result.append(h)
        return result

    async def execute(self, target: str, context: dict = None) -> dict:
        hermes = (context or {}).get("hermes", {})
        live_hosts = hermes.get("live_hosts", [])
        domain = hermes.get("domain", target)
        scope_rules = (context or {}).get("scope_rules", {})
        if scope_rules and (scope_rules.get("in_scope") or scope_rules.get("out_of_scope")):
            live_hosts = self._scope_filter(live_hosts, scope_rules)
            await self.log(f"Scope enforced: {len(live_hosts)} targets in scope", "info")

        if not live_hosts:
            await self.log("No live hosts from Hermes. Scanning primary target only.", "warn")
            live_hosts = [{"host": domain, "url": f"https://{domain}"}]

        await self.log(f"Active assessment of {len(live_hosts)} targets initiated", "info")

        result = {
            "targets_scanned": len(live_hosts),
            "port_results": {},
            "vulnerabilities": [],
            "directories": [],
            "service_findings": [],
        }

        # Nmap port scan
        await self.log("Running Nmap service detection (-sV --top-ports 1000)", "info")
        hosts_str = " ".join(h["host"] for h in live_hosts[:20])
        result["port_results"] = await self._nmap_scan(live_hosts[:20])

        # Nuclei vulnerability scan
        target_list = [h["url"] for h in live_hosts[:30]]
        await self.log(f"Running Nuclei templates against {len(target_list)} URLs", "info")
        result["vulnerabilities"] = await self._nuclei_scan(target_list)

        # Service-specific checks
        await self.log("Running service-specific security checks", "info")
        result["service_findings"] = await self._service_checks(live_hosts[:20], result["port_results"])

        # Directory enumeration on primary target
        await self.log(f"Directory enumeration on {domain}", "info")
        result["directories"] = await self._dir_enum(live_hosts[0]["url"] if live_hosts else f"https://{domain}")

        total_vulns = len(result["vulnerabilities"])
        await self.log(f"Active assessment complete. {total_vulns} vulnerabilities identified.", "success")
        return result

    async def _nmap_scan(self, hosts: list) -> dict:
        port_results = {}
        host_args = [h["host"] for h in hosts]

        stdout, stderr, rc = await self.run_command(
            ["nmap", "-sV", "-sC", "--top-ports", "1000", "-T4",
             "--open", "-oG", "-"] + host_args,
            timeout=300,
        )

        if rc != 0 and rc != 127:
            await self.log(f"Nmap scan error: {stderr[:200]}", "warn")

        if stdout:
            current_host = None
            for line in stdout.splitlines():
                if line.startswith("Host:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        current_host = parts[1]
                        port_results[current_host] = []
                elif line.startswith("Ports:") and current_host:
                    port_section = line.replace("Ports:", "").strip()
                    for port_info in port_section.split(","):
                        port_info = port_info.strip()
                        parts = port_info.split("/")
                        if len(parts) >= 7 and parts[1] == "open":
                            port_results[current_host].append({
                                "port": int(parts[0]),
                                "state": parts[1],
                                "proto": parts[2],
                                "service": parts[4],
                                "version": parts[6],
                            })
                            await self._check_dangerous_port(current_host, int(parts[0]), parts[4])

        if not port_results:
            await self.log("Nmap returned no results (tool may not be available in this environment)", "warn")
        else:
            total_ports = sum(len(v) for v in port_results.values())
            await self.log(f"Nmap complete: {total_ports} open ports across {len(port_results)} hosts", "info")

        return port_results

    async def _check_dangerous_port(self, host: str, port: int, service: str):
        risky = {
            21: ("FTP Open", "FTP transmits credentials in plaintext.", "medium", 5.3),
            23: ("Telnet Open", "Telnet is unencrypted. Replace with SSH.", "high", 7.5),
            25: ("SMTP Open (Port 25)", "Open SMTP may allow relay abuse.", "medium", 5.0),
            445: ("SMB Exposed", "SMB exposed. Risk of EternalBlue / ransomware.", "high", 8.1),
            3389: ("RDP Exposed", "RDP publicly exposed. Brute-force / BlueKeep risk.", "critical", 9.8),
            3306: ("MySQL Exposed", "Database port publicly accessible.", "high", 7.5),
            5432: ("PostgreSQL Exposed", "Database port publicly accessible.", "high", 7.5),
            6379: ("Redis Exposed", "Redis with no auth exposed. Full data access risk.", "critical", 9.8),
            27017: ("MongoDB Exposed", "MongoDB port accessible. Often unauthenticated.", "critical", 9.8),
            9200: ("Elasticsearch Exposed", "Elasticsearch port accessible.", "high", 8.1),
            2375: ("Docker Socket Exposed", "Docker API exposed. Full host compromise.", "critical", 10.0),
            4443: ("Alt HTTPS", "Non-standard HTTPS port in use.", "info", 0.0),
        }
        if port in risky:
            title, desc, sev, cvss = risky[port]
            await self.add_finding(
                title=f"{title} on {host}",
                severity=sev,
                description=desc,
                evidence=f"{host}:{port} ({service})",
                cvss_score=cvss,
                remediation="Restrict port access via firewall. Disable if not required.",
            )

    async def _nuclei_scan(self, urls: list) -> list:
        if not urls:
            return []

        # Write URL list to temp file
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(urls))
            tmpfile = f.name

        findings = []
        try:
            stdout, stderr, rc = await self.run_command(
                ["nuclei", "-l", tmpfile, "-severity", "critical,high,medium",
                 "-json", "-silent", "-no-interactsh", "-timeout", "10"],
                timeout=300,
            )

            if rc == 127:
                await self.log("Nuclei not available in this environment. Skipping template scan.", "warn")
                return []

            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    finding = json.loads(line)
                    sev = finding.get("info", {}).get("severity", "info").lower()
                    mapped_sev, cvss = SEVERITY_MAP.get(sev, ("info", 0.0))
                    template = finding.get("template-id", "unknown")
                    matched_at = finding.get("matched-at", "")
                    name = finding.get("info", {}).get("name", template)
                    description = finding.get("info", {}).get("description", "")
                    remediation = finding.get("info", {}).get("remediation", "")

                    findings.append({
                        "template": template,
                        "name": name,
                        "severity": mapped_sev,
                        "matched_at": matched_at,
                        "description": description,
                    })

                    await self.add_finding(
                        title=f"[Nuclei] {name}",
                        severity=mapped_sev,
                        description=description or f"Nuclei template {template} matched on {matched_at}",
                        evidence=f"Template: {template}\nURL: {matched_at}",
                        cvss_score=cvss,
                        remediation=remediation or "Review and patch the identified vulnerability.",
                    )
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            await self.log(f"Nuclei scan error: {e}", "warn")
        finally:
            os.unlink(tmpfile)

        await self.log(f"Nuclei: {len(findings)} findings", "info")
        return findings

    async def _dir_enum(self, base_url: str) -> list:
        # Use ffuf with a small built-in wordlist
        import tempfile, os
        wordlist = (
            "admin\nlogin\nbackup\nconfig\ntest\napi\ndev\n"
            ".git\n.env\nwp-login.php\nwp-admin\nphpmyadmin\n"
            "robots.txt\nsitemap.xml\nadmin.php\nconfig.php\n"
            "setup\ninstall\ndashboard\nmanager\nconsole\n"
            "upload\nuploads\nfiles\nstatic\nassets\n"
        )
        dirs = []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(wordlist)
            wl = f.name

        try:
            stdout, _, rc = await self.run_command(
                ["ffuf", "-u", f"{base_url}/FUZZ", "-w", wl,
                 "-mc", "200,301,302,403", "-json", "-s"],
                timeout=120,
            )

            if rc == 127:
                await self.log("ffuf not available. Directory enumeration skipped.", "warn")
                return []

            for line in stdout.splitlines():
                try:
                    hit = json.loads(line)
                    url = hit.get("url", "")
                    status = hit.get("status", 0)
                    dirs.append({"url": url, "status": status})

                    if status == 200 and any(s in url for s in [".env", ".git", "config", "backup"]):
                        await self.add_finding(
                            title=f"Sensitive File/Path Exposed: {url}",
                            severity="high",
                            description=f"Potentially sensitive path returned HTTP {status}",
                            evidence=f"GET {url} -> {status}",
                            cvss_score=7.5,
                            remediation="Restrict access via web server config. Remove sensitive files from webroot.",
                        )
                    elif status == 403:
                        dirs[-1]["note"] = "Forbidden (exists but restricted)"
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            await self.log(f"Dir enum error: {e}", "warn")
        finally:
            os.unlink(wl)

        await self.log(f"Directory enumeration: {len(dirs)} paths found", "info")
        return dirs

    async def _service_checks(self, hosts: list, port_results: dict) -> list:
        findings = []
        for host_info in hosts:
            host = host_info["host"]
            ports = port_results.get(host, [])
            port_nums = [p["port"] for p in ports]

            # Check for default credentials on common services
            if 80 in port_nums or 443 in port_nums:
                # Check for exposed .git
                try:
                    import httpx as _httpx
                    async with _httpx.AsyncClient(timeout=5, verify=False) as c:
                        r = await c.get(f"{host_info['url']}/.git/HEAD")
                        if r.status_code == 200 and "ref:" in r.text:
                            await self.add_finding(
                                title=f"Exposed .git Directory on {host}",
                                severity="high",
                                description="Git repository is publicly accessible. Source code exposure risk.",
                                evidence=f"GET {host_info['url']}/.git/HEAD -> 200 OK",
                                cvss_score=7.5,
                                remediation="Block access to .git/ via web server rules or move repo outside webroot.",
                            )
                            findings.append({"type": "git_exposed", "host": host})
                except Exception:
                    pass

        return findings
