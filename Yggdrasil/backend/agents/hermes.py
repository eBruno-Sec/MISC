import asyncio
import os
import re
from datetime import date, datetime
import httpx
from .base import BaseAgent
from core.security import expand_cidr

VENDOR_TXT_PATTERNS = {
    "google-site-verification": ("Google Workspace", "Productivity"),
    "MS=": ("Microsoft 365", "Email/Productivity"),
    "docusign": ("DocuSign", "eSignature"),
    "atlassian-domain-verification": ("Atlassian", "Dev Tools"),
    "stripe": ("Stripe", "Payment"),
    "sendgrid": ("SendGrid", "Email Delivery"),
    "mailchimp": ("Mailchimp", "Marketing Email"),
    "salesforce": ("Salesforce", "CRM"),
    "hubspot": ("HubSpot", "CRM/Marketing"),
    "knowbe4": ("KnowBe4", "Security Awareness Training"),
    "pphosted": ("Proofpoint", "Email Gateway"),
    "proofpoint": ("Proofpoint", "Email Gateway"),
    "mimecast": ("Mimecast", "Email Security"),
    "slack": ("Slack", "Collaboration"),
    "zoom": ("Zoom", "Conferencing"),
    "okta": ("Okta", "SSO/IdP"),
    "duosecurity": ("Duo Security", "MFA"),
    "crowdstrike": ("CrowdStrike", "EDR"),
    "datadog": ("Datadog", "Monitoring"),
    "bugcrowd": ("Bugcrowd", "Bug Bounty Program"),
    "hackerone": ("HackerOne", "Bug Bounty Program"),
    "zmverify.zoho": ("Zoho", "Productivity"),
    "valimail": ("Valimail", "DMARC Management"),
    "docker": ("Docker", "Container Platform"),
    "postman": ("Postman", "API Development"),
    "notion": ("Notion", "Productivity"),
    "github": ("GitHub", "Code Repository"),
    "paloaltonetworks": ("Palo Alto Networks", "Security"),
}

SUBDOMAIN_CATEGORIES = {
    "ci_cd": ["jenkins", "gitlab", "github", "drone", "circleci", "travis", "sonar", "nexus", "artifactory", "build", "ci", "cd", "deploy", "pipeline", "git"],
    "security_infra": ["vpn", "sso", "idp", "auth", "login", "mfa", "ldap", "ad", "activedirectory", "clearpass", "radius"],
    "admin": ["admin", "manage", "panel", "dashboard", "console", "control", "mgmt", "mgr"],
    "dev_staging": ["dev", "staging", "stage", "test", "qa", "uat", "sandbox", "preview", "beta", "alpha"],
    "payment": ["pay", "payment", "billing", "stripe", "checkout", "invoice", "finance", "tokenizer"],
    "api": ["api", "api-", "graphql", "rest", "gateway", "backend"],
}

# Curated port set for the CIDR network sweep: remote-access, file/DB, and web
# services worth surfacing on a red-team host-discovery pass. Web ports are here
# too so a host running only, say, 8080 still shows as alive.
NETWORK_SWEEP_PORTS = (
    "21,22,23,25,53,80,110,111,135,139,143,389,443,445,993,995,"
    "1433,1521,2049,2375,3306,3389,5432,5900,5985,6379,8000,8080,8443,9200,11211,27017"
)

# Non-web services that matter on a network sweep. severity=info means "reachable,
# worth noting" (e.g. SSH); higher severities are genuine exposure risk. Web ports
# (80/443/8080/8443/8000) are intentionally absent — those flow through the normal
# web pipeline (httpx liveness -> TYR), so we don't double-report them here.
NETWORK_SERVICE_RISK = {
    21: ("FTP", "medium", 5.3, "FTP transmits credentials and data in plaintext."),
    22: ("SSH", "info", 0.0, "SSH remote administration is reachable on this host."),
    23: ("Telnet", "high", 7.5, "Telnet is unencrypted remote access; credentials are exposed."),
    25: ("SMTP", "info", 0.0, "SMTP service reachable; check for open relay / user enumeration."),
    111: ("rpcbind", "low", 3.7, "ONC RPC portmapper reachable; can enumerate RPC services (NFS, etc.)."),
    135: ("MSRPC", "medium", 5.0, "Windows RPC endpoint mapper exposed."),
    139: ("NetBIOS", "medium", 5.3, "NetBIOS session service exposed."),
    389: ("LDAP", "medium", 5.3, "LDAP directory service reachable; may permit anonymous bind."),
    445: ("SMB", "high", 8.1, "SMB exposed — EternalBlue / ransomware / null-session surface."),
    1433: ("MSSQL", "high", 7.5, "Microsoft SQL Server port publicly accessible."),
    1521: ("Oracle DB", "high", 7.5, "Oracle database listener publicly accessible."),
    2049: ("NFS", "medium", 5.3, "NFS export service reachable; may allow unauthenticated mounts."),
    2375: ("Docker API", "critical", 10.0, "Unauthenticated Docker daemon API — full host compromise."),
    3306: ("MySQL", "high", 7.5, "MySQL/MariaDB port publicly accessible."),
    3389: ("RDP", "critical", 9.8, "RDP publicly exposed — brute-force / BlueKeep risk."),
    5432: ("PostgreSQL", "high", 7.5, "PostgreSQL port publicly accessible."),
    5900: ("VNC", "high", 8.1, "VNC remote desktop exposed; often weak/no authentication."),
    5985: ("WinRM", "medium", 5.9, "Windows Remote Management (WinRM) exposed."),
    6379: ("Redis", "critical", 9.8, "Redis exposed — often unauthenticated, full data access."),
    9200: ("Elasticsearch", "high", 8.1, "Elasticsearch port accessible; often unauthenticated."),
    11211: ("Memcached", "medium", 5.3, "Memcached exposed; UDP amplification / data leakage risk."),
    27017: ("MongoDB", "critical", 9.8, "MongoDB port accessible; often unauthenticated."),
}


def parse_nmap_greppable(stdout: str) -> dict:
    """Parse nmap -oG output into {ip: {"status": "up", "ports": [ {port, proto,
    service, version} ]}}. Pure (no I/O) so it can be unit-tested without nmap.

    A host appears if nmap marked it Up (Status line) OR reported any open port.
    Only open ports are kept."""
    hosts: dict = {}
    for line in (stdout or "").splitlines():
        if not line.startswith("Host:"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip = parts[1]
        entry = hosts.setdefault(ip, {"status": "unknown", "ports": []})
        if "Status: Up" in line:
            entry["status"] = "up"
        elif "Status: Down" in line and entry["status"] == "unknown":
            entry["status"] = "down"
        if "Ports:" in line:
            port_section = line.split("Ports:", 1)[1].split("Ignored State:")[0].strip()
            for port_info in port_section.split(","):
                fields = port_info.strip().split("/")
                if len(fields) >= 7 and fields[1] == "open" and fields[0].isdigit():
                    entry["status"] = "up"
                    entry["ports"].append({
                        "port": int(fields[0]),
                        "proto": fields[2],
                        "service": fields[4] or "unknown",
                        "version": fields[6],
                    })
    return hosts


class Hermes(BaseAgent):
    name = "hermes"
    symbol = "HE"
    display_name = "HEIMDALL"
    role = "Recon"

    def _extract_domain(self, target: str) -> str:
        target = re.sub(r"^https?://", "", target)
        target = target.split("/")[0].split(":")[0]
        return target.lower().strip()

    def _extract_host_port(self, target: str):
        """Return (host, port|None) preserving an explicit :port."""
        t = re.sub(r"^https?://", "", target).split("/")[0]
        if ":" in t and t.count(":") == 1:
            host, _, port = t.rpartition(":")
            if port.isdigit():
                return host.lower().strip(), int(port)
        return t.lower().strip(), None


    def _apply_scope(self, hosts: list, scope_rules: dict) -> list:
        """Filter a list of hostnames/dicts against scope_rules."""
        in_rules = scope_rules.get("in_scope", [])
        out_rules = scope_rules.get("out_of_scope", [])
        if not in_rules and not out_rules:
            return hosts

        def matches(host: str, rules: list) -> bool:
            h = host.lower().lstrip("*.")
            for rule in rules:
                rid = rule.get("identifier", "").lower().lstrip("*.")
                rtype = rule.get("type", "")
                if not rid:
                    continue
                if rtype in ("url",):
                    rid = rid.split("//", 1)[-1].split("/")[0]
                if h == rid or h.endswith("." + rid) or rid.endswith("." + h):
                    return True
            return False

        result = []
        for host in hosts:
            h = host if isinstance(host, str) else host.get("host", "")
            if out_rules and matches(h, out_rules):
                continue
            if in_rules and not matches(h, in_rules):
                continue
            result.append(host)
        return result

    async def execute(self, target: str, context: dict = None) -> dict:
        domain = self._extract_domain(target)
        _host, _port = self._extract_host_port(target)
        try:
            cidr_cap = max(1, int(os.getenv("YGGDRASIL_CIDR_MAX_HOSTS") or os.getenv("OLYMPUS_CIDR_MAX_HOSTS") or "1024"))
        except ValueError:
            cidr_cap = 1024
        cidr_hosts = expand_cidr(target, cap=cidr_cap)
        if cidr_hosts:
            await self.log(
                f"CIDR target {target}: sweeping {len(cidr_hosts)} host(s) for live web services "
                f"(cap {cidr_cap}; raise YGGDRASIL_CIDR_MAX_HOSTS for bigger ranges)", "info")
        else:
            await self.log(f"Passive recon initiated on {domain}", "info")

        result = {
            "target": target,
            "domain": domain,
            "subdomains": [],
            "live_hosts": [],
            "dns_records": {},
            "whois": {},
            "technologies": {},
            "vendors": [],
            "subdomain_categories": {},
            "network_hosts": [],
        }

        scope_rules = (context or {}).get("scope_rules", {})
        subs = []

        if cidr_hosts:
            # Network sweep: no subdomain / DNS / WHOIS recon makes sense for an IP range.
            all_hosts = cidr_hosts
        else:
            await self.log("WHOIS / RDAP lookup", "info")
            result["whois"] = await self._rdap(domain)

            await self.log("Subdomain enumeration: crt.sh + subfinder (OSINT) + DNS brute", "info")
            ct_subs = await self._cert_transparency(domain)
            osint_subs = await self._subfinder(domain)
            brute_subs = await self._dns_bruteforce(domain)
            subs = sorted(set(ct_subs) | set(osint_subs) | set(brute_subs))
            result["subdomains"] = subs
            await self.log(
                f"{len(subs)} unique subdomains "
                f"(crt.sh {len(ct_subs)}, subfinder {len(osint_subs)}, brute {len(brute_subs)})",
                "success" if subs else "warn",
            )

            # Apply scope rules if provided
            if scope_rules and (scope_rules.get("in_scope") or scope_rules.get("out_of_scope")):
                filtered = self._apply_scope(subs, scope_rules)
                removed = len(subs) - len(filtered)
                if removed:
                    await self.log(f"Scope filter: removed {removed} out-of-scope subdomains", "info")
                subs = filtered
                result["subdomains"] = subs

            if subs:
                result["subdomain_categories"] = self._categorize_subdomains(subs)
                await self._flag_sensitive_subdomains(domain, result["subdomain_categories"])

            await self.log("DNS record enumeration (A, MX, TXT, NS, SOA)", "info")
            result["dns_records"] = await self._dns_enum(domain)

            all_hosts = list(dict.fromkeys(subs + [domain]))
        if all_hosts:
            await self.log(f"Probing {len(all_hosts)} hosts for liveness", "info")
            if cidr_hosts:
                # Sweep the whole range (no [:150] cap — the operator asked for it).
                live = await self._httpx_probe(all_hosts)
                if not live:
                    live = await self._live_detection(all_hosts)
            elif _port:
                # Preserve the explicit host:port probe path (e.g. local Juice Shop).
                live = await self._live_detection(all_hosts[:150], explicit_port=_port)
            else:
                live = await self._httpx_probe(all_hosts[:2000])
                if not live:
                    live = await self._live_detection(all_hosts[:150])

            # Explicit host:port target: always scan exactly that URL, even if the
            # liveness probe could not confirm it. Pointing Yggdrasil at host:port must
            # test host:port on the right scheme — never silently drop the port and
            # fall back to https://host, which is how a live app reads as "0 hosts".
            if _port and not cidr_hosts:
                netloc = f"{_host}:{_port}"
                if not any(h.get("host") == netloc for h in live):
                    scheme = "https" if _port in (443, 8443) else "http"
                    live.insert(0, {
                        "host": netloc, "url": f"{scheme}://{netloc}",
                        "status_code": None, "server": "", "unverified": True,
                    })
                    await self.log(
                        f"⚠ Liveness unconfirmed for {netloc} — scanning it anyway over "
                        f"{scheme}. If the report stays empty the scanner container cannot "
                        f"reach it (app bound to localhost? different Docker network?).", "warn")

            if scope_rules and (scope_rules.get("in_scope") or scope_rules.get("out_of_scope")):
                live = self._apply_scope(live, scope_rules)
            result["live_hosts"] = live
            if result["live_hosts"]:
                await self.log(f"{len(result['live_hosts'])} live hosts confirmed", "success")
            elif cidr_hosts:
                await self.log(
                    f"No live web hosts found across {target} ({len(all_hosts)} IPs swept). "
                    "The range may have no HTTP/S services, or they are firewalled.", "warn")
            else:
                await self.log(
                    "⚠ 0 live hosts confirmed — target appears unreachable from the scanner "
                    "container. The report will be near-empty; this is a connectivity problem, "
                    "not a clean target.", "warn")

        if result["live_hosts"]:
            await self.log("Technology fingerprinting on live hosts", "info")
            result["technologies"] = await self._fingerprint(result["live_hosts"])
            await self._check_takeovers([h.get("host", "") for h in result["live_hosts"]])

        # Network sweep: for a CIDR range, the web-liveness probe above only sees
        # HTTP/S hosts. Run an nmap host-discovery + light service scan so boxes that
        # expose only SSH/RDP/SMB/a database (no web server) are still found + reported.
        if cidr_hosts:
            result["network_hosts"] = await self._nmap_network_sweep(
                cidr_hosts, target, web_live=result["live_hosts"]
            )

        result["vendors"] = self._extract_vendors(result["dns_records"].get("TXT", []))
        if result["vendors"]:
            await self.log(f"Vendor stack identified: {', '.join(v['vendor'] for v in result['vendors'][:5])}", "info")

        await self.log(f"Recon complete. {len(result['live_hosts'])} live | {len(result['subdomains'])} subdomains | {len(result['vendors'])} vendors", "success")
        return result

    async def _rdap(self, domain: str) -> dict:
        data = {}
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
                r = await client.get(f"https://rdap.org/domain/{domain}", headers={"Accept": "application/json"})
                if r.status_code == 200:
                    raw = r.json()
                    for event in raw.get("events", []):
                        action = event.get("eventAction", "")
                        dt = event.get("eventDate", "")[:10] if event.get("eventDate") else None
                        if action == "registration":
                            data["created"] = dt
                        elif action == "expiration":
                            data["expires"] = dt
                        elif action == "last changed":
                            data["updated"] = dt
                    data["nameservers"] = [ns.get("ldhName", "").lower() for ns in raw.get("nameservers", [])]
                    data["status"] = raw.get("status", [])
                    for entity in raw.get("entities", []):
                        if "registrar" in entity.get("roles", []):
                            vc = entity.get("vcardArray", [[], []])[1]
                            for prop in vc:
                                if prop[0] == "fn":
                                    data["registrar"] = prop[3]
                                    break

                    if data.get("expires"):
                        try:
                            exp = datetime.strptime(data["expires"], "%Y-%m-%d").date()
                            days = (exp - date.today()).days
                            if days < 30:
                                await self.add_finding(
                                    title=f"Domain Expiring in {days} Days",
                                    severity="high",
                                    description=f"{domain} expires {data['expires']}. Risk of domain hijacking.",
                                    evidence=f"RDAP expiry: {data['expires']}",
                                    cvss_score=7.5,
                                    remediation="Renew domain immediately.",
                                )
                            elif days < 90:
                                await self.add_finding(
                                    title=f"Domain Expiring in {days} Days",
                                    severity="medium",
                                    description=f"{domain} expires {data['expires']}.",
                                    evidence=f"RDAP expiry: {data['expires']}",
                                    remediation="Schedule domain renewal.",
                                )
                        except ValueError:
                            pass
        except Exception as e:
            await self.log(f"RDAP failed: {e}. Falling back to whois.", "warn")
            stdout, _, rc = await self.run_command(["whois", domain], timeout=20)
            if rc == 0:
                data["raw"] = stdout[:3000]
        return data

    async def _cert_transparency(self, domain: str) -> list:
        subs = set()
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    headers={"User-Agent": "YGGDRASIL-Hermes/1.0"},
                )
                if r.status_code == 200:
                    for entry in r.json():
                        for name in entry.get("name_value", "").split("\n"):
                            name = name.strip().lower().lstrip("*.")
                            if name.endswith(f".{domain}") and "*" not in name and len(name) < 253:
                                subs.add(name)
        except Exception as e:
            await self.log(f"crt.sh query failed: {e}", "warn")
        return sorted(list(subs))

    async def _subfinder(self, domain: str) -> list:
        """Multi-source passive subdomain enumeration (30+ OSINT sources)."""
        stdout, _, rc = await self.run_command(
            ["subfinder", "-d", domain, "-silent", "-all"], timeout=180
        )
        if rc == 127:
            await self.log("subfinder not installed; OSINT enum skipped", "warn")
            return []
        subs = set()
        for line in stdout.splitlines():
            s = line.strip().lower().lstrip("*.")
            if s and "*" not in s and len(s) < 253 and (s == domain or s.endswith(f".{domain}")):
                subs.add(s)
        if subs:
            await self.log(f"subfinder: {len(subs)} subdomains from OSINT sources", "info")
        return sorted(subs)

    async def _dns_bruteforce(self, domain: str, cap: int = 1500) -> list:
        """Resolve a capped slice of the DNS wordlist to surface hosts no OSINT
        source knows about. Wildcard-DNS aware so it does not flood false hits."""
        import secrets as _secrets

        wl = "/opt/wordlists/subdomains-top20000.txt"
        if not os.path.exists(wl):
            return []
        try:
            with open(wl, "r", errors="replace") as f:
                words = [w.strip() for w in f if w.strip() and not w.startswith("#")][:cap]
        except OSError:
            return []
        if not words:
            return []

        loop = asyncio.get_running_loop()
        # Wildcard guard: if a random label resolves, only accept hits that
        # resolve to a different address than the wildcard.
        wildcard_ips = set()
        try:
            res = await loop.getaddrinfo(f"{_secrets.token_hex(6)}.{domain}", None)
            wildcard_ips = {r[4][0] for r in res}
        except Exception:
            pass

        sem = asyncio.Semaphore(100)

        async def resolve(w):
            host = f"{w}.{domain}"
            async with sem:
                try:
                    res = await loop.getaddrinfo(host, None)
                except Exception:
                    return None
            ips = {r[4][0] for r in res}
            return host if ips and not ips.issubset(wildcard_ips) else None

        results = await asyncio.gather(*[resolve(w) for w in words], return_exceptions=True)
        found = [r for r in results if isinstance(r, str)]
        if found:
            await self.log(f"DNS brute: {len(found)} resolvable subdomains from {len(words)} candidates", "info")
        return found

    async def _httpx_probe(self, hosts: list) -> list:
        """Liveness + fingerprint via the httpx binary: status, title, tech, CDN."""
        import json as _json
        import tempfile

        if not hosts:
            return []
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("\n".join(hosts))
            tmp = f.name
        live = []
        try:
            stdout, _, rc = await self.run_command(
                ["httpx", "-l", tmp, "-json", "-silent", "-follow-redirects",
                 "-title", "-tech-detect", "-cdn", "-server", "-tls-grab", "-jarm", "-ip",
                 "-timeout", "8", "-rl", "150", "-nc"],
                timeout=300,
            )
            if rc == 127:
                await self.log("httpx binary not available; using library probe", "warn")
                return []
            for line in stdout.splitlines():
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    j = _json.loads(line)
                except Exception:
                    continue
                host = re.sub(r"^https?://", "", (j.get("input") or j.get("host") or "")).split("/")[0]
                if not host:
                    continue
                live.append({
                    "host": host,
                    "url": j.get("url") or f"https://{host}",
                    "status_code": j.get("status_code"),
                    "server": j.get("webserver", ""),
                    "x_powered_by": "",
                    "content_length": j.get("content_length", 0),
                    "final_url": j.get("url") or "",
                    "title": j.get("title", ""),
                    "tech": j.get("tech", []) or [],
                    "cdn": j.get("cdn_name", ""),
                    "headers": {},
                })
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        if live:
            await self.log(f"httpx: {len(live)} live hosts fingerprinted", "info")
        return live

    async def _nmap_network_sweep(self, hosts: list, target: str, web_live: list = None) -> list:
        """nmap host discovery + curated service scan across a CIDR's IPs. Surfaces
        non-web hosts (SSH/RDP/SMB/DB) the web-liveness probe never sees, and flags
        exposed remote-access / database services. Returns an inventory list of
        {ip, status, ports:[...]}. Service findings for web-host IPs are left to TYR
        (which deep-scans them) to avoid double-reporting; the inventory lists them."""
        # Arg-safety: IPs from expand_cidr never start with '-', but filter anyway so
        # nothing can be parsed as an nmap flag.
        host_args = [h for h in dict.fromkeys(hosts) if h and not h.startswith("-")]
        if not host_args:
            return []

        await self.log(
            f"Network sweep: nmap host discovery + service scan across {len(host_args)} IP(s) "
            f"in {target} (finds SSH/RDP/SMB/DB, not just web)", "info")

        # -sT (TCP connect) needs no root; -sV --version-light grabs service banners;
        # default host discovery still marks a host Up even with no open port in our
        # set; --host-timeout stops a firewalled host from stalling the whole sweep.
        stdout, stderr, rc = await self.run_command(
            ["nmap", "-sT", "-sV", "--version-light", "-T4", "-n", "--open",
             "--host-timeout", "60s", "-oG", "-", "-p", NETWORK_SWEEP_PORTS] + host_args,
            timeout=900,
        )
        if rc == 127:
            await self.log(
                "nmap not available; network sweep skipped (web hosts already covered)", "warn")
            return []
        if not stdout:
            await self.log(f"Network sweep produced no output ({stderr[:160]})", "warn")
            return []

        parsed = parse_nmap_greppable(stdout)
        inventory = [
            {"ip": ip, "status": "up", "ports": sorted(d.get("ports", []), key=lambda p: p["port"])}
            for ip, d in sorted(parsed.items()) if d.get("status") == "up"
        ]
        if not inventory:
            await self.log("Network sweep: no additional live hosts found", "info")
            return []

        with_ports = sum(1 for h in inventory if h["ports"])
        await self.log(
            f"Network sweep: {len(inventory)} live host(s), {with_ports} exposing scanned services",
            "success")
        await self._report_network_services(inventory, target, web_live or [])
        return inventory

    async def _report_network_services(self, inventory: list, target: str, web_live: list) -> None:
        """Emit grouped findings for exposed non-web services + one inventory summary.
        Web-host IPs are excluded from the service findings (TYR reports those); the
        inventory summary still lists every discovered host for completeness."""
        web_ips = {(h.get("host", "") or "").split(":")[0] for h in web_live}

        # Group risky services across non-web hosts: one finding per service type, not
        # one per host — a /24 sweep must not spawn hundreds of near-identical findings.
        by_service: dict = {}   # port -> list[ip]
        for host in inventory:
            if host["ip"] in web_ips:
                continue
            for p in host["ports"]:
                if p["port"] in NETWORK_SERVICE_RISK:
                    by_service.setdefault(p["port"], []).append(host["ip"])

        for port in sorted(by_service):
            ips = by_service[port]
            name, sev, cvss, desc = NETWORK_SERVICE_RISK[port]
            verb = "Reachable" if sev == "info" else "Exposed"
            await self.add_finding(
                title=f"{name} {verb} on {len(ips)} host(s) ({target})",
                severity=sev,
                description=f"{desc} Found on port {port}/tcp during the network sweep.",
                evidence=", ".join(f"{ip}:{port}" for ip in ips[:25]),
                cvss_score=cvss if cvss else None,
                remediation=(
                    f"Confirm {name} exposure is intended; restrict port {port} to trusted "
                    "management networks / VPN and require authentication."),
            )

        # Inventory summary so every discovered host lands in the report even if its
        # services aren't individually risk-flagged (never hide recon results).
        lines = []
        for host in inventory:
            if host["ports"]:
                svc = ", ".join(f"{p['port']}/{p['service']}" for p in host["ports"][:12])
            else:
                svc = "up (no scanned service ports open)"
            lines.append(f"{host['ip']}: {svc}")
        await self.add_finding(
            title=f"Network Sweep Inventory — {len(inventory)} live host(s) in {target}",
            severity="info",
            description=(
                f"nmap host discovery across {target} found {len(inventory)} live host(s). "
                "This is the network-layer attack surface; web hosts are also assessed by TYR."),
            evidence="\n".join(lines[:100]),
            remediation="Review each exposed service; decommission or firewall anything not required.",
        )

    async def _check_takeovers(self, hosts: list) -> None:
        """Flag dangling subdomains (CNAME to an unclaimed service) via nuclei."""
        import json as _json
        import tempfile

        hosts = [h for h in hosts if h][:200]
        if not hosts:
            return
        await self.log(f"Checking {len(hosts)} hosts for subdomain takeover", "info")
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("\n".join(hosts))
            tmp = f.name
        count = 0
        try:
            stdout, _, rc = await self.run_command(
                ["nuclei", "-l", tmp, "-tags", "takeover", "-jsonl", "-silent",
                 "-timeout", "10", "-rl", "50", "-nc"],
                timeout=240,
            )
            if rc == 127:
                await self.log("nuclei not available; takeover check skipped", "warn")
                return
            for line in stdout.splitlines():
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    j = _json.loads(line)
                except Exception:
                    continue
                info = j.get("info", {})
                matched = j.get("matched-at") or j.get("host", "")
                count += 1
                await self.add_finding(
                    title=f"Subdomain Takeover: {matched}",
                    severity="high",
                    description=(info.get("description")
                                 or "A subdomain points via CNAME to an unclaimed third-party service. "
                                    "An attacker can register that resource and serve content under your domain."),
                    evidence=f"Host: {matched}\nTemplate: {j.get('template-id', '')}",
                    cvss_score=8.1,
                    remediation="Remove the dangling DNS record or reclaim the third-party resource it points to.",
                )
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        await self.log(f"Takeover check complete: {count} finding(s)", "success" if count else "info")

    async def _dns_enum(self, domain: str) -> dict:
        records = {}
        for rtype in ["A", "AAAA", "MX", "TXT", "NS", "SOA"]:
            stdout, _, rc = await self.run_command(
                ["dig", "+noall", "+answer", "+short", domain, rtype], timeout=15
            )
            if rc == 0 and stdout.strip():
                records[rtype] = [l.strip() for l in stdout.strip().splitlines() if l.strip()]

        # DMARC
        stdout, _, _ = await self.run_command(
            ["dig", "+noall", "+answer", "+short", f"_dmarc.{domain}", "TXT"], timeout=10
        )
        if stdout.strip():
            records["DMARC"] = [stdout.strip()]
            await self._analyze_dmarc(domain, stdout.strip())
        else:
            records["DMARC"] = []
            await self.add_finding(
                title="DMARC Record Missing",
                severity="medium",
                description=f"No DMARC record found for {domain}. Domain susceptible to email spoofing.",
                evidence="dig _dmarc returned no results",
                cvss_score=5.3,
                remediation="Add: _dmarc.domain TXT v=DMARC1; p=reject; rua=mailto:dmarc@domain.com",
            )

        # SPF analysis
        txt_records = records.get("TXT", [])
        spf = [r for r in txt_records if "v=spf1" in r.lower()]
        if not spf:
            await self.add_finding(
                title="SPF Record Missing",
                severity="medium",
                description=f"No SPF record on {domain}. Risk of email spoofing.",
                evidence="No TXT record containing v=spf1",
                cvss_score=5.3,
                remediation="Add SPF: v=spf1 include:authorized-senders -all",
            )
        elif any("~all" in s for s in spf):
            await self.add_finding(
                title="SPF SoftFail (~all) Configured",
                severity="low",
                description="SPF softfail allows unauthorized senders to pass spam filters.",
                evidence=spf[0][:300],
                cvss_score=3.7,
                remediation="Replace ~all with -all for strict enforcement.",
            )

        return records

    async def _analyze_dmarc(self, domain: str, raw: str):
        if "p=none" in raw:
            await self.add_finding(
                title="DMARC Monitor-Only (p=none)",
                severity="high",
                description=f"DMARC p=none on {domain}: unauthorized emails are NOT blocked. Domain is spoofable.",
                evidence=raw[:300],
                cvss_score=7.5,
                remediation="Escalate to p=quarantine then p=reject.",
            )
        elif "p=quarantine" in raw:
            await self.add_finding(
                title="DMARC Partial Enforcement (p=quarantine)",
                severity="low",
                description="DMARC quarantine moves unauthorized mail to spam but doesn't block it.",
                evidence=raw[:300],
                cvss_score=3.1,
                remediation="Escalate DMARC to p=reject.",
            )
        pct_match = re.search(r"pct=(\d+)", raw)
        if pct_match and int(pct_match.group(1)) < 100:
            await self.add_finding(
                title=f"DMARC Partial Coverage (pct={pct_match.group(1)}%)",
                severity="low",
                description=f"Only {pct_match.group(1)}% of mail is subject to DMARC policy.",
                evidence=raw[:300],
                remediation="Set pct=100 for full enforcement.",
            )

    def _categorize_subdomains(self, subs: list) -> dict:
        cats = {k: [] for k in SUBDOMAIN_CATEGORIES}
        cats["other"] = []
        for sub in subs:
            sub_lower = sub.lower()
            matched = False
            for cat, keywords in SUBDOMAIN_CATEGORIES.items():
                if any(kw in sub_lower for kw in keywords):
                    cats[cat].append(sub)
                    matched = True
                    break
            if not matched:
                cats["other"].append(sub)
        return {k: v for k, v in cats.items() if v}

    async def _flag_sensitive_subdomains(self, domain: str, categories: dict):
        if categories.get("ci_cd"):
            await self.add_finding(
                title=f"CI/CD Infrastructure Exposed ({len(categories['ci_cd'])} subdomains)",
                severity="high",
                description="CI/CD pipeline subdomains are publicly enumerable via certificate transparency logs.",
                evidence=", ".join(categories["ci_cd"][:10]),
                cvss_score=7.5,
                remediation="Restrict CI/CD access to private networks. Review CT log exposure.",
            )
        if categories.get("admin"):
            await self.add_finding(
                title=f"Admin Panels Enumerated ({len(categories['admin'])} subdomains)",
                severity="medium",
                description="Administrative interface subdomains discovered via CT logs.",
                evidence=", ".join(categories["admin"][:10]),
                cvss_score=5.3,
                remediation="Ensure admin panels require VPN/MFA. Review public accessibility.",
            )
        if categories.get("dev_staging"):
            await self.add_finding(
                title=f"Dev/Staging Environments Exposed ({len(categories['dev_staging'])} subdomains)",
                severity="medium",
                description="Development and staging environments are publicly enumerable.",
                evidence=", ".join(categories["dev_staging"][:10]),
                cvss_score=5.3,
                remediation="Move dev/staging behind authentication or private networks.",
            )
        if categories.get("payment"):
            await self.add_finding(
                title=f"Payment Infrastructure Enumerated ({len(categories['payment'])} subdomains)",
                severity="high",
                description="Payment-related subdomains found via CT logs. PCI DSS surface exposed.",
                evidence=", ".join(categories["payment"][:10]),
                cvss_score=8.1,
                remediation="Scope PCI DSS cardholder data environment. Review CT log exposure.",
            )

    async def _live_detection(self, hosts: list, explicit_port: int = None) -> list:
        live = []

        async def probe(host: str):
            # If the user gave an explicit port, hit exactly that with both schemes.
            targets = []
            if explicit_port:
                targets = [
                    ("http", f"{host}:{explicit_port}"),
                    ("https", f"{host}:{explicit_port}"),
                ]
            else:
                targets = [("https", host), ("http", host)]
            for scheme, netloc in targets:
                try:
                    async with httpx.AsyncClient(timeout=7, follow_redirects=True, verify=False) as c:
                        r = await c.get(f"{scheme}://{netloc}")
                        return {
                            "host": host if not explicit_port else f"{host}:{explicit_port}",
                            "url": f"{scheme}://{netloc}",
                            "status_code": r.status_code,
                            "server": r.headers.get("server", ""),
                            "x_powered_by": r.headers.get("x-powered-by", ""),
                            "content_length": len(r.content),
                            "final_url": str(r.url),
                            "headers": dict(r.headers),
                        }
                except Exception:
                    continue
            return None

        for i in range(0, len(hosts), 25):
            batch = hosts[i : i + 25]
            results = await asyncio.gather(*[probe(h) for h in batch], return_exceptions=True)
            for r in results:
                if isinstance(r, dict) and r:
                    live.append(r)
            await asyncio.sleep(0.3)

        return live

    def _extract_vendors(self, txt_records: list) -> list:
        found = {}
        for record in txt_records:
            low = record.lower()
            for pattern, (vendor, category) in VENDOR_TXT_PATTERNS.items():
                if pattern.lower() in low and vendor not in found:
                    found[vendor] = {"vendor": vendor, "category": category, "evidence": record[:100]}
        return list(found.values())

    async def _fingerprint(self, live_hosts: list) -> dict:
        tech_map = {}
        for h in live_hosts:
            techs = list(h.get("tech", []) or [])  # from httpx tech-detect
            if h.get("server"):
                techs.append(h["server"])
            if h.get("x_powered_by"):
                techs.append(h["x_powered_by"])
            headers = h.get("headers", {})
            if headers.get("x-drupal-cache"):
                techs.append("Drupal CMS")
            if headers.get("x-shopify-shop-id"):
                techs.append("Shopify")
            if headers.get("x-wordpress") or headers.get("x-wc-webhook-source"):
                techs.append("WordPress")
            if techs:
                tech_map[h["host"]] = techs
        return tech_map
