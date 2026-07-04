import asyncio
import re
from datetime import date, datetime
import httpx
from .base import BaseAgent

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


class Hermes(BaseAgent):
    name = "hermes"
    symbol = "☿"
    display_name = "HERMES"
    role = "OSINT / Passive Recon"

    def _extract_domain(self, target: str) -> str:
        target = re.sub(r"^https?://", "", target)
        target = target.split("/")[0].split(":")[0]
        return target.lower().strip()

    async def execute(self, target: str, context: dict = None) -> dict:
        domain = self._extract_domain(target)
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
        }

        await self.log("WHOIS / RDAP lookup", "info")
        result["whois"] = await self._rdap(domain)

        await self.log("Certificate transparency enumeration via crt.sh", "info")
        subs = await self._cert_transparency(domain)
        result["subdomains"] = subs
        await self.log(f"{len(subs)} unique subdomains discovered via CT logs", "success" if subs else "warn")

        if subs:
            result["subdomain_categories"] = self._categorize_subdomains(subs)
            await self._flag_sensitive_subdomains(domain, result["subdomain_categories"])

        await self.log("DNS record enumeration (A, MX, TXT, NS, SOA)", "info")
        result["dns_records"] = await self._dns_enum(domain)

        all_hosts = list(set(subs + [domain]))
        if all_hosts:
            await self.log(f"Probing {len(all_hosts)} hosts for liveness", "info")
            result["live_hosts"] = await self._live_detection(all_hosts[:150])
            await self.log(f"{len(result['live_hosts'])} live hosts confirmed", "success")

        if result["live_hosts"]:
            await self.log("Technology fingerprinting on live hosts", "info")
            result["technologies"] = await self._fingerprint(result["live_hosts"])

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
                    headers={"User-Agent": "OLYMPUS-Hermes/1.0"},
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

    async def _live_detection(self, hosts: list) -> list:
        live = []

        async def probe(host: str):
            for scheme in ("https", "http"):
                try:
                    async with httpx.AsyncClient(timeout=7, follow_redirects=True, verify=False) as c:
                        r = await c.get(f"{scheme}://{host}")
                        return {
                            "host": host,
                            "url": f"{scheme}://{host}",
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
            techs = []
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
