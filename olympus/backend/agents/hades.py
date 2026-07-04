from datetime import datetime
from .base import BaseAgent


class Hades(BaseAgent):
    name = "hades"
    symbol = "💀"
    display_name = "HADES"
    role = "Post-Exploitation & Persistence Analysis"

    async def execute(self, target: str, context: dict = None) -> dict:
        hermes = (context or {}).get("hermes", {})
        ares = (context or {}).get("ares", {})
        hephaestus = (context or {}).get("hephaestus", {})

        await self.log("Analyzing post-exploitation landscape", "info")

        result = {
            "lateral_movement_paths": [],
            "persistence_vectors": [],
            "credential_exposure": [],
            "privilege_escalation": [],
            "impact_analysis": {},
        }

        live_hosts = hermes.get("live_hosts", [])
        port_results = ares.get("port_results", {})
        vulns = ares.get("vulnerabilities", [])
        exploitable = hephaestus.get("exploitable_targets", [])
        technologies = hermes.get("technologies", {})
        vendors = hermes.get("vendors", [])
        categories = hermes.get("subdomain_categories", {})

        # Lateral movement analysis from network topology
        await self.log("Mapping lateral movement paths from network topology", "info")
        result["lateral_movement_paths"] = self._map_lateral_movement(port_results, categories)

        # Persistence vectors from identified services
        await self.log("Identifying persistence vectors", "info")
        result["persistence_vectors"] = self._identify_persistence_vectors(port_results, technologies)

        # Credential exposure from vendor stack
        await self.log("Analyzing credential exposure risk from vendor stack", "info")
        result["credential_exposure"] = self._analyze_credential_exposure(vendors, vulns, ares.get("directories", []))

        # Privilege escalation paths
        await self.log("Mapping privilege escalation paths", "info")
        result["privilege_escalation"] = self._map_privesc_paths(port_results, vulns, technologies)

        # Impact analysis
        result["impact_analysis"] = self._calculate_impact(
            live_hosts, exploitable, result["lateral_movement_paths"], result["credential_exposure"]
        )

        # Generate findings for highest-risk post-exploit paths
        await self._generate_findings(result)

        await self.log(
            f"Post-exploitation analysis complete. "
            f"{len(result['lateral_movement_paths'])} lateral paths | "
            f"{len(result['persistence_vectors'])} persistence vectors | "
            f"Impact: {result['impact_analysis'].get('blast_radius', 'unknown')}",
            "success",
        )
        return result

    def _map_lateral_movement(self, port_results: dict, subdomain_cats: dict) -> list:
        paths = []
        smb_hosts = [h for h, ports in port_results.items() if any(p["port"] == 445 for p in ports)]
        rdp_hosts = [h for h, ports in port_results.items() if any(p["port"] == 3389 for p in ports)]
        db_hosts = [h for h, ports in port_results.items()
                    if any(p["port"] in (3306, 5432, 27017, 6379) for p in ports)]

        if smb_hosts:
            paths.append({
                "vector": "SMB Lateral Movement",
                "hosts": smb_hosts,
                "technique": "MITRE T1021.002",
                "description": "SMB-enabled hosts allow pass-the-hash and credential relay attacks.",
                "risk": "high",
            })
        if rdp_hosts:
            paths.append({
                "vector": "RDP Lateral Movement",
                "hosts": rdp_hosts,
                "technique": "MITRE T1021.001",
                "description": "RDP-accessible hosts enable direct remote interactive access post-credential compromise.",
                "risk": "high",
            })
        if db_hosts:
            paths.append({
                "vector": "Database Lateral Pivot",
                "hosts": db_hosts,
                "technique": "MITRE T1210",
                "description": "Database services may store credentials or provide shell access (xp_cmdshell, UDF).",
                "risk": "critical",
            })

        ci_cd = subdomain_cats.get("ci_cd", [])
        if ci_cd:
            paths.append({
                "vector": "CI/CD Pipeline Compromise",
                "hosts": ci_cd[:5],
                "technique": "MITRE T1195.002",
                "description": "CI/CD systems with code execution can deploy malicious builds or exfiltrate secrets.",
                "risk": "critical",
            })

        return paths

    def _identify_persistence_vectors(self, port_results: dict, technologies: dict) -> list:
        vectors = []
        all_techs = [t.lower() for tl in technologies.values() for t in tl]

        if any("wordpress" in t for t in all_techs):
            vectors.append({
                "vector": "WordPress Plugin Backdoor",
                "technique": "MITRE T1505.003",
                "description": "Malicious plugin upload or theme modification can establish persistent shell access.",
                "stealth": "medium",
            })

        ssh_hosts = [h for h, ports in port_results.items() if any(p["port"] == 22 for p in ports)]
        if ssh_hosts:
            vectors.append({
                "vector": "SSH Authorized Keys Persistence",
                "hosts": ssh_hosts,
                "technique": "MITRE T1098.004",
                "description": "Adding attacker SSH key to ~/.ssh/authorized_keys on compromised hosts.",
                "stealth": "high",
            })

        cron_candidates = [h for h, ports in port_results.items()
                           if any(p["port"] in (22, 80, 443) for p in ports)]
        if cron_candidates:
            vectors.append({
                "vector": "Cron Job / Scheduled Task",
                "technique": "MITRE T1053",
                "description": "Web shell or compromised account can plant cron jobs for persistent callback.",
                "stealth": "high",
            })

        return vectors

    def _analyze_credential_exposure(self, vendors: list, vulns: list, directories: list) -> list:
        exposure = []
        vendor_names = [v["vendor"].lower() for v in vendors]

        if any("knowbe4" in v for v in vendor_names):
            exposure.append({
                "type": "Security Awareness Training in Use",
                "note": "KnowBe4 present. Phishing simulation data may reveal click-prone users.",
                "risk": "medium",
            })

        if any("proofpoint" in v for v in vendor_names):
            exposure.append({
                "type": "Email Gateway Identified (Proofpoint)",
                "note": "Proofpoint MX bypass may be possible via misconfigured IP allowlists.",
                "risk": "medium",
            })

        for d in directories:
            url = d.get("url", "")
            if any(s in url for s in [".env", "config", "backup", "credentials", "secret"]):
                exposure.append({
                    "type": "Credential File Exposure",
                    "url": url,
                    "status": d.get("status"),
                    "risk": "critical",
                })

        for v in vulns:
            if "default-login" in v.get("template", "") or "default-creds" in v.get("template", ""):
                exposure.append({
                    "type": "Default Credentials Confirmed",
                    "url": v.get("matched_at", ""),
                    "risk": "critical",
                })

        return exposure

    def _map_privesc_paths(self, port_results: dict, vulns: list, technologies: dict) -> list:
        paths = []
        all_techs = [t.lower() for tl in technologies.values() for t in tl]

        docker_hosts = [h for h, ports in port_results.items()
                        if any(p["port"] == 2375 for p in ports)]
        if docker_hosts:
            paths.append({
                "vector": "Docker Socket Escape",
                "hosts": docker_hosts,
                "technique": "MITRE T1611",
                "description": "Unauthenticated Docker API allows container escape to host root.",
                "impact": "full_host_compromise",
            })

        redis_hosts = [h for h, ports in port_results.items()
                       if any(p["port"] == 6379 for p in ports)]
        if redis_hosts:
            paths.append({
                "vector": "Redis RCE via CONFIG SET",
                "hosts": redis_hosts,
                "technique": "MITRE T1505",
                "description": "Unauthenticated Redis allows writing SSH keys or cron via CONFIG SET.",
                "impact": "rce_root",
            })

        return paths

    def _calculate_impact(self, live_hosts: list, exploitable: list, lateral: list, cred_exposure: list) -> dict:
        score = 0
        score += len(exploitable) * 3
        score += len([l for l in lateral if l.get("risk") in ("critical", "high")]) * 2
        score += len([c for c in cred_exposure if c.get("risk") == "critical"]) * 4

        if score >= 15:
            blast = "catastrophic"
        elif score >= 8:
            blast = "severe"
        elif score >= 4:
            blast = "significant"
        elif score >= 1:
            blast = "limited"
        else:
            blast = "minimal"

        return {
            "blast_radius": blast,
            "score": score,
            "live_hosts": len(live_hosts),
            "exploitable_targets": len(exploitable),
            "lateral_movement_paths": len(lateral),
        }

    async def _generate_findings(self, result: dict):
        for path in result["lateral_movement_paths"]:
            if path["risk"] in ("critical", "high"):
                await self.add_finding(
                    title=f"Post-Exploit Path: {path['vector']}",
                    severity=path["risk"],
                    description=path["description"],
                    evidence=f"Technique: {path.get('technique', 'N/A')} | Hosts: {', '.join(path.get('hosts', [])[:5])}",
                    remediation="Segment network. Apply least-privilege. Enable endpoint detection.",
                )

        crit_creds = [c for c in result["credential_exposure"] if c.get("risk") == "critical"]
        if crit_creds:
            for c in crit_creds:
                await self.add_finding(
                    title=f"Critical Credential Exposure: {c['type']}",
                    severity="critical",
                    description=f"{c['type']} — immediate remediation required.",
                    evidence=c.get("url", "See credential exposure report"),
                    cvss_score=9.8,
                    remediation="Rotate all affected credentials. Revoke exposed secrets immediately.",
                )

        impact = result.get("impact_analysis", {})
        if impact.get("blast_radius") in ("catastrophic", "severe"):
            await self.add_finding(
                title=f"Mission Impact Assessment: {impact['blast_radius'].upper()}",
                severity="critical",
                description=f"Combined exploitation chain creates {impact['blast_radius']} blast radius. "
                            f"Estimated {impact['score']} risk score across {impact['live_hosts']} live targets.",
                evidence=f"Score: {impact['score']} | Exploitable: {impact['exploitable_targets']} | Lateral paths: {impact['lateral_movement_paths']}",
                cvss_score=10.0,
                remediation="Prioritize immediate patching of critical findings. Engage incident response team.",
            )
