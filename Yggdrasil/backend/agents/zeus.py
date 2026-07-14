import os
from core.timeutil import utcnow
from sqlalchemy import update
from core.models import Mission, MissionStatus
from .base import BaseAgent


class Zeus(BaseAgent):
    name = "zeus"
    symbol = "OD"
    display_name = "ODIN"
    role = "Orchestration"

    def _spawn(self, AgentClass):
        return AgentClass(
            session=self.session,
            mission_id=self.mission_id,
            ws_manager=self.ws_manager,
            approval_gates=self.approval_gates,
            approval_results=self.approval_results,
        )

    async def _set_phase(self, status: str, phase: str = None):
        values = {"status": status}
        if phase:
            values["current_phase"] = phase
            self.current_phase_label = phase   # read by the mission heartbeat
        if status in (MissionStatus.COMPLETE, MissionStatus.FAILED):
            values["completed_at"] = utcnow()
        await self.session.execute(
            update(Mission).where(Mission.id == self.mission_id).values(**values)
        )
        await self.session.commit()

        if self.ws_manager:
            await self.ws_manager.broadcast(self.mission_id, {
                "type": "status_change",
                "status": status,
                "phase": phase,
                "timestamp": utcnow().isoformat(),
            })

    async def execute(self, target: str, context: dict = None) -> dict:
        mode = (context or {}).get("mode", "passive")
        scope = (context or {}).get("scope", "")
        scope_rules = (context or {}).get("scope_rules", {})
        ctx = {"scope_rules": scope_rules}

        await self._set_phase(MissionStatus.PLANNING, "zeus")
        from core.brand import RELEASE
        await self.log(f"⚡ YGGDRASIL ONLINE [{RELEASE}] — Target: {target} | Mode: {mode.upper()}", "info")

        # Scanner health check: confirm the tools this mission depends on are
        # actually present before running it, and remember the result so SAGA can
        # render a "Coverage Limitations" section instead of a silent gap.
        try:
            from core.tooling import check_all_tools, format_warnings
            tool_status = await check_all_tools()
            ctx["tooling"] = tool_status
            warnings = format_warnings(tool_status)
            if warnings:
                await self.log(
                    f"Scanner coverage warning: {len(warnings)} tool(s) unavailable "
                    f"({', '.join(sorted(n for n, i in tool_status.items() if not i.get('available')))})",
                    "warn")
            else:
                await self.log("Scanner health check: all tools available", "info")
        except Exception as e:
            await self.log(f"Scanner health check failed to run: {e}", "warn")
            ctx["tooling"] = {}

        sequences = {
            "passive": "FRIGG → HEIMDALL → MIMIR → SAGA",
            "active": "FRIGG → HEIMDALL → [GATE] → TYR → MIMIR → SAGA",
            "full": "FRIGG → HEIMDALL → [GATE] → TYR → MIMIR → [GATE] → BROKKR → [GATE] → SKULD → SAGA",
        }
        await self.log(f"Sequence: {sequences.get(mode, sequences['passive'])}", "info")

        # FRIGG
        from .athena import Athena
        await self._set_phase(MissionStatus.PLANNING, "athena")
        athena = self._spawn(Athena)
        ctx["athena"] = await athena.execute(target, {"mode": mode, "scope": scope})

        # If the operator wrote free-text scope notes but uploaded no structured
        # scope rules, enforce the validated rules FRIGG derived from those notes.
        # Structured rules (from a scope file) always win and are never overridden.
        if not (scope_rules.get("in_scope") or scope_rules.get("out_of_scope")):
            ai_rules = (ctx.get("athena") or {}).get("scope_rules") or {}
            if ai_rules.get("in_scope") or ai_rules.get("out_of_scope"):
                ctx["scope_rules"] = ai_rules
                await self.log(
                    f"Enforcing AI-derived scope from notes: "
                    f"{len(ai_rules.get('in_scope', []))} in / {len(ai_rules.get('out_of_scope', []))} out",
                    "info",
                )

        # Move extracted credentials to a transient key so TYR can authenticate.
        # Kept out of ctx["athena"] and never persisted; passwords are not logged.
        creds = (ctx.get("athena") or {}).pop("_credentials", None)
        if creds:
            ctx["_credentials"] = creds

        # HEIMDALL
        from .hermes import Hermes
        await self._set_phase(MissionStatus.RECON, "hermes")
        hermes = self._spawn(Hermes)
        ctx["hermes"] = await hermes.execute(target, ctx)

        if mode == "passive":
            return await self._finalize(target, ctx)

        # APPROVAL GATE: TYR
        await self.log("Requesting authorization for active scanning phase", "warn")
        live = ctx["hermes"].get("live_hosts", [])
        host_preview = ", ".join(h["host"] for h in live[:5])
        more = f" (+{len(live)-5} more)" if len(live) > 5 else ""
        try:
            max_hosts = max(1, int(os.getenv("YGGDRASIL_OFFENSIVE_MAX_HOSTS") or os.getenv("OLYMPUS_OFFENSIVE_MAX_HOSTS") or "5"))
        except ValueError:
            max_hosts = 5
        covered = min(len(live), max_hosts)
        auth_note = ""
        _creds = ctx.get("_credentials")
        if isinstance(_creds, list) and _creds:
            auth_note = (f" Authenticated scanning is ENABLED: Yggdrasil will log in as "
                         f"'{_creds[0].get('username', '?')}' and test the authenticated surface.")
        approved = await self.request_approval(
            action="Active Scanning + Exploitation (Nmap, Nuclei, sqlmap, dalfox, OWASP ZAP, IDOR/auth probes)",
            description=f"TYR will run Nmap and Nuclei (with OAST), then engage the offensive engine on "
                        f"the first {covered} of {len(live)} live host(s): {host_preview}{more}. "
                        f"Per host it builds the attack surface from the crawl, web archives and active "
                        f"parameter mining, then runs SQL injection, XSS, SSRF, SSTI, path traversal, "
                        f"open-redirect, CORS, host-header, DAST and IDOR/sensitive-endpoint checks plus a "
                        f"full OWASP ZAP active scan against each discovered URL.{auth_note} Real, "
                        f"non-destructive (read-only) testing. Authorized targets only.",
        )
        if not approved:
            await self.log("Active scanning denied. Generating passive report.", "warn")
            return await self._finalize(target, ctx)

        # TYR
        from .ares import Ares
        await self._set_phase(MissionStatus.SCANNING, "ares")
        ares = self._spawn(Ares)
        ctx["ares"] = await ares.execute(target, ctx)

        # MIMIR runs right after TYR — before the BROKKR gate — so its false-
        # positive triage, CWE/OWASP mapping, and correlated Attack Path findings
        # are available for BROKKR to forge from and for SKULD's gating decision.
        await self._set_phase(MissionStatus.SCANNING, "metis")
        await self._run_mimir(target, ctx)

        if mode == "active":
            return await self._finalize(target, ctx)

        # APPROVAL GATE: BROKKR
        # Preview count uses the same actionability rule BROKKR itself applies
        # (critical/high always; medium real injection/access-control signals;
        # MIMIR Attack Path findings) so the gate text matches what BROKKR forges.
        from sqlalchemy import select, or_
        from core.models import Finding
        from core.triage import is_actionable_finding, skuld_trigger_reasons
        _rows = await self.session.execute(
            select(Finding.title, Finding.severity).where(
                Finding.mission_id == self.mission_id,
                or_(Finding.tag.is_(None), Finding.tag != "false_positive"),
            )
        )
        _all = _rows.all()
        vuln_count = sum(1 for title, sev in _all if is_actionable_finding(title, sev))
        approved = await self.request_approval(
            action="Exploitation Phase — Payload Preparation",
            description=f"BROKKR will forge targeted payloads for {vuln_count} actionable "
                        f"finding(s). Exploitation only on authorized targets.",
        )
        if not approved:
            await self.log("Exploitation phase denied.", "warn")
            return await self._finalize(target, ctx)

        # BROKKR
        from .hephaestus import Hephaestus
        await self._set_phase(MissionStatus.EXPLOITING, "hephaestus")
        heph = self._spawn(Hephaestus)
        ctx["hephaestus"] = await heph.execute(target, ctx)

        # APPROVAL GATE: SKULD — run when BROKKR confirmed exploitable targets,
        # MIMIR correlated an attack path, or the mission already carries confirmed
        # (not merely suspected) sensitive-file or injection evidence. Mere SPF/
        # DMARC hygiene findings or a generic AI-surface note never trigger this.
        exploit_count = len(ctx["hephaestus"].get("exploitable_targets", []))
        mimir_chains = (ctx.get("metis") or {}).get("chains", 0)
        _hc_rows = await self.session.execute(
            select(Finding.title, Finding.severity).where(
                Finding.mission_id == self.mission_id,
                Finding.severity.in_(("critical", "high")),
                or_(Finding.tag.is_(None), Finding.tag != "false_positive"),
            )
        )
        high_conf_findings = [{"title": t, "severity": s} for t, s in _hc_rows.all()]
        reasons = skuld_trigger_reasons(exploit_count, mimir_chains, high_conf_findings)
        if not reasons:
            await self.log(
                "No exploitable targets, attack paths, or confirmed high-severity "
                "evidence. Skipping SKULD.", "info")
            return await self._finalize(target, ctx)

        approved = await self.request_approval(
            action="Post-Exploitation Analysis",
            description="SKULD will analyze confirmed exploitable targets for credential access, "
                        f"persistence mechanisms, and lateral movement paths. Triggers: {'; '.join(reasons)}.",
        )
        if not approved:
            await self.log("Post-exploitation phase denied.", "warn")
            return await self._finalize(target, ctx)

        # SKULD
        from .hades import Hades
        await self._set_phase(MissionStatus.POST_EXPLOIT, "hades")
        hades = self._spawn(Hades)
        ctx["hades"] = await hades.execute(target, ctx)

        return await self._finalize(target, ctx)

    async def _run_mimir(self, target: str, ctx: dict):
        """MIMIR triage + correlation (no-op without an AI key). Idempotent per
        mission run — call sites: right after TYR in full/active mode (so BROKKR/
        SKULD gating can consume attack-path correlation), and as a safety net
        inside _finalize for paths that never reach TYR (passive mode, or the TYR
        gate itself denied)."""
        if ctx.get("_mimir_ran"):
            return
        ctx["_mimir_ran"] = True
        try:
            from .metis import Metis
            metis = self._spawn(Metis)
            ctx["metis"] = await metis.execute(target, ctx)
        except Exception as e:
            await self.log(f"MIMIR triage error: {e}", "warn")
            ctx["metis"] = {}

    async def _finalize(self, target: str, ctx: dict) -> dict:
        await self._set_phase(MissionStatus.REPORTING, "apollo")

        # Safety net: passive mode and the TYR-denied path never reach TYR, so
        # MIMIR never ran above. Idempotent — a no-op wherever it already ran.
        await self._run_mimir(target, ctx)

        from .apollo import Apollo
        apollo = self._spawn(Apollo)
        ctx["apollo"] = await apollo.execute(target, ctx)

        # Persist a small, secret-free surface/coverage summary so the attack-surface
        # inventory is queryable after the run. Deliberately NOT the whole ctx: that
        # holds _credentials (a password) and set() objects that aren't JSON-safe.
        try:
            ares = ctx.get("ares", {}) or {}
            off = ares.get("offensive", {}) or {}
            hermes = ctx.get("hermes", {}) or {}
            summary = {
                "endpoints": [str(u) for u in (off.get("endpoints") or []) if isinstance(u, str)][:3000],
                "redirects": [r for r in (off.get("redirects") or []) if isinstance(r, dict)][:300],
                "coverage": {
                    "subdomains": len(hermes.get("subdomains", []) or []),
                    "live_hosts": len(hermes.get("live_hosts", []) or []),
                    "network_hosts": len(hermes.get("network_hosts", []) or []),
                    "hosts_scanned": off.get("hosts_scanned", ares.get("targets_scanned", 0)),
                    "crawled_urls": off.get("crawled_urls", 0),
                    "content_paths": len(ares.get("directories", []) or []),
                },
            }
            fresh = await self.session.get(Mission, self.mission_id)
            if fresh:
                merged = dict(fresh.context or {})
                merged["surface"] = summary
                fresh.context = merged
                await self.session.commit()
        except Exception as e:
            await self.log(f"Surface summary persist skipped: {e}", "warn")

        await self._set_phase(MissionStatus.COMPLETE)
        await self.log("⚡ YGGDRASIL MISSION COMPLETE", "success")

        if self.ws_manager:
            report_path = ctx.get("apollo", {}).get("report_path", "")
            await self.ws_manager.broadcast(self.mission_id, {
                "type": "mission_complete",
                "report_path": report_path,
                "report_available": ctx.get("apollo", {}).get("report_available", bool(report_path)),
                "report_error": ctx.get("apollo", {}).get("report_error"),
                "stats": ctx.get("apollo", {}).get("stats", {}),
                "timestamp": utcnow().isoformat(),
            })

        return ctx
