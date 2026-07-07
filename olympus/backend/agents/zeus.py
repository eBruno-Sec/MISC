import os
from datetime import datetime
from sqlalchemy import update
from core.models import Mission, MissionStatus
from .base import BaseAgent


class Zeus(BaseAgent):
    name = "zeus"
    symbol = "⚡"
    display_name = "ZEUS"
    role = "Mission Orchestrator"

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
        if status in (MissionStatus.COMPLETE, MissionStatus.FAILED):
            values["completed_at"] = datetime.utcnow()
        await self.session.execute(
            update(Mission).where(Mission.id == self.mission_id).values(**values)
        )
        await self.session.commit()

        if self.ws_manager:
            await self.ws_manager.broadcast(self.mission_id, {
                "type": "status_change",
                "status": status,
                "phase": phase,
                "timestamp": datetime.utcnow().isoformat(),
            })

    async def execute(self, target: str, context: dict = None) -> dict:
        mode = (context or {}).get("mode", "passive")
        scope = (context or {}).get("scope", "")
        scope_rules = (context or {}).get("scope_rules", {})
        ctx = {"scope_rules": scope_rules}

        await self._set_phase(MissionStatus.PLANNING, "zeus")
        await self.log(f"⚡ OLYMPUS ONLINE — Target: {target} | Mode: {mode.upper()}", "info")

        sequences = {
            "passive": "ATHENA → HERMES → METIS → APOLLO",
            "active": "ATHENA → HERMES → [GATE] → ARES → METIS → APOLLO",
            "full": "ATHENA → HERMES → [GATE] → ARES → HEPHAESTUS → [GATE] → HADES → [GATE] → METIS → APOLLO",
        }
        await self.log(f"Sequence: {sequences.get(mode, sequences['passive'])}", "info")

        # ── ATHENA ──
        from .athena import Athena
        await self._set_phase(MissionStatus.PLANNING, "athena")
        athena = self._spawn(Athena)
        ctx["athena"] = await athena.execute(target, {"mode": mode, "scope": scope})

        # If the operator wrote free-text scope notes but uploaded no structured
        # scope rules, enforce the validated rules ATHENA derived from those notes.
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

        # Move extracted credentials to a transient key so ARES can authenticate.
        # Kept out of ctx["athena"] and never persisted; passwords are not logged.
        creds = (ctx.get("athena") or {}).pop("_credentials", None)
        if creds:
            ctx["_credentials"] = creds

        # ── HERMES ──
        from .hermes import Hermes
        await self._set_phase(MissionStatus.RECON, "hermes")
        hermes = self._spawn(Hermes)
        ctx["hermes"] = await hermes.execute(target, ctx)

        if mode == "passive":
            return await self._finalize(target, ctx)

        # ── APPROVAL GATE: ARES ──
        await self.log("Requesting authorization for active scanning phase", "warn")
        live = ctx["hermes"].get("live_hosts", [])
        host_preview = ", ".join(h["host"] for h in live[:5])
        more = f" (+{len(live)-5} more)" if len(live) > 5 else ""
        try:
            max_hosts = max(1, int(os.getenv("OLYMPUS_OFFENSIVE_MAX_HOSTS", "5")))
        except ValueError:
            max_hosts = 5
        covered = min(len(live), max_hosts)
        auth_note = ""
        _creds = ctx.get("_credentials")
        if isinstance(_creds, list) and _creds:
            auth_note = (f" Authenticated scanning is ENABLED: OLYMPUS will log in as "
                         f"'{_creds[0].get('username', '?')}' and test the authenticated surface.")
        approved = await self.request_approval(
            action="Active Scanning + Exploitation (Nmap, Nuclei, sqlmap, dalfox, OWASP ZAP, IDOR/auth probes)",
            description=f"Ares will run Nmap and Nuclei (with OAST), then engage the offensive engine on "
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

        # ── ARES ──
        from .ares import Ares
        await self._set_phase(MissionStatus.SCANNING, "ares")
        ares = self._spawn(Ares)
        ctx["ares"] = await ares.execute(target, ctx)

        if mode == "active":
            return await self._finalize(target, ctx)

        # ── APPROVAL GATE: HEPHAESTUS ──
        # Count real findings from the DB. ares["vulnerabilities"] is only the
        # nuclei template hits; the offensive engine (SQLi/XSS/SSRF/SSTI/ZAP/...)
        # writes straight to the findings table.
        from sqlalchemy import select, func, or_
        from core.models import Finding
        _c = await self.session.execute(
            select(func.count()).select_from(Finding).where(
                Finding.mission_id == self.mission_id,
                Finding.severity.in_(("critical", "high")),
                or_(Finding.tag.is_(None), Finding.tag != "false_positive"),
            )
        )
        vuln_count = _c.scalar() or 0
        approved = await self.request_approval(
            action="Exploitation Phase — Payload Preparation",
            description=f"Hephaestus will forge targeted payloads for {vuln_count} high/critical "
                        f"finding(s). Exploitation only on authorized targets.",
        )
        if not approved:
            await self.log("Exploitation phase denied.", "warn")
            return await self._finalize(target, ctx)

        # ── HEPHAESTUS ──
        from .hephaestus import Hephaestus
        await self._set_phase(MissionStatus.EXPLOITING, "hephaestus")
        heph = self._spawn(Hephaestus)
        ctx["hephaestus"] = await heph.execute(target, ctx)

        # ── APPROVAL GATE: HADES ──
        exploit_count = len(ctx["hephaestus"].get("exploitable_targets", []))
        if exploit_count == 0:
            await self.log("No exploitable targets confirmed. Skipping Hades.", "info")
            return await self._finalize(target, ctx)

        approved = await self.request_approval(
            action="Post-Exploitation Analysis",
            description=f"Hades will analyze {exploit_count} confirmed exploitable targets for credential access, "
                        "persistence mechanisms, and lateral movement paths.",
        )
        if not approved:
            await self.log("Post-exploitation phase denied.", "warn")
            return await self._finalize(target, ctx)

        # ── HADES ──
        from .hades import Hades
        await self._set_phase(MissionStatus.POST_EXPLOIT, "hades")
        hades = self._spawn(Hades)
        ctx["hades"] = await hades.execute(target, ctx)

        return await self._finalize(target, ctx)

    async def _finalize(self, target: str, ctx: dict) -> dict:
        await self._set_phase(MissionStatus.REPORTING, "apollo")

        # ── METIS: AI triage + correlation before the report (no-op without AI key) ──
        try:
            from .metis import Metis
            metis = self._spawn(Metis)
            ctx["metis"] = await metis.execute(target, ctx)
        except Exception as e:
            await self.log(f"METIS triage error: {e}", "warn")
            ctx["metis"] = {}

        from .apollo import Apollo
        apollo = self._spawn(Apollo)
        ctx["apollo"] = await apollo.execute(target, ctx)

        await self._set_phase(MissionStatus.COMPLETE)
        await self.log("⚡ OLYMPUS MISSION COMPLETE", "success")

        if self.ws_manager:
            report_path = ctx.get("apollo", {}).get("report_path", "")
            await self.ws_manager.broadcast(self.mission_id, {
                "type": "mission_complete",
                "report_path": report_path,
                "stats": ctx.get("apollo", {}).get("stats", {}),
                "timestamp": datetime.utcnow().isoformat(),
            })

        return ctx
