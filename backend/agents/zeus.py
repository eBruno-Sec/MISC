import asyncio
from contextlib import suppress
from datetime import datetime
from sqlalchemy import update
from core.models import Mission, MissionStatus
from core.mission_health import mission_heartbeat_loop, record_mission_health
from .base import BaseAgent


class Zeus(BaseAgent):
    name = "zeus"
    symbol = "OD"
    display_name = "ODIN"
    role = "Assessment Orchestrator"

    def _spawn(self, AgentClass):
        return AgentClass(
            session=self.session,
            mission_id=self.mission_id,
            ws_manager=self.ws_manager,
            approval_gates=self.approval_gates,
            approval_results=self.approval_results,
        )

    def _brokkr_input_counts(self, ares: dict) -> tuple[int, int]:
        if not isinstance(ares, dict):
            return 0, 0
        template_count = len(ares.get("vulnerabilities", []) or [])
        offensive = ares.get("offensive", {}) if isinstance(ares.get("offensive", {}), dict) else {}
        candidate_count = 0
        for key in ("sqli", "xss", "dast", "auth", "dependency", "scope_candidates", "path_traversal", "idor_bola"):
            candidate_count += len(offensive.get(key, []) or [])
        return template_count, candidate_count

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
        await record_mission_health(self.mission_id, self.ws_manager, allow_terminal=True)

    async def _persist_context(self, ctx: dict):
        mission = await self.session.get(Mission, self.mission_id)
        if not mission:
            return
        current = dict(mission.context or {})
        health = current.get("mission_health")
        current.update(ctx)
        if health:
            current["mission_health"] = health
        mission.context = current
        await self.session.commit()

    async def execute(self, target: str, context: dict = None) -> dict:
        heartbeat_task = asyncio.create_task(mission_heartbeat_loop(self.mission_id, self.ws_manager))
        try:
            mode = (context or {}).get("mode", "passive")
            scope = (context or {}).get("scope", "")
            scope_rules = (context or {}).get("scope_rules", {})
            ctx = {"scope_rules": scope_rules}

            await self._set_phase(MissionStatus.PLANNING, "zeus")
            await self.log(f"Yggdrasil online - Target: {target} | Mode: {mode.upper()}", "info")

            sequences = {
                "passive": "FRIGG -> HEIMDALL -> SAGA",
                "active": "FRIGG -> HEIMDALL -> [GATE] -> TYR -> SAGA",
                "full": "FRIGG -> HEIMDALL -> [GATE] -> TYR -> BROKKR -> [GATE] -> SKULD -> [GATE] -> SAGA",
            }
            await self.log(f"Sequence: {sequences.get(mode, sequences['passive'])}", "info")

            from .athena import Athena
            await self._set_phase(MissionStatus.PLANNING, "athena")
            athena = self._spawn(Athena)
            ctx["athena"] = await athena.execute(
                target,
                {"mode": mode, "scope": scope, "scope_rules": scope_rules},
            )
            await self._persist_context(ctx)

            from .hermes import Hermes
            await self._set_phase(MissionStatus.RECON, "hermes")
            hermes = self._spawn(Hermes)
            ctx["hermes"] = await hermes.execute(target, ctx)
            await self._persist_context(ctx)

            if mode == "passive":
                return await self._finalize(target, ctx)

            await self.log("Requesting authorization for active assessment phase", "warn")
            live = ctx["hermes"].get("live_hosts", [])
            host_preview = ", ".join(h["host"] for h in live[:5])
            more = f" (+{len(live)-5} more)" if len(live) > 5 else ""
            approved = await self.request_approval(
                action="Active Assessment + Web App Testing (Nmap, Nuclei, sqlmap, dalfox, traversal, IDOR/BOLA)",
                description=f"Tyr will run Nmap and Nuclei, then engage the offensive engine "
                            f"(crawl + SQL injection, XSS, DAST, path traversal/LFI, IDOR/BOLA, "
                            f"content discovery, and sensitive-endpoint checks) against {len(live)} live target(s): {host_preview}{more}. "
                            f"This performs real, non-destructive injection testing. Authorized targets only.",
            )
            if not approved:
                await self.log("Active assessment denied. Generating passive report.", "warn")
                return await self._finalize(target, ctx)

            from .ares import Ares
            await self._set_phase(MissionStatus.SCANNING, "ares")
            ares = self._spawn(Ares)
            ctx["ares"] = await ares.execute(target, ctx)
            await self._persist_context(ctx)

            if mode == "active":
                return await self._finalize(target, ctx)

            vuln_count, web_candidate_count = self._brokkr_input_counts(ctx.get("ares", {}))
            approved = await self.request_approval(
                action="Payload Preparation",
                description=(
                    f"Brokkr will prepare targeted payloads for {vuln_count} template finding(s) "
                    f"and {web_candidate_count} Tyr web finding/candidate(s). "
                    "Exploitation only on authorized targets."
                ),
            )
            if not approved:
                await self.log("Payload preparation denied.", "warn")
                return await self._finalize(target, ctx)

            from .hephaestus import Hephaestus
            await self._set_phase(MissionStatus.EXPLOITING, "hephaestus")
            heph = self._spawn(Hephaestus)
            ctx["hephaestus"] = await heph.execute(target, ctx)
            await self._persist_context(ctx)

            exploit_count = len(ctx["hephaestus"].get("exploitable_targets", []))
            candidate_count = len(ctx["hephaestus"].get("candidate_targets", []))
            if exploit_count == 0:
                suffix = f" {candidate_count} candidate target(s) retained for manual validation." if candidate_count else ""
                await self.log(f"No confirmed exploitable targets. Skipping Skuld.{suffix}", "info")
                return await self._finalize(target, ctx)

            approved = await self.request_approval(
                action="Impact Review",
                description=f"Skuld will analyze {exploit_count} confirmed exploitable targets for credential access, "
                            "persistence mechanisms, and lateral movement paths.",
            )
            if not approved:
                await self.log("Impact review denied.", "warn")
                return await self._finalize(target, ctx)

            from .hades import Hades
            await self._set_phase(MissionStatus.POST_EXPLOIT, "hades")
            hades = self._spawn(Hades)
            ctx["hades"] = await hades.execute(target, ctx)
            await self._persist_context(ctx)

            return await self._finalize(target, ctx)
        finally:
            heartbeat_task.cancel()
            with suppress(asyncio.CancelledError):
                await heartbeat_task

    async def _finalize(self, target: str, ctx: dict) -> dict:
        from .apollo import Apollo
        await self._set_phase(MissionStatus.REPORTING, "apollo")
        apollo = self._spawn(Apollo)
        ctx["apollo"] = await apollo.execute(target, ctx)
        await self._persist_context(ctx)

        await self._set_phase(MissionStatus.COMPLETE)
        await self.log("Yggdrasil assessment complete", "success")

        if self.ws_manager:
            apollo_result = ctx.get("apollo", {})
            report_path = apollo_result.get("report_path", "")
            await self.ws_manager.broadcast(self.mission_id, {
                "type": "mission_complete",
                "report_path": report_path,
                "report_available": bool(report_path) and not apollo_result.get("report_error"),
                "report_error": apollo_result.get("report_error"),
                "stats": apollo_result.get("stats", {}),
                "timestamp": datetime.utcnow().isoformat(),
            })

        return ctx
