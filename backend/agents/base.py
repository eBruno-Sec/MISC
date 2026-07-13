from abc import ABC, abstractmethod
import asyncio
import os
from datetime import datetime
from core.models import AgentLog, Finding, ApprovalRequest, Mission, MissionStatus, HttpExchange
from core.mission_health import record_mission_health
from core.poc import redact_headers
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import update


class BaseAgent(ABC):
    name: str = "base"
    symbol: str = "○"
    display_name: str = "BASE"
    role: str = "Unknown"

    def __init__(
        self,
        session: AsyncSession,
        mission_id: str,
        ws_manager=None,
        approval_gates: dict = None,
        approval_results: dict = None,
    ):
        self.session = session
        self.mission_id = mission_id
        self.ws_manager = ws_manager
        self.approval_gates = approval_gates if approval_gates is not None else {}
        self.approval_results = approval_results if approval_results is not None else {}

    async def log(self, message: str, level: str = "info", raw_output: str = None):
        entry = AgentLog(
            mission_id=self.mission_id,
            agent=self.name,
            level=level,
            message=message,
            raw_output=raw_output,
        )
        self.session.add(entry)
        await self.session.commit()

        if self.ws_manager:
            await self.ws_manager.broadcast(self.mission_id, {
                "type": "log",
                "agent": self.name,
                "symbol": self.symbol,
                "display_name": self.display_name,
                "level": level,
                "message": message,
                "timestamp": datetime.utcnow().isoformat(),
            })

    async def add_finding(
        self,
        title: str,
        severity: str,
        description: str,
        evidence: str = None,
        cvss_score: float = None,
        remediation: str = None,
    ):
        finding = Finding(
            mission_id=self.mission_id,
            title=title,
            severity=severity,
            description=description,
            evidence=evidence,
            cvss_score=cvss_score,
            remediation=remediation,
            found_by=self.name,
        )
        self.session.add(finding)
        await self.session.commit()

        if self.ws_manager:
            await self.ws_manager.broadcast(self.mission_id, {
                "type": "finding",
                "severity": severity,
                "title": title,
                "found_by": self.name,
                "display_name": self.display_name,
                "timestamp": datetime.utcnow().isoformat(),
            })

    async def record_http_exchange(
        self,
        *,
        method: str,
        url: str,
        request_headers: dict | None = None,
        request_body: str | None = None,
        response_status: int | None = None,
        response_headers: dict | None = None,
        response_body: str | None = None,
        label: str | None = None,
        finding_id: str | None = None,
    ) -> HttpExchange:
        exchange = HttpExchange(
            mission_id=self.mission_id,
            finding_id=finding_id,
            label=label,
            method=(method or "GET").upper(),
            url=url,
            request_headers=redact_headers(request_headers),
            request_body=request_body,
            response_status=response_status,
            response_headers=redact_headers(response_headers),
            response_body=response_body,
        )
        self.session.add(exchange)
        await self.session.commit()
        await self.session.refresh(exchange)
        return exchange

    async def run_command(self, cmd: list, timeout: int = 300) -> tuple:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=os.environ.copy(),
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode
        except asyncio.TimeoutError:
            await self.log(f"Command timed out ({timeout}s): {cmd[0]}", "warn")
            return "", "timeout", -1
        except FileNotFoundError:
            return "", f"Tool not found: {cmd[0]}", 127
        except Exception as e:
            return "", str(e), -1

    async def request_approval(self, action: str, description: str) -> bool:
        approval = ApprovalRequest(
            mission_id=self.mission_id,
            agent=self.name,
            action=action,
            description=description,
            status="pending",
        )
        self.session.add(approval)
        await self.session.execute(
            update(Mission)
            .where(Mission.id == self.mission_id)
            .values(status=MissionStatus.AWAITING_APPROVAL)
        )
        await self.session.flush()

        event = asyncio.Event()
        approval_id = approval.id
        self.approval_gates[approval_id] = event
        await self.session.commit()

        if self.ws_manager:
            await self.ws_manager.broadcast(self.mission_id, {
                "type": "status_change",
                "status": MissionStatus.AWAITING_APPROVAL,
                "phase": self.name,
                "timestamp": datetime.utcnow().isoformat(),
            })
            await self.ws_manager.broadcast(self.mission_id, {
                "type": "approval_required",
                "approval_id": approval_id,
                "agent": self.name,
                "display_name": self.display_name,
                "symbol": self.symbol,
                "action": action,
                "description": description,
                "timestamp": datetime.utcnow().isoformat(),
            })
        if isinstance(self.session, AsyncSession):
            await record_mission_health(self.mission_id, self.ws_manager, allow_terminal=True)

        await event.wait()

        result = self.approval_results.pop(approval_id, None)
        self.approval_gates.pop(approval_id, None)
        if result is None:
            await self.session.refresh(approval)
            result = approval.status == "approved"

        if result:
            await self.log(f"Authorization approved for: {action}", "success")
        else:
            await self.log(f"Authorization denied for: {action}. Phase skipped.", "warn")
        return result

    @abstractmethod
    async def execute(self, target: str, context: dict = None) -> dict:
        pass
