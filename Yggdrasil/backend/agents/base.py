from abc import ABC, abstractmethod
import asyncio
import os
from core.timeutil import utcnow
from core.models import AgentLog, Finding, ApprovalRequest, Mission, MissionStatus, HttpExchange
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
                "timestamp": utcnow().isoformat(),
            })

    async def add_finding(
        self,
        title: str,
        severity: str,
        description: str,
        evidence: str = None,
        cvss_score: float = None,
        remediation: str = None,
        confidence: str = None,
    ):
        # Every finding is reported; `confidence` labels how sure we are. When a
        # caller doesn't set it, infer a sensible default from severity so no
        # finding is ever unlabeled.
        from core.models import Confidence
        conf = (confidence or Confidence.infer(severity)).lower()
        finding = Finding(
            mission_id=self.mission_id,
            title=title,
            severity=severity,
            description=description,
            evidence=evidence,
            cvss_score=cvss_score,
            remediation=remediation,
            found_by=self.name,
            confidence=conf,
        )
        self.session.add(finding)
        await self.session.commit()

        if self.ws_manager:
            await self.ws_manager.broadcast(self.mission_id, {
                "type": "finding",
                "severity": severity,
                "confidence": conf,
                "title": title,
                "found_by": self.name,
                "display_name": self.display_name,
                "timestamp": utcnow().isoformat(),
            })
        return finding

    async def add_exchange(
        self,
        method: str,
        url: str,
        *,
        finding_id: str = None,
        request_headers: dict = None,
        request_body: str = None,
        status_code: int = None,
        response_headers: dict = None,
        response_body: str = None,
        duration_ms: int = None,
        source: str = None,
        notes: str = None,
    ):
        """Persist a captured HTTP request/response as first-class PoC evidence.
        Credential-bearing headers are redacted at rest."""
        from core.poc import redact_headers
        ex = HttpExchange(
            mission_id=self.mission_id,
            finding_id=finding_id,
            method=(method or "GET").upper(),
            url=url,
            request_headers=redact_headers(request_headers or {}),
            request_body=(request_body or None),
            status_code=status_code,
            response_headers=redact_headers(response_headers or {}),
            response_body=((response_body or "")[:4000] or None),
            duration_ms=duration_ms,
            source=source or self.name,
            notes=notes,
            redacted=True,
        )
        self.session.add(ex)
        await self.session.commit()
        return ex

    async def capture(self, response, *, finding_id: str = None, source: str = None, notes: str = None):
        """Capture an httpx Response (and its request) as an HttpExchange.
        Never raises: evidence capture must not break a scan."""
        try:
            req = response.request
            try:
                resp_body = response.text[:4000]
            except Exception:
                resp_body = ""
            try:
                req_body = req.content.decode("utf-8", "replace")[:2000] if req.content else None
            except Exception:
                req_body = None
            try:
                dur = int(response.elapsed.total_seconds() * 1000)
            except Exception:
                dur = None
            return await self.add_exchange(
                method=req.method, url=str(req.url), finding_id=finding_id,
                request_headers=dict(req.headers), request_body=req_body,
                status_code=response.status_code, response_headers=dict(response.headers),
                response_body=resp_body, duration_ms=dur, source=source, notes=notes,
            )
        except Exception:
            return None

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
        # Pre-authorized (autonomous) mission: the operator consented to every gate
        # at launch, so auto-approve without pausing — but still record and log each
        # gate for the audit trail. Toggled per-mission (auto_approve) or globally
        # via YGGDRASIL_AUTO_APPROVE=1 (or legacy OLYMPUS_AUTO_APPROVE=1).
        try:
            mission = await self.session.get(Mission, self.mission_id)
        except AttributeError:
            mission = None
        mission_auto = bool(mission and (mission.context or {}).get("auto_approve"))
        env_auto = ((os.getenv("YGGDRASIL_AUTO_APPROVE") or os.getenv("OLYMPUS_AUTO_APPROVE") or "").strip().lower() in ("1", "true", "yes"))
        if mission_auto or env_auto:
            approval = ApprovalRequest(
                mission_id=self.mission_id, agent=self.name, action=action,
                description=description, status="approved", resolved_at=utcnow(),
            )
            self.session.add(approval)
            await self.session.flush()
            await self.session.commit()
            await self.log(f"Auto-authorized (pre-approved at launch): {action}", "info")
            if self.ws_manager:
                await self.ws_manager.broadcast(self.mission_id, {
                    "type": "approval_resolved", "approval_id": approval.id,
                    "approved": True, "timestamp": utcnow().isoformat(),
                })
            return True

        approval = ApprovalRequest(
            mission_id=self.mission_id,
            agent=self.name,
            action=action,
            description=description,
            status="pending",
        )
        self.session.add(approval)
        await self.session.flush()
        event = asyncio.Event()
        self.approval_gates[approval.id] = event
        await self.session.execute(
            update(Mission)
            .where(Mission.id == self.mission_id)
            .values(status=MissionStatus.AWAITING_APPROVAL)
        )
        await self.session.commit()

        if self.ws_manager:
            await self.ws_manager.broadcast(self.mission_id, {
                "type": "approval_required",
                "approval_id": approval.id,
                "agent": self.name,
                "display_name": self.display_name,
                "symbol": self.symbol,
                "action": action,
                "description": description,
                "timestamp": utcnow().isoformat(),
            })

        # Hold here until a human authorizes or denies — by default, forever.
        # The mission must not proceed (or auto-deny) just because the operator
        # hasn't gotten to the screen yet. Set YGGDRASIL_APPROVAL_TIMEOUT to a
        # positive number of seconds to auto-deny after that long instead (0 or
        # unset = wait indefinitely).
        try:
            timeout = float(os.getenv("YGGDRASIL_APPROVAL_TIMEOUT") or os.getenv("OLYMPUS_APPROVAL_TIMEOUT") or "0")
        except ValueError:
            timeout = 0.0

        try:
            if timeout > 0:
                await asyncio.wait_for(event.wait(), timeout=timeout)
            else:
                await event.wait()
        except asyncio.TimeoutError:
            await self.log(
                f"Approval gate timed out ({int(timeout)}s). Phase skipped.", "warn"
            )
            self.approval_gates.pop(approval.id, None)
            return False

        result = self.approval_results.pop(approval.id, False)
        self.approval_gates.pop(approval.id, None)
        await self.log(
            f"Approval {'granted' if result else 'denied'} for gate: {action}",
            "info" if result else "warn",
        )
        return result

    @abstractmethod
    async def execute(self, target: str, context: dict = None) -> dict:
        pass
