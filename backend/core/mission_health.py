import asyncio
from datetime import datetime

from core.database import AsyncSessionLocal
from core.models import AgentLog, Mission, MissionStatus


AGENT_DISPLAY = {
    "zeus": "ODIN",
    "athena": "FRIGG",
    "hermes": "HEIMDALL",
    "ares": "TYR",
    "hephaestus": "BROKKR",
    "hades": "SKULD",
    "apollo": "SAGA",
}

TERMINAL_STATUSES = {MissionStatus.COMPLETE, MissionStatus.FAILED}


def _duration(seconds: int | None) -> str:
    if seconds is None:
        return "0s"
    seconds = max(0, int(seconds))
    minutes, sec = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {sec}s"
    return f"{sec}s"


def _parse_dt(value: str | None, fallback: datetime) -> datetime:
    if not value:
        return fallback
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return fallback


def _health_message(status: str, phase_name: str, phase_elapsed: int, elapsed: int) -> str:
    phase_time = _duration(phase_elapsed)
    total_time = _duration(elapsed)
    if status == MissionStatus.AWAITING_APPROVAL:
        return f"Waiting for operator authorization at {phase_name}. Mission alive for {total_time}."
    if status == MissionStatus.SCANNING:
        return f"{phase_name} is still scanning. Current phase {phase_time}; mission alive for {total_time}."
    if status == MissionStatus.RECON:
        return f"{phase_name} is still mapping the target. Current phase {phase_time}; mission alive for {total_time}."
    if status == MissionStatus.EXPLOITING:
        return f"{phase_name} is preparing payloads. Current phase {phase_time}; mission alive for {total_time}."
    if status == MissionStatus.POST_EXPLOIT:
        return f"{phase_name} is reviewing impact. Current phase {phase_time}; mission alive for {total_time}."
    if status == MissionStatus.REPORTING:
        return f"{phase_name} is building the report. Current phase {phase_time}; mission alive for {total_time}."
    if status == MissionStatus.COMPLETE:
        return f"Assessment completed after {total_time}."
    if status == MissionStatus.FAILED:
        return f"Assessment failed after {total_time}. Check the activity log for the error."
    return f"{phase_name} is active. Current phase {phase_time}; mission alive for {total_time}."


async def record_mission_health(
    mission_id: str,
    ws_manager=None,
    *,
    log: bool = False,
    allow_terminal: bool = False,
) -> dict | None:
    now = datetime.utcnow()
    log_event = None

    async with AsyncSessionLocal() as session:
        mission = await session.get(Mission, mission_id)
        if not mission:
            return None
        if mission.status in TERMINAL_STATUSES and not allow_terminal:
            return None

        current_context = dict(mission.context or {})
        previous = current_context.get("mission_health") or {}
        phase_key = mission.current_phase or mission.status
        phase_name = AGENT_DISPLAY.get(mission.current_phase or "", (phase_key or "mission").upper())
        if previous.get("phase_key") == phase_key:
            phase_started_at = _parse_dt(previous.get("phase_started_at"), now)
        else:
            phase_started_at = now

        created_at = mission.created_at or now
        elapsed_seconds = int((now - created_at).total_seconds())
        phase_elapsed_seconds = int((now - phase_started_at).total_seconds())

        health = {
            "last_heartbeat_at": now.isoformat(),
            "phase_started_at": phase_started_at.isoformat(),
            "phase_key": phase_key,
            "phase": mission.current_phase,
            "phase_name": phase_name,
            "status": mission.status,
            "state": "waiting" if mission.status == MissionStatus.AWAITING_APPROVAL else "running",
            "elapsed_seconds": elapsed_seconds,
            "phase_elapsed_seconds": phase_elapsed_seconds,
            "message": _health_message(mission.status, phase_name, phase_elapsed_seconds, elapsed_seconds),
        }

        if mission.status == MissionStatus.COMPLETE:
            health["state"] = "complete"
        elif mission.status == MissionStatus.FAILED:
            health["state"] = "failed"

        current_context["mission_health"] = health
        mission.context = current_context
        mission.updated_at = now

        if log:
            log_event = AgentLog(
                mission_id=mission_id,
                agent="zeus",
                level="info",
                message=f"Heartbeat: {health['message']}",
            )
            session.add(log_event)

        await session.commit()

    if ws_manager:
        await ws_manager.broadcast(mission_id, {
            "type": "mission_heartbeat",
            "health": health,
            "timestamp": now.isoformat(),
        })
        if log_event:
            await ws_manager.broadcast(mission_id, {
                "type": "log",
                "agent": "zeus",
                "symbol": "OD",
                "display_name": "ODIN",
                "level": "info",
                "message": f"Heartbeat: {health['message']}",
                "timestamp": now.isoformat(),
            })

    return health


async def mission_heartbeat_loop(mission_id: str, ws_manager=None, interval: int = 60):
    while True:
        await asyncio.sleep(interval)
        health = await record_mission_health(mission_id, ws_manager, log=True)
        if health is None:
            return
