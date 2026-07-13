import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, update
from core.database import engine, Base, AsyncSessionLocal
from core.models import Mission, MissionStatus, ApprovalRequest, AgentLog
from routers import missions, ws, scope
from core.security import require_api_key, api_key_enabled
from fastapi import Depends


LOST_ON_RESTART_STATUSES = (
    MissionStatus.PENDING,
    MissionStatus.PLANNING,
    MissionStatus.RECON,
    MissionStatus.SCANNING,
    MissionStatus.EXPLOITING,
    MissionStatus.POST_EXPLOIT,
    MissionStatus.REPORTING,
    MissionStatus.AWAITING_APPROVAL,
)


async def mark_orphaned_runtime_missions():
    """Background tasks are in-process; mark old active missions stale on boot."""
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(
            select(Mission).where(Mission.status.in_(LOST_ON_RESTART_STATUSES))
        )).scalars().all()
        if not rows:
            return

        now = datetime.utcnow()
        mission_ids = [m.id for m in rows]
        for mission in rows:
            mission.status = MissionStatus.FAILED
            mission.current_phase = None
            mission.completed_at = now
            session.add(AgentLog(
                mission_id=mission.id,
                agent="zeus",
                level="error",
                message=(
                    "Mission stopped because the backend restarted while it was in progress. "
                    "The in-memory scan task cannot be resumed; relaunch the mission to start a fresh run."
                ),
            ))

        await session.execute(
            update(ApprovalRequest)
            .where(
                ApprovalRequest.mission_id.in_(mission_ids),
                ApprovalRequest.status == "pending",
            )
            .values(status="stale", resolved_at=now)
        )
        await session.commit()
        print(f"[YGGDRASIL][RECOVERY] Marked {len(rows)} orphaned runtime mission(s) as failed after restart.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    if not api_key_enabled():
        print("[YGGDRASIL][WARN] YGGDRASIL_API_KEY is not set - API auth is DISABLED. OLYMPUS_API_KEY remains supported for existing installs.")
    app.state.approval_gates: dict[str, asyncio.Event] = {}
    app.state.approval_results: dict[str, bool] = {}
    await mark_orphaned_runtime_missions()

    yield

    await engine.dispose()


app = FastAPI(
    title="Yggdrasil",
    description="Authorized Security Assessment Workspace",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

import os
_allowed = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _allowed if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(missions.router, prefix="/api/missions", tags=["missions"], dependencies=[Depends(require_api_key)])
app.include_router(scope.router, prefix="/api/scope", tags=["scope"], dependencies=[Depends(require_api_key)])
app.include_router(ws.router, prefix="/ws", tags=["websocket"])


@app.get("/api/health")
async def health():
    return {"status": "online", "platform": "Yggdrasil", "version": "1.0.0"}
