import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from core.database import engine, Base
from core.schema_compat import ensure_schema_compatibility
from core.tooling import check_all_tools, format_warnings
from routers import missions, ws, scope, wordlists, oracle
from core.security import require_api_key, api_key_enabled
from fastapi import Depends


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await ensure_schema_compatibility(conn)

    if not api_key_enabled():
        print("[YGGDRASIL][WARN] YGGDRASIL_API_KEY is not set; API auth is DISABLED. Set it in .env for anything beyond localhost.")

    # Scanner health check: log availability/version for every tool the engine
    # shells out to, so a missing binary is a loud startup warning instead of a
    # silently empty findings section three phases into a mission. Never blocks
    # startup on failure — a check error just means "unknown", not a crash.
    try:
        tool_status = await check_all_tools()
        for name, info in sorted(tool_status.items()):
            state = f"v{info['version']}" if info.get("available") else "NOT AVAILABLE"
            print(f"[YGGDRASIL][TOOLING] {name}: {state}")
        for warning in format_warnings(tool_status):
            print(f"[YGGDRASIL][WARN] {warning}")
    except Exception as e:
        print(f"[YGGDRASIL][WARN] Scanner health check failed to run: {e}")

    app.state.approval_gates: dict[str, asyncio.Event] = {}
    app.state.approval_results: dict[str, bool] = {}

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
app.include_router(wordlists.router, prefix="/api/wordlists", tags=["wordlists"], dependencies=[Depends(require_api_key)])
app.include_router(oracle.router, prefix="/api/oracle", tags=["oracle"], dependencies=[Depends(require_api_key)])
app.include_router(ws.router, prefix="/ws", tags=["websocket"])


@app.get("/api/health")
async def health():
    return {"status": "online", "platform": "Yggdrasil", "version": "1.0.0"}
