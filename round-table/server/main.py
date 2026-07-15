"""
ROUND TABLE // web platform entrypoint.

One FastAPI process serves the JSON API, the WebSocket live feed, and the SPA.
Zero-config: SQLite storage, recon tools baked into the image, optional AI.
Recon & advisory only — Round Table never exploits.
"""
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .core import ai_client, db
from .core.hub import hub
from .routers import curl_router, missions, ws

WEB_DIR = Path(__file__).parent / "web"


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    hub.bind_loop(asyncio.get_running_loop())
    info = ai_client.ai_info()
    print(f"[roundtable] up · AI={'on' if info['enabled'] else 'off'} "
          f"({info['provider']}/{info['model'] if info['enabled'] else 'n/a'})", flush=True)
    yield


app = FastAPI(
    title="Round Table",
    description="Recon & test-guidance platform — advisory only, no exploitation.",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # same-origin SPA; API is local-only by default
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(missions.router, prefix="/api/missions", tags=["missions"])
app.include_router(curl_router.router, prefix="/api/curl", tags=["curl"])
app.include_router(ws.router, prefix="/ws", tags=["websocket"])


@app.get("/api/health")
async def health():
    return {"status": "online", "platform": "Round Table", "version": "2.0.0", "ai": ai_client.ai_info()}


@app.get("/api/config")
async def config():
    return {"ai": ai_client.ai_info(), "modes": ["passive", "active", "full"], "version": "2.0.0"}


# SPA last so it does not shadow the API / WS routes above.
if WEB_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="spa")
