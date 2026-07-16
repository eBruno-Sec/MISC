"""
ROUND TABLE // web platform entrypoint.

One FastAPI process serves the JSON API, the WebSocket live feed, and the SPA.
Zero-config: SQLite storage, recon tools baked into the image, optional AI.
Recon & advisory only — Round Table never exploits.
"""
import asyncio
import os
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
    port = os.getenv("ROUNDTABLE_PORT", "3000")
    ai_line = f"on ({info['provider']}/{info['model']})" if info["enabled"] else "off (rule-based, fully functional)"
    bar = "=" * 54
    # ASCII only: some Windows consoles use cp1252 and would crash on emoji.
    print(f"\n  {bar}\n"
          f"  ROUND TABLE is up  ->  open  http://localhost:{port}\n"
          f"  AI: {ai_line}\n"
          f"  {bar}\n", flush=True)
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


@app.middleware("http")
async def spa_no_cache(request, call_next):
    # The SPA is served from disk and updated on every image rebuild. Tell the
    # browser to always revalidate so a rebuild never shows stale UI.
    resp = await call_next(request)
    p = request.url.path
    if p == "/" or p.endswith((".js", ".css", ".html")):
        resp.headers["Cache-Control"] = "no-cache, must-revalidate"
    return resp


@app.get("/api/health")
async def health():
    return {"status": "online", "platform": "Round Table", "version": "2.0.0", "ai": ai_client.ai_info()}


@app.get("/api/config")
async def config():
    return {"ai": ai_client.ai_info(), "modes": ["passive", "active", "full"], "version": "2.0.0"}


# SPA last so it does not shadow the API / WS routes above.
if WEB_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="spa")
