"""ArsGoatia control-plane API (FastAPI).

M0 scaffold: health + version endpoints so the container and compose stack are
verifiable end to end. M1 mounts the assessment/authorization/scope routers and
wires the AsyncSession + tenant/object-authorization dependency (apps/api/deps.py).
"""

from __future__ import annotations

import os

from fastapi import FastAPI

from .routers import assessments, tenants

app = FastAPI(title="ArsGoatia API", version="0.1.0")
app.include_router(tenants.router)
app.include_router(assessments.router)


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok", "service": "arsgoatia-api"}


@app.get("/api/v1")
async def api_root() -> dict:
    return {
        "name": "ArsGoatia",
        "version": "0.1.0",
        "environment": os.getenv("APP_ENV", "development"),
        "status": "scaffold",
        "resources": [
            "assessments",
            "assets",
            "findings",
            "evidence",
            "capabilities",
            "attack-chains",
            "approvals",
            "modules",
            "reports",
        ],
    }
