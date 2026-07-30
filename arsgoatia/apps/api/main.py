"""ArsGoatia API -- Unified Deterministic Autonomous Security Validation Platform."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from apps.api.routers import (
    actions,
    audit,
    auth as auth_router,
    capabilities,
    engagements,
    evidence,
    findings,
    reports,
    streams,
)

logger = logging.getLogger("arsgoatia.api")

ALLOWED_ORIGINS: list[str] = [
    "http://localhost:3100",
    "http://127.0.0.1:3100",
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("ArsGoatia API starting")
    yield
    logger.info("ArsGoatia API shutting down")


app = FastAPI(
    title="ArsGoatia API",
    description="Unified Deterministic Autonomous Security Validation Platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -- Routers ------------------------------------------------------------------
PREFIX = "/api/v1"

app.include_router(auth_router.router, prefix=PREFIX)
app.include_router(capabilities.router, prefix=PREFIX)
app.include_router(engagements.router, prefix=PREFIX)
app.include_router(actions.router, prefix=PREFIX)
app.include_router(evidence.router, prefix=PREFIX)
app.include_router(findings.router, prefix=PREFIX)
app.include_router(reports.router, prefix=PREFIX)
app.include_router(audit.router, prefix=PREFIX)
app.include_router(streams.router, prefix=PREFIX)


# -- Health -------------------------------------------------------------------
@app.get("/health", tags=["infra"])
async def health():
    return {"status": "ok", "service": "arsgoatia-api"}


@app.get(f"{PREFIX}/health", tags=["infra"])
async def health_prefixed():
    return {"status": "ok", "service": "arsgoatia-api"}
