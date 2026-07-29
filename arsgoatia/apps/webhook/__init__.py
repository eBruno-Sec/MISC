"""ArsGoatia webhook receiver — ingests external callback events."""
from __future__ import annotations

import hashlib
import hmac
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request

app = FastAPI(title="ArsGoatia Webhook Receiver", version="0.1.0")

WEBHOOK_SECRET = b""


def verify_signature(payload: bytes, signature: str, secret: bytes) -> bool:
    expected = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/webhooks/dns-callback")
async def dns_callback(request: Request) -> dict[str, str]:
    body = await request.json()
    return {"status": "received", "type": "dns_callback"}


@app.post("/api/v1/webhooks/http-callback")
async def http_callback(request: Request) -> dict[str, str]:
    body = await request.json()
    return {"status": "received", "type": "http_callback"}


@app.post("/api/v1/webhooks/generic")
async def generic_webhook(
    request: Request,
    x_webhook_signature: str | None = Header(default=None),
) -> dict[str, str]:
    body = await request.body()
    if WEBHOOK_SECRET and x_webhook_signature:
        if not verify_signature(body, x_webhook_signature, WEBHOOK_SECRET):
            raise HTTPException(status_code=403, detail="invalid signature")
    return {"status": "received", "type": "generic"}
