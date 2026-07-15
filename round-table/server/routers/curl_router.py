"""
Advanced cURL console endpoints.

Composes a copy-paste curl command and (optionally) executes it server-side for
manual verification, constrained to the mission scope (or, standalone, to the
host you typed). Operator-driven — this is a manual testing aid, not a scanner.
"""
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..core import curl_tool, db
from ..core import scope as scope_mod

router = APIRouter()


class CurlRequest(BaseModel):
    method: str = "GET"
    url: str = Field(..., min_length=1)
    headers: dict[str, str] = {}
    body: Optional[str] = None
    follow_redirects: bool = False
    insecure: bool = True
    mission_id: Optional[str] = None
    execute: bool = True


def _scope_for(req: CurlRequest) -> dict:
    if req.mission_id:
        m = db.get_mission(req.mission_id)
        if m and m.get("scope"):
            return m["scope"]
    # Standalone: restrict to the host in the URL so the console can't be
    # silently pointed elsewhere. Operator can still change the URL freely.
    host = scope_mod.normalize_target(req.url)
    return {"in_scope": [host, f"*.{host}"], "out_of_scope": [], "allow_active": False}


@router.post("/execute")
async def execute(req: CurlRequest):
    if not req.url.lower().startswith(("http://", "https://")):
        raise HTTPException(400, "url must start with http:// or https://")
    scope = _scope_for(req)
    if not req.execute:
        return {
            "ok": True,
            "executed": False,
            "curl": curl_tool.build_curl(req.method, req.url, req.headers, req.body, req.insecure, req.follow_redirects),
        }
    result = await curl_tool.execute(
        req.method, req.url, req.headers, req.body, scope,
        follow_redirects=req.follow_redirects, insecure=req.insecure,
    )
    result["executed"] = True
    return result


@router.post("/build")
async def build(req: CurlRequest):
    return {"curl": curl_tool.build_curl(req.method, req.url, req.headers, req.body, req.insecure, req.follow_redirects)}
