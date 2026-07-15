"""Mission lifecycle: create/launch, inspect, guidance, topology, reports."""
import asyncio
import re
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field

from ..core import db, report as report_mod, scope as scope_mod
from ..core.hub import hub

router = APIRouter()

VALID_MODES = {"passive", "active", "full"}


class LaunchRequest(BaseModel):
    target: str = Field(..., min_length=1)
    mode: str = "passive"
    scope_text: Optional[str] = None


@router.post("")
async def launch(req: LaunchRequest):
    mode = req.mode.lower().strip()
    if mode not in VALID_MODES:
        raise HTTPException(400, f"mode must be one of {sorted(VALID_MODES)}")
    target = scope_mod.normalize_target(req.target)
    # Accept a domain, a bare host / container name, or host:port
    # (e.g. example.com, juice-shop:3000, host.docker.internal:42000).
    if not target or not re.match(r"^[a-z0-9]([a-z0-9.\-]*[a-z0-9])?(:\d{1,5})?$", target):
        raise HTTPException(400, "target must be a domain, host, or host:port (e.g. example.com or juice-shop:3000)")

    host, _ = scope_mod.split_host_port(target)
    scope = scope_mod.parse_scope_text(req.scope_text) if req.scope_text else scope_mod.default_scope(target)
    if not scope.get("in_scope"):
        scope["in_scope"] = [host, f"*.{host}"]

    mid = db.create_mission(target, mode, scope)
    db.add_event(mid, "info", "mission", f"Mission queued for {target} ({mode} mode)")
    # Fire-and-forget; hub serializes execution behind a lock.
    asyncio.create_task(hub.run_mission(mid))
    return {"id": mid, "target": target, "mode": mode, "status": "queued", "scope": scope}


@router.get("")
async def list_missions(limit: int = 100):
    return {"missions": db.list_missions(limit)}


@router.get("/{mid}")
async def get_mission(mid: str):
    m = db.get_mission(mid)
    if not m:
        raise HTTPException(404, "mission not found")
    return m


@router.delete("/{mid}")
async def delete_mission(mid: str):
    if not db.get_mission(mid):
        raise HTTPException(404, "mission not found")
    db.delete_mission(mid)
    return {"deleted": mid}


@router.get("/{mid}/events")
async def events(mid: str, after: int = 0):
    if not db.get_mission(mid):
        raise HTTPException(404, "mission not found")
    return {"events": db.get_events(mid, after)}


@router.get("/{mid}/guidance")
async def guidance(mid: str, severity: Optional[str] = None, q: Optional[str] = None):
    m = db.get_mission(mid)
    if not m:
        raise HTTPException(404, "mission not found")
    items = (m.get("result") or {}).get("guidance", [])
    if severity:
        wanted = {s.strip().upper() for s in severity.split(",")}
        items = [g for g in items if g["severity"] in wanted]
    if q:
        ql = q.lower()
        items = [g for g in items if ql in g["title"].lower() or ql in g["surface"].lower() or ql in " ".join(g.get("tags", []))]
    return {"guidance": items, "count": len(items)}


@router.get("/{mid}/topology")
async def topology(mid: str):
    m = db.get_mission(mid)
    if not m:
        raise HTTPException(404, "mission not found")
    return (m.get("result") or {}).get("topology", {"nodes": [], "links": []})


@router.get("/{mid}/report")
async def report(mid: str, format: str = Query("html", pattern="^(html|md|markdown|csv|json)$")):
    m = db.get_mission(mid)
    if not m:
        raise HTTPException(404, "mission not found")
    target = m.get("target", "target")
    if format == "html":
        return Response(report_mod.generate_html(m), media_type="text/html")
    if format in ("md", "markdown"):
        return PlainTextResponse(
            report_mod.generate_markdown(m),
            headers={"Content-Disposition": f'attachment; filename="roundtable_{target}.md"'},
        )
    if format == "csv":
        return Response(
            report_mod.generate_csv(m), media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="roundtable_{target}.csv"'},
        )
    return Response(
        report_mod.generate_json(m), media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="roundtable_{target}.json"'},
    )
