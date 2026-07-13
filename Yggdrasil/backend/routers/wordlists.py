import os

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse, FileResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_session
from core.models import Mission
from core import wordlists as wl

router = APIRouter()


class GenerateBody(BaseModel):
    extra_paths: list[str] = []


@router.get("")
async def list_wordlists():
    cat = wl.catalog()
    return {
        "wordlists": cat,
        "default_content_ids": wl.DEFAULT_CONTENT_IDS,
        "total": len(cat),
        "available": sum(1 for c in cat if c["exists"]),
    }


@router.get("/{wid}/preview", response_class=PlainTextResponse)
async def preview_wordlist(wid: str, lines: int = 50):
    path = wl.path_for_id(wid)
    if not path:
        raise HTTPException(404, "Wordlist not found or not present on disk.")
    out = []
    with open(path, "r", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= max(1, min(lines, 500)):
                break
            out.append(line.rstrip("\n"))
    return "\n".join(out)


@router.get("/{wid}/download")
async def download_wordlist(wid: str):
    path = wl.path_for_id(wid)
    if not path:
        raise HTTPException(404, "Wordlist not found or not present on disk.")
    return FileResponse(path, media_type="text/plain",
                        filename=os.path.basename(path))


@router.post("/generate/{mission_id}")
async def generate_for_mission(
    mission_id: str,
    body: GenerateBody,
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(select(Mission).where(Mission.id == mission_id))
    mission = result.scalar_one_or_none()
    if not mission:
        raise HTTPException(404, "Mission not found.")

    hermes = (mission.context or {}).get("hermes", {})
    if not hermes:
        # allow generation from just the target if recon has not populated yet
        hermes = {"domain": mission.target, "subdomains": [], "vendors": [], "technologies": {}}

    entry = wl.build_target_list(mission_id, hermes, body.extra_paths)
    return {"generated": entry}
