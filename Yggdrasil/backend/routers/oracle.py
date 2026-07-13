import os

from fastapi import APIRouter
from pydantic import BaseModel

from agents import oracle

router = APIRouter()


class SolveBody(BaseModel):
    lab_title: str = ""
    description: str = ""
    lab_url: str = ""
    category: str = ""
    captured_request: str = ""
    captured_response: str = ""


class FollowupBody(BaseModel):
    lab_title: str = ""
    description: str = ""
    prior: dict = {}
    what_happened: str = ""
    captured_response: str = ""


def _ai_status() -> dict:
    provider = os.getenv("AI_PROVIDER", "anthropic").lower().strip()
    has_key = bool(os.getenv("AI_API_KEY") or os.getenv("ANTHROPIC_API_KEY"))
    model = os.getenv("AI_MODEL", "claude-sonnet-4-6" if provider != "openrouter" else "meta-llama/llama-3.3-70b-instruct")
    return {"provider": provider, "model": model, "configured": has_key}


@router.get("/status")
async def status():
    return _ai_status()


@router.post("/solve")
async def solve(body: SolveBody):
    plan = await oracle.solve(
        lab_title=body.lab_title,
        description=body.description,
        lab_url=body.lab_url,
        category=body.category,
        captured_request=body.captured_request,
        captured_response=body.captured_response,
    )
    return {"plan": plan, "ai": _ai_status()}


@router.post("/followup")
async def followup(body: FollowupBody):
    plan = await oracle.followup(
        lab_title=body.lab_title,
        description=body.description,
        prior=body.prior,
        what_happened=body.what_happened,
        captured_response=body.captured_response,
    )
    return {"plan": plan, "ai": _ai_status()}
