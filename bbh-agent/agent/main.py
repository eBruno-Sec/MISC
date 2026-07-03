import asyncio
import json
import os
import uuid
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

from agent import BBHAgent, AI_PROVIDER, OPENROUTER_MODEL
from report import generate_report
from scope import ScopeEngine
from tools import ToolRegistry

app = FastAPI(title="BBH Agent")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

sessions: dict[str, dict] = {}


class EngageRequest(BaseModel):
    program_name: str
    in_scope: list[str]
    out_of_scope: list[str] = []
    objective: Optional[str] = None


@app.get("/")
async def ui():
    return FileResponse("/app/ui/index.html")


@app.get("/config")
async def config():
    model = OPENROUTER_MODEL if AI_PROVIDER == "openrouter" else "claude-sonnet-4-6"
    return {"provider": AI_PROVIDER, "model": model}


@app.post("/engage")
async def engage(req: EngageRequest):
    session_id = str(uuid.uuid4())[:8]

    scope = ScopeEngine()
    scope.load_manual(req.in_scope, req.out_of_scope, req.program_name)

    tools = ToolRegistry(scope)
    stop_event = asyncio.Event()
    agent = BBHAgent(scope, tools, stop_event)

    objective = req.objective or (
        f"Perform comprehensive bug bounty recon and vulnerability discovery on {req.program_name}. "
        f"In-scope targets: {', '.join(req.in_scope)}"
    )

    sessions[session_id] = {
        "scope": scope,
        "agent": agent,
        "stop_event": stop_event,
        "objective": objective,
        "status": "created",
        "streaming": False,
    }

    return {"session_id": session_id}


@app.get("/stream/{session_id}")
async def stream(session_id: str):
    if session_id not in sessions:
        raise HTTPException(404, "Session not found")

    sess = sessions[session_id]
    if sess["streaming"]:
        raise HTTPException(409, "Session already streaming")

    sess["streaming"] = True
    sess["status"] = "running"

    async def event_gen():
        try:
            async for event in sess["agent"].run(sess["objective"], session_id):
                yield f"data: {json.dumps(event)}\n\n"
                await asyncio.sleep(0)
        except asyncio.CancelledError:
            yield f"data: {json.dumps({'type': 'complete', 'content': 'Stream disconnected.'})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"
        finally:
            sess["status"] = "complete"

    return StreamingResponse(
        event_gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.post("/stop/{session_id}")
async def stop(session_id: str):
    if session_id not in sessions:
        raise HTTPException(404, "Session not found")
    sess = sessions[session_id]
    sess["stop_event"].set()
    sess["status"] = "stopped"
    return {"ok": True}


@app.get("/report/{session_id}")
async def get_report(session_id: str):
    if session_id not in sessions:
        raise HTTPException(404, "Session not found")
    sess = sessions[session_id]
    agent: BBHAgent = sess["agent"]
    report = generate_report(sess["scope"].program_name, agent.findings, sess["scope"].to_dict())
    return {"markdown": report, "findings": agent.findings}


@app.get("/status/{session_id}")
async def get_status(session_id: str):
    if session_id not in sessions:
        raise HTTPException(404, "Session not found")
    sess = sessions[session_id]
    return {"status": sess["status"], "findings_count": len(sess["agent"].findings)}


@app.on_event("startup")
async def startup():
    provider = AI_PROVIDER
    if provider == "openrouter" and not os.getenv("OPENROUTER_API_KEY"):
        print("[WARN] AI_PROVIDER=openrouter but OPENROUTER_API_KEY is not set")
    elif provider == "anthropic" and not os.getenv("ANTHROPIC_API_KEY"):
        print("[WARN] AI_PROVIDER=anthropic but ANTHROPIC_API_KEY is not set")

    proc = await asyncio.create_subprocess_exec(
        "nuclei", "-update-templates", "-silent",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    asyncio.create_task(proc.communicate())
