import asyncio
import json
import os
import uuid
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse, HTMLResponse, PlainTextResponse
from pydantic import BaseModel

import db
import poc
import replay as replay_mod
import report as report_mod
import scope as scope_mod
import wordlists as wl
from agent import BBHAgent, AI_PROVIDER, OPENROUTER_MODEL, ANTHROPIC_MODEL
from scope import ScopeEngine
from tools import ToolRegistry

app = FastAPI(title="BBH Agent")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# live sessions (agent + scope + stop_event); persisted state lives in SQLite
sessions: dict = {}
UI_PATH = os.getenv("BBH_UI_PATH", "/app/ui/index.html")


# ── models ───────────────────────────────────────────────────────
class EngageRequest(BaseModel):
    program_name: str
    in_scope: list
    out_of_scope: list = []
    objective: Optional[str] = None
    mode: str = "active"           # passive | active | full
    auto_approve: bool = False


class ReplayRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: dict = {}
    body: Optional[str] = None
    follow_redirects: bool = False


class FuzzRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: dict = {}
    body: Optional[str] = None
    param: str
    param_in: str = "query"
    payloads: list = []
    wordlist_id: Optional[str] = None


class DiffRequest(BaseModel):
    a: ReplayRequest
    b: ReplayRequest


class ProfileRequest(BaseModel):
    name: str
    role: str = ""
    headers: dict = {}
    is_owner: bool = False


class AccessCheckRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: dict = {}
    body: Optional[str] = None


class NoteRequest(BaseModel):
    body: str


class GenerateWordlistRequest(BaseModel):
    base_url: str
    kind: str = "paths"            # paths | credentials


# ── helpers ──────────────────────────────────────────────────────
def _scope_for(sid: str) -> ScopeEngine:
    if sid in sessions:
        return sessions[sid]["scope"]
    m = db.get_mission(sid)
    if not m:
        raise HTTPException(404, "Session not found")
    eng = ScopeEngine()
    sc = m["scope"]
    eng.load_manual(sc.get("in_scope", []), sc.get("out_of_scope", []), sc.get("program", m["program"]))
    return eng


def _scope_guard(eng: ScopeEngine, url: str) -> None:
    ok, reason = eng.validate(url)
    if not ok:
        raise HTTPException(400, f"Off-scope: {reason}")


def _require_mission(sid: str) -> dict:
    m = db.get_mission(sid)
    if not m:
        raise HTTPException(404, "Session not found")
    return m


# ── UI + config ──────────────────────────────────────────────────
@app.get("/")
async def ui():
    return FileResponse(UI_PATH)


@app.get("/config")
async def config():
    model = OPENROUTER_MODEL if AI_PROVIDER == "openrouter" else ANTHROPIC_MODEL
    return {"provider": AI_PROVIDER, "model": model}


# ── mission lifecycle ────────────────────────────────────────────
@app.post("/engage")
async def engage(req: EngageRequest):
    session_id = uuid.uuid4().hex[:8]
    scope = ScopeEngine()
    scope.load_manual(req.in_scope, req.out_of_scope, req.program_name)

    tools = ToolRegistry(scope, mission_id=session_id, lab_mode=(req.mode == "full"))
    stop_event = asyncio.Event()
    agent = BBHAgent(scope, tools, stop_event, mode=req.mode,
                     auto_approve=req.auto_approve, mission_id=session_id)

    objective = req.objective or (
        f"Perform comprehensive bug bounty recon and vulnerability discovery on {req.program_name}. "
        f"In-scope targets: {', '.join(req.in_scope)}")

    db.create_mission(session_id, req.program_name, req.mode, objective, scope.to_dict(),
                      {"auto_approve": req.auto_approve})
    sessions[session_id] = {"scope": scope, "agent": agent, "tools": tools,
                            "stop_event": stop_event, "objective": objective,
                            "status": "created", "streaming": False}
    return {"session_id": session_id, "mode": req.mode}


@app.get("/stream/{session_id}")
async def stream(session_id: str):
    if session_id not in sessions:
        raise HTTPException(404, "Session not found (live agent gone; reload mission from archive)")
    sess = sessions[session_id]
    if sess["streaming"]:
        raise HTTPException(409, "Session already streaming")
    sess["streaming"] = True
    sess["status"] = "running"
    db.update_mission(session_id, status="running")

    async def event_gen():
        try:
            async for event in sess["agent"].run(sess["objective"], session_id):
                db.add_log(session_id, event.get("type", "info"), event)
                if event.get("type") == "phase":
                    db.update_mission(session_id, phase=event.get("phase", ""))
                yield f"data: {json.dumps(event)}\n\n"
                await asyncio.sleep(0)
        except asyncio.CancelledError:
            yield f"data: {json.dumps({'type': 'complete', 'content': 'Stream disconnected.'})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"
        finally:
            sess["status"] = "complete"
            db.update_mission(session_id, status="complete")

    return StreamingResponse(event_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/stop/{session_id}")
async def stop(session_id: str):
    if session_id not in sessions:
        raise HTTPException(404, "Session not found")
    sessions[session_id]["stop_event"].set()
    sessions[session_id]["status"] = "stopped"
    db.update_mission(session_id, status="stopped")
    return {"ok": True}


@app.post("/approve/{session_id}/{approval_id}")
async def approve(session_id: str, approval_id: str, approved: bool = True):
    if session_id not in sessions:
        raise HTTPException(404, "Session not found")
    ok = sessions[session_id]["agent"].resolve_approval(approval_id, approved)
    if not ok:
        raise HTTPException(409, "No matching pending approval")
    return {"ok": True, "resolution": "approved" if approved else "denied"}


@app.get("/status/{session_id}")
async def get_status(session_id: str):
    m = _require_mission(session_id)
    return {"status": m["status"], "phase": m["phase"],
            "findings_count": len(db.get_findings(session_id))}


# ── mission archive ──────────────────────────────────────────────
@app.get("/missions")
async def list_missions():
    return {"missions": db.list_missions()}


@app.get("/missions/{session_id}")
async def mission_detail(session_id: str):
    m = _require_mission(session_id)
    return {
        "mission": {k: m[k] for k in ("id", "program", "mode", "status", "phase", "objective", "created_at")},
        "scope": m["scope"],
        "findings": db.get_findings(session_id),
        "notes": db.get_notes(session_id),
        "logs": db.get_logs(session_id, limit=500),
        "playbook": m["context"].get("playbook", []),
        "playbook_stats": m["context"].get("playbook_stats", {}),
        "chains": m["context"].get("chains", []),
    }


@app.delete("/missions/{session_id}")
async def delete_mission(session_id: str):
    _require_mission(session_id)
    db.delete_mission(session_id)
    sessions.pop(session_id, None)
    return {"ok": True}


# ── reports (markdown / html / csv / json / poc) ─────────────────
def _report_bundle(session_id: str):
    m = _require_mission(session_id)
    findings = db.get_findings(session_id)
    ctx = m["context"]
    coverage = _coverage(session_id)
    return m, findings, m["scope"], coverage, ctx.get("chains", [])


def _coverage(session_id: str) -> dict:
    logs = db.get_logs(session_id, limit=2000)
    tools_run = {}
    for l in logs:
        if l.get("type") == "tool_call":
            tools_run[l.get("tool")] = tools_run.get(l.get("tool"), 0) + 1
    return {"tools_invoked": sum(tools_run.values()), "distinct_tools": len(tools_run),
            "surface_urls": len(sessions.get(session_id, {}).get("tools").urls) if session_id in sessions else "n/a",
            "findings": len(db.get_findings(session_id))}


@app.get("/report/{session_id}")
async def get_report(session_id: str):
    m, findings, scope, coverage, chains = _report_bundle(session_id)
    md = report_mod.generate_report(m["program"], findings, scope, coverage, chains)
    return {"markdown": md, "findings": findings}


@app.get("/report/{session_id}/html")
async def get_report_html(session_id: str):
    m, findings, scope, coverage, chains = _report_bundle(session_id)
    return HTMLResponse(report_mod.generate_html_report(m["program"], findings, scope, coverage, chains))


@app.get("/report/{session_id}/csv")
async def get_report_csv(session_id: str):
    _, findings, _, _, _ = _report_bundle(session_id)
    return PlainTextResponse(report_mod.findings_csv(findings), media_type="text/csv")


@app.get("/report/{session_id}/json")
async def get_report_json(session_id: str):
    m, findings, scope, coverage, chains = _report_bundle(session_id)
    return PlainTextResponse(report_mod.findings_json(m["program"], findings, scope, coverage, chains),
                             media_type="application/json")


@app.get("/report/{session_id}/poc")
async def get_report_poc(session_id: str, redact: bool = True):
    m = _require_mission(session_id)
    findings = db.get_findings(session_id)
    ex_by_f = {f.get("id"): db.get_exchanges(session_id, f.get("id")) for f in findings}
    md = poc.mission_markdown(m["program"], findings, ex_by_f, redact=redact)
    return PlainTextResponse(md, media_type="text/markdown")


# ── attack surface + evidence + playbook ─────────────────────────
@app.get("/surface/{session_id}")
async def get_surface(session_id: str):
    _require_mission(session_id)
    if session_id in sessions:
        return sessions[session_id]["tools"].surface_inventory()
    return {"inventory": [], "stats": {}}


@app.get("/exchanges/{session_id}")
async def get_exchanges(session_id: str):
    _require_mission(session_id)
    return {"exchanges": db.get_exchanges(session_id)}


@app.get("/playbook/{session_id}")
async def get_playbook(session_id: str):
    m = _require_mission(session_id)
    return {"playbook": m["context"].get("playbook", []),
            "stats": m["context"].get("playbook_stats", {})}


# ── workbench: repeater / intruder / diff (scope-guarded) ────────
@app.post("/workbench/{session_id}/replay")
async def wb_replay(session_id: str, req: ReplayRequest):
    eng = _scope_for(session_id)
    _scope_guard(eng, req.url)
    async with replay_mod.client(req.follow_redirects) as c:
        r = await replay_mod.send(c, req.method, req.url, req.headers, req.body)
    if session_id in sessions or db.get_mission(session_id):
        db.add_exchange(session_id, {"url": req.url, "method": req.method,
                                     "request_headers": req.headers, "request_body": req.body,
                                     "status_code": r["status"], "response_headers": r["headers"],
                                     "response_body": r["body"][:4000], "notes": "workbench replay"})
    r["curl"] = poc.to_curl({"url": req.url, "method": req.method,
                             "request_headers": req.headers, "request_body": req.body})
    r["body"] = r["body"][:8000]
    return r


@app.post("/workbench/{session_id}/fuzz")
async def wb_fuzz(session_id: str, req: FuzzRequest):
    eng = _scope_for(session_id)
    _scope_guard(eng, req.url)
    payloads = list(req.payloads)
    if req.wordlist_id:
        payloads += wl.get_words(req.wordlist_id)
    if not payloads:
        raise HTTPException(400, "Provide payloads or a wordlist_id")
    async with replay_mod.client() as c:
        result = await replay_mod.fuzz(c, req.method, req.url, req.headers, req.body,
                                       req.param, req.param_in, payloads)
    return result


@app.post("/workbench/{session_id}/diff")
async def wb_diff(session_id: str, req: DiffRequest):
    eng = _scope_for(session_id)
    _scope_guard(eng, req.a.url)
    _scope_guard(eng, req.b.url)
    async with replay_mod.client() as c:
        ra = await replay_mod.send(c, req.a.method, req.a.url, req.a.headers, req.a.body)
        rb = await replay_mod.send(c, req.b.method, req.b.url, req.b.headers, req.b.body)
    return replay_mod.diff_responses(ra, rb)


# ── cURL console (Round Table): send one scoped request ─────────
@app.post("/curl/{session_id}")
async def curl_console(session_id: str, req: ReplayRequest):
    eng = _scope_for(session_id)
    _scope_guard(eng, req.url)
    async with replay_mod.client(req.follow_redirects) as c:
        r = await replay_mod.send(c, req.method, req.url, req.headers, req.body)
    return {
        "status": r["status"], "length": r["length"], "duration_ms": r["duration_ms"],
        "headers": r["headers"], "body": r["body"][:12000],
        "curl": poc.to_curl({"url": req.url, "method": req.method,
                             "request_headers": req.headers, "request_body": req.body}, redact=False),
    }


# ── cross-role access control (IDOR / BOLA / BFLA) ───────────────
@app.get("/profiles/{session_id}")
async def list_profiles(session_id: str):
    _require_mission(session_id)
    return {"profiles": db.get_profiles(session_id, redacted=True)}


@app.post("/profiles/{session_id}")
async def add_profile(session_id: str, req: ProfileRequest):
    _require_mission(session_id)
    pid = db.add_profile(session_id, req.name, req.role, req.headers, req.is_owner)
    return {"id": pid}


@app.delete("/profiles/{session_id}/{pid}")
async def del_profile(session_id: str, pid: str):
    db.delete_profile(pid)
    return {"ok": True}


@app.post("/access-check/{session_id}")
async def access_check(session_id: str, req: AccessCheckRequest):
    eng = _scope_for(session_id)
    _scope_guard(eng, req.url)
    profiles = db.get_profiles_raw(session_id)
    results = []
    async with replay_mod.client() as c:
        # anonymous baseline
        try:
            anon = await replay_mod.send(c, req.method, req.url, req.headers, req.body)
            results.append({"role": "anonymous", "status": anon["status"], "length": anon["length"],
                            "is_owner": False, "is_anon": True})
        except Exception as e:
            results.append({"role": "anonymous", "error": str(e), "is_anon": True})
        for p in profiles:
            h = {**req.headers, **p["headers"]}
            try:
                r = await replay_mod.send(c, req.method, req.url, h, req.body)
                results.append({"role": p["name"], "status": r["status"], "length": r["length"],
                                "is_owner": p["is_owner"], "is_anon": False})
            except Exception as e:
                results.append({"role": p["name"], "error": str(e), "is_owner": p["is_owner"]})
    verdict = replay_mod.access_verdict(results)
    return {"url": req.url, "results": results, **verdict}


# ── findings CRUD ────────────────────────────────────────────────
@app.get("/findings/{session_id}")
async def get_findings(session_id: str):
    _require_mission(session_id)
    return {"findings": db.get_findings(session_id)}


@app.post("/findings/{session_id}")
async def add_finding(session_id: str, finding: dict):
    _require_mission(session_id)
    fid = db.add_finding(session_id, finding)
    return {"id": fid}


@app.put("/findings/{session_id}/{fid}")
async def update_finding(session_id: str, fid: str, finding: dict):
    _require_mission(session_id)
    db.update_finding(fid, finding)
    return {"ok": True}


@app.delete("/findings/{session_id}/{fid}")
async def delete_finding(session_id: str, fid: str):
    db.delete_finding(fid)
    return {"ok": True}


# ── notes ────────────────────────────────────────────────────────
@app.get("/notes/{session_id}")
async def get_notes(session_id: str):
    _require_mission(session_id)
    return {"notes": db.get_notes(session_id)}


@app.post("/notes/{session_id}")
async def add_note(session_id: str, req: NoteRequest):
    _require_mission(session_id)
    return {"id": db.add_note(session_id, req.body)}


@app.delete("/notes/{session_id}/{nid}")
async def delete_note(session_id: str, nid: str):
    db.delete_note(nid)
    return {"ok": True}


# ── wordlists ────────────────────────────────────────────────────
@app.get("/wordlists")
async def wordlists_catalog():
    return {"wordlists": wl.catalog()}


@app.get("/wordlists/{wid}")
async def wordlist_words(wid: str):
    words = wl.get_words(wid)
    if not words:
        raise HTTPException(404, "Unknown wordlist")
    return {"id": wid, "words": words}


@app.post("/wordlists/generate")
async def wordlist_generate(req: GenerateWordlistRequest):
    if req.kind == "credentials":
        from urllib.parse import urlparse
        host = urlparse(req.base_url).hostname or req.base_url
        return {"words": wl.target_credentials(host)}
    return {"words": wl.target_paths(req.base_url)}


# ── scope parsing (multi-format upload) ──────────────────────────
@app.post("/scope/parse")
async def parse_scope(file: Optional[UploadFile] = File(None), text: Optional[str] = Form(None)):
    if file:
        raw = await file.read()
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            content = raw.decode("latin-1")
    elif text:
        content = text
    else:
        raise HTTPException(400, "Provide a file upload or raw text")
    parsed = scope_mod.parse_scope(content)
    ins, outs = scope_mod.web_targets(parsed)
    return {"format_detected": parsed.get("format"),
            "in_scope": parsed["in_scope"], "out_of_scope": parsed["out_of_scope"],
            "web_in_scope": ins, "web_out_of_scope": outs,
            "total_in": len(parsed["in_scope"]), "total_out": len(parsed["out_of_scope"])}


# ── backup / restore ─────────────────────────────────────────────
@app.get("/backup/{session_id}")
async def backup(session_id: str):
    m = _require_mission(session_id)
    data = {
        "bbh_backup_version": 1,
        "mission": {k: m[k] for k in ("id", "program", "mode", "status", "phase", "objective", "created_at")},
        "scope": m["scope"],
        "findings": db.get_findings(session_id),
        "notes": db.get_notes(session_id),
        "logs": db.get_logs(session_id, limit=500),
        "context": m["context"],
    }
    return PlainTextResponse(json.dumps(data, indent=2, default=str),
                             media_type="application/json",
                             headers={"Content-Disposition": f'attachment; filename="BBH_backup_{session_id}.json"'})


@app.post("/restore")
async def restore(payload: dict):
    if payload.get("bbh_backup_version") != 1 or "mission" not in payload or "scope" not in payload:
        raise HTTPException(422, "Invalid or corrupted progress file")
    new_id = uuid.uuid4().hex[:8]
    mm = payload["mission"]
    ctx = dict(payload.get("context", {}))
    ctx["imported"] = True
    db.create_mission(new_id, mm.get("program", "Imported"), mm.get("mode", "active"),
                      mm.get("objective", ""), payload["scope"], ctx)
    db.update_mission(new_id, status="complete", phase="report")
    for f in payload.get("findings", []):
        f.pop("id", None)
        db.add_finding(new_id, f)
    for n in payload.get("notes", []):
        db.add_note(new_id, n.get("body", ""))
    return {"session_id": new_id, "imported": True}


# ── startup ──────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    db.init()
    provider = AI_PROVIDER
    if provider == "openrouter" and not os.getenv("OPENROUTER_API_KEY"):
        print("[WARN] AI_PROVIDER=openrouter but OPENROUTER_API_KEY is not set")
    elif provider == "anthropic" and not os.getenv("ANTHROPIC_API_KEY"):
        print("[WARN] AI_PROVIDER=anthropic but ANTHROPIC_API_KEY is not set")

    # background nuclei template update (best-effort; skipped if binary absent)
    import shutil
    if shutil.which("nuclei"):
        proc = await asyncio.create_subprocess_exec(
            "nuclei", "-update-templates", "-silent",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        asyncio.create_task(proc.communicate())
