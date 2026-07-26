import asyncio
import json
import os
import re
import uuid
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse, HTMLResponse, PlainTextResponse
from pydantic import BaseModel

import db
import graph_model
import memory as memory_mod
import poc
import replay as replay_mod
import report as report_mod
import scope as scope_mod
import surface as surface_mod
import tools as tools_mod
import wordlists as wl
from agent import BBHAgent, ai_status
from scope import ScopeEngine
from tools import ToolRegistry

app = FastAPI(title="Apolaki")
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
    # authenticated scanning: raw session headers and/or an auto-login
    auth_headers: dict = {}        # e.g. {"Cookie": "session=..."} or {"Authorization": "Bearer ..."}
    login: Optional[dict] = None   # {"url": ..., "username": ..., "password": ...}
    parent_id: Optional[str] = None  # rescan: link this new mission to the one it was cloned from
    recon_cycles: int = 1            # iterative recon: 1 (default, unchanged) .. 3
    strategy: Optional[str] = None   # manual | deterministic | low_ai | agentic (default: deterministic)
    max_ai_calls: Optional[int] = None  # override the per-strategy AI-call budget
    # OWASP ZAP DAST — opt-in from the scan setup UI. enable_zap OFF (default) means
    # ZAP never runs (report: "user disabled"); nothing else changes. When ON, ZAP
    # runs in Full mode with zap_policy. require_zap makes it mandatory: an
    # unavailable ZAP BLOCKS the scan with an actionable error instead of silently
    # downgrading to no-ZAP.
    enable_zap: bool = False
    zap_policy: str = "safe_active"   # passive | safe_active | thorough_active
    # Two INDEPENDENT dials: speed = request pacing (how fast/polite); aggression =
    # ZAP attack strength (how hard it hits each parameter). Orthogonal — e.g. a
    # turtle-speed + demon-aggression scan is slow on the network but throws every
    # payload at each param.
    zap_speed: str = "normal"         # turtle (slow/polite) | normal | fast
    zap_aggression: str = "normal"    # low | normal | demon (max attack strength)
    require_zap: bool = False
    # Heavyweight nmap NSE vulnerability scan (full `vuln` category minus DoS) on
    # in-scope hosts. Opt-in; runs in Full mode only. Results are advisory leads.
    enable_nmap_vuln: bool = False
    # Heavy nuclei mode — the full vulnerability template set (CVEs/network/misconfig/
    # exposures/default-creds/SSL). Opt-in, Full mode only; results are advisory leads.
    enable_nuclei_heavy: bool = False
    # Intensity dial — how HARD each heavy tool hits an in-scope target (orthogonal to
    # `mode`, which is the permission gate). standard = today's light/fast flags (default,
    # no regression); deep = thorough; insane = maximum coverage (can run for hours).
    # Truth-first is unchanged: heavier flags surface more candidates, not more confirmations.
    intensity: str = "standard"       # standard | deep | insane


class EstimateRequest(BaseModel):
    in_scope: list = []
    mode: str = "active"
    strategy: Optional[str] = None


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


def _warm_start(scope: ScopeEngine, tools: ToolRegistry, agent) -> dict:
    """Seed a new mission's surface from prior-mission memory on the same target.

    Returns a small summary ({seeded, subdomains, hosts, endpoints, prior_findings})
    for the UI/log; also sets ``agent.memory_note`` so the model knows these
    assets are already known and can go straight to deeper coverage. Everything is
    scope-validated here, so a since-changed scope silently drops stale intel."""
    tkey = memory_mod.target_key(scope.to_dict())
    assets = db.get_memory_assets(tkey)
    if not assets:
        return {"seeded": False}

    subs = [a["value"] for a in assets.get("subdomains", []) if scope.validate(a["value"])[0]]
    for s in subs:
        if s not in tools.recon["subdomains"]:
            tools.recon["subdomains"].append(s)

    host_urls = [f"https://{a['value']}" for a in assets.get("hosts", [])]
    ep_urls = []
    for a in assets.get("endpoints", []):
        v = a["value"]                        # stored as "host/path"
        ep_urls.append("https://" + v if "://" not in v else v)
    before = len(tools.urls)
    tools._add_urls(host_urls + ep_urls)      # each URL re-validated against scope
    seeded_urls = len(tools.urls) - before

    prior = db.get_prior_snapshot(tkey)
    prior_findings = len(prior.get("findings", [])) if prior else 0

    summary = {"seeded": bool(subs or seeded_urls), "subdomains": len(subs),
               "endpoints": seeded_urls, "prior_findings": prior_findings,
               "assets_known": sum(len(v) for v in assets.values())}
    if summary["seeded"] or prior_findings:
        agent.memory_note = (
            f"\n\nPRIOR INTEL (cross-session memory for this target): a previous mission already "
            f"mapped {len(subs)} in-scope subdomain(s) and {seeded_urls} endpoint(s), now pre-loaded into "
            f"the attack surface, and confirmed {prior_findings} finding(s). Do NOT waste cycles rediscovering "
            "these — treat them as known, verify they still hold, and spend your effort finding NEW surface and "
            "NEW vulnerabilities beyond what was seen before. Every seeded asset is already scope-validated.")
    return summary


# ── UI + config ──────────────────────────────────────────────────
@app.get("/")
async def ui():
    # no-store so a rebuilt image never serves a browser-cached stale index.html
    # (a stale UI is the most likely reason a JS fix appears "not applied").
    return FileResponse(UI_PATH, headers={"Cache-Control": "no-store, must-revalidate"})


@app.get("/health")
async def health():
    """Liveness probe for Docker / monitoring. Cheap, no secrets, always 200 when
    the app is up; reports AI readiness so a health check can also see config."""
    return {"status": "ok", "app": "apolaki", "ai_ready": ai_status().get("ready", False),
            "xss_confirm": tools_mod.xss_confirm_status()}


@app.get("/config")
async def config():
    import collaborator as collab
    # ai_status() reports the effective provider/model/base_url + credential
    # readiness; it never returns the API key.
    return {**ai_status(), "oob_enabled": collab.enabled(), "oob_base": collab.base(),
            "xss_confirm": tools_mod.xss_confirm_status()}


@app.get("/zap/status")
async def zap_status():
    """Live ZAP DAST availability for the scan-setup UI, so a user can see 'ZAP
    Ready / Not Running / Misconfigured' before starting — no Docker guesswork.
    Never returns the ZAP API key."""
    import zap_client
    h = await zap_client.health()
    if not h["configured"]:
        state, label = "not_configured", "ZAP Not Configured"
    elif h["running"]:
        state, label = "ready", f"ZAP Ready (v{h['version']})"
    else:
        state, label = "not_running", "ZAP Not Running"
    return {"state": state, "label": label, "configured": h["configured"],
            "running": h["running"], "version": h["version"], "addr": h["addr"],
            "policies": ["passive", "safe_active", "thorough_active"], "error": h["error"]}


# ── native OOB collaborator: inbound interaction sink + correlation ──
# include_in_schema=False: this one path answers 7 methods, which otherwise makes
# FastAPI emit a duplicate-operation-id warning at startup. It's an internal sink,
# not part of the API surface, so keeping it out of the schema is correct anyway.
@app.api_route("/oob/{token:path}", include_in_schema=False,
               methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"])
async def oob_sink(token: str, request: Request):
    """Catch-all endpoint that records any inbound OOB interaction. A blind-vuln
    probe injected earlier points a target's server here; the callback is the
    proof. Returns a tiny, harmless 200."""
    import collaborator as collab
    tok = collab.token_from_request(f"oob/{token}", request.headers.get("host", ""))
    collab.record(tok, {
        "source_ip": request.client.host if request.client else "?",
        "method": request.method, "path": "/oob/" + token,
        "host": request.headers.get("host", ""), "ua": request.headers.get("user-agent", "")})
    return PlainTextResponse("ok")


@app.get("/api/oob/{token}")
async def oob_hits(token: str):
    import collaborator as collab
    return {"token": token, "interactions": collab.hits(token)}


# ── mission lifecycle ────────────────────────────────────────────
@app.post("/engage")
async def engage(req: EngageRequest):
    # Resolve the execution strategy. DEFAULT IS DETERMINISTIC — the proof-first engine
    # is peak for finding + confirming vulnerabilities (every confirmation is a
    # deterministic oracle, never a model's opinion), and empirically AI strategy never
    # moved the confirmed-finding count. AI (low_ai/agentic) is an opt-in ENHANCEMENT
    # layer (narrative + business-logic reasoning) on top of the deterministic floor.
    st = ai_status()
    strategy = req.strategy or "deterministic"
    if strategy not in ("manual", "deterministic", "low_ai", "agentic"):
        raise HTTPException(422, "strategy must be manual | deterministic | low_ai | agentic")
    # Credential preflight only for AI strategies — deterministic/manual need none.
    if strategy in ("low_ai", "agentic") and not st["ready"]:
        raise HTTPException(422, st["hint"])
    if not req.in_scope:
        raise HTTPException(422, "At least one in-scope target is required.")

    # ZAP configuration + preflight. require_zap implies enable_zap.
    if req.zap_policy not in ("passive", "safe_active", "thorough_active"):
        raise HTTPException(422, "zap_policy must be passive | safe_active | thorough_active")
    if req.zap_speed not in ("turtle", "normal", "fast"):
        raise HTTPException(422, "zap_speed must be turtle | normal | fast")
    if req.zap_aggression not in ("low", "normal", "demon"):
        raise HTTPException(422, "zap_aggression must be low | normal | demon")
    enable_zap = bool(req.enable_zap or req.require_zap)
    if enable_zap and req.mode != "full":
        raise HTTPException(422, "ZAP (DAST) only runs in Full mode. Select Full mode, or turn off Enable ZAP.")
    if req.enable_nmap_vuln and req.mode != "full":
        raise HTTPException(422, "The nmap NSE vuln scan is intrusive and only runs in Full mode. "
                                 "Select Full mode, or turn off the NSE vuln scan.")
    if req.enable_nuclei_heavy and req.mode != "full":
        raise HTTPException(422, "Heavy nuclei (full vuln template set) is intrusive and only runs in "
                                 "Full mode. Select Full mode, or turn off heavy nuclei.")
    if req.intensity not in ("standard", "deep", "insane"):
        raise HTTPException(422, "intensity must be standard | deep | insane")
    if req.intensity in ("deep", "insane") and req.mode != "full":
        raise HTTPException(422, f"intensity '{req.intensity}' turns the intrusive tools up to heavy settings "
                                 "and only runs in Full mode. Select Full mode, or use standard intensity.")
    if req.require_zap:
        # fail closed — a required-but-unavailable ZAP blocks the scan with an
        # actionable error rather than silently downgrading to no-ZAP.
        import zap_client
        h = await zap_client.health(timeout=8)
        if not h["configured"]:
            raise HTTPException(422, "ZAP required but not configured (ZAP_ADDR is unset). Start the zap "
                                     "service (it is on by default) or set ZAP_ADDR.")
        if not h["running"]:
            raise HTTPException(503, f"ZAP required but the daemon at {h['addr']} is unavailable "
                                     f"({h['error']}). Start/repair the zap service, then retry.")

    session_id = uuid.uuid4().hex[:8]
    scope = ScopeEngine()
    scope.load_manual(req.in_scope, req.out_of_scope, req.program_name)

    # authenticated scanning: raw headers first, then optional auto-login (scoped).
    # Drop empty-value headers (e.g. the UI's prefilled template names) so they
    # never break a scan.
    session_headers = {k: v for k, v in (req.auth_headers or {}).items() if str(v).strip()}
    auth_note = ""
    if req.login and req.login.get("url"):
        import auth as auth_mod
        if not scope.validate(req.login["url"])[0]:
            auth_note = "login URL is out of scope — skipped"
        else:
            res = await auth_mod.login(req.login["url"], req.login.get("username", ""),
                                       req.login.get("password", ""))
            session_headers.update(res.get("headers", {}))
            auth_note = res.get("note", "")

    tools = ToolRegistry(scope, mission_id=session_id, lab_mode=(req.mode == "full"),
                         session_headers=session_headers, intensity=req.intensity)
    stop_event = asyncio.Event()
    # A fresh agent + stop_event per mission — rescans clone config into a NEW
    # session and never reuse a prior mission's in-memory objects.
    recon_cycles = max(1, min(int(req.recon_cycles or 1), 3))
    agent = BBHAgent(scope, tools, stop_event, mode=req.mode,
                     auto_approve=req.auto_approve, mission_id=session_id, recon_cycles=recon_cycles,
                     strategy=strategy, max_ai_calls=req.max_ai_calls,
                     enable_zap=enable_zap, zap_policy=req.zap_policy,
                     zap_speed=req.zap_speed, zap_aggression=req.zap_aggression,
                     enable_nmap_vuln=req.enable_nmap_vuln, enable_nuclei_heavy=req.enable_nuclei_heavy)

    # ── warm-start from cross-session memory ─────────────────────────
    # If a prior mission on the SAME target (keyed by scope, not id) left intel,
    # seed the known-good subdomains / hosts / endpoints back in — every value is
    # re-validated against THIS mission's scope, so a tightened scope drops stale
    # assets. No prior memory ⇒ nothing seeded and the scan behaves as a cold run.
    warm_start = _warm_start(scope, tools, agent)

    objective = req.objective or (
        f"Perform comprehensive bug bounty recon and vulnerability discovery on {req.program_name}. "
        f"In-scope targets: {', '.join(req.in_scope)}")

    context = {"auto_approve": req.auto_approve,
               "authenticated": bool(session_headers), "auth_note": auth_note,
               "recon_cycles": recon_cycles, "warm_start": warm_start,
               "strategy": strategy, "max_ai_calls": agent.max_ai_calls,
               "enable_zap": enable_zap, "zap_policy": req.zap_policy,
               "zap_speed": req.zap_speed, "zap_aggression": req.zap_aggression,
               "intensity": req.intensity}
    if req.parent_id and db.get_mission(req.parent_id):
        context["parent_id"] = req.parent_id   # archive parent/child linkage
    db.create_mission(session_id, req.program_name, req.mode, objective, scope.to_dict(), context)
    sessions[session_id] = {"scope": scope, "agent": agent, "tools": tools,
                            "stop_event": stop_event, "objective": objective,
                            "status": "created", "events": [], "task": None, "done": False}
    # /engage only PREPARES the mission (status=created). An API/CLI caller that
    # stops here sees no progress forever; the UI hides this by opening /stream.
    # Tell every caller explicitly how to start the run.
    return {"session_id": session_id, "mode": req.mode,
            "authenticated": bool(session_headers), "auth_note": auth_note,
            "parent_id": context.get("parent_id"), "warm_start": warm_start,
            "strategy": strategy, "max_ai_calls": agent.max_ai_calls,
            "status": "created", "started": False,
            "next_step": f"POST /run/{session_id} (or open GET /stream/{session_id}) to begin the scan",
            "run_url": f"/run/{session_id}", "stream_url": f"/stream/{session_id}"}


@app.post("/estimate")
async def estimate(req: EstimateRequest):
    """Pre-launch estimate of deterministic workload + AI-call budget per strategy,
    so the UI can show 'this will use ~N AI calls' before Start."""
    import planner
    st = ai_status()
    strategy = req.strategy or "deterministic"      # default deterministic (see engage)
    roots = sorted({(v or "").lower().lstrip("*.").split("/")[0] for v in (req.in_scope or []) if v})
    det = planner.estimate(req.mode, roots)
    ai_budget = {"manual": 0, "deterministic": 0, "low_ai": 2, "agentic": "≤40 (ReAct)"}.get(strategy, 0)
    return {"strategy": strategy, "mode": req.mode, "ai_ready": st["ready"],
            "deterministic_steps": det, "estimated_ai_calls": ai_budget}


@app.post("/run/{session_id}")
async def run_mission(session_id: str):
    """Start execution WITHOUT opening an SSE stream — for API-only clients.

    /stream also starts the run (that's the UI path), but a caller that only POSTs
    /engage and never streams would otherwise sit at 'created'. This kicks off the
    same background task; poll /status and read /missions/{id} logs for progress."""
    if session_id not in sessions:
        raise HTTPException(404, "Session not found")
    _ensure_run_started(session_id)   # idempotent
    return {"ok": True, "status": sessions[session_id]["status"]}


@app.get("/stream/{session_id}")
async def stream(session_id: str):
    if session_id not in sessions:
        raise HTTPException(404, "Session not found (live agent gone; reload mission from archive)")
    sess = sessions[session_id]
    _ensure_run_started(session_id)   # idempotent — the run is a background task

    async def event_gen():
        # Replay buffered events first (so a reconnecting client catches up), then
        # tail live. Client disconnect (CancelledError) just stops this consumer —
        # the background task keeps running and owns the final status.
        idx = 0
        try:
            while True:
                events = sess["events"]
                while idx < len(events):
                    ev = events[idx]
                    idx += 1
                    yield f"data: {json.dumps(ev)}\n\n"
                if sess.get("done") and idx >= len(sess["events"]):
                    break
                await asyncio.sleep(0.2)
        except asyncio.CancelledError:
            return   # viewer left; do NOT touch mission status

    return StreamingResponse(event_gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/stop/{session_id}")
async def stop(session_id: str):
    if session_id not in sessions:
        raise HTTPException(404, "Session not found")
    sessions[session_id]["stop_event"].set()
    # The background task sets the terminal 'stopped' status when the agent loop
    # unwinds; reflect the intent immediately for the UI.
    sessions[session_id]["status"] = "stopping"
    db.update_mission(session_id, status="stopping")
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
        "mission": {**{k: m[k] for k in ("id", "program", "mode", "status", "phase", "objective", "created_at")},
                    "parent_id": m["context"].get("parent_id"),
                    "recon_cycles": m["context"].get("recon_cycles", 1),
                    "strategy": m["context"].get("strategy", "agentic"),
                    "ai_summary": m["context"].get("ai_summary", "")},
        "scope": m["scope"],
        "findings": db.get_findings(session_id),
        "notes": db.get_notes(session_id),
        "logs": db.get_logs(session_id, limit=500),
        "playbook": m["context"].get("playbook", []),
        "playbook_stats": m["context"].get("playbook_stats", {}),
        "chains": m["context"].get("chains", []),
        "leads": m["context"].get("leads", []),
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


def _ai_summary(m) -> str:
    return (m.get("context", {}) or {}).get("ai_summary", "")


def _execution(m) -> dict:
    return (m.get("context", {}) or {}).get("execution", {})


def _leads(m) -> list:
    return (m.get("context", {}) or {}).get("leads", [])


def _attack_surface(session_id: str) -> dict:
    """Attack-surface metrics for the report (works live or archived, via the same
    recon/urls source the graph uses)."""
    recon, urls, _ = _graph_inputs(session_id)
    inv = surface_mod.build_inventory(urls or [])
    params = set()
    for ep in inv:
        params.update(ep.get("params") or [])
    return {
        "subdomains": len(recon.get("subdomains") or []),
        "live_hosts": len(recon.get("live_hosts") or []),
        "endpoints": len(inv),
        "parameterized": sum(1 for ep in inv if ep.get("parameterized")),
        "params": len(params),
        "body_sinks": sum(1 for ep in inv if ep.get("body_sink")),
    }


def _coverage(session_id: str) -> dict:
    logs = db.get_logs(session_id, limit=2000)
    tools_run = {}
    for l in logs:
        if l.get("type") == "tool_call":
            tools_run[l.get("tool")] = tools_run.get(l.get("tool"), 0) + 1
    return {"tools_invoked": sum(tools_run.values()), "distinct_tools": len(tools_run),
            "surface_urls": len(sessions.get(session_id, {}).get("tools").urls) if session_id in sessions else "n/a",
            "findings": len(db.get_findings(session_id))}


def _tool_ledger(session_id: str) -> dict:
    """Per-tool execution ledger (executed / skipped / failed + why) plus ZAP status,
    auth posture, strategy and AI-call count — for the report Methodology section.
    Derived deterministically from the persisted event log; no scan re-run."""
    m = db.get_mission(session_id)
    ctx = (m or {}).get("context", {}) or {}
    ex = ctx.get("execution", {}) or {}
    agg = {}
    for l in db.get_logs(session_id, limit=4000):
        t = l.get("tool")
        if not t or l.get("type") not in ("tool_call", "tool_result", "tool_error", "scope_block"):
            continue
        a = agg.setdefault(t, {"calls": 0, "findings": 0, "note": "", "error": ""})
        typ = l.get("type")
        if typ == "tool_call":
            a["calls"] += 1
        elif typ == "tool_result":
            cnt = int(l.get("count") or 0)
            out = str(l.get("output") or "")
            # A no-confirmation pass that still returned a data-carrier (e.g. sqlmap's
            # log-tail record) must not inflate the findings count — otherwise the ledger
            # reads "9 findings / No SQLi confirmed". Mirrors the scan-time count fix so a
            # report rendered from older logs is consistent too.
            if cnt and re.search(r"no\b[\w\s/]*\bconfirmed|\b0\s+confirmed", out, re.I):
                cnt = 0
            a["findings"] += cnt
            # Prefer the note from a call that actually produced findings, so the ledger
            # reflects the CONFIRMING call — not an earlier 0-result call on another
            # endpoint (the bug that made run_sqli/run_xxe read "0 confirmed" next to a
            # confirmed finding). A hit-call note locks; benign notes only fill a blank.
            if out:
                if cnt > 0:
                    a["note"], a["_locked"] = out[:140], True
                elif not a["note"] and not a.get("_locked"):
                    a["note"] = out[:140]
        else:  # tool_error / scope_block
            a["error"] = str(l.get("error") or "")[:140]
    # Was SQLi confirmed by a native tool? Used to reword sqlmap's "No SQLi confirmed"
    # note so it reads as corroboration, not a contradiction next to a confirmed SQLi.
    _sqli_confirmed = any(
        str(f.get("family") or "").lower() == "sqli" or "cwe-89" in str(f.get("cwe") or "").lower()
        for f in db.get_findings(session_id))
    tools = []
    for t, a in sorted(agg.items()):
        low = (a["note"] + " " + a["error"]).lower()
        if a["error"]:
            status, note = "failed", a["error"]
        elif any(k in low for k in ("not configured", "skipped", "skip cleanly", "disabled")):
            status, note = "skipped", a["note"]
        else:
            status, note = "executed", a["note"]
        # sqlmap is corroboration here — the native SQLi oracle + UNION enrichment do the
        # confirming. Reword its "No SQLi confirmed" so the ledger never reads contradictory
        # next to a confirmed SQLi finding.
        if t == "run_sqlmap" and re.search(r"no sqli confirmed|\b0 confirmed|not confirmed", note, re.I):
            note = ("sqlmap did not independently confirm; the native SQLi oracle + UNION "
                    "enrichment confirmed the injection and extracted DB metadata"
                    if _sqli_confirmed else
                    "sqlmap found no injection on the tested endpoints")
        tools.append({"tool": t, "status": status, "calls": a["calls"],
                      "findings": a["findings"], "note": note})
    # ZAP status is reported honestly: if no ZAP daemon is configured (ZAP_ADDR unset)
    # the report says "Skipped — not configured", NOT "Not Invoked" — the latter is
    # reserved for the case where ZAP IS configured but the scan mode/plan didn't run
    # it (e.g. a non-Full mode). This removes the ambiguous "Not Invoked" that looked
    # like ZAP was available but silently skipped.
    try:
        import zap_client
        _zap_configured = zap_client.configured()
    except Exception:
        _zap_configured = False
    _zap_enabled = bool(ctx.get("enable_zap"))
    z = agg.get("run_zap")
    if not _zap_configured:
        zap = "not_configured"                # ZAP_ADDR unset — nothing to run
    elif not _zap_enabled:
        zap = "user_disabled"                 # available but the user did not enable it
    elif not z:
        zap = "not_invoked"                   # enabled but never scheduled (e.g. no live host)
    elif z["error"]:
        zap = "failed"
    elif "not configured" in z["note"].lower():
        zap = "not_configured"
    else:
        # executed — reflect the policy the note recorded (policy=<p>; ...)
        note = z.get("note", "")
        pol = note.split("policy=", 1)[1].split(";", 1)[0].strip() if "policy=" in note else ""
        zap = {"passive": "executed_passive", "safe_active": "executed_safe_active",
               "thorough_active": "executed_thorough_active"}.get(pol, "executed")
    return {"tools": tools, "zap_status": zap,
            "authenticated": bool(ctx.get("authenticated")),
            "strategy": ex.get("strategy") or ctx.get("strategy") or "",
            "ai_calls": ex.get("ai_calls", 0)}


def _delta(session_id: str) -> dict:
    """'Since last scan' diff for the report — current surface vs the most recent
    prior mission on the same target (same source as /memory/{id}/diff). Best-effort;
    {} when unavailable so the report never breaks on a cold target."""
    try:
        m = db.get_mission(session_id)
        if not m:
            return {}
        recon, urls, findings = _graph_inputs(session_id)
        curr = memory_mod.snapshot(recon, urls, findings)
        prior = db.get_prior_snapshot(memory_mod.target_key(m["scope"]), before_mission=session_id)
        return memory_mod.diff(prior, curr)
    except Exception:
        return {}


def _scan_config(m) -> dict:
    ctx = (m.get("context", {}) or {})
    return {"mode": m.get("mode"), "strategy": ctx.get("strategy"),
            "recon_cycles": ctx.get("recon_cycles"), "max_ai_calls": ctx.get("max_ai_calls"),
            "authenticated": bool(ctx.get("authenticated")),
            # heavy-hitter provenance: the intensity dial + ZAP dials that actually ran
            "intensity": ctx.get("intensity", "standard"),
            "enable_zap": bool(ctx.get("enable_zap")), "zap_policy": ctx.get("zap_policy"),
            "zap_speed": ctx.get("zap_speed"), "zap_aggression": ctx.get("zap_aggression")}


@app.get("/report/{session_id}")
async def get_report(session_id: str):
    m, findings, scope, coverage, chains = _report_bundle(session_id)
    md = report_mod.generate_report(m["program"], findings, scope, coverage, chains,
                                    status=m["status"], ai_summary=_ai_summary(m),
                                    execution=_execution(m), leads=_leads(m),
                                    delta=_delta(session_id), tool_ledger=_tool_ledger(session_id))
    return {"markdown": md, "findings": findings, "status": m["status"], "leads": _leads(m)}


def _report_fname(m: dict, scope: dict, ext: str) -> str:
    """Convention: target_config_YYYYMMDD@HHMMPST.ext (e.g. juiceshop_full-det_20260726@1440PST.html)."""
    import re as _re
    from datetime import datetime
    try:
        from zoneinfo import ZoneInfo
        now = datetime.now(ZoneInfo("America/Los_Angeles"))
    except Exception:
        now = datetime.utcnow()
    sc = scope if isinstance(scope, dict) else {}
    ins = sc.get("in_scope") or []
    tgt = (ins[0] if ins else (m.get("program") or "target"))
    tgt = _re.sub(r"[^a-z0-9]+", "", tgt.split(":")[0].split(".")[0].lower()) or "target"
    smap = {"deterministic": "det", "agentic": "agentic", "low_ai": "lowai", "manual": "man"}
    cfg = f"{(m.get('mode') or 'scan')[:4]}-{smap.get(m.get('strategy'), (m.get('strategy') or 'det'))}"
    return f"{tgt}_{cfg}_{now.strftime('%Y%m%d@%H%M')}PST.{ext}"


@app.get("/report/{session_id}/md")
async def get_report_md(session_id: str):
    m, findings, scope, coverage, chains = _report_bundle(session_id)
    md = report_mod.generate_report(m["program"], findings, scope, coverage, chains,
                                    status=m["status"], ai_summary=_ai_summary(m),
                                    execution=_execution(m), leads=_leads(m),
                                    delta=_delta(session_id), tool_ledger=_tool_ledger(session_id))
    fname = _report_fname(m, scope, "md")
    return PlainTextResponse(md, media_type="text/markdown",
                             headers={"Content-Disposition": f'attachment; filename="{fname}"'})


def _sec_headers(session_id: str) -> list:
    """Aggregate protective-header coverage across probed responses (present per header
    vs total responses seen). Data for the report's Security Headers Coverage section."""
    KEYS = ["content-security-policy", "strict-transport-security", "x-frame-options",
            "x-content-type-options", "referrer-policy", "permissions-policy"]
    NICE = {"content-security-policy": "Content-Security-Policy", "strict-transport-security": "Strict-Transport-Security",
            "x-frame-options": "X-Frame-Options", "x-content-type-options": "X-Content-Type-Options",
            "referrer-policy": "Referrer-Policy", "permissions-policy": "Permissions-Policy"}
    ex = db.get_exchanges(session_id) or []
    total, present = 0, {k: 0 for k in KEYS}
    for e in ex:
        h = e.get("response_headers") or {}
        if not isinstance(h, dict):
            continue
        total += 1
        low = {k.lower() for k in h.keys()}
        for k in KEYS:
            if k in low:
                present[k] += 1
    if not total:
        return []
    return [{"header": NICE[k], "present": present[k], "total": total} for k in KEYS]


@app.get("/report/{session_id}/html")
async def get_report_html(session_id: str, download: bool = False):
    m, findings, scope, coverage, chains = _report_bundle(session_id)
    html = report_mod.generate_html_report(
        m["program"], findings, scope, coverage, chains,
        status=m["status"], ai_summary=_ai_summary(m), execution=_execution(m), leads=_leads(m),
        attack_surface=_attack_surface(session_id), playbook=m["context"].get("playbook", []),
        mode=m.get("mode"), delta=_delta(session_id), tool_ledger=_tool_ledger(session_id),
        report_id=session_id, security_headers=_sec_headers(session_id))
    _fn = _report_fname(m, scope, "html")
    headers = {"Content-Disposition": f'attachment; filename="{_fn}"'} if download else {}
    return HTMLResponse(html, headers=headers)


@app.get("/report/{session_id}/csv")
async def get_report_csv(session_id: str):
    _, findings, _, _, _ = _report_bundle(session_id)
    return PlainTextResponse(report_mod.findings_csv(findings), media_type="text/csv")


@app.get("/report/{session_id}/json")
async def get_report_json(session_id: str):
    m, findings, scope, coverage, chains = _report_bundle(session_id)
    return PlainTextResponse(
        report_mod.findings_json(
            m["program"], findings, scope, coverage, chains, leads=_leads(m),
            config=_scan_config(m), attack_surface=_attack_surface(session_id),
            playbook=m["context"].get("playbook", []), tool_ledger=_tool_ledger(session_id),
            delta=_delta(session_id), execution=_execution(m), report_id=session_id),
        media_type="application/json")


@app.get("/report/{session_id}/poc")
async def get_report_poc(session_id: str, redact: bool = True):
    m = _require_mission(session_id)
    findings = db.get_findings(session_id)
    ex_by_f = {f.get("id"): db.get_exchanges(session_id, f.get("id")) for f in findings}
    md = poc.mission_markdown(m["program"], findings, ex_by_f, redact=redact)
    _fn = _report_fname(m, m.get("scope") or {}, "poc.md")
    return PlainTextResponse(md, media_type="text/markdown",
                             headers={"Content-Disposition": f'attachment; filename="{_fn}"'})


# ── cross-session memory: record + graph + diff ──────────────────
def _graph_inputs(session_id: str):
    """(recon, urls, findings) for graph/surface — from the live agent if the
    session is in memory, else from the snapshot persisted at mission end."""
    findings = db.get_findings(session_id)
    if session_id in sessions:
        t = sessions[session_id]["tools"]
        return t.recon, t.urls, findings
    m = db.get_mission(session_id)
    gd = (m or {}).get("context", {}).get("graph_data", {}) if m else {}
    return gd.get("recon", {}), gd.get("urls", []), findings


def _record_memory(session_id: str) -> None:
    """At mission end: snapshot the discovered surface into cross-session memory
    (for warm-start + diffing) and stash a compact graph_data blob in the mission
    context so archived views render without the live agent. Best-effort — never
    breaks the run teardown."""
    try:
        if session_id not in sessions:
            return
        m = db.get_mission(session_id)
        if not m:
            return
        tools = sessions[session_id]["tools"]
        findings = db.get_findings(session_id)
        tkey = memory_mod.target_key(m["scope"])
        snap = memory_mod.snapshot(tools.recon, tools.urls, findings)
        db.record_memory(tkey, session_id, snap)
        ctx = dict(m["context"])
        ctx["graph_data"] = {
            "recon": {"live_hosts": tools.recon.get("live_hosts", []),
                      "subdomains": tools.recon.get("subdomains", [])},
            "urls": tools.urls[:1000],
        }
        db.update_mission(session_id, context=ctx)
    except Exception:
        pass


def _ensure_playbook(session_id: str) -> None:
    """Deterministic playbook safety-net. In full/active mode the model sometimes
    dives into scanning and never calls generate_playbook, so a mission with a
    populated surface ends up with an empty Playbooks tab (Codex hit this). If
    none was produced but there IS surface, build one from the same deterministic
    guidance engine the tool uses — passive and full now reach parity."""
    try:
        if session_id not in sessions:
            return
        m = db.get_mission(session_id)
        if not m or (m["context"].get("playbook") or []):
            return
        tools = sessions[session_id]["tools"]
        if not tools.urls and not tools.recon.get("live_hosts"):
            return
        import guidance as guidance_mod
        recon = dict(tools.recon)
        recon["urls"] = tools.urls
        guide = guidance_mod.consolidate(guidance_mod.build_guidance(recon))
        if not guide:
            return
        ctx = dict(m["context"])
        ctx["playbook"] = guide
        ctx["playbook_stats"] = guidance_mod.guidance_stats(guide)
        ctx["playbook_auto"] = True     # note it was generated by the safety-net
        db.update_mission(session_id, context=ctx)
    except Exception:
        pass


def _record_execution(session_id: str) -> None:
    """Persist how the mission ran (strategy + AI usage) so the report can state it
    honestly — 'deterministic no-AI coverage' or 'AI wrap-up skipped (RateLimitError)'."""
    try:
        if session_id not in sessions:
            return
        agent = sessions[session_id]["agent"]
        m = db.get_mission(session_id)
        if not m:
            return
        ctx = dict(m["context"])
        ctx["execution"] = {"strategy": getattr(agent, "strategy", "agentic"),
                            "ai_calls": getattr(agent, "ai_calls", 0),
                            "max_ai_calls": getattr(agent, "max_ai_calls", 0),
                            "ai_note": getattr(agent, "ai_note", "")}
        # Unconfirmed leads (candidate/static signals) live separately from findings
        # so the report stays bounty-trustworthy. Dedup + cap.
        leads, seen = [], set()
        for lead in getattr(agent, "leads", []):
            key = (lead.get("title", ""), lead.get("target", ""))
            if key in seen:
                continue
            seen.add(key)
            leads.append({"title": lead.get("title", ""), "severity": lead.get("severity", "info"),
                          "target": lead.get("target", ""), "confidence": lead.get("confidence", "candidate"),
                          "description": lead.get("description", "") or lead.get("detail", "")})
        ctx["leads"] = leads[:60]
        db.update_mission(session_id, context=ctx)
    except Exception:
        pass


def _finalize_mission(session_id: str) -> None:
    """One place that runs when a mission's agent loop ends: guarantee a playbook,
    then persist cross-session memory + archived-render data + execution note."""
    _ensure_playbook(session_id)
    _record_execution(session_id)
    _record_memory(session_id)


def _sanitize_error(e: Exception) -> str:
    """Turn a raw provider/client exception into an operator-safe message. Never
    leaks a key, and gives quota/rate-limit/auth failures a clear, actionable
    line instead of a raw stack string."""
    s = str(e)
    low = s.lower()
    if "429" in s or "rate limit" in low or "rate-limit" in low or "quota" in low or "free-models-per-day" in low:
        return ("Provider quota reached (HTTP 429) — the model's request limit was hit "
                "(e.g. a free-tier daily cap). The run stopped early; retry after the limit "
                "resets or configure a model with more headroom. This is a provider limit, not a target result.")
    if "401" in s or "invalid api key" in low or "unauthorized" in low or "authentication" in low:
        return "Provider authentication failed (HTTP 401) — check the configured API key/model. The run stopped early."
    if "timeout" in low or "timed out" in low:
        return "Provider request timed out. The run stopped early; retry."
    # Generic: keep the exception class + a short, key-free message.
    msg = re.sub(r"(sk-[A-Za-z0-9_\-]{6,}|Bearer\s+\S+)", "[redacted]", s)
    return f"Run error ({type(e).__name__}): {msg[:300]}"


async def _drive_mission(session_id: str) -> None:
    """Run the agent to completion in a BACKGROUND task, independent of any SSE
    connection. Events are persisted (DB logs) and buffered on the session so
    /stream can attach, detach and re-attach without affecting the run. The final
    mission status is owned HERE — a client disconnect can no longer mark an
    unfinished run 'complete' (the lifecycle bug Codex found)."""
    sess = sessions.get(session_id)
    if not sess:
        return
    stop_event = sess["stop_event"]
    try:
        async for event in sess["agent"].run(sess["objective"], session_id):
            db.add_log(session_id, event.get("type", "info"), event)
            etype = event.get("type")
            if etype == "phase":
                db.update_mission(session_id, phase=event.get("phase", ""))
            elif etype == "approval_required":
                # Make the pause observable to pollers/API clients, not just the
                # modal (the mission is blocked, not silently "running").
                sess["status"] = "awaiting_approval"
                db.update_mission(session_id, status="awaiting_approval")
            elif etype == "approval_resolved" and sess.get("status") == "awaiting_approval":
                sess["status"] = "running"
                db.update_mission(session_id, status="running")
            sess["events"].append(event)
    except asyncio.CancelledError:
        # process/app shutdown cancelled the task — not a normal completion
        sess["status"] = "interrupted"
        db.update_mission(session_id, status="interrupted")
        sess["done"] = True
        raise
    except Exception as e:
        err = {"type": "error", "content": _sanitize_error(e)}
        db.add_log(session_id, "error", err)
        sess["events"].append(err)
        sess["status"] = "failed"
        db.update_mission(session_id, status="failed")
        sess["done"] = True
        return
    final = "stopped" if stop_event.is_set() else "complete"
    _finalize_mission(session_id)
    sess["status"] = final
    db.update_mission(session_id, status=final)
    sess["done"] = True


def _ensure_run_started(session_id: str) -> None:
    """Start the background agent task exactly once for a session."""
    sess = sessions[session_id]
    if sess.get("task") is not None:
        return
    sess["events"] = sess.get("events", [])
    sess["done"] = False
    sess["status"] = "running"
    db.update_mission(session_id, status="running")
    sess["task"] = asyncio.create_task(_drive_mission(session_id))


# ── attack surface + evidence + playbook ─────────────────────────
@app.get("/surface/{session_id}")
async def get_surface(session_id: str):
    _require_mission(session_id)
    if session_id in sessions:
        return sessions[session_id]["tools"].surface_inventory()
    # Archived mission: rebuild the inventory from the persisted URL list.
    _, urls, _ = _graph_inputs(session_id)
    inv = surface_mod.build_inventory(urls)
    return {"inventory": inv, "stats": surface_mod.surface_stats(inv)}


@app.get("/graph/{session_id}")
async def get_graph(session_id: str):
    """Knowledge graph over this mission's surface: domain→host→endpoint→finding,
    plus host→tech. Deterministic; drives the topology view and lets the agent
    reason over relationships. Works live or from the archived snapshot."""
    _require_mission(session_id)
    recon, urls, findings = _graph_inputs(session_id)
    return graph_model.build_graph(recon, urls, findings)


@app.get("/memory/{session_id}/diff")
async def get_memory_diff(session_id: str):
    """'Since last scan' — diff this mission's surface against the most recent
    prior mission on the same target: new/removed subdomains, endpoints, tech and
    findings. Empty (has_prior=false) when this is the target's first scan."""
    m = _require_mission(session_id)
    recon, urls, findings = _graph_inputs(session_id)
    curr = memory_mod.snapshot(recon, urls, findings)
    tkey = memory_mod.target_key(m["scope"])
    prior = db.get_prior_snapshot(tkey, before_mission=session_id)
    return {"target_key": tkey, "diff": memory_mod.diff(prior, curr),
            "current": curr.get("counts", {})}


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
    # Persist the manual request like Workbench replay does — as redacted evidence
    # and a log entry — so archived missions can reconstruct what was tested.
    if session_id in sessions or db.get_mission(session_id):
        db.add_exchange(session_id, {"url": req.url, "method": req.method,
                                     "request_headers": req.headers, "request_body": req.body,
                                     "status_code": r["status"], "response_headers": r["headers"],
                                     "response_body": r["body"][:4000], "notes": "cURL console"})
        db.add_log(session_id, "tool_result", {"tool": "cURL Console",
                   "output": f"{req.method} {req.url} → HTTP {r['status']} · {r['length']}B · {r['duration_ms']}ms"})
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
    # A role must carry a real credential. Drop empty-value template headers; a
    # role with no non-empty auth header is indistinguishable from anonymous and
    # would make the access-check flag public pages (the Codex FP), so reject it.
    headers = {k: v for k, v in (req.headers or {}).items() if str(v).strip()}
    if not headers:
        raise HTTPException(422, "A role needs at least one non-empty auth header "
                                 "(e.g. Cookie or Authorization) — a blank-auth role is just anonymous.")
    pid = db.add_profile(session_id, req.name, req.role, headers, req.is_owner)
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
    verdict = replay_mod.access_verdict(results, req.url)
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
    skipped = int(parsed.get("skipped", 0))
    non_web = (len(parsed["in_scope"]) - len(ins)) + (len(parsed["out_of_scope"]) - len(outs))
    fmt = parsed.get("format")
    summary = f"Detected {fmt}: {len(ins)} in-scope, {len(outs)} out-of-scope web target(s)."
    extra = []
    if non_web > 0:
        extra.append(f"{non_web} non-web asset(s) (mobile/source) skipped")
    if skipped > 0:
        extra.append(f"{skipped} unparseable/empty row(s) skipped")
    if extra:
        summary += " " + "; ".join(extra) + "."
    return {"format_detected": fmt,
            "in_scope": parsed["in_scope"], "out_of_scope": parsed["out_of_scope"],
            "web_in_scope": ins, "web_out_of_scope": outs,
            "total_in": len(parsed["in_scope"]), "total_out": len(parsed["out_of_scope"]),
            "skipped": skipped, "summary": summary}


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
    # DEF-3: reconcile orphaned missions. Any run still marked in-flight belongs to a
    # process that has since exited (a prior crash/restart), so nothing in memory drives
    # it — mark it interrupted so the archive never shows a phantom "running" scan.
    for _m in db.list_missions(limit=500):
        if _m.get("status") in ("running", "stopping", "awaiting_approval"):
            db.update_mission(_m["id"], status="interrupted")
    st = ai_status()   # secret-free; never prints the key
    if not st["ready"]:
        print(f"[WARN] AI provider '{st['provider']}' has no credentials — {st['hint']}")
    else:
        print(f"[INFO] AI ready: {st['provider']} / {st['model']} (key from {st['key_source']})")

    # Probe the headless-browser XSS confirmer ONCE (launch, not just presence).
    # When it's dead, reflected XSS in JS/DOM contexts can only ever be leads —
    # say so loudly instead of shipping silent "0 findings" runs.
    xc = await tools_mod.probe_xss_confirm()
    print("[INFO] XSS execution confirmer: headless browser OK" if xc else
          "[WARN] XSS execution confirmer UNAVAILABLE (no launchable headless browser) — "
          "reflected XSS in script/DOM contexts will remain advisory leads, not confirmed findings")

    # background nuclei template update (best-effort; skipped if binary absent)
    import shutil
    if shutil.which("nuclei"):
        proc = await asyncio.create_subprocess_exec(
            "nuclei", "-update-templates", "-silent",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        asyncio.create_task(proc.communicate())
