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


@app.middleware("http")
async def _platform_auth_mw(request, call_next):
    """Local-only by default (no-op). When APOLAKI_API_TOKEN is set, every non-exempt request must
    present a matching X-Apolaki-Token / Bearer token (platform hardening for external/multi-user)."""
    import platform_auth as _pa
    if not _pa.authorize(request.url.path, request.headers):
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "platform token required (set X-Apolaki-Token)"}, status_code=401)
    return await call_next(request)

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
    # opt-in: reuse credentials a PRIOR scan of this target DISCOVERED to run authenticated. The UI offers
    # this (via GET /auth/available) only when a prior scan gathered creds. Off = discover + report, scan out.
    authenticated_scan: bool = False
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


class ProxyRulesRequest(BaseModel):
    rules: list = []               # match-and-replace rules the mitm addon applies in flight


class ProxyReplayRequest(BaseModel):
    flow: dict = {}                # a captured flow record (from GET /proxy/flows) to resend
    mutations: dict = {}           # optional method/url/headers/body overrides (Repeater-style)
    send: bool = False             # False = build the request spec only; True = actually re-issue it


class AuthAvailableRequest(BaseModel):
    in_scope: list = []            # the scope being configured; checked against prior-scan target memory
    out_of_scope: list = []


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
                     enable_nmap_vuln=req.enable_nmap_vuln, enable_nuclei_heavy=req.enable_nuclei_heavy,
                     authenticated_scan=req.authenticated_scan)

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
                                    delta=_delta(session_id), tool_ledger=_tool_ledger(session_id),
                                    intel=m["context"].get("intel"),
                                    orchestration=m["context"].get("orchestration"))
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
                                    delta=_delta(session_id), tool_ledger=_tool_ledger(session_id),
                                    intel=m["context"].get("intel"),
                                    orchestration=m["context"].get("orchestration"))
    fname = _report_fname(m, scope, "md")
    return PlainTextResponse(md, media_type="text/markdown",
                             headers={"Content-Disposition": f'attachment; filename="{fname}"'})


# ── Lab Mode: activatable target-specific solver packs (fingerprint-gated, isolated from the
# general detector). The lab target is fixed server-side — the UI cannot point it at an
# arbitrary host, so a lab pack can never fire against a real engagement. ──
_LAB_SOLVE_TARGETS = {"juiceshop": "http://juice-shop:3000"}


@app.get("/lab/targets")
async def lab_targets():
    """List available lab solver packs for the UI (the activatable 'packs' taxonomy)."""
    return {"labs": [{"id": k, "target": v} for k, v in _LAB_SOLVE_TARGETS.items()]}


@app.post("/lab/{lab_id}/solve")
async def lab_solve(lab_id: str):
    """Run a lab-mode SOLVER pack against its fixed lab target; return the scoreboard delta."""
    import labs
    base = _LAB_SOLVE_TARGETS.get(lab_id)
    if not base:
        return {"error": "no solver pack for lab '%s'" % lab_id, "available": list(_LAB_SOLVE_TARGETS)}
    return labs.solve(lab_id, base)


@app.get("/lab/{lab_id}/conquest")
async def lab_conquest(lab_id: str):
    """Read-only knowledge base: the lab's solved challenges annotated with the technique and a full
    write-up per solve, merged live with the scoreboard. Same fixed-target safety as /solve."""
    import labs
    base = _LAB_SOLVE_TARGETS.get(lab_id)
    if not base:
        return {"error": "no solver pack for lab '%s'" % lab_id, "available": list(_LAB_SOLVE_TARGETS)}
    return labs.conquest(lab_id, base)


@app.get("/techniques")
async def techniques_taxonomy(lens: str = "owasp"):
    """Technique registry grouped by a taxonomy lens (owasp/wstg/cwe/mitre/class). Switching the
    lens only changes the view; the techniques themselves are the transferable capability."""
    import techniques as T
    try:
        return _intel_enrich_view(T.taxonomy_view(lens))
    except Exception as e:
        return {"error": str(e), "lens": lens}


# --- Offensive intel feeds (Phase 0): enrich the registry with KEV/CAPEC. Deterministic, cached. ---
_INTEL_CACHE = {"mtime": None, "snaps": {}}


def _intel_snapshots():
    """Load feed snapshots, re-reading only when the on-disk manifest changes."""
    import intel_feeds
    man = os.path.join(intel_feeds._dir(), "manifest.json")
    try:
        mtime = os.path.getmtime(man)
    except OSError:
        return {}
    if _INTEL_CACHE["mtime"] != mtime:
        _INTEL_CACHE["snaps"] = intel_feeds.load()
        _INTEL_CACHE["mtime"] = mtime
    return _INTEL_CACHE["snaps"]


def _kev_cwes():
    """The set of CWE ids CISA lists as known-exploited-in-the-wild (empty if no feeds loaded)."""
    import intel_feeds
    try:
        return intel_feeds.known_exploited_cwes(_intel_snapshots())
    except Exception:
        return set()


def _intel_enrich_view(view):
    """Merge KEV known-exploited flags + CAPEC patterns into each technique of a taxonomy_view.
    Degrades cleanly to {'intel': {'loaded': False}} when no feed snapshots are present."""
    import intel_feeds
    snaps = _intel_snapshots()
    if not snaps:
        view["intel"] = {"loaded": False}
        return view
    flat = [{"id": t.get("id"), "cwe": t.get("cwe")}
            for g in view.get("groups", []) for t in g.get("techniques", [])]
    enr = intel_feeds.enrich_techniques(flat, snaps)
    ke = 0
    for g in view.get("groups", []):
        for t in g.get("techniques", []):
            e = enr.get(t.get("id"))
            if not e:
                continue
            t["known_exploited"] = e["known_exploited"]
            t["kev_cves"] = e["kev_cves"]
            t["kev_ransomware"] = e["kev_ransomware"]
            t["capec"] = e["capec"]
            ke += 1 if e["known_exploited"] else 0
    kev = snaps.get("kev") or {}
    view["intel"] = {"loaded": True, "kev_catalog_version": kev.get("catalog_version"),
                     "known_exploited_techniques": ke}
    return view


@app.get("/intel/feeds")
async def intel_feeds_status():
    """Offensive intelligence feeds (Phase 0): CISA KEV + MITRE CAPEC status/freshness. Tier-A,
    deterministic, no crawl, no LLM. The optional intel-feeds sidecar refreshes these on a schedule."""
    import intel_feeds
    st = intel_feeds.status()
    try:
        import techniques as T
        snaps = _intel_snapshots()
        if snaps:
            enr = intel_feeds.enrich_techniques(
                [{"id": t["id"], "cwe": t.get("cwe")} for t in T.TECHNIQUES.values()], snaps)
            st["registry"] = {"techniques": len(enr),
                              "known_exploited": sum(1 for e in enr.values() if e["known_exploited"]),
                              "with_capec": sum(1 for e in enr.values() if e["capec"])}
    except Exception:
        pass
    return st


@app.post("/intel/feeds/refresh")
async def intel_feeds_refresh():
    """Trigger a one-shot deterministic feed refresh (KEV + CAPEC from Tier-A sources). Best-effort;
    the sidecar normally does this on a schedule. Returns the manifest."""
    import intel_feeds
    try:
        return intel_feeds.refresh()
    except Exception as e:
        return {"error": str(e)}


# --- First-class Technique knowledge model: unified view + human review workflow (Phase 1) ---
class ProseExtractRequest(BaseModel):
    document: str
    source: str = "manual"
    ref: str = ""
    tier: str = "B"


class ReviewRequest(BaseModel):
    action: str                # promote | prove | reject | deprecate | conflict | merge
    by: str = "operator"
    note: str = ""
    keep: str = ""             # target id when action == merge


class BulkReviewRequest(BaseModel):
    action: str                # promote | prove | reject | deprecate | conflict
    ids: list
    by: str = "operator"


_TECH_STORE_CACHE = {"mtime": None, "store": None}


def _tech_store():
    """Load the candidate store, re-reading only when the file changes on disk."""
    import technique_store
    p = technique_store._path()
    try:
        mtime = os.path.getmtime(p)
    except OSError:
        mtime = None
    if _TECH_STORE_CACHE["store"] is None or _TECH_STORE_CACHE["mtime"] != mtime:
        _TECH_STORE_CACHE["store"] = technique_store.load()
        _TECH_STORE_CACHE["mtime"] = mtime
    return _TECH_STORE_CACHE["store"]


def _registry_as_canonical():
    """Project the proven techniques.py seed into the first-class Technique shape, enriched with KEV/CAPEC."""
    import techniques as T, technique_model, intel_feeds
    snaps = _intel_snapshots()
    enr = {}
    if snaps:
        enr = intel_feeds.enrich_techniques(
            [{"id": t["id"], "cwe": t.get("cwe")} for t in T.TECHNIQUES.values()], snaps)
    try_map = getattr(T, "_TRY", {})
    out = []
    for rec in T.TECHNIQUES.values():
        e = enr.get(rec["id"], {})
        out.append(technique_model.from_registry(
            rec, try_it=try_map.get(rec["id"]), known_exploited=e.get("known_exploited", False),
            kev_cves=e.get("kev_cves"), capec=e.get("capec")))
    return out


@app.get("/intel/techniques")
async def intel_techniques(status: str = "", q: str = "", limit: int = 200, source: str = ""):
    """Unified first-class Technique view: the proven registry seed + ingested candidates, ONE shape.
    This is what consumers query -- techniques, not articles. Filter by status / source / free text."""
    import technique_store
    reg = _registry_as_canonical()
    cand = technique_store.listing(_tech_store())
    allitems = reg + cand
    by = {}
    for t in allitems:
        by[t.get("status", "?")] = by.get(t.get("status", "?"), 0) + 1
    items = reg if source == "registry" else (cand if source == "store" else allitems)
    if status:
        items = [t for t in items if t.get("status") == status]
    if q:
        ql = q.lower()
        items = [t for t in items if ql in (t.get("name", "") + " " + t.get("summary", "") + " "
                 + " ".join(t.get("cwe", [])) + " " + " ".join(t.get("capec", []))).lower()]
    items = sorted(items, key=lambda t: (t.get("confidence") or {}).get("score", 0), reverse=True)
    return {"total": len(allitems), "by_status": by, "shown": min(len(items), limit),
            "techniques": items[:limit]}


@app.get("/intel/techniques/{tid}")
async def intel_technique_detail(tid: str):
    """Full technique record: provenance, confidence factors, version history, parent/child."""
    import technique_store
    for t in _registry_as_canonical():
        if t["id"] == tid:
            return t
    return technique_store.get(_tech_store(), tid) or {"error": "not found", "id": tid}


@app.post("/intel/extract/capec")
async def intel_extract_capec():
    """Deterministically mint candidate Techniques from the CAPEC feed into the store. No LLM."""
    import intel_extractor, technique_store
    snaps = _intel_snapshots()
    if not (snaps or {}).get("capec"):
        return {"error": "no CAPEC feed loaded; refresh /intel/feeds first"}
    store = technique_store.load()
    summ = intel_extractor.run_capec_extraction(snaps, store)
    technique_store.save(store)
    _TECH_STORE_CACHE["store"] = None
    return summ


@app.post("/intel/extract/prose")
async def intel_extract_prose(req: ProseExtractRequest):
    """Sandboxed LLM extraction of a candidate Technique from a trusted document (lands pending_review).
    Degrades to deterministic-only when no LLM is configured. Never auto-active."""
    import intel_extractor, technique_store
    if not (req.document or "").strip():
        return {"error": "empty document"}
    t = intel_extractor.extract_prose(req.document, source=req.source or "manual", ref=req.ref, tier=req.tier)
    store = technique_store.load()
    action = technique_store.upsert(store, t, by="prose-extractor")
    technique_store.save(store)
    _TECH_STORE_CACHE["store"] = None
    return {"action": action, "technique": t}


@app.post("/intel/techniques/{tid}/review")
async def intel_review(tid: str, req: ReviewRequest):
    """Human review action on a stored candidate: promote / prove / reject / deprecate / conflict /
    merge. Every action is versioned and audit-logged; nothing is ever deleted."""
    import technique_store
    _ACT = {"promote": "experimental", "prove": "proven", "reject": "rejected",
            "deprecate": "deprecated", "conflict": "conflicting"}
    store = technique_store.load()
    if req.action == "merge":
        r = technique_store.merge(store, req.keep, tid, req.by)
    elif req.action in _ACT:
        r = technique_store.transition(store, tid, _ACT[req.action], req.by, req.note)
    else:
        return {"error": "unknown action %r" % req.action}
    if r is None:
        return {"error": "technique not found or invalid target", "id": tid}
    technique_store.save(store)
    _TECH_STORE_CACHE["store"] = None
    return {"ok": True, "id": tid, "status": r.get("status"), "version": r.get("version")}


@app.get("/intel/dedup")
async def intel_dedup():
    """Phase 2 semantic dedup: deterministic merge SUGGESTIONS (shared CWE/CAPEC + lexical similarity).
    The human decides -- apply with POST /intel/techniques/{keep}/review action=merge keep=<other>."""
    import technique_store
    return {"suggestions": technique_store.dedup_suggestions(_tech_store())}


@app.post("/intel/techniques/bulk")
async def intel_bulk_review(req: BulkReviewRequest):
    """Bulk lifecycle action across many stored candidates (CHAD's bulk promote / archive). Audited;
    nothing deleted -- each is a versioned transition."""
    import technique_store
    _ACT = {"promote": "experimental", "prove": "proven", "reject": "rejected",
            "deprecate": "deprecated", "conflict": "conflicting"}
    if req.action not in _ACT:
        return {"error": "unknown action %r" % req.action}
    store = technique_store.load()
    done = 0
    for tid in (req.ids or [])[:300]:
        if technique_store.transition(store, tid, _ACT[req.action], req.by, "bulk"):
            done += 1
    technique_store.save(store)
    _TECH_STORE_CACHE["store"] = None
    return {"ok": True, "action": req.action, "updated": done}


@app.get("/benchmark/targets")
async def benchmark_targets():
    """Validation fixtures with expected-vulnerability manifests (ground truth for benchmarking)."""
    import benchmark
    return benchmark.list_fixtures()


@app.get("/benchmark/{fixture}")
async def benchmark_fixture(fixture: str, session: str = ""):
    """Score a scan's findings against a fixture's expected-vulnerability manifest: class coverage,
    confirmed rate, false negatives, per-class breakdown, and a failed-stage hint per miss. Deterministic
    and zero-token. Pass ?session=<sid> to evaluate that mission; without it, returns the manifest only."""
    import benchmark
    if not session:
        man = benchmark.MANIFESTS.get(fixture)
        if not man:
            return {"error": "unknown fixture %r" % fixture, "fixtures": sorted(benchmark.MANIFESTS)}
        return {"fixture": fixture, "manifest": man}
    m = _require_mission(session)
    findings = db.get_findings(session)
    leads = (m.get("context") or {}).get("leads", [])
    return benchmark.evaluate(fixture, findings, leads)


@app.get("/plan/{session_id}")
async def technique_plan(session_id: str):
    """Deterministic evidence-driven plan (CHAD's core, zero-token): derive observations from everything
    the scan gathered (surface + harvest + code-intel + findings/leads), gate techniques by their
    preconditions, and return the ordered next-best actions. Empty plan = honest 'exhausted path'."""
    import asyncio
    import technique_planner as TP
    import intel_feeds
    import codeintel
    m = _require_mission(session_id)
    ctx = m.get("context") or {}
    findings = db.get_findings(session_id)
    leads = ctx.get("leads", [])
    harvest = ctx.get("intel") or {}
    targets = [f.get("target") or f.get("url") for f in findings] + [l.get("target") for l in leads]
    base = next((u for u in targets if isinstance(u, str) and u.startswith("http")), "")
    code_intel = {}
    if base:
        from urllib.parse import urlparse
        p = urlparse(base)
        origin = "%s://%s" % (p.scheme, p.netloc)
        try:
            code_intel = await asyncio.to_thread(codeintel.harvest, origin)
        except Exception:
            code_intel = {}
    obs = TP.derive_observations(
        surface=[t for t in targets if t], harvest=harvest, findings=findings, leads=leads,
        code_intel=code_intel, authenticated=bool(ctx.get("authenticated")))
    if base and os.environ.get("CDP_BROWSER_URL"):     # browser-as-sensor folds into the SAME observations
        try:
            import browser_engine
            bobs = await asyncio.to_thread(browser_engine.observe, base)
            obs |= browser_engine.to_observations(bobs)
        except Exception:
            pass
    try:                                               # intercept-proxy traffic feeds the SAME observations
        import proxy as _proxy
        obs |= _proxy.to_observations()
    except Exception:
        pass
    snaps = _intel_snapshots()
    kev = intel_feeds.known_exploited_cwes(snaps) if snaps else set()
    p = TP.plan(obs, _registry_as_canonical(), kev_cwes=kev)
    try:                                   # Phase 3: reweight by LEARNED per-class reliability (all targets)
        import learning
        rel = learning.reliability()
        for a in p:
            w = learning.class_weight(a.get("family"), rel)
            if w:
                a["score"] = round(a["score"] + w, 1)
                a["learned"] = {"weight": w}
        p.sort(key=lambda x: x.get("score", 0), reverse=True)
    except Exception:
        pass
    if base:                               # fold in what prior engagements on THIS target already learned
        try:
            import attack_chain
            p = attack_chain.annotate_plan(base, p)
        except Exception:
            pass
    return {"session": session_id, "observations": sorted(obs), "plan": p, "plan_size": len(p)}


@app.get("/mutate")
async def mutate(vuln_class: str = "", base: str = "", limit: int = 30):
    """Payload mutation: ordered payload variants for a vuln class (deterministic families + encodings +
    bypass tricks) plus the bounded retry policy. Feeds the execution engines when a first payload is
    filtered -- systematic alternatives without an LLM."""
    import mutation
    return {"vuln_class": vuln_class, "variants": mutation.variants(vuln_class, base or None, limit),
            "retry_policy": mutation.retry_policy(vuln_class)}


@app.get("/browser/observe")
async def browser_observe(url: str = ""):
    """Browser-as-sensor: drive a real headless Chrome to collect structured observations (forms, inputs,
    routes, runtime API/WS/GraphQL endpoints, storage, cookies, framework, CSP) that feed the SAME
    planner + attack graph as HTTP recon. Labelled empty result when no headless browser is configured."""
    import asyncio
    import browser_engine
    if not url:
        return {"error": "url required (in scope)"}
    return await asyncio.to_thread(browser_engine.observe, url)


@app.get("/intel/learning")
async def intel_learning():
    """Continuous-learning view: per-vuln-class reliability rolled up from oracle-confirmed outcomes
    across ALL engagements. Deterministic, zero-token; feeds the planner's ranking."""
    import learning
    return {"reliability": learning.reliability()}


@app.get("/chain/{target}")
async def attack_chain_view(target: str):
    """Attack-chain memory for a target: what was tried / confirmed / failed across ALL engagements, so
    the next run (and the planner) starts smarter. Deterministic, append-only."""
    import attack_chain
    ch = attack_chain.load(target)
    return {"target": ch.get("target"), "steps": ch.get("steps", []),
            "outcomes": attack_chain.summary(target)}


@app.get("/graph/attack/{session_id}")
async def attack_graph_view(session_id: str):
    """The UNIFIED attack graph for an engagement: host -> observations -> techniques -> findings/leads,
    one model every subsystem publishes into (recon, harvest, code-intel, browser sensor, planner,
    findings). Deterministic, zero-token -- composes the shared state, does not invent a new one."""
    import asyncio
    from urllib.parse import urlparse
    import technique_planner as TP
    import intel_feeds
    import codeintel
    import attack_graph
    m = _require_mission(session_id)
    ctx = m.get("context") or {}
    findings = db.get_findings(session_id)
    leads = ctx.get("leads", [])
    harvest = ctx.get("intel") or {}
    targets = [f.get("target") or f.get("url") for f in findings] + [l.get("target") for l in leads]
    base = next((u for u in targets if isinstance(u, str) and u.startswith("http")), "")
    host = urlparse(base).netloc if base else ""
    code_intel = {}
    if base:
        try:
            code_intel = await asyncio.to_thread(codeintel.harvest, "%s://%s" % (urlparse(base).scheme, host))
        except Exception:
            code_intel = {}
    obs = TP.derive_observations(surface=[t for t in targets if t], harvest=harvest, findings=findings,
                                 leads=leads, code_intel=code_intel)
    if base and os.environ.get("CDP_BROWSER_URL"):
        try:
            import browser_engine
            obs |= browser_engine.to_observations(await asyncio.to_thread(browser_engine.observe, base))
        except Exception:
            pass
    try:                                               # intercept-proxy traffic feeds the unified graph too
        import proxy as _proxy
        obs |= _proxy.to_observations()
    except Exception:
        pass
    snaps = _intel_snapshots()
    kev = intel_feeds.known_exploited_cwes(snaps) if snaps else set()
    plan = TP.plan(obs, _registry_as_canonical(), kev_cwes=kev)
    return attack_graph.build(findings=findings, leads=leads, observations=obs, plan=plan, host=host)


@app.get("/codereview")
async def code_review(path: str = ""):
    """Code Intelligence: static review of a source tree — a path the operator provides, or source
    the recon phase reconstructed from the target's own leaks (source maps / exposed .git / backups).
    Returns leads (file:line + why + the dynamic confirmation the scanner can fire), each mapped to a
    technique in the Taxonomy. Source finds the candidate; a live request proves it."""
    import codeintel
    p = path or os.environ.get("CODEREVIEW_DEFAULT", "/labsrc/juiceshop")
    try:
        return codeintel.review(p)
    except Exception as e:
        return {"error": str(e), "findings": []}


@app.get("/codeintel")
async def code_intel(url: str = ""):
    """Black-box Code Intelligence: curl a target and mine its served JS bundles + exposed vectors
    into ACTIONABLE intel — API endpoints, client routes (incl. unlinked/sensitive ones), leaked
    versions, browsable dirs, and any source the target leaks (source maps -> reconstructed source,
    which then gets the static sink review). No source folder handed over: recon-phase automation."""
    import codeintel
    u = url or _LAB_SOLVE_TARGETS.get("juiceshop", "http://juice-shop:3000")
    try:
        return codeintel.harvest(u)
    except Exception as e:
        return {"error": str(e), "target": url}


class AuthzMatrixRequest(BaseModel):
    base_url: str = ""
    roles: list = []       # [{"role","rank":0|1|2,"headers"?,"tenant"?}]
    requests: list = []    # [{"request"|"path","method"?,"owner"?}]


@app.post("/authz/matrix")
async def authz_matrix(req: AuthzMatrixRequest):
    """Differential Authorization Engine: replay the given requests as EVERY role and return the
    authorization matrix + detected gaps (missing-auth / BOLA-IDOR / BFLA / cross-tenant). The
    differences between roles are the signal a single-user scan can't see. Read-only by default
    (GET/HEAD/OPTIONS) so it is a safe recon differential."""
    import authz
    base = req.base_url or _LAB_SOLVE_TARGETS.get("juiceshop", "")
    if not base:
        return {"error": "base_url required (or a known lab target)"}
    try:
        return authz.run_matrix(base, req.roles, req.requests)
    except Exception as e:
        return {"error": str(e)}


@app.get("/bizlogic")
async def biz_logic(url: str = ""):
    """Business-Logic Graph: infer the target's workflows from its discovered routes (harvested
    black-box) and generate the logic-abuse tests a scanner can't derive — replay/double-execute,
    negative amount, skip a mandatory step, run steps out of order. Recon -> workflow understanding
    -> concrete test hypotheses."""
    import codeintel
    import bizlogic
    u = url or _LAB_SOLVE_TARGETS.get("juiceshop", "http://juice-shop:3000")
    try:
        h = codeintel.harvest(u)
        routes = (h.get("routes") or []) + (h.get("endpoints") or [])
        return bizlogic.analyze(routes)
    except Exception as e:
        return {"error": str(e)}


@app.get("/packs")
async def list_packs():
    """Unified activatable pack registry (the 'taxonomies you enable' model): LAB packs (target-
    specific, oracle-confirmed solvers) + TECHNIQUE packs (general, grouped by vuln class from the
    registry, each with its proven/generalized counts). One place to see every activatable capability."""
    import techniques as T
    packs = []
    for lab, tgt in _LAB_SOLVE_TARGETS.items():
        packs.append({"id": "lab:" + lab, "kind": "lab", "name": lab.replace("_", " ").title() + " solver pack",
                      "target": tgt, "activatable": True,
                      "detail": "Target-specific, oracle-confirmed solvers (Lab Mode)."})
    by_class: dict = {}
    for t in T.TECHNIQUES.values():
        by_class.setdefault(t["vuln_class"], []).append(t)
    for cls, ts in sorted(by_class.items()):
        proven = sum(1 for t in ts if t.get("validated_on"))
        gen = sum(1 for t in ts if T.is_generalized(t))
        packs.append({"id": "tech:" + cls, "kind": "technique",
                      "name": cls.replace("_", " ").title() + " pack", "count": len(ts),
                      "proven": proven, "generalized": gen, "activatable": True,
                      "detail": "%d techniques — %d proven, %d generalized." % (len(ts), proven, gen)})
    return {"packs": packs,
            "lab_packs": sum(1 for p in packs if p["kind"] == "lab"),
            "technique_packs": sum(1 for p in packs if p["kind"] == "technique")}


@app.get("/cdp")
async def cdp_collect(url: str = ""):
    """Headless-browser RUNTIME collection: service workers, runtime XHR/GraphQL endpoints, lazily
    loaded JS chunks, storage keys and window config hints — the artifacts a curl never sees.
    Needs the optional headless-chrome sidecar (env CDP_BROWSER_URL); with none configured it
    returns a clearly-labelled empty result (nothing faked)."""
    import cdp
    u = url or _LAB_SOLVE_TARGETS.get("juiceshop", "http://juice-shop:3000")
    try:
        return cdp.collect(u)
    except Exception as e:
        return {"error": str(e), "target": url}


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
        report_id=session_id, security_headers=_sec_headers(session_id),
        intel=m["context"].get("intel"), kev_cwes=_kev_cwes(),
        orchestration=m["context"].get("orchestration"))
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
        # stash a credential the scan DISCOVERED (target-exposed) so the NEXT scan of this target can
        # authenticate itself from prior intel. The raw secret goes to the ENCRYPTED VAULT; the snapshot
        # keeps only the username + login recipe reference (no plaintext credential — CHAD section 8).
        ag = sessions[session_id].get("agent")
        cred = getattr(ag, "_scan_credential", None)
        if cred and ":" in cred:
            user, pw = cred.split(":", 1)
            login_url = getattr(ag, "_scan_login_url", None)
            try:
                import vault as _vault
                snap["scan_auth_ref"] = _vault.default().put(
                    session_id, "__scan__",
                    {"username": user, "password": pw,
                     "recipe": {"login_url": login_url, "mode": "discovered-credential",
                                "success_oracle": "session-token-present"}})
            except Exception:
                pass
            snap["scan_auth_user"] = user            # username only (non-secret) for the rescan offer
            snap["scan_login_url"] = login_url
        db.record_memory(tkey, session_id, snap)
        # canonical asset/intelligence graph — project everything gathered (surface, findings,
        # personas, capabilities) into one provenance store and persist it so a later scan resumes
        # the world model and the planner can query it. Best-effort.
        try:
            import asset_graph as _ag
            personas = ag._persona_manager.to_dict() if getattr(ag, "_persona_manager", None) else None
            caps = [c["capability"] for c in tools.state.to_dict().get("capabilities", [])]
            _ag.build_from_engagement(session_id, recon=tools.recon, urls=tools.urls, findings=findings,
                                      personas=personas, capabilities=caps, scope_asset=tkey).save()
        except Exception:
            pass
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
            # carry the fields the operator needs to CONFIRM a lead (how-to steps, evidence) + a stable
            # id so the confirm/dismiss actions can address it after the run.
            leads.append({"_lid": "L%d" % len(leads), "title": lead.get("title", ""),
                          "severity": lead.get("severity", "info"), "target": lead.get("target", ""),
                          "confidence": lead.get("confidence", "candidate"),
                          "family": lead.get("family", ""), "cwe": lead.get("cwe", ""),
                          "tags": lead.get("tags", []),
                          "description": lead.get("description", "") or lead.get("detail", "") or lead.get("evidence", ""),
                          "evidence": lead.get("evidence", ""),
                          "how_to_confirm": lead.get("reproduction_steps", []),
                          "analyst_notes": lead.get("analyst_notes", "")})
        ctx["leads"] = leads[:80]
        db.update_mission(session_id, context=ctx)
    except Exception:
        pass


def _finalize_mission(session_id: str) -> None:
    """One place that runs when a mission's agent loop ends: guarantee a playbook,
    then persist cross-session memory + archived-render data + execution note."""
    _ensure_playbook(session_id)
    _record_execution(session_id)
    _record_memory(session_id)
    _record_intel(session_id)
    _record_orchestration(session_id)
    _record_capture(session_id)


def _record_intel(session_id: str) -> None:
    """At mission end: snapshot the harvested Target Intelligence (redacted) into the mission
    context so the report/UI can surface what the target itself leaked. Best-effort — never
    breaks the run teardown."""
    try:
        if session_id not in sessions:
            return
        m = db.get_mission(session_id)
        if not m:
            return
        store = getattr(sessions[session_id]["tools"], "intel", None)
        if store is None:
            return
        ctx = dict(m["context"])
        ctx["intel"] = store.to_dict(redact_secrets=True)
        db.update_mission(session_id, context=ctx)
    except Exception:
        pass


def _record_orchestration(session_id: str) -> None:
    """At mission end: snapshot how the knowledge model + code intelligence DROVE this scan (technique
    advisor picks + the code-intelligence recon summary) into the mission context, so the report/UI can
    show the intelligence was actually consumed, not just displayed. Best-effort — never breaks teardown."""
    try:
        if session_id not in sessions:
            return
        m = db.get_mission(session_id)
        if not m:
            return
        ag = sessions[session_id].get("agent")
        ctx = dict(m["context"])
        ctx["orchestration"] = {"code_intel": getattr(ag, "_codeintel_summary", {}) or {},
                                "advisor": getattr(ag, "_advisor_recs", []) or [],
                                "next_best": getattr(ag, "_next_best", []) or []}
        db.update_mission(session_id, context=ctx)
    except Exception:
        pass


def _record_capture(session_id: str) -> None:
    """At mission end: snapshot the traffic-capture ledger (redacted) into the mission context so the
    report/UI can show the whole request/response trail and export HAR. Best-effort."""
    try:
        if session_id not in sessions:
            return
        m = db.get_mission(session_id)
        if not m:
            return
        store = getattr(sessions[session_id]["tools"], "capture", None)
        if store is None:
            return
        ctx = dict(m["context"])
        ctx["capture"] = store.to_dict()
        db.update_mission(session_id, context=ctx)
    except Exception:
        pass


@app.get("/capture/{session_id}")
async def get_capture(session_id: str):
    """The engagement's traffic-capture ledger (every request/response, secret-redacted). Live from the
    running tools when active, else the persisted snapshot."""
    if session_id in sessions:
        store = getattr(sessions[session_id]["tools"], "capture", None)
        if store is not None:
            return store.to_dict()
    m = _require_mission(session_id)
    return (m.get("context") or {}).get("capture", {"count": 0, "entries": []})


_EMPTY_HAR = {"log": {"version": "1.2", "creator": {"name": "apolaki", "version": "1"}, "entries": []}}


@app.get("/capture/{session_id}/har")
async def get_capture_har(session_id: str):
    """Export the engagement's captured traffic as a HAR 1.2 document (opens in Burp/Chrome/any tool).
    Always returns a valid HAR: an empty log when nothing was captured, never a 500."""
    m = _require_mission(session_id)   # 404 only if the session truly does not exist
    try:
        if session_id in sessions:
            store = getattr(sessions[session_id]["tools"], "capture", None)
            if store is not None:
                return store.har()
        import capture
        return capture.from_dict((m.get("context") or {}).get("capture", {})).har()
    except Exception:
        return dict(_EMPTY_HAR)


@app.post("/auth/available")
async def auth_available(req: AuthAvailableRequest):
    """Does a PRIOR scan of this target already have DISCOVERED credentials? The Launch UI calls this as
    the scope is entered; when available it offers an 'authenticated scan' (reuse the prior creds). Only the
    username + login URL are returned -- never the password."""
    try:
        eng = ScopeEngine()
        eng.load_manual(req.in_scope, req.out_of_scope, "auth-check")
        tkey = memory_mod.target_key(eng.to_dict())
        snap = db.get_prior_snapshot(tkey) or {}
        user = snap.get("scan_auth_user")
        if not user:
            sa = snap.get("scan_auth")            # legacy plaintext snapshot (pre-vault)
            user = sa.split(":", 1)[0] if (sa and ":" in sa) else None
        if user:
            return {"available": True, "username": user, "login_url": snap.get("scan_login_url") or "",
                    "target": tkey}
    except Exception:
        pass
    return {"available": False}


# ---------------------------------------------------------------------------- intercept proxy (Burp-core)
@app.get("/proxy/status")
async def proxy_status():
    """Is the intercepting proxy active, and what has it captured? Degrades to a labelled-off result when
    the mitmproxy sidecar is not running (nothing faked)."""
    import proxy
    return proxy.status()


@app.get("/proxy/flows")
async def proxy_flows(limit: int = 200):
    """The live traffic the intercept proxy has captured (secret-redacted), newest last."""
    import proxy
    return proxy.FlowStore.load(limit=limit).to_dict()


@app.get("/proxy/flows/har")
async def proxy_flows_har(limit: int = 500):
    """Export the proxy's captured traffic as a HAR 1.2 document (opens in Burp/Chrome/any tool)."""
    import proxy
    try:
        return proxy.FlowStore.load(limit=limit).har()
    except Exception:
        return {"log": {"version": "1.2", "creator": {"name": "apolaki-proxy", "version": "1"}, "entries": []}}


@app.get("/proxy/rules")
async def proxy_get_rules():
    """The match-and-replace rules currently in effect (what the addon rewrites in flight)."""
    import proxy
    return {"rules": proxy.RuleSet.load().rules}


@app.post("/proxy/rules")
async def proxy_set_rules(req: ProxyRulesRequest):
    """Install deterministic match-and-replace rules (Burp match-and-replace). Validated then written to
    the shared file the mitm addon hot-reloads. A malformed rule returns 400 rather than writing junk."""
    import proxy
    try:
        saved = proxy.RuleSet(req.rules).save()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True, "count": len(saved), "rules": saved}


@app.post("/proxy/replay")
async def proxy_replay(req: ProxyReplayRequest):
    """Replay a captured flow (Repeater-style), optionally mutated, optionally actually re-issued. Bounded
    to a single request -- never a loop, so it cannot become a DoS."""
    import proxy
    return proxy.replay(req.flow, mutations=req.mutations, send=bool(req.send))


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


@app.get("/graph/canonical/{session_id}")
async def get_canonical_graph(session_id: str):
    """The CANONICAL asset/intelligence graph: one provenance store projected from everything the
    engagement gathered (surface, findings, personas, capabilities). Each fact carries its source,
    confidence, scope asset, what it may unlock, and whether it was tested — the planner's world
    model. Built on-demand here; also persisted at mission end so a later scan resumes it."""
    m = _require_mission(session_id)
    import asset_graph as _ag
    recon, urls, findings = _graph_inputs(session_id)
    personas, caps = None, []
    sess = sessions.get(session_id) or {}
    ag = sess.get("agent")
    if ag is not None:
        try:
            if getattr(ag, "_persona_manager", None):
                personas = ag._persona_manager.to_dict()
            tl = sess.get("tools")
            if tl is not None:
                caps = [c["capability"] for c in tl.state.to_dict().get("capabilities", [])]
        except Exception:
            pass
    g = _ag.build_from_engagement(session_id, recon=recon, urls=urls, findings=findings,
                                  personas=personas, capabilities=caps,
                                  scope_asset=memory_mod.target_key(m["scope"]))
    d = g.to_dict()
    d["stats"] = g.stats()
    d["next_best_actions"] = g.next_best_actions()   # the planner querying the world model
    return d


@app.get("/mission/{session_id}/export")
async def export_mission(session_id: str):
    """Portable, redacted mission bundle: metadata + findings + surface + canonical graph +
    capabilities. The archival / hand-off / diagnostic artifact — safe to share (secrets scrubbed)."""
    m = _require_mission(session_id)
    import mission_export as _me
    import asset_graph as _ag
    recon, urls, findings = _graph_inputs(session_id)
    snap = memory_mod.snapshot(recon, urls, findings)
    caps = []
    tl = (sessions.get(session_id) or {}).get("tools")
    if tl is not None:
        try:
            caps = [c["capability"] for c in tl.state.to_dict().get("capabilities", [])]
        except Exception:
            caps = []
    g = _ag.build_from_engagement(session_id, recon=recon, urls=urls, findings=findings,
                                  capabilities=caps, scope_asset=memory_mod.target_key(m["scope"]))
    return _me.build_bundle(mission=m, findings=findings, snapshot=snap,
                            graph={**g.to_dict(), "stats": g.stats()}, capabilities=caps)


@app.get("/audit")
async def get_audit(mission: str = None, limit: int = 200):
    """The tamper-evident audit log (hash-chained): recent security-relevant, state-changing actions
    plus a chain-integrity check (chain_intact=false + first_bad_index pinpoints any tampering)."""
    import audit as _audit
    log = _audit.default()
    ok, bad = log.verify_chain()
    return {"chain_intact": ok, "first_bad_index": bad,
            "entries": log.entries(mission=mission, limit=max(1, min(int(limit), 1000)))}


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


@app.post("/findings/{session_id}/{fid}/poc")
async def capture_finding_poc(session_id: str, fid: str):
    """Capture a browser PoC (screenshot of the finding's URL) and attach it to the finding as evidence
    (CHAD's PoC assets). Needs the headless-chrome sidecar; returns a labelled note when unavailable."""
    import asyncio
    import browser_engine
    _require_mission(session_id)
    finding = next((f for f in db.get_findings(session_id) if str(f.get("id")) == fid), None)
    if not finding:
        raise HTTPException(404, "finding not found")
    url = finding.get("url") or finding.get("target") or ""
    if not str(url).startswith("http"):
        return {"ok": False, "note": "finding has no http URL to screenshot"}
    shot = await asyncio.to_thread(browser_engine.screenshot, url)
    if not shot.get("browser"):
        return {"ok": False, "note": shot.get("note")}
    merged = dict(finding)
    merged["poc_screenshot"] = shot["png_b64"][:1200000]
    merged["poc_url"] = url
    db.update_finding(fid, merged)
    return {"ok": True, "bytes": shot.get("bytes"), "attached_to": fid}


# ── lead confirmation workflow: leads are UNCONFIRMED; a human confirms (or dismisses) them ──
@app.get("/leads/{session_id}")
async def get_leads(session_id: str):
    """The scan's unconfirmed leads (candidate signals), each carrying how-to-confirm steps. The tool
    can't auto-prove these -- the operator confirms them into findings or dismisses them."""
    m = _require_mission(session_id)
    return {"leads": (m.get("context") or {}).get("leads", [])}


@app.post("/leads/{session_id}/{lid}/confirm")
async def confirm_lead(session_id: str, lid: str):
    """Promote an unconfirmed lead to a CONFIRMED finding (the operator verified it), then drop it from
    the lead list. The report updates automatically. Confirmation can't be automated -- this is the
    human saying 'I proved this'."""
    m = _require_mission(session_id)
    ctx = dict(m["context"])
    leads = list(ctx.get("leads", []))
    lead = next((l for l in leads if l.get("_lid") == lid), None)
    if not lead:
        raise HTTPException(404, "lead not found")
    finding = {"title": lead.get("title", ""), "severity": lead.get("severity", "info"),
               "url": lead.get("target", ""), "family": lead.get("family", ""), "cwe": lead.get("cwe", ""),
               "confidence": "confirmed", "confirmed": True,
               "evidence": lead.get("evidence", "") or lead.get("description", ""),
               "reproduction_steps": lead.get("how_to_confirm", []),
               "analyst_notes": ("Operator-confirmed from a lead. " + (lead.get("analyst_notes", "") or "")).strip(),
               "tags": (lead.get("tags") or []) + ["operator-confirmed"]}
    fid = db.add_finding(session_id, finding)
    ctx["leads"] = [l for l in leads if l.get("_lid") != lid]
    db.update_mission(session_id, context=ctx)
    try:                                   # attack-chain memory: this class WORKED here
        import attack_chain
        attack_chain.record(lead.get("target"), lead.get("family") or lead.get("title", "")[:40],
                            "confirmed", evidence=lead.get("title", ""), session=session_id, name=lead.get("title", ""))
    except Exception:
        pass
    return {"ok": True, "finding_id": fid, "promoted": lead.get("title", "")}


@app.post("/leads/{session_id}/{lid}/dismiss")
async def dismiss_lead(session_id: str, lid: str):
    """Mark a lead as NOT a finding and drop it (kept in a dismissed list for audit)."""
    m = _require_mission(session_id)
    ctx = dict(m["context"])
    leads = list(ctx.get("leads", []))
    lead = next((l for l in leads if l.get("_lid") == lid), None)
    if not lead:
        raise HTTPException(404, "lead not found")
    ctx["leads"] = [l for l in leads if l.get("_lid") != lid]
    dm = list(ctx.get("dismissed_leads", []))
    dm.append(lead.get("title", ""))
    ctx["dismissed_leads"] = dm[:100]
    db.update_mission(session_id, context=ctx)
    try:                                   # attack-chain memory: this class did NOT pan out here
        import attack_chain
        attack_chain.record(lead.get("target"), lead.get("family") or lead.get("title", "")[:40],
                            "dismissed", session=session_id, name=lead.get("title", ""))
    except Exception:
        pass
    return {"ok": True, "dismissed": lead.get("title", "")}


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
