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
    if not _pa.authorize(request.url.path, request.headers, request.query_params.get("token")):
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
    # Operator scoping (#34): vulnerability CATEGORIES to leave untested. Empty = test everything, which
    # stays the default so an unscoped scan is unchanged. Excluded classes are recorded in the report,
    # because an untested class is not a clean one.
    exclude_categories: list = []
    # Blind benchmarking: extra published-ground-truth paths to HARD-BLOCK from the scanner, for a target
    # whose answer key does not live at the default /vulnerabilities. Blocked at the scope choke point,
    # so no crawl, browser, JS-route harvest or candidate generator can reach it mid-mission.
    answer_key_paths: list = []
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
    # IDS-evasion profile for Apolaki's OWN port scan (#113): off | polite | sneaky | paranoid.
    # Evasion, never DoS — slower timing, fragmentation, decoys, padding. Orthogonal to intensity.
    stealth: str = "off"


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
    import stealth as _stealth
    if req.stealth not in _stealth.LEVELS:
        raise HTTPException(422, "stealth must be one of: %s" % ", ".join(_stealth.LEVELS))
    if req.stealth != "off" and req.mode == "passive":
        raise HTTPException(422, "stealth profiles apply to the active port scan; passive mode makes no "
                                 "live contact, so there is nothing to evade")
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
    # Blind benchmarking against a target whose published ground truth does NOT live at the default
    # /vulnerabilities path: name it here and it is blocked at the same choke point, so the scanner can
    # never crawl the answers it is about to be scored against.
    scope.answer_key_paths = [str(p) for p in (req.answer_key_paths or []) if str(p).strip()]

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
                         session_headers=session_headers, intensity=req.intensity,
                         stealth=req.stealth)
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
                     authenticated_scan=req.authenticated_scan,
                     exclude_categories=list(req.exclude_categories or []))

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
    # Operator scoping travels WITH the scope, because that is what it is. The report reads
    # m["scope"], so recording it here is what makes an excluded class appear as UNTESTED rather than
    # silently absent.
    _scope_dict = scope.to_dict()
    if req.exclude_categories:
        _scope_dict = dict(_scope_dict, exclude_categories=list(req.exclude_categories))
    db.create_mission(session_id, req.program_name, req.mode, objective, _scope_dict, context)
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
    # truth-first proof gate (CHAD #5): a confirmed access-control finding without ownership/authz
    # proof is demoted to a lead before it can reach ANY report format. Default enforces the
    # access-control classes (where a false confirm is most damaging + producers are audited);
    # APOLAKI_ENFORCE_PROOF=all extends it to every family.
    try:
        import proof_schema as _ps
        findings = _ps.demote_unproven(findings)
    except Exception:
        pass
    ctx = m["context"]
    coverage = _coverage(session_id)
    return m, findings, m["scope"], coverage, ctx.get("chains", [])


def _ai_summary(m) -> str:
    return (m.get("context", {}) or {}).get("ai_summary", "")


def _execution(m) -> dict:
    return (m.get("context", {}) or {}).get("execution", {})


def _leads(m) -> list:
    return (m.get("context", {}) or {}).get("leads", [])


def _project_cloud_postures(g, m) -> list:
    """Rebuild EVERY persisted cloud account's model into the graph `g` (CHAD #2/#5) — used by both the
    canonical graph and the portable export so archived missions keep all cloud provider/account nodes.
    Reads ctx['cloud_postures'] (multi-account) with a fallback to the legacy single 'cloud_posture'.
    Returns a compact summary list [{provider, account, account_id, partial, posture}]."""
    ctx = (m or {}).get("context", {}) or {}
    postures = dict(ctx.get("cloud_postures") or {})
    legacy = ctx.get("cloud_posture")
    if legacy and not postures:                       # back-compat with the pre-multi-account shape
        postures["%s:%s" % (legacy.get("provider", "cloud"), legacy.get("account", "cloud"))] = legacy
    summary = []
    for _key, cp in postures.items():
        if not cp.get("model"):
            continue
        try:
            import cloud_iam as _ci
            _ci.to_graph(g, cp["model"], account=(cp.get("account_id") or cp.get("account") or "cloud"),
                         source=cp.get("provider", "cloud"))
        except Exception:
            pass
        summary.append({k: cp.get(k) for k in ("provider", "account", "account_id", "partial", "posture")})
    return summary


def _auth_artery_evidence(session_id: str, m=None) -> dict:
    """Structured proof the authentication artery fired (personas/auth_success/matrix). Prefer the
    LIVE agent (freshest), fall back to what was persisted to mission context at teardown. Never
    raises; {"ran": False} when the artery did not run (unauthenticated scan)."""
    try:
        sess = sessions.get(session_id)
        if sess is not None:
            ag = sess.get("agent")
            a = getattr(ag, "_auth_artery", None)
            if a:
                return a
        m = m or db.get_mission(session_id)
        return ((m or {}).get("context", {}) or {}).get("auth_artery", {"ran": False}) or {"ran": False}
    except Exception:
        return {"ran": False}


def _intel_provenance(session_id: str) -> dict:
    """Where the world model came from (per-source counts + needs-validation worklist). Prefer the
    LIVE graph — it holds the wayback/github/cloud feed nodes with provenance; fall back to the
    snapshot persisted at mission end so archived views still show it. Never raises."""
    try:
        sess = sessions.get(session_id)
        if sess is not None:
            g = getattr(sess.get("tools"), "graph", None)
            if g is not None:
                return g.provenance_summary()
        m = db.get_mission(session_id)
        return ((m or {}).get("context", {}) or {}).get("graph_data", {}).get("provenance", {}) or {}
    except Exception:
        return {}


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
        a = agg.setdefault(t, {"calls": 0, "findings": 0, "note": "", "error": "",
                               "ok": 0, "scope_blocks": 0, "scope_note": ""})
        typ = l.get("type")
        if typ == "tool_call":
            a["calls"] += 1
        elif typ == "tool_result":
            a["ok"] += 1                        # a call that actually returned (not blocked/errored)
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
            # A SCOPE BLOCK is CORRECT enforcement (an out-of-scope target was skipped on
            # purpose), NOT a tool failure. Track it apart from real errors so a tool that
            # ran fine on its in-scope targets but skipped one off-scope host (e.g. a
            # third-party CDN a page loads, or a discovered subdomain on a non-pinned port)
            # is never mislabeled "failed" — that mislabel is itself a reporting-integrity bug.
            if typ == "scope_block" or "SCOPE BLOCK" in str(l.get("error") or ""):
                a["scope_blocks"] += 1
                a["scope_note"] = str(l.get("error") or "")[:140]
            else:
                a["error"] = str(l.get("error") or "")[:140]
    # Was SQLi confirmed by a native tool? Used to reword sqlmap's "No SQLi confirmed"
    # note so it reads as corroboration, not a contradiction next to a confirmed SQLi.
    _sqli_confirmed = any(
        str(f.get("family") or "").lower() == "sqli" or "cwe-89" in str(f.get("cwe") or "").lower()
        for f in db.get_findings(session_id))
    tools = []
    for t, a in sorted(agg.items()):
        low = (a["note"] + " " + a["error"]).lower()
        # `ok` = calls that actually returned a result. A tool is only "failed" when it
        # genuinely errored AND never returned anything useful. A tool that returned on
        # some targets but skipped others as out-of-scope is "executed" (with a skipped
        # count), not "failed" — and a tool ALL of whose targets were out of scope simply
        # did not run in-scope, so it is "skipped", not "failed".
        if a["error"] and not a["ok"]:
            status, note = "failed", a["error"]
        elif any(k in low for k in ("not configured", "skipped", "skip cleanly", "disabled")):
            status, note = "skipped", a["note"]
        elif not a["ok"] and a["scope_blocks"]:
            status, note = "skipped", (a["scope_note"] or "every target was out of scope — nothing tested")
        else:
            status, note = "executed", a["note"]
            extra = []
            if a["error"]:                      # a real error on one call, others still ran
                extra.append("1+ call errored")
            if a["scope_blocks"]:
                extra.append("%d off-scope target%s skipped" %
                             (a["scope_blocks"], "" if a["scope_blocks"] == 1 else "s"))
            if extra:
                note = (note + " " if note else "") + "(" + "; ".join(extra) + ")"
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


@app.get("/bench/labs")
async def bench_labs():
    """The multi-lab regression surface (#101): every wired benchmark lab, its expected vuln classes, and whether
    it is reachable right now — so a run scores only labs that are UP. The full sweep (scan+score each) is driven
    by bench_all.bench(reachable, scan_via_mission); this endpoint is the cheap, non-blocking inventory."""
    import bench_all as BA
    import benchmark as B
    try:
        up = set(await BA.reachable_labs())
        labs = [{"fixture": k, "name": B.MANIFESTS[k]["name"], "url": BA.LAB_URLS[k],
                 "expected": B.MANIFESTS[k]["expected"], "reachable": k in up}
                for k in BA.LAB_URLS if k in B.MANIFESTS]
        return {"labs": labs, "reachable_count": len(up), "min_gate": BA.MIN_GATE}
    except Exception as e:
        return {"error": str(e)}


@app.get("/orchestration/audit")
async def orchestration_audit():
    """Apolaki's north star made checkable: every auto-fired, oracle-confirmed technique must feed the planner
    (evidence-gated) or be a declared always-on path (sweep / passive recon / persona artery / tool-gate) — NEVER a
    dashboard island. Returns the gated + always-on lists and, critically, `islands` (must be empty) so the
    no-island property is visible, not just asserted in CI."""
    import technique_planner as TP
    import techniques as T
    import engine_descriptor as ED
    try:
        full = [T.get(t["id"]) for t in T.list_techniques()]
        a = TP.orchestration_audit(full)
        # Effects layer (T6): the same no-island question one level deeper. Reachability says an engine
        # CAN fire; the effects model says what firing it makes possible. `vocabulary_ok` is the load-
        # bearing check — an effect outside the observation vocabulary can never satisfy a precondition,
        # so it is a declaration that silently does nothing.
        d = ED.build()
        v = ED.validate(d)
        chains, conflicts = ED.chains(d), ED.conflicts(d)
        # An ALWAYS_ON entry is accepted on the strength of its stated REASON, and the reason is prose.
        # `graphql_argument_injection` was declared reached "via graphql_tool.build_query" while nothing
        # called it — the engine ran on paper only and this audit reported no islands. Checking the prose
        # against the code closes that gap.
        reasons = ED.verify_always_on()
        return {**a, "gated_count": len(a["gated"]), "always_on_count": len(a["always_on"]),
                "island_count": len(a["islands"]), "no_islands": a["islands"] == [],
                "always_on_reasons": TP.ALWAYS_ON,
                "reason_verification": {
                    "identifiers_checked": len(reasons["checked"]),
                    "unwired": reasons["unwired"], "ok": reasons["ok"],
                    "note": ("Every function an always-on reason NAMES must be referenced by code that "
                             "runs. Mentions in techniques.py or the descriptor are prose, not wiring."),
                },
                "effects": {
                    "engines_with_effects": v["with_effects"], "engines_total": v["total"],
                    "vocabulary_ok": v["ok"],
                    "unknown_effect_vocabulary": v["unknown_effect_vocabulary"],
                    "chains": [{"producer": p, "observation": o, "consumer": c} for p, o, c in chains],
                    "conflicts": [{"technique": t, "observation": o, "blocks": c} for t, o, c in conflicts],
                    "chain_count": len(chains), "conflict_count": len(conflicts),
                    "planner_uses_effects": False,
                    "note": ("Effects are DECLARED and validated but the planner does not yet search over "
                             "them: it still filters by preconditions only, so these chains are visible "
                             "here and not yet acted on."),
                }}
    except Exception as e:
        return {"error": str(e)}


@app.post("/scope/categories")
async def scope_categories(payload: dict = None):
    """Vulnerability categories an operator can include/exclude, and what excluding them COSTS (#34).

    The cost half is the point. Engines do not stand alone: `engine_descriptor` knows which establish the
    observations others require, so excluding one category can leave a category you kept UNREACHABLE.
    Showing the count without that turns scoping into guesswork.

    Read-only and side-effect free — this is the preview an operator sees BEFORE committing a scan."""
    import scan_scope as ss
    import techniques as T
    try:
        techs = [T.get(t["id"]) for t in T.list_techniques()]
        excluded = (payload or {}).get("exclude") or []
        r = ss.resolve(excluded, techs)
        con = ss.consequences(excluded, techs)
        cats = []
        for name, spec in sorted(ss.CATEGORIES.items()):
            ids = ss.technique_ids_in([name], techs)
            cats.append({"id": name, "label": spec["label"], "techniques": len(ids),
                         "excluded": name in r["excluded_categories"]})
        total = len(techs)
        return {"categories": cats, "total_techniques": total,
                "skipped_technique_ids": r["skipped_technique_ids"],
                "skipped_count": r["skipped_count"],
                "will_run": total - r["skipped_count"],
                "unknown_categories": r["unknown_categories"],
                "starved_observations": con["starved_observations"],
                "collateral_unreachable": con["unreachable_engines"],
                "note": ("Excluded classes are recorded in the report as UNTESTED. Absence of findings "
                         "in an excluded class means nothing."),
                "report_preview": ss.report_block(excluded, techs)}
    except Exception as e:
        return {"error": str(e)}


@app.post("/orchestration/reachability")
async def orchestration_reachability(payload: dict):
    """Forward search over engine EFFECTS (T8): given a set of observations, what is runnable now, what
    would each runnable engine unlock or cost, and how many steps away is each remaining goal.

    This is the question the precondition filter structurally cannot answer. The filter says what is
    applicable in the current state; this says what states are REACHABLE from it, and by which sequence.
    `assumes` flags steps routed through an always-on engine, whose real requirements (credentials, a
    browser) live outside the observation vocabulary."""
    import effect_search as ES
    import engine_descriptor as ED
    import technique_planner as TP
    try:
        obs = [o for o in (payload or {}).get("observations") or [] if o in TP.OBSERVATIONS]
        unknown = sorted(set((payload or {}).get("observations") or []) - set(TP.OBSERVATIONS))
        d = ED.build()
        goal = (payload or {}).get("goal")
        out = {"observations": sorted(obs), "unknown_observations": unknown,
               "vocabulary": list(TP.OBSERVATIONS), "frontier": ES.frontier(d, obs)}
        if goal:
            out["goal"] = goal
            out["plan"] = ES.plan(d, obs, goal)
        return out
    except Exception as e:
        return {"error": str(e)}


@app.get("/coverage/wstg")
async def wstg_coverage():
    """Honest coverage against the full OWASP WSTG v4.2 active-test catalog (109 tests): how many Apolaki
    fully tests (a confirming engine owns it), partially touches, or deliberately does NOT test — including
    the safety exclusions (no-brute lock-out, MFA-pauses, request-smuggling collateral) with the reason."""
    import wstg_catalog as wc
    try:
        return wc.coverage()
    except Exception as e:
        return {"error": str(e)}


@app.post("/intel/exploit-descriptor")
async def exploit_descriptor_build(payload: dict):
    """Build an exploit-module DESCRIPTOR (Codex Tier-3 #15) — taxonomy for planning, never a payload runner.
    Body: {source: nuclei|exploitdb|metasploit|manual, template|entry|module|..., lab_only, approved}.
    Destructive/unknown side effects are BLOCKED unless lab_only AND approved; ExploitDB entries are always
    manual/never-auto-run. Returns the descriptor + the is_executable decision."""
    import exploit_descriptor as ed
    p = payload or {}
    src = str(p.get("source") or "manual").lower()
    if src == "nuclei" and p.get("template") is not None:
        d = ed.from_nuclei(p["template"])
    elif src == "exploitdb" and p.get("entry") is not None:
        d = ed.from_exploitdb(p["entry"])
    elif src == "metasploit" and p.get("module") is not None:
        d = ed.from_metasploit(p["module"])
    else:
        d = ed.make_descriptor(src, str(p.get("id") or "descriptor"), family=p.get("family"),
                               cwe=p.get("cwe"), requires_auth=bool(p.get("requires_auth")),
                               side_effects=str(p.get("side_effects") or "unknown"),
                               check_method=p.get("check_method"), proof_contract=p.get("proof_contract"))
    allowed, reason = ed.is_executable(d, lab_only=bool(p.get("lab_only")), approved=bool(p.get("approved")))
    return {"descriptor": d, "executable": allowed, "reason": reason}


@app.get("/intel/ad-frontier")
async def ad_frontier_view(capability: str = None):
    """The AD/Windows frontier modeled read-only (Codex Tier-3 #13): which capabilities are read-only-present
    vs environment-gated (authenticated AD attacks — Kerberoast/ADCS/DCSync/relay — stay BLOCKED until an
    authorized DC lab). With ?capability= it returns the gate decision for one capability."""
    import ad_context as ad
    if capability:
        allowed, reason = ad.is_capability_allowed(capability)
        return {"capability": capability, "allowed": allowed, "reason": reason}
    return ad.frontier()


@app.post("/intel/ad-context")
async def ad_context_analyze(payload: dict):
    """Read-only AD context from LDAP/SMB facts (Codex Tier-3 #13): domain model + SPN/CA inventory + SMB-relay
    risk observation. Inventory only — no authenticated AD attack is performed. Body: {facts, ldap_entries,
    smb_signing_required}."""
    import ad_context as ad
    p = payload or {}
    out = {}
    if p.get("facts"):
        out["domain_model"] = ad.model_domain(p["facts"])
    if p.get("ldap_entries") is not None:
        out["spn_inventory"] = ad.spn_inventory(p["ldap_entries"])
        ca = ad.ca_presence(p["ldap_entries"])
        if ca:
            out["ca_presence"] = ca
    if "smb_signing_required" in p:
        relay = ad.smb_relay_risk(p["smb_signing_required"])
        if relay:
            out["smb_relay_risk"] = relay
    return out


@app.post("/intel/ot-context")
async def ot_context_analyze(payload: dict):
    """OT/ICS zone + process-impact context for an ICS finding (Codex Tier-3 #12). Body: {finding} for asset
    context + potential process impact (POTENTIAL until operator-confirmed), or {pack} to check whether an OT
    service pack's declared safety_class is admissible (only read_only is — ot_write/state_change/firmware and
    undeclared packs are rejected), or {protocol} to check if it may be routed."""
    import ot_context as ot
    p = payload or {}
    out = {}
    if p.get("finding"):
        ctx = ot.ot_asset_context(p["finding"])
        out["asset_context"] = ctx
        out["process_impact"] = ot.process_impact(ctx, operator_context=p.get("operator_context"))
    if p.get("pack") is not None:
        allowed, reason = ot.is_pack_allowed(p["pack"])
        out["pack_allowed"] = allowed
        out["pack_reason"] = reason
    if p.get("protocol"):
        out["can_route_protocol"] = ot.can_route_protocol(p["protocol"])
    return out


@app.post("/intel/action-envelope")
async def action_envelope_mint(payload: dict):
    """Mint + validate a durable action envelope (Codex Tier-3 #11) — the replay-safe contract a side-effecting
    tool carries. Body: {mission_id, tool, inputs, scope, permission, approval_id}. Returns the envelope (only
    hashes of secret-stripped input/scope — no raw secrets), plus the authorize + validate decisions so a
    caller can see whether an INTRUSIVE action would be admitted."""
    import action_envelope as ae
    p = payload or {}
    env = ae.make_envelope(str(p.get("mission_id") or "adhoc"), str(p.get("tool") or "tool"),
                           p.get("inputs") or {}, p.get("scope") or {},
                           permission=str(p.get("permission") or "ACTIVE"))
    authz = ae.authorize(env, approval_id=p.get("approval_id"))
    valid = ae.validate_before_execute(authz["envelope"], p.get("scope") or {}, p.get("inputs") or {},
                                       approval_id=p.get("approval_id"))
    return {"envelope": authz["envelope"], "authorized": authz["allowed"], "validate": valid}


@app.post("/intel/api-inventory")
async def api_inventory_reconcile(payload: dict):
    """API inventory drift + version governance (Codex Tier-2 #10): reconcile runtime vs documented (OpenAPI)
    vs archived vs code-discovered endpoints. Surfaces undocumented-live, documented-dead (coverage gap),
    deprecated-version, multi-version-coexistence, schema-drift, and third-party dependency observations —
    almost all OBSERVATIONS/leads, not vulns. Off-scope archived endpoints are not imported as live. Body:
    {runtime, documented, archived, code, observed_fields, spec_fields, outbound_urls, target_hosts}."""
    import api_inventory as ai
    p = payload or {}
    out = {"drift": ai.reconcile(runtime=p.get("runtime"), documented=p.get("documented"),
                                 archived=p.get("archived"), code=p.get("code"))}
    if p.get("observed_fields") is not None or p.get("spec_fields") is not None:
        out["schema_drift"] = ai.schema_drift(p.get("observed_fields"), p.get("spec_fields"),
                                              endpoint=str(p.get("endpoint") or ""))
    if p.get("outbound_urls"):
        out["third_party"] = ai.third_party_dependency_apis(p.get("outbound_urls"), p.get("target_hosts"))
    return out


@app.post("/intel/field-authz")
async def field_authz_analyze(payload: dict):
    """Field-level authorization / excessive-data-exposure analysis (Codex Tier-2 #9) — distinct from BOLA.
    Body: {response, role?, authenticated?, own_resource?} flags a single response that leaks sensitive/admin/
    debug fields; {low_response, high_response, low_role, high_role} does a two-persona differential. Raw
    secret values are redacted; a same-role diff yields nothing (no privilege differential)."""
    import field_authz as fa
    p = payload or {}
    out = {}
    if "low_response" in p or "high_response" in p:
        out["differential"] = fa.field_authz_diff(p.get("low_response") or {}, p.get("high_response") or {},
                                                   low_role=str(p.get("low_role") or "user"),
                                                   high_role=str(p.get("high_role") or "admin"))
    if "response" in p:
        out["excessive_data_exposure"] = fa.excessive_data_exposure(
            p.get("response") or {}, role=str(p.get("role") or "user"),
            authenticated=bool(p.get("authenticated", True)), own_resource=bool(p.get("own_resource", True)))
    return out


@app.post("/intel/api-protocols")
async def api_protocol_inventory(payload: dict):
    """API protocol inventory beyond REST/OpenAPI/GraphQL (Codex Tier-2 #8). Body may carry {wsdl: <xml>} to
    parse a WSDL into service/endpoints/operations + SOAP XML-body candidates (routing to the XXE check under
    existing safety rules), {html, base_url} to discover WSDL links, and/or {headers, content_type, path} to
    classify a protocol family. INVENTORY ONLY — no vulnerability is implied. Off-scope WSDL URLs are dropped."""
    import api_protocols as ap
    p = payload or {}
    out = {"note": "API protocol inventory — surface only; no vulnerabilities implied by inventory."}
    if p.get("html") is not None:
        out["wsdl_links"] = ap.detect_wsdl_links(str(p.get("html")), base_url=str(p.get("base_url") or ""))
    if p.get("wsdl"):
        parsed = ap.parse_wsdl(str(p.get("wsdl")))
        out["wsdl"] = parsed
        out["soap_candidates"] = ap.soap_body_candidates(parsed)
    if any(k in p for k in ("headers", "content_type", "path")):
        out["protocol"] = ap.detect_protocol(headers=p.get("headers"), path=str(p.get("path") or ""),
                                              content_type=str(p.get("content_type") or ""))
        grpc = ap.grpc_observation(headers=p.get("headers"), url=str(p.get("path") or ""),
                                   content_type=str(p.get("content_type") or ""))
        if grpc:
            out["grpc_observation"] = grpc
    return out


@app.get("/intel/defenses")
async def defense_catalog(family: str = None):
    """Curated defensive-control mappings (Codex Tier-1 #3): finding family -> the control(s) that neutralize
    it + the attacker CAPABILITY each reduces. HONEST: curated local mappings, not official D3FEND ids. With
    ?family= it returns the controls for one family (unknown family -> empty, never a fabricated control)."""
    import defense_mapping as dm
    try:
        if family:
            return {"family": family, "controls": dm.controls_for(family), "reduces": dm.reduces_for(family)}
        return {"scheme": dm.SCHEME, "provenance": dm.PROVENANCE, "families": dm.families_covered(),
                "controls": {f: dm.controls_for(f) for f in dm.families_covered()}}
    except Exception as e:
        return {"error": str(e)}


@app.get("/coverage/asvs")
async def asvs_coverage(session: str = None):
    """Curated-partial OWASP ASVS-5 objective coverage: what security PROPERTIES were verified / failed /
    blocked / not tested — the verification-objective complement to WSTG's test catalog. With `?session=<sid>`
    it folds in that mission's findings (which violate objectives) and the engines that actually ran (a clean
    run verifies the property); without a session it returns the static curated catalog (all untested). HONEST:
    always a curated partial model, never a full-ASVS claim."""
    import asvs_model as am
    try:
        findings, ran = [], set()
        if session:
            findings = db.get_findings(session) or []
            for l in db.get_logs(session, limit=4000):
                if l.get("type") == "tool_call" and l.get("tool"):
                    ran.add(l.get("tool"))
        return am.assess(findings, attempted_engines=ran)
    except Exception as e:
        return {"error": str(e)}


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


def _kev_cves():
    """The set of EXACT CVE ids in CISA's KEV catalog — the only defensible basis for a client-facing
    'known-exploited in the wild' claim (KEV is CVE-indexed; never inferred from CWE class)."""
    import intel_feeds
    try:
        return intel_feeds.known_exploited_cves(_intel_snapshots())
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


@app.post("/benchmark/natas")
async def natas_ladder_run(payload: dict = None):
    """Climb the OverTheWire Natas ladder with Apolaki's GENERAL engines and report an honest ceiling.

    Natas is uniquely good as a benchmark because each level hides the NEXT level's password, so the
    oracle is not a judgement call: a recovered value either authenticates or it does not.

    SAFETY. The target host family is FIXED to `natas.labs.overthewire.org` and cannot be overridden by
    the caller — this endpoint makes outbound requests to a third party, and a benchmark runner that can
    be pointed anywhere is an SSRF primitive with a friendly name. Only `last_level` is tunable.

    HONESTY. `solved` counts only levels where a general engine surfaced a credential that then
    authenticated. Results are bucketed by class (surface / injection / session_logic / specialist)
    because a scanner missing a hash-extension forgery is a different fact from one missing a SQL
    injection, and one percentage covering both says nothing.

    Discovered credentials are returned to the caller but NEVER written to the repository."""
    import urllib.error
    import urllib.request
    from urllib.parse import urljoin
    import natas_ladder as nl
    try:
        last = max(0, min(int((payload or {}).get("last_level", 10)), nl.LAST_LEVEL))

        def fetch(u, h):
            try:
                r = urllib.request.urlopen(urllib.request.Request(u, headers=h), timeout=20)
                return r.getcode(), r.read().decode("utf-8", "replace"), str(r.headers)
            except urllib.error.HTTPError as e:
                try:
                    return e.code, e.read().decode("utf-8", "replace"), str(e.headers)
                except Exception:
                    return e.code, "", ""
            except Exception:
                return 0, "", ""

        def post(u, h, payload):
            """Form submission — the step that turns observation into interaction. Levels 0-5 fall to
            observation alone; the first level needing a discovered value SUBMITTED is where an
            observation-only harness stops."""
            from urllib.parse import urlencode
            data = urlencode(payload or {}).encode()
            hh = dict(h)
            hh["Content-Type"] = "application/x-www-form-urlencoded"
            try:
                r = urllib.request.urlopen(urllib.request.Request(u, data=data, headers=hh), timeout=20)
                return r.getcode(), r.read().decode("utf-8", "replace"), str(r.headers)
            except urllib.error.HTTPError as e:
                try:
                    return e.code, e.read().decode("utf-8", "replace"), str(e.headers)
                except Exception:
                    return e.code, "", ""
            except Exception:
                return 0, "", ""

        pw, results, creds = "natas0", [], {}
        for lvl in range(0, last + 1):
            # ONE implementation: natas_ladder.solve_level. Two copies of a solver drift and then
            # disagree about what the benchmark measured.
            r = nl.solve_level(lvl, pw, fetch, post=post)
            results.append(r)
            if not r.get("solved"):
                break
            creds["natas%d" % (lvl + 1)] = r["next_password"]
            pw = r["next_password"]
        summary = nl.summarise(results)
        safe = [{k: v for k, v in r.items() if k != "next_password"} for r in results]
        return {"summary": summary, "report": nl.report_line(summary), "levels": safe,
                "credentials_recovered": len(creds),
                "note": "Credentials are returned here but never written to the repository. "
                        "General engines only — no level-specific logic."}
    except Exception as e:
        return {"error": str(e)}


@app.post("/benchmark/blind/{session_id}")
async def blind_benchmark_run(session_id: str, answer_key_url: str = ""):
    """BLIND benchmark (CHAD): score a SEALED mission against the target's published answer key WITHOUT
    the scanner ever having seen it. The mission ran with the answer-key surface hard-blocked at the
    scope choke point; here we (1) seal + hash the mission's independently-produced output, (2) THEN fetch
    the answer key with our own client (bypassing the agent), (3) parse + match by path+family+proof,
    (4) emit two hashed+timestamped artifacts whose ordering proves the key did not influence discovery."""
    import blind_benchmark as bb
    import httpx
    m = _require_mission(session_id)
    findings = db.get_findings(session_id) or []
    ctx = m.get("context") or {}
    leads = ctx.get("leads") or []
    cvrec = (ctx.get("candidate_validation") or {}).get("records") or []
    candidates = list(leads) + list(cvrec) + list(findings)
    counts = (ctx.get("candidate_validation") or {}).get("counts") or {}
    validations = {"executed": counts.get("confirmed", 0) + counts.get("dismissed", 0),
                   "dismissed": counts.get("dismissed", 0), "unsupported": counts.get("unsupported", 0),
                   "blocked": counts.get("blocked", 0)}
    # derive the target host from the mission's own artifacts (never from the answer key)
    host = ""
    for it in findings + candidates:
        t = str((it or {}).get("target") or "")
        if t.startswith("http"):
            from urllib.parse import urlparse as _up
            host = _up(t).netloc
            break
    if not host:
        host = str(ctx.get("primary_host") or (m.get("in_scope") or [""])[0] or "").split("//")[-1].split("/")[0]
    key_url = answer_key_url or ("https://%s/vulnerabilities" % host)
    code_rev = ctx.get("code_rev") or os.environ.get("APOLAKI_GIT_COMMIT", "")

    # 1) SEAL the mission output BEFORE the answer key is ever fetched (hash + timestamp)
    blind = bb.blind_artifact(session_id, host, findings, candidates, validations, code_rev)
    # ON THE DATA VOLUME, NOT BESIDE THE CODE. This used to resolve to /app/benchmark_results, which is
    # INSIDE the image: every `docker compose build agent` + recreate deleted it. For ordinary output that
    # is annoying; for these two files it destroys the evidence itself. The sealed artifact and its hash
    # are the proof that the mission was frozen BEFORE the answer key was fetched — lose them and the
    # claim that a benchmark ran blind is unfalsifiable, which is worth nothing. Observed for real: the
    # 2026-08-09 ginandjuice artifacts were gone after the next rebuild and survive only because they had
    # been copied out by hand. Same BBH_DATA_DIR convention every other writer here already follows.
    outdir = os.path.join(os.environ.get("BBH_DATA_DIR", "/app/data"), "benchmark_results")
    os.makedirs(outdir, exist_ok=True)
    bpath = os.path.join(outdir, "blind_%s_%s.json" % (session_id, blind["content_hash"][:12]))
    with open(bpath, "w", encoding="utf-8") as fh:
        json.dump(blind, fh, indent=2, default=str)

    # 2) ONLY NOW fetch the answer key, with our OWN client (the agent/scope never sees it)
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=30) as c:
            r = await c.get(key_url)
            key_html = r.text if r.status_code == 200 else ""
    except Exception as e:
        return {"error": "answer-key fetch failed: %s" % e, "blind_artifact": blind, "blind_path": bpath}
    if not key_html:
        return {"error": "answer key empty/unreachable at %s" % key_url, "blind_artifact": blind}

    # 3) parse + match by path+family+proof, 4) score, 5) comparison artifact (bound to the sealed hash)
    expected = bb.parse_answer_key(key_html, host)
    matched = bb.match(expected, findings, candidates)
    scored = bb.score(expected, matched, candidates, validations)
    key_sha = bb.sha256_text(key_html)
    comparison = bb.comparison_artifact(blind, expected, matched, scored, key_sha, key_url)
    cpath = os.path.join(outdir, "compare_%s_%s.json" % (session_id, comparison["content_hash"][:12]))
    with open(cpath, "w", encoding="utf-8") as fh:
        json.dump(comparison, fh, indent=2, default=str)

    return {"session_id": session_id, "target": host, "answer_key_url": key_url,
            "blind_artifact_hash": blind["content_hash"], "blind_sealed_at": blind["sealed_at"],
            "answer_key_sha256": key_sha, "ordering_ok": comparison["ordering_ok"],
            "score": scored, "expected_instances": len(expected),
            "true_positives": [e["path"] + " / " + e["family"] for e in matched["true_positives"]],
            "missed": [e["path"] + " / " + e["family"] for e in matched["missed"]],
            "discovered_unconfirmed": [e["path"] + " / " + e["family"] for e in matched["discovered_unconfirmed"]],
            "false_positives": matched["false_positives"],
            "artifacts": {"blind": bpath, "comparison": cpath}}


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
        code_intel=code_intel, authenticated=bool(ctx.get("authenticated")),
        graph=getattr((sessions.get(session_id) or {}).get("tools"), "graph", None))
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
                                 leads=leads, code_intel=code_intel,
                                 graph=getattr((sessions.get(session_id) or {}).get("tools"), "graph", None))
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
        intel=m["context"].get("intel"), kev_cwes=_kev_cwes(), kev_cves=_kev_cves(),
        orchestration=m["context"].get("orchestration"),
        auth_artery=_auth_artery_evidence(session_id, m), intel_provenance=_intel_provenance(session_id),
        degraded=m["context"].get("degraded"),
        candidate_validation=m["context"].get("candidate_validation"))
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
            delta=_delta(session_id), execution=_execution(m), report_id=session_id,
            intel_provenance=_intel_provenance(session_id),
            auth_artery=_auth_artery_evidence(session_id, m),
            degraded=(m.get("context", {}) or {}).get("degraded"),
            candidate_validation=(m.get("context", {}) or {}).get("candidate_validation")),
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
        # persona vault refs (role -> vault://...) so the NEXT scan reacquires FULL personas from their
        # stored login recipes, not just the single discovered credential. Refs only — no secrets.
        prefs = getattr(ag, "_persona_refs", None)
        if prefs:
            snap["persona_refs"] = prefs
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
        # Snapshot intel PROVENANCE from the LIVE graph (which carries the wayback/github/cloud
        # feed nodes the rebuilt projection would drop) so the report/UI can show WHERE the world
        # model came from and what still needs current validation — after teardown too. Redacted
        # by construction (secrets are already hashes/vault refs). Best-effort.
        try:
            if getattr(tools, "graph", None) is not None:
                ctx["graph_data"]["provenance"] = tools.graph.provenance_summary()
        except Exception:
            pass
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
        # Persist structured PROOF the auth artery fired (personas, auth_success, matrix), so it is
        # queryable from the report/API instead of only in the event stream. Also reconcile the
        # top-level `authenticated` flag: it previously tracked raw-header/login ONLY, reading False
        # even when the autonomous artery bound live persona sessions and ran an authenticated matrix.
        artery = getattr(ag, "_auth_artery", {"ran": False}) or {"ran": False}
        ctx["auth_artery"] = artery
        if artery.get("ran") and artery.get("auth_success", 0) >= 1:
            ctx["authenticated"] = True
        # utility-ranked attack-path opportunities from the canonical graph (Pentera-style: which lead
        # to pursue next, ranked by impact x evidence-confidence / cost / risk with Cosmos decay). Same
        # source the /graph endpoint serves, snapshotted so an archived report renders it too.
        try:
            import asset_graph as _ag
            recon, urls, findings = _graph_inputs(session_id)
            _personas = {"personas": artery["personas"]} if artery.get("personas") else None
            g = _ag.build_from_engagement(session_id, recon=recon, urls=urls, findings=findings,
                                          personas=_personas, capabilities=list(artery.get("capabilities") or []),
                                          scope_asset=memory_mod.target_key(m["scope"]))
            ctx["orchestration"]["attack_paths"] = g.next_best_actions(limit=8)
        except Exception:
            pass
        # structured degraded/failure state (e.g. a halted primary cycle) so it shows in status/report
        deg = getattr(ag, "_degraded", None)
        if deg:
            ctx["degraded"] = deg
        # candidate-validation ledger: every testable lead -> validator -> terminal state + evidence,
        # so a reviewer can see nothing was left sitting untested (and "no browser" is visible debt).
        cval = getattr(ag, "_candidate_assurance", None)
        if cval:
            ctx["candidate_validation"] = {"counts": getattr(ag, "_candidate_validation_counts", {}) or {},
                                           "records": cval[:200]}
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
    # Liveness-independent fallback: once the session is evicted the live agent is gone, but the auth
    # artery persisted its personas (with has_session) + capabilities to context. Use them so the
    # canonical graph is IDENTICAL whether or not the session is still in RAM — a canonical graph must
    # not depend on process memory (the determinism benchmark caught persona/session nodes vanishing
    # after eviction). Personas carry role/rank/method/identity-label only, never secrets.
    aa = (m.get("context") or {}).get("auth_artery") or {}
    if personas is None and aa.get("personas"):
        personas = {"personas": aa["personas"]}
    if not caps and aa.get("capabilities"):
        caps = list(aa["capabilities"])
    g = _ag.build_from_engagement(session_id, recon=recon, urls=urls, findings=findings,
                                  personas=personas, capabilities=caps,
                                  scope_asset=memory_mod.target_key(m["scope"]),
                                  code_review=(m.get("context") or {}).get("code_review"))
    # rebuild EVERY persisted cloud account's graph so an ARCHIVED mission keeps its cloud
    # account/resource/role nodes (CHAD #2/#5) — shared with the portable export.
    cloud_summary = _project_cloud_postures(g, m)
    d = g.to_dict()
    d["stats"] = g.stats()
    d["next_best_actions"] = g.next_best_actions()   # the planner querying the world model
    d["provenance"] = _intel_provenance(session_id)  # WHERE the world model came from (feeds + worklist)
    d["cloud_postures"] = cloud_summary
    return d


@app.get("/graph/opengraph/{session_id}")
async def get_opengraph_export(session_id: str):
    """Sanitized OpenGraph / BloodHound-style projection of the canonical graph (Codex Tier-2 #7): namespaced
    node kinds, secrets exported as refs only, and edges that DISTINGUISH topology from capability transitions
    (only capability edges with traversable=true are attack-path edges). An interoperability export, never the
    internal model. Built from the same one engagement state as /graph/canonical (no island)."""
    m = _require_mission(session_id)
    import asset_graph as _ag
    import graph_export as _gx
    recon, urls, findings = _graph_inputs(session_id)
    aa = (m.get("context") or {}).get("auth_artery") or {}
    personas = {"personas": aa["personas"]} if aa.get("personas") else None
    caps = list(aa.get("capabilities") or [])
    g = _ag.build_from_engagement(session_id, recon=recon, urls=urls, findings=findings,
                                  personas=personas, capabilities=caps,
                                  scope_asset=memory_mod.target_key(m["scope"]),
                                  code_review=(m.get("context") or {}).get("code_review"))
    _project_cloud_postures(g, m)
    _scope_blob = " ".join(str(x) for x in (m.get("in_scope") or [])) + " " + str(m.get("scope") or "")
    env = (m.get("context") or {}).get("environment") or (
        "lab" if any(t in _scope_blob for t in ("localhost", "127.0.0.1", "juice-shop", ":3000")) else "unknown")
    return _gx.export_graph(g, scope=memory_mod.target_key(m["scope"]), environment=env)


@app.post("/retest/{session_id}")
async def retest_findings(session_id: str, finding_id: str = ""):
    """Remediation-revalidation closure loop (Picus): re-fire each confirmed finding's oracle and report
    OPEN (still vulnerable) / CLOSED (fixed) / INCONCLUSIVE (can't tell — never a false closure). Read-only:
    only families whose confirming request is a safe idempotent GET to the finding's OWN in-scope target are
    auto-retested; state-changing or recipe-less findings are honestly not_retestable. Feeds attack_chain
    (OPEN re-confirms, CLOSED dismisses the dead technique) so a closure updates the cross-run memory."""
    import httpx
    import retest as _rt
    import attack_chain as _ac
    m = _require_mission(session_id)
    findings = db.get_findings(session_id) or []
    if finding_id:
        findings = [f for f in findings if str(f.get("id")) == str(finding_id)]
    # in-scope guard: a retest may only re-hit a target the mission was scoped to. Rebuild the mission's
    # ScopeEngine from m["scope"] (the CORRECT shape — the old m.get("in_scope") always read empty because
    # scope lives at m["scope"]["in_scope"], so the guard silently NEVER fired, #9) and validate EVERY
    # retest URL — host, pinned port, and pinned path included.
    import scope as _scope
    _sc = m.get("scope") or {}
    _scoped = bool(_sc.get("in_scope"))
    _eng = None
    if _scoped:
        _eng = _scope.ScopeEngine()
        try:
            _eng.load_manual(_sc.get("bases") or _sc.get("in_scope") or [], _sc.get("out_of_scope") or [],
                             _sc.get("program") or "Program")
        except Exception:
            _eng = None
    results, summary = [], {"open": 0, "closed": 0, "inconclusive": 0, "not_retestable": 0}
    async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=20) as c:
        for f in findings:
            base = {"id": f.get("id"), "title": f.get("title"), "family": f.get("family")}
            plan = _rt.plan(f)
            if not plan.get("retestable"):
                summary["not_retestable"] += 1
                results.append({**base, "verdict": "not_retestable", "detail": plan.get("reason", "")})
                continue
            url = plan["url"]
            if _eng is not None and not _eng.validate(url)[0]:
                summary["inconclusive"] += 1
                results.append({**base, "verdict": "inconclusive", "detail": "target out of mission scope"})
                continue
            try:
                r = await c.get(url)
                v = _rt.evaluate(f, r.status_code, body=r.text, headers=dict(r.headers))
            except Exception as ex:
                v = {"verdict": "inconclusive", "detail": "retest request failed: %s" % ex, "url": url}
            summary[v["verdict"]] = summary.get(v["verdict"], 0) + 1
            results.append({**base, **v})
            try:
                _ac.record(f.get("target"), f.get("family") or f.get("title", "")[:40],
                           _rt.chain_outcome(v["verdict"]), evidence="retest: " + str(v.get("detail", ""))[:200],
                           session=session_id, name="retest")
            except Exception:
                pass
    return {"session_id": session_id, "retested": len(results), "summary": summary, "results": results}


@app.get("/mission/{session_id}/poc-bundle")
async def poc_bundle_export(session_id: str, finding_id: str = ""):
    """Per-finding proof-of-concept EVIDENCE BUNDLES (#111): a self-contained, submission-ready artifact
    per CONFIRMED finding — reproduction (curl + PoC), the #115 FP-safety negative control, the evidence-
    graded impact, the #117 retest recipe, remediation, provenance. Reuses poc/retest/report/technique_model
    (no island). Secrets redacted. Downloadable JSON; the exact evidence a reviewer needs to believe +
    reproduce + re-verify, nothing external required."""
    import poc_bundle as _pb
    m = _require_mission(session_id)
    findings = db.get_findings(session_id) or []
    if finding_id:
        findings = [f for f in findings if str(f.get("id")) == str(finding_id)]
    # scope lives at m["scope"]["in_scope"] — m.get("in_scope") is the wrong shape and always empty
    # (same class as the retest-scope bug fixed in the 2026-08-06 fix-pass #9).
    _scope = m.get("scope") or {}
    tgt = str((_scope.get("in_scope") or _scope.get("bases") or [""])[0] or "")
    tool_version = (m.get("context") or {}).get("code_rev") or os.environ.get("APOLAKI_GIT_COMMIT", "")
    chains = (m.get("context") or {}).get("chains") or []   # the attack path each dossier's finding is part of
    bundles = _pb.build_all(findings, tool_version=tool_version, target=tgt, chains=chains)
    return {"session_id": session_id, "count": len(bundles), "bundles": bundles}


@app.get("/mission/{session_id}/sarif")
async def sarif_export(session_id: str):
    """Export this mission's ATOMIC findings as SARIF 2.1.0 for toolchain ingestion (Codex Tier-1 #2). Attack
    CHAINS are intentionally not exported (SARIF has no faithful chain semantics — chain severity stays
    Apolaki's own model). Snippets/evidence are redacted before emission."""
    import sarif_io as _sf
    _require_mission(session_id)
    findings = db.get_findings(session_id) or []
    return _sf.export_sarif(findings, tool_name="Apolaki")


@app.get("/mission/{session_id}/tool-provenance")
async def tool_provenance_view(session_id: str):
    """Per-external-tool-execution provenance for a live mission (Codex Tier-3 #14): tool + binary path/version,
    argv hash (secrets redacted), timeout, exit code, output-artifact hash, scope hash, permission class. Read
    from the live session's tool wrapper; empty (with a note) once the session is evicted from RAM."""
    _require_mission(session_id)
    tl = (sessions.get(session_id) or {}).get("tools")
    recs = list(getattr(tl, "_tool_provenance", []) or []) if tl is not None else []
    return {"session_id": session_id, "count": len(recs), "records": recs,
            "note": ("" if tl is not None else
                     "session not live in RAM — external-tool provenance is in-memory this build; "
                     "re-run or keep the session live to capture it.")}


@app.post("/intel/sarif")
async def sarif_import(payload: dict):
    """Import a SARIF document (Semgrep/CodeQL/other SAST) as Apolaki CANDIDATES — NEVER auto-confirmed
    findings. Each result requires runtime validation; producer suppressions are preserved as external
    metadata (not trusted triage); secret-looking snippets are redacted. Body: a SARIF 2.1.0 document."""
    import sarif_io as _sf
    cands = _sf.import_sarif(payload or {})
    return {"count": len(cands), "candidates": cands,
            "note": "SARIF results are UNVALIDATED candidates; runtime proof is still required before any "
                    "becomes a confirmed finding or an attack-path edge."}


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
    # include EVERY persisted cloud account in the portable export too (CHAD #5) — same rebuild the
    # canonical graph uses, so an archived export never loses cloud graph state.
    cloud_summary = _project_cloud_postures(g, m)
    return _me.build_bundle(mission=m, findings=findings, snapshot=snap,
                            graph={**g.to_dict(), "stats": g.stats(), "cloud_postures": cloud_summary},
                            capabilities=caps)


def _cloud_posture_run(provider: str) -> dict:
    """Collect + analyze a provider's posture (READ-ONLY) and shape the response. No state change."""
    import cloud_iam as _ci
    res = _ci.collect(provider)
    findings = res.get("findings", []) or []
    partial = bool(res.get("partial")) or bool(res.get("blocked"))
    if res.get("blocked"):
        posture = "blocked"
    elif partial:
        posture = "incomplete"                     # some endpoints failed — 0 findings is NOT "clean"
    elif findings:
        posture = "issues_found"
    else:
        posture = "clean"                          # complete collection AND zero findings
    return {"res": res, "findings": findings, "partial": partial, "posture": posture,
            "provider": provider, "blocked": bool(res.get("blocked")),
            "reason": res.get("reason", ""), "counts": res.get("counts", {}),
            "manifest": res.get("manifest", {}),
            "summary": {"findings": len(findings),
                        "by_severity": {s: sum(1 for f in findings if f.get("severity") == s)
                                        for s in ("critical", "high", "medium", "low")},
                        "collection_complete": not partial}}


@app.post("/mission/{session_id}/codereview")
async def codereview_ingest(session_id: str, payload: dict):
    """Code review as pre-recon (#114 Part 2): run static source review on SUPPLIED authorized source,
    store it on the mission, and seed the canonical graph with STATIC candidate facts (routes / sinks /
    secrets) that the planner then validates at runtime (white -> black). Secrets are hashed, never stored
    raw; a source route is reachable='unverified' until a live probe proves it. Body: {source, source_name}."""
    import codereview as _cr
    import codereview_graph as _crg
    import asset_graph as _ag
    m = _require_mission(session_id)
    src = str((payload or {}).get("source") or "")
    name = str((payload or {}).get("source_name") or "source")
    if not src.strip():
        raise HTTPException(status_code=400, detail="no source provided")
    rev = _cr.review(src, name)
    ctx = dict(m.get("context") or {})
    prev = ctx.get("code_review") or {"findings": [], "endpoints": []}
    prev["findings"] = (prev.get("findings") or []) + (rev.get("findings") or [])
    prev["endpoints"] = sorted(set((prev.get("endpoints") or []) + (rev.get("endpoints") or [])))
    ctx["code_review"] = prev
    db.update_mission(session_id, context=ctx)
    g = _ag.AssetGraph(session_id)
    delta = _crg.seed(g, rev, scope_asset=memory_mod.target_key(m["scope"]))
    return {"session_id": session_id, "source_name": name,
            "review": {"findings": len(rev.get("findings") or []), "endpoints": len(rev.get("endpoints") or [])},
            "graph_delta": delta,
            "note": "static candidate facts seeded into the engagement graph; the planner validates them at runtime"}


@app.get("/intel/sources")
async def intel_sources_view():
    """The trusted-source ALLOWLIST + governance state (#114): every approved feed with tier / type /
    license / rate-limit / cache, whether a fetcher exists (`live`) and whether it is currently ENABLED
    (default: ALL OFF until a per-source flag or the Tier-1 master switch is set, and a key is present for
    key-gated sources). Also the ingestion lifecycle + the explicit prohibited list. Read-only, makes NO
    outward request. This is the operator's per-source configuration surface, so nothing is an island."""
    import intel_sources as _isrc
    srcs = [{k: s.get(k) for k in ("name", "tier", "type", "license", "requires_key", "live",
                                   "rate_per_min", "cache_ttl_s", "parser_version", "purpose")}
            | {"enabled": _isrc.is_enabled(s["name"])} for s in _isrc.allowlist()]
    return {"sources": srcs, "enabled": _isrc.enabled_sources(),
            "validation_states": list(_isrc.VALIDATION_STATES),
            "provenance_fields": list(_isrc.PROVENANCE_FIELDS),
            "prohibited": list(_isrc.PROHIBITED),
            "note": "external connectors are DISABLED by default; enable per-source via config + credentials"}


@app.get("/intel/audit")
async def intel_audit(limit: int = 100):
    """The outward-request audit log (#114): every governed connector call, with source / endpoint /
    purpose / target-scope / timestamp / status / rate-limit / cache / parser-version. Empty by default
    because connectors are disabled and make no requests. Read-only."""
    import intel_connectors as _ic
    return {"requests": _ic.audit_log(limit), "count": len(_ic.audit_log(limit))}


@app.get("/intel/registry")
async def intel_registry_view():
    """Staged intel-knowledge registry (#114): how many ingested candidates sit at each lifecycle state
    (candidate -> validating -> validated -> fixture_backed -> reviewed -> production). Only PRODUCTION
    records are trusted; internet intel never auto-promotes there. Read-only."""
    import intel_registry as _ir
    return {**_ir.stats(), "production": len(_ir.production())}


@app.post("/intel/fetch/{source}")
async def intel_fetch(source: str, key: str = ""):
    """Governed fetch of an allowlisted intel source (#114). Returns 'disabled' unless the source's
    allowlist entry is explicitly enabled (+ credential for key-gated). Records are strict-provenance
    CANDIDATES (untrusted until validated); the raw feed is never returned. No outward I/O when disabled."""
    import intel_connectors as _ic
    import intel_registry as _ir
    r = _ic.fetch(source, key)
    ingested = _ir.ingest(r.get("records") or []) if r["status"] == "ok" else 0
    return {"source": source, "status": r["status"], "cache": r.get("cache"),
            "records": len(r.get("records") or []), "ingested_as_candidates": ingested,
            "note": r.get("note"), "log": r.get("log")}


@app.get("/cloud/policy")
async def cloud_policy_view(provider: str = None, action: str = None):
    """The effective cloud provider-policy that GATES cloud actions (Codex Tier-1 #4). Default is read-only:
    only read-only inventory is permitted; every mutating/active/destructive action is default-denied until an
    explicit policy (env APOLAKI_CLOUD_POLICY) grants it. With ?action= it returns the gate decision for that
    action (dry-run — no cloud call is made)."""
    import cloud_policy as cp
    try:
        out = {"effective_policy": cp.summary(provider)}
        if action:
            out["decision"] = cp.gate(provider or "any", action)
        return out
    except Exception as e:
        return {"error": str(e)}


@app.get("/cloud/posture/{provider}")
async def cloud_posture(provider: str):
    """READ-ONLY PREVIEW of the operator's OWN cloud account (CHAD: a GET must not change state). For
    `linode` it uses LINODE_TOKEN to enumerate users/firewalls/buckets/databases/instances (ALL pages)
    and flag misconfigs; token is auth-only and NEVER returned. An incomplete/failed collection is
    NEVER reported clean (partial/blocked + manifest). This endpoint does NOT persist anything — use
    POST /cloud/posture/{provider}/ingest to record a review into a mission."""
    p = _cloud_posture_run(provider)
    return {k: p[k] for k in ("provider", "blocked", "partial", "posture", "reason", "counts",
                              "manifest", "summary")} | {"findings": p["findings"]}


@app.post("/cloud/posture/{provider}/ingest")
async def cloud_posture_ingest(provider: str, session_id: str, account: str = "linode",
                               allow_unverified: bool = False):
    """EXPLICIT ingestion of a cloud posture review into a mission (state-changing => POST). Requires an
    explicit session_id + a VERIFIED collected account identity (CHAD final #2): if /account did not
    return an id, ingestion is REFUSED unless the operator passes allow_unverified=true, and then it is
    keyed under an explicit 'unverified:' namespace — the operator label is NEVER treated as a real id.
    CONTEXT-FIRST with honest partial-failure accounting (CHAD final #4): mission context is persisted
    FIRST; if that fails, NO findings are written (no orphaned findings). This ordering is NOT full ACID
    atomicity — after context persists, findings are written best-effort per-finding; any that fail are
    counted in results.findings_failed and set ingested=false, but already-written findings are not rolled
    back. Findings are deduped by (provider, account_id, title, target)."""
    import cloud_iam as _ci
    m = _require_mission(session_id)
    p = _cloud_posture_run(provider)
    if p["blocked"]:
        return {"ingested": False, "reason": p["reason"] or "collection blocked — nothing ingested",
                "posture": p["posture"], "partial": p["partial"], "manifest": p["manifest"]}
    res = p["res"]
    findings = p["findings"]
    prov = provider.lower()
    prov_tag = "%s-posture" % prov
    account_id_real = str(res.get("account_id") or "").strip()
    identity_verified = bool(account_id_real)
    # #2: never treat the operator label as a real identity. Refuse an unverified ingest unless the
    # operator explicitly opts in, and then namespace it as unverified.
    if not identity_verified and not allow_unverified:
        return {"ingested": False, "identity_verified": False, "posture": p["posture"],
                "reason": "account identity NOT verified (/account returned no id). Use a token that can "
                          "read /account, or pass allow_unverified=true to ingest under an explicit "
                          "UNVERIFIED key.", "manifest": p["manifest"]}
    account_id = account_id_real if identity_verified else ("unverified:%s" % account)
    acct_key = "%s:%s" % (prov, account_id)
    # #4 CONTEXT-FIRST: persist context FIRST; on failure write NO findings (avoids orphaned findings).
    # NOT full atomicity: the per-finding write loop below is best-effort and surfaces partial failures.
    context_persisted = False
    try:
        ctx = dict(m["context"])
        postures = dict(ctx.get("cloud_postures") or {})
        postures[acct_key] = {"provider": provider, "account": account, "account_id": account_id,
                              "identity_verified": identity_verified, "partial": p["partial"],
                              "posture": p["posture"], "manifest": p["manifest"],
                              "model": res.get("model", {}), "findings_total": len(findings)}
        ctx["cloud_postures"] = postures
        db.update_mission(session_id, context=ctx)
        context_persisted = True
    except Exception:
        context_persisted = False
    if not context_persisted:
        return {"ingested": False, "identity_verified": identity_verified, "account_id": account_id,
                "posture": p["posture"], "reason": "context persistence FAILED — no findings written "
                                                   "(context-first abort, no orphaned state)",
                "results": {"findings_attempted": len(findings), "findings_stored": 0,
                            "findings_deduped": 0, "findings_failed": 0, "context_persisted": False},
                "manifest": p["manifest"]}
    # context OK -> now write findings, deduped by (provider, account_id, title, target) (CHAD #1).
    existing = {(x.get("title"), x.get("target")) for x in (db.get_findings(session_id) or [])
                if str(x.get("provenance", "")).startswith(prov) and x.get("cloud_account_id") == account_id}
    attempted, stored, deduped, failed = len(findings), 0, 0, 0
    for f in findings:
        key = (f.get("title"), f.get("target"))
        f["provenance"] = prov_tag
        f["cloud_account"] = account
        f["cloud_account_id"] = account_id
        f["cloud_identity_verified"] = identity_verified
        if key in existing:
            deduped += 1
            continue
        try:
            db.add_finding(session_id, f)
            existing.add(key)
            stored += 1
        except Exception:
            failed += 1
    live_graph_projected = False
    if session_id in sessions:
        g = getattr(sessions[session_id]["tools"], "graph", None)
        if g is not None:
            try:
                _ci.to_graph(g, res.get("model", {}), account=account_id, source=prov)
                live_graph_projected = True
            except Exception:
                live_graph_projected = False
    ok = failed == 0                                    # context already guaranteed persisted here
    return {"ingested": bool(ok), "identity_verified": identity_verified,
            "partial": (not ok) or bool(p["partial"]) or (not identity_verified),
            "mission": session_id, "provider": provider, "account": account, "account_id": account_id,
            "posture": p["posture"],
            "results": {"findings_attempted": attempted, "findings_stored": stored,
                        "findings_deduped": deduped, "findings_failed": failed,
                        "context_persisted": True, "live_graph_projected": live_graph_projected},
            "manifest": p["manifest"], "summary": p["summary"]}


@app.get("/capabilities")
async def get_capabilities():
    """Machine-readable capability matrix: every declared capability at its highest achieved state
    (implemented/wired/exercised/live_proven/blocked/unfinished — never merged), each with evidence.
    Includes an integrity self-check so the matrix cannot silently overstate."""
    import capability_matrix as cm
    m = cm.matrix()
    m["integrity_violations"] = cm.validate()
    return m


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
    if not db.update_finding(session_id, fid, finding):   # scoped to (mission, id) — no cross-mission write
        raise HTTPException(404, "finding not found in this mission")
    return {"ok": True}


@app.delete("/findings/{session_id}/{fid}")
async def delete_finding(session_id: str, fid: str):
    _require_mission(session_id)                          # was unguarded — require the mission first
    if not db.delete_finding(session_id, fid):            # scoped to (mission, id) — no cross-mission delete
        raise HTTPException(404, "finding not found in this mission")
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
    db.update_finding(session_id, fid, merged)            # scoped to (mission, id) — tenant isolation (#10)
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
