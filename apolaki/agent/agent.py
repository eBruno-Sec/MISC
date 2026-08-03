import asyncio
import json
import os
import uuid
from typing import AsyncGenerator

import db
import triage as triage_mod
from scope import ScopeEngine, PermissionLevel
from tools import ToolRegistry, TOOL_PERMISSIONS

APPROVAL_TIMEOUT = int(os.getenv("BBH_APPROVAL_TIMEOUT", "0"))  # 0 = wait forever


def _zap_configured() -> bool:
    """True when a ZAP daemon is configured (ZAP_ADDR set), so the deterministic
    planner schedules a real DAST pass in Full mode. Read fresh (env can change);
    best-effort so a missing/partial zap_client never breaks planning."""
    try:
        import zap_client
        return zap_client.configured()
    except Exception:
        return False

DEFAULT_OPENROUTER_MODEL = "meta-llama/llama-3.3-70b-instruct:free"
DEFAULT_OPENROUTER_BASE = "https://openrouter.ai/api/v1"
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-6"


def resolve_ai_config() -> dict:
    """Resolve the effective AI provider/key/model/base_url.

    Precedence for every field: provider-specific var > generic AI_* alias >
    default. This keeps the original OPENROUTER_* / ANTHROPIC_* vars working while
    also accepting the generic AI_API_KEY / AI_MODEL / AI_BASE_URL format. Empty
    provider vars (e.g. OPENROUTER_API_KEY="" injected by compose) fall through to
    the generic alias, which is the fix for the empty-key 500. Read fresh each call
    so it reflects the current environment; the api_key is never logged."""
    provider = os.getenv("AI_PROVIDER", "openrouter").lower()
    g_key = os.getenv("AI_API_KEY", "").strip()
    g_model = os.getenv("AI_MODEL", "").strip()
    g_base = os.getenv("AI_BASE_URL", "").strip()
    if provider == "anthropic":
        key = os.getenv("ANTHROPIC_API_KEY", "").strip() or g_key
        model = os.getenv("ANTHROPIC_MODEL", "").strip() or g_model or DEFAULT_ANTHROPIC_MODEL
        base = g_base  # empty -> the anthropic SDK uses its own default endpoint
        key_var = "ANTHROPIC_API_KEY"
    else:
        provider = "openrouter"
        key = os.getenv("OPENROUTER_API_KEY", "").strip() or g_key
        model = os.getenv("OPENROUTER_MODEL", "").strip() or g_model or DEFAULT_OPENROUTER_MODEL
        base = g_base or DEFAULT_OPENROUTER_BASE
        key_var = "OPENROUTER_API_KEY"
    return {"provider": provider, "api_key": key, "model": model,
            "base_url": base, "key_var": key_var}


def ai_status() -> dict:
    """Secret-free view of the effective AI config for /config and the /engage
    preflight. Reports readiness and where the key came from, but never the key."""
    c = resolve_ai_config()
    ready = bool(c["api_key"])
    if ready:
        source = c["key_var"] if os.getenv(c["key_var"], "").strip() else "AI_API_KEY"
    else:
        source = ""
    hint = "" if ready else f"{c['key_var']} is missing — set it (or AI_API_KEY) with your {c['provider']} API key."
    return {"provider": c["provider"], "model": c["model"], "base_url": c["base_url"],
            "ready": ready, "key_var": c["key_var"], "key_source": source, "hint": hint}

# tool -> assessment phase (drives the phase status bar in the UI)
PHASE_OF = {
    "run_subfinder": "recon", "run_crtsh": "recon", "run_wayback": "recon", "run_dns": "recon",
    "run_asn": "recon", "run_github_recon": "recon",
    "run_httpx": "enum", "http_probe": "enum", "run_whatweb": "enum", "run_fingerprint": "enum",
    "run_katana": "enum", "fetch_openapi": "enum", "check_takeover": "enum",
    "run_graphql": "enum", "run_jwt": "enum", "run_xss": "probe", "run_dom_audit": "probe", "run_js_review": "enum",
    "run_csrf": "enum", "run_oauth": "enum",
    "run_nmap": "scan", "run_nmap_vuln": "scan", "run_nuclei": "scan", "run_zap": "scan",
    "run_content_discovery": "probe", "run_ffuf": "probe", "run_web_probes": "probe",
    "run_injection_probes": "probe", "run_bfla": "probe", "run_race": "probe",
    "run_ssrf": "probe", "run_deserialization": "probe", "run_exposure": "probe",
    "run_xxe": "probe", "run_sqli": "probe", "run_auth_sqli": "probe", "run_cmdi": "probe",
    "run_form_cmdi": "probe", "run_nosqli": "probe", "run_form_nosqli": "probe", "run_upload_test": "probe",
    "run_cache_poison": "probe", "run_llm_probe": "probe", "run_stored_xss": "probe",
    "run_param_mine": "scan", "run_anomaly_scan": "scan", "run_dalfox": "probe", "run_sqlmap": "probe",
    "generate_playbook": "guidance", "store_finding": "report",
}
PHASES = ["recon", "enum", "scan", "probe", "guidance", "report"]

# Tools whose confirmed, finding-shaped results should be auto-stored when no model
# is driving (deterministic / low_ai). These native probes only emit CONFIRMED
# vulns; without auto-store a deterministic scan would confirm and then drop them.
_AUTO_STORE_TOOLS = {
    "run_sqli", "run_auth_sqli", "run_form_cmdi", "run_nosqli", "run_form_nosqli", "run_upload_test",
    "run_cache_poison", "run_llm_probe", "run_cmdi", "run_ssrf", "run_xss", "run_stored_xss", "run_dom_audit", "run_xxe", "run_deserialization",
    "run_injection_probes", "run_web_probes", "run_exposure", "run_bfla", "run_race",
    "run_nuclei", "run_zap", "check_takeover", "run_oauth", "run_jwt", "run_csrf",
    "run_dalfox", "run_sqlmap", "run_graphql", "run_js_review",
    "run_content_discovery", "run_ffuf", "run_nmap_vuln", "run_param_mine", "run_anomaly_scan",
    # investigative + exploitation tools (their confirmed findings must persist too)
    "run_dir_harvest", "confirm_idor", "run_metadata", "run_sourcemap", "test_numeric_abuse",
}
# Confirmatory tools that emit no per-finding confidence grade — their results are
# confirmed by construction (a template/active-scan/fingerprint match). Everything
# else must carry confidence=="confirmed" to enter the report.
_CONFIRMED_BY_TOOL = {"run_nuclei", "run_zap", "check_takeover", "run_sqlmap", "run_dalfox"}

SYSTEM_PROMPT = """You are a professional bug bounty hunter operating exclusively within provided scope.

CURRENT PHASE: Tier 1 — HackerOne/Bugcrowd public programs.
PRIORITY VULN CLASSES: IDOR/BOLA, broken access control, business-logic flaws, API authorization, subdomain takeovers, exposed sensitive endpoints, injection (SQLi/XSS/SSRF/SSTI/traversal).

HARD RULES:
1. Never test any asset not explicitly listed in scope. A scope block means stop — do not retry.
2. Passive recon before active scanning. Enumeration before fingerprinting. Fingerprinting before nuclei. Nuclei before intrusive probing.
3. Start nuclei with safe tags only (tech, misconfig, exposed-panels, takeovers). Escalate to cve tags only on targets with confirmed vulnerable versions.
4. Never brute-force credentials.
5. Call store_finding only when: evidence is real, the PoC is reproducible, impact is clearly articulated, and you have exact reproduction steps a triage reviewer can follow.
6. Do not store theoretical or speculative findings.
7. INTRUSIVE tools (content discovery, web probes, ffuf, dalfox, sqlmap) require operator approval unless the run is pre-authorized. If a probe is denied, continue with passive/active work.
8. SEVERITY DISCIPLINE — be consistent between what you say and what you store. Missing SPF/DMARC/DKIM, missing CAA, and missing security headers (CSP/HSTS/X-Frame-Options) are LOW or INFORMATIONAL email/transport-hygiene observations — never "Critical". Do not narrate an issue as a "Critical finding" unless you also store_finding it with that severity and reproducible evidence. If you choose not to store something, present it as an observation/recommendation, not a confirmed finding, so the report and your summary never disagree.
9. Before you finish, ALWAYS call generate_playbook once the surface is populated (any mode), so the operator gets cURL-ready manual tests even if you ran out of active/intrusive budget.
10. CLOSING SUMMARY — when you have no further tool to run, end with a short, CONCLUSIVE wrap-up: what was covered, what was confirmed (or that nothing reproducible was), and where the operator should look next (point at the playbook). Do NOT end on an open-ended "we need to continue testing…" — the run is finishing, so the final message must read as a conclusion, not a cliffhanger.

RECOMMENDED METHODOLOGY:
1. Subdomain enumeration: run_subfinder + run_crtsh on every in-scope root domain. run_wayback to seed historical URLs. run_dns for SPF/DMARC/CAA/vendor intel. run_asn to map the org's IP range (scope expansion). run_github_recon to hunt leaked secrets in public repos (passive, uses the operator's own PAT).
2. Live host probe: run_httpx on discovered subdomains. check_takeover on subdomains to catch dangling-CNAME hijacks.
3. Enrich: http_probe interesting hosts (captures evidence, reads security headers, seeds the surface). run_fingerprint to identify the tech stack (server/language/framework/CMS + versions). fetch_openapi on any /swagger or /openapi.json. run_graphql on any /graphql endpoint (introspection + batching abuse). run_jwt on any JWT/Bearer token you capture (alg:none, weak-secret crack, forged-admin). run_oauth on any OAuth authorization URL (/oauth/authorize with client_id/redirect_uri — redirect_uri bypass, missing-state CSRF, implicit-flow token leak). run_js_review on discovered .js bundles (hardcoded secrets, dangerous sinks, hidden endpoints).
4. Surface scan: run_nuclei with safe tags on live hosts. run_nmap on unusual fingerprints. If the ZAP daemon is available, run_zap for a full DAST pass on a primary in-scope web app (spider + AJAX spider + active scan, scope-fenced).
5. Plan: call generate_playbook to get a rule-based, per-surface test playbook (what/how/payloads/confidence/cURL). Use it to target the next step.
6. Targeted probing (INTRUSIVE): run_content_discovery for sensitive paths (body-validated), run_exposure for exposed .git/.env/backup/credential files (signature-confirmed, source-recoverable escalation), run_web_probes for traversal/IDOR, run_injection_probes for CORS/open-redirect/host-header/SSTI on parameterized URLs, run_bfla for broken function-level authorization (write methods / admin paths with a low-priv token) + side-channel BOLA, run_race on single-use actions (coupon/transfer/vote) for race conditions, run_ssrf on URL-taking parameters (fetch/redirect/proxy/image/webhook) for server-side request forgery (cloud-metadata reflection + internal port oracle), run_deserialization on requests carrying serialized blobs in params/cookies (PHP/Java/pickle/.NET/Ruby — corrupt-and-watch-for-parser-error confirmation), run_xxe on endpoints that accept XML (in-band file read + OOB blind confirmation via the native collaborator), run_sqli on parameterized URLs (error/boolean/time oracles, baseline-confirmed, native — no binary needed), run_nosqli on parameterized URLs for MongoDB-style operator injection (id[$ne]=/[$regex]= — boolean/error oracles), run_auth_sqli and run_form_nosqli on login-style POST/JSON bodies for auth-bypass (SQL OR-payloads / NoSQL operator objects — the class query-string probes can't reach), run_form_cmdi on captured forms for POST-body command injection, run_upload_test on pages with a file-upload form for extension-filter bypass (CWE-434, non-destructive canary payloads), run_cache_poison on live host roots for unkeyed-header cache poisoning (X-Forwarded-Host/Scheme, X-Original-URL — confirmed only when a clean re-request still receives the injected canary), run_llm_probe on any discovered URL that looks like a chat/AI endpoint for prompt injection (instruction-override probe with a unique marker — confirmed only on exact marker compliance), run_cmdi on params that feed OS commands (ping/host/filename/exec — computed-output + time + OOB oracles), run_xss on reflected parameters and pages with client-side sinks (browser-confirmed, catches DOM XSS).
7. Correlate. Store every confirmed reportable vulnerability with store_finding.

INVESTIGATIVE TESTING (you are an operator, not just a scanner runner):
The canned scanners are your floor, not your ceiling. For access-control, authorization, auth/token, and business-logic classes the scanners cannot fully judge, DRIVE THE LOOP yourself with the request primitives:
  - acquire_session{login_url, username/email, password, role} — log in ONCE and store a reusable session under a role name. Acquire TWO roles (e.g. a victim account and an attacker account you register) so you can test cross-user access. Then pass session="<role>" to the primitives below to act as that identity. (Single-credential auth only — never iterate passwords.)
  - http_read{method:GET/HEAD/OPTIONS, url, headers} — send a scope-guarded read with custom headers (e.g. an Authorization token you acquired) and read the response.
  - http_diff{a,b} — send two reads and get a DETERMINISTIC differential (status, length delta, body_similarity, distinct_objects). This is your CONFIRMATION ORACLE.
  - http_request{method, url, headers, body} — a scope-guarded state-changing request (INTRUSIVE, gated). Use for write tests.
  - confirm_idor{owned_url, target_url, headers} — the IDOR/BOLA ORACLE: pass your own object + another id + your session; it deterministically confirms (and stores) cross-object access. Prefer this over storing an IDOR by hand.
  - enumerate_ids{url_template (with {id}), start, end, headers} — bounded object-id enumeration to find accessible objects at scale (then confirm ownership with confirm_idor).
  - browser_navigate{url, steps:[{action:goto|click|fill|press|wait,...}], session} — drive a real headless browser for authenticated SPA flows and to capture client-side state (localStorage/sessionStorage tokens, XHR/fetch API calls, scripts, DOM). Declarative steps only, no arbitrary JS.
  - test_numeric_abuse{url, param, body, session} — business-logic probe: does the server accept out-of-range numeric values (negative/zero/huge) for a quantity/price/amount field? Then verify the downstream effect (negative total etc.) with http_read. Never finalize a payment.
LOOP: DISCOVER a suspicious endpoint/flow (object id in path, role/authz boundary, token, price/quantity, multi-step sequence) → HYPOTHESIZE one vuln class → TEST by crafting requests → COMPARE with http_diff or a control request → ADAPT (change one thing, retry, bounded) → CONFIRM only when the oracle is unambiguous → CHAIN a confirmed primitive (a token, an id, a leaked value) into the next hypothesis.
ORACLE DISCIPLINE (truth-first, non-negotiable): never store_finding on a hunch. Confirm with EVIDENCE:
  - IDOR/BOLA: acquire a session, http_read another object's id, and http_diff against your own object — confirmed only when both are 200 and distinct_objects is true (you read data that is not yours). Include the two requests + responses as evidence.
  - Broken auth / token: forge/modify a token, http_read a protected endpoint with it — confirmed only when it authenticates (200 + your injected identity reflected).
  - Business logic: establish the invariant (e.g. server total == sum of item prices), attempt a BOUNDED violation with http_request, and re-read state — confirmed only when the invariant provably broke. Do NOT finalize payments or perform destructive/irreversible actions; inspect the outgoing request and stop at that boundary, recording the manual step.
GENERALIZE, never hardcode: discover identities/ids/values at runtime (enumerate /api/Users, read a source map, parse an error) — do not assume target-specific strings. The same loop works on any object endpoint, any REST API, any SPA.
STOP when: evidence is inadequate (record it as a lead + the exact manual repro), impact would be unsafe/irreversible, approval is required, or budget is spent.

HIGH-VALUE SIGNALS:
- Subdomains pointing to unclaimed cloud resources (S3, GitHub Pages, Heroku, Fastly)
- Admin panels with default or no credentials
- API endpoints returning PII or internal data without authorization
- Exposed .git/.env/backup/config files (only when the body confirms it)
- Dev/staging subdomains with weaker auth
- Mismatched CORS on authenticated API endpoints"""

MODE_NOTES = {
    "passive": "\n\nASSESSMENT MODE: PASSIVE. Only passive tools are permitted (subfinder, crtsh, wayback, dns, asn, github_recon, generate_playbook). Active and intrusive tools are disabled. Produce a recon picture and a test playbook the operator can execute by hand.",
    "active": "\n\nASSESSMENT MODE: ACTIVE. Passive + active tools auto-run. Intrusive probing requires one operator approval.",
    "full": "\n\nASSESSMENT MODE: FULL. Passive + active auto-run; intrusive probing requires approval. Go deep: content discovery, web probes, and confirmation on every promising surface.",
}


def _is_generic_objective(objective: str) -> bool:
    """True when the objective is the default template (adds no steering signal)."""
    o = (objective or "").strip().lower()
    return (not o) or o.startswith("perform comprehensive bug bounty recon")


class BBHAgent:
    # execution strategies (how tools are chosen), orthogonal to `mode` (which
    # tiers of tool are allowed). Default budgets: manual/deterministic use no AI,
    # low_ai spends at most 2 calls, agentic caps the ReAct loop.
    _DEFAULT_BUDGET = {"manual": 0, "deterministic": 0, "low_ai": 2, "agentic": 40}

    def __init__(self, scope: ScopeEngine, tools: ToolRegistry, stop_event: asyncio.Event,
                 mode: str = "active", auto_approve: bool = False, mission_id: str = None,
                 recon_cycles: int = 1, strategy: str = "low_ai", max_ai_calls: int = None,
                 enable_zap: bool = False, zap_policy: str = "safe_active",
                 zap_speed: str = "normal", zap_aggression: str = "normal",
                 enable_nmap_vuln: bool = False, enable_nuclei_heavy: bool = False,
                 authenticated_scan: bool = False):
        self.scope = scope
        # opt-in: reuse credentials the scan/prior-scan DISCOVERED to run authenticated (HITL — the UI
        # prompts for this on the next scan once a prior scan has gathered creds). Off = discover + report
        # the exposed creds, but scan unauthenticated.
        self.authenticated_scan = bool(authenticated_scan)
        # structured proof of the authentication artery — {"ran": False} until _do_persona_authz
        # actually mints/reacquires personas + runs the matrix. Lets a correctness check tell
        # "artery did not run" apart from "ran and produced no personas" (both differ from a smoke test).
        self._auth_artery = {"ran": False}
        self._graph_projection_error = None
        self._degraded = None                # structured degraded/failure state (e.g. graph projection halt)
        self._candidate_assurance = []       # per-candidate validation ledger (candidate->validator->result->evidence)
        self._candidate_validation_counts = {}
        self.tools = tools
        self.stop_event = stop_event
        self.tools.stop_event = stop_event   # let long ZAP polls honor a user stop
        # ZAP DAST is opt-in per scan: it runs only when the user enabled it (and
        # only in Full mode via the planner's INTRUSIVE gate). Policy chooses
        # passive / safe-active / thorough-active. Stored on the tool registry so
        # _run_zap can read the policy without threading it through every call.
        self.enable_zap = bool(enable_zap)
        self.zap_policy = zap_policy if zap_policy in ("passive", "safe_active", "thorough_active") else "safe_active"
        self.zap_speed = zap_speed if zap_speed in ("turtle", "normal", "fast") else "normal"
        self.zap_aggression = zap_aggression if zap_aggression in ("low", "normal", "demon") else "normal"
        self.tools.zap_policy = self.zap_policy
        self.tools.zap_speed = self.zap_speed
        self.tools.zap_aggression = self.zap_aggression
        # heavyweight nmap NSE vuln scan — opt-in, Full-mode only (INTRUSIVE gate)
        self.enable_nmap_vuln = bool(enable_nmap_vuln)
        # heavy nuclei (full vuln template set) — opt-in, Full mode only
        self.enable_nuclei_heavy = bool(enable_nuclei_heavy)
        self.mode = mode if mode in ("passive", "active", "full") else "active"
        self.auto_approve = auto_approve
        self.mission_id = mission_id
        self.recon_cycles = max(1, min(int(recon_cycles or 1), 3))
        self.strategy = strategy if strategy in self._DEFAULT_BUDGET else "low_ai"
        self.ai_calls = 0
        self.ai_degraded = False
        self.ai_note = ""   # human-readable AI-usage outcome for the report
        self.max_ai_calls = (max(0, int(max_ai_calls)) if max_ai_calls is not None
                             else self._DEFAULT_BUDGET[self.strategy])
        # Warm-start directive from cross-session memory (set by /engage when a
        # prior mission on the same target left intel). Empty by default so a
        # first-ever scan behaves exactly as before.
        self.memory_note = ""
        self.findings: list = []
        self.leads: list = []           # unconfirmed candidate/static signals (not report findings)
        self._advisor_recs: list = []   # technique-advisor picks for this run (report orchestration view)
        self._codeintel_summary: dict = {}   # what code-intelligence recon fed the scan (orchestration view)
        self._stored_fps: set = set()   # fingerprints already stored (auto-store dedup)
        # share the dedup set with the tool registry so the model's store_finding tool
        # deduplicates against what auto-store already recorded (AI stays additive).
        try:
            self.tools._stored_fps = self._stored_fps
        except Exception:
            pass
        self.current_phase = "init"
        self._recon_passes = 0   # counts entries into the recon phase (cycle labels)

        # HITL gate state (one session-level intrusive authorization)
        self.intrusive_state = None  # None | "approved" | "denied"
        self.pending_approval: dict = None
        self._approval_event = asyncio.Event()
        self._approval_result = None

        cfg = resolve_ai_config()
        self.provider = cfg["provider"]
        self.model = cfg["model"]
        self._has_key = bool(cfg["api_key"])
        # Client construction is best-effort: deterministic/manual strategies run
        # with NO AI at all, so a missing key must never stop the agent from being
        # built. low_ai/agentic get a credential preflight in /engage.
        self.client = None
        try:
            if cfg["provider"] == "openrouter":
                from openai import AsyncOpenAI
                self.client = AsyncOpenAI(base_url=cfg["base_url"] or DEFAULT_OPENROUTER_BASE,
                                          api_key=cfg["api_key"] or "missing")
            else:
                import anthropic
                kwargs = {}
                if cfg["api_key"]:
                    kwargs["api_key"] = cfg["api_key"]
                if cfg["base_url"]:
                    kwargs["base_url"] = cfg["base_url"]
                self.client = anthropic.AsyncAnthropic(**kwargs)
        except Exception:
            self.client = None

    # ── HITL approval API (called by main.py) ────────────────────
    def resolve_approval(self, approval_id: str, approved: bool) -> bool:
        if not self.pending_approval or self.pending_approval.get("id") != approval_id:
            return False
        self._approval_result = "approved" if approved else "denied"
        self._approval_event.set()
        return True

    async def _await_gate(self, tool_name: str, tool_input: dict):
        """Yield an approval_required event, block until the operator resolves it."""
        approval_id = uuid.uuid4().hex[:8]
        self.pending_approval = {"id": approval_id, "tool": tool_name, "input": tool_input}
        self._approval_event.clear()
        self._approval_result = None
        yield {"type": "approval_required", "approval_id": approval_id, "tool": tool_name,
               "input": tool_input, "phase": "probe",
               "prompt": f"Authorize INTRUSIVE probing for this engagement? First request: {tool_name}",
               "content": f"Awaiting operator authorization for INTRUSIVE probing (first request: {tool_name}). "
                          "Approve or deny in the gate modal — the run is paused until you do."}
        try:
            if APPROVAL_TIMEOUT > 0:
                await asyncio.wait_for(self._approval_event.wait(), timeout=APPROVAL_TIMEOUT)
            else:
                await self._approval_event.wait()
        except asyncio.TimeoutError:
            self._approval_result = "denied"
        self.intrusive_state = self._approval_result or "denied"
        self.pending_approval = None
        yield {"type": "approval_resolved", "approval_id": approval_id,
               "resolution": self.intrusive_state,
               "content": f"Intrusive gate {self.intrusive_state} — "
                          + ("resuming intrusive probes." if self.intrusive_state == "approved"
                             else "intrusive probes skipped; continuing with passive/active work.")}

    def _set_phase(self, tool_name: str):
        ph = PHASE_OF.get(tool_name)
        if ph and ph != self.current_phase:
            self.current_phase = ph
            return ph
        return None

    # ── shared tool handling (mode gate + HITL + execution) ──────
    async def _run_tool(self, tool_name: str, tool_input: dict, session_id: str):
        """Async generator: yields UI events, then a final {'_content': str} the
        caller feeds back to the model as the tool result."""
        perm = TOOL_PERMISSIONS.get(tool_name, PermissionLevel.ACTIVE)

        ph = self._set_phase(tool_name)
        if ph:
            yield {"type": "phase", "phase": ph}
            # Explicit recon-cycle label each time the run (re-)enters the recon
            # phase, so iterative recon reads as "cycle 1 → 2 → 3" instead of an
            # opaque phase bounce. Only when >1 cycle is configured (default run
            # is unchanged and emits none).
            # Only the agentic ReAct flow emits cycle banners here on recon re-entry;
            # deterministic/low_ai own their cycle banners in _execute_plan (avoids
            # a duplicate "Recon cycle 1" message).
            if ph == "recon" and self.recon_cycles > 1 and self.strategy == "agentic":
                self._recon_passes += 1
                n = min(self._recon_passes, self.recon_cycles)
                yield {"type": "cycle", "cycle": n, "total": self.recon_cycles,
                       "content": f"Recon cycle {n} of {self.recon_cycles}: enumerate, then learn "
                                  "from newly discovered in-scope assets before the next pass."}

        # Mode enforcement: passive mode forbids active + intrusive.
        if self.mode == "passive" and perm != PermissionLevel.PASSIVE:
            msg = f"{tool_name} blocked: PASSIVE mode permits passive tools only."
            yield {"type": "scope_block", "tool": tool_name, "error": msg}
            yield {"_content": json.dumps({"success": False, "error": msg})}
            return

        # HITL gate for intrusive tools.
        if perm == PermissionLevel.INTRUSIVE:
            if self.auto_approve and self.intrusive_state is None:
                self.intrusive_state = "approved"
                yield {"type": "info", "content": "Intrusive phase pre-authorized (autonomous run)."}
            if self.intrusive_state is None:
                async for ev in self._await_gate(tool_name, tool_input):
                    yield ev
            if self.intrusive_state == "denied":
                msg = f"{tool_name} skipped: operator denied intrusive probing."
                yield {"type": "scope_block", "tool": tool_name, "error": msg}
                yield {"_content": json.dumps({"success": False, "error": msg})}
                return

        yield {"type": "tool_call", "tool": tool_name, "input": tool_input, "permission": perm.value}
        result = await self.tools.execute(tool_name, tool_input, session_id)

        if result.error:
            etype = "scope_block" if "SCOPE BLOCK" in result.error else "tool_error"
            yield {"type": etype, "tool": tool_name, "error": result.error}
        else:
            # Count real results only: some tools (e.g. run_sqlmap on a no-confirmation
            # pass) return a severity-less data-carrier {"vulnerable": False, log_tail...}
            # purely to preserve the tool log. It is explicitly NOT a finding, so it must
            # not inflate the ledger's findings count (that produced the "9 findings /
            # No SQLi confirmed" contradiction the integrity check now guards against).
            _real = sum(1 for f in result.findings
                        if not (isinstance(f, dict) and f.get("vulnerable") is False))
            yield {"type": "tool_result", "tool": tool_name, "output": result.output,
                   "count": _real}

        if tool_name == "store_finding" and not result.error:
            # A model-authored finding (agentic). Dedup by fingerprint against what
            # auto-store already recorded so the AI layer is purely ADDITIVE — it can
            # add business-logic findings but never double-count a proof-based one that
            # auto-store already landed (tools._store_finding skips the DB write for a dup).
            import memory as memory_mod
            fin = result.findings[0] if result.findings else dict(tool_input)
            fp = memory_mod.finding_fp(fin)
            if fp not in self._stored_fps:
                self._stored_fps.add(fp)
                self.findings.append(fin)
                yield {"type": "finding", "finding": fin}

        # ALWAYS auto-store confirmed findings from the proof-based probes — regardless of
        # strategy. Confirmation is a deterministic oracle (proof), never the model's
        # opinion, so these MUST land even in agentic mode: relying on the model to store
        # them made agentic silently UNDERCOUNT (a run confirmed a SQLi + 19 leads but the
        # report showed neither because the model never called store_finding). The model's
        # own store_finding stays additive and is deduped against the same fingerprint set.
        if not result.error and tool_name in _AUTO_STORE_TOOLS:
            async for ev in self._auto_store(result):
                yield ev

        content = json.dumps({
            "success": result.success, "output": result.output,
            "findings": result.findings[:25], "error": result.error,
        })[:3500]
        yield {"_content": content}

    def _is_confirmed(self, tool: str, f: dict) -> bool:
        """A finding is report-worthy CONFIRMED only when the probe says so. The
        native tools grade every finding (confirmed / candidate / possible /
        probable); we trust that grade. A tool that confirms by construction but
        emits no grade (nuclei/zap/takeover) is treated as confirmed; anything
        graded weaker — reflection candidates, IDOR signals, static JS review — is
        a LEAD, never a confirmed report finding.

        HARD GUARD: a native-graded "confirmed" with NO proof at all (no evidence,
        reason, or detail) is downgraded to a lead. Evidence is what makes a
        confirmed finding trustworthy; a proofless "confirmed" is the exact shape
        of the round-9 reflected-XSS false positive, so we refuse to promote it."""
        c = str(f.get("confidence", "")).strip().lower()
        if c == "confirmed":
            proof = f.get("evidence") or f.get("reason") or f.get("detail")
            return bool(str(proof).strip()) if proof is not None else False
        if c:                                 # candidate / possible / probable
            return False
        return tool in _CONFIRMED_BY_TOOL      # no grade + confirmatory tool

    async def _auto_store(self, result):
        """Route finding-shaped probe results (deterministic/low_ai) when no model
        drives the scan: CONFIRMED → /findings + report; weaker signals → Leads.
        Deduped by fingerprint. `severity` is the finding discriminator; the title
        is derived from whichever label key the tool used."""
        import memory as memory_mod
        for f in (result.findings or []):
            if not isinstance(f, dict) or not f.get("severity"):
                continue                      # data item, not a finding
            title = (f.get("title") or f.get("name") or f.get("issue")
                     or f.get("type") or f.get("detail") or f"{result.tool} finding")
            f = dict(f)
            f["title"] = str(title)[:140]
            f["target"] = f.get("target") or f.get("url") or result.target or ""
            f["severity"] = str(f.get("severity") or "info").lower()
            fp = memory_mod.finding_fp(f)
            if fp in self._stored_fps:
                continue
            self._stored_fps.add(fp)
            if self._is_confirmed(result.tool, f):
                if self.mission_id:
                    f["id"] = db.add_finding(self.mission_id, f)
                self.findings.append(f)
                yield {"type": "finding", "finding": f}
            else:
                f.setdefault("confidence", "candidate")
                self.leads.append(f)
                yield {"type": "lead", "lead": f}

    async def _promote_leads(self, session_id: str):
        """Convert candidate leads to CONFIRMED findings by re-testing them with a
        confirmatory oracle they didn't already get. Currently: XSS-class candidate
        leads (reflection/dalfox/js-review signals) are replayed through the headless
        browser executor — a lead that now fires alert() becomes a browser-confirmed
        finding (with PoC). Truth-first: promotion requires real execution, never the
        signal alone; nothing is promoted when no browser is available."""
        import tools as _t
        from urllib.parse import urlparse, parse_qs
        if not self.leads or _t.xss_confirm_status() is False:
            return
        # one representative parameterized target per path among XSS-class leads
        targets = {}
        for lead in self.leads:
            cwe, ttl = str(lead.get("cwe") or ""), str(lead.get("title") or "").lower()
            if not ("79" in cwe or "xss" in ttl or "cross-site script" in ttl):
                continue
            tgt = str(lead.get("target") or "")
            if tgt and "?" in tgt and self.scope.validate(tgt)[0]:
                targets.setdefault(urlparse(tgt).path, tgt)
        if not targets:
            return
        promoted_paths = set()
        for tgt in list(targets.values())[:15]:          # bounded browser sweep
            if self.stop_event.is_set():
                break
            params = list(parse_qs(urlparse(tgt).query).keys())
            if not params:
                continue
            try:
                confs = await self.tools._xss_execute(tgt, params)
            except Exception:
                confs = []
            for f in confs:
                f.setdefault("found_by", "promoted from candidate lead (browser-confirmed)")
                if self.mission_id:
                    f["id"] = db.add_finding(self.mission_id, f)
                self.findings.append(f)
                promoted_paths.add(urlparse(str(f.get("target") or tgt)).path)
                yield {"type": "finding", "finding": f}
        # drop the now-redundant XSS-class leads on any promoted path
        if promoted_paths:
            before = len(self.leads)
            self.leads = [l for l in self.leads if not (
                ("79" in str(l.get("cwe") or "") or "xss" in str(l.get("title") or "").lower())
                and urlparse(str(l.get("target") or "")).path in promoted_paths)]
            dropped = before - len(self.leads)
            if dropped:
                yield {"type": "info", "content": f"Lead promotion: {dropped} candidate lead(s) "
                       "browser-confirmed and promoted to findings."}

    @staticmethod
    def _dom_class_match(family: str, finding: dict) -> bool:
        blob = (str(finding.get("title") or "") + " " + str(finding.get("family") or "")
                + " " + " ".join(str(x) for x in (finding.get("tags") or []))).lower()
        if family == "prototype_pollution":
            return "prototype pollution" in blob or "proto" in blob
        if family == "csti":
            return "template injection" in blob or "csti" in blob or "angular" in blob
        if family in ("dom_xss", "eval_sink"):
            return ("dom" in blob and "xss" in blob) or "dom-based" in blob or "client-side" in blob and "xss" in blob
        return False

    async def _validate_candidates(self, session_id: str):
        """Safety wrapper: a validator bug must NEVER fail the mission — candidate validation is a
        late enhancement pass, so any unexpected error degrades to a visible note and the run
        completes (findings/leads already gathered are preserved)."""
        try:
            async for ev in self._validate_candidates_impl(session_id):
                yield ev
        except Exception as _e:
            yield {"type": "info", "content": "Candidate validation degraded (%s) — mission continues; "
                   "leads preserved." % str(_e)[:100]}

    async def _validate_candidates_impl(self, session_id: str):
        """General, target-agnostic candidate-validation pipeline. Normalizes every remaining
        testable lead, routes it to a real validator, and finishes it in an EXPLICIT terminal
        state with a per-candidate assurance record {candidate, family, validator, attempted,
        oracle, result, evidence}. False-finding guard: DOM-class leads found only in library
        source are retested against the APPLICATION PAGES and confirmed ONLY by a runtime canary."""
        import candidate_pipeline as cp
        import tools as _t
        recs = self._candidate_assurance
        # record the reflected-XSS leads the promoter already browser-confirmed (one table for all)
        for f in self.findings:
            if "promoted from candidate lead" in str(f.get("found_by") or ""):
                recs.append({"candidate": f.get("title"), "family": "reflected_xss", "validator": "run_xss",
                             "attempted": True, "oracle": "browser alert() executed",
                             "result": cp.CONFIRMED, "evidence": str(f.get("evidence") or "")[:160],
                             "target": f.get("target")})
        if not self.leads:
            if recs:
                yield {"type": "info", "content": "Candidate validation: %d confirmed via promotion." % len(recs)}
            return
        app_pages = cp.application_pages(getattr(self.tools, "urls", []) or [])[:8]
        browser_ok = _t.xss_confirm_status() is not False and bool(getattr(_t, "_chrome_path", lambda: None)())

        # ── one browser DOM audit sweep over the application pages, reused by every DOM family ──
        dom_findings, dom_ran = [], False
        dom_needed = any(cp.canonical_family(l) in ("prototype_pollution", "csti", "dom_xss", "eval_sink") for l in self.leads)
        if dom_needed and app_pages and browser_ok and not self.stop_event.is_set():
            for page in app_pages:
                if self.stop_event.is_set():
                    break
                try:
                    r = await self.tools.execute("run_dom_audit", {"url": page}, session_id)
                except Exception:
                    continue
                dom_ran = True
                for f in (r.findings or []):
                    f.setdefault("target", page)
                    dom_findings.append(f)

        counts = {cp.CONFIRMED: 0, cp.DISMISSED: 0, cp.BLOCKED: 0, cp.SCHEDULED: 0, cp.UNSUPPORTED: 0}
        keep, confirmed_titles = [], set()
        for lead in list(self.leads):
            if self.stop_event.is_set():
                keep.append(lead); continue
            n = cp.normalize(lead)
            fam, validator = n["family"], n["validator"]
            rec = {"candidate": lead.get("title"), "family": fam, "validator": validator,
                   "attempted": False, "oracle": n["oracle"], "result": None, "evidence": "",
                   "target": n["raw_target"], "missing_prerequisite": None}
            state, promoted = None, None

            # dedupe: a generic advisor lead ("Technique to test — X") whose vuln a scan probe
            # ALREADY confirmed is CONFIRMED-by-dedupe, never re-dismissed.
            already = next((f for f in self.findings if str(f.get("confidence")) == "confirmed"
                            and (cp.canonical_family(f) == fam
                                 or (fam not in ("unknown", "") and fam in str(f.get("family") or "").lower()))), None)
            if already:
                rec["attempted"] = True
                state = cp.CONFIRMED
                rec["evidence"] = "already confirmed by a scan probe (deduped to: %s)" % str(already.get("title") or "")[:80]
            elif fam in ("prototype_pollution", "csti", "dom_xss", "eval_sink"):
                if not browser_ok:
                    state, rec["missing_prerequisite"] = cp.BLOCKED, "headless browser (Chromium) unavailable"
                elif not app_pages:
                    state, rec["missing_prerequisite"] = cp.BLOCKED, "no in-scope application page to test the library against"
                else:
                    rec["attempted"] = True
                    hit = next((f for f in dom_findings if self._dom_class_match(fam, f)), None)
                    if hit:
                        promoted = dict(hit); state = cp.CONFIRMED
                        rec["evidence"] = "runtime canary fired on %s: %s" % (hit.get("target"), str(hit.get("evidence") or hit.get("title"))[:120])
                    else:
                        state = cp.DISMISSED
                        rec["evidence"] = "canary never fired across %d application page(s) — library-only match, not a runtime app vuln" % len(app_pages)

            elif fam == "reflected_xss":
                # parameterized reflected XSS is browser-confirmed earlier by _promote_leads; here we
                # confirm a lead that carries its own parameterized point, else dismiss after that sweep.
                rec["attempted"] = True
                if not browser_ok:
                    state, rec["missing_prerequisite"] = cp.BLOCKED, "headless browser (Chromium) unavailable"
                else:
                    from urllib.parse import urlparse as _up, parse_qs as _pq
                    confs = []
                    if "?" in n["raw_target"]:
                        try:
                            confs = await self.tools._xss_execute(n["raw_target"], list(_pq(_up(n["raw_target"]).query).keys()))
                        except Exception:
                            confs = []
                    if confs:
                        promoted = confs[0]; state = cp.CONFIRMED
                        rec["evidence"] = "browser alert() executed on " + str(n["raw_target"])[:80]
                    else:
                        state = cp.DISMISSED
                        rec["evidence"] = "browser XSS sweep found no reflected execution on a parameterized point"

            elif fam == "exposed_credentials":
                cred_f = next((f for f in self.findings if "credential" in str(f.get("title") or "").lower()
                               and str(f.get("severity")) in ("high", "critical")), None)
                rec["attempted"] = True
                if cred_f:
                    state = cp.CONFIRMED; rec["result_ref"] = cred_f.get("title")
                    rec["evidence"] = "harvested credential yielded a valid session (see: %s)" % str(cred_f.get("title"))[:80]
                else:
                    state = cp.DISMISSED
                    rec["evidence"] = "harvested value did not produce an authenticated session"

            elif fam == "exposed_files":
                rec["attempted"] = True
                try:
                    r = await self.tools.execute("run_exposure", {"base_url": n["raw_target"] or self._primary_base()}, session_id)
                    if r.findings:
                        promoted = r.findings[0]; state = cp.CONFIRMED
                        rec["evidence"] = "content/type signature matched: " + str(r.output or "")[:120]
                    elif "SCOPE BLOCK" in str(r.error or ""):
                        state, rec["missing_prerequisite"] = cp.BLOCKED, "target out of scope"
                    else:
                        state = cp.DISMISSED; rec["evidence"] = "no signature match (soft 200/404, not a real exposed file)"
                except Exception as e:
                    state = cp.DISMISSED; rec["evidence"] = "validator error: %s" % str(e)[:80]

            elif fam == "stored_xss":
                if not browser_ok:
                    state, rec["missing_prerequisite"] = cp.BLOCKED, "headless browser (Chromium) unavailable"
                else:
                    rec["attempted"] = True
                    try:
                        r = await self.tools.execute("run_stored_xss", {"url": n["raw_target"] or self._primary_base()}, session_id)
                        if r.findings:
                            promoted = r.findings[0]; state = cp.CONFIRMED
                            rec["evidence"] = "canary stored + re-read + executed: " + str(r.output or "")[:100]
                        else:
                            state = cp.DISMISSED; rec["evidence"] = "canary not reflected/executed on any display surface"
                    except Exception as e:
                        state = cp.DISMISSED; rec["evidence"] = "validator error: %s" % str(e)[:80]

            elif fam == "bfla":
                has_session = bool(getattr(self.tools, "session_headers", None)) or bool(getattr(self, "_auth_artery", {}).get("ran"))
                if not has_session:
                    state, rec["missing_prerequisite"] = cp.BLOCKED, "authenticated low-privilege session (run authenticated scan)"
                else:
                    rec["attempted"] = True
                    try:
                        r = await self.tools.execute("run_bfla", {"url": n["raw_target"] or self._primary_base()}, session_id)
                        if r.findings:
                            promoted = r.findings[0]; state = cp.CONFIRMED
                            rec["evidence"] = "low-priv session performed a prohibited action: " + str(r.output or "")[:100]
                        else:
                            state = cp.DISMISSED; rec["evidence"] = "privileged control correctly denied the low-priv session"
                    except Exception as e:
                        state = cp.DISMISSED; rec["evidence"] = "validator error: %s" % str(e)[:80]

            elif fam == "jsonp":
                rec["attempted"] = True
                try:
                    r = await self.tools.execute("run_jsonp", {"url": n["raw_target"] or self._primary_base()}, session_id)
                    if r.findings:
                        promoted = r.findings[0]; state = cp.CONFIRMED
                        rec["evidence"] = str(r.output or "")[:120]
                    elif "SCOPE BLOCK" in str(r.error or ""):
                        state, rec["missing_prerequisite"] = cp.BLOCKED, "target out of scope"
                    else:
                        state = cp.DISMISSED; rec["evidence"] = str(r.output or "no executable JSONP wrapper with sensitive data")[:120]
                except Exception as e:
                    state = cp.DISMISSED; rec["evidence"] = "validator error: %s" % str(e)[:80]

            elif fam == "weak_random":
                blob = (str(lead.get("evidence") or "") + " " + str(lead.get("title") or "")
                        + " " + " ".join(str(x) for x in (lead.get("tags") or []))).lower()
                rec["attempted"] = True
                if any(k in blob for k in ("token", "session", "csrf", "password", "reset", "secret", "nonce", "otp", "id=")):
                    state, rec["missing_prerequisite"] = cp.BLOCKED, "manual trace: confirm the random output controls the named security value"
                    rec["evidence"] = "security-relevant sink suspected — needs runtime trace to confirm impact"
                else:
                    state = cp.DISMISSED
                    rec["evidence"] = "downgraded to informational — Math.random with no security-relevant sink is not a weakness"

            elif fam == "dev_comments":
                import re as _re
                blob = str(lead.get("evidence") or "") + " " + str(lead.get("target") or "")
                base = self._primary_base()
                paths = sorted(set(_re.findall(r"/[A-Za-z0-9_\-/.]{2,60}", blob)))[:8]
                rec["attempted"] = True
                state = cp.DISMISSED
                added = 0
                urls = getattr(self.tools, "urls", None)
                for p in paths:
                    if base and isinstance(urls, list):
                        url = base.rstrip("/") + p
                        if self.scope.validate(url)[0] and url not in urls:
                            urls.append(url)       # CONSUMED: folds into surface -> graph/report/memory + next-scan warm-start
                            added += 1
                rec["evidence"] = ("comment is not itself a vulnerability; %d derived in-scope route(s) folded into the "
                                   "surface (graph + memory) for validation" % added) if added else \
                                  "comment carried no new in-scope derived route"

            else:
                state = cp.UNSUPPORTED
                rec["evidence"] = "no validator implemented for family '%s' yet (explicit coverage debt)" % fam

            rec["result"] = state
            counts[state] = counts.get(state, 0) + 1
            recs.append(rec)
            if state == cp.CONFIRMED and promoted:
                promoted.setdefault("found_by", "candidate-validation pipeline (%s, %s)" % (validator, rec["oracle"]))
                promoted.setdefault("confidence", "confirmed")
                if self.mission_id:
                    try:
                        promoted["id"] = db.add_finding(self.mission_id, promoted)
                    except Exception:
                        pass
                self.findings.append(promoted)
                confirmed_titles.add(str(lead.get("title")))
                yield {"type": "finding", "finding": promoted}
            elif state in (cp.CONFIRMED, cp.DISMISSED):
                pass                                   # terminal, non-promoting -> drop the lead
            else:
                keep.append(lead)                      # blocked / scheduled / unsupported -> keep visible
        self.leads = keep
        self._candidate_validation_counts = counts
        yield {"type": "info", "content": (
            "Candidate validation: %d confirmed, %d dismissed, %d blocked, %d unsupported "
            "(every testable lead reached a terminal state)."
            % (counts[cp.CONFIRMED], counts[cp.DISMISSED], counts[cp.BLOCKED], counts[cp.UNSUPPORTED]))}

    async def _ai_business_logic_leads(self, session_id: str):
        """Additive AI enhancement layer: when an AI strategy is selected, run ONE bounded
        end-of-scan pass over the surface + confirmed findings and propose BUSINESS-LOGIC
        test hypotheses (workflow/step-skipping, price/quantity manipulation, IDOR/BOLA id
        sequences, coupon/referral abuse, auth-flow gaps, mass-assignment, races) that the
        deterministic probes can't reason about. Truth-first: these are candidate LEADS the
        operator must verify — the model hunts and hypothesizes, it never confirms. No-op in
        deterministic mode (AI is an opt-in enhancement, never the engine)."""
        if self.strategy not in ("low_ai", "agentic") or not self._ai_usable() or not self._budget_left():
            return
        import surface as surface_mod
        inv = surface_mod.build_inventory(getattr(self.tools, "urls", []) or [])[:40]
        if not inv:
            return
        surf = "\n".join(f"- {e['host']}{e['path']}"
                         + (f"  params={','.join(e.get('params') or [])}" if e.get("params") else "")
                         for e in inv)
        finds = "; ".join(f.get("title", "") for f in self.findings[:15]) or "none confirmed yet"
        system = ("You are a senior web/API pentester. From the attack surface and confirmed findings, propose "
                  "concrete BUSINESS-LOGIC test hypotheses a human should try that automated scanners miss — "
                  "workflow/step-skipping, price/quantity/negative-value manipulation, IDOR/BOLA id sequences, "
                  "coupon/referral/loyalty abuse, auth-flow and password-reset gaps, mass-assignment, race "
                  "conditions. Output 3-8 lines, each EXACTLY: '<endpoint or flow> | <hypothesis> | <how to test>'. "
                  "Hypotheses only — never claim anything is confirmed.")
        user = f"Attack surface:\n{surf}\n\nConfirmed findings: {finds}"
        try:
            txt = await self._ai_text(system, user, max_tokens=650)
        except Exception:
            return
        tgt0 = (getattr(self.tools, "recon", {}) or {}).get("target") or ""
        n = 0
        for raw in (txt or "").splitlines():
            line = raw.strip().lstrip("-*0123456789.) ")
            if line.count("|") < 1 or len(line) < 16:
                continue
            parts = [p.strip() for p in line.split("|")]
            where, hyp = parts[0][:80], (parts[1] if len(parts) > 1 else "")
            how = parts[2] if len(parts) > 2 else (parts[1] if len(parts) > 1 else "")
            lead = {"severity": "info", "confidence": "candidate", "family": "business_logic",
                    "tags": ["business-logic", "ai-hypothesis"], "cwe": "CWE-840",
                    "target": where if where.startswith("http") else tgt0,
                    "title": f"Business-logic hypothesis — {(hyp or where)[:90]}",
                    "evidence": f"{where}: {hyp}".strip(": "),
                    "reproduction_steps": [how] if how else [],
                    "analyst_notes": "AI-proposed hunt lead (business logic) — verify manually; not a confirmed vulnerability."}
            self.leads.append(lead)
            yield {"type": "lead", "lead": lead}
            n += 1
            if n >= 8:
                break

    def _primary_base(self) -> str:
        try:
            b = self.scope.base_urls()
            return b[0] if b else ""
        except Exception:
            return ""

    async def _recon_code_intelligence(self, session_id: str):
        """Deterministic code-intelligence recon. Black-box harvest the primary target's served JS,
        fold the mined API endpoints into the scan SURFACE (so the planner actually probes them), and
        raise the unlinked/sensitive routes + business-logic hypotheses as LEADS. Runs for EVERY
        strategy, before the scan, so the harvest drives the run instead of sitting in a dashboard."""
        import asyncio
        import codeintel
        base = self._primary_base()
        if not base:
            return
        try:
            h = await asyncio.to_thread(codeintel.harvest, base)
        except Exception:
            return
        if not isinstance(h, dict):
            return
        # 1) fold mined endpoints into the surface the planner probes
        existing = set(getattr(self.tools, "urls", []) or [])
        added = 0
        for ep in (h.get("endpoints") or []):
            u = base.rstrip("/") + ep if str(ep).startswith("/") else str(ep)
            if u not in existing:
                self.tools.urls.append(u)
                existing.add(u)
                added += 1
        # 2) sensitive / unlinked routes -> attack-surface leads
        ns = 0
        for r in (h.get("sensitive_routes") or [])[:12]:
            lead = {"severity": "info", "confidence": "candidate", "family": "attack_surface",
                    "tags": ["code-intel", "unlinked-route"], "cwe": "CWE-200", "target": base,
                    "title": "Unlinked/sensitive route mined from JS — %s" % str(r)[:80],
                    "evidence": "Code-intelligence harvest found client route '%s' in a served JS bundle." % r,
                    "reproduction_steps": ["Probe '%s' on %s for privileged functionality or missing authorization." % (r, base)],
                    "analyst_notes": "Code-intelligence recon lead — sensitive surface to test for access control."}
            self.leads.append(lead)
            yield {"type": "lead", "lead": lead}
            ns += 1
        # 3) business-logic hypotheses (derived from the mined routes) -> leads
        nl = 0
        for wf in ((h.get("logic") or {}).get("detail") or []):
            for t in (wf.get("tests") or []):
                lead = {"severity": "info", "confidence": "candidate", "family": "business_logic",
                        "tags": ["code-intel", "business-logic", t.get("kind", "logic")], "cwe": "CWE-840",
                        "target": base,
                        "title": "Business-logic hypothesis (%s) — %s" % (wf.get("workflow", "flow"), t.get("kind", "")),
                        "evidence": t.get("test", ""),
                        "reproduction_steps": [t.get("test", "")] if t.get("test") else [],
                        "analyst_notes": (t.get("rationale", "") + " Derived from routes mined by code intelligence; verify manually.").strip()}
                self.leads.append(lead)
                yield {"type": "lead", "lead": lead}
                nl += 1
                if nl >= 12:
                    break
            if nl >= 12:
                break
        self._codeintel_summary = {"endpoints": len(h.get("endpoints") or []), "added_to_surface": added,
                                   "sensitive_routes": ns, "logic_hypotheses": nl}
        yield {"type": "info", "content": "Code intelligence: mined %d endpoints (%d new to surface), "
               "raised %d sensitive-route + %d business-logic leads." % (len(h.get("endpoints") or []), added, ns, nl)}

    async def _technique_advisor(self, session_id: str):
        """Consult the first-class Technique knowledge model for the highest-priority techniques to
        test given the surface + confirmed findings, and raise them as prioritized (relevance + KEV +
        confidence ranked) leads. Deterministic; makes the technique registry a test GENERATOR rather
        than a static library. Runs for every strategy."""
        try:
            import techniques as T
            import technique_model
            import technique_advisor as adv
            import intel_feeds
        except Exception:
            return
        try:
            snaps = intel_feeds.load()
            kev = intel_feeds.known_exploited_cwes(snaps)
            enr = intel_feeds.enrich_techniques(
                [{"id": t["id"], "cwe": t.get("cwe")} for t in T.TECHNIQUES.values()], snaps) if snaps else {}
        except Exception:
            kev, enr = set(), {}
        try_map = getattr(T, "_TRY", {})
        canon = []
        for rec in T.TECHNIQUES.values():
            e = enr.get(rec["id"], {})
            canon.append(technique_model.from_registry(
                rec, try_it=try_map.get(rec["id"]), known_exploited=e.get("known_exploited", False),
                kev_cves=e.get("kev_cves"), capec=e.get("capec")))
        # Build vuln-class SIGNALS from EVERYTHING recon gathered, so the advisor is driven by all
        # intel (not just confirmed findings). This is the orchestration contract: gathered info -> intel.
        signals = set()
        for l in (self.leads or []):                       # code-intel + harvest-derived leads
            f = str(l.get("family") or "").strip().lower()
            if f:
                signals.add(f)
        try:                                               # the harvested intel store (versions/ids/coupons/...)
            by_kind = (self.tools.intel.to_dict(redact_secrets=True) or {}).get("by_kind", {})
            _K = {"object_id": "access_control", "version": "vulnerable_component", "coupon": "business_logic",
                  "email": "broken_auth", "username": "broken_auth", "secret": "sensitive_exposure",
                  "encoded": "crypto", "route": "access_control"}
            for kind, family in _K.items():
                if by_kind.get(kind):
                    signals.add(family)
        except Exception:
            pass
        recs = adv.recommend(self.findings, canon, kev_cwes=kev, signals=signals, top=8)
        if not recs:
            return
        base = self._primary_base()
        self._advisor_recs = [{"id": r["technique"]["id"], "name": r["technique"].get("name"),
                               "score": r["score"], "reasons": r["reasons"]} for r in recs]
        for lead in adv.as_leads(recs, base):
            self.leads.append(lead)
            yield {"type": "lead", "lead": lead}
        yield {"type": "info", "content": "Technique advisor: %d techniques recommended from the "
               "knowledge model (relevance + KEV + confidence ranked)." % len(recs)}

    async def _close_autonomy_loop(self, session_id: str):
        """Close CHAD's deterministic autonomy loop (Execution -> Evidence -> State -> Next-Best-Action).
        Records THIS engagement's confirmed findings (and attempted lead classes) into the per-target
        attack-chain memory, then runs the SAME evidence-driven technique planner that powers /plan --
        precondition-gated, KEV-ranked, learning-reweighted, chain-annotated -- to emit the ranked
        next-best actions. So real scans FEED the autonomy memory (not just manual confirm/dismiss), and
        the planner + learning get smarter every engagement. Zero-token, fully best-effort (never breaks a
        scan). This is the missing wire: the autonomy engine was a dashboard; now the scan drives + feeds it."""
        base = self._primary_base()
        if not base:
            return
        recorded, nxt = 0, []
        try:
            import attack_chain
            import technique_planner as TP
            # 1) Evidence -> State: confirmed findings + attempted lead classes into per-target memory.
            for f in (self.findings or []):
                fam = str(f.get("family") or f.get("vuln_class") or f.get("type") or "").strip()
                if not fam:
                    continue
                try:
                    attack_chain.record(f.get("target") or base, fam, "confirmed",
                                        evidence=str(f.get("title", ""))[:200], session=session_id)
                    recorded += 1
                except Exception:
                    pass
            for l in (self.leads or []):
                fam = str(l.get("family") or "").strip()
                if fam:
                    try:
                        attack_chain.record(l.get("target") or base, fam, "attempted",
                                            evidence=str(l.get("title", ""))[:120], session=session_id)
                    except Exception:
                        pass
            # 2) Next-Best-Action: the SAME planner /plan uses, now fed by the memory this scan just wrote.
            try:
                harvest = self.tools.intel.to_dict(redact_secrets=True) if getattr(self.tools, "intel", None) else {}
            except Exception:
                harvest = {}
            kev = set()
            try:
                import intel_feeds
                snaps = intel_feeds.load()
                kev = intel_feeds.known_exploited_cwes(snaps) if snaps else set()
            except Exception:
                pass
            # feed ALL gathered intel + findings INTO the live graph first, so the planner reads a
            # complete world model FROM the graph (graph-as-brain), not just flat lists.
            _g = getattr(self.tools, "graph", None)
            if _g is not None:
                try:
                    _g.ingest_intel(self.tools.intel.to_dict() if hasattr(self.tools.intel, "to_dict") else {})
                    for _f in self.findings:
                        _g.observe("finding", str(_f.get("id") or _f.get("title", "")[:40]),
                                   label=_f.get("title", "finding"), source="scan", family=(_f.get("family") or ""))
                except Exception:
                    pass
            # GRAPH-AUTHORITATIVE planning (CHAD capability B): the live graph already ingested ALL
            # recon/intel/findings (graph-as-brain slice 1), so the graph — not flat recon — is the
            # authority. plan_graph_authoritative derives observations SOLELY from the graph; an empty
            # graph could not be driven by recon alone. Flat derive_observations is merged only as a
            # backward-compat projection (a subset of what the graph already holds).
            _seed = TP.registry_seed()
            gplan = TP.plan_graph_authoritative(_g, _seed, kev_cwes=kev)
            self._graph_plan = gplan
            obs = set(gplan["observations"])
            obs |= TP.derive_observations(surface=list(self.tools.urls or []), harvest=harvest,
                                          findings=self.findings, leads=self.leads,
                                          authenticated=bool(getattr(self.tools, "_sessions", None)),
                                          graph=_g)   # compatibility projection
            try:
                import proxy as _proxy
                obs |= _proxy.to_observations()
            except Exception:
                pass
            p = TP.plan(obs, _seed, kev_cwes=kev)
            try:
                import learning
                rel = learning.reliability()
                for a in p:
                    w = learning.class_weight(a.get("family"), rel)
                    if w:
                        a["score"] = round(a["score"] + w, 1)
                p.sort(key=lambda x: x.get("score", 0), reverse=True)
            except Exception:
                pass
            try:
                p = attack_chain.annotate_plan(base, p)
            except Exception:
                pass
            nxt = p[:6]
            self._next_best = nxt
        except Exception:
            return
        if recorded or nxt:
            try:
                import attack_chain
                key = attack_chain.target_key(base)
            except Exception:
                key = base
            top = ", ".join(a.get("id", "") for a in nxt[:3]) or "none (evidence exhausts the gated techniques)"
            yield {"type": "info", "content": "Autonomy loop closed — %d confirmed finding(s) recorded to "
                   "engagement memory for %s; next-best actions: %s." % (recorded, key, top)}

    async def _acquire_scan_auth(self, session_id: str):
        """AUTHENTICATED SCANNING, autonomous + deterministic. Discover credentials the TARGET itself
        exposes -- harvested by recon this engagement, INHERITED from a prior engagement's memory, or found
        by a small bounded probe of likely credential-disclosure pages -- then log in ONCE and set
        self.tools.session_headers so the WHOLE scan runs AUTHENTICATED (all probe types inherit it). A
        single DISCOVERED value is used; passwords are never guessed/iterated. Exposed creds are recorded as
        a finding, and the discovery is stashed into target memory so the NEXT scan authenticates itself.
        Fully best-effort -- any missing attribute/error degrades to a no-op, never breaking a scan."""
        try:
            events = await self._do_scan_auth(session_id)
        except Exception:
            events = []
        for e in (events or []):
            yield e
        # Second half of the artery: mint same-privilege personas + run the two-user authorization
        # matrix. Best-effort; a failure here never breaks the scan.
        try:
            pevents = await self._do_persona_authz(session_id)
        except Exception:
            pevents = []
        for e in (pevents or []):
            yield e

    async def _do_scan_auth(self, session_id: str) -> list:
        events: list = []
        base = self._primary_base()
        sh = getattr(self.tools, "session_headers", None) or {}
        if not base or self.mode == "passive" or sh.get("Cookie") or sh.get("Authorization"):
            return events
        intel = getattr(self.tools, "intel", None)
        if intel is None:
            return events
        # 1) discovered creds: this engagement's harvest -> a prior engagement's memory -> a bounded probe.
        creds = list((intel.with_sources("credential") or {}).keys())
        prior_login, from_prior = None, False
        if not creds:
            try:
                import memory as _mem
                prior = db.get_prior_snapshot(_mem.target_key(self.scope.to_dict()), self.mission_id) or {}
                pc, plogin = self._creds_from_prior(prior)
                if pc:
                    creds = [pc]
                    prior_login = plogin
                    from_prior = True
            except Exception:
                pass
        if not creds:
            creds = await self._probe_for_creds(base)
        creds = [c for c in creds if ":" in c and c.split(":", 1)[0].lower() not in ("user", "username")
                 and "<redacted>" not in c]
        if not creds:
            return events
        user, pw = creds[0].split(":", 1)
        login_url = prior_login or self._discover_login_url(base) or base.rstrip("/") + "/login"
        # 2) DISCOVERY is unconditional: exposed creds are a FINDING (password redacted) and are stashed to
        #    target memory so the NEXT scan can OFFER an authenticated run. Authenticating is a separate,
        #    opted-in step (HITL) -- a scan never silently logs in.
        self._scan_credential = "%s:%s" % (user, pw)     # reuse channel (persisted to target memory; redacted in reports)
        self._scan_login_url = login_url
        # 2) VERIFY the discovered credential ACTUALLY WORKS with a single login (anti-brute capped) --
        #    a found credential is only a real finding once it authenticates. This does NOT run the scan
        #    authenticated; it just confirms validity + obtains a session. The FULL authenticated scan
        #    stays opt-in (the rescan prompt).
        try:
            await self.tools.execute("acquire_session",
                                     {"login_url": login_url, "username": user, "password": pw,
                                      "role": "__scan__"}, session_id)
        except Exception:
            pass
        sess = (getattr(self.tools, "_sessions", None) or {}).get("__scan__")
        verified = bool(sess)
        self._creds_verified = verified
        _src = "inherited from a prior scan of this target" if from_prior else "harvested from the target's own client-reachable surface"
        f = {"title": "%s application credentials for '%s'" % ("Confirmed working" if verified else "Exposed", user),
             "severity": "high" if verified else "medium",
             "family": "broken_auth", "confidence": "confirmed" if verified else "candidate",
             "target": login_url,
             # mappings supported by the actual evidence: a real, usable credential exposed to attackers
             "cwe": "CWE-522", "capec": "CAPEC-560", "owasp": "A07:2021",
             # CVSS reflects single-user-account compromise via a no-effort known credential (network,
             # low complexity, no privileges/interaction). Elevate I to High if the account holds
             # privileged/admin functions. N/A only if verification could not run — see evidence.
             "cvss_vector": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N" if verified else ""),
             "cvss_score": (8.2 if verified else None),
             "description": ("A valid, working login for the account '%s' is exposed to attackers (%s). Anyone who "
                             "reads the target's own surface obtains it — no guessing or brute force. Apolaki verified "
                             "the credential authenticates and issues a live session." % (user, _src)) if verified else
                            ("A candidate login for '%s' was %s, but a single verification login did not yield a "
                             "session (form/flow mismatch) — treat as an unconfirmed lead." % (user, _src)),
             "impact": ("An attacker logs in as '%s' and gains that user's full account access — reads and modifies "
                        "the account's data and can invoke every function that account is authorised for, and pivot "
                        "from there. Because the credential is exposed on the target itself, exploitation needs no "
                        "guessing, brute force, or user interaction." % user) if verified else
                       ("If valid, an attacker would gain '%s' account access with no brute force." % user),
             "evidence": ("Verified working: a login to %s as '%s' (password redacted) returned a valid "
                          "authenticated session (session cookie/token issued). Raw credential stored redacted in "
                          "the vault, never in this report." % (login_url, user)) if verified else
                         ("Discovered '%s:<redacted>' for the login at %s; a verification login did not return a "
                          "session." % (user, login_url)),
             "reproduction_steps": [
                 "POST %s  (form/JSON) with username='%s' and password=<the redacted discovered value>" % (login_url, user),
                 "Success oracle: the response issues a session cookie or bearer token; then a GET to an "
                 "authenticated-only page/identity endpoint returns 200 as '%s' (not the anonymous/login view)." % user,
             ] if verified else ["POST %s with '%s' and the discovered value; observe whether a session is issued." % (login_url, user)],
             "success_oracle": ("A session cookie/token is issued AND a subsequent authenticated-only request "
                                "loads as '%s'." % user) if verified else "A session is issued for the account.",
             "remediation": "Rotate/disable the '%s' account credential immediately and remove the exposed value from "
                            "all client-reachable content; enforce unique, secret, non-published credentials." % user,
             "validation": "Replay the exact login above with the OLD credential — it MUST now fail (401 / invalid "
                           "credentials) and issue no session; confirm the value no longer appears in any "
                           "client-reachable response."}
        if self.mission_id:
            try:
                f["id"] = db.add_finding(self.mission_id, f)
            except Exception:
                pass
        self.findings.append(f)
        events.append({"type": "finding", "finding": f})
        # 3) APPLY the session (whole scan runs authenticated) ONLY when the operator opted in -- the UI
        #    offers this on a rescan whose target has prior discovered creds. Otherwise: verified + saved,
        #    but the scan stays unauthenticated until the user chooses.
        if self.authenticated_scan and verified:
            self.tools.session_headers = {**sh, **sess}
            events.append({"type": "info", "content": "Authenticated as '%s' from %s credentials — the remaining "
                           "probes run logged-in (session applied across all probe types)."
                           % (user, "prior-scan" if from_prior else "discovered")})
        elif self.authenticated_scan and not verified:
            events.append({"type": "info", "content": "Could not authenticate as '%s' — the verification login "
                           "did not yield a session (form/flow mismatch); continuing unauthenticated." % user})
        elif verified:
            events.append({"type": "info", "content": "Verified WORKING credentials for '%s' (a valid session was "
                           "obtained) — recorded as a finding and saved. This scan runs UNAUTHENTICATED; re-run "
                           "with 'authenticated scan' to test the logged-in surface with these credentials." % user})
        else:
            events.append({"type": "info", "content": "Discovered a credential lead for '%s' (could not verify) — "
                           "recorded and saved." % user})
        return events

    def _creds_from_prior(self, prior: dict):
        """Recover a discovered credential from a prior scan's snapshot for reacquisition. Prefers the
        encrypted vault reference (scan_auth_ref); falls back to a legacy plaintext scan_auth for
        snapshots written before the vault. Returns (user:pw or None, login_url or None) — this is the
        'load the login recipe, acquire a fresh session' step of the session lifecycle."""
        prior = prior or {}
        ref = prior.get("scan_auth_ref")
        if ref:
            try:
                import vault as _vault
                sec = _vault.default().get(ref) or {}
                if sec.get("username") and sec.get("password"):
                    login = (sec.get("recipe") or {}).get("login_url") or prior.get("scan_login_url")
                    return "%s:%s" % (sec["username"], sec["password"]), login
            except Exception:
                pass
        sa = prior.get("scan_auth")   # legacy plaintext snapshot (pre-vault)
        if sa and ":" in sa:
            return sa, prior.get("scan_login_url")
        return None, None

    def _discover_register_url(self, base: str):
        """Pick an in-scope registration/signup endpoint from the harvested surface, else a common
        default. Mirrors _discover_login_url but hunts register/signup/join surfaces."""
        import re as _re
        cands = []
        try:
            for u in (self.tools.urls or []):
                if _re.search(r"/(register|signup|sign-up|join|create-account|users?)\b", str(u), _re.I):
                    cands.append(str(u))
        except Exception:
            pass
        for kind in ("route", "endpoint", "url"):
            try:
                for v in self.tools.intel.get(kind):
                    s = str(v)
                    if _re.search(r"regist|signup|sign-up|create.?account", s, _re.I):
                        cands.append(s if s.startswith("http") else base.rstrip("/") + "/" + s.lstrip("/"))
            except Exception:
                pass
        cands += [base.rstrip("/") + "/register", base.rstrip("/") + "/api/Users"]  # Juice-Shop-style default
        for u in cands:
            try:
                if self.scope.validate(u)[0]:
                    return u
            except Exception:
                pass
        return None

    def _register_candidates(self, base: str) -> list:
        """Ordered registration-endpoint candidates. API/JSON registration paths first (so a real
        signup API like Juice Shop /api/Users wins before an SPA /register route that returns 200
        index.html without creating anything), then the discovered URL, then form defaults. Deduped
        + scope-valid."""
        b = base.rstrip("/")
        cands = [b + p for p in ("/api/Users", "/api/register", "/api/auth/register", "/api/signup", "/api/users")]
        d = self._discover_register_url(base)
        if d:
            cands.append(d)
        cands += [b + p for p in ("/register", "/signup", "/users")]
        seen, out = set(), []
        for u in cands:
            if u in seen:
                continue
            seen.add(u)
            try:
                if self.scope.validate(u)[0]:
                    out.append(u)
            except Exception:
                pass
        return out[:6]

    async def _run_service_packs(self, session_id: str) -> list:
        """Beyond-web: DISCOVER non-web services on the target, classify them, and RUN each matching
        technique pack. Self-contained — it does a bounded socket port-scan of common service ports
        ITSELF (so it no longer depends on the model having run nmap first; CHAD review #1), in
        addition to any ports a prior nmap already reported. Scope-gated, bounded, best-effort."""
        import asyncio as _aio
        import service_router as _sr
        from urllib.parse import urlparse as _up
        events = []
        recon = getattr(self.tools, "recon", {}) or {}
        base = self._primary_base()
        host = (_up(base).hostname if base else "") or recon.get("target") or recon.get("domain") or ""
        if not host or not self.scope.validate(host)[0]:
            return events
        services = _sr.parse_nmap_ports((recon.get("nmap") or {}).get("open_ports") or [], host)
        known = {s["port"] for s in services}
        probe = [p for p in (21, 22, 23, 25, 53, 110, 143, 389, 445, 873, 1433, 1521, 2049, 2375,
                             3306, 3389, 5432, 5900, 5985, 6379, 9200, 11211, 27017) if p not in known]

        async def _open(p):
            try:
                r, w = await _aio.wait_for(_aio.open_connection(host, p), timeout=1.5)
                w.close()
                return p
            except Exception:
                return None
        for p in [x for x in await _aio.gather(*[_open(p) for p in probe]) if x]:
            svc = _sr.fingerprint(p)
            services.append({"host": host, "port": p, "service": svc, "banner": ""})
            self.tools.recon.setdefault("nmap", {}).setdefault("open_ports", []).append("%d/tcp open %s" % (p, svc))
        ran = 0
        for s in services:
            if _sr.is_web(s["service"]) or s["service"] == "unknown" or not s.get("host"):
                continue
            try:
                res = await self.tools.execute("run_service_pack",
                                               {"host": s["host"], "port": s["port"],
                                                "service": s["service"]}, session_id)
            except Exception:
                continue
            ran += 1
            for f in (res.findings or []):
                if self.mission_id:
                    try:
                        f["id"] = db.add_finding(self.mission_id, f)
                    except Exception:
                        pass
                self.findings.append(f)
                events.append({"type": "finding", "finding": f})
        if ran:
            events.append({"type": "info", "content": "Ran %d network service pack(s) from the port "
                           "scan (beyond-web execution)." % ran})
        return events

    async def _authenticated_recrawl(self, roles, base, session_id) -> list:
        """Per-persona authenticated pass. For EACH session persona, GET a set of common authed routes
        (harvesting object ids + endpoints into the surface/intel/LIVE graph) and, when a headless
        browser is available, load the base page to capture SPA routes + XHR/fetch APIs. Returns the
        newly-discovered in-scope URLs. Now a bounded DEPTH-2 BFS (CHAD capability D): the fixed-route +
        browser pass seeds depth-1, then crawl.bfs_frontier follows the newly-discovered authed
        links/XHR one level deeper. HONEST SCOPE: depth is capped at 2 and the frontier at 30 URLs;
        deeper recursion, form submission, and CSRF/MFA-resume recipes remain. Bounded + best-effort."""
        before = set(self.tools.urls or [])
        routes = ["", "/profile", "/account", "/me", "/dashboard", "/settings", "/api/users",
                  "/rest/user/whoami", "/api/orders", "/rest/basket", "/api/basket", "/orders",
                  "/api/user", "/graphql"]
        b = base.rstrip("/")
        for role in (roles or []):
            for r in routes:
                url = b + r
                try:
                    if self.scope.validate(url)[0]:
                        await self.tools.execute("http_read", {"url": url, "session": role}, session_id)
                except Exception:
                    pass
            # authenticated browser pass AS this persona: captures SPA routes + XHR APIs (seed _add_urls)
            try:
                await self.tools.execute("browser_navigate",
                                         {"url": base, "session": role,
                                          "steps": [{"action": "wait", "ms": 1200}]}, session_id)
            except Exception:
                pass
        # Depth-2 BFS (CHAD capability D): the fixed-route + browser pass just discovered new authed
        # links/XHR endpoints. Follow that frontier ONE more level AS the first persona (bounded) so
        # authenticated-only deep endpoints enter the surface + graph — a real recursive step, not a
        # fixed list. Pure crawl.bfs_frontier picks the frontier; the visits are scope-gated + budgeted.
        try:
            import crawl as _crawl
            import os as _os
            # configurable recursion depth (CHAD capability D): default 2, capped at 4. Each round
            # follows the newly-discovered authed frontier one level deeper AND extracts FORMS from
            # the fetched pages (action + method + fields), feeding form targets back into the surface.
            max_depth = max(1, min(int(_os.environ.get("BBH_CRAWL_DEPTH", "2") or 2), 4))
            deep_role = (roles or [None])[0]
            seen = set(before)
            for _round in range(max_depth - 1):     # depth-1 (routes + browser) already done above
                discovered = [u for u in (self.tools.urls or []) if u not in seen]
                frontier = _crawl.bfs_frontier(discovered, base, seen, limit=30)
                if not frontier:
                    break
                for u in frontier:
                    seen.add(u)
                    if not self.scope.validate(u)[0]:
                        continue
                    try:
                        res = await self.tools.execute("http_read", {"url": u, "session": deep_role}, session_id)
                        body = getattr(res, "output", "") if isinstance(getattr(res, "output", None), str) else ""
                        if "<form" in body.lower():
                            for fm in _crawl.extract_forms(body, u):
                                if fm.get("action") and self.scope.validate(fm["action"])[0]:
                                    self.tools._add_urls([fm["action"]])
                    except Exception:
                        pass
        except Exception:
            pass
        return [u for u in (self.tools.urls or []) if u not in before]

    async def _reacquire_personas(self, prior, pm, session_id) -> list:
        """Restore personas from a PRIOR scan: load each persona's vaulted account + login recipe and
        re-login to obtain a FRESH session (CHAD review #5 — reacquire complete persona recipes, not
        just the single discovered credential). Returns the roles restored. Best-effort."""
        import vault as _vault
        refs = (prior or {}).get("persona_refs") or {}
        restored = []
        for role, ref in refs.items():
            try:
                sec = _vault.default().get(ref) or {}
            except Exception:
                sec = {}
            recipe = sec.get("recipe") or {}
            login_url = recipe.get("login_url")
            user = sec.get("email") or sec.get("username")
            pw = sec.get("password")
            if not (login_url and user and pw):
                continue
            try:
                await self.tools.execute("acquire_session",
                                         {"login_url": login_url, "username": user, "password": pw,
                                          "role": role}, session_id)
            except Exception:
                pass
            hdr = (getattr(self.tools, "_sessions", None) or {}).get(role) or {}
            if hdr:
                pm.add(role, identity=user, method="reacquired", headers=hdr, account={"identity_ref": ref})
                self._persona_refs[role] = ref
                restored.append(role)
        return restored

    async def _do_persona_authz(self, session_id: str) -> list:
        """The artery's second half: mint TWO same-privilege personas via the target's own signup,
        re-crawl authenticated, then run the two-user AUTHORIZATION MATRIX and record confirmed
        access-control findings. Account creation is state-changing, so this is gated on an explicit
        authenticated_scan opt-in (active/full only). Secrets go to the encrypted vault; only role
        names and vault refs travel further. Best-effort — any error degrades to a no-op."""
        events: list = []
        if not self.authenticated_scan or self.mode == "passive":
            return events
        base = self._primary_base()
        if not base:
            return events
        import personas as _p
        import register as _reg
        import vault as _vault
        import authz as _authz
        import authz_matrix as _am
        from urllib.parse import urlparse as _up
        pm = _p.PersonaManager()
        vlt = _vault.default()
        mid = self.mission_id or "default"
        self._persona_refs = {}

        # 0) reacquire personas from a PRIOR scan (fresh sessions from vaulted login recipes) before
        #    minting new ones — so future scans restore full personas, not just the scan credential.
        try:
            import memory as _mem
            prior = db.get_prior_snapshot(_mem.target_key(self.scope.to_dict()), self.mission_id) or {}
        except Exception:
            prior = {}
        restored = await self._reacquire_personas(prior, pm, session_id)
        if restored:
            pm.bind(self.tools)
            events.append({"type": "info", "content": "Reacquired %d persona(s) from a prior scan "
                           "(fresh sessions from vaulted login recipes): %s."
                           % (len(restored), ", ".join(restored))})

        # 1) mint any MISSING same-privilege personas through the signup flow (bounded). Probe an
        #    API-first candidate list so a real registration API (e.g. Juice Shop /api/Users) wins over
        #    an SPA /register route that would 200 without creating anything.
        reg_cands = self._register_candidates(base)
        minted, stop = list(restored), False
        for label, role in (("user_a", _p.USER_A), ("user_b", _p.USER_B)):
            if stop or role in minted:      # already restored from a prior scan — don't re-register
                continue
            res, reg_url = None, None
            for cand in reg_cands:
                try:
                    r = await _reg.register(cand, label=label)
                except Exception:
                    r = {"created": False, "headers": {}, "blocked": []}
                if r.get("blocked"):
                    events.append({"type": "info", "content": "Registration needs a manual step (%s) at %s — "
                                   "skipping autonomous account creation; supply operator accounts to test "
                                   "access control." % (", ".join(r["blocked"]), cand)})
                    stop = True
                    break
                if r.get("created"):
                    res, reg_url = r, cand
                    break
            if res is None:
                continue
            acct = res.get("account") or {}
            hdr = res.get("headers") or {}
            login_url = None
            if not hdr and acct.get("password"):
                # API-style signup doesn't auto-login — log in with the freshly-created account.
                # Probe a short ordered candidate list (one KNOWN credential, never a password list)
                # and stop at the first that yields a session.
                for lu in self._login_candidates(base):
                    try:
                        await self.tools.execute("acquire_session",
                                                 {"login_url": lu,
                                                  "username": acct.get("email") or acct.get("username"),
                                                  "password": acct.get("password"), "role": role}, session_id)
                    except Exception:
                        pass
                    hdr = (getattr(self.tools, "_sessions", None) or {}).get(role) or {}
                    if hdr:
                        login_url = lu
                        break
            if not hdr and acct.get("password"):
                # browser-driven fallback (CHAD 1): API/form login didn't yield a session (SPA login,
                # client-side token, JS-gated form) — drive a real headless login through the UI and
                # promote the token from web storage / cookies into the persona's session.
                login_page = self._discover_login_url(base) or base
                steps = [
                    {"action": "goto", "url": login_page},
                    {"action": "fill", "selector": "input[type=email], input[name=email], input[name=username], #email",
                     "value": acct.get("email") or acct.get("username")},
                    {"action": "fill", "selector": "input[type=password], input[name=password], #password",
                     "value": acct.get("password")},
                    {"action": "click", "selector": "button[type=submit], button#loginButton, button, input[type=submit]"},
                    {"action": "wait", "ms": 1500},
                ]
                try:
                    await self.tools.execute("browser_navigate",
                                             {"url": login_page, "steps": steps, "promote_session": role}, session_id)
                except Exception:
                    pass
                hdr = (getattr(self.tools, "_sessions", None) or {}).get(role) or {}
                if hdr:
                    login_url = login_page
            if not hdr:
                continue  # created but no session — cannot test as this persona
            ref = vlt.put(mid, role, {"username": acct.get("username"), "email": acct.get("email"),
                                      "password": acct.get("password"), "headers": hdr,
                                      "recipe": {"register_url": reg_url, "login_url": login_url,
                                                 "mode": "registration", "success_oracle": "session-cookie-present"}})
            pm.add(role, identity=res.get("identity") or acct.get("email", ""), method="registered",
                   headers=hdr, account={"identity_ref": ref})
            minted.append(role)
            self._persona_refs[role] = ref     # so the NEXT scan can reacquire this persona
            try:
                import audit as _audit
                _audit.record("account_created", actor="apolaki", mission=mid, target=role,
                              method="registered", identity_ref=ref)
            except Exception:
                pass
            events.append({"type": "info", "content": "Created test persona '%s' (%s) via signup — session "
                           "captured, secret vaulted (%s)." % (role, res.get("identity"), ref)})

        # 2) fall back to the verified single discovered credential as one persona
        scan_sess = (getattr(self.tools, "_sessions", None) or {}).get("__scan__")
        if scan_sess and _p.USER_A not in minted:
            pm.add(_p.USER_A, identity="(discovered credential)", method="discovered", headers=scan_sess)
            minted.append(_p.USER_A)
        if not pm.session_roles():
            return events
        pm.bind(self.tools)   # project persona sessions onto the live registry (_sessions + identities)

        # 3) REAL per-persona authenticated re-crawl: crawl authed routes AS EACH persona (not a single
        #    GET-root) so the logged-in surface — object ids, authed-only endpoints, SPA XHR APIs —
        #    enters the inventory + LIVE graph, which the planner now reads (CHAD review #1/#7).
        new_urls = await self._authenticated_recrawl(pm.session_roles(), base, session_id)
        events.append({"type": "info", "content": "Authenticated re-crawl as %s — %d new endpoint(s) "
                       "merged into the surface + live graph before the authorization matrix."
                       % (", ".join(pm.session_roles()), len(new_urls))})

        # 4) build the operation set from the (now authenticated) surface + intel
        urls = [str(u) for u in (self.tools.urls or [])]
        for kind in ("endpoint", "route", "url"):
            try:
                for v in self.tools.intel.get(kind):
                    s = str(v)
                    urls.append(s if s.startswith("http") else base.rstrip("/") + "/" + s.lstrip("/"))
            except Exception:
                pass
        operations = _am.candidate_operations(urls)
        for u in urls:                                  # + privileged-looking paths for the vertical (BFLA) check
            try:
                p = _up(u).path
            except Exception:
                p = ""
            if p and _authz._looks_privileged(p) and not any(o["path"] == p for o in operations):
                operations.append({"request": p, "path": p})
        if not operations:
            events.append({"type": "info", "content": "Authorization matrix: no object-bearing endpoints "
                           "discovered to compare across personas."})
            return events

        # 5) run the matrix through the scoped + captured transport
        roles = [{"role": r["role"], "rank": r["rank"], "tenant": r["tenant"]} for r in pm.matrix_roles()]
        pair = pm.same_privilege_pair()
        owner_identity = ""
        if pair and pm.get(pair[0]):
            p0 = pm.get(pair[0])
            owner_identity = p0.identity or (p0.account or {}).get("email", "")
        res = await self.tools.execute("run_authz_matrix",
                                       {"base_url": base, "roles": roles, "operations": operations,
                                        "pair": list(pair) if pair else None,
                                        "owner_identity": owner_identity}, session_id)
        # real per-persona transport counters from the matrix (CHAD #2) — attempted/succeeded auth
        # requests, status distribution, endpoints touched. Stored in _auth_artery below as PROOF.
        try:
            self._authz_request_stats = json.loads(res.output or "{}").get("auth_requests", {})
        except Exception:
            self._authz_request_stats = {}
        for f in (res.findings or []):
            if self.mission_id:
                try:
                    f["id"] = db.add_finding(self.mission_id, f)
                except Exception:
                    pass
            self.findings.append(f)
            events.append({"type": "finding", "finding": f})

        # 5b) horizontal WRITE test — Full mode only (state-changing), on objects already proven
        #     cross-user READABLE, using the same persona pair. Bounded + restore-capable.
        if self.mode == "full" and pair:
            read_idor = [f["target"] for f in (res.findings or [])
                         if f.get("family") == "idor" and "write" not in (f.get("tags") or [])]
            for tgt in read_idor[:5]:
                try:
                    wr = await self.tools.execute("confirm_authz_write",
                                                  {"target_url": tgt, "owner_session": pair[0],
                                                   "attacker_session": pair[1]}, session_id)
                except Exception:
                    continue
                for f in (wr.findings or []):
                    if self.mission_id:
                        try:
                            f["id"] = db.add_finding(self.mission_id, f)
                        except Exception:
                            pass
                    self.findings.append(f)
                    events.append({"type": "finding", "finding": f})

        # 5c) CREATE-OBJECT IDOR (CHAD C): the strongest cross-user proof — create a uniquely-owned
        #     object as the owner persona, then access it as the attacker. Ownership is definitive
        #     (we made it with a private marker). Bounded + self-cleaning; runs on the same pair.
        if pair:
            app = "juiceshop" if "juice" in base.lower() else ""
            try:
                cres = await self.tools.execute("confirm_create_object_idor",
                                                {"base_url": base, "owner": pair[0], "attacker": pair[1],
                                                 "app": app, "allow_write": self.mode == "full"}, session_id)
                for f in (cres.findings or []):
                    if self.mission_id:
                        try:
                            f["id"] = db.add_finding(self.mission_id, f)
                        except Exception:
                            pass
                    self.findings.append(f)
                    events.append({"type": "finding", "finding": f})
                if cres.findings:
                    events.append({"type": "info", "content": "Create-object IDOR: %d confirmed cross-user "
                                   "object access(es) proven via owned-object creation." % len(cres.findings)})
                # record that C actually FIRED (attempts + confirmed), so the artifact proves the
                # owner-create -> attacker-access flow ran live, even when the target enforces authz
                # correctly (0 confirmed = no false positive, still a real executed test).
                try:
                    self._create_object_result = {**json.loads(cres.output or "{}"),
                                                  "confirmed": len(cres.findings)}
                except Exception:
                    self._create_object_result = {"ran": True, "confirmed": len(cres.findings)}
            except Exception:
                pass

        # 6) record the capabilities this phase unlocked (feeds the planner + attack graph)
        caps = pm.capabilities() + (["authenticated_surface_mapped"] if pm.session_roles() else [])
        for cap in caps:
            try:
                self.tools.state.add_capability(cap, "persona authz phase")
            except Exception:
                pass
        events.append({"type": "info", "content": "Authorization matrix complete: %d persona(s), %d "
                       "operation(s), %d confirmed access-control finding(s). Capabilities: %s."
                       % (len(pm.session_roles()), len(operations), len(res.findings or []),
                          ", ".join(caps) or "none")})
        self._persona_manager = pm
        # Structured PROOF the artery actually fired — persisted to mission context + report so it is
        # queryable, not trapped in the event stream. Personas carry role/rank/method/identity only
        # (pm.to_dict() never emits secrets). auth_success = personas that obtained a live session. This
        # is what a correctness benchmark asserts on (auth_success>=2, matrix ran) instead of a smoke test.
        try:
            plist = (pm.to_dict() or {}).get("personas", [])
            areq = getattr(self, "_authz_request_stats", {}) or {}
            by_role = areq.get("by_role", {}) or {}
            # PROOF (not inference): real authenticated requests happened AND succeeded from BOTH
            # same-privilege personas — the strongest evidence the sessions are genuinely usable.
            both_ok = bool(pair) and all((by_role.get(r, {}).get("succeeded", 0) > 0) for r in (pair or []))
            self._auth_artery = {
                "ran": True,
                "personas": plist,
                "persona_count": len(pm.session_roles()),
                "auth_success": sum(1 for r in pm.session_roles() if pm.get(r) and pm.get(r).has_session()),
                "reacquired": list(restored),
                "recrawl_new_endpoints": len(new_urls),
                "matrix": {"operations": len(operations),
                           "findings": len(res.findings or []),
                           "pair": list(pair) if pair else None,
                           "ran": True},
                # REAL transport evidence (CHAD #2): counted at the wire, not matrix_ops*personas
                "authenticated_requests": {
                    "attempted": areq.get("attempted", 0),
                    "succeeded": areq.get("succeeded", 0),
                    "by_role": by_role,
                    "status_dist": areq.get("status_dist", {}),
                    "endpoints_touched": areq.get("endpoints_touched", 0),
                    "with_auth_material": areq.get("with_auth_material", 0),
                    "both_personas_succeeded": both_ok,
                },
                # PROOF capability C (create-object IDOR) executed live: {ran, attempts, confirmed}
                "create_object_idor": getattr(self, "_create_object_result", {"ran": False}),
                "capabilities": caps,
            }
        except Exception:
            self._auth_artery = {"ran": True, "note": "artery ran; evidence capture degraded"}
        return events

    def _discover_login_url(self, base: str):
        """Pick an in-scope login endpoint from the harvested surface, else a common default."""
        import re as _re
        cands = []
        try:
            for u in (self.tools.urls or []):
                if _re.search(r"/(login|signin|sign-in|session|auth)\b", str(u), _re.I):
                    cands.append(str(u))
        except Exception:
            pass
        for kind in ("route", "endpoint", "url"):
            try:
                for v in self.tools.intel.get(kind):
                    s = str(v)
                    if _re.search(r"login|signin|auth", s, _re.I):
                        cands.append(s if s.startswith("http") else base.rstrip("/") + "/" + s.lstrip("/"))
            except Exception:
                pass
        cands.append(base.rstrip("/") + "/login")
        for u in cands:
            try:
                if self.scope.validate(u)[0]:
                    return u
            except Exception:
                pass
        return None

    def _login_candidates(self, base: str) -> list:
        """Ordered login-endpoint candidates for logging in a freshly-created account. API/JSON login
        paths first (so a real token login wins before an SPA /login route can hand back a bare
        tracking cookie), then the discovered login URL, then form defaults. Deduped + scope-valid.
        One KNOWN credential is tried against each until a session is obtained — endpoint discovery,
        never a password list."""
        b = base.rstrip("/")
        cands = [b + p for p in ("/rest/user/login", "/api/login", "/api/auth/login", "/auth/login")]
        d = self._discover_login_url(base)
        if d:
            cands.append(d)
        cands += [b + p for p in ("/login", "/user/login", "/api/sessions")]
        seen, out = set(), []
        for u in cands:
            if u in seen:
                continue
            seen.add(u)
            try:
                if self.scope.validate(u)[0]:
                    out.append(u)
            except Exception:
                pass
        return out[:6]   # bounded — stays under the acquire_session anti-brute cap

    async def _probe_for_creds(self, base: str) -> list:
        """Bounded, polite fetch of the login page + common credential-disclosure pages, harvesting any
        exposed creds into the intel store. Small fixed page set -- never a crawl/brute."""
        import httpx
        for p in ("/vulnerabilities", "/", "/login", "/readme", "/README.md", "/help", "/about"):
            u = base.rstrip("/") + p
            try:
                if not self.scope.validate(u)[0]:
                    continue
                async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=12,
                                             headers={"User-Agent": "apolaki-recon"}) as c:
                    self.tools._harvest_body(u, {}, (await c.get(u)).text)
            except Exception:
                continue
        return list((self.tools.intel.with_sources("credential") or {}).keys())

    # ── AI-call budget helpers ───────────────────────────────────
    def _ai_usable(self) -> bool:
        return bool(self.client) and self._has_key

    def _budget_left(self) -> bool:
        return self.ai_calls < self.max_ai_calls

    def _budget_event(self) -> dict:
        return {"type": "ai_budget", "used": self.ai_calls, "max": self.max_ai_calls,
                "strategy": self.strategy}

    async def _ai_text(self, system: str, user: str, max_tokens: int = 800) -> str:
        """One plain (no-tool) LLM completion; counts against the budget."""
        self.ai_calls += 1
        if self.provider == "openrouter":
            r = await self.client.chat.completions.create(
                model=self.model, max_tokens=max_tokens,
                messages=[{"role": "system", "content": system}, {"role": "user", "content": user}])
            return (r.choices[0].message.content or "").strip()
        r = await self.client.messages.create(
            model=self.model, max_tokens=max_tokens, system=system,
            messages=[{"role": "user", "content": user}])
        return "".join(getattr(b, "text", "") for b in r.content).strip()

    # ── entry ────────────────────────────────────────────────────
    async def run(self, objective: str, session_id: str) -> AsyncGenerator[dict, None]:
        yield {"type": "phase", "phase": "recon"}
        if self.recon_cycles > 1:
            yield {"type": "info", "content": f"Iterative recon enabled: up to {self.recon_cycles} cycles "
                   "(refine from discovered assets each pass; intrusive tools are not looped)."}
        # Be honest when the browser XSS confirmer is dead: reflected XSS in
        # script/DOM contexts can then only ever be advisory leads.
        import tools as _tools_mod
        if _tools_mod.xss_confirm_status() is False:
            yield {"type": "info", "content": "Headless-browser XSS confirmer unavailable — reflected XSS in "
                   "script/DOM contexts will stay advisory leads (HTML/attribute-context reflections still confirm)."}
        yield self._budget_event()

        # Deterministic code-intelligence recon: mine the target's served JS, seed the scan surface,
        # and raise sensitive-route + business-logic leads BEFORE the scan runs (every strategy).
        async for ev in self._recon_code_intelligence(session_id):
            yield ev

        # Beyond-web: turn the port scan into service-pack EXECUTION (nmap -> classify -> run pack).
        try:
            for ev in await self._run_service_packs(session_id):
                yield ev
        except Exception:
            pass

        # Authenticated scanning: discover credentials the target exposes (or inherit them from a prior
        # scan) and log in, so the whole assessment runs as a real user (every strategy, active/full only).
        async for ev in self._acquire_scan_auth(session_id):
            yield ev

        strat = self.strategy
        # Degrade to deterministic when AI is needed but unusable (missing key /
        # exhausted quota) — the platform stays useful without AI (item 4).
        if strat in ("low_ai", "agentic") and not self._ai_usable():
            self.ai_degraded = True
            self.ai_note = f"AI unavailable (no usable credential) — {strat} degraded to deterministic coverage."
            yield {"type": "info", "content": "AI unavailable — completing with deterministic coverage."}
            strat = "deterministic"

        if strat == "manual":
            yield {"type": "complete", "content": "Manual mode: no automated run. Drive testing yourself "
                   "with the cURL Console, Workbench, and Access Check."}
            return
        if strat == "deterministic":
            async for ev in self._run_deterministic(session_id):
                yield ev
        elif strat == "low_ai":
            async for ev in self._run_low_ai(objective, session_id):
                yield ev
        else:
            # QUAL-1: an agentic run must never fall below deterministic coverage.
            # Previously the ReAct loop ran alone, so a model that decided "analysis
            # complete" after a couple of calls could silently under-scan (observed:
            # 2 tools / 0 findings where deterministic found 6 on the same target).
            # Run the deterministic plan as a COVERAGE FLOOR first, then let the ReAct
            # loop augment on the already-mapped surface — AI adds, never replaces.
            yield {"type": "info", "content": "Agentic: establishing a deterministic coverage floor, "
                   "then the AI augments on the mapped surface."}
            # mark the floor so _run_tool auto-stores its confirmed findings (no model
            # is driving during the floor); the ReAct phase below stores its own.
            self._in_floor = True
            try:
                async for ev in self._execute_plan(session_id):
                    yield ev
            finally:
                self._in_floor = False
            floor_steps = getattr(self, "_plan_steps", 0)
            # ReAct augmentation. A RUNTIME provider failure (e.g. a 429 free-tier
            # quota hit) can't be seen by the credential pre-check; since the floor
            # already produced full coverage, catch it and finalize gracefully
            # instead of failing the run.
            gen = self._run_openrouter(objective, session_id) if self.provider == "openrouter" \
                else self._run_anthropic(objective, session_id)
            try:
                async for event in gen:
                    yield event
            except Exception as ex:
                low = str(ex).lower()
                ai_err = any(k in low for k in ("429", "quota", "rate limit", "rate-limit",
                                                "timeout", "timed out", "401", "unauthorized",
                                                "authentication", "insufficient"))
                self.ai_degraded = True
                self.ai_note = (f"Agentic AI unavailable ({type(ex).__name__}) — deterministic "
                                f"coverage floor completed ({floor_steps} step(s)).")
                yield {"type": "info", "content": ("AI rate-limited/unavailable" if ai_err
                       else f"AI augmentation error ({type(ex).__name__})") +
                       " — the deterministic coverage floor already completed for this run."}
                yield {"type": "complete", "content": f"Agentic run completed on the deterministic "
                       f"coverage floor ({floor_steps} step(s)). See Playbooks and the report."}
        # Deterministic technique advisor: consult the knowledge model for the top applicable
        # techniques given the surface + confirmed findings, raised as prioritized leads (every strategy).
        async for ev in self._technique_advisor(session_id):
            yield ev
        # Close CHAD's deterministic autonomy loop: record this engagement's evidence into per-target
        # memory and emit the ranked next-best-action from the SAME planner that powers /plan (every strategy).
        async for ev in self._close_autonomy_loop(session_id):
            yield ev
        # GENERAL candidate-validation pipeline (runs for EVERY strategy, LATE — after the technique
        # advisor + autonomy loop have contributed their leads). Every remaining testable lead is
        # normalized, routed to a real validator, and driven to an EXPLICIT terminal state
        # (confirmed / dismissed / blocked-with-named-prereq / unsupported), with a per-candidate
        # assurance record. No testable lead is left sitting; "no browser" is a visible BLOCKED row.
        async for ev in self._validate_candidates(session_id):
            yield ev
        # advisory triage pass (METIS) over persisted findings
        async for ev in self._triage():
            yield ev

    # ── deterministic executor (planner-driven, no AI) ───────────
    def _seed_and_project_graph(self, g) -> None:
        """Project ALL current engagement state into the mission graph so the graph is the single
        source the primary planner reads (CHAD: graph-authoritative execution). Seeds the in-scope
        roots as host nodes (bootstrap) and folds recon subdomains/live-hosts, discovered URLs, and
        findings into the graph. Idempotent (observe merges); best-effort."""
        try:
            for e in self.scope.in_scope:
                v = (getattr(e, "value", "") or "").lower().lstrip("*.")
                if v:
                    g.observe("host", v, label=v, source="scope")
            for s in (self.tools.recon.get("subdomains") or []):
                s = str(s).lower()
                if s:
                    g.observe("host", s, label=s, source="recon")
            for h in (self.tools.recon.get("live_hosts") or []):
                u = h.get("url") if isinstance(h, dict) else str(h)
                if u:
                    g.observe("endpoint", u, label=u, source="recon")
            for u in (self.tools.urls or []):
                if u:
                    g.observe("endpoint", str(u), label=str(u), source="recon")
            for f in (self.findings or []):
                g.observe("finding", str(f.get("id") or (f.get("title", "")[:40])),
                          label=f.get("title", "finding"), source="scan", family=(f.get("family") or ""))
            self._graph_projection_error = None
        except Exception as e:
            # do NOT swallow silently (CHAD): a projection failure means the graph is stale, which
            # directly affects primary action selection — record it so the executor can surface it.
            self._graph_projection_error = str(e)

    def _graph_primary_state(self, g):
        """Derive the planner's ASSET-SELECTION world-state FROM THE GRAPH only. roots = graph host
        labels; urls = graph endpoint labels; live_hosts = the tool-discovered detail for hosts the
        GRAPH holds. An empty graph yields empty roots+urls, so flat recon can NEVER independently
        select a primary action (that is the graph-authoritative guarantee). Returns (roots, urls, recon)."""
        from urllib.parse import urlparse
        hosts = sorted({n.get("label") for n in g.nodes("host") if n.get("label")})
        hostset = set(hosts)
        eps = [n.get("label") for n in g.nodes("endpoint") if n.get("label")]

        def _host_of(u):
            try:
                return urlparse(u).netloc or u
            except Exception:
                return u
        live = [h for h in (self.tools.recon.get("live_hosts") or [])
                if isinstance(h, dict) and (_host_of(h.get("url", "")) in hostset or h.get("url") in eps)]
        recon = {"subdomains": hosts, "live_hosts": live,
                 "target": self.tools.recon.get("target"), "domain": self.tools.recon.get("domain")}
        return hosts, eps, recon

    async def _execute_plan(self, session_id: str):
        """Drive the planner through the SAME scoped, HITL-gated tool pipeline — but GRAPH-FIRST
        (CHAD): each step projects engagement state into the mission graph, then derives the planner's
        asset-selection world-state FROM the graph and gates on it (empty graph => no primary action).
        recon_cycles are honored; dedup + a hard step cap guarantee it ends."""
        import planner
        base_roots = [e.value.lower().lstrip("*.") for e in self.scope.in_scope]
        done, steps = set(), 0
        MAX_STEPS = 220
        cycles = self.recon_cycles
        for cyc in range(1, cycles + 1):
            if self.stop_event.is_set() or steps >= MAX_STEPS:
                break
            if cycles > 1:
                yield {"type": "cycle", "cycle": cyc, "total": cycles,
                       "content": f"Deterministic recon cycle {cyc} of {cycles} — folding in newly "
                                  "discovered in-scope assets."}
            before = self._surface_size()
            # a fresh playbook each cycle reflects everything found so far
            done.discard("generate_playbook")
            while steps < MAX_STEPS:
                if self.stop_event.is_set():
                    self._plan_steps = steps
                    return
                # GRAPH-AUTHORITATIVE primary execution (CHAD major #1): project everything into the
                # mission graph, then derive the planner's asset-selection world-state FROM the graph.
                # Flat recon populates the graph but never selects actions directly; an EMPTY graph
                # yields no roots/urls => no primary action.
                g = getattr(self.tools, "graph", None)
                if g is None:
                    # FAIL-CLOSED (CHAD): with no mission graph there is no asset-selection authority —
                    # halt primary execution rather than silently falling back to flat recon.
                    yield {"type": "info", "content": "No mission graph — primary execution halted "
                           "(the graph is the asset-selection authority; no flat-recon fallback)."}
                    break
                self._seed_and_project_graph(g)
                if getattr(self, "_graph_projection_error", None):
                    # HALT the primary planning cycle (CHAD): a projection failure means the graph is
                    # stale/partial, so the planner must NOT keep selecting actions off it. Emit + persist
                    # a structured degraded event so it shows in mission status + report.
                    self._degraded = {"reason": "graph_projection_failed",
                                      "detail": str(self._graph_projection_error)}
                    yield {"type": "degraded", "reason": "graph_projection_failed",
                           "content": "Primary execution HALTED — mission graph projection failed: %s"
                                      % self._graph_projection_error}
                    self._plan_steps = steps
                    return
                g_roots, g_urls, g_recon = self._graph_primary_state(g)
                if not g_roots and not g_urls:
                    break
                state = {"mode": self.mode, "roots": g_roots, "done": done,
                         "recon": g_recon, "urls": g_urls,
                         "bases": self.scope.base_map(),
                         # ZAP runs only when the user enabled it for this scan (and
                         # a daemon is configured); the planner's INTRUSIVE gate keeps
                         # it to Full mode. Policy rides along to the run_zap step.
                         "zap": self.enable_zap and _zap_configured(),
                         "zap_policy": self.zap_policy,
                         "zap_speed": self.zap_speed, "zap_aggression": self.zap_aggression,
                         "nmap_vuln": self.enable_nmap_vuln,
                         "nuclei_heavy": self.enable_nuclei_heavy,
                         # intensity dial (on the tool registry) rides to the planner so
                         # deep/insane can schedule the heavy sqlmap pass alongside run_sqli.
                         "intensity": getattr(self.tools, "intensity", "standard")}
                batch = planner.next_batch(state)
                if not batch:
                    break
                for step in batch:
                    if self.stop_event.is_set():
                        self._plan_steps = steps
                        return
                    done.add(step["key"])
                    steps += 1
                    async for ev in self._run_tool(step["tool"], step["input"], session_id):
                        if "_content" not in ev:      # no model to feed; drop the tool-result payload
                            yield ev
            # stop early once a cycle stops finding new surface
            if cyc < cycles and self._surface_size() <= before:
                yield {"type": "info", "content": f"Recon cycle {cyc} found no new in-scope assets — "
                       "stopping early."}
                break
        # promotion pass: re-test high-signal candidate leads with a confirmatory oracle
        async for ev in self._promote_leads(session_id):
            yield ev
        # additive AI enhancement: business-logic hypotheses -> leads (no-op unless an AI
        # strategy is selected and usable). The model hunts; deterministic oracles confirm.
        async for ev in self._ai_business_logic_leads(session_id):
            yield ev
        # NOTE: the general candidate-validation pipeline runs LATE in the main scan flow (after the
        # technique advisor + autonomy loop have added their leads) so EVERY lead is validated, not
        # only the ones known at deterministic-pass time. See _run_scan.
        self._plan_steps = steps

    async def _run_deterministic(self, session_id: str):
        yield {"type": "info", "content": f"Deterministic scan planner engaged ({self.mode} mode, no AI) — "
               "recon → live hosts → fingerprint → enrich → surface probes → nuclei → playbook."}
        async for ev in self._execute_plan(session_id):
            yield ev
        note = " AI was unavailable; deterministic coverage completed." if self.ai_degraded else ""
        if not self.ai_note:
            self.ai_note = ("Deterministic (no-AI) coverage completed." if not self.ai_degraded
                            else self.ai_note)
        yield {"type": "complete", "content":
               f"Deterministic scan complete — {getattr(self, '_plan_steps', 0)} step(s).{note} "
               "See Playbooks for cURL-ready leads and the report."}

    # ── low-AI executor (planner + ≤2 targeted AI calls) ─────────
    async def _run_low_ai(self, objective: str, session_id: str):
        # AI call #1 (optional): only when there IS a specific objective and budget
        # allows — a generic objective adds no signal, so we save the call for #2.
        if self._budget_left() and objective and not _is_generic_objective(objective):
            try:
                pri = await self._ai_text(
                    "You are a lead penetration tester. Given the objective and scope, list 3-6 concise, "
                    "weighted testing priorities (most important first) as short bullet lines. No preamble.",
                    f"OBJECTIVE:\n{objective}\n\nSCOPE:\n{json.dumps(self.scope.to_dict())}")
                if pri:
                    yield {"type": "text", "content": "Testing priorities (AI):\n" + pri}
                yield self._budget_event()
            except Exception as e:
                yield {"type": "info", "content": f"AI prioritization skipped ({type(e).__name__})."}
                yield self._budget_event()   # the attempt counted; keep the chip in sync

        yield {"type": "info", "content": f"Low-AI scan — deterministic planner ({self.mode} mode) with an "
               "AI wrap-up. Budget: " + f"{self.ai_calls}/{self.max_ai_calls} calls used."}
        async for ev in self._execute_plan(session_id):
            yield ev

        # AI call #2 (the high-value one): summarize evidence + prioritize leads.
        wrapped = False
        if self._budget_left():
            try:
                async for ev in self._ai_wrapup(session_id):
                    yield ev
                wrapped = True
            except Exception as e:
                self.ai_note = f"Low-AI: deterministic scan completed; AI wrap-up skipped ({type(e).__name__})."
                yield {"type": "info", "content": f"AI wrap-up skipped ({type(e).__name__})."}
                yield self._budget_event()   # the attempt counted; keep the chip in sync
        if not self.ai_note:
            self.ai_note = (f"Low-AI: deterministic scan + AI wrap-up ({self.ai_calls} AI call(s))."
                            if wrapped else f"Low-AI: deterministic scan ({self.ai_calls} AI call(s)).")
        yield {"type": "complete", "content":
               f"Low-AI scan complete — {getattr(self, '_plan_steps', 0)} step(s), "
               f"{self.ai_calls}/{self.max_ai_calls} AI call(s). See Playbooks and the report."}

    async def _ai_wrapup(self, session_id: str):
        """AI call #2: turn the deterministic evidence into an executive summary +
        prioritized next leads, stored on the mission for the report."""
        inv = self.tools.surface_inventory()
        findings = db.get_findings(self.mission_id) if self.mission_id else []
        pb = []
        if self.mission_id:
            m = db.get_mission(self.mission_id)
            pb = [g.get("title") for g in ((m or {}).get("context", {}).get("playbook") or [])][:15]
        payload = {"scope": self.scope.to_dict().get("in_scope", []),
                   "surface": inv.get("stats", {}),
                   "findings": [{"title": f.get("title"), "severity": f.get("severity"),
                                 "target": f.get("target")} for f in findings],
                   "playbook_leads": pb}
        summary = await self._ai_text(
            "You are a lead penetration tester writing the executive summary of an authorized assessment. "
            "Given the surface stats, any confirmed findings, and the rule-based playbook leads, write: "
            "(1) a 2-4 sentence honest summary (if nothing was confirmed, say so plainly), then "
            "(2) 'Top leads to test next:' with 3-6 prioritized bullets referencing the playbook. Be specific.",
            json.dumps(payload), max_tokens=900)
        yield self._budget_event()
        if summary:
            yield {"type": "summary", "content": summary}
            if self.mission_id:
                m = db.get_mission(self.mission_id)
                ctx = dict((m or {}).get("context", {}))
                ctx["ai_summary"] = summary
                db.update_mission(self.mission_id, context=ctx)

    async def _triage(self):
        if not self.mission_id:
            return
        findings = db.get_findings(self.mission_id)
        if not findings:
            return
        self.current_phase = "report"
        yield {"type": "phase", "phase": "report"}
        result = triage_mod.triage(findings)
        for f in findings:
            ann = result["annotations"].get(f.get("id"))
            if not ann:
                continue
            f["cwe"] = f.get("cwe") or ann["cwe"]
            f["owasp"] = ann["owasp"]
            existing = f.get("analyst_notes", "")
            f["analyst_notes"] = (existing + " | " + ann["analyst_notes"]).strip(" |") if existing else ann["analyst_notes"]
            db.update_finding(f["id"], f)
        m = db.get_mission(self.mission_id)
        ctx = (m or {}).get("context", {})
        ctx["chains"] = result["chains"]
        db.update_mission(self.mission_id, context=ctx)
        yield {"type": "triage", "verdict": result["verdict"], "chains": result["chains"]}

    def _recon_note(self) -> str:
        """Iterative-recon directive. Empty at 1 cycle (default = unchanged)."""
        n = self.recon_cycles
        if n <= 1:
            return ""
        return (
            f"\n\nITERATIVE RECON: Perform up to {n} recon cycles before active/intrusive testing. "
            "After each recon pass, review the newly discovered in-scope subdomains, live hosts, URLs, "
            "technologies, and OpenAPI/GraphQL hints, then run passive/active recon again ONLY on assets you "
            "have not yet covered, to deepen the surface. Deduplicate — never re-run the same tool against a "
            "target already covered, and do not repeat intrusive tools across cycles. Every discovered target "
            "is still scope-validated. Stop early and proceed to the next phase once a cycle yields no new "
            "in-scope assets.")

    def _system(self) -> str:
        # Surface any non-default target base (explicit scheme/port, e.g. a local app
        # on http://host:42000) so the model probes it instead of assuming https:443.
        nonstd = [u for u in self.scope.base_urls()
                  if not (u.startswith("https://") and u.count(":") == 1)]
        seed = ("\n\nTARGET BASE URLS — probe these EXACT scheme+port (do NOT assume https on 443):\n"
                + "\n".join(f"- {u}" for u in sorted(nonstd))) if nonstd else ""
        return (SYSTEM_PROMPT + MODE_NOTES.get(self.mode, "") + self._recon_note()
                + (self.memory_note or "")
                + f"\n\nSCOPE:\n{json.dumps(self.scope.to_dict(), indent=2)}" + seed)

    # ── ReAct loop guards (dedup + no-progress + budget) ─────────
    def _surface_size(self) -> int:
        return (len(self.tools.urls) + len(self.tools.recon.get("subdomains", []))
                + len(self.tools.recon.get("live_hosts", [])) + len(self.findings))

    @staticmethod
    def _tool_sig(name: str, inp: dict) -> str:
        try:
            return name + ":" + json.dumps(inp, sort_keys=True)[:200]
        except Exception:
            return name + ":?"

    async def _react_finish(self, session_id: str, reason: str):
        """Deterministic wrap-up when the ReAct loop hits its budget or stalls —
        guarantees a playbook and a clean completion instead of burning calls."""
        yield {"type": "info", "content": f"Wrapping up ({reason}) — generating the deterministic playbook."}
        m = db.get_mission(self.mission_id) if self.mission_id else None
        if not ((m or {}).get("context", {}).get("playbook")):
            async for ev in self._run_tool("generate_playbook", {}, session_id):
                if "_content" not in ev:
                    yield ev
        yield {"type": "complete", "content": f"Analysis complete ({reason}). See Playbooks and the report."}

    # ── OpenRouter / OpenAI ──────────────────────────────────────
    async def _run_openrouter(self, objective: str, session_id: str):
        messages = [{"role": "system", "content": self._system()},
                    {"role": "user", "content": objective}]
        openai_tools = self.tools.get_openai_tools()
        called, stall, last = set(), 0, self._surface_size()

        while True:
            if self.stop_event.is_set():
                yield {"type": "complete", "content": "Hunt stopped by user."}
                return
            if not self._budget_left():
                async for ev in self._react_finish(session_id, f"AI budget reached ({self.max_ai_calls} calls)"):
                    yield ev
                return
            self.ai_calls += 1
            yield self._budget_event()
            response = await self.client.chat.completions.create(
                model=self.model, messages=messages, tools=openai_tools, max_tokens=4096)
            msg = response.choices[0].message
            if msg.content:
                yield {"type": "text", "content": msg.content}
            if not msg.tool_calls:
                yield {"type": "complete", "content": "Analysis complete. Check the report for findings."}
                return
            messages.append({"role": "assistant", "content": msg.content,
                             "tool_calls": [{"id": tc.id, "type": "function",
                                             "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                                            for tc in msg.tool_calls]})
            for tc in msg.tool_calls:
                try:
                    tool_input = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    tool_input = {}
                sig = self._tool_sig(tc.function.name, tool_input)
                # dedup: an identical earlier scanner call is skipped (loop guard). The
                # investigative primitives are EXEMPT — the same request legitimately runs
                # again across a state change (before/after auth, mutation, role swap), so
                # deduping them would break stateful retesting.
                _repeatable = ("generate_playbook", "store_finding", "http_read", "http_request",
                               "http_diff", "confirm_idor", "enumerate_ids", "acquire_session",
                               "browser_navigate", "test_numeric_abuse")
                if sig in called and tc.function.name not in _repeatable:
                    yield {"type": "info", "content": f"Skipped duplicate {tc.function.name} (loop guard)."}
                    messages.append({"role": "tool", "tool_call_id": tc.id,
                                     "content": json.dumps({"success": True,
                                     "note": "deduplicated: identical call already executed this run"})})
                    continue
                called.add(sig)
                content = "{}"
                async for ev in self._run_tool(tc.function.name, tool_input, session_id):
                    if "_content" in ev:
                        content = ev["_content"]
                    else:
                        yield ev
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": content})
            # no-progress guard. PROGRESS IS MORE THAN NEW URLS: a real investigation makes
            # progress by confirming findings, acquiring sessions/capabilities, or changing
            # state — not only by discovering surface. Count all of them, so the loop is not
            # killed mid-investigation just because it stopped finding new endpoints.
            cur = (self._surface_size()
                   + len(getattr(self, "_stored_fps", ()) or ())          # findings confirmed/stored
                   + len(getattr(self.tools, "_sessions", {}) or {})       # identities acquired
                   + int(getattr(self.tools, "_login_attempts", 0) or 0))  # auth/state actions taken
            stall = stall + 1 if cur <= last else 0
            last = cur
            if stall >= 4:
                async for ev in self._react_finish(session_id, "no further progress (surface, findings, or sessions)"):
                    yield ev
                return

    # ── Anthropic ────────────────────────────────────────────────
    async def _run_anthropic(self, objective: str, session_id: str):
        messages = [{"role": "user", "content": objective}]
        tool_defs = self.tools.get_claude_tools()
        called, stall, last = set(), 0, self._surface_size()

        while True:
            if self.stop_event.is_set():
                yield {"type": "complete", "content": "Hunt stopped by user."}
                return
            if not self._budget_left():
                async for ev in self._react_finish(session_id, f"AI budget reached ({self.max_ai_calls} calls)"):
                    yield ev
                return
            self.ai_calls += 1
            yield self._budget_event()
            response = await self.client.messages.create(
                model=self.model, max_tokens=4096, system=self._system(),
                tools=tool_defs, messages=messages)
            for block in response.content:
                if getattr(block, "text", None):
                    yield {"type": "text", "content": block.text}
            tool_calls = [b for b in response.content if b.type == "tool_use"]
            if not tool_calls or response.stop_reason == "end_turn":
                yield {"type": "complete", "content": "Analysis complete. Check the report for findings."}
                return
            tool_results = []
            for call in tool_calls:
                sig = self._tool_sig(call.name, call.input)
                if sig in called and call.name not in ("generate_playbook", "store_finding"):
                    yield {"type": "info", "content": f"Skipped duplicate {call.name} (loop guard)."}
                    tool_results.append({"type": "tool_result", "tool_use_id": call.id,
                                         "content": json.dumps({"success": True,
                                         "note": "deduplicated: identical call already executed this run"})})
                    continue
                called.add(sig)
                content = "{}"
                async for ev in self._run_tool(call.name, call.input, session_id):
                    if "_content" in ev:
                        content = ev["_content"]
                    else:
                        yield ev
                tool_results.append({"type": "tool_result", "tool_use_id": call.id, "content": content})
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})
            cur = self._surface_size()
            stall = stall + 1 if cur <= last else 0
            last = cur
            if stall >= 3:
                async for ev in self._react_finish(session_id, "no new surface discovered"):
                    yield ev
                return
