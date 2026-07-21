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
    "run_graphql": "enum", "run_jwt": "enum", "run_xss": "probe", "run_js_review": "enum",
    "run_csrf": "enum", "run_oauth": "enum",
    "run_nmap": "scan", "run_nuclei": "scan", "run_zap": "scan",
    "run_content_discovery": "probe", "run_ffuf": "probe", "run_web_probes": "probe",
    "run_injection_probes": "probe", "run_bfla": "probe", "run_race": "probe",
    "run_ssrf": "probe", "run_deserialization": "probe", "run_exposure": "probe",
    "run_xxe": "probe", "run_sqli": "probe", "run_cmdi": "probe",
    "run_dalfox": "probe", "run_sqlmap": "probe",
    "generate_playbook": "guidance", "store_finding": "report",
}
PHASES = ["recon", "enum", "scan", "probe", "guidance", "report"]

# Tools whose confirmed, finding-shaped results should be auto-stored when no model
# is driving (deterministic / low_ai). These native probes only emit CONFIRMED
# vulns; without auto-store a deterministic scan would confirm and then drop them.
_AUTO_STORE_TOOLS = {
    "run_sqli", "run_cmdi", "run_ssrf", "run_xss", "run_xxe", "run_deserialization",
    "run_injection_probes", "run_web_probes", "run_exposure", "run_bfla", "run_race",
    "run_nuclei", "run_zap", "check_takeover", "run_oauth", "run_jwt", "run_csrf",
    "run_dalfox", "run_sqlmap", "run_graphql", "run_js_review",
    "run_content_discovery", "run_ffuf",
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
6. Targeted probing (INTRUSIVE): run_content_discovery for sensitive paths (body-validated), run_exposure for exposed .git/.env/backup/credential files (signature-confirmed, source-recoverable escalation), run_web_probes for traversal/IDOR, run_injection_probes for CORS/open-redirect/host-header/SSTI on parameterized URLs, run_bfla for broken function-level authorization (write methods / admin paths with a low-priv token) + side-channel BOLA, run_race on single-use actions (coupon/transfer/vote) for race conditions, run_ssrf on URL-taking parameters (fetch/redirect/proxy/image/webhook) for server-side request forgery (cloud-metadata reflection + internal port oracle), run_deserialization on requests carrying serialized blobs in params/cookies (PHP/Java/pickle/.NET/Ruby — corrupt-and-watch-for-parser-error confirmation), run_xxe on endpoints that accept XML (in-band file read + OOB blind confirmation via the native collaborator), run_sqli on parameterized URLs (error/boolean/time oracles, baseline-confirmed, native — no binary needed), run_cmdi on params that feed OS commands (ping/host/filename/exec — computed-output + time + OOB oracles), run_xss on reflected parameters and pages with client-side sinks (browser-confirmed, catches DOM XSS).
7. Correlate. Store every confirmed reportable vulnerability with store_finding.

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
                 recon_cycles: int = 1, strategy: str = "low_ai", max_ai_calls: int = None):
        self.scope = scope
        self.tools = tools
        self.stop_event = stop_event
        self.tools.stop_event = stop_event   # let long ZAP polls honor a user stop
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
        self._stored_fps: set = set()   # fingerprints already stored (auto-store dedup)
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
               "prompt": f"Authorize INTRUSIVE probing for this engagement? First request: {tool_name}"}
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
               "resolution": self.intrusive_state}

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
            yield {"type": "tool_result", "tool": tool_name, "output": result.output,
                   "count": len(result.findings)}

        if tool_name == "store_finding" and not result.error:
            fin = result.findings[0] if result.findings else dict(tool_input)
            self.findings.append(fin)
            yield {"type": "finding", "finding": fin}

        # Auto-store confirmed findings from the native confirmatory probes when NO
        # model is driving (deterministic / low_ai). Without this the probes confirm
        # e.g. a SQLi and it is silently dropped — a deterministic scan would report
        # zero findings. In agentic mode the model stores them, so we don't here
        # (avoids duplicates). Deduped by fingerprint.
        if (not result.error and self.strategy in ("deterministic", "low_ai")
                and tool_name in _AUTO_STORE_TOOLS):
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
            gen = self._run_openrouter(objective, session_id) if self.provider == "openrouter" \
                else self._run_anthropic(objective, session_id)
            async for event in gen:
                yield event
        # advisory triage pass (METIS) over persisted findings
        async for ev in self._triage():
            yield ev

    # ── deterministic executor (planner-driven, no AI) ───────────
    async def _execute_plan(self, session_id: str):
        """Drive planner.next_batch through the SAME scoped, HITL-gated tool
        pipeline. recon_cycles are honored: each cycle folds newly discovered
        subdomains into the root set so recon + discovery deepen, and re-runs the
        playbook over everything found. Dedup + a hard step cap guarantee it ends."""
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
            roots = sorted(set(base_roots) | set(self.tools.recon.get("subdomains", [])))
            while steps < MAX_STEPS:
                if self.stop_event.is_set():
                    self._plan_steps = steps
                    return
                state = {"mode": self.mode, "roots": roots, "done": done,
                         "recon": self.tools.recon, "urls": self.tools.urls}
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
        return (SYSTEM_PROMPT + MODE_NOTES.get(self.mode, "") + self._recon_note()
                + (self.memory_note or "")
                + f"\n\nSCOPE:\n{json.dumps(self.scope.to_dict(), indent=2)}")

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
                # dedup: an identical earlier call is skipped (loop guard), except
                # generate_playbook/store_finding which are legitimately repeatable.
                if sig in called and tc.function.name not in ("generate_playbook", "store_finding"):
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
            # no-progress guard: stop looping if surface stops growing
            cur = self._surface_size()
            stall = stall + 1 if cur <= last else 0
            last = cur
            if stall >= 3:
                async for ev in self._react_finish(session_id, "no new surface discovered"):
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
