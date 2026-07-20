import asyncio
import json
import os
import uuid
from typing import AsyncGenerator

import db
import triage as triage_mod
from scope import ScopeEngine, PermissionLevel
from tools import ToolRegistry, TOOL_PERMISSIONS

AI_PROVIDER = os.getenv("AI_PROVIDER", "openrouter").lower()
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct:free")
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
APPROVAL_TIMEOUT = int(os.getenv("BBH_APPROVAL_TIMEOUT", "0"))  # 0 = wait forever

# tool -> assessment phase (drives the phase status bar in the UI)
PHASE_OF = {
    "run_subfinder": "recon", "run_crtsh": "recon", "run_wayback": "recon", "run_dns": "recon",
    "run_asn": "recon",
    "run_httpx": "enum", "http_probe": "enum", "run_whatweb": "enum", "run_fingerprint": "enum",
    "run_katana": "enum", "fetch_openapi": "enum", "check_takeover": "enum",
    "run_graphql": "enum", "run_jwt": "enum", "run_xss": "probe", "run_js_review": "enum",
    "run_csrf": "enum",
    "run_nmap": "scan", "run_nuclei": "scan", "run_zap": "scan",
    "run_content_discovery": "probe", "run_ffuf": "probe", "run_web_probes": "probe",
    "run_injection_probes": "probe", "run_bfla": "probe", "run_race": "probe",
    "run_ssrf": "probe", "run_dalfox": "probe", "run_sqlmap": "probe",
    "generate_playbook": "guidance", "store_finding": "report",
}
PHASES = ["recon", "enum", "scan", "probe", "guidance", "report"]

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

RECOMMENDED METHODOLOGY:
1. Subdomain enumeration: run_subfinder + run_crtsh on every in-scope root domain. run_wayback to seed historical URLs. run_dns for SPF/DMARC/CAA/vendor intel. run_asn to map the org's IP range (scope expansion).
2. Live host probe: run_httpx on discovered subdomains. check_takeover on subdomains to catch dangling-CNAME hijacks.
3. Enrich: http_probe interesting hosts (captures evidence, reads security headers, seeds the surface). run_fingerprint to identify the tech stack (server/language/framework/CMS + versions). fetch_openapi on any /swagger or /openapi.json. run_graphql on any /graphql endpoint (introspection + batching abuse). run_jwt on any JWT/Bearer token you capture (alg:none, weak-secret crack, forged-admin). run_js_review on discovered .js bundles (hardcoded secrets, dangerous sinks, hidden endpoints).
4. Surface scan: run_nuclei with safe tags on live hosts. run_nmap on unusual fingerprints. If the ZAP daemon is available, run_zap for a full DAST pass on a primary in-scope web app (spider + AJAX spider + active scan, scope-fenced).
5. Plan: call generate_playbook to get a rule-based, per-surface test playbook (what/how/payloads/confidence/cURL). Use it to target the next step.
6. Targeted probing (INTRUSIVE): run_content_discovery for sensitive paths (body-validated), run_web_probes for traversal/IDOR, run_injection_probes for CORS/open-redirect/host-header/SSTI on parameterized URLs, run_bfla for broken function-level authorization (write methods / admin paths with a low-priv token) + side-channel BOLA, run_race on single-use actions (coupon/transfer/vote) for race conditions, run_ssrf on URL-taking parameters (fetch/redirect/proxy/image/webhook) for server-side request forgery (cloud-metadata reflection + internal port oracle), run_xss on reflected parameters and pages with client-side sinks (browser-confirmed, catches DOM XSS).
7. Correlate. Store every confirmed reportable vulnerability with store_finding.

HIGH-VALUE SIGNALS:
- Subdomains pointing to unclaimed cloud resources (S3, GitHub Pages, Heroku, Fastly)
- Admin panels with default or no credentials
- API endpoints returning PII or internal data without authorization
- Exposed .git/.env/backup/config files (only when the body confirms it)
- Dev/staging subdomains with weaker auth
- Mismatched CORS on authenticated API endpoints"""

MODE_NOTES = {
    "passive": "\n\nASSESSMENT MODE: PASSIVE. Only passive tools are permitted (subfinder, crtsh, wayback, generate_playbook). Active and intrusive tools are disabled. Produce a recon picture and a test playbook the operator can execute by hand.",
    "active": "\n\nASSESSMENT MODE: ACTIVE. Passive + active tools auto-run. Intrusive probing requires one operator approval.",
    "full": "\n\nASSESSMENT MODE: FULL. Passive + active auto-run; intrusive probing requires approval. Go deep: content discovery, web probes, and confirmation on every promising surface.",
}


class BBHAgent:
    def __init__(self, scope: ScopeEngine, tools: ToolRegistry, stop_event: asyncio.Event,
                 mode: str = "active", auto_approve: bool = False, mission_id: str = None):
        self.scope = scope
        self.tools = tools
        self.stop_event = stop_event
        self.tools.stop_event = stop_event   # let long ZAP polls honor a user stop
        self.mode = mode if mode in ("passive", "active", "full") else "active"
        self.auto_approve = auto_approve
        self.mission_id = mission_id
        self.findings: list = []
        self.current_phase = "init"

        # HITL gate state (one session-level intrusive authorization)
        self.intrusive_state = None  # None | "approved" | "denied"
        self.pending_approval: dict = None
        self._approval_event = asyncio.Event()
        self._approval_result = None

        if AI_PROVIDER == "openrouter":
            from openai import AsyncOpenAI
            self.client = AsyncOpenAI(base_url="https://openrouter.ai/api/v1",
                                      api_key=os.environ.get("OPENROUTER_API_KEY", "missing"))
        else:
            import anthropic
            self.client = anthropic.AsyncAnthropic()

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

        content = json.dumps({
            "success": result.success, "output": result.output,
            "findings": result.findings[:25], "error": result.error,
        })[:3500]
        yield {"_content": content}

    # ── entry ────────────────────────────────────────────────────
    async def run(self, objective: str, session_id: str) -> AsyncGenerator[dict, None]:
        yield {"type": "phase", "phase": "recon"}
        if AI_PROVIDER == "openrouter":
            gen = self._run_openrouter(objective, session_id)
        else:
            gen = self._run_anthropic(objective, session_id)
        async for event in gen:
            yield event
        # advisory triage pass (METIS) over persisted findings
        async for ev in self._triage():
            yield ev

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

    def _system(self) -> str:
        return (SYSTEM_PROMPT + MODE_NOTES.get(self.mode, "")
                + f"\n\nSCOPE:\n{json.dumps(self.scope.to_dict(), indent=2)}")

    # ── OpenRouter / OpenAI ──────────────────────────────────────
    async def _run_openrouter(self, objective: str, session_id: str):
        messages = [{"role": "system", "content": self._system()},
                    {"role": "user", "content": objective}]
        openai_tools = self.tools.get_openai_tools()
        max_iter = 40

        for _ in range(max_iter):
            if self.stop_event.is_set():
                yield {"type": "complete", "content": "Hunt stopped by user."}
                return
            response = await self.client.chat.completions.create(
                model=OPENROUTER_MODEL, messages=messages, tools=openai_tools, max_tokens=4096)
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
                content = "{}"
                async for ev in self._run_tool(tc.function.name, tool_input, session_id):
                    if "_content" in ev:
                        content = ev["_content"]
                    else:
                        yield ev
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": content})
        yield {"type": "complete", "content": f"Reached max iterations ({max_iter}). Generating report."}

    # ── Anthropic ────────────────────────────────────────────────
    async def _run_anthropic(self, objective: str, session_id: str):
        messages = [{"role": "user", "content": objective}]
        tool_defs = self.tools.get_claude_tools()
        max_iter = 40

        for _ in range(max_iter):
            if self.stop_event.is_set():
                yield {"type": "complete", "content": "Hunt stopped by user."}
                return
            response = await self.client.messages.create(
                model=ANTHROPIC_MODEL, max_tokens=4096, system=self._system(),
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
                content = "{}"
                async for ev in self._run_tool(call.name, call.input, session_id):
                    if "_content" in ev:
                        content = ev["_content"]
                    else:
                        yield ev
                tool_results.append({"type": "tool_result", "tool_use_id": call.id, "content": content})
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})
        yield {"type": "complete", "content": f"Reached max iterations ({max_iter}). Generating report."}
