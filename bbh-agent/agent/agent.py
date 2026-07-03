import asyncio
import json
import os
from typing import AsyncGenerator

from scope import ScopeEngine
from tools import ToolRegistry, TOOL_PERMISSIONS, PermissionLevel

AI_PROVIDER = os.getenv("AI_PROVIDER", "openrouter").lower()
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct:free")

SYSTEM_PROMPT = """You are a professional bug bounty hunter operating exclusively within provided scope.

CURRENT PHASE: Tier 1 — HackerOne/Bugcrowd public programs.
PRIORITY VULN CLASSES: IDOR, broken access control, business logic flaws, API authorization, subdomain takeovers, exposed sensitive endpoints.

HARD RULES:
1. Never test any asset not explicitly listed in scope. Scope block = stop, do not retry.
2. Passive recon before any active scanning. Enumeration before fingerprinting. Fingerprinting before nuclei.
3. Start nuclei with safe tags only (tech, misconfig, exposed-panels, takeovers). Escalate to cve tags only on targets with confirmed vulnerable software versions.
4. Never brute-force credentials.
5. Call store_finding only when: evidence is real, PoC is reproducible, impact is clearly articulated, and you have exact reproduction steps a triage reviewer can follow.
6. Do not store theoretical or speculative findings.

HUNT METHODOLOGY (follow this order):
1. Subdomain enumeration: run_subfinder + run_crtsh on every in-scope root domain
2. Live host probe: run_httpx on all discovered subdomains
3. Tech fingerprint interesting targets: run_whatweb on hosts with interesting titles or non-standard status codes
4. Surface vuln scan: run_nuclei with tags=tech,misconfig,exposed-panels,takeovers on all live hosts
5. Port scan hosts with unusual service fingerprints: run_nmap
6. Directory/endpoint discovery on API hosts, admin panels, or dev/staging subdomains: run_ffuf
7. CVE scan on hosts where you confirmed specific software versions: run_nuclei with tags=cve
8. Correlate findings. Store every confirmed reportable vulnerability.

HIGH-VALUE SIGNALS:
- Subdomains pointing to unclaimed cloud resources (AWS S3, GitHub Pages, Heroku, Fastly)
- Admin panels with default or no credentials
- API endpoints returning PII or internal data without authorization
- Software versions with public CVEs
- Exposed .git, .env, backup, or config files
- Dev/staging subdomains with weaker auth
- Mismatched CORS on authenticated API endpoints"""


class BBHAgent:
    def __init__(self, scope: ScopeEngine, tools: ToolRegistry, stop_event: asyncio.Event):
        self.scope = scope
        self.tools = tools
        self.stop_event = stop_event
        self.findings: list[dict] = []

        if AI_PROVIDER == "openrouter":
            from openai import AsyncOpenAI
            self.client = AsyncOpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=os.environ["OPENROUTER_API_KEY"],
            )
        else:
            import anthropic
            self.client = anthropic.AsyncAnthropic()

    async def run(self, objective: str, session_id: str) -> AsyncGenerator[dict, None]:
        if AI_PROVIDER == "openrouter":
            async for event in self._run_openrouter(objective, session_id):
                yield event
        else:
            async for event in self._run_anthropic(objective, session_id):
                yield event

    # ── OpenRouter / OpenAI ────────────────────────────────────────────────────

    async def _run_openrouter(self, objective: str, session_id: str) -> AsyncGenerator[dict, None]:
        full_system = SYSTEM_PROMPT + f"\n\nSCOPE:\n{json.dumps(self.scope.to_dict(), indent=2)}"
        messages: list[dict] = [
            {"role": "system", "content": full_system},
            {"role": "user", "content": objective},
        ]
        openai_tools = self.tools.get_openai_tools()
        max_iter = 35

        for i in range(max_iter):
            if self.stop_event.is_set():
                yield {"type": "complete", "content": "Hunt stopped by user."}
                return

            response = await self.client.chat.completions.create(
                model=OPENROUTER_MODEL,
                messages=messages,
                tools=openai_tools,
                max_tokens=4096,
            )

            msg = response.choices[0].message

            if msg.content:
                yield {"type": "text", "content": msg.content}

            if not msg.tool_calls:
                yield {"type": "complete", "content": "Analysis complete. Check the report for findings."}
                return

            # Append assistant turn (dict form, not SDK object)
            messages.append({
                "role": "assistant",
                "content": msg.content,
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                    }
                    for tc in msg.tool_calls
                ],
            })

            for tc in msg.tool_calls:
                tool_name = tc.function.name
                try:
                    tool_input = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    tool_input = {}

                perm = TOOL_PERMISSIONS.get(tool_name, PermissionLevel.ACTIVE)
                yield {"type": "tool_call", "tool": tool_name, "input": tool_input, "permission": perm.value}

                result = await self.tools.execute(tool_name, tool_input, session_id)

                if result.error:
                    event_type = "scope_block" if "SCOPE BLOCK" in result.error else "tool_error"
                    yield {"type": event_type, "tool": tool_name, "error": result.error}
                else:
                    yield {"type": "tool_result", "tool": tool_name, "output": result.output, "count": len(result.findings)}

                if tool_name == "store_finding" and not result.error:
                    self.findings.append(tool_input)
                    yield {"type": "finding", "finding": tool_input}

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json.dumps({
                        "success": result.success,
                        "output": result.output,
                        "findings": result.findings[:25],
                        "error": result.error,
                    })[:3500],
                })

        yield {"type": "complete", "content": f"Reached max iterations ({max_iter}). Generating report."}

    # ── Anthropic ──────────────────────────────────────────────────────────────

    async def _run_anthropic(self, objective: str, session_id: str) -> AsyncGenerator[dict, None]:
        import anthropic as _anthropic
        messages: list[dict] = [{"role": "user", "content": objective}]
        tool_defs = self.tools.get_claude_tools()
        max_iter = 35

        for i in range(max_iter):
            if self.stop_event.is_set():
                yield {"type": "complete", "content": "Hunt stopped by user."}
                return

            response = await self.client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=4096,
                system=SYSTEM_PROMPT + f"\n\nSCOPE:\n{json.dumps(self.scope.to_dict(), indent=2)}",
                tools=tool_defs,
                messages=messages,
            )

            for block in response.content:
                if hasattr(block, "text") and block.text:
                    yield {"type": "text", "content": block.text}

            tool_calls = [b for b in response.content if b.type == "tool_use"]

            if not tool_calls or response.stop_reason == "end_turn":
                yield {"type": "complete", "content": "Analysis complete. Check the report for findings."}
                return

            tool_results = []
            for call in tool_calls:
                perm = TOOL_PERMISSIONS.get(call.name, PermissionLevel.ACTIVE)
                yield {"type": "tool_call", "tool": call.name, "input": call.input, "permission": perm.value}

                result = await self.tools.execute(call.name, call.input, session_id)

                if result.error:
                    event_type = "scope_block" if "SCOPE BLOCK" in result.error else "tool_error"
                    yield {"type": event_type, "tool": call.name, "error": result.error}
                else:
                    yield {"type": "tool_result", "tool": call.name, "output": result.output, "count": len(result.findings)}

                if call.name == "store_finding" and not result.error:
                    self.findings.append(call.input)
                    yield {"type": "finding", "finding": call.input}

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": call.id,
                    "content": json.dumps({
                        "success": result.success,
                        "output": result.output,
                        "findings": result.findings[:25],
                        "error": result.error,
                    })[:3500],
                })

            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})

        yield {"type": "complete", "content": f"Reached max iterations ({max_iter}). Generating report."}
