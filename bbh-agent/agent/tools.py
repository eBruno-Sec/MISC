import asyncio
import json
import os
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import aiohttp

from scope import ScopeEngine, PermissionLevel


@dataclass
class ToolResult:
    tool: str
    target: str
    success: bool
    output: str
    findings: list = field(default_factory=list)
    error: Optional[str] = None


TOOL_PERMISSIONS = {
    "run_subfinder": PermissionLevel.PASSIVE,
    "run_crtsh": PermissionLevel.PASSIVE,
    "run_httpx": PermissionLevel.ACTIVE,
    "run_whatweb": PermissionLevel.ACTIVE,
    "run_nmap": PermissionLevel.ACTIVE,
    "run_nuclei": PermissionLevel.ACTIVE,
    "run_ffuf": PermissionLevel.INTRUSIVE,
    "store_finding": PermissionLevel.PASSIVE,
}

# Canonical tool definitions (Anthropic format — converted to OpenAI format on demand)
CLAUDE_TOOLS = [
    {
        "name": "run_subfinder",
        "description": "PASSIVE: Enumerate subdomains via OSINT sources (crt.sh, VirusTotal, etc.). Zero direct contact with target.",
        "input_schema": {
            "type": "object",
            "properties": {"domain": {"type": "string", "description": "Root domain to enumerate subdomains for"}},
            "required": ["domain"],
        },
    },
    {
        "name": "run_crtsh",
        "description": "PASSIVE: Certificate transparency log enumeration. Zero direct contact with target.",
        "input_schema": {
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
    },
    {
        "name": "run_httpx",
        "description": "ACTIVE: Probe a list of hosts for live HTTP/HTTPS, detect status codes, titles, and tech stack.",
        "input_schema": {
            "type": "object",
            "properties": {
                "targets": {"type": "array", "items": {"type": "string"}, "description": "List of hosts or subdomains"},
                "ports": {"type": "string", "default": "80,443,8080,8443,3000,8000,9000"},
            },
            "required": ["targets"],
        },
    },
    {
        "name": "run_whatweb",
        "description": "ACTIVE: Web technology fingerprinting. Identify CMS, frameworks, and server versions.",
        "input_schema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "URL or domain"}},
            "required": ["target"],
        },
    },
    {
        "name": "run_nmap",
        "description": "ACTIVE: Port scan and service/version detection.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "flags": {"type": "string", "default": "-sT -sV --top-ports 1000 -T3"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "run_nuclei",
        "description": (
            "ACTIVE/INTRUSIVE: Template-based vulnerability scanner. "
            "Safe tags: tech, misconfig, exposed-panels, takeovers. "
            "Intrusive tags: cve, sqli, xss, rce. "
            "Start with safe tags, escalate to cve only on confirmed targets."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "tags": {"type": "string", "description": "Comma-separated nuclei tags"},
                "severity": {"type": "string", "default": "low,medium,high,critical"},
            },
            "required": ["target", "tags"],
        },
    },
    {
        "name": "run_ffuf",
        "description": "INTRUSIVE: Directory and endpoint fuzzing. Include FUZZ in the URL.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL with FUZZ placeholder e.g. https://target.com/api/FUZZ"},
                "wordlist": {"type": "string", "default": "/usr/share/wordlists/dirb/common.txt"},
                "filter_codes": {"type": "string", "default": "404,403"},
                "method": {"type": "string", "default": "GET"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "store_finding",
        "description": (
            "Store a confirmed, reproducible vulnerability finding for the final report. "
            "Only call when you have real evidence and exact reproduction steps. "
            "Do NOT call for theoretical issues."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "informational"]},
                "target": {"type": "string"},
                "description": {"type": "string"},
                "reproduction_steps": {"type": "array", "items": {"type": "string"}},
                "impact": {"type": "string"},
                "cvss_score": {"type": "number"},
                "cvss_vector": {"type": "string"},
                "cwe": {"type": "string"},
                "evidence": {"type": "string"},
            },
            "required": ["title", "severity", "target", "description", "reproduction_steps", "impact"],
        },
    },
]


class ToolRegistry:
    def __init__(self, scope: ScopeEngine):
        self.scope = scope

    def get_claude_tools(self) -> list[dict]:
        """Anthropic tool use format."""
        return CLAUDE_TOOLS

    def get_openai_tools(self) -> list[dict]:
        """OpenAI / OpenRouter function calling format."""
        return [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["input_schema"],
                },
            }
            for t in CLAUDE_TOOLS
        ]

    async def execute(self, tool_name: str, tool_input: dict, session_id: str) -> ToolResult:
        if tool_name == "store_finding":
            return ToolResult("store_finding", tool_input.get("target", ""), True, "Finding stored", [tool_input])

        single = tool_input.get("domain") or tool_input.get("target") or tool_input.get("url")
        if single:
            check = single.split("FUZZ")[0] if "FUZZ" in single else single
            allowed, reason = self.scope.validate(check)
            if not allowed:
                return ToolResult(tool_name, single, False, "", [], f"SCOPE BLOCK: {reason}")

        if "targets" in tool_input:
            filtered = [t for t in tool_input["targets"] if self.scope.validate(t)[0]]
            if not filtered:
                return ToolResult(tool_name, "", False, "", [], "SCOPE BLOCK: No in-scope targets in list")
            tool_input = {**tool_input, "targets": filtered}

        method = getattr(self, f"_{tool_name}", None)
        if not method:
            return ToolResult(tool_name, "", False, "", [], f"Unknown tool: {tool_name}")

        return await method(tool_input)

    async def _cmd(self, cmd: list[str], timeout: int = 180) -> tuple[str, str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return out.decode(errors="replace"), err.decode(errors="replace")
        except asyncio.TimeoutError:
            return "", "Command timed out"
        except Exception as e:
            return "", str(e)

    async def _run_subfinder(self, inp: dict) -> ToolResult:
        domain = inp["domain"]
        out, _ = await self._cmd(["subfinder", "-d", domain, "-silent", "-json"], timeout=120)
        subs = []
        for line in out.strip().split("\n"):
            if not line.strip():
                continue
            try:
                sub = json.loads(line).get("host", "")
            except Exception:
                sub = line.strip()
            if sub and self.scope.validate(sub)[0]:
                subs.append({"subdomain": sub})
        return ToolResult("subfinder", domain, True, f"{len(subs)} subdomains found", subs)

    async def _run_crtsh(self, inp: dict) -> ToolResult:
        domain = inp["domain"]
        subs = []
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        seen: set[str] = set()
                        for entry in data:
                            for name in entry.get("name_value", "").split("\n"):
                                name = name.strip().lstrip("*.")
                                if name and name not in seen and self.scope.validate(name)[0]:
                                    seen.add(name)
                                    subs.append({"subdomain": name, "source": "crt.sh"})
        except Exception as e:
            return ToolResult("crtsh", domain, False, "", [], str(e))
        return ToolResult("crtsh", domain, True, f"{len(subs)} CT log entries", subs)

    async def _run_httpx(self, inp: dict) -> ToolResult:
        targets = inp["targets"]
        ports = inp.get("ports", "80,443,8080,8443,3000,8000,9000")
        tmp = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                for t in targets[:400]:
                    f.write(t + "\n")
                tmp = f.name
            out, _ = await self._cmd(
                ["httpx", "-l", tmp, "-ports", ports, "-status-code", "-title", "-tech-detect", "-silent", "-json"],
                timeout=300,
            )
        finally:
            if tmp and os.path.exists(tmp):
                os.unlink(tmp)
        hosts = []
        for line in out.strip().split("\n"):
            if not line.strip():
                continue
            try:
                d = json.loads(line)
                hosts.append({
                    "url": d.get("url"),
                    "status": d.get("status-code"),
                    "title": d.get("title"),
                    "tech": d.get("technologies", []),
                    "server": d.get("webserver"),
                })
            except Exception:
                pass
        return ToolResult("httpx", f"{len(targets)} probed", True, f"{len(hosts)} live hosts", hosts)

    async def _run_whatweb(self, inp: dict) -> ToolResult:
        target = inp["target"]
        out, _ = await self._cmd(["whatweb", "--log-json=/dev/stdout", "-q", target], timeout=60)
        findings = []
        for line in out.strip().split("\n"):
            if not line.strip():
                continue
            try:
                findings.append(json.loads(line))
            except Exception:
                pass
        return ToolResult("whatweb", target, True, "Fingerprint complete", findings)

    async def _run_nmap(self, inp: dict) -> ToolResult:
        target = inp["target"]
        flags = inp.get("flags", "-sT -sV --top-ports 1000 -T3")
        out, _ = await self._cmd(["nmap"] + flags.split() + ["-oX", "-", target], timeout=360)
        ports = []
        try:
            root = ET.fromstring(out)
            for port in root.findall(".//port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    svc = port.find("service")
                    ports.append({
                        "port": port.get("portid"),
                        "proto": port.get("protocol"),
                        "service": svc.get("name", "") if svc is not None else "",
                        "version": f"{svc.get('product', '')} {svc.get('version', '')}".strip() if svc is not None else "",
                    })
        except Exception:
            pass
        return ToolResult("nmap", target, True, f"{len(ports)} open ports", ports)

    async def _run_nuclei(self, inp: dict) -> ToolResult:
        target = inp["target"]
        tags = inp.get("tags", "tech,misconfig,exposed-panels")
        severity = inp.get("severity", "low,medium,high,critical")
        out, _ = await self._cmd(
            ["nuclei", "-u", target, "-tags", tags, "-severity", severity, "-silent", "-json", "-no-interactsh"],
            timeout=360,
        )
        findings = []
        for line in out.strip().split("\n"):
            if not line.strip():
                continue
            try:
                d = json.loads(line)
                findings.append({
                    "template": d.get("template-id"),
                    "name": d.get("info", {}).get("name"),
                    "severity": d.get("info", {}).get("severity"),
                    "url": d.get("matched-at"),
                    "description": d.get("info", {}).get("description"),
                    "cvss": d.get("info", {}).get("classification", {}).get("cvss-score"),
                })
            except Exception:
                pass
        return ToolResult("nuclei", target, True, f"{len(findings)} findings", findings)

    async def _run_ffuf(self, inp: dict) -> ToolResult:
        url = inp["url"]
        wl = inp.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        fc = inp.get("filter_codes", "404,403")
        method = inp.get("method", "GET")
        out, _ = await self._cmd(
            ["ffuf", "-u", url, "-w", wl, "-fc", fc, "-X", method, "-json", "-s", "-t", "50"],
            timeout=240,
        )
        findings = []
        try:
            data = json.loads(out)
            for r in data.get("results", []):
                findings.append({"url": r.get("url"), "status": r.get("status"), "length": r.get("length")})
        except Exception:
            pass
        return ToolResult("ffuf", url, True, f"{len(findings)} paths found", findings)
