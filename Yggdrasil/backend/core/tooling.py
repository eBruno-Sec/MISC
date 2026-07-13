"""
Scanner health diagnostics.

Confirms the security tools Yggdrasil shells out to are actually present (and
which version) at backend startup and at the start of every mission, so a
silently-missing binary shows up as a loud warning instead of a quietly empty
"0 findings" section. Self-contained (drives subprocesses directly, not via
BaseAgent.run_command) so it can run both before any agent/session exists
(app startup) and inside a mission (as a Zeus-owned pre-flight check).
"""
import asyncio
import os
import re

import httpx

# name -> (version command, regex to pull the version string out of stdout+stderr)
CLI_TOOLS = {
    "nmap":      (["nmap", "--version"],    r"Nmap version (\S+)"),
    "nuclei":    (["nuclei", "-version"],   r"[Nn]uclei\s+(?:Engine\s+)?[Vv]ersion[:\s]+(\S+)"),
    "ffuf":      (["ffuf", "-V"],           r"ffuf version:\s*(\S+)"),
    "subfinder": (["subfinder", "-version"], r"[Ss]ubfinder\s+(?:Engine\s+)?[Vv]ersion[:\s]+(\S+)"),
    "katana":    (["katana", "-version"],   r"[Kk]atana\s+(?:Engine\s+)?[Vv]ersion[:\s]+(\S+)"),
    "dalfox":    (["dalfox", "version"],    r"(\d+\.\d+\.\d+)"),
    "sqlmap":    (["sqlmap", "--version"],  r"(\d+(?:\.\d+){1,2}(?:#\S+)?)"),
}


async def _run(cmd: list, timeout: int = 15) -> tuple:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            env=os.environ.copy(),
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode
    except asyncio.TimeoutError:
        return "", "timeout", -1
    except FileNotFoundError:
        return "", f"Tool not found: {cmd[0]}", 127
    except Exception as e:
        return "", str(e), -1


async def check_cli_tools(tools: dict = None) -> dict:
    """Return {tool_name: {"available": bool, "version": str|None}}. `tools`
    defaults to CLI_TOOLS; overridable so tests don't depend on which binaries
    happen to be installed on the machine running them."""
    tools = tools if tools is not None else CLI_TOOLS
    results = {}
    for name, (cmd, pattern) in tools.items():
        stdout, stderr, rc = await _run(cmd)
        if rc == 127:
            results[name] = {"available": False, "version": None}
            continue
        blob = (stdout or "") + (stderr or "")
        m = re.search(pattern, blob)
        results[name] = {"available": True, "version": (m.group(1) if m else "unknown")}
    return results


async def check_zap(zap_url: str = None, api_key: str = None) -> dict:
    """Probe the OWASP ZAP daemon — a separate service, not a CLI binary."""
    zap_url = (zap_url or os.getenv("ZAP_URL", "http://zap:8090")).rstrip("/")
    api_key = api_key if api_key is not None else os.getenv("ZAP_API_KEY", "")
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            params = {"apikey": api_key} if api_key else {}
            r = await c.get(f"{zap_url}/JSON/core/view/version/", params=params)
            if r.status_code == 200:
                return {"available": True, "version": (r.json() or {}).get("version", "unknown")}
    except Exception:
        pass
    return {"available": False, "version": None}


async def check_all_tools() -> dict:
    """Full scanner health report: every CLI tool Yggdrasil shells out to, plus
    the ZAP daemon."""
    results = await check_cli_tools()
    results["zap"] = await check_zap()
    return results


def format_warnings(results: dict) -> list:
    """One human-readable warning line per unavailable tool. Empty list when
    everything's present."""
    return [
        f"{name} is not available — checks that depend on it will be skipped "
        "or reported as tool_unavailable, not tested."
        for name, info in sorted(results.items())
        if not (info or {}).get("available")
    ]
