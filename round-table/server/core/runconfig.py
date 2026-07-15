"""
Execution profile (run_config) — the backbone for tool toggles, Fast/Slow,
pre-authorization, the iterative recon loop, and AI RedTeam mode.

Every field defaults to today's behavior, so an empty/absent config is a no-op:
all tools on, fast, pre-authorized, no loop, no RedTeam.
"""
from typing import Any

TOOLS = ["subfinder", "amass", "httpx", "nmap", "ffuf", "nuclei"]


def normalize(raw: Any) -> dict[str, Any]:
    raw = raw if isinstance(raw, dict) else {}
    tools_in = raw.get("tools") if isinstance(raw.get("tools"), dict) else {}
    tools = {t: bool(tools_in.get(t, True)) for t in TOOLS}

    speed = str(raw.get("speed", "fast")).lower()
    if speed not in ("fast", "slow"):
        speed = "fast"

    try:
        max_loops = int(raw.get("max_loops", 3) or 3)
    except (TypeError, ValueError):
        max_loops = 3
    max_loops = max(1, min(3, max_loops))

    return {
        "tools": tools,
        "speed": speed,
        "pre_authorized": bool(raw.get("pre_authorized", True)),
        "recon_loop": bool(raw.get("recon_loop", False)),
        "max_loops": max_loops,
        "ai_redteam": bool(raw.get("ai_redteam", False)),
        "ai_endpoint": str(raw.get("ai_endpoint", "") or "").strip(),
    }


def tool_enabled(config: dict, tool: str) -> bool:
    return bool((config.get("tools") or {}).get(tool, True))


# ── Fast/Slow → per-tool flags ──────────────────────────────────────────────
# Slow adds strict rate-limiting, delays, and jitter to protect production
# systems and avoid tripping WAFs. Fast is aggressive/multi-threaded for labs.
def speed_profile(config: dict) -> dict:
    slow = config.get("speed") == "slow"
    if slow:
        return {
            "slow": True,
            "nmap_timing": "-T2 --scan-delay 250ms --max-rate 60",
            "ffuf_extra": "-rate 25 -p 0.1",          # 25 req/s + 0.1s jitter
            "nuclei_extra": "-rl 30 -c 10",           # rate-limit 30/s, 10 concurrent
            "httpx_extra": "-rl 20",                  # 20 req/s
            "threads": 5,
        }
    return {
        "slow": False,
        "nmap_timing": "-T4",
        "ffuf_extra": "",
        "nuclei_extra": "",
        "httpx_extra": "",
        "threads": 10,
    }
