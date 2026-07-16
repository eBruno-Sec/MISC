"""
Execution profile (run_config) — the backbone for tool toggles, Fast/Slow,
pre-authorization, the iterative recon loop, AI RedTeam mode, and authenticated
scanning (session passthrough).

Every field defaults to today's behavior, so an empty/absent config is a no-op:
all tools on, fast, pre-authorized, no loop, no RedTeam, unauthenticated.
"""
import shlex
from typing import Any

TOOLS = ["subfinder", "amass", "httpx", "nmap", "ffuf", "nuclei"]
AUTH_TYPES = ("none", "cookie", "bearer", "header")


def _norm_auth(raw: Any) -> dict[str, Any]:
    a = raw if isinstance(raw, dict) else {}
    atype = str(a.get("type", "none")).lower().strip()
    if atype not in AUTH_TYPES:
        atype = "none"
    headers = [str(h).strip() for h in (a.get("headers") or []) if str(h).strip() and ":" in str(h)]
    return {
        "type": atype,
        "cookie": str(a.get("cookie", "") or "").strip(),
        "bearer": str(a.get("bearer", "") or "").strip(),
        "headers": headers[:10],
    }


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
        "auth": _norm_auth(raw.get("auth")),
    }


def auth_headers(config: dict) -> list[str]:
    """Return the auth material as a list of 'Name: Value' header strings
    (empty when unauthenticated). Session passthrough — the operator supplies a
    cookie / bearer / custom headers they already obtained by logging in."""
    a = (config or {}).get("auth") or {}
    t = a.get("type", "none")
    out: list[str] = []
    if t == "cookie" and a.get("cookie"):
        out.append("Cookie: " + a["cookie"])
    elif t == "bearer" and a.get("bearer"):
        tok = a["bearer"]
        out.append("Authorization: " + (tok if tok.lower().startswith("bearer ") else "Bearer " + tok))
    elif t == "header":
        out.extend(h for h in (a.get("headers") or []) if ":" in h)
    return out


def is_authenticated(config: dict) -> bool:
    return bool(auth_headers(config))


def tool_enabled(config: dict, tool: str) -> bool:
    return bool((config.get("tools") or {}).get(tool, True))


# ── Fast/Slow → per-tool flags ──────────────────────────────────────────────
# Slow adds strict rate-limiting, delays, and jitter to protect production
# systems and avoid tripping WAFs. Fast is aggressive/multi-threaded for labs.
def speed_profile(config: dict) -> dict:
    slow = config.get("speed") == "slow"
    if slow:
        prof = {
            "slow": True,
            "nmap_timing": "-T2 --scan-delay 250ms --max-rate 60",
            "ffuf_extra": "-rate 25 -p 0.1",          # 25 req/s + 0.1s jitter
            "nuclei_extra": "-rl 30 -c 10",           # rate-limit 30/s, 10 concurrent
            "httpx_extra": "-rl 20",                  # 20 req/s
            "threads": 5,
        }
    else:
        prof = {
            "slow": False,
            "nmap_timing": "-T4",
            "ffuf_extra": "",
            "nuclei_extra": "",
            "httpx_extra": "",
            "threads": 10,
        }

    # Authenticated scanning: attach the operator's session to every HTTP tool
    # (httpx / ffuf / nuclei) so active enumeration reaches post-login surface.
    ah = auth_headers(config)
    if ah:
        flags = " ".join(f"-H {shlex.quote(h)}" for h in ah)
        for k in ("httpx_extra", "ffuf_extra", "nuclei_extra"):
            prof[k] = (prof[k] + " " + flags).strip()
    return prof
