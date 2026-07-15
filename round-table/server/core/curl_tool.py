"""
Advanced cURL console backend.

Composes a copy-paste `curl` command from a structured request and (optionally)
executes it server-side for manual verification. Execution is scope-guarded and
size/redirect-limited. This is a manual testing aid — the operator crafts the
request; Round Table never auto-fires payloads during a scan.
"""
import shlex
import time
from typing import Any, Optional

import httpx

from . import scope as scope_mod

MAX_BODY_PREVIEW = 200_000  # 200 KB response preview cap


def build_curl(method: str, url: str, headers: dict[str, str], body: Optional[str],
               insecure: bool = True, follow: bool = False) -> str:
    parts = ["curl", "-sS", "-i", "-X", method.upper()]
    if insecure:
        parts.append("-k")
    if follow:
        parts.append("-L")
    parts += ["--max-time", "20"]
    for k, v in (headers or {}).items():
        if not k:
            continue
        parts += ["-H", f"{k}: {v}"]
    if body:
        parts += ["--data-raw", body]
    parts.append(url)
    return " ".join(shlex.quote(p) for p in parts)


async def execute(
    method: str,
    url: str,
    headers: dict[str, str],
    body: Optional[str],
    scope: dict,
    follow_redirects: bool = False,
    insecure: bool = True,
    timeout: float = 20.0,
) -> dict[str, Any]:
    ok, reason = scope_mod.in_scope(url, scope or {})
    curl_cmd = build_curl(method, url, headers, body, insecure, follow_redirects)
    if not ok:
        return {
            "ok": False,
            "blocked": True,
            "reason": f"Out of scope: {reason}",
            "curl": curl_cmd,
        }

    started = time.time()
    try:
        async with httpx.AsyncClient(
            verify=not insecure,
            follow_redirects=follow_redirects,
            timeout=timeout,
        ) as client:
            resp = await client.request(
                method.upper(),
                url,
                headers={k: v for k, v in (headers or {}).items() if k},
                content=(body.encode() if body else None),
            )
            raw = resp.content[:MAX_BODY_PREVIEW]
            truncated = len(resp.content) > MAX_BODY_PREVIEW
            try:
                text = raw.decode(resp.encoding or "utf-8", errors="replace")
            except Exception:
                text = raw.decode("utf-8", errors="replace")
            return {
                "ok": True,
                "blocked": False,
                "curl": curl_cmd,
                "status": resp.status_code,
                "reason_phrase": resp.reason_phrase,
                "elapsed_ms": round((time.time() - started) * 1000, 1),
                "response_headers": dict(resp.headers),
                "final_url": str(resp.url),
                "body": text,
                "body_bytes": len(resp.content),
                "truncated": truncated,
            }
    except httpx.TimeoutException:
        return {"ok": False, "blocked": False, "curl": curl_cmd, "error": "request timed out"}
    except Exception as e:
        return {"ok": False, "blocked": False, "curl": curl_cmd, "error": f"{type(e).__name__}: {e}"}
