"""
OWASP ZAP daemon client (REST API over httpx) + pure alert->finding mapping.

BBH drives ZAP in daemon mode via its JSON API. The scan is fenced to a ZAP
*context* built from the mission scope (an include-regex per in-scope host) and
run in-scope-only, so ZAP is physically constrained on top of our wrapper scope.
The mapping/regex helpers are pure and unit-tested; only ZapClient touches the
network. ZAP runs as an optional compose service (profile "zap"); when ZAP_ADDR
is unset, run_zap skips cleanly.
"""
from __future__ import annotations

import asyncio
import os
import re
import time

ZAP_ADDR = os.getenv("ZAP_ADDR", "").rstrip("/")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")

_RISK_TO_SEV = {"high": "high", "medium": "medium", "low": "low",
                "informational": "informational", "info": "informational"}


def configured() -> bool:
    return bool(ZAP_ADDR)


def risk_to_severity(risk: str) -> str:
    return _RISK_TO_SEV.get((risk or "").strip().lower(), "informational")


def include_regexes(scope) -> list:
    """Build ZAP context include-regexes from the scope's in-scope hosts.
    Each matches the host and all its subdomains over http/https + optional port."""
    out = []
    for e in getattr(scope, "in_scope", []):
        host = e.value.lstrip("*.")
        out.append(rf"https?://([^/]*\.)?{re.escape(host)}(:\d+)?(/.*)?$")
    return out


def alert_to_finding(a: dict) -> dict:
    """Map one ZAP alert dict to a BBH finding."""
    name = a.get("alert") or a.get("name") or "ZAP alert"
    cweid = str(a.get("cweid", "")).strip()
    cwe = f"CWE-{cweid}" if cweid and cweid not in ("", "-1", "0") else ""
    param = a.get("param", "")
    step = f"Request {a.get('url', '')}" + (f" (parameter: {param})" if param else "")
    return {
        "title": f"ZAP: {name}",
        "severity": risk_to_severity(a.get("risk")),
        "target": a.get("url", ""),
        "description": (a.get("description") or "")[:1500],
        "impact": "",
        "evidence": (a.get("evidence") or "")[:500],
        "cwe": cwe,
        "remediation": (a.get("solution") or "")[:1000],
        "reproduction_steps": [step],
        "found_by": "zap",
        "param": param,
        "confidence": a.get("confidence", ""),
        "family": "zap",
        "tags": ["zap"],
    }


def dedup_alerts(alerts: list) -> list:
    """Collapse ZAP alerts that repeat across many URLs/instances."""
    seen, out = set(), []
    for a in alerts:
        key = (a.get("alert") or a.get("name"), a.get("url"), a.get("param"))
        if key in seen:
            continue
        seen.add(key)
        out.append(a)
    return out


class ZapClient:
    def __init__(self, addr: str = None, api_key: str = None, timeout: int = 30):
        self.addr = (addr if addr is not None else ZAP_ADDR).rstrip("/")
        self.api_key = api_key if api_key is not None else ZAP_API_KEY
        self.timeout = timeout

    async def _call(self, component: str, kind: str, action: str, **params):
        import httpx
        url = f"{self.addr}/JSON/{component}/{kind}/{action}/"
        q = {"apikey": self.api_key, **{k: v for k, v in params.items() if v is not None}}
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.get(url, params=q)
            return r.json()

    async def version(self):
        return (await self._call("core", "view", "version")).get("version")

    async def new_context(self, name: str) -> str:
        return (await self._call("context", "action", "newContext", contextName=name)).get("contextId")

    async def include_in_context(self, name: str, regex: str):
        return await self._call("context", "action", "includeInContext", contextName=name, regex=regex)

    async def access_url(self, url: str):
        return await self._call("core", "action", "accessUrl", url=url, followRedirects="true")

    async def spider(self, url: str, context: str = None) -> str:
        return (await self._call("spider", "action", "scan", url=url,
                                 contextName=context, recurse="true")).get("scan")

    async def spider_status(self, sid: str) -> int:
        return int((await self._call("spider", "view", "status", scanId=sid)).get("status", 0))

    async def ajax_start(self, url: str, context: str = None):
        return await self._call("ajaxSpider", "action", "scan", url=url,
                                contextName=context, inScope="true")

    async def ajax_status(self) -> str:
        return (await self._call("ajaxSpider", "view", "status")).get("status", "")

    async def ascan(self, url: str, context_id: str = None, policy: str = None) -> str:
        return (await self._call("ascan", "action", "scan", url=url, contextId=context_id,
                                 recurse="true", inScopeOnly="true",
                                 scanPolicyName=(policy or None))).get("scan")

    async def set_injectable(self, injectable: int = 27, rpc: int = 7):
        """Tune active-scan input vectors. injectable bitmask: querystring(1) +
        postdata(2) + headers(8) + cookie(16) = 27. rpc: multipart(1)+xml(2)+
        json(4) = 7 — so JSON API bodies get fuzzed. Best-effort; option names
        vary by ZAP version."""
        await self._call("ascan", "action", "setOptionTargetParamsInjectable", Integer=injectable)
        await self._call("ascan", "action", "setOptionTargetParamsEnabledRPC", Integer=rpc)

    async def add_scan_header(self, name: str = "X-Scanner", value: str = "BBH-ZAP-authorized"):
        """Tag every ZAP request with an identifying header (AddZAPHeader.js idea)
        so the target owner can spot authorized scan traffic and allowlist it."""
        return await self._call("replacer", "action", "addRule", description=f"bbh-{name}",
                                enabled="true", matchType="REQ_HEADER", matchString=name,
                                matchRegex="false", replacement=value, initiators="")

    async def ascan_status(self, sid: str) -> int:
        return int((await self._call("ascan", "view", "status", scanId=sid)).get("status", 0))

    async def alerts(self, baseurl: str = None, count: int = 1000) -> list:
        return (await self._call("core", "view", "alerts", baseurl=baseurl,
                                 start=0, count=count)).get("alerts", [])

    async def wait_int(self, status_fn, cap: int = 300, interval: int = 3, stop_event=None) -> bool:
        """Poll an int 0..100 status_fn until 100, the time cap, or a stop signal."""
        t0 = time.time()
        while time.time() - t0 < cap:
            if stop_event is not None and stop_event.is_set():
                return False
            try:
                if await status_fn() >= 100:
                    return True
            except Exception:
                return False
            await asyncio.sleep(interval)
        return False

    async def wait_str(self, status_fn, cap: int = 180, interval: int = 3, stop_event=None) -> bool:
        """Poll a string status_fn (ajax spider) until stopped/complete or cap."""
        t0 = time.time()
        while time.time() - t0 < cap:
            if stop_event is not None and stop_event.is_set():
                return False
            try:
                s = (await status_fn() or "").lower()
            except Exception:
                return False
            if s in ("stopped", "complete", "completed"):
                return True
            await asyncio.sleep(interval)
        return False
