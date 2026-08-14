"""
OWASP ZAP daemon client (REST API over httpx) + pure alert->finding mapping.

Apolaki drives ZAP in daemon mode via its JSON API. The scan is fenced to a ZAP
*context* built from the mission scope (an include-regex per in-scope host) and
run in-scope-only, so ZAP is physically constrained on top of our wrapper scope.
The mapping/regex helpers are pure and unit-tested; only ZapClient touches the
network. ZAP runs as an optional compose service (profile "zap"); when ZAP_ADDR
is unset, run_zap skips cleanly.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import re
import time
from urllib.parse import urlparse

ZAP_ADDR = os.getenv("ZAP_ADDR", "").rstrip("/")
ZAP_API_KEY = os.getenv("ZAP_API_KEY", "")

_RISK_TO_SEV = {"high": "high", "medium": "medium", "low": "low",
                "informational": "informational", "info": "informational"}


def configured() -> bool:
    return bool(ZAP_ADDR)


async def health(timeout: int = 6) -> dict:
    """Live ZAP status for the UI: is a daemon configured, and is it actually
    reachable right now? Returns {configured, running, version, addr, error}.
    Never raises — a down/absent daemon simply reports running=False."""
    addr = ZAP_ADDR
    if not addr:
        return {"configured": False, "running": False, "version": "", "addr": "", "error": ""}
    try:
        ver = await ZapClient(timeout=timeout).version()
        return {"configured": True, "running": bool(ver), "version": ver or "",
                "addr": addr, "error": "" if ver else "no version returned"}
    except Exception as e:
        return {"configured": True, "running": False, "version": "", "addr": addr,
                "error": f"{type(e).__name__}: {e}"}


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
    """Map one ZAP alert to a lead, never to deterministic Apolaki proof.

    ZAP's confidence is scanner metadata, not an Apolaki oracle.  Keeping it in
    ``scanner_confidence`` while grading the finding as a candidate prevents a
    missing ZAP grade from falling through a confirm-by-tool allow-list.
    """
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
        "confidence": "candidate",
        "scanner_confidence": a.get("confidence", ""),
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


def message_observation(message: dict) -> dict | None:
    """Extract the target URL, status and headers from one ZAP history row."""
    request = str(message.get("requestHeader") or "")
    response = str(message.get("responseHeader") or "")
    req_line = request.splitlines()[0] if request else ""
    res_lines = response.splitlines()
    req_match = re.match(r"^[A-Z]+\s+(https?://\S+)\s+HTTP/", req_line, re.I)
    status_match = re.match(r"^HTTP/\S+\s+(\d{3})\b", res_lines[0], re.I) if res_lines else None
    if not req_match or not status_match:
        return None
    headers = {}
    for line in res_lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()
    request_headers = {}
    for line in request.splitlines()[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        request_headers[key.strip().lower()] = value.strip()
    return {"url": req_match.group(1), "status": int(status_match.group(1)),
            "headers": headers, "request_headers": request_headers,
            "message_id": str(message.get("id") or "")}


def normalized_hostname(value: str) -> str:
    parsed = urlparse(value if "://" in str(value) else "//" + str(value))
    return (parsed.hostname or "").lower().lstrip("*.")


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

    @staticmethod
    def _require_ok(result: dict, action: str):
        if str((result or {}).get("Result") or "").upper() != "OK":
            raise RuntimeError(f"ZAP {action} failed: {result}")

    async def configure_target_safety(self, url: str, hosts=None) -> dict:
        """Install and verify a daemon-side one-request-per-second host fence.

        ZAP creates target traffic inside its own process, outside Apolaki's
        httpx hooks.  The daemon-side rule must therefore exist as a fact before
        accessUrl, either spider, or active scan is allowed to start.  One worker
        per scanner keeps a limiting response observable before another worker
        can race ahead; ``observe_rate_limits`` then feeds Retry-After into the
        process-wide Apolaki policy and the caller aborts the ZAP pass.
        """
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("ZAP target safety requires an absolute HTTP(S) URL")
        hostnames = {parsed.hostname.lower()}
        hostnames.update(filter(None, (normalized_hostname(h) for h in (hosts or []))))
        verified = []
        for hostname in sorted(hostnames):
            description = "apolaki-" + hashlib.sha256(hostname.encode("utf8")).hexdigest()[:16]
            rules = (await self._call("network", "view", "getRateLimitRules")).get(
                "getRateLimitRules", [])
            matched = next((r for r in rules
                            if normalized_hostname(r.get("matchString") or "") == hostname
                            and r.get("enabled")
                            and 0 < float(r.get("requestsPerSecond") or 0) <= 1), None)
            if matched is not None:
                verified.append(matched)
                continue

            # A stable description makes this idempotent across missions. Removal
            # is best-effort because a first run has no prior rule; creation and
            # read-back are fail-closed.
            try:
                await self._call("network", "action", "removeRateLimitRule",
                                 description=description)
            except Exception:
                pass
            added = await self._call(
                "network", "action", "addRateLimitRule",
                description=description, enabled="true", matchRegex="false",
                matchString=hostname, requestsPerSecond="1", groupBy="host")
            self._require_ok(added, "addRateLimitRule")
            rules = (await self._call("network", "view", "getRateLimitRules")).get(
                "getRateLimitRules", [])
            matched = next((r for r in rules if r.get("description") == description), None)
            if (not matched or not matched.get("enabled")
                    or float(matched.get("requestsPerSecond") or 0) > 1):
                raise RuntimeError("ZAP target rate-limit rule was not active after creation")
            verified.append(matched)

        # These are global daemon options, so establish them before every pass.
        # The verified network rule is the aggregate host cap; one worker also
        # minimizes already-in-flight traffic when a target starts a cooldown.
        for component, action, params in (
                ("spider", "setOptionThreadCount", {"Integer": 1}),
                ("ajaxSpider", "setOptionNumberOfBrowsers", {"Integer": 1}),
                ("ascan", "setOptionThreadPerHost", {"Integer": 1}),
                ("ascan", "setOptionHostPerScan", {"Integer": 1})):
            result = await self._call(component, "action", action, **params)
            self._require_ok(result, f"{component}.{action}")
        return {"descriptions": [r["description"] for r in verified],
                "hosts": sorted(hostnames),
                "requests_per_second": max(float(r["requestsPerSecond"]) for r in verified)}

    async def history_cursor(self) -> int:
        result = await self._call("core", "view", "numberOfMessages")
        return int(result.get("numberOfMessages") or 0)

    async def alerts_since(self, cursor: int, baseurl: str = None,
                           count: int = 1000) -> tuple[list, int]:
        """Return alerts attributable to history messages after ``cursor``.

        A shared ZAP daemon retains alerts from earlier scans.  Base-URL
        filtering alone therefore lets a later mission claim old alerts.  Join
        alerts to the message IDs created during this pass; an alert without a
        current message ID is excluded rather than attributed by inference.
        The second return value is the unfiltered alert count for diagnostics.
        """
        current = await self.history_cursor()
        if current < cursor:
            cursor = 0
        messages = []
        if current > cursor:
            result = await self._call("core", "view", "messages", start=cursor,
                                      count=max(1, current - cursor))
            messages = result.get("messages", [])
        message_ids = {str(row.get("id")) for row in messages if row.get("id") is not None}
        all_alerts = await self.alerts(baseurl=baseurl, count=count)
        attributable = []
        for alert in all_alerts:
            alert_ids = {
                str(value) for value in (
                    alert.get("messageId"), alert.get("sourceMessageId"),
                    alert.get("messageID"), alert.get("messageid"))
                if value is not None
            }
            if alert_ids & message_ids:
                attributable.append(alert)
        return attributable, len(all_alerts)

    async def observe_rate_limits(self, cursor: int, target_url: str, rate_policy,
                                  allowed_hosts=None):
        """Observe new ZAP responses and return the first Retry-After cooldown."""
        current = await self.history_cursor()
        if current < cursor:
            cursor = 0
        if current == cursor:
            return current, None
        result = await self._call("core", "view", "messages", start=cursor,
                                  count=max(1, current - cursor))
        allowed = {normalized_hostname(target_url)}
        allowed.update(filter(None, (normalized_hostname(h) for h in (allowed_hosts or []))))
        for raw in result.get("messages", []):
            obs = message_observation(raw)
            if not obs:
                # ZAP can increment numberOfMessages before responseHeader is
                # committed. Advancing now permanently skips a rate-limiting
                # response and lets the next traffic phase race its cooldown.
                # Retain the cursor and retry this row on the next poll.
                return cursor, None
            seen_host = normalized_hostname(obs["url"])
            if not any(seen_host == host or seen_host.endswith("." + host) for host in allowed):
                continue
            delay = rate_policy.observe(obs["url"], obs["status"], obs["headers"])
            if delay is not None:
                return current, {**obs, "retry_after_seconds": delay}
        return current, None

    async def new_context(self, name: str) -> str:
        return (await self._call("context", "action", "newContext", contextName=name)).get("contextId")

    async def include_in_context(self, name: str, regex: str):
        return await self._call("context", "action", "includeInContext", contextName=name, regex=regex)

    async def access_url(self, url: str, request_id: str = ""):
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("ZAP seed request requires an absolute HTTP(S) URL")
        # core/accessUrl internally retried a 429 in the live acceptance target
        # and exposed only one of the two requests in ZAP history. sendRequest is
        # one explicit transaction, so every target request remains observable
        # to the shared Retry-After policy before another phase can start.
        request = (
            f"GET {url} HTTP/1.1\r\n"
            f"Host: {parsed.netloc}\r\n"
            "User-Agent: Apolaki-ZAP/1\r\n"
            f"X-Apolaki-ZAP-Seed: {request_id}\r\n"
            "Connection: close\r\n\r\n"
        )
        return await self._call("core", "action", "sendRequest",
                                request=request, followRedirects="false")

    async def stop_all(self):
        """Stop + remove any running/queued spider & active scans so a NEW mission does
        not inherit an earlier (or killed) mission's still-running load — the shared
        single ZAP daemon otherwise bogs down and its API read-times-out (DEF-2)."""
        for comp in ("spider", "ascan"):
            for act in ("stopAllScans", "removeAllScans"):
                result = await self._call(comp, "action", act)
                self._require_ok(result, f"{comp}.{act}")
        # The AJAX add-on has one global `stop` action. The old generic loop
        # called two nonexistent actions and swallowed both BAD_ACTION results.
        result = await self._call("ajaxSpider", "action", "stop")
        self._require_ok(result, "ajaxSpider.stop")

    async def spider(self, url: str, context: str = None) -> str:
        return (await self._call("spider", "action", "scan", url=url,
                                 contextName=context, recurse="true")).get("scan")

    async def spider_status(self, sid: str) -> int:
        return int((await self._call("spider", "view", "status", scanId=sid)).get("status", 0))

    async def spider_stop(self, sid: str):
        return await self._call("spider", "action", "stop", scanId=sid)

    async def ajax_start(self, url: str, context: str = None):
        return await self._call("ajaxSpider", "action", "scan", url=url,
                                contextName=context, inScope="true")

    async def ajax_status(self) -> str:
        return (await self._call("ajaxSpider", "view", "status")).get("status", "")

    async def ajax_stop(self):
        return await self._call("ajaxSpider", "action", "stop")

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

    async def set_scan_rate(self, delay_ms: int = 0, threads_per_host: int = None):
        """Slow/polite the active scanner — a delay between requests and a
        per-host thread cap keep a 'safe active' scan gentle on the target.
        Best-effort; option names vary by ZAP version."""
        try:
            await self._call("ascan", "action", "setOptionDelayInMs", Integer=delay_ms)
        except Exception:
            pass
        if threads_per_host is not None:
            try:
                await self._call("ascan", "action", "setOptionThreadPerHost", Integer=threads_per_host)
            except Exception:
                pass

    async def set_hosts_per_scan(self, hosts: int = 2):
        """Parallel hosts per active scan — part of the SPEED dial (higher = faster).
        Best-effort; option name varies by ZAP version."""
        try:
            await self._call("ascan", "action", "setOptionHostPerScan", Integer=hosts)
        except Exception:
            pass

    async def set_attack_strength(self, strength: str = "MEDIUM", threshold: str = None):
        """AGGRESSION dial — how hard the active scanner hits each parameter.
        Sets attack strength (LOW/MEDIUM/HIGH/INSANE) and optional alert threshold
        (OFF/LOW/MEDIUM/HIGH) across every plugin category (0..5) of the default
        scan policy. Demon = HIGH strength + LOW threshold (throw everything, flag
        anything). Best-effort — silently skips categories a ZAP version rejects."""
        for cat in range(6):
            try:
                await self._call("ascan", "action", "setPolicyAttackStrength",
                                 id=cat, attackStrength=strength)
            except Exception:
                pass
            if threshold:
                try:
                    await self._call("ascan", "action", "setPolicyAlertThreshold",
                                     id=cat, alertThreshold=threshold)
                except Exception:
                    pass

    async def pscan_remaining(self) -> int:
        """Records still queued for passive scanning (0 = passive scan drained)."""
        try:
            return int((await self._call("pscan", "view", "recordsToScan")).get("recordsToScan", 0))
        except Exception:
            return 0

    async def add_scan_header(self, name: str = "X-Scanner", value: str = "Apolaki-ZAP-authorized"):
        """Tag every ZAP request with an identifying header (AddZAPHeader.js idea)
        so the target owner can spot authorized scan traffic and allowlist it."""
        return await self._call("replacer", "action", "addRule", description=f"bbh-{name}",
                                enabled="true", matchType="REQ_HEADER", matchString=name,
                                matchRegex="false", replacement=value, initiators="")

    async def set_oast_service(self, name: str = "BOAST"):
        """Point ZAP's active scanner at an OAST service (BOAST / Interactsh /
        Callbacks) so blind, out-of-band vulns — OOB SSRF, XXE, blind SQLi, OOB
        RCE — get detected and reported as alerts. Requires the ZAP oast add-on."""
        return await self._call("oast", "action", "setActiveScanServiceForOast", name=name)

    async def ascan_status(self, sid: str) -> int:
        return int((await self._call("ascan", "view", "status", scanId=sid)).get("status", 0))

    async def ascan_stop(self, sid: str):
        return await self._call("ascan", "action", "stop", scanId=sid)

    async def alerts(self, baseurl: str = None, count: int = 1000) -> list:
        return (await self._call("core", "view", "alerts", baseurl=baseurl,
                                 start=0, count=count)).get("alerts", [])

    async def wait_int(self, status_fn, cap: int = 300, interval: int = 3,
                       stop_event=None, guard=None) -> bool:
        """Poll an int 0..100 status_fn until 100, the time cap, or a stop signal."""
        t0 = time.time()
        while time.time() - t0 < cap:
            if stop_event is not None and stop_event.is_set():
                return False
            if guard is not None and await guard():
                return False
            try:
                if await status_fn() >= 100:
                    return True
            except Exception:
                return False
            await asyncio.sleep(interval)
        return False

    async def wait_str(self, status_fn, cap: int = 180, interval: int = 3,
                       stop_event=None, guard=None) -> bool:
        """Poll a string status_fn (ajax spider) until stopped/complete or cap."""
        t0 = time.time()
        while time.time() - t0 < cap:
            if stop_event is not None and stop_event.is_set():
                return False
            if guard is not None and await guard():
                return False
            try:
                s = (await status_fn() or "").lower()
            except Exception:
                return False
            if s in ("stopped", "complete", "completed"):
                return True
            await asyncio.sleep(interval)
        return False
