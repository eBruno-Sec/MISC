"""Reproducible timing instrument for the browser-heavy probe engines.

Normal pytest collection exercises only the artifact/measurement helpers.  The live
instrument is explicit::

    python tests/test_throughput_diagnosis.py --live --url https://owaspbench:8443/benchmark/

It wraps the shipping Playwright implementation; it does not replace navigation,
settle windows, or the engine oracle.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import ssl
import statistics
import sys
import threading
import time
from collections import defaultdict
from contextlib import contextmanager
from urllib.parse import urlparse


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


VOLATILE_FINDING_KEYS = frozenset({"screenshot", "dom_snippet", "request", "curl", "response"})


class _RateLimitState:
    def __init__(self):
        self.lock = threading.Lock()
        self.active = 0
        self.peak = 0
        self.starts = []
        self.responses = []


@contextmanager
def rate_limit_target(retry_after=2, response_delay=0.05):
    state = _RateLimitState()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            return

        def do_GET(self):
            with state.lock:
                state.active += 1
                state.peak = max(state.peak, state.active)
                state.starts.append(time.perf_counter())
            try:
                time.sleep(response_delay)
                body = b"rate limited"
                self.send_response(429)
                self.send_header("Retry-After", str(retry_after))
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                with state.lock:
                    state.responses.append(time.perf_counter())
            finally:
                with state.lock:
                    state.active -= 1

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/limited", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def normalized_findings(findings):
    """Drop presentation artifacts that vary even across two serial replays."""
    rows = []
    for finding in findings or []:
        row = {k: v for k, v in finding.items() if k not in VOLATILE_FINDING_KEYS}
        # Browser canaries are random by design; retain the proof shape, not its nonce.
        encoded = json.dumps(row, sort_keys=True, default=str)
        import re
        encoded = re.sub(r"(?:domtr|domfr|bbhx)[0-9a-f]{6,16}", "<CANARY>", encoded)
        rows.append(json.loads(encoded))
    return rows


def finding_digest(findings):
    payload = json.dumps(normalized_findings(findings), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def summarize_samples(samples):
    if not samples:
        return {"n": 0, "total_s": 0.0, "mean_s": 0.0}
    return {
        "n": len(samples),
        "total_s": round(sum(samples), 6),
        "mean_s": round(statistics.fmean(samples), 6),
    }


class Recorder:
    def __init__(self):
        self.samples = defaultdict(list)

    async def await_bucket(self, bucket, awaitable):
        started = time.perf_counter()
        try:
            return await awaitable
        finally:
            self.samples[bucket].append(time.perf_counter() - started)

    def report(self):
        return {key: summarize_samples(self.samples[key]) for key in sorted(self.samples)}


class _Page:
    def __init__(self, real, recorder):
        self._real = real
        self._recorder = recorder

    def __getattr__(self, name):
        return getattr(self._real, name)

    async def goto(self, *args, **kwargs):
        return await self._recorder.await_bucket("page_goto", self._real.goto(*args, **kwargs))

    async def wait_for_timeout(self, *args, **kwargs):
        return await self._recorder.await_bucket(
            "fixed_settle_sleep", self._real.wait_for_timeout(*args, **kwargs))

    async def wait_for_load_state(self, *args, **kwargs):
        return await self._recorder.await_bucket(
            "wait_networkidle", self._real.wait_for_load_state(*args, **kwargs))

    async def evaluate(self, *args, **kwargs):
        return await self._recorder.await_bucket("page_evaluate", self._real.evaluate(*args, **kwargs))

    async def screenshot(self, *args, **kwargs):
        return await self._recorder.await_bucket("page_screenshot", self._real.screenshot(*args, **kwargs))


class _Context:
    def __init__(self, real, recorder):
        self._real = real
        self._recorder = recorder

    def __getattr__(self, name):
        return getattr(self._real, name)

    async def new_page(self, *args, **kwargs):
        page = await self._recorder.await_bucket("page_create", self._real.new_page(*args, **kwargs))
        return _Page(page, self._recorder)

    async def close(self, *args, **kwargs):
        return await self._recorder.await_bucket("context_close", self._real.close(*args, **kwargs))


class _Browser:
    def __init__(self, real, recorder):
        self._real = real
        self._recorder = recorder

    def __getattr__(self, name):
        return getattr(self._real, name)

    async def new_context(self, *args, **kwargs):
        ctx = await self._recorder.await_bucket(
            "context_create", self._real.new_context(*args, **kwargs))
        return _Context(ctx, self._recorder)

    async def close(self, *args, **kwargs):
        return await self._recorder.await_bucket("browser_close", self._real.close(*args, **kwargs))


class _BrowserType:
    def __init__(self, real, recorder):
        self._real = real
        self._recorder = recorder

    def __getattr__(self, name):
        return getattr(self._real, name)

    async def launch(self, *args, **kwargs):
        browser = await self._recorder.await_bucket(
            "browser_launch", self._real.launch(*args, **kwargs))
        return _Browser(browser, self._recorder)


class _Playwright:
    def __init__(self, real, recorder):
        self._real = real
        self.chromium = _BrowserType(real.chromium, recorder)

    def __getattr__(self, name):
        return getattr(self._real, name)


class _PlaywrightManager:
    def __init__(self, real, recorder):
        self._real = real
        self._recorder = recorder

    async def __aenter__(self):
        return _Playwright(await self._real.__aenter__(), self._recorder)

    async def __aexit__(self, *args):
        return await self._real.__aexit__(*args)


@contextmanager
def instrument_playwright(recorder):
    import playwright.async_api as api
    original = api.async_playwright
    api.async_playwright = lambda: _PlaywrightManager(original(), recorder)
    try:
        yield
    finally:
        api.async_playwright = original


def transport_floor(url, attempts=5):
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    connects, tls = [], []
    for _ in range(attempts):
        started = time.perf_counter()
        sock = socket.create_connection((host, port), timeout=10)
        connects.append(time.perf_counter() - started)
        try:
            if parsed.scheme == "https":
                context = ssl._create_unverified_context()
                started = time.perf_counter()
                wrapped = context.wrap_socket(sock, server_hostname=host)
                tls.append(time.perf_counter() - started)
                wrapped.close()
            else:
                sock.close()
        finally:
            try:
                sock.close()
            except Exception:
                pass
    return {"tcp_connect": summarize_samples(connects), "tls_handshake": summarize_samples(tls)}


async def run_engine(engine, url, width):
    import scope as scope_mod
    import tools

    os.environ["BBH_BROWSER_CONCURRENCY"] = str(width)
    host = urlparse(url).hostname or ""
    scope = scope_mod.ScopeEngine()
    scope.load_manual([host], [], "throughput diagnosis")
    registry = tools.ToolRegistry(scope, mission_id=None, lab_mode=True)
    recorder = Recorder()
    original_http = registry._http

    async def timed_http(*args, **kwargs):
        return await recorder.await_bucket("http_request", original_http(*args, **kwargs))

    registry._http = timed_http
    method = {
        "dom_audit": registry._run_dom_audit,
        "xss": registry._run_xss,
        "dom_trace": registry._run_dom_trace,
    }[engine]
    started = time.perf_counter()
    with instrument_playwright(recorder):
        result = await method({"url": url})
    elapsed = time.perf_counter() - started
    return {
        "engine": engine,
        "url": url,
        "width": width,
        "elapsed_s": round(elapsed, 6),
        "finding_count": len(result.findings or []),
        "finding_digest": finding_digest(result.findings),
        "findings": normalized_findings(result.findings),
        "buckets": recorder.report(),
        "swallowed": registry.swallowed,
    }


async def run_rate_limit_control(width, retry_after=2):
    with rate_limit_target(retry_after=retry_after) as (url, state):
        run = await run_engine("dom_audit", url, width)
    first_response = min(state.responses) if state.responses else None
    starts_in_window = []
    if first_response is not None:
        starts_in_window = [
            started for started in state.starts
            if first_response < started < first_response + retry_after
        ]
    return {
        "width": width,
        "retry_after_s": retry_after,
        "request_count": len(state.starts),
        "peak_in_flight": state.peak,
        "requests_started_during_retry_window": len(starts_in_window),
        "retry_after_honored": not starts_in_window,
        "engine_run": run,
    }


async def run_mission(url, width):
    import agent as agent_mod
    import scope as scope_mod
    import tools

    os.environ["BBH_BROWSER_CONCURRENCY"] = str(width)
    scope = scope_mod.ScopeEngine()
    scope.load_manual([url], [], "throughput mission diagnosis")
    registry = tools.ToolRegistry(scope, mission_id=None, lab_mode=True)
    registry._add_urls([url])
    scanner = agent_mod.BBHAgent(
        scope,
        registry,
        asyncio.Event(),
        mode="full",
        auto_approve=True,
        mission_id=None,
        strategy="deterministic",
    )
    current_phase = "startup"
    phase_started = time.perf_counter()
    phase_samples = defaultdict(list)
    tool_samples = defaultdict(list)
    tool_errors = []
    event_counts = defaultdict(int)
    pending_tool = None
    started = phase_started
    async for event in scanner.run("throughput diagnosis", f"throughput-width-{width}"):
        event_counts[event.get("type", "unknown")] += 1
        if event.get("type") == "phase":
            now = time.perf_counter()
            phase_samples[current_phase].append(now - phase_started)
            current_phase = event.get("phase") or "unknown"
            phase_started = now
        elif event.get("type") == "tool_call":
            pending_tool = (event.get("tool") or "unknown", time.perf_counter())
        elif event.get("type") in ("tool_result", "tool_error") and pending_tool:
            tool_name, tool_started = pending_tool
            if tool_name == (event.get("tool") or "unknown"):
                tool_samples[tool_name].append(time.perf_counter() - tool_started)
                pending_tool = None
        if event.get("type") == "tool_error":
            tool_errors.append({"tool": event.get("tool"), "error": event.get("error")})
    finished = time.perf_counter()
    phase_samples[current_phase].append(finished - phase_started)
    return {
        "url": url,
        "width": width,
        "elapsed_s": round(finished - started, 6),
        "url_count": len(registry.urls),
        "seconds_per_url": round((finished - started) / max(1, len(registry.urls)), 6),
        "phases": {key: summarize_samples(value) for key, value in sorted(phase_samples.items())},
        "tools": {key: summarize_samples(value) for key, value in sorted(tool_samples.items())},
        "tool_errors": tool_errors,
        "event_counts": dict(sorted(event_counts.items())),
        "finding_count": len(scanner.findings),
        "finding_digest": finding_digest(scanner.findings),
        "findings": normalized_findings(scanner.findings),
        "swallowed": registry.swallowed,
    }


async def live(args):
    if args.mission:
        missions = [await run_mission(args.url, width) for width in args.width]
        print(json.dumps({"mission_runs": missions}, sort_keys=True, indent=2))
        return
    if args.rate_limit_control:
        controls = [await run_rate_limit_control(width) for width in args.width]
        print(json.dumps({"rate_limit_controls": controls}, sort_keys=True, indent=2))
        return
    runs = []
    for width in args.width:
        for engine in args.engine:
            for _ in range(args.repeats):
                runs.append(await run_engine(engine, args.url, width))
    artifact = {
        "url": args.url,
        "transport_floor": transport_floor(args.url),
        "runs": runs,
    }
    print(json.dumps(artifact, sort_keys=True, indent=2))


def test_finding_digest_ignores_browser_artifacts_but_not_the_verdict():
    base = {"family": "dom_xss", "confidence": "confirmed", "evidence": "canary domtr1234abcd fired"}
    decorated = {**base, "screenshot": "data:image/png;base64,random", "dom_snippet": "random"}
    other = {**base, "confidence": "candidate"}
    assert finding_digest([base]) == finding_digest([decorated])
    assert finding_digest([base]) != finding_digest([other])


def test_sample_summary_keeps_the_full_denominator():
    summary = summarize_samples([0.1, 0.2, 0.3])
    assert summary == {"n": 3, "total_s": 0.6, "mean_s": 0.2}
    assert summarize_samples([]) == {"n": 0, "total_s": 0.0, "mean_s": 0.0}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--url", default="https://owaspbench:8443/benchmark/")
    parser.add_argument("--engine", action="append", choices=("dom_audit", "xss", "dom_trace"))
    parser.add_argument("--width", action="append", type=int)
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--rate-limit-control", action="store_true")
    parser.add_argument("--mission", action="store_true")
    args = parser.parse_args()
    if not args.live:
        parser.error("the live instrument requires --live")
    args.engine = args.engine or ["dom_audit", "xss", "dom_trace"]
    args.width = args.width or [1, 6]
    asyncio.run(live(args))


if __name__ == "__main__":
    main()
