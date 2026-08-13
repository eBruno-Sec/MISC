"""Cross-path controls for the target Retry-After policy.

The real-network tests use loopback only.  Delays are capped to 80 ms there so
the controls prove ordering without making the suite inherit server-sized waits.
"""
from __future__ import annotations

import ast
import asyncio
import email.utils
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
import time

import browser_engine as browser
import httpx
import pytest
import proxy
import scope as scope_mod
import tools


class _ServerState:
    def __init__(self, status=429, retry_after="1", limit_first=True):
        self.status = status
        self.retry_after = retry_after
        self.limit_first = limit_first
        self.lock = threading.Lock()
        self.starts = []
        self.responses = []


@contextmanager
def _target(status=429, retry_after="1", limit_first=True):
    state = _ServerState(status, retry_after, limit_first)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *_args):
            return

        def do_GET(self):
            with state.lock:
                index = len(state.starts)
                state.starts.append(time.monotonic())
            limited = not state.limit_first or index == 0
            code = state.status if limited else 200
            body = ("limited" if limited else "ok").encode()
            self.send_response(code)
            if limited:
                self.send_header("Retry-After", state.retry_after)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            with state.lock:
                state.responses.append(time.monotonic())

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


def _registry(url):
    parsed = httpx.URL(url)
    sc = scope_mod.ScopeEngine()
    sc.load_manual([parsed.host], [], "rate policy control")
    return tools.ToolRegistry(sc, mission_id=None, lab_mode=True)


def _clear_shipping_policy():
    policy = getattr(browser, "target_rate_policy", None)
    if policy is not None:
        policy.clear()


def _run(awaitable):
    return asyncio.run(awaitable)


def test_http_engine_path_starts_zero_requests_inside_the_retry_window(monkeypatch):
    """The negative control: removing `_http`'s policy call makes this fail."""
    monkeypatch.setenv("BBH_RETRY_AFTER_MAX_SECONDS", "0.08")
    _clear_shipping_policy()
    with _target(status=429) as (url, state):
        reg = _registry(url)

        async def exercise():
            first = await reg._http(url, capture=False)
            returned = time.monotonic()
            rest = await asyncio.gather(*[reg._http(url, capture=False) for _ in range(6)])
            return first, returned, rest

        first, returned, rest = _run(exercise())

    assert first["status"] == 429
    assert all(row["status"] == 200 for row in rest)
    assert len(state.starts) == 7
    assert min(state.starts[1:]) - returned >= 0.06, (
        "a concurrent worker issued a request inside the active Retry-After window"
    )


def test_http_investigation_path_honors_503_retry_after(monkeypatch):
    """`_http_send` is a second general path; `_http` coverage cannot protect it."""
    monkeypatch.setenv("BBH_RETRY_AFTER_MAX_SECONDS", "0.08")
    _clear_shipping_policy()
    with _target(status=503) as (url, state):
        reg = _registry(url)

        async def exercise():
            first, _ = await reg._http_send("GET", url, {}, None, True)
            returned = time.monotonic()
            second, _ = await reg._http_send("GET", url, {}, None, True)
            return first, returned, second

        first, returned, second = _run(exercise())

    assert first.status_code == 503 and second.status_code == 200
    assert state.starts[1] - returned >= 0.06


def _policy(*args, **kwargs):
    return getattr(browser, "TargetRatePolicy")(*args, **kwargs)


@pytest.mark.parametrize("status", [429, 503])
def test_delta_seconds_is_honored_for_both_retry_statuses(status):
    sleeps = []

    async def sleep(delay):
        sleeps.append(delay)
        clock[0] += delay

    clock = [10.0]
    policy = _policy(max_wait=10, clock=lambda: clock[0], async_sleep=sleep)
    assert policy.observe("https://a.example/x", status, {"Retry-After": "3"}) == 3
    _run(policy.wait_async("https://a.example/y"))
    assert sleeps == [3]


@pytest.mark.parametrize("status", [429, 503])
def test_http_date_is_honored_for_both_retry_statuses(status):
    wall = datetime(2026, 8, 13, 12, 0, tzinfo=timezone.utc).timestamp()
    header = email.utils.format_datetime(datetime.fromtimestamp(wall + 7, timezone.utc), usegmt=True)
    clock = [20.0]
    sleeps = []

    def sleep(delay):
        sleeps.append(delay)
        clock[0] += delay

    policy = _policy(max_wait=20, clock=lambda: clock[0], wall_clock=lambda: wall,
                     sync_sleep=sleep)
    assert policy.observe("https://a.example/x", status, {"retry-after": header}) == 7
    policy.wait_sync("https://a.example/y")
    assert sleeps == [7]


def test_retry_after_is_per_origin_not_global():
    clock = [100.0]
    sleeps = []

    async def sleep(delay):
        sleeps.append(delay)
        clock[0] += delay

    policy = _policy(max_wait=10, clock=lambda: clock[0], async_sleep=sleep)
    policy.observe("https://a.example/limited", 429, {"retry-after": "5"})

    _run(policy.wait_async("https://b.example/free"))
    assert sleeps == [], "host A's cooldown stalled host B"
    _run(policy.wait_async("https://a.example/next"))
    assert sleeps == [5]


def test_an_inflight_response_extends_a_waiters_deadline():
    clock = [0.0]
    sleeps = []
    policy = None

    async def sleep(delay):
        sleeps.append(delay)
        if len(sleeps) == 1:
            policy.observe("https://a.example/second", 503, {"retry-after": "5"})
        clock[0] += delay

    policy = _policy(max_wait=10, clock=lambda: clock[0], async_sleep=sleep)
    policy.observe("https://a.example/first", 429, {"retry-after": "2"})
    _run(policy.wait_async("https://a.example/next"))
    assert sleeps == [2, 3], "an in-flight response did not extend the shared origin deadline"


def test_absurd_retry_after_is_capped():
    clock = [100.0]
    sleeps = []

    async def sleep(delay):
        sleeps.append(delay)
        clock[0] += delay

    policy = _policy(max_wait=4, clock=lambda: clock[0], async_sleep=sleep)
    assert policy.observe("https://a.example/", 429, {"retry-after": "86400"}) == 4
    _run(policy.wait_async("https://a.example/next"))
    assert sleeps == [4]


def test_non_limiting_origin_never_calls_a_sleeper():
    async_calls = []
    sync_calls = []

    async def async_sleep(delay):
        async_calls.append(delay)

    policy = _policy(async_sleep=async_sleep, sync_sleep=sync_calls.append)
    _run(policy.wait_async("https://clean.example/a"))
    policy.wait_sync("https://clean.example/b")
    policy.observe("https://clean.example/a", 200, {"retry-after": "10"})
    _run(policy.wait_async("https://clean.example/c"))
    assert async_calls == [] and sync_calls == []


class _Response:
    def __init__(self, url, status, retry_after=None):
        self.url = url
        self.status = status
        self.headers = {} if retry_after is None else {"retry-after": retry_after}


class _Page:
    def __init__(self, url):
        self.url = url
        self.calls = 0
        self.route_handler = None
        self.response_handler = None

    async def route(self, _pattern, handler):
        self.route_handler = handler

    def on(self, event, handler):
        if event == "response":
            self.response_handler = handler

    async def goto(self, url, **_kwargs):
        self.calls += 1
        return _Response(url, 429, "2") if self.calls == 1 else _Response(url, 200)


def test_playwright_navigation_uses_the_same_policy():
    clock = [0.0]
    sleeps = []

    async def sleep(delay):
        sleeps.append(delay)
        clock[0] += delay

    policy = _policy(max_wait=5, clock=lambda: clock[0], async_sleep=sleep)
    page = _Page("https://a.example/")

    async def exercise():
        await browser.rate_limited_goto(page, page.url, rate_policy=policy)
        await browser.rate_limited_goto(page, page.url, rate_policy=policy)

    _run(exercise())
    assert page.calls == 2 and sleeps == [2]


def test_playwright_subrequests_use_the_same_policy():
    clock = [0.0]
    sleeps = []

    async def sleep(delay):
        sleeps.append(delay)
        clock[0] += delay

    class Request:
        url = "https://a.example/favicon.ico"

    class Route:
        continued = False

        async def continue_(self):
            self.continued = True

    policy = _policy(max_wait=5, clock=lambda: clock[0], async_sleep=sleep)
    page = _Page("https://a.example/")

    async def exercise():
        await browser.rate_limited_goto(page, page.url, rate_policy=policy)
        route = Route()
        await page.route_handler(route, Request())
        return route

    route = _run(exercise())
    assert route.continued and sleeps == [2]


def test_tools_has_no_unguarded_target_page_goto():
    """Every target navigation in tools.py must pass the shared policy helper."""
    tree = ast.parse(Path(tools.__file__).read_text(encoding="utf8"))
    bypasses = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "goto":
            continue
        first = node.args[0] if node.args else None
        if isinstance(first, ast.Constant) and first.value == "about:blank":
            continue
        bypasses.append(node.lineno)
    assert bypasses == [], "target page.goto bypasses rate policy at lines %s" % bypasses


def test_tools_has_no_raw_async_client_bypass():
    """Every specialized client must use the shared construction chokepoint."""
    tree = ast.parse(Path(tools.__file__).read_text(encoding="utf8"))
    raw = []
    guarded = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (isinstance(func, ast.Attribute) and func.attr == "AsyncClient"
                and isinstance(func.value, ast.Name) and func.value.id == "httpx"):
            raw.append(node.lineno)
        if isinstance(func, ast.Name) and func.id == "_target_client":
            guarded.append(node.lineno)
    assert guarded, "the client inventory is vacuous"
    assert raw == [], "raw AsyncClient bypasses rate policy at lines %s" % raw


def test_specialized_async_client_observes_and_waits_without_call_site_wiring():
    """Removing the factory hooks makes the second MockTransport request start at zero."""
    clock = [0.0]
    starts = []
    custom_hooks = []

    async def sleep(delay):
        clock[0] += delay

    async def custom_request(_request):
        custom_hooks.append("request")

    async def custom_response(_response):
        custom_hooks.append("response")

    responses = [429, 200]

    def send(request):
        starts.append(clock[0])
        status = responses.pop(0)
        headers = {"retry-after": "2"} if status == 429 else {}
        return httpx.Response(status, headers=headers, request=request)

    policy = _policy(max_wait=5, clock=lambda: clock[0], async_sleep=sleep)

    async def exercise():
        async with browser.rate_limited_async_client(
            httpx,
            transport=httpx.MockTransport(send),
            rate_policy=policy,
            event_hooks={"request": [custom_request], "response": [custom_response]},
        ) as client:
            await client.get("https://a.example/first")
            await client.get("https://a.example/second")

    _run(exercise())
    assert starts == [0, 2]
    assert custom_hooks == ["request", "response", "request", "response"]


def test_browserless_navigation_result_starts_the_same_origin_cooldown(monkeypatch):
    clock = [0.0]
    posts = []
    calls = [0]

    def sleep(delay):
        clock[0] += delay

    policy = _policy(max_wait=5, clock=lambda: clock[0], sync_sleep=sleep)
    monkeypatch.setattr(browser, "target_rate_policy", policy)

    class Result:
        status_code = 200

        def json(self):
            calls[0] += 1
            nav = {"url": "https://a.example/", "status": 429,
                   "headers": {"retry-after": "2"}} if calls[0] == 1 else {
                       "url": "https://a.example/", "status": 200, "headers": {}}
            return {"data": {"title": "page", "_apolaki_navigation": nav}}

    scripts = []

    def post(*_args, **kwargs):
        posts.append(clock[0])
        scripts.append(kwargs.get("content") or "")
        return Result()

    monkeypatch.setattr(httpx, "post", post)
    browser.drive("https://a.example/", "export default async function () { return {}; }",
                  browser_url="http://browser.test")
    browser.drive("https://a.example/", "export default async function () { return {}; }",
                  browser_url="http://browser.test")
    assert posts == [0, 2]
    assert all("isNavigationRequest" in script and "setRequestInterception" in script
               for script in scripts)


def test_screenshot_uses_the_observable_browserless_path(monkeypatch):
    calls = []
    png = "iVBORw0KGgo="

    def drive(target, script, browser_url=None, timeout=45):
        calls.append((target, script, browser_url, timeout))
        return {"png_b64": png, "target": target, "script_errors": []}

    monkeypatch.setattr(browser, "drive", drive)
    result = browser.screenshot("https://a.example/page", browser_url="http://browser.test",
                                full=True, timeout=9)
    assert result == {"browser": True, "png_b64": png, "bytes": 8,
                      "target": "https://a.example/page"}
    assert len(calls) == 1
    assert "page.goto" in calls[0][1] and "fullPage: true" in calls[0][1]


def test_proxy_replay_uses_the_shared_policy(monkeypatch):
    clock = [0.0]
    starts = []

    def sleep(delay):
        clock[0] += delay

    policy = _policy(max_wait=5, clock=lambda: clock[0], sync_sleep=sleep)
    monkeypatch.setattr(browser, "target_rate_policy", policy)
    responses = [429, 200]

    class Response:
        def __init__(self, status):
            self.status_code = status
            self.url = "https://a.example/replay"
            self.headers = {"retry-after": "2"} if status == 429 else {}
            self.content = b""

    def request(*_args, **_kwargs):
        starts.append(clock[0])
        return Response(responses.pop(0))

    monkeypatch.setattr(httpx, "request", request)
    flow = {"method": "GET", "url": "https://a.example/replay"}
    assert proxy.replay(flow, send=True)["response"]["status"] == 429
    assert proxy.replay(flow, send=True)["response"]["status"] == 200
    assert starts == [0, 2]


def test_race_rounds_cannot_route_around_the_shared_policy(monkeypatch):
    clock = [0.0]
    starts = []

    async def sleep(delay):
        clock[0] += delay

    policy = _policy(max_wait=5, clock=lambda: clock[0], async_sleep=sleep)
    monkeypatch.setattr(browser, "target_rate_policy", policy)

    class Response:
        def __init__(self, status, retry=False):
            self.status_code = status
            self.url = "https://a.example/action"
            self.headers = {"retry-after": "2"} if retry else {}
            self.content = b""
            self.text = ""

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def request(self, method, _url, **_kwargs):
            if method == "OPTIONS":
                return Response(200)
            starts.append(clock[0])
            return Response(429, retry=True)

    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: Client())
    reg = _registry("https://a.example/action")
    _run(reg._run_race({"url": "https://a.example/action", "count": 2, "rounds": 2}))
    assert starts == [0, 0, 2, 2]
