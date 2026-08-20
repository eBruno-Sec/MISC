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
import urllib.error
import urllib.request

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


# Q-085: the original bypass controls below parsed ``tools.__file__`` only.  That made
# tools.py clean while every sibling module was invisible.  Inventory raw target-capable
# transports from every production Python module; explicit control-plane calls are recorded
# here by owner so adding a new module cannot inherit an exemption by accident.
_RAW_HTTP_CALLS = {
    "httpx.Client", "httpx.AsyncClient", "httpx.request", "httpx.get", "httpx.post",
    "httpx.put", "httpx.patch", "httpx.delete", "httpx.head", "httpx.options",
    "requests.Session", "requests.request", "requests.get", "requests.post", "requests.put",
    "requests.patch", "requests.delete", "requests.head", "requests.options",
    "urllib.request.urlopen", "aiohttp.ClientSession", "urllib3.PoolManager",
    "http.client.HTTPConnection", "http.client.HTTPSConnection",
}

_CONTROL_PLANE_CALLS = {
    ("benchmark_assert.py", "_get", "urllib.request.urlopen"):
        "reads the local Apolaki API, not the assessment target",
    ("browser_engine.py", "drive", "httpx.post"):
        "calls the configured browserless control plane; browser target traffic is gated separately",
    ("cdp.py", "collect", "httpx.post"):
        "calls the browserless CDP control plane, not the assessment target",
    ("ci_summary.py", "_get_json", "urllib.request.urlopen"):
        "reads the local Apolaki API for CI output",
    ("cloud_iam.py", "_linode_get", "urllib.request.urlopen"):
        "queries the Linode provider API rather than the assessment target",
    ("dns_recon.py", "doh", "httpx.AsyncClient"):
        "queries the configured DNS-over-HTTPS resolver",
    ("intel_connectors.py", "_default_http", "httpx.get"):
        "queries a configured intelligence provider",
    ("intel_extractor.py", "_call_llm", "urllib.request.urlopen"):
        "calls the configured LLM control plane",
    ("intel_feeds.py", "fetch", "urllib.request.urlopen"):
        "downloads an intelligence feed, not an assessment target",
    ("labs.py", "_http_json", "urllib.request.urlopen"):
        "calls the local Docker control plane for lab state",
    ("main.py", "blind_benchmark_run", "httpx.AsyncClient"):
        "fetches a benchmark answer key only after sealing the blind artifact",
    ("zap_client.py", "_call", "httpx.AsyncClient"):
        "calls the ZAP daemon API; ZAP target traffic has a separate verified daemon-side fence",
    ("bench_all.py", "reachable", "httpx.AsyncClient"):
        "one-shot health check against compose-pinned local lab URLs",
    ("bench_all.py", "scan_via_mission", "httpx.AsyncClient"):
        "drives the Apolaki mission API; the mission owns target pacing",
    ("owasp_bench.py", "scan", "httpx.Client"):
        "isolated adapter for the compose-pinned OWASP benchmark corpus",
    ("owasp_bench.py", "scan_source", "httpx.Client"):
        "isolated source-benchmark adapter limited to the two pinned local suites",
}

_POLICY_CHOKEPOINT_CALLS = {
    ("browser_engine.py", "rate_limited_async_client", "httpx.AsyncClient"),
    ("browser_engine.py", "rate_limited_sync_client", "httpx.Client"),
    ("browser_engine.py", "rate_limited_goto", "page.goto"),
    ("browser_engine.py", "rate_limited_goto_sync", "page.goto"),
    ("browser_engine.py", "rate_limited_urlopen", "urllib.request.urlopen"),
}


def _dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = _dotted(node.value)
        return (left + "." if left else "") + node.attr
    return ""


def _canonical_call(node, aliases):
    name = _dotted(node.func)
    head, dot, tail = name.partition(".")
    if head in aliases:
        name = aliases[head] + (dot + tail if dot else "")
    if name.endswith(".goto"):
        return "page.goto"
    return name


def _production_python_paths(root):
    """Every production module, including future nested packages; test/gate code is not traffic."""
    root = Path(root)
    return sorted(path for path in root.rglob("*.py")
                  if not ({"tests", "tier3"} & set(path.relative_to(root).parts[:-1])))


def _raw_transport_inventory(paths=None):
    root = Path(tools.__file__).resolve().parent
    default_corpus = paths is None
    paths = _production_python_paths(root) if default_corpus else [Path(p) for p in paths]
    rows = []
    for path in paths:
        source = path.read_text(encoding="utf8")
        tree = ast.parse(source, filename=str(path))
        parents = {}
        aliases = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
            if isinstance(parent, ast.Import):
                for item in parent.names:
                    if item.asname:
                        aliases[item.asname] = item.name
                    elif "." not in item.name:
                        aliases[item.name] = item.name
            elif isinstance(parent, ast.ImportFrom) and parent.module:
                for item in parent.names:
                    aliases[item.asname or item.name] = parent.module + "." + item.name

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call = _canonical_call(node, aliases)
            if call not in _RAW_HTTP_CALLS and call != "page.goto":
                continue
            owner = node
            while owner in parents and not isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
                owner = parents[owner]
            fn = owner.name if isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)) else "<module>"
            # The browser bootstrap navigates to a local blank document, not to the assessment target.
            if call == "page.goto" and node.args and isinstance(node.args[0], ast.Constant) \
                    and node.args[0].value == "about:blank":
                continue
            module = path.relative_to(root).as_posix() if default_corpus else path.name
            rows.append({"path": path, "module": module, "function": fn,
                         "call": call, "line": node.lineno, "owner": owner})
    return rows


def _is_locally_wrapped(row):
    """A raw send is acceptable only when the same function gates before and observes after it."""
    owner = row["owner"]
    if not isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    calls = [(_dotted(n.func), n.lineno) for n in ast.walk(owner) if isinstance(n, ast.Call)]
    waits = [line for name, line in calls if name.endswith(("target_rate_policy.wait_sync",
                                                            "target_rate_policy.wait_async"))]
    observations = [line for name, line in calls if name.endswith("target_rate_policy.observe")]
    return any(line < row["line"] for line in waits) and any(line > row["line"] for line in observations)


def _target_traffic_bypasses(paths=None):
    rows = _raw_transport_inventory(paths)
    exemption_use = {}
    bypasses = []
    for row in rows:
        key = (row["module"], row["function"], row["call"])
        if key in _POLICY_CHOKEPOINT_CALLS or _is_locally_wrapped(row):
            continue
        if key in _CONTROL_PLANE_CALLS:
            # Every exemption names one measured call site. A second raw call in the same function is
            # drift, not a free extension of the exemption.
            exemption_use[key] = exemption_use.get(key, 0) + 1
            if exemption_use[key] == 1:
                continue
        bypasses.append("%s:%d:%s:%s" %
                        (row["module"], row["line"], row["function"], row["call"]))
    return sorted(bypasses)


def test_repository_wide_rate_policy_inventory_is_non_vacuous_and_ratcheted():
    bypasses = _target_traffic_bypasses()
    modules = {row.split(":", 1)[0] for row in bypasses}
    root = Path(tools.__file__).resolve().parent
    # Measured after the Juice Shop slice: 179 top-level production modules are in scope. Raw-call
    # count is deliberately NOT a floor: removing a bypass must be allowed to reduce it.
    assert len(_production_python_paths(root)) >= 179, \
        "the repository-wide production-module census loaded too little"
    assert _raw_transport_inventory(), "the transport inventory is vacuous"
    assert len(bypasses) <= 8, "ungated target-call sites rose above the measured Q-085 ratchet: %s" % bypasses
    assert len(modules) <= 8, "modules bypassing the target policy rose above the measured ratchet: %s" % sorted(modules)


def test_every_rate_policy_exemption_is_named_and_matches_exactly_one_call_site():
    assert all(isinstance(reason, str) and reason.strip()
               for reason in _CONTROL_PLANE_CALLS.values())
    inventory = _raw_transport_inventory()
    counts = {key: sum((row["module"], row["function"], row["call"]) == key
                       for row in inventory)
              for key in _CONTROL_PLANE_CALLS}
    assert {key: count for key, count in counts.items() if count != 1} == {}, (
        "rate-policy exemptions must identify one measured call site: %s" % counts)


@pytest.mark.xfail(strict=True, reason=(
    "Q-085 LIVE GAP: 8 ungated target calls remain across 8 modules outside this lease; "
    "registration is not compliance, and SKIPPED/NOT SEEN is not a pass"))
def test_every_target_transport_uses_the_shared_rate_policy():
    assert _target_traffic_bypasses() == []


def test_repository_wide_guard_catches_a_new_previously_invisible_module(tmp_path, monkeypatch):
    fake_root = tmp_path / "agent"
    nested = fake_root / "new_package"
    nested.mkdir(parents=True)
    fake_tools = fake_root / "tools.py"
    fake_tools.write_text("# collection anchor\n", encoding="utf8")
    dirty = nested / "brand_new_engine.py"
    dirty.write_text("import httpx\n\ndef send(url):\n    return httpx.AsyncClient(base_url=url)\n",
                     encoding="utf8")
    monkeypatch.setattr(tools, "__file__", str(fake_tools))

    assert _target_traffic_bypasses() == [
        "new_package/brand_new_engine.py:4:send:httpx.AsyncClient"
    ]

    dirty.write_text("import browser_engine\nimport httpx\n\ndef send(url):\n"
                     "    return browser_engine.rate_limited_async_client(httpx, base_url=url)\n",
                     encoding="utf8")
    assert _target_traffic_bypasses() == []


def test_juiceshop_solver_routes_every_target_send_through_the_policy():
    bypasses = [row for row in _target_traffic_bypasses()
                if row.startswith("juiceshop_solvers.py:")]
    assert bypasses == [], (
        "the lab solver promises no DoS but still has raw target transports: %s" % bypasses)


def test_owned_q085_call_sites_route_every_target_send_through_the_policy():
    """The BIE and API slices must not consume the residual ratchet forever."""
    bypasses = [row for row in _target_traffic_bypasses()
                if row.startswith(("bie.py:", "main.py:"))]
    assert bypasses == [], "owned Q-085 target transports remain ungated: %s" % bypasses


def test_sync_client_waits_and_observes_at_the_shared_chokepoint():
    clock = [0.0]
    starts = []
    responses = [429, 200]

    def sleep(delay):
        clock[0] += delay

    def handler(request):
        starts.append(clock[0])
        status = responses.pop(0)
        headers = {"Retry-After": "2"} if status == 429 else {}
        return httpx.Response(status, headers=headers, request=request)

    policy = browser.TargetRatePolicy(max_wait=5, clock=lambda: clock[0], sync_sleep=sleep)
    with browser.rate_limited_sync_client(
            httpx, transport=httpx.MockTransport(handler), rate_policy=policy) as client:
        client.get("https://target.example/one")
        client.get("https://target.example/two")

    assert starts == [0.0, 2.0]
    assert policy.stats()["observations"] == 1
    assert policy.stats()["waits"] == 1


def test_all_ten_juice_shop_race_workers_cross_the_shared_gate():
    import juiceshop_solvers as js

    class CountingPolicy:
        def __init__(self):
            self.waited = []
            self.observed = []
            self.lock = threading.Lock()

        def wait_sync(self, url):
            with self.lock:
                self.waited.append(url)

        def observe(self, url, status, headers):
            with self.lock:
                self.observed.append((url, status))

    def handler(request):
        path = request.url.path
        if path == "/rest/user/login":
            return httpx.Response(200, json={"authentication": {"token": "T"}}, request=request)
        if path == "/rest/products/1/reviews":
            return httpx.Response(200, json={"data": [{"_id": "R"}]}, request=request)
        return httpx.Response(200, request=request)

    policy = CountingPolicy()
    with browser.rate_limited_sync_client(
            httpx, base_url="https://juice.invalid", transport=httpx.MockTransport(handler),
            rate_policy=policy) as client:
        js._multiple_likes(client)

    review_waits = [url for url in policy.waited if url.endswith("/rest/products/reviews")]
    review_observations = [row for row in policy.observed if row[0].endswith("/rest/products/reviews")]
    assert len(review_waits) == 10, "one or more race workers routed around the request gate"
    assert len(review_observations) == 10, "one or more race responses escaped policy observation"


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


class _SyncPage:
    def __init__(self, url, clock):
        self.url = url
        self.clock = clock
        self.starts = []
        self.calls = 0
        self.route_handler = None
        self.response_handler = None

    def route(self, _pattern, handler):
        self.route_handler = handler

    def on(self, event, handler):
        if event == "response":
            self.response_handler = handler

    def goto(self, url, **_kwargs):
        self.starts.append(self.clock[0])
        self.calls += 1
        return _Response(url, 429, "2") if self.calls == 1 else _Response(url, 200)


def test_sync_playwright_navigation_waits_and_observes_at_the_shared_chokepoint():
    clock = [0.0]
    sleeps = []

    def sleep(delay):
        sleeps.append(delay)
        clock[0] += delay

    policy = _policy(max_wait=5, clock=lambda: clock[0], sync_sleep=sleep)
    page = _SyncPage("https://a.example/", clock)

    browser.rate_limited_goto_sync(page, page.url, rate_policy=policy)
    browser.rate_limited_goto_sync(page, page.url, rate_policy=policy)

    assert page.starts == [0.0, 2.0]
    assert sleeps == [2]


def test_sync_playwright_guard_falls_through_to_existing_context_routes():
    """A page safety route must not shadow BIE's context-level request mutation."""
    clock = [0.0]
    sleeps = []
    downstream = []

    def sleep(delay):
        sleeps.append(delay)
        clock[0] += delay

    class Request:
        url = "https://a.example/api/object/1"

    class Route:
        continued = False
        fell_back = False

        def fallback(self):
            self.fell_back = True
            downstream.append("context-route")

        def continue_(self):
            self.continued = True

    policy = _policy(max_wait=5, clock=lambda: clock[0], sync_sleep=sleep)
    page = _SyncPage("https://a.example/", clock)
    browser.rate_limited_goto_sync(page, page.url, rate_policy=policy)
    route = Route()
    page.route_handler(route, Request())

    assert sleeps == [2]
    assert route.fell_back is True and route.continued is False
    assert downstream == ["context-route"]


class _UrlopenResponse:
    def __init__(self, url, status=200, headers=None):
        self.url = url
        self.status = status
        self.headers = headers or {}

    def getcode(self):
        return self.status

    def geturl(self):
        return self.url


def test_urlopen_waits_and_observes_at_the_shared_chokepoint(monkeypatch):
    clock = [0.0]
    starts = []
    sleeps = []
    statuses = [429, 200]

    def sleep(delay):
        sleeps.append(delay)
        clock[0] += delay

    def send(request, **_kwargs):
        starts.append(clock[0])
        status = statuses.pop(0)
        headers = {"Retry-After": "2"} if status == 429 else {}
        return _UrlopenResponse(request.full_url, status, headers)

    monkeypatch.setattr(urllib.request, "urlopen", send)
    policy = _policy(max_wait=5, clock=lambda: clock[0], sync_sleep=sleep)
    request = urllib.request.Request("https://a.example/")

    browser.rate_limited_urlopen(request, rate_policy=policy)
    browser.rate_limited_urlopen(request, rate_policy=policy)

    assert starts == [0.0, 2.0]
    assert sleeps == [2]


def test_urlopen_observes_http_error_before_reraising_it(monkeypatch):
    clock = [0.0]
    starts = []

    def sleep(delay):
        clock[0] += delay

    errors = [urllib.error.HTTPError(
        "https://a.example/", 429, "limited", {"Retry-After": "3"}, None)]

    def send(request, **_kwargs):
        starts.append(clock[0])
        if errors:
            raise errors.pop()
        return _UrlopenResponse(request.full_url)

    monkeypatch.setattr(urllib.request, "urlopen", send)
    policy = _policy(max_wait=5, clock=lambda: clock[0], sync_sleep=sleep)
    request = urllib.request.Request("https://a.example/")

    with pytest.raises(urllib.error.HTTPError):
        browser.rate_limited_urlopen(request, rate_policy=policy)
    browser.rate_limited_urlopen(request, rate_policy=policy)

    assert starts == [0.0, 3.0]


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
