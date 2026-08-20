"""
Browser execution engine -- Apolaki's second first-class execution world (CHAD's "Playwright moment").

HTTP is fast but blind to JavaScript. This drives a real headless Chrome (via a browserless /function
endpoint) so the platform can faithfully exercise SPA routing, dynamic DOM, client-side validation,
storage, service workers, and JS-generated requests -- and, just as important, act as a SENSOR: one
navigation collects a rich structured observation set (forms, inputs, routes, JS bundles, runtime
API/WS endpoints, storage, cookies, framework) that feeds the SAME planner observations + attack graph
as HTTP recon. Deterministic, zero LLM.

Two entry points:
  observe(url)  -- browser-as-sensor: navigate + return structured observations.
  drive(url, js)-- browser-as-executor: run a browserless /function script (login, fill, click, assert).

With no browser configured (env CDP_BROWSER_URL / the headless-chrome sidecar) both degrade cleanly to a
clearly-labelled empty result -- nothing is faked, and the rest of the platform keeps working on HTTP.
"""
from __future__ import annotations

import asyncio
import contextlib
import contextvars
from datetime import timezone
import email.utils
import json
import math
import os
import threading
import time
from urllib.parse import urlparse


RATE_POLICY_DEFAULT_MAX_SECONDS = 30.0
RATE_POLICY_HARD_MAX_SECONDS = 300.0
_RETRY_STATUSES = frozenset({429, 503})

# Q-043 GAP-2, the bare 429. MEASURED (docs/handoff/rate_policy.md §3/§4): a 429 or 503 carrying no
# usable `Retry-After` produces 0.003 s of backoff on the `_http` path and 0.027 s on the browser
# path -- i.e. none, on both. That is not an oversight. It is a DESIGNED boundary held by a named
# negative control from an earlier Q-043 commit (9c37ced):
#
#   test_backoff_bounds.py::test_a_response_without_retry_after_is_never_recorded_as_a_wait
#   "a 429 the server did not annotate must not manufacture one"
#
# The ticket wants the opposite, and both positions are defensible: nginx `limit_req` and Cloudflare
# routinely return 429 with no Retry-After, so honouring only the annotated case misses the common
# shape; but a cooldown we invented is indistinguishable in the ledger from one the target asked
# for. Resolving that by deleting the control would be weakening an oracle, so the fallback is
# CONFIGURABLE and ships OFF. Zero keeps today's behaviour byte-for-byte and keeps the control
# green; setting it opts in, bounded by the same ceiling as a header-supplied delay.
# The choice of default belongs to whoever owns the ticket, not to this constant.
RATE_POLICY_BARE_DEFAULT_SECONDS = 0.0

# Q-043 GAP-1. The cap in `observe()` bounds ONE HEADER; it never bounded the WAIT. The origin
# deadline is extend-only and shared, so a sibling worker meeting a fresh 429 pushes the deadline
# out from under a caller that is already parked on it. MEASURED: eight such extensions, each one
# individually clamped to the 30s cap, held a single caller for 270.0s. That is the self-inflicted
# denial of service the cap exists to prevent, arriving through the door the cap does not cover.
#
# So a GATE CROSSING is bounded too, by the same number: one crossing waits at most `_max_wait()`
# seconds in total, however many times the deadline moves. Past that the request GOES OUT rather
# than the mission stopping -- politeness that parks a scan indefinitely is worse than one request
# sent inside a cooldown, and the deadline survives, so the NEXT crossing waits again. Progress is
# therefore guaranteed while the target is still being honoured on every request.
#
# The iteration cap is the separate belt-and-braces for GAP-3: `wait_*` re-reads the deadline after
# each sleep, so a sleeper that does not advance the clock spins forever. Unreachable with the real
# `time.sleep`, but it ate this lane's own first measurement run, and the house rules REQUIRE tests
# to inject a fake sleep -- which is exactly the shape that trips it.
_WAIT_ITERATION_CAP = 64

# Per-dispatch wait accounting. A ContextVar rather than a global counter because engines run
# concurrently: a global delta between dispatch and outcome would bill one tool for another tool's
# cooldown. An asyncio task inherits the context at creation and `asyncio.to_thread` copies it, so
# both the async transport and the sync browser path land in the right box. A bare threading.Thread
# does not inherit it; those waits fall back to the process-wide counters in `stats()`.
_wait_scope = contextvars.ContextVar("apolaki_rate_wait_scope", default=None)


def _new_wait_box():
    return {"waits": 0, "seconds": 0.0, "truncated": 0, "origins": []}


@contextlib.contextmanager
def rate_wait_scope():
    """Bracket a dispatch so target-cooldown waits inside it are attributable to THAT dispatch.

    Yields the accounting box; read it after the block. Always yields a box, so a caller never has
    to branch on None -- a dispatch that never waited yields zeros, which is the honest answer and
    not the same as "we did not look"."""
    box = _new_wait_box()
    token = _wait_scope.set(box)
    try:
        yield box
    finally:
        _wait_scope.reset(token)


def describe_wait(box):
    """One bounded ledger token for a dispatch's cooldown time, or '' when it never waited.

    Deliberately empty at zero: an engine that met no rate limiting must log byte-for-byte what it
    logged before this existed, so the ledger's existing notes and every test over them are
    untouched unless a backoff REALLY happened."""
    if not box or not box.get("waits"):
        return ""
    return "[backoff %.1fs x%d%s]" % (
        float(box.get("seconds") or 0.0), int(box["waits"]),
        ", truncated at cap" if box.get("truncated") else "")


def _origin(url):
    """Canonical origin key. Default and explicit default ports share a cooldown."""
    try:
        parsed = urlparse(str(url or ""))
        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").lower()
        if scheme not in ("http", "https") or not host:
            return ""
        port = parsed.port or (443 if scheme == "https" else 80)
        host = "[%s]" % host if ":" in host and not host.startswith("[") else host
        return "%s://%s:%d" % (scheme, host, port)
    except (TypeError, ValueError):
        return ""


def retry_after_seconds(value, now=None):
    """Parse RFC 9110 Retry-After delta-seconds or HTTP-date into a non-negative delay."""
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        delay = float(raw)
        if math.isfinite(delay) and delay >= 0:
            return delay
    except (TypeError, ValueError):
        pass
    try:
        parsed = email.utils.parsedate_to_datetime(raw)
        if parsed is None:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        delay = parsed.timestamp() - (time.time() if now is None else float(now))
        return max(0.0, delay)
    except (TypeError, ValueError, OverflowError):
        return None


class TargetRatePolicy:
    """A shared per-origin Retry-After deadline observed by sync and async transports.

    This is deliberately not a scheduler and offers no simultaneity guarantee. Existing requests may
    finish after one sibling receives a limiting response; every request that reaches the gate after
    that response waits. Deadlines are monotonic, thread-safe, extend-only, and capped.
    """

    def __init__(self, max_wait=None, clock=None, wall_clock=None,
                 async_sleep=None, sync_sleep=None, bare_retry_seconds=None):
        self._explicit_max_wait = max_wait
        self._explicit_bare_retry = bare_retry_seconds
        self._clock = clock or time.monotonic
        self._wall_clock = wall_clock or time.time
        self._async_sleep = async_sleep or asyncio.sleep
        self._sync_sleep = sync_sleep or time.sleep
        self._deadlines = {}
        self._lock = threading.Lock()
        self._stats = {"observations": 0, "capped": 0, "waits": 0,
                       "seconds": 0.0, "truncated": 0}

    def _max_wait(self):
        value = self._explicit_max_wait
        if value is None:
            value = os.environ.get("BBH_RETRY_AFTER_MAX_SECONDS", RATE_POLICY_DEFAULT_MAX_SECONDS)
        try:
            value = float(value)
        except (TypeError, ValueError):
            value = RATE_POLICY_DEFAULT_MAX_SECONDS
        if not math.isfinite(value) or value < 0:
            value = RATE_POLICY_DEFAULT_MAX_SECONDS
        return min(value, RATE_POLICY_HARD_MAX_SECONDS)

    def _bare_wait(self):
        """Fallback cooldown for a rate limit the server did not annotate. 0.0 disables it.

        Every unusable setting -- unparseable, negative, NaN, inf -- resolves to the SAFE default
        rather than to something large, because this knob's failure mode is a parked mission and a
        malformed env var must not be the thing that parks it. Bounded by `_max_wait()` so the
        invented delay can never outlive a header-supplied one."""
        value = self._explicit_bare_retry
        if value is None:
            value = os.environ.get("BBH_RETRY_AFTER_BARE_SECONDS",
                                   RATE_POLICY_BARE_DEFAULT_SECONDS)
        try:
            value = float(value)
        except (TypeError, ValueError):
            return RATE_POLICY_BARE_DEFAULT_SECONDS
        if not math.isfinite(value) or value < 0:
            return RATE_POLICY_BARE_DEFAULT_SECONDS
        return min(value, self._max_wait())

    def clear(self, url=None):
        origin = _origin(url) if url else ""
        with self._lock:
            if origin:
                self._deadlines.pop(origin, None)
            else:
                self._deadlines.clear()

    def observe(self, url, status, headers):
        """Record a target cooldown and return the bounded delay, or None when not applicable."""
        try:
            status = int(status or 0)
        except (TypeError, ValueError):
            return None
        if status not in _RETRY_STATUSES:
            return None
        lowered = {str(k).lower(): v for k, v in dict(headers or {}).items()}
        delay = retry_after_seconds(lowered.get("retry-after"), now=self._wall_clock())
        origin = _origin(url)
        if not origin:
            return None
        if delay is None:
            # The limit carried no usable hint. `_bare_wait()` is 0.0 unless someone opted in, and
            # at 0.0 this returns None exactly as it always has -- the unannotated 429 manufactures
            # nothing, no observation is counted, and the ledger note stays byte-for-byte identical.
            delay = self._bare_wait()
            if delay <= 0:
                return None
        capped = delay > self._max_wait()
        delay = min(delay, self._max_wait())
        deadline = self._clock() + delay
        with self._lock:
            self._deadlines[origin] = max(deadline, self._deadlines.get(origin, 0.0))
            self._stats["observations"] += 1
            self._stats["capped"] += 1 if capped else 0
        return delay

    def remaining(self, url):
        origin = _origin(url)
        if not origin:
            return 0.0
        now = self._clock()
        with self._lock:
            deadline = self._deadlines.get(origin, 0.0)
            remaining = max(0.0, deadline - now)
            if not remaining and origin in self._deadlines:
                self._deadlines.pop(origin, None)
        return remaining

    def _next_wait(self, url, waited, iterations):
        """One bounded step of a gate crossing.

        Returns ``(seconds_to_sleep, truncation)``. ``seconds_to_sleep`` is None when the crossing
        is over; ``truncation`` is non-empty ONLY when it ended on a bound instead of on an expired
        cooldown, so the two endings are never confused by the caller that reports them."""
        cap = self._max_wait()
        if waited >= cap:
            return None, "cap"
        if iterations >= _WAIT_ITERATION_CAP:
            return None, "iterations"
        remaining = self.remaining(url)
        if remaining <= 0:
            return None, ""
        return min(remaining, cap - waited), ""

    def _record_wait(self, url, waited, truncation):
        """Make the wait OBSERVABLE. A silent sleep and a slow engine are the same picture."""
        if waited <= 0 and not truncation:
            return
        with self._lock:
            self._stats["waits"] += 1
            self._stats["seconds"] += waited
            self._stats["truncated"] += 1 if truncation else 0
        box = _wait_scope.get()
        if box is None:
            return
        box["waits"] += 1
        box["seconds"] += waited
        box["truncated"] += 1 if truncation else 0
        origin = _origin(url)
        if origin and origin not in box["origins"]:
            box["origins"].append(origin)

    async def wait_async(self, url):
        waited, iterations = 0.0, 0
        while True:
            step, truncation = self._next_wait(url, waited, iterations)
            if step is None:
                self._record_wait(url, waited, truncation)
                return waited
            await self._async_sleep(step)
            waited += step
            iterations += 1

    def wait_sync(self, url):
        waited, iterations = 0.0, 0
        while True:
            step, truncation = self._next_wait(url, waited, iterations)
            if step is None:
                self._record_wait(url, waited, truncation)
                return waited
            self._sync_sleep(step)
            waited += step
            iterations += 1

    def stats(self):
        """Process-wide cooldown accounting. The per-dispatch view is `rate_wait_scope`."""
        with self._lock:
            return dict(self._stats)

    def reset_stats(self):
        with self._lock:
            self._stats = {"observations": 0, "capped": 0, "waits": 0,
                           "seconds": 0.0, "truncated": 0}


target_rate_policy = TargetRatePolicy()


def rate_limited_async_client(httpx_module, *args, rate_policy=None, **kwargs):
    """Build an AsyncClient whose redirects and requests share the target policy.

    ``rate_policy=False`` is reserved for callers that put the gate outside a
    timing measurement and observe the response themselves. Existing httpx
    hooks are preserved and run after the safety hooks.
    """
    if rate_policy is False:
        return httpx_module.AsyncClient(*args, **kwargs)
    policy = rate_policy or target_rate_policy
    hooks = dict(kwargs.pop("event_hooks", {}) or {})
    request_hooks = list(hooks.get("request", ()))
    response_hooks = list(hooks.get("response", ()))

    async def wait_for_target(request):
        await policy.wait_async(str(request.url))

    async def observe_target(response):
        policy.observe(str(response.url), response.status_code, response.headers)

    hooks["request"] = [wait_for_target, *request_hooks]
    hooks["response"] = [observe_target, *response_hooks]
    return httpx_module.AsyncClient(*args, event_hooks=hooks, **kwargs)


async def _guard_playwright_page(page, policy):
    """Install one request gate per real Playwright page, covering navigation subresources too."""
    if getattr(page, "_apolaki_rate_guard", False):
        return
    route_method = getattr(page, "route", None)
    if not callable(route_method):
        return

    async def gate(route, request):
        try:
            await policy.wait_async(request.url)
        finally:
            await route.continue_()

    def observe(response):
        try:
            policy.observe(response.url, response.status, response.headers or {})
        except Exception:
            pass

    await route_method("**/*", gate)
    page.on("response", observe)
    setattr(page, "_apolaki_rate_guard", True)


async def rate_limited_goto(page, url, rate_policy=None, **kwargs):
    """Playwright navigation guarded by the process-wide target policy."""
    policy = rate_policy or target_rate_policy
    await _guard_playwright_page(page, policy)
    await policy.wait_async(url)
    response = await page.goto(url, **kwargs)
    if response is not None:
        policy.observe(getattr(response, "url", None) or url,
                       getattr(response, "status", 0), getattr(response, "headers", {}) or {})
    return response

# browser-as-SENSOR: one navigation, a full structured observation set.
_OBSERVE_JS = r"""
export default async function ({ page }) {
  const target = %TARGET_JSON%;
  // Script-level failures are COLLECTED, not swallowed. A navigation that fails silently produces an
  // empty observation indistinguishable from a page with nothing on it -- the defect that hid a dead
  // page.waitForTimeout call and an unguarded localStorage read for the entire life of this engine.
  const errs = [];
  const api = new Set(), ws = new Set(), gql = new Set();
  page.on('request', r => { const u = r.url();
    if (/\/(api|rest|v1|v2|internal)\//i.test(u)) api.add(u.split('?')[0]);
    if (/graphql/i.test(u)) gql.add(u.split('?')[0]);
    if (u.startsWith('ws://') || u.startsWith('wss://')) ws.add(u); });
  let csp = '';
  page.on('response', res => { try { if (res.url() === target) {
    const h = res.headers(); csp = h['content-security-policy'] || csp; } } catch (e) {} });
  try { await page.goto(target, { waitUntil: "networkidle2", timeout: 25000 }); }
  catch (e) { errs.push("goto: " + String(e).slice(0, 120)); }
  // page.waitForTimeout was REMOVED in modern Puppeteer. It threw TypeError into the silent catch
  // below, and because that catch also wrapped the navigation the whole observation came back empty:
  // links 0, forms 0, title "". A plain promise sleep works on every version.
  await new Promise(r => setTimeout(r, 1500));
  const dom = await page.evaluate(() => {
    const forms = [...document.querySelectorAll('form')].map(f => ({
      action: f.getAttribute('action') || '', method: (f.getAttribute('method') || 'get').toLowerCase(),
      inputs: [...f.querySelectorAll('input,textarea,select')].map(i => i.getAttribute('name') || i.getAttribute('id') || i.type).filter(Boolean) }));
    const inputs = [...document.querySelectorAll('input,textarea')].map(i => ({
      name: i.getAttribute('name') || i.id || '', type: i.type || 'text', placeholder: i.placeholder || '' }));
    const links = [...new Set([...document.querySelectorAll('a[href]')].map(a => a.getAttribute('href')).filter(h => h && !/^https?:/i.test(h)))];
    const scripts = [...document.querySelectorAll('script[src]')].map(s => s.src);
    const framework = window.angular ? 'angular'
      : (window.React || document.querySelector('[data-reactroot],[data-reactid],#___gatsby')) ? 'react'
      : (window.Vue || document.querySelector('#app[data-v-app]')) ? 'vue' : '';
    return { title: document.title, forms, inputs, links, scripts, framework,
      buttons: [...document.querySelectorAll('button')].map(b => (b.innerText || '').trim()).filter(Boolean).slice(0, 40),
      // GUARDED. Reading localStorage throws SecurityError on an opaque origin — a failed navigation,
      // a sandboxed frame, about:blank. Unguarded, that exception escaped evaluate() and browserless
      // answered 400, so ONE inaccessible storage object discarded the ENTIRE observation: links,
      // forms, scripts, CSP, all of it. That is why the browser sensor returned nothing on every run.
      storage: (function () {
        try { return { local: Object.keys(localStorage || {}), session: Object.keys(sessionStorage || {}) }; }
        catch (e) { return { local: [], session: [], denied: true }; }
      })(),
      cookies: (function () {
        try { return document.cookie ? document.cookie.split(';').map(c => c.split('=')[0].trim()) : []; }
        catch (e) { return []; }
      })() };
  });
  // BROWSERLESS v2 REQUIRES THE { data, type } ENVELOPE. Returning a bare object is rejected with
  // HTTP 400, which drive() reported as "headless browser returned 400" and observe() turned into an
  // empty result -- so the browser sensor produced NOTHING against the pinned browserless/chromium v2
  // image, for every mission, silently. drive() already unwraps data.get("data", data), so only the
  // script side was wrong.
  return { data: { ...dom, runtime_api: [...api], runtime_ws: [...ws], graphql: [...gql], csp,
                   script_errors: errs, url: page.url() },
           type: "application/json" };
}
"""

_SCREENSHOT_JS = r"""
export default async function ({ page }) {
  const target = %TARGET_JSON%;
  const errors = [];
  try { await page.goto(target, { waitUntil: "networkidle2", timeout: 25000 }); }
  catch (e) { errors.push("goto: " + String(e).slice(0, 120)); }
  if (errors.length) {
    return { data: { png_b64: "", target, script_errors: errors }, type: "application/json" };
  }
  try {
    const png = await page.screenshot({ type: "png", fullPage: %FULL_JSON%, encoding: "base64" });
    return { data: { png_b64: png, target, script_errors: [] }, type: "application/json" };
  } catch (e) {
    return { data: { png_b64: "", target,
      script_errors: ["screenshot: " + String(e).slice(0, 120)] }, type: "application/json" };
  }
}
"""


def _browser_url(browser_url=None):
    return (browser_url or os.environ.get("CDP_BROWSER_URL", "")).rstrip("/")


def _empty(target, note):
    return {"target": target, "browser": False, "note": note, "forms": [], "inputs": [], "links": [],
            "scripts": [], "runtime_api": [], "runtime_ws": [], "graphql": [], "framework": "",
            "storage": {"local": [], "session": []}, "cookies": [], "csp": ""}


def _instrument_script(js, target_url):
    """Wrap any browserless function so its main-frame response feeds the shared cooldown."""
    code = str(js or "").replace("%TARGET_JSON%", json.dumps(target_url))
    marker = "export default"
    if marker not in code:
        return code
    user_code = code.replace(marker, "const __apolaki_user =", 1)
    wrapper = r'''

export default async function (__apolaki_ctx) {
  const __apolaki_target = %APOLAKI_TARGET%;
  let __apolaki_nav = { url: __apolaki_target, status: 0, headers: {} };
  const __apolaki_deadlines = new Map(), __apolaki_events = [];
  const __apolaki_max_wait = %APOLAKI_MAX_WAIT_MS%;
  const __apolaki_origin = value => { try { return new URL(value).origin; } catch (e) { return ''; } };
  const __apolaki_delay = value => {
    if (value === undefined || value === null || value === '') return null;
    if (/^\d+(?:\.\d+)?$/.test(String(value).trim())) return Number(value) * 1000;
    const parsed = Date.parse(String(value));
    return Number.isFinite(parsed) ? Math.max(0, parsed - Date.now()) : null;
  };
  try {
    await __apolaki_ctx.page.setRequestInterception(true);
    __apolaki_ctx.page.on('request', async request => {
      try {
        const deadline = __apolaki_deadlines.get(__apolaki_origin(request.url())) || 0;
        const remaining = deadline - Date.now();
        if (remaining > 0) await new Promise(resolve => setTimeout(resolve, remaining));
      } catch (e) {}
      try { await request.continue(); } catch (e) {}
    });
    __apolaki_ctx.page.on('response', response => { try {
      const request = response.request();
      if (request.isNavigationRequest() && request.frame() === __apolaki_ctx.page.mainFrame()) {
        __apolaki_nav = { url: response.url(), status: response.status(), headers: response.headers() };
      }
      const status = response.status(), headers = response.headers();
      if ((status === 429 || status === 503) && headers['retry-after'] !== undefined) {
        const delay = __apolaki_delay(headers['retry-after']);
        const origin = __apolaki_origin(response.url());
        if (delay !== null && origin) {
          const bounded = Math.min(delay, __apolaki_max_wait);
          __apolaki_deadlines.set(origin, Math.max(Date.now() + bounded,
            __apolaki_deadlines.get(origin) || 0));
          __apolaki_events.push({ url: response.url(), status, headers });
        }
      }
    } catch (e) {} });
  } catch (e) {}
  const __apolaki_result = await __apolaki_user(__apolaki_ctx);
  try {
    const __apolaki_data = (__apolaki_result && typeof __apolaki_result === 'object' &&
      Object.prototype.hasOwnProperty.call(__apolaki_result, 'data'))
      ? __apolaki_result.data : __apolaki_result;
    if (__apolaki_data && typeof __apolaki_data === 'object') {
      __apolaki_data._apolaki_navigation = __apolaki_nav;
      __apolaki_data._apolaki_rate_events = __apolaki_events;
    }
  } catch (e) {}
  return __apolaki_result;
}
'''.replace("%APOLAKI_TARGET%", json.dumps(target_url)).replace(
        "%APOLAKI_MAX_WAIT_MS%", str(int(target_rate_policy._max_wait() * 1000)))
    return user_code + wrapper


def drive(target_url, js, browser_url=None, timeout=45):
    """Run a browserless /function script against the target. Returns the script's JSON result, or a
    labelled empty result when no browser is configured/reachable. Never raises."""
    browser = _browser_url(browser_url)
    if not browser:
        return _empty(target_url, "no headless browser configured (start the headless-chrome sidecar + set CDP_BROWSER_URL)")
    try:
        import httpx
    except Exception:
        return _empty(target_url, "httpx unavailable")
    code = _instrument_script(js, target_url)
    # Route the headless browser through the intercept proxy when one is configured, so every request the
    # browser makes is captured + rule-rewritable (browserless v2 accepts Chrome launch args via ?launch=).
    # ignoreHTTPSErrors is ALWAYS on. Staging, internal and lab targets routinely serve a self-signed or
    # expired certificate; without this, page.goto() fails, the script's `catch (e) {}` swallows it, and
    # we "successfully" observe a blank page — zero links, zero forms, no error. The HTTP engine already
    # runs verify=False for the same reason; the browser must match it or the two disagree about what
    # is reachable. Certificate problems are reported by the TLS engine, not by refusing to look.
    launch = {"ignoreHTTPSErrors": True}
    try:
        import proxy as _proxy
        args = _proxy.browser_launch_args()
        if args:
            launch["args"] = args
    except Exception:
        pass
    params = {"launch": json.dumps(launch)}
    try:
        target_rate_policy.wait_sync(target_url)
        r = httpx.post(browser + "/function", headers={"Content-Type": "application/javascript"},
                       content=code, params=params or None, timeout=timeout)
        if r.status_code != 200:
            return _empty(target_url, "headless browser returned %s" % r.status_code)
        data = r.json()
        result = data.get("data", data) if isinstance(data, dict) else {}
        if isinstance(result, dict):
            nav = result.pop("_apolaki_navigation", None) or {}
            target_rate_policy.observe(nav.get("url") or target_url, nav.get("status"), nav.get("headers"))
            for event in result.pop("_apolaki_rate_events", None) or []:
                target_rate_policy.observe(event.get("url") or target_url,
                                           event.get("status"), event.get("headers"))
        return result
    except Exception as e:
        return _empty(target_url, "headless browser unreachable: %s" % str(e)[:80])


def screenshot(target_url, browser_url=None, full=False, timeout=45):
    """Capture a PNG screenshot (base64) of the target via headless Chrome -- a PoC asset to attach to a
    finding. Labelled-empty dict when no browser is configured; never raises."""
    try:
        import base64
        script = _SCREENSHOT_JS.replace("%FULL_JSON%", json.dumps(bool(full)))
        result = drive(target_url, script, browser_url=browser_url, timeout=timeout)
        if not isinstance(result, dict) or result.get("browser") is False:
            return {"browser": False, "note": (result or {}).get("note", "screenshot unavailable"),
                    "png_b64": ""}
        png = str(result.get("png_b64") or "")
        if not png:
            errors = result.get("script_errors") or []
            return {"browser": False,
                    "note": str(errors[0]) if errors else "screenshot returned no image",
                    "png_b64": ""}
        size = len(base64.b64decode(png, validate=True))
        return {"browser": True, "png_b64": png, "bytes": size, "target": target_url}
    except Exception as e:
        return {"browser": False, "note": "unreachable: %s" % str(e)[:60], "png_b64": ""}


def observe(target_url, browser_url=None):
    """Browser-as-sensor: navigate and return the structured observation set. Falls back to a labelled
    empty result when no browser is available."""
    res = drive(target_url, _OBSERVE_JS, browser_url=browser_url)
    if isinstance(res, dict) and res.get("browser") is False:
        return res
    res = res if isinstance(res, dict) else {}
    res.setdefault("target", target_url)
    res["browser"] = True
    # `browser: True` means the SCRIPT RAN, not that the page loaded. A failed navigation still returns
    # a well-formed observation full of zeros, which reads exactly like a page with nothing on it —
    # the ambiguity that let a dead API and a cert error hide here indefinitely. Promote the script's
    # own error list into `note` so the caller sees WHY the observation is empty.
    errs = res.get("script_errors") or []
    if errs:
        res["note"] = "; ".join(str(e) for e in errs[:3])
    elif not (res.get("links") or res.get("forms") or res.get("scripts") or res.get("title")):
        landed = str(res.get("url") or "")
        res["note"] = ("navigated but observed nothing (landed on %s)" % landed if landed
                       else "navigated but observed nothing")
    return res


# ---------------------------------------------------------------------------- browser -> planner sensor
def to_observations(obs):
    """Map a browser observation set onto the deterministic planner vocabulary, so the browser sensor
    feeds the SAME technique planner as HTTP recon (one shared observation model). Pure."""
    out = set()
    if not obs or obs.get("browser") is False:
        return out
    inputs = obs.get("inputs") or []
    forms = obs.get("forms") or []
    names = " ".join((i.get("name", "") + " " + i.get("placeholder", "")).lower() for i in inputs)
    paths = " ".join(str(x).lower() for x in (obs.get("links") or []) + obs.get("runtime_api", []))
    ftext = " ".join(json.dumps(f).lower() for f in forms)
    if obs.get("scripts"):
        out.add("serves_js")
    if obs.get("runtime_api") or "/api" in paths or "/rest" in paths:
        out.add("has_api")
    if any(t in (names + ftext) for t in ("password", "login", "signin")):
        out.add("has_login")
    if "search" in (names + paths) or any("q" == (i.get("name") or "").lower() for i in inputs):
        out.add("has_search_param")
    if any(t in (names + ftext) for t in ("file", "upload")):
        out.add("has_file_upload")
    if any(t in (names + paths) for t in ("redirect", "url", "return", "next")):
        out.add("has_redirect_param")
    if obs.get("graphql"):
        out.add("has_api")
    if obs.get("runtime_ws"):
        out.add("has_api")
    return out
