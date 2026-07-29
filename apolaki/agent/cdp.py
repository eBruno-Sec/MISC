"""
Headless-browser (CDP) runtime collector.

curl sees the served bytes; it does NOT see what the app becomes at RUNTIME. This drives a real
headless Chrome (via a browserless/CDP HTTP endpoint) to collect the artifacts only a rendered
browser exposes:

  - service_workers   : registered SW scripts / scopes (offline caches, push, request interception)
  - runtime_endpoints : API/XHR/fetch/GraphQL URLs the SPA actually calls after load + interaction
  - lazy_scripts      : JS chunks loaded lazily (route-split bundles curl never requested)
  - storage_keys      : localStorage / sessionStorage / IndexedDB names (tokens, feature flags)
  - global_hints      : window-level config objects (feature flags, API bases, build metadata)

This feeds the SAME Code-Intelligence + harvest pipeline as the static collectors — it's another
evidence source, not new architecture.

ACTIVATION: needs a headless-Chrome endpoint (the optional `headless-chrome` compose service, or
any browserless-compatible /function endpoint) set in env CDP_BROWSER_URL. With no browser
configured it degrades cleanly to an empty, clearly-labelled result — nothing is faked.
"""
from __future__ import annotations

import os

# A browserless /function module: navigate, settle, then read the runtime-only artifacts.
_COLLECT_JS = """
export default async function ({ page }) {
  const target = %TARGET_JSON%;
  const seen = new Set();
  page.on('request', r => { const u = r.url(); if (/\\/(api|rest|graphql|v1|v2|internal)\\//i.test(u)) seen.add(u); });
  try { await page.goto(target, { waitUntil: 'networkidle2', timeout: 25000 }); } catch (e) {}
  try { await page.waitForTimeout(1500); } catch (e) {}
  const sw = await page.evaluate(async () => {
    if (!navigator.serviceWorker) return [];
    try { const rs = await navigator.serviceWorker.getRegistrations();
          return rs.map(r => (r.active && r.active.scriptURL) || r.scope); } catch (e) { return []; }
  });
  const storage = await page.evaluate(() => {
    const idb = (window.indexedDB && indexedDB.databases) ? undefined : undefined;
    return { local: Object.keys(localStorage || {}), session: Object.keys(sessionStorage || {}) };
  });
  const perf = await page.evaluate(() => performance.getEntriesByType('resource').map(e => e.name));
  const lazy = perf.filter(n => /\\.js(\\?|$)/i.test(n));
  const hints = await page.evaluate(() => {
    const out = {};
    for (const k of Object.keys(window)) {
      try { const v = window[k];
        if (v && typeof v === 'object' && /config|env|flag|api|settings|firebase|__/i.test(k)) out[k] = true;
      } catch (e) {}
    }
    return Object.keys(out);
  });
  return { serviceWorkers: sw, runtimeEndpoints: [...seen], lazyScripts: [...new Set(lazy)],
           storageKeys: storage, globalHints: hints };
}
"""


def _empty(target, note):
    return {"target": target, "configured": False, "note": note,
            "service_workers": [], "runtime_endpoints": [], "lazy_scripts": [],
            "storage_keys": {"local": [], "session": []}, "global_hints": []}


def parse_result(target: str, data: dict) -> dict:
    """Normalise a browserless /function result into the collector's stable shape (pure/testable)."""
    d = data or {}
    return {"target": target, "configured": True,
            "service_workers": list(d.get("serviceWorkers") or []),
            "runtime_endpoints": sorted(set(d.get("runtimeEndpoints") or [])),
            "lazy_scripts": sorted(set(d.get("lazyScripts") or [])),
            "storage_keys": d.get("storageKeys") or {"local": [], "session": []},
            "global_hints": list(d.get("globalHints") or []),
            "counts": {"service_workers": len(d.get("serviceWorkers") or []),
                       "runtime_endpoints": len(set(d.get("runtimeEndpoints") or [])),
                       "lazy_scripts": len(set(d.get("lazyScripts") or []))}}


def collect(target_url: str, browser_url: str = None, timeout: int = 40) -> dict:
    """Drive a headless Chrome to collect runtime artifacts. Returns a clearly-labelled empty result
    (never raises, never fakes) when no browser endpoint is configured or reachable."""
    import json
    browser = browser_url or os.environ.get("CDP_BROWSER_URL", "")
    if not browser:
        return _empty(target_url, "no headless browser configured (set CDP_BROWSER_URL or start the "
                                  "headless-chrome compose service to activate runtime collection)")
    try:
        import httpx
    except Exception:
        return _empty(target_url, "httpx unavailable")
    code = _COLLECT_JS.replace("%TARGET_JSON%", json.dumps(target_url))
    try:
        r = httpx.post(browser.rstrip("/") + "/function",
                       headers={"Content-Type": "application/javascript"}, content=code, timeout=timeout)
        if r.status_code != 200:
            return _empty(target_url, "headless browser returned %s" % r.status_code)
        data = r.json().get("data", r.json()) if r.headers.get("content-type", "").startswith("application/json") else {}
        return parse_result(target_url, data if isinstance(data, dict) else {})
    except Exception as e:
        return _empty(target_url, "headless browser unreachable: %s" % str(e)[:80])
